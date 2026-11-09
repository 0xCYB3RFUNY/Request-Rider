package active

// OutOfBand settles the checks whose evidence is a callback the application
// makes *after* the response.
//
// Burp files them as four rows — `0x00100A00` out-of-band resource load (HTTP),
// `0x00300200` external service interaction (DNS), `0x00300210` external service
// interaction (HTTP) and `0x00300220` external service interaction (SMTP) — and
// the two JWT key headers beside them. All six share one shape: the application
// is asked to reach an address the operator named, and the only evidence that it
// did is that the address received something.
//
// # What the row claims, and what it does not
//
// A callback proves the application **fetched** the address. It does not prove
// what it did with the answer, and it does not prove that the fetch was
// unauthenticated or reachable by a third party. So the row says the fetch
// happened, names the protocol it arrived over, and leaves the consequence to
// the operator — a callback on a payload URL an anonymous request produced *is*
// the SSRF, and the operator reads it that way.
//
// # Why this reuses the SSRF detector's shape rather than inventing one
//
// An out-of-band resource load is an SSRF with a different evidence channel: the
// same parameter, the same "the server went to an address the run named", read
// from the listener instead of from the response. Writing a second, differently
// shaped SSRF prober would be a second answer to one question, so this module
// fires the address the same way `SSRF` fires its probe and reads the answer
// from the listener.
//
// # What it does not do
//
// SMTP (`0x00300220`) is not ported and the register says so: the module speaks
// HTTP to the service and offers an HTTP address, and a target that mails an
// address rather than fetching one produces a callback the service would not
// record under these protocols. Reporting it from an HTTP callback would be
// reporting the wrong transport.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// OutOfBand is the callback-settled resource-load detector.
type OutOfBand struct {
	// client is the registered listener. Nil is a real state: the operator has
	// not configured an out-of-band service, and a detector that cannot observe
	// the callback would have to guess.
	client *OASTClient
}

// Name implements Module.
func (OutOfBand) Name() string { return "out-of-band" }

// Level implements Module.
//
// Parameter level, and the level is what makes the probe reach the application at
// all. An out-of-band resource load happens when a request's **value** is fetched,
// so the detector needs a parameter to put the watched address into: an endpoint
// with no parameter has nowhere to put it, and `Fire` with an empty parameter
// sends the original request unchanged, which fetches nothing. Every row in this
// family is a statement about a value the client supplied.
//
// The listener is registered **once** for the run rather than per surface: two
// listeners would be two addresses, and an operator reading the report would have
// to work out which one a row came from.
func (OutOfBand) Level() Level { return LevelParam }

// Scan offers the target an address the operator is watching and reports the
// callback.
func (o OutOfBand) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if o.client == nil {
		return nil
	}
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	address := o.client.PayloadURL()
	if strings.TrimSpace(address) == "" {
		return nil
	}

	var out []Finding
	if finding := o.oobLoad(ctx, t, p, address); finding != nil {
		out = append(out, *finding)
	}
	if finding := o.jwtKeyURL(ctx, t, p, address); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// oobLoad submits the watched address as a parameter value and waits.
//
// It is deliberately the same shape as the SSRF probe: one request carrying the
// address in every parameter the surface has, then a wait. The difference is
// where the answer is read from.
func (o OutOfBand) oobLoad(ctx context.Context, t *Transport, p Point, address string) *Finding {
	// One address, one wait. Offering the bare hostname as well was tried and
	// cost double the wall time on every surface while proving nothing extra: the
	// service watches the payload address, and a hostname the target has to
	// resolve to reach it is the same event seen through DNS.
	for _, value := range []string{address} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, err := t.Fire(ctx, p, p.Param, value, false, nil); err != nil {
			continue
		}
		events, err := o.client.WaitFor(ctx, o.client.Wait)
		if err != nil || len(events) == 0 {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "out-of-band",
			Title:   "Out-of-Band Resource Load (HTTP): 0x00100A00",
			Claimed: SeverityHigh,
			Tier:    TierVerified,
			Point:   p,
			Payload: value,
			Evidence: "the application fetched " + value + "; the callback arrived over " +
				firstNonBlank(events[0].Protocol, "http") + " from " +
				firstNonBlank(events[0].Source, "an address the service reported") +
				"\noast event: " + oastEventJSON(events[0]),
			Description: "The endpoint was given the address " + value + " as a parameter value " +
				"and the address received a connection. The application therefore fetches a " +
				"resource a client named, and does so outside the request the client waited for — " +
				"which is what makes an internal-only target reachable and what makes this " +
				"usable against a target that filters by your own address.",
			Remediation: "Validate the destination against an allow-list of hosts the application " +
				"is meant to reach, and refuse link-local, loopback and metadata addresses before " +
				"the fetch rather than after it.",
		})
		return &finding
	}
	return nil
}

// jwtKeyURL asks whether the application fetches a JWT key from an address the
// token named.
//
// The two checks are `0x00200904` (`jku`) and `0x00200905` (`x5u`). The probe
// builds a token that carries the watched address in the header the check names
// and a signature that cannot be valid, then waits: a server that verified the
// token against a signature the run could not have produced would have rejected
// it *before* fetching, and the absence of a callback is the correct negative.
func (o OutOfBand) jwtKeyURL(ctx context.Context, t *Transport, p Point, address string) *Finding {
	if p.Values == nil || p.Param == "" {
		return nil
	}
	current := p.Values.Get(p.Param)
	if !looksLikeJWT(current) {
		return nil
	}
	for _, header := range []string{"jku", "x5u"} {
		token, err := jwtWithHeader(current, header, address)
		if err != nil {
			continue
		}
		if _, err := t.Fire(ctx, p, p.Param, token, false, nil); err != nil {
			continue
		}
		events, err := o.client.WaitFor(ctx, o.client.Wait)
		if err != nil || len(events) == 0 {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "out-of-band",
			Title:   "JWT Key URL Header Honoured (" + header + "): 0x002009" + jwtKeyHeaderIndex(header),
			Claimed: SeverityHigh,
			Tier:    TierVerified,
			Point:   p,
			Payload: token,
			Evidence: "the token named " + address + " in its " + header + " header and the " +
				"address received a connection\noast event: " + oastEventJSON(events[0]),
			Description: "The application fetched a key from an address the **token itself** named, " +
				"in its " + header + " header. The key that verifies the token therefore comes from " +
				"the token, so anyone who can mint a token chooses the key it is verified " +
				"against — which is the whole of the forgery primitive this header opens.",
			Remediation: "Ignore the key URL from the token. Resolve the verification key from " +
				"configuration or from a JWKS endpoint your application names itself, and never " +
				"from a field the bearer of the token controls.",
		})
		return &finding
	}
	return nil
}

// jwtKeyHeaderIndex is the register suffix for the header's check, so the title
// carries the original's own identifier and a reader can look the row up.
func jwtKeyHeaderIndex(header string) string {
	if header == "jku" {
		return "04"
	}
	return "05"
}

// looksLikeJWT reports whether a parameter's current value is a token this
// detector can rewrite. Three segments and two dots is the shape, and the shape
// is what the rewrite needs — not a verified signature.
func looksLikeJWT(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts[:2] {
		if strings.TrimSpace(part) == "" {
			return false
		}
	}
	return true
}

// jwtWithHeader rebuilds a token with one key-URL header added, keeping the rest
// of the token — including a signature this run cannot produce, which is the
// point: a server that verifies before fetching must reject it, and the callback
// is the evidence that it did not.
func jwtWithHeader(token, header, address string) (string, error) {
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return "", err
		}
	}
	var head map[string]interface{}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", err
	}
	head[header] = address
	rebuilt, err := json.Marshal(head)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(rebuilt) + "." + parts[1] + "." + parts[2], nil
}

// oastEventJSON renders one callback for the evidence line, so a reader sees
// what the service reported rather than a paraphrase of it.
func oastEventJSON(event OASTEvent) string {
	if len(event.Raw) == 0 {
		return "{}"
	}
	encoded, err := json.Marshal(event.Raw)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// withClient returns the same detector carrying the run's listener.
//
// It is a method rather than a field read at construction because the listener is
// registered once per run, after the module set is assembled: the registration
// is a network call and a module list that did network I/O in its constructor
// would make `AllModules()` — the set the documentation and the registers read —
// depend on a service being reachable.
func (o OutOfBand) withClient(client *OASTClient) *OutOfBand {
	o.client = client
	return &o
}
