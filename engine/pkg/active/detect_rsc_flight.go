package active

// ReactServerFlight asks whether an endpoint answers a React Server Components
// action with the Server Components render rather than rejecting the shape.
//
// Burp's check `0x00101200` (React Server Components RCE) is about the Flight
// protocol: a POST carrying a `Next-Action` header and a multipart body whose
// parts are Flight arguments. A server that routes it through the Server
// Components render has taken attacker-supplied, deeply nested structured data
// into a deserialiser that was never designed to be a boundary — the CVE-2025-55182
// family is exactly that, and the whole family starts with the same observable:
// the action was *handled*.
//
// What this row proves and what it does not. It proves the endpoint ran the
// action path: the response is either the RSC component stream (`text/x-component`)
// or a Flight error envelope carrying a `digest`, which only the Server Components
// render writes. It does **not** prove code execution — that needs a payload
// against a specific version and a confirmation, and a scanner that reported
// "RCE" on the strength of an error envelope would be reporting a guess.
//
// The tier is therefore potential, the title names what was observed, and the
// escaped-string column carries the exact request so the operator can drive it
// by hand against the version they care about.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ReactServerFlight is the Flight action probe.
type ReactServerFlight struct{}

// Name implements Module.
func (ReactServerFlight) Name() string { return "rsc-flight" }

// Level implements Module.
func (ReactServerFlight) Level() Level { return LevelEndpoint }

// rscActionID is the action identifier the probe declares.
//
// It is fixed for the reason `urlOverrideCanary` is fixed. The *answer* is what
// identifies the run's probe — `text/x-component` or a Flight envelope — so the
// id itself carries no information a reader needs and no uniqueness the report
// depends on.
const rscActionID = "rr-flight-action"

// rscMarkers are the answers that mean the Server Components render ran. The
// first is the content type of the component stream itself; the rest are the
// Flight envelope a thrown error produces.
var rscMarkers = []struct {
	name    string
	probe   func(resp *Response) bool
	claimed Severity
}{
	{"the component stream", func(resp *Response) bool {
		return strings.Contains(strings.ToLower(resp.HeaderValue("Content-Type")), "text/x-component")
	}, SeverityHigh},
	{"a Flight error envelope carrying a digest", func(resp *Response) bool {
		body := resp.Body
		return (strings.Contains(body, "\"digest\"") || strings.Contains(body, "digest:")) &&
			(strings.Contains(body, "\"message\"") || strings.Contains(body, "Error"))
	}, SeverityMedium},
	{"a Server Components render failure", func(resp *Response) bool {
		body := resp.Body
		return strings.Contains(body, "Server Components render") ||
			strings.Contains(body, "An error occurred in the Server Components")
	}, SeverityMedium},
}

// Scan posts a Flight action at the endpoint and reads what answered.
func (ReactServerFlight) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	// The action id is fixed, and that is deliberate: a finding's identity
	// hashes its payload, so a random id would make two runs of the same target
	// produce two different reports — which is what
	// `TestScanReportIsDeterministic` refuses, because a diff between two
	// reports has to show a change and not a reshuffle.
	action := rscActionID
	body, contentType := rscFlightBody(action)
	header := http.Header{
		"Next-Action":            {action},
		"Next-Router-State-Tree": {`%5B%22%22%2C%7B%7D%5D`},
		"Accept":                 {"text/x-component"},
		"RSC":                    {"1"},
		"Content-Type":           {contentType},
	}
	resp, err := t.DoBody(ctx, http.MethodPost, p.URL, []byte(body), contentType, false, header)
	if err != nil || resp == nil {
		return nil
	}

	for _, marker := range rscMarkers {
		if !marker.probe(resp) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "rsc-flight",
			Title:    "React Server Components Action Handled: " + marker.name,
			Claimed:  marker.claimed,
			Tier:     TierPotential,
			Point:    Point{URL: p.URL, Method: http.MethodPost, Origin: p.Origin},
			Payload:  "Next-Action: " + action + "\n" + contentType + "\n\n" + body,
			Evidence: rscEvidence(resp),
			Description: "The endpoint answered a POST carrying a `Next-Action` header and a " +
				"multipart Flight body with " + marker.name + ". That answer means the request " +
				"reached the Server Components action path rather than being rejected as a form " +
				"post, so attacker-supplied nested structured data reached the render. Whether it " +
				"is exploitable depends on the framework version, and this row does not claim " +
				"execution — it claims the boundary was reached, which is the precondition for " +
				"every exploit in the family.",
			Remediation: "Upgrade the framework and the server renderer to a patched release. " +
				"Where an action must be reachable, require the request to be a genuine " +
				"navigation action by checking the Origin and the Sec-Fetch-Site headers, and " +
				"bound the size and depth of the action payload at the edge.",
		})
		return []Finding{finding}
	}
	return nil
}

// rscFlightBody builds a multipart body whose parts are Flight arguments.
//
// The shape is the one a React Server Action sends: each part is named `1_$N`
// and carries a Flight reference to a value the server will resolve and bind to
// the action's parameters. The values are deliberately ordinary — a string and a
// nested object — because the point of the probe is the deserialisation path,
// not any particular payload.
func rscFlightBody(action string) (body, contentType string) {
	const boundary = "----rrflight"
	var b []byte
	parts := []struct {
		name  string
		value string
	}{
		{"1_$1", "\"$@1\""},
		{"1_$2", fmt.Sprintf(`{"id":%q,"action":%q}`, action, "rr")},
		{"0", `["$K1"]`},
	}
	for _, part := range parts {
		b = append(b, "--"+boundary+"\r\n"...)
		b = append(b, "Content-Disposition: form-data; name=\""+part.name+"\"\r\n\r\n"...)
		b = append(b, part.value...)
		b = append(b, "\r\n"...)
	}
	b = append(b, "--"+boundary+"--\r\n"...)
	return string(b), "multipart/form-data; boundary=" + boundary
}

// rscEvidence renders what answered, in a shape a triager can read.
func rscEvidence(resp *Response) string {
	evidence := strings.TrimSpace(resp.Status)
	if contentType := resp.HeaderValue("Content-Type"); contentType != "" {
		evidence += " " + contentType
	}
	if shown := firstLine(resp.Body); shown != "" {
		evidence += "\nfirst line: " + shown
	}
	if slice := rscSlice(resp.Body); slice != "" {
		evidence += "\n" + slice
	}
	return evidence
}

// rscSlice shows the part of a Flight envelope that carries the digest, so the
// row names which marker fired rather than a category.
func rscSlice(body string) string {
	for _, anchor := range []string{"digest", "x-component"} {
		if idx := strings.Index(body, anchor); idx >= 0 {
			start := idx
			if start > 40 {
				start = idx - 40
			}
			end := idx + len(anchor) + 60
			if end > len(body) {
				end = len(body)
			}
			return "around `" + anchor + "`: …" + strconv.Quote(body[start:end]) + "…"
		}
	}
	return ""
}
