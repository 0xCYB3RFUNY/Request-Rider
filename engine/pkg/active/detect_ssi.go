// Server-Side Includes: a parameter that reaches a page SSI still processes.
//
// # The bug, and why it needs a header to prove
//
// Apache's `mod_include` and nginx's SSI filter run a second pass over the
// response body *after* the application has produced it. A value the
// application echoes therefore gets a second chance to become code: the value
// `<!--#exec cmd="id" -->` is inert text to the application, and a directive to
// the include filter.
//
// The usual proof — "the response contains the payload" — proves nothing here,
// because a page that echoes the parameter contains it whether or not SSI ran.
// Sending the directive and looking for it again is the same mistake the CRLF
// detector refuses to make.
//
// So the proof is a value that never left the request: the payload asks the
// filter to echo a **request header**, and the header carries a canary that was
// never in any parameter value. The canary can reach the response by exactly one
// route — the include filter executed, read the header, and wrote it into the
// document.
//
// # Why the header is namespaced
//
// `X-RR-SSI-Probe` is a header no server sets and no proxy adds. A common name
// would let an intermediary's own header satisfy the check, which is the same
// reasoning the response-splitting detector uses for its planted header.
package active

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// ssiProbeHeader carries the canary the include filter is asked to echo.
const ssiProbeHeader = "X-RR-SSI-Probe"

// ssiDirectives are the `#echo` forms tried, in order.
//
// The double-quoted variable name is what both Apache and nginx document. The
// single-quoted and unquoted forms are there because a filter that is strict
// about one spelling is a filter whose configuration the operator will want to
// know is stricter than its documentation; the cost is one request each, spent
// only after the first form did not execute.
var ssiDirectives = []string{
	`<!--#echo var="HTTP_X_RR_SSI_PROBE"-->`,
	`<!--#echo var='HTTP_X_RR_SSI_PROBE'-->`,
	`<!--#echo var=HTTP_X_RR_SSI_PROBE-->`,
}

// SSI is the server-side-include detector.
type SSI struct{}

// Name implements Module.
func (SSI) Name() string { return "ssi" }

// Level implements Module.
//
// Endpoint rather than parameter: SSI is a property of the *page*, and a
// parameter is merely the carrier the detector uses to reach it. Running it per
// parameter would spend the same request once per surface, which on a form with
// eight fields is eight identical probes.
func (SSI) Level() Level { return LevelEndpoint }

// Scan probes one surface.
func (m SSI) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || ctx.Err() != nil {
		return nil
	}
	// An XML or JSON response is not processed for includes, and neither is a
	// binary body. Checking first keeps the probe off documents that cannot
	// possibly carry the directive.
	if !isHTMLContentType(baseline) {
		return nil
	}
	canary := newCanary("rrssi")
	if canary == "" {
		return nil
	}
	for _, directive := range ssiDirectives {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := fireSSIProbe(ctx, t, p, directive, ssiCanaryHeader(canary))
		if err != nil {
			continue
		}
		if !Fresh(baseline, resp, canary) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "ssi",
			Title:    "Server-Side Includes execute a directive built from a parameter",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  directive,
			Evidence: Snippet(resp.Body, canary, 200),
			Description: "The submitted value reached the response body and the server then executed it as a " +
				"Server-Side Include directive. The proof is the " + ssiProbeHeader + " header this scan sent: " +
				"that value was never part of any parameter, so it can only appear in the response if the include " +
				"filter ran and echoed a request header. On a server where the filter also accepts #exec, the " +
				"same primitive is remote command execution as the operator running the page.",
			Remediation: "Turn the include filter off, or restrict it so it never processes a response body that " +
				"contains user input (mod_include: `Options -Includes`; nginx: remove `ssi on`). Do not try to " +
				"escape the directive syntax in application code — the filter runs after the application is done.",
		})
		return []Finding{finding}
	}
	return nil
}

// ssiCanaryHeader builds the header the directive asks the filter to echo.
func ssiCanaryHeader(canary string) http.Header {
	header := http.Header{}
	header.Set(ssiProbeHeader, canary)
	return header
}

// fireSSIProbe sends the point's request with one parameter replaced by the
// directive and the probe header attached.
//
// It repeats the parameter substitution `Transport.Fire` performs instead of
// calling it, because `Fire` takes its extra headers as an `http.Header` and the
// header here is the *evidence*: the call has to be visible in this file, where
// the argument is the canary, rather than hidden behind a helper whose name
// says nothing about what it is for.
func fireSSIProbe(ctx context.Context, t *Transport, p Point, payload string, extra http.Header) (*Response, error) {
	values := url.Values{}
	for key, list := range p.Values {
		for _, value := range list {
			values.Add(key, value)
		}
	}
	if p.Param != "" {
		values.Set(p.Param, payload)
	}
	return t.Do(ctx, p.Method, p.URL, values, false, extra)
}

// ssiCarriesDirective reports whether a body contains an include directive.
//
// It is exported to the package's own tests rather than kept private because it
// is the only place that knows what a directive looks like, and a detector that
// fires without the directive having survived is a detector that reported the
// application's own markup.
func ssiCarriesDirective(body string) bool {
	return strings.Contains(body, "<!--#")
}
