// CRLF injection and HTTP response splitting.
//
// # The bug, stated precisely
//
// A parameter that reaches a response header, a `Location`, or a `Set-Cookie` is
// dangerous for a reason that has nothing to do with the value: the parameter can
// *end* the header it is in. `foo%0d%0aX-Injected:%20value` does not merely put
// those bytes in a header — it terminates the header and starts another one. If
// the application reflects the parameter into a header without stripping CR and
// LF, an attacker chooses the name and the contents of a response header.
//
// Splitting is the same bug used destructively: a second CRLF ends the headers
// entirely, and everything after it is the response body — so an attacker writes
// the page. That is why both are checked here rather than only the header case.
//
// # Why the canary is checked in the *response headers* and not the body
//
// Because a body match would be worthless. The payload's own text is what the
// attacker sent, so any parameter that reflects input contains the canary in the
// body whether or not anything was injected anywhere. The evidence for this bug
// is a *header the server did not have*, carrying a canary the server could not
// have invented. That is the only shape of the proof that is not also the shape of
// ordinary reflection.
//
// # The overlong forms are upstream's, and they are worth keeping
//
// Eagle probes `%0D%0A` and then the two overlong UTF-8 encodings of U+554A and
// U+554D. That is not superstition: a filter that decodes UTF-8 strictly will
// reject the overlong pair as invalid encoding, but a filter that decodes leniently
// — or an application that passes bytes to a parser which does — will produce a
// bare CR and a bare LF from them. A filter tuned only on `%0D%0A` is exactly the
// filter this pair exists to walk around.
package active

import (
	"context"
	"strings"
)

// crlfEncodings are the byte sequences tried as a line break.
//
// The first is the canonical CRLF. The other two are Eagle's: the overlong UTF-8
// encodings of U+554A and U+554D, which a strict decoder rejects and a lenient one
// turns into `A` and `M` — a bare CR and a bare LF, in that order. They are listed
// separately rather than folded into the canonical form because the point of them
// is that they survive a filter which blocks the canonical pair.
var crlfEncodings = []struct {
	name string
	crlf string
}{
	{"percent-encoded", "%0d%0a"},
	{"overlong U+554A/U+554D", "%E5%98%8A%E5%98%8D"},
}

// crlfProbeHeader is the header the attacker plants.
//
// It is namespaced (`X-RR-Injected`) so that finding it in a response is
// unambiguous: no server sends it, no proxy adds it, and no framework emits it. A
// commoner name such as `X-Injected` could be added by a WAF on the way in, which
// would make a reflection in an *echoed request* look like a split.
const crlfProbeHeader = "X-RR-Injected"

// crlfProbeValue is the canary that goes in the planted header.
//
// It has to be value-like rather than marker-like: a header value that is not a
// plausible header value may be dropped by an intermediary before it reaches the
// operator's browser, and a dropped header is not evidence of anything.
const crlfProbeValue = "rrcanary8f2c1a"

// CRLF is the CRLF injection and response splitting detector.
type CRLF struct{}

// Name implements Module.
func (CRLF) Name() string { return "crlf" }

// Level implements Module.
func (CRLF) Level() Level { return LevelParam }

// Scan probes one surface.
//
// The header case is checked first because it is the one with a positive
// fingerprint, and splitting second because it is the destructive variant of the
// same bug. A run that found the header case has already established that CR and
// LF survive, so the splitting request — which forces the attacker to write a body
// on a target that has just shown it will take a header — is only spent when the
// first did not fire.
func (m CRLF) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if finding := crlfHeaderProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := crlfSplitProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	return nil
}

// crlfHeaderProbe tries to plant a response header.
func crlfHeaderProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	if baseline != nil && baseline.HeaderValue(crlfProbeHeader) != "" {
		// The header is already there on the unmodified page, so finding it after
		// an injection proves nothing about the injection.
		return nil
	}
	for _, encoding := range crlfEncodings {
		if ctx.Err() != nil {
			return nil
		}
		payload := encoding.crlf + crlfProbeHeader + ": " + crlfProbeValue
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		planted := resp.HeaderValue(crlfProbeHeader)
		if planted == "" || !strings.Contains(planted, crlfProbeValue) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "crlf",
			Title:    "CRLF Injection (response header planted, " + encoding.name + ")",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  payload,
			Evidence: crlfProbeHeader + ": " + planted,
			Description: "The parameter value reached a response header without CR and LF being removed, so the " +
				"submitted bytes ended that header and started a new one. The attacker chooses both the name " +
				"and the value of a response header, which is enough to set a cookie, to poison a cache " +
				"entry, or to place content in front of every subsequent response.",
			Remediation: "Strip CR, LF and NUL from any value that reaches a header, or reject the request " +
				"when they are present. Encode the value if it is not a plain header token — never let it " +
				"terminate the line it is written into.",
		})
		return &finding
	}
	return nil
}

// crlfSplitProbe tries to end the header block and write the body.
//
// The evidence is the canary appearing in the *body* of a response whose baseline
// body did not contain it, sent after a double line break. The canary is a
// distinct string from the one used for the header probe on purpose: a value that
// doubles as a header proves two headers were created, while a value that lands
// in the body proves the header block was closed.
func crlfSplitProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	const bodyCanary = "<html>rrsplit8f2c1a</html>"
	for _, encoding := range crlfEncodings {
		if ctx.Err() != nil {
			return nil
		}
		payload := encoding.crlf + encoding.crlf + bodyCanary
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		if !Fresh(baseline, resp, bodyCanary) {
			// The marker was already on the page, so it did not come from the
			// injection. A page that echoes a parameter contains whatever was sent;
			// only the absence of it in the baseline distinguishes the two.
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "crlf",
			Title:    "HTTP Response Splitting (" + encoding.name + ")",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  payload,
			Evidence: Snippet(resp.Body, bodyCanary, 160),
			Description: "A double line break in the submitted value terminated the response's header block, " +
				"and the bytes after it were served as the response body. The attacker therefore writes the " +
				"page: this is cache poisoning against any cache that stores the response, and a reflected " +
				"file download or phishing page served from the target's own origin.",
			Remediation: "Reject any value containing CR, LF or NUL before it reaches a header, and normalise " +
				"CRLF to a single space. Do not rely on encoding the value for a header context: find the " +
				"code that concatenates it and remove the concatenation.",
		})
		return &finding
	}
	return nil
}
