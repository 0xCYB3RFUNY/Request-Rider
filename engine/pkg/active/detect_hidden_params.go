package active

// Hidden parameters: names the program binds that no page declares.
//
// # What this is, and where the wordlist comes from
//
// The one-liner this ports walks a JavaScript file, prints every `var` name, and
// fires each of them at the site as `?name=value`, because a name a program binds
// is a name its server may accept even when no form, no link and no document
// mentions it. The upstream version fires one value and looks for an echo. This
// detector keeps the wordlist and replaces the echo check, because an echo is not
// what a hidden parameter looks like: a page that reflects its query reflects
// every parameter, hidden or not, and a detector built on reflection reports the
// whole wordlist on the first page it touches.
//
// The wordlist arrives on the module rather than being derived here. That is the
// same arrangement the other operator-driven inputs use (`BlindDelay`,
// `MarkerHost`), and the reason is the same: the names come from a different part
// of this project — the JavaScript analyser, which reads the parse tree and
// produces `js.ParamCandidates` — and re-deriving them here would be a second
// implementation of a question that is already answered once. An empty wordlist
// means the detector does not run and reports nothing, which is stated rather
// than silent.
//
// # Why two values per candidate
//
// Every other differential detector in this package learned the same lesson: a
// page that changes on its own — a rotating banner, a request id, a timestamp —
// makes "the response changed" a statement about the page rather than about the
// parameter. `timeProbe` answers it by sending the same writing twice and reading
// the difference of the differences. This detector answers it by sending two
// *different* values of the same parameter and asking a question the page cannot
// fake:
//
//   - both answers are identical to each other and both differ from the baseline:
//     the application reacted to the parameter's existence and ignored its value.
//     That is a parameter the server reads, and it is the finding.
//   - the two answers differ from each other: the value reached the response, and
//     the parameter is reflected rather than consumed. That is a different finding
//     with a different title, and it is what an echo-based check would have called
//     "found" on a page that reflects everything.
//
// # What is not claimed
//
// Neither outcome is a vulnerability. A hidden parameter is attack surface the
// developer did not publish, and the report says so: `medium` at `potential` for a
// consumed parameter, `medium` for a reflected one. What the run does not do is
// call the reflected parameter cross-site scripting, because that claim belongs to
// `XSS` on a surface the crawl already knew about, and this detector has not shown
// that the value is unencoded or that a browser executes it.

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// HiddenParams probes parameter names the operator's wordlist supplies.
type HiddenParams struct {
	// Params is the wordlist: one entry per candidate name.
	//
	// Empty means the detector is not asked to run and reports nothing. It is a
	// field rather than a discovery because there is no honest way for a scanner
	// to invent the names: the ones worth firing are the ones the target's own
	// code named.
	Params []string
}

// Name implements Module.
func (HiddenParams) Name() string { return "hidden_params" }

// Level implements Module.
//
// Endpoint level, and the reason is the unit of work. A candidate name is fired at
// a URL, not at a parameter, so running this per injectable parameter would send
// the same wordlist at the same URL once per surface and report the same rows N
// times. At endpoint level the run fires each candidate once per unique URL.
func (HiddenParams) Level() Level { return LevelEndpoint }

// candidateFloor is the shortest name worth firing. It is the same floor the
// analyser applies to the names it collects, for the same reason: a one- or
// two-letter binding is a loop counter, and a wordlist of them is a wordlist of
// noise.
const candidateFloor = 3

// candidateCeiling is the longest name worth sending in a query string.
//
// It is not a limit on what may be probed — the operator's list is used as given —
// it is the length beyond which a name cannot be a parameter name on any server
// that reads a query, and a 400-byte key is either an attempt at something else or
// a bug in the caller.
const candidateCeiling = 80

// Scan probes one endpoint with every candidate name.
func (m HiddenParams) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	names := m.usableNames()
	if len(names) == 0 {
		return nil
	}
	var findings []Finding
	for _, name := range names {
		if ctx.Err() != nil {
			return findings
		}
		if finding := probeHiddenParam(ctx, t, p, baseline, name); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

// normalizeCanary replaces every form of a payload in a body with one token, so
// two documents can be compared for a difference that is *not* the payload.
//
// It is `stripEcho` plus a marker, and the marker is the whole point. `stripEcho`
// alone answers "do these two documents say the same thing once the payload is
// ignored", and a page that reflects the payload passes that test — which is why
// the first version of this detector called every reflected parameter a consumed
// one, and why `TestAReflectedUndeclaredParameterIsItsOwnRow` failed. Replacing
// the payload with a token answers the question the detector is actually asking:
// does this document change when the *value* changes.
//
// Every echo form is replaced, not just the raw one, because a page is entitled to
// render the value HTML-escaped and `html.EscapeString` and a hand-written escaper
// disagree on the quote entities.
func normalizeCanary(body, payload string) string {
	if payload == "" {
		return body
	}
	const token = "\x00rr-canary\x00"
	replaced := body
	for _, variant := range echoVariants(payload) {
		if variant == "" {
			continue
		}
		replaced = strings.ReplaceAll(replaced, variant, token)
	}
	return replaced
}

// usableNames is the wordlist after the checks that keep a scan from firing
// rubbish, applied to what the operator supplied rather than replacing it.
func (m HiddenParams) usableNames() []string {
	seen := make(map[string]bool, len(m.Params))
	out := make([]string, 0, len(m.Params))
	for _, raw := range m.Params {
		name := strings.TrimSpace(raw)
		if len(name) < candidateFloor || len(name) > candidateCeiling {
			continue
		}
		// A name carrying a query separator is not a name, it is a query. Firing
		// it would send a request the operator never asked for and report the
		// result as a parameter discovery.
		if strings.ContainsAny(name, " \t\r\n?#&=\"'\\") {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	// Sorted so two runs against the same wordlist spend their requests in the
	// same order, which is what makes two reports diffable.
	sort.Strings(out)
	return out
}

// probeHiddenParam fires one candidate name and decides what the two answers
// mean.
func probeHiddenParam(
	ctx context.Context, t *Transport, p Point, baseline *Response, name string,
) *Finding {
	if baseline == nil {
		// The honest reading of "I could not read the original page" is "I cannot
		// tell", and a detector that reports anyway is guessing with a severity
		// attached. This is `Fresh`'s rule, applied to a differential detector.
		return nil
	}
	first := newCanary("rrp1")
	second := newCanary("rrp2")
	if first == "" || second == "" {
		return nil
	}
	// The finding is reported on a point carrying the candidate name, because the
	// candidate *is* the surface: no page declared it, so nothing else in the
	// record says which parameter the row is about.
	surface := p
	surface.Param = name
	surface.Source = SourceQuery

	// Two values of the same parameter, and nothing else changed. The point's own
	// values are carried over so a page that needs `page=3&lang=en` still receives
	// both while the candidate is under test.
	values := cloneValues(p.Values)
	values.Set(name, first)
	answered, err := t.Do(ctx, http.MethodGet, p.URL, values, false, nil)
	if err != nil || answered == nil {
		return nil
	}
	values.Set(name, second)
	control, err := t.Do(ctx, http.MethodGet, p.URL, values, false, nil)
	if err != nil || control == nil {
		return nil
	}

	// Two answers, and the question is what they say about the *value*.
	//
	// Containment first, because equality alone cannot tell the two cases apart: a
	// page that renders the value produces "you came from <first>" and "you came
	// from <second>", and normalising each value away makes those two documents
	// identical — so an equality test calls a reflected parameter a consumed one.
	// That was the first version, and `TestAReflectedUndeclaredParameterIsItsOwnRow`
	// is the fixture that caught it.
	reflected := strings.Contains(answered.Body, first) && strings.Contains(control.Body, second)
	consumed := !reflected &&
		normalizeCanary(answered.Body, first) == normalizeCanary(control.Body, second)
	if consumed {
		if answered.Body == baseline.Body {
			// Byte-identical to the page without the parameter: the application
			// ignored it. Nothing here is a finding, and reporting "the server
			// ignores it" is what makes a wordlist scan produce a badge full of
			// noise.
			return nil
		}
		finding, _ := NewFinding(Spec{
			Module:   "hidden_params",
			Title:    "Undeclared parameter accepted by " + p.URL,
			Claimed:  SeverityMedium,
			Tier:     TierPotential,
			Point:    surface,
			Payload:  name + "=" + first,
			Evidence: Snippet(answered.Body, first, 200),
			Description: "The parameter name is not declared by any form or link on the site, and the " +
				"application's response to it is identical for two different values while differing from " +
				"the response without it. That is the signature of a parameter the server reads: the value " +
				"was not used, but its presence was. The name came from the application's own JavaScript.",
			Remediation: "Declare every parameter the endpoint reads, or remove the branch that reads it. " +
				"Parameters a client can supply but no page exposes are attack surface with no owner.",
		})
		return &finding
	}

	// The two answers differ, so the value reached the response. That is a
	// reflection, and a reflection is only reported when the canary is absent from
	// the baseline: a page that already prints the parameter it was given is telling
	// the scanner nothing new, and one that prints the canary on its own page for
	// another reason is the false positive this check exists to remove.
	if !Fresh(baseline, answered, first) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "hidden_params",
		Title:    "Undeclared parameter reflected by " + p.URL,
		Claimed:  SeverityMedium,
		Tier:     TierPotential,
		Point:    surface,
		Payload:  name + "=" + first,
		Evidence: Snippet(answered.Body, first, 200),
		Description: "The parameter name is not declared by any form or link on the site, and its value is " +
			"returned in the response. Two different values produce two different answers, so the value is " +
			"reaching the output. Whether that output is encoded, and whether a browser executes it, is not " +
			"claimed here: the XSS detector answers that question on surfaces the crawl already knew about.",
		Remediation: "Reject parameters the endpoint does not read, and encode every value that is rendered.",
	})
	return &finding
}
