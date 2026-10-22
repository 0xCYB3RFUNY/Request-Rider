package active

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// xsseMarkerProof replaces the detector's title statement when a real browser is
// going to load the page.
//
// It is a *request* rather than a title because the title cannot be read back:
// the worker reports what a page requested, and it reports that for every load,
// while a title would need either a second render or an action this proof has
// no reason to perform. `fetch` is issued at parse time of the handler, so the
// request exists before the navigation the worker is waiting on completes.
//
// The honest limit is CSP: a page whose `connect-src` refuses the marker will
// execute the script and still produce no request. That page's row keeps the
// tier the detector proved, which is the correct outcome — the row says the
// value escaped its context, and nothing here claims more.
func xsseMarkerProof(marker string) string {
	return "fetch('" + marker + "')"
}

// xsseProofPayload returns the payload a browser executes, and whether there is
// one.
//
// The substitution is textual and refuses rather than guesses: the payload has to
// carry this package's own proof statement verbatim, and a row whose payload does
// not — the `javascript:` URI shape, which needs a click — produces no proof here
// instead of a mangled one. Rewriting an arbitrary payload by pattern would be a
// second, untested payload builder living next to the real one.
func xsseProofPayload(payload, marker string) (string, bool) {
	if strings.TrimSpace(marker) == "" || !strings.Contains(payload, xsseProof) {
		return "", false
	}
	return strings.ReplaceAll(payload, xsseProof, xsseMarkerProof(marker)), true
}

// xsseMarkerToken reduces a finding id to characters that are safe inside a
// JavaScript string literal and inside a URL path, so the marker can never be
// the reason a payload stops being valid.
func xsseMarkerToken(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	return b.String()
}

// xsseMarkerURL is the address whose request proves execution.
//
// It lives under the run's marker host, so an operator who configured their own
// listener receives the callback for real and an operator who did not still gets
// a proof: the browser records the request either way, and the `.invalid` canary
// can never resolve to anybody's host.
func xsseMarkerURL(markerHost, findingID string) string {
	host := strings.TrimSpace(markerHost)
	if host == "" {
		return ""
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	token := xsseMarkerToken(findingID)
	if token == "" {
		return ""
	}
	return "http://" + host + "/rrxe/" + token
}

// proofURL is the address the browser loads: the finding's own endpoint with the
// executable payload in the parameter under test.
//
// A GET is the honest form here. A surface harvested from a POST form is still
// reachable by query string in every application that reflects the parameter at
// all — the detector proved the reflection through that form's own request, and
// if the application only reflects on POST the page the browser loads will not
// carry the payload, so the proof declines on its own rather than reporting an
// execution that did not happen.
func proofURL(finding Finding, payload string) string {
	endpoint := strings.TrimSpace(finding.Endpoint)
	if endpoint == "" || strings.TrimSpace(finding.Param) == "" {
		return ""
	}
	values := url.Values{}
	values.Set(finding.Param, payload)
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	return endpoint + separator + values.Encode()
}

// BrowserProvable is a module whose rows a real browser can settle.
//
// It is a payload builder rather than a proof routine on purpose: the marker, the
// address, the tier and the decision to stay silent on anything unproven are the
// same for every module, and a second copy of them per module is how two modules
// end up disagreeing about what counts as proof.
//
// It returns *candidates* rather than one payload because a row sometimes does
// not carry everything needed to pick one. A client-template row names its engine
// only when the page stated a version, and an application that loads its bundle
// from a file states none — so the stage tries each expression in turn and stops
// at the one the page executes. Returning nil is the honest "there is nothing to
// execute here", and it costs the row no browser time at all.
type BrowserProvable func(finding Finding, marker string) []string

// browserProofPayloads is the one place a module's browser payload is registered.
//
// A map keyed by module name rather than a type switch inside the proof stage:
// the stage asks "can this row be executed, and with what", and a module that
// cannot answer is skipped rather than guessed at.
var browserProofPayloads = map[string]BrowserProvable{
	"xss-escape": func(finding Finding, marker string) []string {
		payload, ok := xsseProofPayload(finding.Payload, marker)
		if !ok {
			return nil
		}
		return []string{payload}
	},
	"csti":        cstiProofPayloads,
	"dom-vectors": domVectorProofPayloads,
}

// executeInBrowser proves a row by loading the page in a real browser and looking
// for the request only executed script could have made.
//
// It returns nil for every outcome that is not a demonstration — no renderer, no
// payload variant, a page that did not ask for the marker, a browser that failed
// — and the row then keeps the tier the detector proved. A proof is not a
// downgrade mechanism and it is not an upgrade on trust: the marker is a URL this
// run chose, so a page carrying the payload as text cannot produce it.
func (s *Suite) executeInBrowser(ctx context.Context, finding Finding) *Proof {
	if s == nil || s.Renderer == nil {
		return nil
	}
	provable, ok := browserProofPayloads[finding.Module]
	if !ok {
		return nil
	}
	marker := xsseMarkerURL(s.MarkerHost, finding.ID)
	if marker == "" {
		return nil
	}
	candidates := provable(finding, marker)
	if s.Candidates > 0 && len(candidates) > s.Candidates {
		// The number that was dropped is counted, not forgotten: a report that shows
		// "settled nothing" without saying it stopped early is a report that reads
		// as a target that resisted.
		s.browserSkipped += len(candidates) - s.Candidates
		candidates = candidates[:s.Candidates]
	}
	for _, payload := range candidates {
		target := proofURL(finding, payload)
		if target == "" {
			continue
		}
		s.countBrowserAttempt()
		page, err := s.Renderer.Render(ctx, target)
		if err != nil {
			// A browser that failed is not a page that refused, and trying the next
			// candidate against a dead browser would multiply the same failure. It is
			// counted, so the run can say the tool failed rather than leave the row
			// looking like a target that resisted.
			s.browserErrors++
			return nil
		}
		if !page.Requested(marker) {
			continue
		}
		return s.executionProof(finding, page, marker, payload, target)
	}
	return nil
}

// executionProof is the evidence for one page that asked for this run's marker.
func (s *Suite) executionProof(finding Finding, page BrowserPage, marker, payload, target string) *Proof {
	return &Proof{
		FindingID: finding.ID,
		Kind:      "browser-execution",
		Proof: fmt.Sprintf(
			"a real browser loaded %s and the injected code ran: the page requested %s "+
				"(%d request(s) observed). The executed payload was `%s`",
			page.URL, marker, len(page.Network), payload),
		Runnable: target,
	}
}
