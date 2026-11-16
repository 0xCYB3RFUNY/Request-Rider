// Input transformation analysis: the technique from backslash-powered-scanner.
//
// # What this detector is for, and why it is not another injection detector
//
// Every other parameter-level detector in this package asks "did this payload do
// something". This one asks a prior question: "what is this parameter wrapped in
// on the way to the sink?" A value that reaches a MySQL query inside a PHP string
// passes through two escapers — PHP's, which turns `"` into `\"`, and MySQL's,
// which turns `\` into `\\`. The payload that works against that sink is different
// from the payload that works against a raw one, and every detector in this package
// otherwise has to guess which sink it is facing.
//
// The technique answers it by measurement. Submit a single backslash between two
// random anchors and see whether it comes back. If it does, nothing ate it. If it
// does not, exactly one layer consumed it, and the set of characters that survive
// tells you which. That is the insight of the PortSwigger whitepaper: the escaping
// stack is *discoverable from the outside*, and knowing it is what makes a filter
// bypass writable at all.
//
// # Why anchors and not a bare backslash
//
// A bare `\` is ambiguous. A page that HTML-escapes backslashes renders `&#92;`;
// one that URL-decodes once renders `\`; one that does both renders `&#92;`.
// Bracketing the backslash between two random anchors makes all of those
// distinguishable, because the *relationship* between the anchors stays observable
// even when the backslash itself is mangled: left anchor immediately followed by
// the right one means the backslash was consumed.
//
// # Why the whole character set is probed, not just three characters
//
// The classification needs a backslash, a single quote and a backtick. The other
// sixteen characters are probed anyway, and the reason is that they are what make
// the row auditable: the evidence line lists, for every character upstream tests,
// whether it survived. That turns a conclusion ("two escape layers") into
// something a reader can re-derive, and it is the same reason upstream keeps the
// full list — a classification supported by three measurements is a guess that
// happens to be labelled.
//
// # What is claimed, and what is not
//
// An escaping stack is not a vulnerability, and a report that called it one would
// be wrong in exactly the way this package exists to avoid. The row is `info` at
// `TierPotential`, and what it states is the useful consequence: which injection
// classes are worth trying on this parameter at all, and that a target whose
// parameters arrive unwrapped has no filter between them and their sink.
package active

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// transformationSyntaxes are the characters whose handling identifies a stack.
//
// The set is upstream's own payload list from `TransformationScan.java`, in its
// order. Four of them do the classifying — backslash, single quote, double quote
// and backtick — because each is escaped by exactly one of the layers that can sit
// between a query parameter and a sink. The other fifteen are probed for the
// evidence line: they distinguish an application-level escaper from a
// database-level one, because the two escape different halves of this list.
var transformationSyntaxes = []string{
	`\`, `'`, `"`, "{", "}", "(", ")", "[", "]", "$", "`", "/", "@", "#", ";", "%", "&", "|", "^", "?",
}

// transformationDecodeProbes are upstream's decode-based payloads, called
// `decodeBasedPayloads` in the source.
//
// They are not escaping characters at all — they are numbers written in four
// notations, three of which mean `A` and three of which mean NUL. They exist to
// test whether the parameter is *decoded* on the way to the sink, which is a
// precondition for every bypass: a sink receiving `%27` was never decoded, and no
// escaping bypass is reachable through it. Upstream separates them for that
// reason, and so does this detector: they measure the pipe, not the destination.
var transformationDecodeProbes = []string{
	"101",   // 'A' as a decimal number
	"x41",   // 'A' as hex
	"u0041", // 'A' as a JavaScript unicode escape
	"0",     // NUL as a decimal number
	"1",     // SOH as a decimal number
	"x0",    // NUL as hex
}

// transformationObservation is one character's measured fate.
type transformationObservation struct {
	// syntax is the character as it was submitted.
	syntax string
	// survived reports whether it came back between the anchors unchanged.
	survived bool
}

// transformationLayer is one identified escaping stack.
type transformationLayer struct {
	// name is what the operator should call it.
	name string
	// why is the measurement that identified it, and it is carried into the
	// evidence so the row can be checked rather than believed.
	why string
}

// transformationStack classifies the measurements into a layer.
//
// The classification reads the survival of the backslash and the two quotes,
// because those three are enough to separate the stacks that matter: unwrapped,
// one escape layer, two escape layers, and a shell in the path.
func transformationStack(backslashSurvived, singleQuoteSurvived, backtickSurvived bool) transformationLayer {
	switch {
	case !backslashSurvived && singleQuoteSurvived && backtickSurvived:
		return transformationLayer{
			name: "unwrapped (no escaping layer observed)",
			why: "the backslash was consumed and both quote characters survive verbatim, which is the " +
				"behaviour of a value handed to its destination with no escaping at all",
		}
	case backslashSurvived && !singleQuoteSurvived:
		return transformationLayer{
			name: "single escape layer (backslash-consuming, quote-escaping)",
			why: "the backslash survives but the single quote does not, which is the behaviour of exactly " +
				"one layer that escapes quotes and preserves backslashes — the shape of a MySQL filter " +
				"applied to the whole query, or of an application-level escaper",
		}
	case !backslashSurvived && !singleQuoteSurvived:
		return transformationLayer{
			name: "double escape layer",
			why: "neither the backslash nor the single quote survives, which takes two layers — the common " +
				"shape is a language escaper that doubles backslashes and quotes, wrapping a database " +
				"escaper that does the same",
		}
	case backtickSurvived:
		return transformationLayer{
			name: "shell in the path",
			why: "the backtick survives verbatim, which is only meaningful where a shell would expand it; " +
				"a value carrying backticks past an escaper is reaching something that may execute it",
		}
	default:
		return transformationLayer{
			name: "unclassified",
			why: "the measurements did not fall into any classified shape, and reporting an unclassified " +
				"stack under a named one would be a guess with a title on it",
		}
	}
}

// Escaping is the input transformation detector.
type Escaping struct{}

// Name implements Module.
func (Escaping) Name() string { return "escaping" }

// Level implements Module.
func (Escaping) Level() Level { return LevelParam }

// Scan probes one surface and reports the escaping stack it measured.
//
// This costs twenty requests, which is why it is the last detector a surface sees
// and not the first: the information it produces is only worth twenty requests
// when the cheap detectors found nothing, and a run that finds SQL injection on a
// parameter would rather spend them proving that.
func (m Escaping) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	// A value that is not reflected cannot be measured. The anchors would not come
	// back, every probe would look like a consumed backslash, and the detector
	// would confidently report the worst possible answer from a target that is
	// simply not echoing. It declines instead.
	if baseline == nil || strings.TrimSpace(baseline.Body) == "" {
		return nil
	}
	left := newCanary("rresc")
	if left == "" {
		// No entropy source. The measurement depends on anchors the application
		// could not have produced, and a fixed prefix would be a string a page may
		// legitimately contain — which is the failure `Fresh` exists to prevent
		// everywhere else in this package.
		return nil
	}
	right := "z" + left[2:5]

	// One probe function for every measurement, so no technique can accidentally
	// get a different anchoring from the others.
	probe := func(payload string) (*Response, error) {
		return t.Fire(ctx, p, p.Param, left+payload+right, false, nil)
	}

	// The control. With nothing between them the two anchors must come back, or
	// the page is not echoing the value in any form this measurement can read and
	// every conclusion below would be about the page's HTML escaping.
	control, err := probe("")
	if err != nil || control == nil {
		return nil
	}
	if !strings.Contains(control.Body, left) || !strings.Contains(control.Body, right) {
		return nil
	}

	observations := make([]transformationObservation, 0, len(transformationSyntaxes))
	anchored := func(syntax string, resp *Response) bool {
		// The exact anchored form first, then the two encodings a reflecting page
		// is entitled to produce of a character it considers unsafe. A page that
		// HTML-escapes is not lying about what it received; it is reporting it in
		// its own encoding, and counting that as a consumed character would make
		// every escaped page look like it strips escapes.
		for _, form := range []string{left + syntax + right, left + htmlEscaped(syntax) + right} {
			if strings.Contains(resp.Body, form) {
				return true
			}
		}
		return false
	}

	for _, syntax := range transformationSyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		resp, probeErr := probe(syntax)
		if probeErr != nil || resp == nil {
			return nil
		}
		observations = append(observations, transformationObservation{syntax, anchored(syntax, resp)})
	}

	survived := func(syntax string) bool {
		for _, observation := range observations {
			if observation.syntax == syntax {
				return observation.survived
			}
		}
		return false
	}
	layer := transformationStack(survived(`\`), survived(`'`), survived("`"))

	// The decode measurement, reported alongside because "the parameter is not
	// decoded" decides whether any bypass is reachable at all.
	decoded := false
	for _, decodeProbe := range transformationDecodeProbes {
		if ctx.Err() != nil {
			break
		}
		resp, decodeErr := probe(decodeProbe)
		if decodeErr != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.Body, left+decodeProbe+right) {
			// It arrived unchanged, so the pipe did not decode it into something
			// else. A decoding pipe would have turned `101` into `A`.
			decoded = true
			break
		}
	}

	consumed := make([]string, 0, len(observations))
	for _, observation := range observations {
		if !observation.survived {
			consumed = append(consumed, observation.syntax)
		}
	}
	// Sorted, because the evidence line is compared between runs and an
	// unsorted map walk would make two identical scans produce different reports.
	sort.Strings(consumed)

	finding, _ := NewFinding(Spec{
		Module:  "escaping",
		Title:   "Input Transformation Analysis (" + layer.name + ")",
		Claimed: SeverityInfo,
		// The measurement was observed, so the tier says observed. The severity is
		// `info` rather than something louder because an escaping stack is not a
		// vulnerability — it is the context that decides which payloads are worth
		// sending, and the row below says exactly that.
		Tier:  TierPotential,
		Point: p,
		// The payload is the probe *shape*, not the bytes sent.
		//
		// The anchors are random per run — they have to be, since a fixed anchor is
		// a string a page may legitimately contain — and `FindingID` hashes the
		// payload. Embedding the anchors therefore gave the same unchanging
		// observation a different ID on every run, which broke
		// `TestScanReportIsDeterministic` and with it the one property the whole ID
		// scheme exists for: diffing two scans to see what changed on the target.
		// The measurement itself, including what each character did, is in the
		// evidence; this field carries the input shape so the row is reproducible
		// in form.
		Payload: strings.Join(transformationSyntaxes, ""),
		Evidence: fmt.Sprintf("characters consumed by the escaping stack: [%s]; values arrive undecoded: "+
			"%t. %s", strings.Join(consumed, " "), decoded, layer.why),
		Description: "The escaping stack between this parameter and its sink was measured from outside rather " +
			"than assumed. This is not itself a vulnerability: it is the condition that decides which " +
			"injection classes can succeed here. A single escape layer means a quote-based payload is " +
			"neutralised and a backslash-based bypass is required; two layers mean both are consumed and the " +
			"sink needs a wider payload; an unwrapped parameter means the filter that would have made SQL and " +
			"command injection expensive was never applied between here and the sink.",
		Remediation: "Use parameterised queries and argument arrays rather than escaping. Escaping applied at " +
			"the wrong layer is the condition this row reports, and it is also why the same input needs a " +
			"different payload per sink.",
	})
	return []Finding{finding}
}

// htmlEscaped renders the HTML entity a reflecting page would emit for a
// character it considers unsafe.
//
// Only the characters this package probes are handled, and each is the entity the
// character actually has: `&` for the ampersand, `<` for the less-than, and the
// numeric reference for the quote, because a page is free to emit either the named
// or the numeric form and a detector that checked only one of them would call a
// surviving quote a consumed one.
func htmlEscaped(syntax string) string {
	switch syntax {
	case "&":
		return "&amp;"
	case "<":
		return "&lt;"
	case ">":
		return "&gt;"
	case `'`:
		return "&#39;"
	case `"`:
		return "&quot;"
	default:
		return syntax
	}
}
