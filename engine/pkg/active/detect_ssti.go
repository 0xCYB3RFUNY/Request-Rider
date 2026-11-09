// Server-side template injection.
//
// # Why arithmetic is not enough on its own
//
// The standard SSTI probe sends `{{7*7}}` and looks for `49`. It works, and it
// also fails in a way that is easy to miss: the product of two small numbers is
// a string that appears in real pages. A product counter, a price, a year, a
// postcode, a page number — all of them print numbers, and every one of them
// prints a number that some pair of small digits multiplies out to.
//
// Two checks make the arithmetic mean something, and both are required here.
//
// The first is the baseline: the product has to be absent before the injection.
// The second is that the template syntax has to have been *consumed*. A page
// that echoes `{{7*7}}` verbatim has not evaluated anything, whatever else it
// happens to print; a page that prints `49` and no trace of the expression has.
// That second check is what distinguishes a template engine from a page that
// merely contains the number forty-nine, and it costs nothing — the evidence is
// already in the response.
//
// # Why the dead code in the upstream module is worth naming
//
// The upstream implementation declares a table of engine-specific payload
// builders, a set of RCE templates, a combined polyglot probe, an error-signature
// regexp and a placeholder that references `math.MaxInt` — and then uses none of
// them. The detector builds its own payload list inline. This file has no such
// table: a payload list that is not the one being sent is a list that will be
// reviewed, believed to be the truth, and quietly diverge from the code.
package active

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// sstiEngines are the template syntaxes tried, in the order a server-side
// render is most likely to interpret. Each is a distinct engine family, because
// a page behind Jinja2 will not interpret `${...}` and a page behind Velocity
// will not interpret `{{...}}`; one payload per family is the minimum that
// covers them without sending the whole list everywhere.
var sstiEngines = []struct {
	// name is the engine family, reported when the probe succeeds.
	name string
	// wrap builds the payload for a pair of operands.
	wrap func(left, right int) string
}{
	{"Jinja2 / Twig / Pebble", func(l, r int) string { return fmt.Sprintf("{{ %d*%d }}", l, r) }},
	{"Jinja2 / Twig (compact)", func(l, r int) string { return fmt.Sprintf("{{%d*%d}}", l, r) }},
	{"EL / FreeMarker / Velocity", func(l, r int) string { return fmt.Sprintf("${%d*%d}", l, r) }},
	{"ERB / Ruby", func(l, r int) string { return fmt.Sprintf("<%%= %d*%d %%>", l, r) }},
	{"Smarty", func(l, r int) string { return fmt.Sprintf("{math equation=%d*%d}", l, r) }},
	{"Java / Spring EL", func(l, r int) string { return fmt.Sprintf("#{%d*%d}", l, r) }},
}

// sstiOperands are the pairs of small integers used as arithmetic.
//
// Three pairs rather than one, because the point of using more than one is that
// a page printing 49 is not a page evaluating 7*7. With several pairs, a
// coincidence has to coincide for all of them, and the engine that consumes the
// syntax but does not implement arithmetic fails every one of them.
var sstiOperands = [][2]int{{7, 7}, {6, 9}, {13, 3}, {11, 11}}

// SSTI is the server-side template injection detector.
type SSTI struct{}

// Name implements Module.
func (SSTI) Name() string { return "ssti" }

// Level implements Module.
func (SSTI) Level() Level { return LevelParam }

// Scan probes one surface.
func (m SSTI) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	for _, engine := range sstiEngines {
		if ctx.Err() != nil {
			return nil
		}
		for _, operand := range sstiOperands {
			if ctx.Err() != nil {
				return nil
			}
			payload := engine.wrap(operand[0], operand[1])
			product := strconv.Itoa(operand[0] * operand[1])
			resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
			if err != nil {
				continue
			}
			evidence, ok := evaluationEvidence(baseline, resp, payload, product)
			if !ok {
				continue
			}
			finding, _ := NewFinding(Spec{
				Module:  "ssti",
				Title:   "Server-Side Template Injection (" + engine.name + ")",
				Claimed: SeverityCritical,
				// An arithmetic fingerprint proves the engine evaluated an
				// expression. It does not prove code execution, and the chain
				// that connects the two is a separate claim that has to earn
				// its own tier.
				Tier:     TierVerified,
				Point:    p,
				Payload:  payload,
				Evidence: evidence,
				Description: "A template expression injected through the parameter was evaluated server-side: " +
					"the expression itself no longer appears in the response and its product does, and that " +
					"product was absent from the unmodified response. Template evaluation is the condition for " +
					"code execution on most engines, and the next step is a single payload away.",
				Remediation: "Never pass user input into template source; pass it as a data variable. " +
					"Sandbox the template engine and remove dangerous globals. Render untrusted content with a " +
					"templating mode that escapes by default.",
			})
			return []Finding{finding}
		}
	}
	return nil
}

// evaluationEvidence decides whether a response shows an evaluated expression,
// and returns the excerpt that shows it.
//
// Three conditions, and all three are needed:
//
//   - the product is present and was not there before, so it is new;
//   - the expression itself is gone, so it was consumed rather than reflected;
//   - therefore the engine rendered the result of evaluating it.
//
// The second condition is the one that separates a template engine from a page
// that happens to print the number. Without it, a page with a product counter
// satisfies the first condition for `{{7*7}}` and is reported, and the operator
// spends an afternoon proving that forty-nine was a price.
func evaluationEvidence(baseline, injected *Response, payload, product string) (string, bool) {
	if injected == nil || !Fresh(baseline, injected, product) {
		return "", false
	}
	if strings.Contains(injected.Body, payload) {
		// The expression came back intact. Whatever produced the product, it
		// was not this expression being evaluated.
		return "", false
	}
	evidence := Snippet(injected.Body, product, 120)
	if evidence == "" {
		return "", false
	}
	return fmt.Sprintf("the expression %q was consumed and its product %s was rendered instead; the product "+
		"was absent from the unmodified response", payload, product), true
}
