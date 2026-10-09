package active

// Tests for the server-side template injection detector.
//
// The failure this module guards against is quiet: a page that prints the number
// forty-nine for unrelated reasons satisfies the arithmetic probe exactly as well
// as a Jinja2 template evaluating it. The tests below are built around a page
// that does that, because a fixture that always evaluates the expression cannot
// tell the two apart.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type sstiFixture struct {
	render func(value string) string
}

func newSSTIFixture(t *testing.T, render func(string) string) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, render(r.URL.Query().Get("tpl")))
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "tpl",
		Values: url.Values{"tpl": {"hello"}},
	}
}

func (SSTI) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return SSTI{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

// A template engine that evaluates the expression and renders the product: the
// expression is consumed, the product appears, and the product is new.
func TestSSTIReportsAnEvaluatedExpression(t *testing.T) {
	transport, point := newSSTIFixture(t, func(value string) string {
		if product, ok := evaluateBraces(value); ok {
			return "<html><body><h1>Hello " + product + "</h1></body></html>"
		}
		return "<html><body><h1>Hello " + value + "</h1></body></html>"
	})
	findings := (SSTI{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if finding.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", finding.Severity)
	}
	if !strings.Contains(finding.Title, "Jinja2") {
		t.Errorf("title = %q, want the engine family named", finding.Title)
	}
	if !strings.Contains(finding.Evidence, "consumed") {
		t.Errorf("evidence = %q, want it to state that the expression was consumed", finding.Evidence)
	}
}

// The page prints forty-nine for its own reasons and reflects the expression.
// Every part of the arithmetic probe is satisfied except the one that matters:
// nothing was evaluated, because the expression is still right there.
func TestSSTIIgnoresAReflectionThatAlsoPrintsTheProduct(t *testing.T) {
	transport, point := newSSTIFixture(t, func(value string) string {
		// A price page: it echoes the input and separately shows a total that
		// happens to equal seven times seven.
		return `<html><body><p>query: ` + value + `</p><p>Subtotal: 49 USD</p></body></html>`
	})
	findings := (SSTI{}).probe(t, transport, point)
	if len(findings) != 0 {
		t.Fatalf("findings = %d (%s), want none: the expression was reflected, not evaluated",
			len(findings), findings[0].Title)
	}
}

// The expression is consumed and the product rendered, but the product was
// already on the page. Nothing about the template engine is established.
func TestSSTIIgnoresAProductAlreadyOnThePage(t *testing.T) {
	transport, point := newSSTIFixture(t, func(value string) string {
		return `<html><body><p>There are 49 results</p><p>Hello world</p></body></html>`
	})
	findings := (SSTI{}).probe(t, transport, point)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want none: the product was on the page already", len(findings))
	}
}

// Several operand pairs, so a coincidence has to coincide for all of them. This
// is what a page printing many numbers does not survive.
func TestSSTIUsesSeveralOperandPairs(t *testing.T) {
	if len(sstiOperands) < 2 {
		t.Fatalf("operand pairs = %d, want more than one: a single pair is a coincidence waiting to happen",
			len(sstiOperands))
	}
	products := map[string]bool{}
	for _, operand := range sstiOperands {
		product := operand[0] * operand[1]
		if products[strconv.Itoa(product)] {
			t.Errorf("operand pair %v repeats the product %d", operand, product)
		}
		products[strconv.Itoa(product)] = true
		if operand[0] < 2 || operand[1] < 2 {
			t.Errorf("operand pair %v includes a trivial factor", operand)
		}
	}
}

// The engine families must be genuinely distinct syntaxes. Two entries that build
// the same payload cost a request and prove nothing on the second one.
func TestSSTIEngineSyntaxesAreDistinct(t *testing.T) {
	if len(sstiEngines) == 0 {
		t.Fatal("no engines configured")
	}
	seen := map[string]string{}
	for _, engine := range sstiEngines {
		payload := engine.wrap(7, 7)
		if previous, clash := seen[payload]; clash {
			t.Errorf("engines %q and %q build the same payload %q", previous, engine.name, payload)
		}
		seen[payload] = engine.name
		if !strings.Contains(payload, "7*7") {
			t.Errorf("engine %q built %q, which does not carry the arithmetic", engine.name, payload)
		}
	}
}

// Every family that is claimed has to be a real template delimiter. A payload
// that is not template syntax at all is a reflection probe wearing a template
// probe's name, and it is what makes this class of detector produce findings on
// pages that merely print numbers.
func TestSSTIEngineWrappersUseTemplateDelimiters(t *testing.T) {
	delimiters := []string{"{{", "${", "<%", "{math", "#{"}
	for _, engine := range sstiEngines {
		payload := engine.wrap(7, 7)
		matched := false
		for _, delimiter := range delimiters {
			if strings.Contains(payload, delimiter) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("engine %q built %q, which carries no template delimiter", engine.name, payload)
		}
	}
}

func TestSSTIReportsNothingWhenNothingIsEvaluated(t *testing.T) {
	transport, point := newSSTIFixture(t, func(value string) string {
		return "<html><body>Nothing happens here.</body></html>"
	})
	if findings := (SSTI{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none", len(findings))
	}
}

func TestSSTIReportsNothingOnCancellation(t *testing.T) {
	transport, point := newSSTIFixture(t, func(value string) string {
		return "<html><body>ok</body></html>"
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (SSTI{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

// evaluationEvidence is the whole contract of the module, asserted directly so a
// change to it cannot hide behind a scan.
func TestEvaluationEvidenceRequiresConsumption(t *testing.T) {
	payload, product := "{{ 7*7 }}", "49"

	// Evaluated: the product is new, the expression is gone.
	got, ok := evaluationEvidence(
		body("<p>Hello world</p>"),
		body("<p>Hello 49</p>"),
		payload, product)
	if !ok || !strings.Contains(got, "consumed") {
		t.Errorf("a consumed expression was not accepted: %q, %v", got, ok)
	}

	// Reflected with the product also present: rejected, because the expression
	// came back.
	if _, ok := evaluationEvidence(
		body("Subtotal: 49"),
		body("<p>{{ 7*7 }}</p><p>Subtotal: 49</p>"),
		payload, product); ok {
		t.Error("a reflected expression with a product present was accepted")
	}

	// Product absent: rejected.
	if _, ok := evaluationEvidence(body("nothing"), body("<p>Hello</p>"), payload, product); ok {
		t.Error("a response with no product was accepted")
	}

	// No baseline: rejected, because "already there" cannot be ruled out.
	if _, ok := evaluationEvidence(nil, body("<p>Hello 49</p>"), payload, product); ok {
		t.Error("accepted with no baseline to compare against")
	}

	// No injected response: rejected.
	if _, ok := evaluationEvidence(body("x"), nil, payload, product); ok {
		t.Error("accepted with no injected response")
	}
}

// evaluateBraces is a minimal stand-in for a template engine, so the fixture
// behaves like a real one: it consumes the expression and renders the product.
func evaluateBraces(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, "}}") {
		return "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(trimmed, "{{"), "}}")
	inner = strings.ReplaceAll(inner, " ", "")
	parts := strings.Split(inner, "*")
	if len(parts) != 2 {
		return "", false
	}
	left, errLeft := strconv.Atoi(parts[0])
	right, errRight := strconv.Atoi(parts[1])
	if errLeft != nil || errRight != nil {
		return "", false
	}
	return strconv.Itoa(left * right), true
}
