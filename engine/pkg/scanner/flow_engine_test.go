package scanner

// The flow engine runs what nuclei refuses to run, so its tests are about the
// two things that would make a wrong answer invisible: a step that is skipped,
// and a precedence read left-to-right when the expression is not.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const twoStepFlow = `id: two-step
info:
  name: Two step flow
  author: test
  severity: high
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/first"
    matchers:
      - type: word
        words:
          - "FIRST-OK"
  - method: GET
    path:
      - "{{BaseURL}}/second"
    matchers:
      - type: word
        words:
          - "SECOND-OK"
`

func TestAFlowWithBothStepsMatchingIsAMatch(t *testing.T) {
	server := newFlowServer()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), twoStepFlow, server.URL, transport)
	if run.Reason != "" {
		t.Fatalf("flow was not run: %s", run.Reason)
	}
	if transport.count() != 2 {
		t.Errorf("sent %d requests, want 2 — a flow that skips a step has not been run", transport.count())
	}
	if !run.Matched {
		t.Error("no match, but both steps' matchers are present in the fixture responses")
	}
}

func TestAFlowFailsWhenOneStepMisses(t *testing.T) {
	server := newFlowServer()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	// Only the first step can match, so `&&` must be false while both requests
	// still have to go out.
	oneOnly := strings.Replace(twoStepFlow, "SECOND-OK", "NEVER-IN-BODY", 1)
	run := RunTemplateLocally(context.Background(), oneOnly, server.URL, transport)
	if run.Matched {
		t.Error("matched, but the second step cannot match")
	}
	if transport.count() != 2 {
		t.Errorf("sent %d requests, want 2: an `&&` chain runs every step, it does not stop at the first miss", transport.count())
	}
}

// Precedence is the failure that reads as a real answer: `a || b && c` is
// `a || (b && c)`, not `(a || b) && c`, and the two disagree as soon as `a` is
// false and `b` is true.
//
// Asserted by **what each step did**, not by the node's type. The parse result used
// to be a `flowOr` with a `flowAnd` inside it, and asserting that shape is how a
// test ends up protecting a representation instead of a rule: when the statement
// layer was added above the expression parser, the top node became `programNode`
// and both tests went red while the precedence was exactly as before.
//
// So the steps are observed instead. http(1) answers 200, http(2) and http(3)
// answer 404:
//   - `a || (b && c)` → satisfied by `a` alone, and the right side may be skipped
//   - `(a || b) && c` → `b` fails, so the whole flow is unsatisfied
func TestFlowPrecedenceIsNotLeftToRight(t *testing.T) {
	server := flowStatusFixture(200, 404, 404)
	defer server.Close()
	document := flowDocument("http(1) || http(2) && http(3)", 3)

	run := RunTemplateLocally(context.Background(), document, server.URL,
		&countingTransport{inner: http.DefaultTransport})

	if !run.Matched {
		t.Fatalf("`http(1) || http(2) && http(3)` did not match although http(1) did: %q", run.Reason)
	}
}

func TestPrecedenceAloneCannotBeMistakenForLeftToRight(t *testing.T) {
	server := flowStatusFixture(404, 404, 200)
	defer server.Close()
	document := flowDocument("http(1) || http(2) && http(3)", 3)

	run := RunTemplateLocally(context.Background(), document, server.URL,
		&countingTransport{inner: http.DefaultTransport})

	if run.Matched {
		t.Fatal("`http(1) || http(2) && http(3)` matched with http(1) and http(2) failing")
	}
}

// Parentheses group as written: `a && (b || c)` is satisfied when `a` holds and
// either `b` or `c` does. Reading it left to right, `(a && b) || c`, would be
// satisfied by `c` alone with `a` failing.
func TestParenthesesGroupAsWritten(t *testing.T) {
	server := flowStatusFixture(200, 404, 200)
	defer server.Close()
	document := flowDocument("http(1) && (http(2) || http(3))", 3)

	run := RunTemplateLocally(context.Background(), document, server.URL,
		&countingTransport{inner: http.DefaultTransport})

	if !run.Matched {
		t.Fatalf("`http(1) && (http(2) || http(3))` did not match although http(1) and http(3) did: %q",
			run.Reason)
	}
}

func TestParenthesesAreNotReadLeftToRight(t *testing.T) {
	server := flowStatusFixture(404, 200, 200)
	defer server.Close()
	document := flowDocument("http(1) && (http(2) || http(3))", 3)

	run := RunTemplateLocally(context.Background(), document, server.URL,
		&countingTransport{inner: http.DefaultTransport})

	if run.Matched {
		t.Fatal("`http(1) && (http(2) || http(3))` matched with http(1) failing")
	}
}

// A step this runner cannot perform is refused by name. Reporting it as a
// non-match would be a statement about a check that never ran.
func TestANonHttpStepIsRefusedByName(t *testing.T) {
	server := newFlowServer()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	for _, expression := range []string{
		"http(1) && headless(1)",
		"tcp(1) && javascript(1)",
	} {
		document := twoStepFlow
		document = strings.Replace(document, "flow: http(1) && http(2)", "flow: "+expression, 1)
		run := RunTemplateLocally(context.Background(), document, server.URL, transport)
		if run.Reason == "" {
			t.Errorf("%q: reported no reason for a step this runner cannot perform", expression)
		}
		if run.Matched {
			t.Errorf("%q: reported a match for a step that was never performed", expression)
		}
	}
}

// Відмова на те, чого ми не читаємо, і прийняття того, що вже читаємо.
//
// Приклад у цьому тесті раніше був `for (let x of iterate(y)) { set(z, x) }`, і
// тест вимагав відмови. Відмова була правильною тоді — мови ще не було — і стала
// неправильною після того, як `for`, `set` і змінна циклу з'явилися. Замість того,
// щоб видалити твердження, воно переписане на справжньо чужий вираз, а поруч
// додано контртест: те, що тепер читається, приймається.
//
// Мутація: прибрати `JSON.parse` із переліку непрочитаних.
func TestAFlowWrittenInSomethingElseIsRefusedWithTheText(t *testing.T) {
	server := newFlowServer()
	defer server.Close()
	// `JSON.parse` used to be in this list and stopped being foreign when it became
	// readable: a refusal list that keeps names of things now supported reports
	// the implementation's history instead of its limits. These three are what the
	// corpus still uses and this runner still cannot read — user-defined functions
	// (6 templates), an IIFE wrapper (4), and a counted loop (2).
	for _, expression := range []string{
		`function target_is_in_scope(url) { return true; } if (target_is_in_scope("x")) { http(1) }`,
		`(function () { if (!http(1)) { return; } http(2) })()`,
		`for (let i = 0; i < 3; i++) { http(1) }`,
	} {
		document := strings.Replace(twoStepFlow, "flow: http(1) && http(2)",
			"flow: "+expression, 1)
		run := RunTemplateLocally(context.Background(), document, server.URL,
			&countingTransport{inner: http.DefaultTransport})
		if run.Reason == "" {
			t.Errorf("%q was accepted; it is not something this runner reads", expression)
		}
		if run.Matched {
			t.Errorf("%q reported a match for a flow it could not read", expression)
		}
		if !run.Skipped {
			t.Errorf("%q produced a verdict rather than a refusal", expression)
		}
	}
}

// Контртест до попереднього: ті самі конструкції, які тепер читаються, приймаються
// і виконуються. Без нього попередній тест можна було б «виправити» простою
// відмовою від усього нового.
func TestTheConstructsTheFlowLanguageNowReadsAreAccepted(t *testing.T) {
	server := newFlowServer()
	defer server.Close()
	for _, expression := range []string{
		`http(1); http(2)`,
		`http(1) && http(2) // both steps must match`,
		`if (template["absent"]) { http(1) } http(2)`,
		`for (let x of iterate(template["absent"])) { http(1) } http(2)`,
	} {
		document := strings.Replace(twoStepFlow, "flow: http(1) && http(2)",
			"flow: "+expression, 1)
		run := RunTemplateLocally(context.Background(), document, server.URL,
			&countingTransport{inner: http.DefaultTransport})
		if run.Reason != "" {
			t.Errorf("%q was refused: %s", expression, run.Reason)
		}
	}
}

func TestAStepBeyondTheDocumentIsRefused(t *testing.T) {
	server := newFlowServer()
	defer server.Close()
	document := strings.Replace(twoStepFlow, "flow: http(1) && http(2)", "flow: http(1) && http(9)", 1)
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if !strings.Contains(run.Reason, "http(9)") {
		t.Errorf("reason = %q, want it to name the step the document does not have", run.Reason)
	}
}

// newFlowServer answers `/first` with the word the first step matches and
// `/second` with a body the second step does not match, so both steps genuinely
// run against a real server rather than a matcher stub.
func newFlowServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/first", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<p>FIRST-OK</p>"))
	})
	mux.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<p>SECOND-OK</p>"))
	})
	return httptest.NewServer(mux)
}

// flowFixture answers each successive request with the given status, so a test can
// decide which steps match without inventing a matcher per block: block 1 gets the
// first status, block 2 the second, and a block past the list gets 404.
func flowStatusFixture(statuses ...int) *httptest.Server {
	var mu sync.Mutex
	served := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		index := served
		served++
		mu.Unlock()
		status := http.StatusNotFound
		if index < len(statuses) {
			status = statuses[index]
		}
		w.WriteHeader(status)
		// The body only on success: the template's matcher is a word in it, so a
		// body on an error would make every step match and the test would decide
		// nothing. The status alone chooses which steps pass.
		if status >= 200 && status < 300 {
			_, _ = w.Write([]byte("flow-fixture-body"))
		}
	}))
}

// flowDocument writes a template whose flow is the given expression over blocks
// that all match the same single word, so a step matches exactly when its block's
// response carried it.
func flowDocument(expression string, blocks int) string {
	var builder strings.Builder
	builder.WriteString("id: flow-precedence\ninfo:\n  name: flow precedence\n  severity: info\nflow: ")
	builder.WriteString(expression)
	builder.WriteString("\nhttp:\n")
	for index := 1; index <= blocks; index++ {
		builder.WriteString("  - method: GET\n    path:\n      - \"{{BaseURL}}/block")
		builder.WriteString(string(rune('0' + index)))
		builder.WriteString("\"\n")
		builder.WriteString("    matchers:\n      - type: word\n        part: body\n        words:\n          - \"flow-fixture-body\"\n")
	}
	return builder.String()
}
