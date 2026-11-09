package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Генератори звірено з оригіналом, а не згадано:
//
//	{{randstr}}     -> 3KCM2qmEGJd8y4dN4wLaHl8jgRu   28 знаків
//	{{randstr:10}}  -> nuclei не надсилає нічого
//	{{num}}         -> nuclei не надсилає нічого поза fuzzing
//
// Тому тести нижні вимірюють не «схоже на оригінал», а те саме, що вимірено.

// `{{randstr}}` існує і має ту саму довжину, що в оригіналі.
func TestRandStrIsGeneratedAtTheMeasuredLengthAndAlphabet(t *testing.T) {
	value, err := generateRandStr()
	if err != nil {
		t.Fatalf("draw: %v", err)
	}
	if len(value) != randStrLength {
		t.Fatalf("length = %d, want %d (measured on nuclei v3.11.1)", len(value), randStrLength)
	}
	for _, symbol := range value {
		if !strings.ContainsRune(randStrAlphabet, symbol) {
			t.Fatalf("the generated value carries %q, which is outside the measured alphabet", symbol)
		}
	}
}

// Два випадки мають дати два різні значення: nuclei малює їх окремо, і повторювати
// одне й те саме означало б надсилати не те, що він.
func TestTwoOccurrencesDrawTwoDifferentValues(t *testing.T) {
	first, _ := generateRandStr()
	second, _ := generateRandStr()
	if first == second {
		t.Fatal("two draws produced the same value, so a path with two {{randstr}} would repeat one")
	}
}

// Плейсхолдер, який ми генеруємо, не є відмовою — інакше кожен шаблон із ним
// відмовився б, а ми б повідомили про це як про невмілість.
func TestRandStrIsNotARefusal(t *testing.T) {
	if got := ungeneratedPlaceholders("/x={{randstr}}", nil); len(got) != 0 {
		t.Fatalf("{{randstr}} was refused: %v", got)
	}
}

// Аргументна форма відмовляється, бо оригінал на ній не надсилає нічого. Підставити
// значення означало б видати вердикт за перевірку, якої не було.
func TestTheArgumentedRandStrIsRefusedBecauseNucleiSendsNothing(t *testing.T) {
	got := ungeneratedPlaceholders("/x={{randstr:10}}", nil)
	if len(got) != 1 {
		t.Fatalf("refusals = %v, want the argumented form refused", got)
	}
	reason := generatorRefusal("randstr:10")
	if !strings.Contains(reason, "sends nothing") {
		t.Fatalf("the reason does not say what nuclei does: %q", reason)
	}
}

// `{{num}}` належить рушієві fuzzing, тож поза ним і не підставляється.
func TestNumIsRefusedWithItsMeasuredReason(t *testing.T) {
	got := ungeneratedPlaceholders("/x={{num}}", nil)
	if len(got) != 1 {
		t.Fatalf("refusals = %v, want {{num}} refused", got)
	}
	if !strings.Contains(generatorRefusal("num"), "fuzzing") {
		t.Fatalf("the reason does not say where {{num}} belongs: %q", generatorRefusal("num"))
	}
}

// Кінцевий доказ: запит із `{{randstr}}` іде на дріт із підставленим значенням, а
// літерал `{{randstr}}` на дроті не лишається.
func TestRandStrReachesTheWireSubstituted(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	document := `id: randstr-wire
info:
  name: randstr
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/x={{randstr}}"
    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a template with {{randstr}} was refused: %s", run.Reason)
	}
	if strings.Contains(seen, "{{") {
		t.Fatalf("the literal placeholder went on the wire: %q", seen)
	}
	if len(seen) != len("/x=")+randStrLength {
		t.Fatalf("path = %q, want a /x/ followed by %d characters", seen, randStrLength)
	}
	if !run.Matched {
		t.Fatal("the target's answer was not matched")
	}
}
