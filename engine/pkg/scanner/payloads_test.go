package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Уся семантика `attack` звірена з nuclei v3.11.1 на ехо-фістурі, яка повертає
// назад сам запит. Тести нижні відтворюють саме ті числа, а не «схоже».
//
//	attack:          імен   надіслано
//	---------------  -----  ----------
//	(не вказано)     1      усі значення
//	(не вказано)     2+     0
//	batteringram     1      усі значення
//	batteringram     2+     відмова: must have single payload set
//	pitchfork        будь-яке  до найкоротшого
//	clusterbomb      будь-яке  декартів добуток
//	sniper           будь-яке  відмова: invalid attack type: sniper

func twoNames() payloadSet {
	return payloadSet{
		"u": {"U0", "U1"},
		"v": {"V0", "V1", "V2"},
	}
}

func pairs(combinations []payloadCombination) []string {
	out := make([]string, 0, len(combinations))
	for _, combination := range combinations {
		keys := make([]string, 0, len(combination))
		for key := range combination {
			keys = append(keys, key)
		}
		// Deterministic rendering so the assertion reads like the measurement.
		sortStrings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s=%s", key, combination[key]))
		}
		out = append(out, strings.Join(parts, ","))
	}
	return out
}

func assertPairs(t *testing.T, got []payloadCombination, want []string, label string) {
	t.Helper()
	rendered := pairs(got)
	if len(rendered) != len(want) {
		t.Fatalf("%s: %d combinations, want %d: %v", label, len(rendered), len(want), rendered)
	}
	seen := map[string]bool{}
	for _, pair := range rendered {
		seen[pair] = true
	}
	for _, pair := range want {
		if !seen[pair] {
			t.Fatalf("%s: %q is missing from %v", label, pair, rendered)
		}
	}
}

// clusterbomb over 2×3 is the 6 measured from nuclei.
func TestClusterBombIsTheFullProduct(t *testing.T) {
	got, reason := generateCombinations("clusterbomb", twoNames())
	if reason != "" {
		t.Fatalf("clusterbomb refused: %s", reason)
	}
	assertPairs(t, got, []string{
		"u=U0,v=V0", "u=U0,v=V1", "u=U0,v=V2",
		"u=U1,v=V0", "u=U1,v=V1", "u=U1,v=V2",
	}, "clusterbomb")
}

// pitchfork walks together and stops at the shorter list — measured as 2 requests
// over lists of 2 and 5.
func TestPitchForkStopsAtTheShortestList(t *testing.T) {
	payloads := payloadSet{"u": {"U0", "U1"}, "v": {"V0", "V1", "V2", "V3", "V4"}}
	got, reason := generateCombinations("pitchfork", payloads)
	if reason != "" {
		t.Fatalf("pitchfork refused: %s", reason)
	}
	assertPairs(t, got, []string{"u=U0,v=V0", "u=U1,v=V1"}, "pitchfork")
}

// The two names with no `attack:` are a case where nuclei sends nothing at all.
// Repeating the silence would hide it, so it is a refusal with the measurement.
func TestTwoPayloadNamesWithoutAnAttackSaySoRatherThanSendingNothing(t *testing.T) {
	_, reason := generateCombinations("", twoNames())
	if reason == "" {
		t.Fatal("two payload names with no attack produced requests, where nuclei produces none")
	}
	if !strings.Contains(reason, "sends nothing at all") {
		t.Fatalf("the reason does not state what nuclei does: %q", reason)
	}
	if !strings.Contains(reason, "two send zero") {
		t.Fatalf("the reason does not carry the measurement: %q", reason)
	}
}

// `attack: sniper` is refused by nuclei at load time, so it is refused here with
// nuclei's own words.
func TestTheSpelledOutSniperIsRefusedWithNucleisOwnReason(t *testing.T) {
	_, reason := generateCombinations("sniper", twoNames())
	if reason == "" {
		t.Fatal("attack: sniper was accepted")
	}
	if !strings.Contains(reason, "invalid attack type: sniper") {
		t.Fatalf("the reason does not quote the binary: %q", reason)
	}
}

func TestBatteringRamNeedsASinglePayloadName(t *testing.T) {
	got, reason := generateCombinations("batteringram", twoNames())
	if reason == "" {
		t.Fatal("batteringram over two names was accepted")
	}
	if !strings.Contains(reason, "single payload set") {
		t.Fatalf("the reason does not quote the binary: %q", reason)
	}
	_ = got

	one := payloadSet{"u": {"U0", "U1", "U2"}}
	combinations, reason := generateCombinations("batteringram", one)
	if reason != "" {
		t.Fatalf("batteringram over one name refused: %s", reason)
	}
	assertPairs(t, combinations, []string{"u=U0", "u=U1", "u=U2"}, "batteringram one name")
}

// Кінцевий доказ: clusterbomb справді надсилає всі шість запитів, і на дроті немає
// літералів `{{u}}` / `{{v}}`.
//
// Фістура навмисно не збігається: свип зупиняється на першій знайденій комбінації,
// і якби він збігся з першою, надіслалося б six→1, що не доводило б нічого про
// генерацію.
func TestAPayloadSweepReachesTheWireForEveryCombination(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		_, _ = w.Write([]byte("nothing here"))
	}))
	defer server.Close()
	document := `id: sweep
info:
  name: sweep
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/p"
    attack: clusterbomb
    payloads:
      u: ["U0", "U1"]
      v: ["V0", "V1", "V2"]
    matchers:
      - type: word
        part: body
        words:
          - "found"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a clusterbomb was refused: %s", run.Reason)
	}
	if run.Matched {
		t.Fatal("a sweep that matched nothing reported a match")
	}
	if len(seen) != 6 {
		t.Fatalf("requests = %d, want 6: %v", len(seen), seen)
	}
	for _, query := range seen {
		if strings.Contains(query, "{{") {
			t.Fatalf("a payload placeholder went on the wire: %q", query)
		}
	}
	if run.Matched {
		t.Fatal("a sweep over six combinations that all missed reported a match")
	}
}

// Одна знайдена комбінація зупиняє свип: інакше clusterbomb відсилав би запити
// після того, як відповідь уже є.
func TestASweepStopsAtTheFirstMatch(t *testing.T) {
	sent := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		if strings.Contains(r.URL.RawQuery, "u=U0") {
			_, _ = w.Write([]byte("found"))
			return
		}
		_, _ = w.Write([]byte("nothing"))
	}))
	defer server.Close()
	document := `id: sweep-stop
info:
  name: sweep stop
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/p?u={{u}}&v={{v}}"
    attack: clusterbomb
    payloads:
      u: ["U0", "U1"]
      v: ["V0", "V1"]
    matchers:
      - type: word
        part: body
        words:
          - "found"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if !run.Matched {
		t.Fatalf("the sweep did not match: %s", run.Reason)
	}
	if sent != 1 {
		t.Fatalf("requests sent = %d, want 1: a sweep stops at the first match", sent)
	}
}

// Згенерований запит, чиї плейсхолдери не розв'язуються, пропускається — і блок
// виконується далі.
//
// Виміряно на v3.11.1: `laravel-env.yaml` має 21 значення payload, одне з яких
// `/.env.{{DN}}`, і nuclei відкриває **20** з'єднань. Тобто він пропускає те, що
// не розв'язалося, і сканує решту. Відмова від всього шаблону коштувала б 20
// справжніх перевірок.
func TestAGeneratedRequestWithAnUnresolvablePlaceholderIsSkippedNotFatal(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		_, _ = w.Write([]byte("nothing"))
	}))
	defer server.Close()
	document := `id: skip-one
info:
  name: skip one
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}{{p}}"
    payloads:
      p:
        - "/.env"
        - "/.env.{{DN}}"
        - "/.env.local"
    matchers:
      - type: word
        part: body
        words:
          - "found"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})

	if len(seen) != 2 {
		t.Fatalf("requests sent = %d, want 2 of the 3 values: %v", len(seen), seen)
	}
	for _, path := range seen {
		if strings.Contains(path, "{{") {
			t.Fatalf("an unresolved placeholder went on the wire: %q", path)
		}
	}
	if run.Matched {
		t.Fatal("a block whose every request missed reported a match")
	}
	if !strings.Contains(run.Reason, "{{DN}}") {
		t.Fatalf("the reason does not name what was skipped: %q", run.Reason)
	}
	// The reason states what was *skipped*, so it can be checked against the
	// dictionary by eye: one value carried `{{DN}}`, so one was skipped.
	if !strings.Contains(run.Reason, "skipped 1 of the 3") {
		t.Fatalf("the reason does not say how many were skipped: %q", run.Reason)
	}
}

// Згенерований запит не може зупинити блок, коли інші збіглисяся: знайдена
// комбінація і є вердикт, а решта — деталь обліку.
func TestASkippedRequestDoesNotHideAMatchFromAnotherCombination(t *testing.T) {
	sent := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		if strings.HasSuffix(r.URL.Path, "/.env") {
			_, _ = w.Write([]byte("found"))
			return
		}
		_, _ = w.Write([]byte("nothing"))
	}))
	defer server.Close()
	document := `id: skip-then-match
info:
  name: skip then match
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}{{p}}"
    payloads:
      p:
        - "/.env.{{DN}}"
        - "/.env"
    matchers:
      - type: word
        part: body
        words:
          - "found"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if !run.Matched {
		t.Fatalf("a later combination matched and the run did not report it: %q", run.Reason)
	}
	if sent != 1 {
		t.Fatalf("requests sent = %d, want 1: the sweep stops at the first match", sent)
	}
}
