package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `variables:` ділиться на два класи, і тільки один з них працює.
//
//	простий скаляр                            202 змінних у 153 шаблонах
//	значення з викликом хелпера                928 змінних у 504 шаблонах
//
// Другий клас nuclei відмовляє — виміряно:
//
//	variables:
//	  a: "{{rand_base(7)}}"
//	[WRN] [rb] Could not make http request: unresolved variables found: rand_base

// Проста змінна існує і потрапляє в запит: це те, що робить nuclei.
func TestAPlainVariableReachesTheWire(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	document := `id: var-plain
info:
  name: var plain
  author: tester
  severity: info
variables:
  num: "999999999"
http:
  - method: GET
    path:
      - "{{BaseURL}}/x?md5={{num}}"
    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a template with a plain variable was refused: %s", run.Reason)
	}
	if !strings.Contains(seen, "999999999") {
		t.Fatalf("the variable did not reach the wire: %q", seen)
	}
	if strings.Contains(seen, "{{") {
		t.Fatalf("the placeholder went on the wire: %q", seen)
	}
	if !run.Matched {
		t.Fatal("the target's answer did not satisfy the template")
	}
}

// Змінна, що пише іншу змінну, — звичайний шаблонізатор, і nuclei його
// розгортає: два проході, щоб результат не залежав від порядку імен.
func TestAVariableMaySpellAnotherVariable(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	document := `id: var-nested
info:
  name: var nested
  author: tester
  severity: info
variables:
  domain: example.test
  url: "https://{{domain}}/p"
http:
  - method: GET
    path:
      - "{{BaseURL}}/?ref={{url}}"
    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a nested variable was refused: %s", run.Reason)
	}
	if !strings.Contains(seen, "example.test") {
		t.Fatalf("the nested value did not reach the wire: %q", seen)
	}
}

// Хелпер у значенні змінної — відмова, бо оригінал відмовляє на ньому. Підставити
// щось означало б зробити перевірку, якої nuclei не робить.
func TestAVariableCallingAHelperIsRefusedWithTheMeasuredReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}
	document := `id: var-helper
info:
  name: var helper
  author: tester
  severity: info
variables:
  a: "{{rand_base(7)}}"
http:
  - method: GET
    path:
      - "{{BaseURL}}/a={{a}}"
    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if got := transport.count(); got != 0 {
		t.Fatalf("requests sent = %d, want 0: the original sends nothing for this shape", got)
	}
	if !strings.Contains(run.Reason, "unresolved variables found") {
		t.Fatalf("the reason does not carry what the binary says: %q", run.Reason)
	}
	if !strings.Contains(run.Reason, "a") {
		t.Fatalf("the reason does not name the variable: %q", run.Reason)
	}
}

// Змінна без значення — це не порожній рядок, а відмова з причиною.
func TestAVariableWithoutAValueIsRefused(t *testing.T) {
	_, reason := readVariables(map[string]interface{}{"x": nil})
	if reason == "" {
		t.Fatal("a variable with no value produced no reason")
	}
	if !strings.Contains(reason, "{{x}}") {
		t.Fatalf("the reason does not name it: %q", reason)
	}
}

// Змінна, що посилається на невизначену, відмовляється — інакше запит пішов би з
// літералом.
func TestAVariableReferringToAnUndefinedOneIsRefused(t *testing.T) {
	_, reason := readVariables(map[string]interface{}{"a": "{{missing}}"})
	if reason == "" {
		t.Fatal("a variable referring to an undefined name produced no reason")
	}
	if !strings.Contains(reason, "does not define") {
		t.Fatalf("the reason does not say what is missing: %q", reason)
	}
}

// Найважливіша різниця з оригіналом, виміряна на обліку.
//
// nuclei пише `not_matched` і для запиту, який **не надіслав**. Виміряно на
// `http/cves/2011/CVE-2011-4640`: три raw-записи, друга з `{{username}}` і
// `{{password}}`, яких ніщо не визначає.
//
//	nuclei -duc -nc -v -u http://127.0.0.1:20642/ -t CVE-2011-4640.yaml
//	[WRN] [CVE-2011-4640] Could not make http request for …:
//	      unresolved variables found: username,password
//	облік: not_matched   (причина порожня)
//
// Тобто бінарник не надіслав нічого і повідомив «перевірив, нічого не знайшов».
// Наш раннер відмовляє і називає причину. Це і є те, навіщо все затівалося:
// вердикт «нічого не знайдено» має спиратися на запит, який пішов.
//
// 444 з 4 000 шаблонів у цій відмінності — нестача не наша, а різниця у чесності
// звіту.
func TestNoVerdictIsClaimedForARequestThatWasNeverSent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a target was called for a document whose only request cannot be built")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}
	document := `id: unsent
info:
  name: unsent
  author: tester
  severity: info
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}

        user={{username}}&pass={{password}}

    unsafe: true

    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if got := transport.count(); got != 0 {
		t.Fatalf("requests sent = %d, want 0", got)
	}
	if run.Matched {
		t.Fatal("a document whose request never went out reported a match")
	}
	if run.Reason == "" {
		t.Fatal("a document that could not be sent produced no reason")
	}
	if !strings.Contains(run.Reason, "{{username}}") || !strings.Contains(run.Reason, "{{password}}") {
		t.Fatalf("the reason does not name what was missing: %q", run.Reason)
	}
}
