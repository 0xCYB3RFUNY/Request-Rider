package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// `javascript:` — 192 документи корпусу. 54 з них не вимагають жодного
// `require("nuclei/…")`: їм потрібні лише `template.*` та `args:`. Ці тести
// перевіряють саме цю підмножину і відмову для решти — з назвою модуля.

// httptestServer answers one JSON body, which is where the script's inputs come
// from.
func httptestServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// javascriptWithRequest turns a javascript-only document into one that also has an
// `http:` block, so the script has something to read its values from. Without a
// request there is nothing to extract, and the corpus's own scripts are written on
// the assumption that a request ran first.
func javascriptWithRequest(document string) string {
	return strings.Replace(document, "javascript:\n", "http:\n"+
		"  - method: GET\n    path:\n      - \"{{BaseURL}}/serial\"\n"+
		"    extractors:\n      - type: json\n        name: serial\n        part: body\n"+
		"        field: serial\n    matchers:\n      - type: word\n        part: body\n"+
		"        words:\n          - ABC123\njavascript:\n", 1)
}

const javascriptTemplate = `
id: js-argwise
info:
  name: a script judged on the value it ends with
  severity: info
javascript:
  - code: |
      var base = args.prefix;
      var serial = template.serial;
      base + serial
    args:
      prefix: "serial="
    matchers:
      - type: word
        part: response
        words:
          - "serial=ABC123"
`

// Мутація: не передавати `args` у скрипт.
func TestAScriptRunsAndItsLastValueDecidesTheMatch(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("this machine has no node")
	}
	server := httptestServer(t, `{"serial":"ABC123"}`)
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), javascriptWithRequest(javascriptTemplate), server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a javascript block was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the script's last value matched its matcher and the block did not match: %q / %q",
			run.Reason, run.Response)
	}
}

// Мутація: не передавати `template` у скрипт.
func TestTheScriptReadsWhatTheRequestExtracted(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("this machine has no node")
	}
	server := httptestServer(t, `{"serial":"ABC123"}`)
	// The request's own matcher must NOT match: `withCodePhase` skips the script
	// once a phase matched, so a document whose request matched would never run
	// the script at all — and the test would then prove nothing about `template`.
	document := `
id: js-template
info:
  name: a script reading an extracted value
  severity: info
javascript:
  - code: |
      template.serial + "-from-script"
    matchers:
      - type: word
        part: response
        words:
          - "ABC123-from-script"
http:
  - method: GET
    path:
      - "{{BaseURL}}/serial"
    extractors:
      - type: regex
        name: serial
        part: body
        regex:
          - "(ABC[0-9A-Za-z]+)"
    matchers:
      - type: word
        part: body
        words:
          - NEVER-PRESENT-IN-THE-BODY
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a javascript block beside a request was refused: %s / %q", run.Reason, run.Response)
	}
	// The marker the script itself appends. Asserting only `ABC123` was a false
	// green: `run.Response` also carries the HTTP exchange, whose body contains
	// `ABC123` on its own — so the mutation that empties `template` left the test
	// passing while the script had read nothing.
	if !strings.Contains(run.Response, "ABC123-from-script") {
		t.Fatalf("the script never saw the extracted value: %q / %q", run.Reason, run.Response)
	}
}

// Скрипт, який піднімає помилку, — це відмова з текстом помилки, а не негативний
// результат: перевірка не відбулася.
func TestAScriptThatRaisesIsNamedAndClaimsNoVerdict(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("this machine has no node")
	}
	document := `
id: js-raises
info:
  name: a script that throws
  severity: info
javascript:
  - code: |
      throw new Error("the target refused the token");
    matchers:
      - type: word
        part: response
        words:
          - anything
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if run.Matched {
		t.Fatal("a script that threw reported a finding")
	}
	if !strings.Contains(run.Reason, "the target refused the token") {
		t.Fatalf("the script's own message was not reported: %q", run.Reason)
	}
}

// Протокольна бібліотека nuclei — це не дрібниця. Шаблон, що її вимагає, має
// право знати, чому він не виконаний, і має бути відмовлений, а не запущений без
// неї: `require` у такому середовищі просто впаде, і повідомлення про падіння
// сказало б про щось інше.
func TestAScriptNeedingANucleiProtocolModuleIsRefusedByName(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("this machine has no node")
	}
	document := `
id: js-needs-net
info:
  name: a script needing nuclei's own protocol library
  severity: info
javascript:
  - code: |
      const net = require("nuclei/net");
      net.sendRequest({url: "http://example/"});
    matchers:
      - type: word
        part: response
        words:
          - anything
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if run.Matched {
		t.Fatal("a script needing a nuclei module reported a finding")
	}
	if !strings.Contains(run.Reason, "nuclei/net") {
		t.Fatalf("the module the script needs was not named: %q", run.Reason)
	}
	if !run.Skipped {
		t.Fatalf("a refused script was reported as a check that ran: %+v", run)
	}
}
