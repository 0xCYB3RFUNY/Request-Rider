package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// `code:` — 967 документів офіційного корпусу. Ці тести пишуться разом із
// виконавцем, і кожен із них має почервоніти, коли його правку відкотити.
//
// Рухачі виміряні на корпусі: sh 1734, bash 53, py 28, ruby 1, rb 1, php 1,
// powershell 1. Тести нижче беруть `sh`, бо він є на машині, де їх прогонять, а
// решта потрапляє в ту саму таблицю інтерпретаторів.

const codeEchoTemplate = `
id: code-echo
info:
  name: code block whose stdout is matched
  severity: info
code:
  - engine:
      - sh
    source: |
      echo "found-the-marker"
    matchers:
      - type: word
        part: stdout
        words:
          - "found-the-marker"
`

// The document ran, the script's stdout reached the matcher, and the verdict says
// so. Without this the whole protocol could be a no-op that reports `not_matched`
// forever and still look like an honest negative.
func TestACodeBlockRunsAndItsStdoutDecidesTheMatch(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh, so the code: protocol cannot be exercised here")
	}
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), codeEchoTemplate, "http://127.0.0.1:1/", transport)

	if !run.Matched {
		t.Fatalf("the script printed the word its matcher looks for, so the template matched nothing: %q", run.Reason)
	}
	if !strings.Contains(run.Response, "found-the-marker") {
		t.Fatalf("the verdict has no evidence of what the script printed: %q", run.Response)
	}
	if transport.count() != 0 {
		t.Fatalf("a code-only document sent %d request(s); it should send none", transport.count())
	}
}

// `engine:` має дві форми в корпусі, і жодна з них не може бути відкинута як
// «не той тип»:
//
//	engine:            engine:
//	  - sh               sh: "id"
//
// Коли типізація приймала лише список, документи з відображенням падали в
// «invalid YAML» — і тест на відмову, що називає протокол, падав разом із ними.
// Мутація: прибрати гілку MappingNode з `codeEngines.UnmarshalYAML`.
func TestTheMappingSpellingOfEngineIsExecutedToo(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: code-map-engine
info:
  name: engine written as a mapping
  severity: info
code:
  - engine:
      sh: "id"
    source: |
      echo mapped-form-ran
    matchers:
      - type: word
        part: stdout
        words:
          - mapped-form-ran
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if strings.Contains(run.Reason, "invalid YAML") || strings.Contains(run.Reason, "unmarshal") {
		t.Fatalf("engine written as a mapping was rejected as malformed: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the mapping spelling did not run: %q", run.Reason)
	}
}

// A script that fails has produced no verdict, and the run must say which failure
// rather than reporting a clean `not_matched` as if the check had happened.
func TestAFailingScriptIsNamedAndClaimsNoVerdict(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: code-failing
info:
  name: script that exits non-zero
  severity: info
code:
  - engine:
      - sh
    source: |
      echo partial-output
      exit 7
    matchers:
      - type: word
        part: stdout
        words:
          - never-printed
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if run.Matched {
		t.Fatal("a script that failed reported a match")
	}
	if !strings.Contains(run.Reason, "failed") {
		t.Fatalf("a failing script did not say so: %q", run.Reason)
	}
	if !strings.Contains(run.Response, "partial-output") && !strings.Contains(run.Request, "partial-output") {
		t.Fatalf("what the script did print before failing was thrown away: %q / %q",
			run.Response, run.Request)
	}
}

// A script that never returns must be named by its deadline rather than hanging the
// run forever — and the deadline must be the one the template wrote, because a
// template that knows its own runtime keeps that answer.
func TestAScriptThatNeverFinishesIsNamedByItsDeadline(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: code-hanging
info:
  name: script that never returns
  severity: info
code:
  - engine:
      - sh
    timeout: 1
    source: |
      sleep 30
    matchers:
      - type: word
        part: stdout
        words:
          - never
`
	transport := &countingTransport{inner: http.DefaultTransport}

	started := time.Now()
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)
	elapsed := time.Since(started)

	if run.Matched {
		t.Fatal("a script that never finished reported a match")
	}
	if !strings.Contains(run.Reason, "RR_CODE_TIMEOUT_SEC") {
		t.Fatalf("the deadline was not named, nor the way to raise it: %q", run.Reason)
	}
	// The bound itself is the assertion, not the wording above. The script sleeps
	// thirty seconds and the template allows one, so a run that reports the
	// deadline while still taking thirty has not honoured it.
	//
	// This is the assertion that covers `WaitDelay`: killing the interpreter
	// leaves its child holding the output pipe, so without a bound on the wait
	// after the kill the run ends when the *script* decides, not when the
	// deadline says. Measured: 30.0 s with the reason spelled correctly, and the
	// reason alone would have read as a pass.
	if elapsed > 10*time.Second {
		t.Fatalf("the deadline was reported but the run took %s; the script's own 30 s runtime won", elapsed)
	}
}

// Це тест на 14 документів корпусу, які мають і `http:`, і `code:`.
//
// Раніше `code:` повертався раніше за фазу запитів, і їхні запити зникали
// мовчки: 953 документи лише з `code:` виглядали правильно, а 14 змішаних
// втрачали половину своєї роботи без рядка в звіті. Мутація: повернути ранній
// вихід перед `allPassiveRequests`.
func TestARequestBlockIsNotDroppedByTheCodePhase(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nothing here"))
	}))
	defer server.Close()
	document := `
id: mixed-http-and-code
info:
  name: a request beside a script
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
code:
  - engine:
      - sh
    source: |
      echo code-phase-ran
    matchers:
      - type: word
        part: stdout
        words:
          - never-printed-here
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if transport.count() != 1 {
		t.Fatalf("a document with one `http:` and one `code:` block sent %d request(s); the request "+
			"block was dropped by the code phase", transport.count())
	}
	// Asserted on the evidence, not on the wording of the reason: the script's own
	// output has to be in the run for the code phase to have happened.
	if !strings.Contains(run.Response, "code-phase-ran") {
		t.Fatalf("the code phase did not run: %q", run.Reason)
	}
}

// Порядок «запити, потім скрипт» — це не припущення, а те, що робить змішані
// документи корисними: скрипт читає ім'я, яке попередній блок видобув.
// Якщо `code:` виконується першим, `{{token}}` не існує і скрипт друкує
// порожнечу, а шаблон мовчки не збігається.
func TestCodeRunsAfterTheRequestSoItCanReadWhatTheRequestExtracted(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok TOKEN-abc123"))
	}))
	defer server.Close()
	document := `
id: mixed-token-into-script
info:
  name: the script reads what the request extracted
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    extractors:
      - type: regex
        name: token
        part: body
        regex:
          - "TOKEN-(\\w+)"
    matchers:
      - type: word
        part: body
        words:
          - TOKEN
code:
  - engine:
      - sh
    source: |
      echo "token-is-{{token}}"
    matchers:
      - type: word
        part: stdout
        words:
          - "token-is-abc123"
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if !run.Matched {
		t.Fatalf("the script never saw the extracted token, so the document reported nothing: %q / %q",
			run.Reason, run.Response)
	}
}

// Мутація: прибрати `if !strings.Contains(merged, engine)` і перетворити
// прибирання на доказ.
func TestNoEngineMeansNoRunRatherThanAGuess(t *testing.T) {
	document := `
id: code-no-engine
info:
  name: a code block that names no interpreter
  severity: info
code:
  - source: |
      echo hello
    matchers:
      - type: word
        part: stdout
        words:
          - hello
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if run.Matched {
		t.Fatal("a code block with no engine reported a match")
	}
	if !strings.Contains(run.Reason, "engine") {
		t.Fatalf("the missing engine was not named: %q", run.Reason)
	}
}

// `code: true` — форма, якою корпус вмикає протокол, не оголошуючи блоків.
// Виміряно на `code/cves/2025`: таких шаблонів 10 із 500 вибірки, і кожен падав
// у «invalid YAML» — скарга на форму ключа, а не на дії шаблону. Мутація:
// повернути `CodeBlocks []passiveRequest`.
func TestABareCodeTrueDoesNotMakeTheDocumentUnreadable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nothing here"))
	}))
	defer server.Close()
	document := `
id: code-enabled-by-flag
info:
  name: protocol switched on without blocks
  severity: info
code: true
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if strings.Contains(run.Reason, "invalid YAML") || strings.Contains(run.Reason, "unmarshal") {
		t.Fatalf("a document writing `code: true` was rejected as malformed: %s", run.Reason)
	}
	if transport.count() != 1 {
		t.Fatalf("`code: true` cost the document its only request: %d sent, reason %q",
			transport.count(), run.Reason)
	}
}

// Відмова — це не відсутність збігу. Виміряно: 434 із 500 `code:`-шаблонів корпусу
// несуть `flow:`, який цей раннер не читає, і кожен раніше потрапляв у
// `not_matched` — тобто звіт про перевірку, якої не було. Мутація: зняти
// `run.Skipped = true` у `runFlow`.
func TestADocumentWhoseFlowCannotBeReadIsSkippedRatherThanNegative(t *testing.T) {
	document := `
id: flow-this-runner-cannot-read
info:
  name: flow written in javascript
  severity: info
flow: for(let i of urls){ sendRequest(...) }
http:
  - method: GET
    path:
      - "{{BaseURL}}/one"
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if !run.Skipped {
		t.Fatalf("a document whose flow could not be read reported itself as a check that ran: %+v", run)
	}
	if run.Matched {
		t.Fatal("a document whose flow could not be read reported a match")
	}
}

// Сверка з оригіналом: nuclei передає скрипт файлом, а не вводом.
//
//	виміряно на v3.11.1:
//	failed to exec command got: /tmp/nuclei-tmp-1096024597/2915071191: 1: az: not found
//
// На трьох шаблонах, де `az` не встановлено, обидва способи дають
// `exit status 127`, тобто вердикт той самий. Різниця в іншому: через stdin у
// скрипта немає власного імені файлу, тому `$0` і шляхи від нього вказують не
// туди. Скрипт, який читає себе, у оригіналі працював би, а тут — мовчки ні.
// Мутація: повернути `command.Stdin` без аргументу-файлу.
func TestTheScriptRunsAsAFileSoItCanNameItself(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: code-reads-its-own-name
info:
  name: the script reads $0
  severity: info
code:
  - engine:
      - sh
    source: |
      case "$0" in
        */script.sh) echo "the-script-has-a-file" ;;
        *)          echo "no-file-name: $0" ;;
      esac
    matchers:
      - type: word
        part: stdout
        words:
          - the-script-has-a-file
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if !run.Matched {
		t.Fatalf("a script that names itself found no file to name: %q / %q", run.Reason, run.Response)
	}
}

// Сценарій, покладений у тимчасову теку, не залишається на диску — інакше кожен
// прогін лишив би у /tmp текст стороннього шаблону. Мутація: прибрати `defer
// os.Remove`.
func TestTheStagedScriptIsRemovedAfterTheRun(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: code-cleanup
info:
  name: staging is cleaned up
  severity: info
code:
  - engine:
      - sh
    source: |
      echo "$0" > /tmp/opencode/last-script-path.txt
      echo done
    matchers:
      - type: word
        part: stdout
        words:
          - done
`
	transport := &countingTransport{inner: http.DefaultTransport}

	RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	staged, err := os.ReadFile("/tmp/opencode/last-script-path.txt")
	if err != nil {
		t.Fatalf("the script did not report its own path, so the cleanup cannot be checked: %v", err)
	}
	if _, err := os.Stat(strings.TrimSpace(string(staged))); !os.IsNotExist(err) {
		t.Fatalf("the staged script is still on disk at %s", strings.TrimSpace(string(staged)))
	}
}
