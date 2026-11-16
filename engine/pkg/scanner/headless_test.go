package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// `headless:` — 222 документи корпусу.
//
// Ці тести потребують **справжнього браузера**: значення, звірене з шаблоном,
// мешкає в `alert()`, яку викликає код сторінки. Обхід, який повертає DOM, його
// не бачить, а мок відповіді worker'а погодився б із тим, що діалогу не було.
//
// Тому тест пропускається, коли worker не запущено, і **ніколи** не підміняє
// браузер моком: зелений тест на мку тут довів би не більше, ніж те, що рядок
// правильно розбирається.

const headlessFixture = `<!doctype html><html><body><h1>probe page</h1>
<script>
setTimeout(function () {
  alert("reflected-" + location.search.replace(/^\?/, ""));
}, 100);
</script>
</body></html>
`

// headlessWorkerFixture serves the dialog-firing page over loopback HTTP.
func headlessWorkerFixture(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(headlessFixture))
	}))
	t.Cleanup(server.Close)
	return server
}

// requireHeadlessWorker skips when the project's browser worker cannot answer a
// probe from here.
//
// The worker is not running, or the browser cannot start. Either way this is an
// environment fact rather than a defect, and a test that failed on it would be
// reporting someone else's configuration — so it skips with the reason named.
//
// (There used to be a second skip reason here: a worker that answered 403 because
// the caller's environment lacked `RR_INTERNAL_API_KEY`. That check no longer
// exists, so the branch went with it.)
//
// The logic under test is still covered without a browser by the tests below that
// build a `headlessProbe` by hand, so a skip here costs liveness, not coverage.
func requireHeadlessWorker(t *testing.T) string {
	t.Helper()
	worker := headlessWorkerURL()
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(worker + "/health")
	if err != nil {
		t.Skipf("the browser worker at %s is not answering (%v); `headless:` cannot be exercised here",
			worker, err)
	}
	_ = response.Body.Close()
	if headlessProbeOnceName() != "ok" {
		t.Skipf("the browser worker at %s does not answer a probe from here", worker)
	}
	return worker
}

// headlessProbeOnceName asks the worker whether it would answer, and says which
// reason it would not.
func headlessProbeOnceName() string {
	_, reason := headlessProbeOnce(context.Background(), headlessWorkerURL(),
		"http://127.0.0.1:1/", nil)
	switch {
	case reason == "":
		return "ok"
	case strings.Contains(reason, "403"):
		return "missing-key"
	default:
		return "unreachable"
	}
}

// Мутація: діалог не захоплюється — блок не має чим замінити `reflected_message`.
func TestTheCapturedDialogTextBecomesTheNamedPart(t *testing.T) {
	requireHeadlessWorker(t)
	page := headlessWorkerFixture(t)
	// The whole query string is echoed, not one named parameter: this runner appends
	// the fuzz value to the URL as the query, so a fixture reading a parameter *name*
	// would see nothing and report a dialog the document never asked about.
	document := `
id: headless-dialog
info:
  name: a page that reflects into an alert
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "marker-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - reflected == true
          - contains(reflected_message, "marker-")
        condition: and
`
	run := RunTemplateLocally(context.Background(), document, page.URL, http.DefaultTransport)

	if run.Reason != "" {
		t.Fatalf("a headless block was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the page fired alert(reflected-marker-0) and the block did not match: %q / %q",
			run.Reason, run.Response)
	}
}

// `{{num}}` — лічильник спроби. Якщо він не підставляється, `…_message == num` не
// може збігтися, а блок мовчки перетворюється на завжди-негативний.
func TestTheFuzzNumberReachesThePayloadAndTheDSL(t *testing.T) {
	requireHeadlessWorker(t)
	page := headlessWorkerFixture(t)
	document := `
id: headless-number
info:
  name: the payload's own attempt number comes back
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "num-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - reflected == true
          - contains(reflected_message, "reflected-num-")
        condition: and
`
	run := RunTemplateLocally(context.Background(), document, page.URL, http.DefaultTransport)

	if !run.Matched {
		t.Fatalf("the attempt number never reached the dialog text: %q / %q", run.Reason, run.Response)
	}
}

// Браузер, якого немає, — це відмова з назвою, а не негативний результат.
func TestAHeadlessBlockWithoutTheBrowserIsRefusedByName(t *testing.T) {
	document := `
id: headless-no-browser
info:
  name: a headless block with no browser to run it
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "x"
    matchers:
      - type: dsl
        dsl:
          - reflected == true
`
	t.Setenv(headlessWorkerEnv, "http://127.0.0.1:1")

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if run.Matched {
		t.Fatal("a headless block whose browser never answered reported a finding")
	}
	if !run.Skipped {
		t.Fatalf("a headless block that could not run was reported as a check that ran: %+v", run)
	}
	if !strings.Contains(run.Reason, "browser worker") || !strings.Contains(run.Reason, headlessWorkerDefault) &&
		!strings.Contains(run.Reason, "127.0.0.1:1") {
		t.Fatalf("the refusal does not say which browser service was asked for: %q", run.Reason)
	}
}

// Правило, що інструментує в частину, якої немає, називається — інакше оператор
// бачить лише «нічого не збіглося».
func TestAFuzzingPartThisRunnerCannotPerformIsNamed(t *testing.T) {
	document := `
id: headless-part
info:
  name: a fuzzing rule for a part this runner does not perform
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
    fuzzing:
      - part: cookie
        type: postfix
        mode: single
        fuzz:
          - "x"
    matchers:
      - type: dsl
        dsl:
          - "1 == 1"
`
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if !strings.Contains(run.Reason, "cookie") {
		t.Fatalf("the refusal does not name the part it cannot inject into: %q", run.Reason)
	}
}

// Блок без кроку `navigate` не відкриває нічого: казати «нічого не збіглося» про
// ніколи не відкриту сторінку — це негатив для перевірки, якої не було.
func TestABlockWithoutANavigateStepIsRefused(t *testing.T) {
	document := `
id: headless-no-navigate
info:
  name: a block that never says where to go
  severity: info
headless:
  - steps:
      - action: waitdialog
        name: reflected
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "x"
    matchers:
      - type: dsl
        dsl:
          - reflected == true
`
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if !strings.Contains(run.Reason, "navigate") {
		t.Fatalf("the refusal does not say the block names nowhere to go: %q", run.Reason)
	}
}

// Плейсхолдер, якого документ не оголошує, — це відмова з назвою того, що є.
func TestAnUndeclaredPayloadIsNamedWithWhatTheDocumentHas(t *testing.T) {
	document := `
id: headless-undeclared
info:
  name: a fuzzing rule naming a payload the document never declares
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
    payloads:
      declared:
        - "value"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{never_declared}}"
    matchers:
      - type: dsl
        dsl:
          - "1 == 1"
`
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if !strings.Contains(run.Reason, "never_declared") || !strings.Contains(run.Reason, "declared") {
		t.Fatalf("the refusal names neither the missing payload nor what exists: %q", run.Reason)
	}
}

// Доказ у звіті: без діалогу в рядку вердикт не пояснений.
func TestTheTranscriptShowsWhatThePageSaid(t *testing.T) {
	requireHeadlessWorker(t)
	page := headlessWorkerFixture(t)
	document := `
id: headless-transcript
info:
  name: the dialog is kept as evidence
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "evidence-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers:
      - type: dsl
        dsl:
          - reflected == true
`
	run := RunTemplateLocally(context.Background(), document, page.URL, http.DefaultTransport)

	// The transcript is the request side: it says where the browser went and what the
	// page said back. The response side is the DOM, which does not contain the
	// dialog text — an `alert()` is not part of the document, and asserting it there
	// was asserting on the wrong half.
	if !strings.Contains(run.Request, "dialog: reflected-evidence-0") {
		t.Fatalf("the transcript does not carry the dialog the template judged on: %q", run.Request)
	}
}

// Прапорчик діалогу має бути **булевим**, а не словом "true".
//
// Виміряно на виразі, який корпус пише 203 рази (`reflected == true`):
//
//	data["reflected"] = true    → збігається
//	data["reflected"] = "true"  → не збігається взагалі
//
// бо govaluate порівнює параметр із булевим. Рядок робив 203 блоки корпусу
// нездатними спрацювати, і при цьому **жний** тест на них не червонів: матчер
// спрацьовував за замовчуванням `or`, і збіг несли другий вираз — а перший, той
// що і є перевіркою діалогу, мовчки не працював.
//
// Тому цей документ має рівно один вираз і `condition: and`: збіг може принести
// тільки він.
func TestTheNamedDialogFlagIsABoolAndNotTheWordTrue(t *testing.T) {
	requireHeadlessWorker(t)
	page := headlessWorkerFixture(t)
	document := `
id: headless-bool-flag
info:
  name: the dialog flag is a bool
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "flag-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - reflected == true
        condition: and
`
	run := RunTemplateLocally(context.Background(), document, page.URL, http.DefaultTransport)

	if !run.Matched {
		t.Fatalf("a bool dialog flag did not satisfy `reflected == true`: %q / %q",
			run.Reason, run.Request)
	}
}

// `{{num}}` дійшов до діалогу, але DSL порівнює marker, а не слово: якщо число не
// підставилося, `contains` не знайде нічого. Окремий документ і `condition: and`,
// щоб перевірка числа не могла пройти на рахунок першого виразу.
func TestTheAttemptNumberIsVisibleInTheDialogMessageAlone(t *testing.T) {
	requireHeadlessWorker(t)
	page := headlessWorkerFixture(t)
	document := `
id: headless-number-alone
info:
  name: the attempt number alone decides
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "n{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - contains(reflected_message, "reflected-n0")
        condition: and
`
	run := RunTemplateLocally(context.Background(), document, page.URL, http.DefaultTransport)

	if !run.Matched {
		t.Fatalf("the attempt number never reached the dialog message: %q / %q", run.Reason, run.Request)
	}
}

// Тип діалогу: nuclei's `waitdialog` пише `<name>_type`, і на нього може спиратися
// матчер. Наш відповідь має це ім'я.
func TestTheDialogTypeIsReadableAsAPart(t *testing.T) {
	requireHeadlessWorker(t)
	page := headlessWorkerFixture(t)
	document := `
id: headless-dialog-type
info:
  name: the dialog's own type is readable
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "kind-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - reflected_type == "alert"
        condition: and
`
	run := RunTemplateLocally(context.Background(), document, page.URL, http.DefaultTransport)

	if !run.Matched {
		t.Fatalf("the dialog's own type never reached the DSL: %q / %q", run.Reason, run.Request)
	}
}

// --- перевірки без браузера ---------------------------------------------------------
//
// Прапорчик діалогу, повідомлення, тип і транскрипт вирішуються **до** будь-якого
// браузера: `headlessParts` перетворює відповідь на змінні, а далі працює той самий
// `scoreCompiled`, що й для HTTP. Тому виправлення типу доводиться тут, де тест
// не залежить ні від Firefox, ні від ключа воркера.

// headlessProbeOf builds one block whose only named step is a dialog, for scoring
// against a hand-written answer.
const headlessProbeOf = `
id: headless-parts
info:
  name: a dialog the page fired
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "value-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - %s
        condition: and
`

// scoreHeadlessExpression judges one `dsl:` expression against a hand-written
// browser answer.
//
// This is the seam that was wrong: a bool flag versus the string "true" decides
// whether `reflected == true` can fire at all, and a browser cannot be consulted to
// prove which one this runner holds.
func scoreHeadlessExpression(t *testing.T, expression string, answer headlessProbe) bool {
	t.Helper()
	document := fmt.Sprintf(headlessProbeOf, expression)
	// The capability this parser also reports is the *passive band's* admission
	// check, and it refuses a `headless:` document by design — a browser produces a
	// page, not a response to match. These tests bypass the band deliberately: they
	// judge one expression against one hand-written answer, which is the seam that
	// was wrong.
	parsed, _ := parsePassiveDocument(document)
	if parsed == nil || len(parsed.HeadlessBlocks) != 1 {
		t.Fatal("document did not parse into exactly one headless block")
	}
	block := parsed.HeadlessBlocks[0]
	parts, native, transcript := headlessParts(block, answer, headlessFuzz{target: "query"})
	if transcript == "" {
		t.Fatal("the transcript is empty, so nothing here could be evidence")
	}
	exchange := PassiveExchange{
		Method: "HEADLESS", URL: "http://127.0.0.1/", Host: "127.0.0.1",
		RawRequest: transcript, RawResponse: answer.Body, Body: answer.Body,
		StatusCode: answer.Status, Header: http.Header{}, Parts: parts, Native: native,
	}
	return scoreCompiled(parsed, block, exchange).Matched
}

// Мутація: прапорчик пишеться рядком замість булевої — і `reflected == true` не
// спрацьовує ні за якого значення.
func TestTheDialogFlagIsABoolSoTheCorpusExpressionCanFire(t *testing.T) {
	spoken := headlessProbe{Dialog: true, DialogMessage: "reflected-value-0", DialogType: "alert", Status: 200}
	if !scoreHeadlessExpression(t, "reflected == true", spoken) {
		t.Fatal("a bool dialog flag did not satisfy the expression 203 corpus blocks use")
	}
	if scoreHeadlessExpression(t, "reflected == true", headlessProbe{Dialog: false}) {
		t.Fatal("no dialog, and the expression reported a match anyway")
	}
}

// Мутація: `_message` порожній — вираз, що чекає на текст діалогу, не спрацьовує.
func TestTheDialogMessageIsReadableAsAPart(t *testing.T) {
	spoken := headlessProbe{Dialog: true, DialogMessage: "reflected-value-0", DialogType: "alert", Status: 200}
	if !scoreHeadlessExpression(t, `reflected_message == "reflected-value-0"`, spoken) {
		t.Fatal("the dialog's text never reached the DSL")
	}
	if scoreHeadlessExpression(t, `reflected_message == "something-else"`, spoken) {
		t.Fatal("a message the page never spoke satisfied the expression")
	}
}

// Мутація: тип діалогу не пишеться — `reflected_type == "alert"` не спрацьовує.
func TestTheDialogTypeIsReadableAsAPartWithoutABrowser(t *testing.T) {
	spoken := headlessProbe{Dialog: true, DialogMessage: "x", DialogType: "alert", Status: 200}
	if !scoreHeadlessExpression(t, `reflected_type == "alert"`, spoken) {
		t.Fatal("the dialog's own type never reached the DSL")
	}
	other := headlessProbe{Dialog: true, DialogMessage: "x", DialogType: "confirm", Status: 200}
	if scoreHeadlessExpression(t, `reflected_type == "alert"`, other) {
		t.Fatal("a confirm dialog reported itself as an alert")
	}
}

// Доказ у звіті: без діалогу в транскрипті вердикт не пояснений.
func TestTheTranscriptCarriesTheDialogWithoutABrowser(t *testing.T) {
	document := headlessProbeOf
	parsed, _ := parsePassiveDocument(fmt.Sprintf(document, "reflected == true"))
	if parsed == nil || len(parsed.HeadlessBlocks) != 1 {
		t.Fatal("document did not parse into exactly one headless block")
	}
	spoken := headlessProbe{Dialog: true, DialogMessage: "reflected-evidence-0", DialogType: "alert", Status: 200}
	_, _, transcript := headlessParts(parsed.HeadlessBlocks[0], spoken,
		headlessFuzz{target: "query", value: "evidence-0"})
	for _, wanted := range []string{"dialog: reflected-evidence-0", "status: 200", "HEADLESS query"} {
		if !strings.Contains(transcript, wanted) {
			t.Fatalf("the transcript does not carry %q: %q", wanted, transcript)
		}
	}
}

// Блок без `fuzzing:` все одно відкриває сторінку — виміряно 24 з 222 таких у корпусі.
//
// Твердження про відмову, а не про браузер: без браузера блок має відмовитися
// **браузером**, а не «немає чого надсилати». Різниця принципова — перша причина
// каже, що перевірку не виконали, друга що її не на що виконувати, хоча
// `navigate` у блоці є.
func TestABlockWithoutFuzzingStillNavigates(t *testing.T) {
	document := `
id: headless-no-fuzzing
info:
  name: a block that only opens the page and looks at it
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    matchers:
      - type: dsl
        dsl:
          - reflected == true
        condition: and
`
	t.Setenv(headlessWorkerEnv, "http://127.0.0.1:1")

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if strings.Contains(run.Reason, "nothing to send") || strings.Contains(run.Reason, "no `fuzzing:`") {
		t.Fatalf("a block whose only step is `navigate` was refused for having nothing to send: %q", run.Reason)
	}
	if !strings.Contains(run.Reason, "browser worker") {
		t.Fatalf("the refusal does not name the browser it asked for: %q", run.Reason)
	}
}

// `headless(n)` у потоці: індекс має розв'язуватися, і помилковий — називатися.
//
// Без браузера доводиться саме розв'язання: воно й є причиною, з якої 193
// шаблони корпусу відмовлялися.
func TestAFlowHeadlessStepResolvesItsBlockByIndexAndNamesAMissingOne(t *testing.T) {
	document := `
id: flow-headless-step
info:
  name: a flow that drives a browser
  severity: info
flow: |
  headless(1)
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    matchers:
      - type: dsl
        dsl:
          - reflected == true
        condition: and
`
	t.Setenv(headlessWorkerEnv, "http://127.0.0.1:1")

	// The flow calls the browser step and nothing else: an `http(1)` in front would
	// fail on the unreachable target first, and the headless step would never be
	// reached — so the test would pass for the wrong reason.
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if strings.Contains(run.Reason, "performs http, code and headless steps") ||
		strings.Contains(run.Reason, `flow calls "headless"`) ||
		strings.Contains(run.Reason, "refers to a block the file does not have") {
		t.Fatalf("a flow step that calls headless is still refused as unperformable: %q", run.Reason)
	}
	if !strings.Contains(run.Reason, "browser worker") {
		t.Fatalf("the step resolved but never reached the browser: %q", run.Reason)
	}

	absent := strings.Replace(document, "headless(1)", "headless(9)", 1)
	run = RunTemplateLocally(context.Background(), absent, "http://127.0.0.1:1/", http.DefaultTransport)
	if !strings.Contains(run.Reason, "declares 1 headless block") {
		t.Fatalf("an index past the end did not say what the document declares: %q", run.Reason)
	}
}

// `concat(…)` будує текст із плейсхолдерів — виміряно на
// `angular-client-side-template-injection.yaml`, чий payload є
// `{{concat("{{", "{{first}}*{{second}}", "}}")}}`, а на виході має бути
// `{{<first>*<second>}}` для сторінки Angular.
//
// Мутація: аргументи не склеюються.
func TestConcatBuildsTheTextOutOfTheResolvedPayloads(t *testing.T) {
	payloads := map[string][]string{
		"first":  {"firstValue"},
		"second": {"secondValue"},
	}
	raw := `{{concat("{{", "{{first}}*{{second}}", "}}")}}`

	value, missing := expandHeadlessPayload(raw, payloads, 0)

	if len(missing) > 0 {
		t.Fatalf("a declared payload was reported undeclared: %v", missing)
	}
	if value != "{{firstValue*secondValue}}" {
		t.Fatalf("concat built %q, want %q", value, "{{firstValue*secondValue}}")
	}
}

// Порядок перевірки має бути «спершу неоголошені, потім concat»: результат
// склеювання навмисно містить дужки, і перевірка після нього назвала б його
// неоголошеним плейсхолдером.
func TestAConcatenationResultIsNotMistakenForAnUndeclaredPlaceholder(t *testing.T) {
	// `first` is declared here too, so the argument's `{{first}}` is substituted and
	// the concatenation builds `{{firstValue}}` — text whose braces are the point.
	payloads := map[string][]string{
		"payload": {`{{concat("{{", "{{first}}", "}}")}}`},
		"first":   {"firstValue"},
	}

	value, missing := expandHeadlessPayload("{{payload}}", payloads, 0)

	if len(missing) > 0 {
		t.Fatalf("a complete document was refused for an undeclared placeholder: %v", missing)
	}
	if value != "{{firstValue}}" {
		t.Fatalf("got %q, want %q", value, "{{firstValue}}")
	}
}

// Незакритий `concat(` — це відмова з назвою, а не мовчкизрізаний рядок.
func TestAnUnclosedConcatIsNamed(t *testing.T) {
	_, missing := expandHeadlessPayload(`{{concat("a", "b"`, map[string][]string{}, 0)

	if len(missing) == 0 {
		t.Fatal("an unclosed concat was accepted silently")
	}
	if !strings.Contains(missing[0], "not closed") {
		t.Fatalf("the refusal does not say what is wrong: %v", missing)
	}
}

// Порядок підстановки не має бути випадковим.
//
// Три рівні залежності, оголошені у зворотному алфавітному порядку, тому одна
// відсоротована прохід не встигає: `outer` вставляє `{{middle}}` після того, як
// `middle` уже оброблено. Мутація — перейти на порядок мапи або на одну прохід.
func TestAPayloadNamingAnotherPayloadResolvesInEitherDeclarationOrder(t *testing.T) {
	payloads := map[string][]string{
		"outer":  {"{{middle}}!"},
		"middle": {"{{inner}}?"},
		"inner":  {"leaf"},
	}

	value, missing := expandHeadlessPayload("{{outer}}", payloads, 0)

	if len(missing) > 0 {
		t.Fatalf("three declared levels were reported undeclared: %v", missing)
	}
	if value != "leaf?!" {
		t.Fatalf("nested payloads resolved to %q, want %q", value, "leaf?!")
	}
}

// `{{url_encode(name)}}` називає **имя** payload, а не `url_encode(name)`.
//
// Виміряно: через цю різницю відмовлялися **192 з 222** блоків корпусу — усі вони
// оголошують `injection`, і всі їхні fuzz-значення є `{{url_encode(injection)}}`.
func TestTheUrlEncodeHelperNamesThePayloadItWraps(t *testing.T) {
	payloads := map[string][]string{"injection": {"a value"}}

	if missing := headlessUndeclaredNames("{{url_encode(injection)}}", payloads); len(missing) > 0 {
		t.Fatalf("a declared payload was reported undeclared through url_encode: %v", missing)
	}
	value, missing := expandHeadlessPayload("{{url_encode(injection)}}", payloads, 0)
	if len(missing) > 0 {
		t.Fatalf("expansion reported %v", missing)
	}
	if value != url.QueryEscape("a value") {
		t.Fatalf("url_encode produced %q, want %q", value, url.QueryEscape("a value"))
	}
}

// Порожнє ім'я — це не ім'я: `{{}}` не є оголошеним payload.
func TestAnEmptyPlaceholderIsNotAPayloadName(t *testing.T) {
	if missing := headlessUndeclaredNames("{{}}", map[string][]string{}); len(missing) > 0 {
		t.Fatalf("an empty placeholder was reported as a payload: %v", missing)
	}
}

// Перевірка, яка **виконана** і нічого не знайшла, — це негативний результат, а не
// відмова.
//
// Виміряно: блок, що виконався, позначавався `skipped` з реченням «ran and matched
// nothing», тобто «не виконано», хоча браузер відкрив сторінку, діалог дочекалися
// і DSL спрацював. 25 з 222 блоків корпусу поверталися саме так.
func TestABlockThatRanAndFoundNothingIsANegativeNotARefusal(t *testing.T) {
	if headlessNegativeSaysSkipped() {
		t.Fatal("a block that ran and found nothing still claims it was not performed")
	}
	// And the browser's own refusal must survive: a block that never ran is still a
	// refusal, and this must not have swallowed it.
	t.Setenv(headlessWorkerEnv, "http://127.0.0.1:1")
	document := `
id: headless-no-browser-negative
info:
  name: a block whose browser is absent
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "nothing-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers:
      - type: dsl
        dsl:
          - reflected == true
        condition: and
`
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)

	if !run.Skipped || !strings.Contains(run.Reason, "browser worker") {
		t.Fatalf("a block that never ran stopped being a refusal: %+v", run)
	}
}

// headlessNegativeSway says whether the executor marks a clean negative as skipped.
func headlessNegativeSaysSkipped() bool {
	document := `
id: headless-negative-skip
info:
  name: whether a clean negative claims to be a skip
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
    matchers:
      - type: word
        part: body
        words:
          - a-word-this-page-never-contains
`
	parsed, _ := parsePassiveDocument(document)
	if parsed == nil || len(parsed.HeadlessBlocks) != 1 {
		return false
	}
	// Scored directly, with no browser: what is under test is the verdict the
	// executor attaches to a block that ran.
	parts, native, transcript := headlessParts(parsed.HeadlessBlocks[0],
		headlessProbe{Status: 200, Body: "<html></html>"}, headlessFuzz{target: "none"})
	exchange := PassiveExchange{
		Method: "HEADLESS", URL: "http://127.0.0.1/", Host: "127.0.0.1",
		RawRequest: transcript, RawResponse: "<html></html>", Body: "<html></html>",
		StatusCode: 200, Header: http.Header{}, Parts: parts, Native: native,
	}
	verdict := scoreCompiled(parsed, parsed.HeadlessBlocks[0], exchange)
	return verdict.Reason != ""
}

// --- перевірка на межі з браузером ---------------------------------------------------
//
// Тести нижче відповідають на `/headless/probe` **стабом**, а не браузером. Це
// подібно до `countingTransport` для HTTP: доводиться шар, який приймає відповідь і
// виносить вердикт, тоді як сам браузер доведено окремим виміром ендпойнта.
//
// Стаб **не** замінює браузерні тести вище: він не бачить сторінки.

// headlessProbeStub answers `/headless/probe` with one fixed answer.
func headlessProbeStub(t *testing.T, answer headlessProbe) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(server.Close)
	t.Setenv(headlessWorkerEnv, server.URL)
	return server.URL
}

const headlessNegativeDocument = `
id: headless-stub-negative
info:
  name: a block whose browser saw no dialog
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/probe"
      - action: waitdialog
        name: reflected
    payloads:
      injection:
        - "nothing-{{num}}"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{url_encode(injection)}}"
    matchers:
      - type: dsl
        dsl:
          - reflected == true
        condition: and
`

// Мутація: негатив знову позначається як відмова — рядок читається як «не виконано».
func TestABlockWhoseBrowserSawNothingIsReportedAsANegative(t *testing.T) {
	headlessProbeStub(t, headlessProbe{Dialog: false, Status: 200, Body: "<html></html>"})

	run := RunTemplateLocally(context.Background(), headlessNegativeDocument,
		"http://127.0.0.1/", http.DefaultTransport)

	if run.Reason != "" || run.Skipped {
		t.Fatalf("a check that ran to the end was reported as something else: %+v", run)
	}
	if run.Matched {
		t.Fatal("a page with no dialog reported a finding")
	}
	if !strings.Contains(run.Request, "dialog: none") {
		t.Fatalf("the transcript does not say the page stayed silent: %q", run.Request)
	}
}

// Той самий шлях, коли діалог був: вердикт має бути позитивним, і рядок — доказ.
func TestABlockWhoseBrowserSpokeIsReportedAsAMatch(t *testing.T) {
	headlessProbeStub(t, headlessProbe{
		Dialog: true, DialogMessage: "reflected-nothing-0", DialogType: "alert",
		Status: 200, Body: "<html></html>",
	})

	run := RunTemplateLocally(context.Background(), headlessNegativeDocument,
		"http://127.0.0.1/", http.DefaultTransport)

	if !run.Matched {
		t.Fatalf("the stub's dialog did not satisfy the matcher: %+v", run)
	}
	if !strings.Contains(run.Request, "dialog: reflected-nothing-0") {
		t.Fatalf("the transcript does not carry the dialog: %q", run.Request)
	}
}

// Браузер, який не відповів, — це відмова, і її reason має називати браузер.
func TestAWorkerThatDoesNotAnswerIsARefusalByName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"the browser never started"}`))
	}))
	defer server.Close()
	t.Setenv(headlessWorkerEnv, server.URL)

	run := RunTemplateLocally(context.Background(), headlessNegativeDocument,
		"http://127.0.0.1/", http.DefaultTransport)

	if !run.Skipped || !strings.Contains(run.Reason, "browser worker") {
		t.Fatalf("a worker that failed is not a named refusal: %+v", run)
	}
}

// `status_code` у DSL-карті має бути **числом**, а не текстом.
//
// Nuclei пише `data["status_code"] = resp.StatusCode` — `int`
// (`pkg/protocols/http/operators.go:125`). Я виміряв це, склавши `data` руками з
// рядком `"200"`, і дійшов висновку, що вираз не працює — насправді не працював
// **харнес**, а не продукт. Цей тест іде через справжній шлях: `scoreCompiled`
// з реальним обміном.
//
// Числове порівняння зустрічається у **2107** шаблонах корпусу, тож тип тут не
// дріниця.
func TestStatusCodeIsANumberInTheDslMap(t *testing.T) {
	for _, expression := range []string{"status_code == 200", "status_code != 404", "status_code >= 200"} {
		document := "id: s\ninfo:\n  name: s\n  severity: info\nhttp:\n  - method: GET\n    path:\n" +
			"      - \"{{BaseURL}}/\"\n    matchers:\n      - type: dsl\n        dsl:\n          - '" + expression + "'\n"
		parsed, _ := parsePassiveDocument(document)
		if parsed == nil || len(parsed.HTTP) != 1 {
			t.Fatalf("%s: не розібрано", expression)
		}
		block := parsed.HTTP[0]
		if capability := block.Compile(); capability != nil {
			t.Fatalf("%s: compile %v", expression, capability)
		}
		exchange := PassiveExchange{
			Method: "GET", URL: "http://127.0.0.1/", Host: "127.0.0.1",
			RawRequest: "GET / HTTP/1.1", RawResponse: "HTTP/1.1 200 OK", Body: "hello",
			StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}},
			Parts: map[string]string{"body": "hello"},
		}
		verdict := scoreCompiled(parsed, block, exchange)
		if !verdict.Matched {
			t.Fatalf("`%s` did not match a 200 response: %s", expression, verdict.Reason)
		}
	}
}
