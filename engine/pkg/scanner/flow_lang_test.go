package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// `flow:` виміряний на корпусі: 1 268 виразів читались і без мови, 1 684 — з нею.
// Різниця — це `for`, `if`, `set()`, `;`, коментарі та змінна циклу. Ці тести
// пишуться на кожну з цих конструкцій, і кожен має почервоніти, коли його правку
// відкотити.

// loopFixture answers every request and echoes back what path it was asked for, so
// a test can see which branch the flow actually took.
func loopFixture() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("path=" + r.URL.Path))
	}))
}

// loopDocument writes a two-block template: block 1 extracts two paths, block 2
// echoes one of them back, which is the shape `iterate()` exists for.
func loopDocument(flow string, secondPath string) string {
	// The flow body is indented under `flow: |`. Writing it flush against column
	// zero produced `yaml: line 6: could not find expected ':'` and every test in
	// this file failed on its own document rather than on the loop.
	var indented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(flow, "\n"), "\n") {
		indented.WriteString("  " + line + "\n")
	}
	return "id: flow-loop\ninfo:\n  name: flow loop\n  severity: info\nflow: |\n" + indented.String() +
		"http:\n" +
		"  - method: GET\n    path:\n      - \"{{BaseURL}}/detect\"\n" +
		"    extractors:\n      - type: regex\n        name: found\n        part: body\n        regex:\n" +
		"          - \"/first\"\n          - \"/second\"\n" +
		"    matchers:\n      - type: word\n        part: body\n        words:\n          - /first\n" +
		"  - method: GET\n    path:\n      - \"{{BaseURL}}" + secondPath + "\"\n" +
		"    matchers:\n      - type: word\n        part: body\n        words:\n          - path=\n"
}

// Мутація: прибрати розбір `for`.
func TestALoopWalksEveryExtractedValueAndTheLastOneIsWhatTheRequestSends(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	// Block 1 answers with both markers, so `found` extracts two values.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/detect" {
			_, _ = w.Write([]byte("/first and /second"))
			return
		}
		_, _ = w.Write([]byte("path=" + r.URL.Path))
	})
	document := loopDocument(`http(1)
for (let item of iterate(template["found"])) {
  path = item
  http(2)
}`, "{{path}}")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow with a loop was refused: %s", run.Reason)
	}
	if transport.count() != 3 {
		t.Fatalf("a loop over two values sent %d request(s); want the detection and one per value", transport.count())
	}
	// Both values walked, so the second block was asked for each of them, and the
	// last assignment is what the request carried.
	sawSecond := false
	for _, request := range transport.seen {
		if request.URL.Path == "/second" {
			sawSecond = true
		}
	}
	if !sawSecond {
		t.Fatalf("the loop walked %d values but never asked the second block for /second: %v",
			transport.count(), pathsOf(transport))
	}
}

func pathsOf(transport *countingTransport) []string {
	var out []string
	for _, request := range transport.seen {
		out = append(out, request.URL.Path)
	}
	return out
}

// Мутація: прибрати `break` — тоді цикл не зупиняється на першому значенні.
func TestBreakStopsTheLoopAtTheFirstValue(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/detect" {
			_, _ = w.Write([]byte("/first and /second"))
			return
		}
		_, _ = w.Write([]byte("path=" + r.URL.Path))
	})
	document := loopDocument(`http(1)
for (let item of iterate(template["found"])) {
  path = item
  http(2)
  break
}`, "{{path}}")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow with `break` was refused: %s", run.Reason)
	}
	if transport.count() != 2 {
		t.Fatalf("`break` on the first value still produced %d request(s); want the detection and one value",
			transport.count())
	}
}

// Мутація: прибрати `if` — тоді гілка виконується незалежно від умови.
func TestAGuardDecidesWhetherTheBodyRunsAtAll(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	document := loopDocument(`http(1)
if (template["absent"]) {
  http(2)
}`, "/second")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if transport.count() != 1 {
		t.Fatalf("a guard over a name nothing extracted still sent %d request(s); want only the detection",
			transport.count())
	}
	if run.Reason != "" {
		t.Fatalf("a flow whose guard simply did not hold was reported as a problem: %s", run.Reason)
	}
}

// Мутація: вимкнути читання змінної циклу.
func TestTheLoopVariableIsReadableByTheBody(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/detect" {
			_, _ = w.Write([]byte("/first and /second"))
			return
		}
		_, _ = w.Write([]byte("path=" + r.URL.Path))
	})
	document := loopDocument(`http(1)
for (let item of iterate(template["found"])) {
  path = item
  http(2)
}`, "{{path}}")
	transport := &countingTransport{inner: http.DefaultTransport}

	RunTemplateLocally(context.Background(), document, server.URL, transport)

	for _, request := range transport.seen {
		if request.URL.Path == "/first" || request.URL.Path == "/second" {
			return
		}
	}
	t.Fatalf("the loop variable never reached the request; asked for %v", pathsOf(transport))
}

// `set("name", value)` — перший рядок тіла циклу в хмарних шаблонах корпусу:
// `for (let B of iterate(template.buckets)) { set("bucket", B); … }`
func TestSetHandsTheLoopVariableToTheNextBlock(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/detect" {
			_, _ = w.Write([]byte("/first and /second"))
			return
		}
		_, _ = w.Write([]byte("path=" + r.URL.Path))
	})
	document := loopDocument(`http(1)
for (let item of iterate(template["found"])) {
  set("where", item)
  http(2)
}`, "{{where}}")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow using `set` was refused: %s", run.Reason)
	}
	for _, request := range transport.seen {
		if request.URL.Path == "/first" || request.URL.Path == "/second" {
			return
		}
	}
	t.Fatalf("`set` did not reach the next block; asked for %v", pathsOf(transport))
}

// Роздільники `;` і коментарі `//` — виміряно: коментарем шаблон пояснює власні
// кроки, тож парсер, що спиняється на `//`, відмовить шаблон, логіку якого він
// прочитав би досконало.
func TestSemicolonsAndCommentsAreReadRatherThanRefused(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	document := loopDocument(`// 1) find the admin path
http(1);

// 2) ask the second block about it
http(2);`, "/second")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow written with comments and semicolons was refused: %s", run.Reason)
	}
	if transport.count() != 2 {
		t.Fatalf("a two-step flow sent %d request(s)", transport.count())
	}
}

// Найважливіша межа: цикл бачить **усі** значення, а запит — лише одне.
//
// `singleValuedExtractions` відкидає ім'я, що збіглося кілька разів, інакше на
// дроті з'явився б текст, якого шаблон не писав. `iterate()` має ходити списком,
// але жоден запит не повинен отримати список. Мутація: злити `ExtractLists` назад у
// `Dynamic`.
func TestALoopSeesEveryValueWhileARequestStillRefusesAnAmbiguousName(t *testing.T) {
	server := loopFixture()
	defer server.Close()
	document := `
id: flow-ambiguous
info:
  name: a request must not carry a name that matched twice
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/one"
    extractors:
      - type: regex
        name: twice
        part: body
        regex:
          - "TOKEN-(\\w+)"
    matchers:
      - type: word
        part: body
        words:
          - TOKEN
  - method: GET
    path:
      - "{{BaseURL}}/{{twice}}"
    matchers:
      - type: word
        part: body
        words:
          - path=
`
	ambiguous := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("TOKEN-aaa TOKEN-bbb"))
	}))
	defer ambiguous.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, ambiguous.URL, transport)

	if !strings.Contains(run.Reason, "twice") {
		t.Fatalf("a request carried a name that matched twice: %q", run.Reason)
	}
	_ = server
}

// `code(n)` у flow — 589 викликів у корпусі, друге місце після `http`.
// Хмарна родина пише `for (let B of iterate(template.buckets)) { set("bucket", B);
// code(1) }`, тож сценарій виконується **після** того, як цикл дав йому значення.
//
// Мутація: прибрати передавання змінних потоку в сценарій.
func TestACodeStepInAFlowRunsAndItsOutputDecidesTheStep(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: flow-code-step
info:
  name: a flow that runs a script
  severity: info
flow: |
  code(1)
code:
  - engine:
      - sh
    source: |
      echo "script-ran"
    matchers:
      - type: word
        part: stdout
        words:
          - script-ran
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if run.Reason != "" {
		t.Fatalf("a flow calling code(1) was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the script printed what its matcher looks for and the step did not match: %q", run.Reason)
	}
	if transport.count() != 0 {
		t.Fatalf("a `code(1)` step sent %d HTTP request(s); it runs a local interpreter", transport.count())
	}
}

// Той самий сценарій, але значення йому дає цикл — і щоб цикл мав що ходити,
// значення спершу **видобуває** блок `http(1)`. Попередня версія цього тесту брала
// `iterate(template["buckets"])` без джерела: список був порожній, цикл не
// виконувався, а вердикт проходив, бо AND порожнього набору істинний. Мутація
// «не передавати змінні в сценарій» такий тест робила зеленим.
func TestACodeStepReadsTheVariableTheLoopBound(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("/prod and /staging"))
	}))
	defer server.Close()
	document := `
id: flow-code-after-loop
info:
  name: the script acts on what the loop bound
  severity: info
flow: |
  http(1)
  for (let name of iterate(template["buckets"])) {
    set("bucket", name)
    code(1)
  }
http:
  - method: GET
    path:
      - "{{BaseURL}}/list"
    extractors:
      - type: regex
        name: buckets
        part: body
        regex:
          - "/prod"
          - "/staging"
    matchers:
      - type: word
        part: body
        words:
          - /prod
code:
  - engine:
      - sh
    source: |
      echo "bound-{{bucket}}"
    matchers:
      - type: word
        part: stdout
        words:
          - bound-/staging
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow running a script inside a loop was refused: %s", run.Reason)
	}
	// The evidence, not the verdict: the script really printed the value the loop
	// bound last. A vacuously-true flow passes the verdict check and fails here.
	if !strings.Contains(run.Response, "bound-/staging") {
		t.Fatalf("the script never saw the value the loop bound: %q / %q", run.Reason, run.Response)
	}
}

// `code(2)` — другий блок `code:`, а не другий блок узагалі. Мутація: брати
// `httpBlocks` для кроку `code`.
func TestCodeStepIndexesTheCodeListNotTheRequestList(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: flow-code-index
info:
  name: code(2) is the second code block
  severity: info
flow: |
  code(2)
code:
  - engine:
      - sh
    source: |
      echo first-block
    matchers:
      - type: word
        part: stdout
        words:
          - never-printed
  - engine:
      - sh
    source: |
      echo second-block
    matchers:
      - type: word
        part: stdout
        words:
          - second-block
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if run.Reason != "" {
		t.Fatalf("a flow calling code(2) was refused: %s", run.Reason)
	}
	if !strings.Contains(run.Response, "second-block") {
		t.Fatalf("code(2) did not run the second code block: %q", run.Response)
	}
}

// Крок, якого в документі немає, називається — а не виконується щось інше.
func TestACodeStepBeyondTheListIsNamed(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	document := `
id: flow-code-missing
info:
  name: a code step the file does not have
  severity: info
flow: |
  code(3)
code:
  - engine:
      - sh
    source: |
      echo only-one
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if !strings.Contains(run.Reason, "code(3)") || !strings.Contains(run.Reason, "1 code block") {
		t.Fatalf("a missing code block was not named: %q", run.Reason)
	}
	if run.Matched {
		t.Fatal("a flow whose step does not exist reported a match")
	}
}

// `http("name")` посилається на блок з `id:` того самого імені — виміряно на 16
// шаблонах корпусу, де поруч стоять `flow: http("version-check")` і
// `- id: version-check`. Читати ім'я як позицію означало б надіслати інший запит
// там, де вони розходяться.
// Мутація: зняти розрізнення за `id:` і читати ім'я як індекс.
func TestANamedStepSendsTheBlockCarryingThatID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from-" + r.URL.Path))
	}))
	defer server.Close()
	document := `
id: flow-named-step
info:
  name: a step named by its id
  severity: info
flow: |
  http("first")
http:
  - id: first
    method: GET
    path:
      - "{{BaseURL}}/the-first-one"
    matchers:
      - type: word
        part: body
        words:
          - from-/the-first-one
  - method: GET
    path:
      - "{{BaseURL}}/the-other-one"
    matchers:
      - type: word
        part: body
        words:
          - from-/the-other-one
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow naming its block by id was refused: %s", run.Reason)
	}
	if transport.count() != 1 {
		t.Fatalf("a named step sent %d request(s); want exactly one", transport.count())
	}
	if got := transport.seen[0].URL.Path; got != "/the-first-one" {
		t.Fatalf("the name resolved to %s instead of the block whose `id:` is `first`", got)
	}
}

// Ім'я, якого в документі немає, називається — і показує, що є.
func TestAStepNamedAfterNothingIsNamedWithWhatTheDocumentHas(t *testing.T) {
	document := `
id: flow-missing-id
info:
  name: a step naming a block that does not exist
  severity: info
flow: |
  http("login")
http:
  - id: auth
    method: GET
    path:
      - "{{BaseURL}}/x"
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", transport)

	if !strings.Contains(run.Reason, `http("login")`) || !strings.Contains(run.Reason, "auth") {
		t.Fatalf("the refusal names neither the missing step nor what exists: %q", run.Reason)
	}
}

// `subnet = JSON.parse(subnet); set("subnetName", subnet.name)` — форма 176
// шаблонів хмарної родини: розпарсений об'єкт читається за полем.
// Мутація: прибрати доступ через `.`
func TestAParsedJsonValueIsReadableByField(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"name":"first-subnet","region":"eu"}]}`))
	}))
	defer server.Close()
	document := `
id: flow-json-field
info:
  name: a parsed value read by field
  severity: info
flow: |
  http(1)
  parsed = JSON.parse(template["body"])
  set("region", parsed.items[0].region)
  code(1)
http:
  - method: GET
    path:
      - "{{BaseURL}}/list"
    extractors:
      - type: regex
        name: body
        part: body
        group: 1
        regex:
          - "(.*)"
    matchers:
      - type: word
        part: body
        words:
          - '"items"'
code:
  - engine:
      - sh
    source: |
      echo "region-is-{{region}}"
    matchers:
      - type: word
        part: stdout
        words:
          - region-is-eu
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a flow parsing JSON and reading a field was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the field never reached the script: %q / %q", run.Reason, run.Response)
	}
}

// `iterate(template.postid)[0]` — 178 шаблонів, найчастіша форма після `for`.
//
// Твердження тут навмисно **не** про те, який саме елемент дістанеться на
// позиції 1. Порядок списку, який повертає екстрактор nuclei, не є порядком
// написання і не стабільний між запусками: виміряно `[/three /one /two]` в одному
// прогоні й `[/one …]` в іншому на тих самих файлах. Тест, що вимагав `/two` на
// індексі 1, падав на правильній поведінці двічі.
//
// Що можна твердити — і треба: індекс застосовується (поза межею він відмовляє
// з назвою розміру списку) і всередині межі дає один з видобутих значень, а не
// весь список.
func TestIterateCanBeIndexedAtItsUse(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("this machine has no /bin/sh")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("/one /two /three"))
	}))
	defer server.Close()
	body := func(pick string) string {
		return `
id: flow-index-iterate
info:
  name: a loop over one element of an extracted list
  severity: info
flow: |
  http(1)
  only = iterate(template["postid"])[` + pick + `]
  code(1)
http:
  - method: GET
    path:
      - "{{BaseURL}}/list"
    extractors:
      - type: regex
        name: postid
        part: body
        regex:
          - "/(one|two|three)"
    matchers:
      - type: word
        part: body
        words:
          - /one
code:
  - engine:
      - sh
    source: |
      echo "picked-{{only}}"
    matchers:
      - type: word
        part: stdout
        words:
          - picked-
`
	}
	transport := &countingTransport{inner: http.DefaultTransport}

	inside := RunTemplateLocally(context.Background(), body("0"), server.URL, transport)
	if inside.Reason != "" {
		t.Fatalf("an index inside the list was refused: %s", inside.Reason)
	}
	picked := ""
	for _, candidate := range []string{"/one", "/two", "/three"} {
		if strings.Contains(inside.Response, "picked-"+candidate) {
			picked = candidate
		}
	}
	if picked == "" {
		t.Fatalf("the index produced none of the extracted values: %q", inside.Response)
	}
	if strings.Contains(inside.Response, "picked-/one /two /three") {
		t.Fatal("the index handed the whole list to the script rather than one element")
	}

	beyond := RunTemplateLocally(context.Background(), body("99"), server.URL, transport)
	if beyond.Matched {
		t.Fatal("an index past the end of the list reported a finding")
	}
	if !strings.Contains(beyond.Reason, "list of") {
		t.Fatalf("an index past the end did not say what the list holds: %q", beyond.Reason)
	}
}

// `template.items` — це те саме ім'я, що `template["items"]`.
//
// Виміряно: `for (let pod of template.items)` є у 6 шаблонах корпусу, і до цього
// воно відмовлялося як «не те, що можна індексувати» — значення `template` несе
// текст, а член на тексті у цих документах і є іменем іншої видобутої величини.
func TestAMemberOnATemplateValueNamesAnotherExtraction(t *testing.T) {
	if _, err := parseFlow(`for (let pod of template.items) { http(1) }`); err != nil {
		t.Fatalf("`for (let x of template.items)` is unreadable: %s", err)
	}
}

// Пробіл перед дужкою — написання корпусу: `http () && code ()` у 3 шаблонах.
func TestAStepCallMayCarryASpaceBeforeItsParenthesis(t *testing.T) {
	if _, err := parseFlow(`http () && code ()`); err != nil {
		t.Fatalf("`http ()` is unreadable: %s", err)
	}
}

// Член, якого документ не видобув, — це відмова з назвою, а не порожній рядок:
// значення, яке порожнє, і значення, якого немає, — різні твердження.
func TestAMemberThatWasNeverExtractedIsRefusedByName(t *testing.T) {
	runner := &flowRunner{
		vars:    map[string]flowValue{},
		dynamic: map[string]string{"present": "yes"},
		lists:   map[string][]string{},
	}
	base := flowValue{scalar: "text", name: "root", runner: runner}

	if _, why := flowIndex(base, flowValue{scalar: "absent"}); why == "" {
		t.Fatal("a member that was never extracted produced a value")
	} else if !strings.Contains(why, "absent") {
		t.Fatalf("the refusal does not name the member: %q", why)
	}
	if value, why := flowIndex(base, flowValue{scalar: "present"}); why != "" {
		t.Fatalf("an extracted member was refused: %s", why)
	} else if value.scalar != "yes" {
		t.Fatalf("member read produced %q, want %q", value.scalar, "yes")
	}
}
