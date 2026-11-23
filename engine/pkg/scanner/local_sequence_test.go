package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Послідовність запитів — це 897 відмов із 4 000 перевірених `http`-шаблонів
// офіційного корпусу, тобто 22.4 % вибірки. Вони не були складними: їх не
// оцінював пасив, бо в нього один збережений обмін, а послідовність — це
// кілька обмінів, які треба зробити самому.
//
// Тести нижче перевіряють саме це: що ми виконуємо блоки по порядку, що друге
// блок надсилається тоді й тільки тоді, коли перше збіглося, і що те, що
// перше витягло, їде в другий запит.

// loginThenUse is the shape most real multi-block templates have: take a token
// out of a login response and send it as a header.
const loginThenUse = `id: login-then-use
info:
  name: login then use
  author: tester
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    body: "user=admin&pass=secret"
    headers:
      Content-Type: application/x-www-form-urlencoded
    matchers:
      - type: word
        part: body
        words:
          - "TOKEN-abc123"
    extractors:
      - type: regex
        name: token
        part: body
        regex:
          - "TOKEN-([a-z0-9]+)"
        group: 1
  - method: GET
    path:
      - "{{BaseURL}}/private"
    headers:
      X-Auth: "{{token}}"
    matchers:
      - type: word
        part: body
        words:
          - "welcome"
`

// twoBlockFixture answers the login with a token and the private page only when
// that token arrives, so a run that forgets to carry the value cannot match.
func twoBlockFixture() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte("ok TOKEN-abc123"))
		case "/private":
			if r.Header.Get("X-Auth") == "abc123" {
				_, _ = w.Write([]byte("welcome"))
				return
			}
			_, _ = w.Write([]byte("no token"))
		default:
			_, _ = w.Write([]byte("nothing here"))
		}
	}))
}

// The whole point: both blocks are sent, in order, and the second one carries
// what the first extracted. A runner that sent only the first would report no
// match, and one that sent both without carrying the token would report the same
// — so the assertion has to be on the evidence, not only on the verdict.
func TestASequenceSendsEveryBlockAndCarriesTheExtractedValue(t *testing.T) {
	server := twoBlockFixture()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), loginThenUse, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a two-block template was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the chain did not match: %s", run.Reason)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("requests sent = %d, want 2: the chain must perform both blocks", got)
	}
	if !strings.Contains(run.Request, "X-Auth: abc123") {
		t.Fatalf("the second block did not carry the extracted value:\n%s", run.Request)
	}
	if !strings.Contains(run.Response, "welcome") {
		t.Fatalf("the second response is missing from the evidence:\n%s", run.Response)
	}
}

// `req-condition` is the rule that makes a multi-block template a test rather
// than a list: nuclei's default is true, so a later block is sent only after the
// previous one matched. Skipping the second block must therefore produce a miss
// with a reason, not a silent success.
func TestASequenceStopsWhenTheFirstBlockDoesNotMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("no token here"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), loginThenUse, server.URL, transport)

	if run.Matched {
		t.Fatal("a chain whose first block failed reported a match")
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("requests sent = %d, want 1: the chain must not send a block it is not entitled to", got)
	}
	if !strings.Contains(run.Reason, "req-condition") {
		t.Fatalf("the reason does not name the rule that stopped it: %q", run.Reason)
	}
	if !strings.Contains(run.Reason, "request 2 of 2") {
		t.Fatalf("the reason does not say which request was skipped: %q", run.Reason)
	}
}

// A name that extracted more than one value cannot go into a request line: a
// header holds one value, and joining them with a comma would put text on the
// wire that the template never wrote. The chain refuses that block by name
// instead of guessing.
func TestAMultiValuedExtractionIsNotPutIntoAHeader(t *testing.T) {
	document := `id: two-values
info:
  name: two values
  author: tester
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    matchers:
      - type: word
        part: body
        words:
          - "TOKEN"
    extractors:
      - type: regex
        name: token
        part: body
        regex:
          - "TOKEN-([a-z0-9]+)"
          - "OTHER-([a-z0-9]+)"
        group: 1
  - method: GET
    path:
      - "{{BaseURL}}/private"
    headers:
      X-Auth: "{{token}}"
    matchers:
      - type: word
        part: body
        words:
          - "welcome"
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok TOKEN-abc123 and OTHER-def456"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if got := transport.count(); got != 1 {
		t.Fatalf("requests sent = %d, want 1: the chain cannot continue without a single value", got)
	}
	if run.Matched {
		t.Fatal("a chain that could not build its header reported a match")
	}
	if !strings.Contains(run.Reason, "{{token}}") {
		t.Fatalf("the reason does not name the value it could not supply: %q", run.Reason)
	}
}

// A template that is one block is still one block: the sequence path must not
// change its verdict, its evidence, or the number of requests it makes.
func TestASingleBlockTemplateStillTakesTheSingleRequestPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	single := `id: single
info:
  name: single
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/private"
    matchers:
      - type: word
        part: body
        words:
          - "welcome"
`
	run := RunTemplateLocally(context.Background(), single, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("a one-block template was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatal("a matching one-block template reported no match")
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("requests sent = %d, want 1", got)
	}
}

// The refusal must name the protocol the file really declares. A `code`
// template says "declares a code block", not "declares no request block": the
// second is true and leaves the operator with nothing to act on.
func TestTheRefusalNamesTheProtocolTheDocumentDeclares(t *testing.T) {
	for _, protocol := range []string{"code", "javascript", "dns", "ssl", "tcp", "headless"} {
		document := "id: p\ninfo:\n  name: p\n  author: t\n  severity: info\n" +
			protocol + ":\n  - engine:\n      sh: id\n"
		run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)
		if run.Reason == "" {
			t.Fatalf("a %s template was accepted", protocol)
		}
		if !strings.Contains(run.Reason, protocol) {
			t.Fatalf("a %s template was refused without naming it: %q", protocol, run.Reason)
		}
		if run.Matched {
			t.Fatalf("a %s template reported a match", protocol)
		}
	}
}

// Плейсхолдер, якого раннер не генерує, відмовляється на ім'я. Надсилати його
// літералом означало б покласти на дріт `{{…}}` і приписати шаблону вердикт за
// відповідь на той текст.
//
// Свідомо не `{{randstr}}`: його раннер генерує, і він має власний тест.
func TestAPlaceholderTheRunnerCannotGenerateIsRefusedByName(t *testing.T) {
	document := `id: marker
info:
  name: marker
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{marker}}"
    matchers:
      - type: word
        part: body
        words:
          - "welcome"
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if got := transport.count(); got != 0 {
		t.Fatalf("requests sent = %d, want 0: an ungenerated placeholder must not go on the wire", got)
	}
	if !strings.Contains(run.Reason, "{{marker}}") {
		t.Fatalf("the refusal does not name the placeholder: %q", run.Reason)
	}
}

// The base target placeholders must keep working, or every template in the
// corpus would be refused for the same reason.
func TestTheTargetPlaceholdersAreStillSubstituted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	}))
	defer server.Close()
	document := `id: placeholders
info:
  name: placeholders
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/p"
    headers:
      X-Host: "{{Hostname}}"
    matchers:
      - type: word
        part: body
        words:
          - "welcome"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a template using {{BaseURL}} and {{Hostname}} was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatal("the target placeholders did not resolve")
	}
}

// Документ, який парсер відхилив, — це не привід читати його далі. `parsePassiveDocument`
// повертає nil разом із причиною, і раннер, що не перевірить nil, падає на всьому
// прогоні замість одного рядка.
//
// Виміряно: без цієї перевірки `localband` падав на 2 500-му файлі з 4 000,
// виняток `invalid memory address or nil pointer dereference` у
// nuclei_local_run.go:89.
func TestARefusedDocumentIsReportedRatherThanDereferenced(t *testing.T) {
	// A YAML bomb is refused by the amplification guard, which is the cheapest
	// way to make the parser return nil.
	document := "id: bomb\ninfo:\n  name: bomb\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n" +
		strings.Repeat("    # padding\n", 40000)
	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1:1/", http.DefaultTransport)
	if run.Reason == "" {
		t.Fatal("a refused document produced no reason, which means it was read anyway")
	}
	if run.Matched {
		t.Fatal("a refused document reported a match")
	}
}

// `raw:` — 1 263 відмови з 4 000, найбільша прогалина після цієї фази. Запит у ній
// написаний словами, тож виконати його — це розібрати, а не згенерувати.
//
// Цей тест бере два справжніх корпусні форми: honeypot, що надсилає непридатний
// метод, і LFI, що надсилає сирий шлях. Обидві мають відповідати так, щоб вердикт
// був справжнім, а не «запит пішов».
func TestARawRequestIsSentAndScored(t *testing.T) {
	var seenMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		if r.Method == "AAAA" {
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte("not implemented"))
			return
		}
		_, _ = w.Write([]byte("root:x:0:0"))
	}))
	defer server.Close()

	document := `id: raw-honeypot
info:
  name: raw honeypot
  author: tester
  severity: info
http:
  - raw:
      - |
        AAAA / HTTP/1.1
        Host: {{Hostname}}

    unsafe: true

    matchers:
      - type: status
        status:
          - 501
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})

	if run.Reason != "" {
		t.Fatalf("a raw request was refused: %s", run.Reason)
	}
	if seenMethod != "AAAA" {
		t.Fatalf("method on the wire = %q, want AAAA: a raw request must go out as written", seenMethod)
	}
	if !run.Matched {
		t.Fatal("the 501 the target returned did not satisfy the template's own matcher")
	}
	if !strings.Contains(run.Request, "AAAA / HTTP/1.1") {
		t.Fatalf("the evidence does not show the request as written:\n%s", run.Request)
	}
}

// `Host:` у сирому запиті — це адреса іншого походження, і переписати її на ціль
// означало б відправити запит не туди. Go тримає її окремо від карти заголовків,
// тому вона мусить потрапити саме туди.
func TestARawRequestKeepsTheHostItNames(t *testing.T) {
	var seenHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	document := `id: raw-host
info:
  name: raw host
  author: tester
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: example.invalid

    unsafe: true

    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	run := RunTemplateLocally(context.Background(), document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a raw request naming its own host was refused: %s", run.Reason)
	}
	if seenHost != "example.invalid" {
		t.Fatalf("host on the wire = %q, want the one the raw request named", seenHost)
	}
}

// Сирий запит, який не можна розібрати, відмовляється з причиною — надсилати
// щось інше означало б приписати шаблону вердикт за інший запит.
func TestAnUnparsableRawRequestIsRefusedWithItsReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	for name, raw := range map[string]string{
		"no request line": "   \n\n",
		"one field":       "GET\n",
		"header no colon": "GET / HTTP/1.1\nbroken-header\n\n",
	} {
		document := "id: bad-raw\ninfo:\n  name: bad\n  author: t\n  severity: info\nhttp:\n  - raw:\n      - |\n" +
			indentRaw(raw) + "\n    unsafe: true\n    matchers:\n      - type: word\n        part: body\n        words: [\"ok\"]\n"
		run := RunTemplateLocally(context.Background(), document, server.URL, transport)
		if run.Reason == "" {
			t.Fatalf("%s: an unparsable raw request produced no reason", name)
		}
		if run.Matched {
			t.Fatalf("%s: an unparsable raw request reported a match", name)
		}
	}
	if got := transport.count(); got != 0 {
		t.Fatalf("requests sent = %d, want 0: an unparsable raw request must not go on the wire", got)
	}
}

// indentRaw puts a raw block under a YAML block scalar at the depth `raw:` uses.
func indentRaw(raw string) string {
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	for index, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines[index] = "        " + line
	}
	return strings.Join(lines, "\n")
}
