package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// `{{interactsh-url}}` — 53 відмови на вибірці з 4 000 і 596 шаблонів у корпусі.
// Єдине місце, де ми не можемо нічого згенерувати самі: адреса має бути справжньою,
// тобто на неї можуть зателефонувати.
//
// Тому тут не генератор, а джерело. Рушій уже має OAST-слухач, і Scanner не повинен
// заводити другий — тому тут інтерфейс і тест на нього.

// fakeOAST is a source that answers from a script, so the test can say which of
// the two outcomes it is exercising.
type fakeOAST struct {
	payload  string
	err      error
	hit      bool
	awaitErr error
	asked    string
	waited   time.Duration
}

func (f *fakeOAST) NewPayload(context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.payload, nil
}

func (f *fakeOAST) Await(_ context.Context, payload string, wait time.Duration) (bool, error) {
	f.asked, f.waited = payload, wait
	if f.awaitErr != nil {
		return false, f.awaitErr
	}
	return f.hit, nil
}

const oastTemplate = `id: oast-probe
info:
  name: oast probe
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/ping?cb={{interactsh-url}}"
    matchers:
      - type: word
        part: body
        words:
          - "never-in-this-body"
`

func oastRun(t *testing.T, source OASTSource, hit bool) (LocalRun, *fakeOAST) {
	t.Helper()
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	stub := &fakeOAST{payload: "https://cb.invalid/abc", hit: hit}
	if source != nil {
		stub = source.(*fakeOAST)
	}
	ctx := WithOASTSource(context.Background(), stub)
	run := RunTemplateLocally(ctx, oastTemplate, server.URL, &countingTransport{inner: http.DefaultTransport})
	if seen != "" && strings.Contains(seen, "{{") {
		t.Fatalf("the literal placeholder went on the wire: %q", seen)
	}
	return run, stub
}

// Зворотний дзвінок — це вердикт: у шаблона з `interactsh-url` немає матчера
// відповіді, його відповідь у тому, що ціль зателефонувала.
func TestACallbackIsTheTemplatesVerdict(t *testing.T) {
	run, stub := oastRun(t, nil, true)
	if run.Reason != "" {
		t.Fatalf("an OAST template was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatal("a callback that arrived did not become the verdict")
	}
	if stub.asked != "https://cb.invalid/abc" {
		t.Fatalf("awaited %q, want the address that was substituted", stub.asked)
	}
	if run.Dynamic[OASTHitKey] != "true" {
		t.Fatalf("the callback was not recorded for a later block: %v", run.Dynamic)
	}
}

// Відсутність зворотного дзвінка — це не збіг і не помилка, а відповідь «ні».
//
// Матчер відповіді в цьому шаблоні навмисно не збігається: інакше вердикт міг би
// прийти з відповіді, а не зі зворотного дзвінка, і тест нічого б не довів.
func TestNoCallbackIsANegativeAnswerNotAFailure(t *testing.T) {
	run, _ := oastRun(t, nil, false)
	if run.Reason != "" {
		t.Fatalf("a run whose callback never came reported a reason: %q", run.Reason)
	}
	if run.Matched {
		t.Fatal("a run with no callback reported a match")
	}
}

// Без джерела адреси немає — і літерал на дріт не йде.
func TestWithoutAnOASTSourceTheTemplateIsRefusedByName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), oastTemplate, server.URL, transport)

	if got := transport.count(); got != 0 {
		t.Fatalf("requests sent = %d, want 0: without an address there is nothing to send", got)
	}
	if !strings.Contains(run.Reason, "{{interactsh-url}}") {
		t.Fatalf("the reason does not name what is missing: %q", run.Reason)
	}
}

// Джерело, що не змогло зареєструвати адресу, каже це своїми словами — інакше
// оператор бачить «шаблон не дав вердикта» без причини.
func TestASourceThatCannotRegisterSaysWhy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	stub := &fakeOAST{err: errors.New("provider refused the registration")}
	ctx := WithOASTSource(context.Background(), stub)
	run := RunTemplateLocally(ctx, oastTemplate, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason == "" {
		t.Fatal("a failed registration produced no reason")
	}
	if !strings.Contains(run.Reason, "provider refused the registration") {
		t.Fatalf("the reason does not carry the cause: %q", run.Reason)
	}
}

// Межа очікування задається викликом і передається джерелу: джерело не має
// вирішувати, скільки чекати, бо воно не знає, який у тебе прогін.
func TestTheWaitBoundComesFromTheCaller(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	stub := &fakeOAST{payload: "https://cb.invalid/abc", hit: false}
	ctx := WithOASTSource(context.Background(), stub)
	ctx = WithOASTWait(ctx, 45*time.Second)
	RunTemplateLocally(ctx, oastTemplate, server.URL, &countingTransport{inner: http.DefaultTransport})
	if stub.waited != 45*time.Second {
		t.Fatalf("waited %s, want the caller's 45s", stub.waited)
	}
}

// Очікування не відбувається там, де адреси не було: перевірка виконується лише
// для блоку, який її назвав.
func TestAWaitOnlyHappensWhenAnAddressWasNamed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	stub := &fakeOAST{payload: "https://cb.invalid/abc", hit: true}
	document := `id: plain
info:
  name: plain
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/plain"
    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	ctx := WithOASTSource(context.Background(), stub)
	run := RunTemplateLocally(ctx, document, server.URL, &countingTransport{inner: http.DefaultTransport})
	if run.Reason != "" {
		t.Fatalf("a plain template was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatal("a plain matching template reported no match")
	}
	if stub.asked != "" {
		t.Fatalf("a plain template waited for a callback to %q", stub.asked)
	}
}

// Плейсхолдер усередині `raw:` — те саме, що й у шляху, і мусить перевірятися так
// само.
//
// Виміряно: `Raw` не читався перевіркою, і 162 шаблони з 4 000 надсилали літерал
// `{{interactsh-url}}` у тілі сирого запиту. Їхній «вердикт» був відповіддю цілі
// на текст `{{interactsh-url}}`, а не тим, що шаблон перевіряв.
func TestAPlaceholderInsideARawBlockIsAlsoRefused(t *testing.T) {
	document := `id: raw-oast
info:
  name: raw oast
  author: tester
  severity: info
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/xml

        <string>http://{{marker}}</string>

    unsafe: true

    matchers:
      - type: word
        part: body
        words:
          - "ok"
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if got := transport.count(); got != 0 {
		t.Fatalf("requests sent = %d, want 0: an unresolved placeholder in a raw body must not go on the wire", got)
	}
	if !strings.Contains(run.Reason, "{{marker}}") {
		t.Fatalf("the refusal does not name the placeholder: %q", run.Reason)
	}
}
