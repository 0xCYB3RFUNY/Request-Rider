package scanner

// The local runner is the project's own nuclei, so these tests hold it to the
// same standard the binary is held to: the request it sends must be the one the
// template describes, the verdict must be nuclei's own verdict, and the
// evidence must survive the round trip.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// countingTransport records what went over the wire, so a test can assert what
// the runner sent instead of trusting that it sent something.
type countingTransport struct {
	inner  http.RoundTripper
	mu     sync.Mutex
	seen   []*http.Request
	bodies []string
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	payload := ""
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		payload = string(raw)
		r.Body = io.NopCloser(strings.NewReader(payload))
	}
	c.mu.Lock()
	c.seen = append(c.seen, r)
	c.bodies = append(c.bodies, payload)
	c.mu.Unlock()
	return c.inner.RoundTrip(r)
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

const localWordTemplate = `
id: local-word
info:
  name: Local word match
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: word
        words:
          - "Admin Login"
`

const localStatusTemplate = `
id: local-status
info:
  name: Local status match
  author: test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: status
        status:
          - 200
`

func localFixture() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<title>Admin Login</title>"
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

func TestLocalRunnerSendsTheRequestsTheTemplateDescribes(t *testing.T) {
	server := localFixture()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), localWordTemplate, server.URL, transport)

	if run.Reason != "" {
		t.Fatalf("template was not run: %s", run.Reason)
	}
	if transport.count() != 1 {
		t.Errorf("sent %d requests, want exactly 1", transport.count())
	}
	sent := transport.seen[0]
	if sent.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", sent.Method)
	}
	if sent.URL.Path != "/admin/login" {
		t.Errorf("path = %q, want /admin/login — the template path was not sent", sent.URL.Path)
	}
	if strings.Contains(sent.URL.String(), "{{") {
		t.Errorf("url = %q still carries an unsubstituted placeholder", sent.URL.String())
	}
	if !run.Matched {
		t.Error("no match, but the fixture body carries the word the template matches")
	}
	if run.StatusCode != 200 {
		t.Errorf("status = %d, want 200", run.StatusCode)
	}
}

func TestLocalRunnerVerdictIsNucleisOwnVerdict(t *testing.T) {
	server := localFixture()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	if run := RunTemplateLocally(context.Background(), localStatusTemplate, server.URL, transport); !run.Matched {
		t.Errorf("status matcher did not fire on a 200: reason %q", run.Reason)
	}
	missing := strings.Replace(localWordTemplate, "Admin Login", "Not In The Body", 1)
	if run := RunTemplateLocally(context.Background(), missing, server.URL, transport); run.Matched {
		t.Error("matched a word the response does not contain")
	}
}

// The evidence is not decoration: a verdict without the exchange it rests on
// cannot be checked by the operator, and the RAW window exists to show it.
func TestLocalRunnerKeepsTheExchangeAsEvidence(t *testing.T) {
	server := localFixture()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), localWordTemplate, server.URL, transport)
	if !strings.HasPrefix(run.Response, "HTTP/1.1 200") {
		t.Errorf("response evidence does not start with the status line: %q", run.Response[:min(40, len(run.Response))])
	}
	if !strings.Contains(run.Response, "Admin Login") {
		t.Error("response evidence does not carry the body the match rests on")
	}
	if !strings.HasPrefix(run.Request, "GET /admin/login HTTP/1.1") {
		t.Errorf("request evidence = %q, want the request line first", run.Request[:min(40, len(run.Request))])
	}
	if !strings.Contains(run.Request, "Host: ") {
		t.Error("request evidence carries no Host header")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A run outside the recording path produces evidence the project cannot show,
// so it is refused rather than quietly performed.
func TestLocalRunnerRefusesWithoutATransport(t *testing.T) {
	run := RunTemplateLocally(context.Background(), localWordTemplate, "http://127.0.0.1:1/", nil)
	if run.Reason == "" {
		t.Fatal("ran with no transport, which would leave no evidence in History")
	}
	if run.Matched {
		t.Error("reported a match from a run that never happened")
	}
}

func TestLocalRunnerRefusesWhatItCannotSend(t *testing.T) {
	server := localFixture()
	defer server.Close()
	transport := &countingTransport{inner: http.DefaultTransport}

	cases := map[string]struct{ document, mentions string }{
		"code template": {
			document: "id: c\ninfo:\n  name: c\n  author: t\n  severity: info\ncode:\n  - engine:\n      sh: \"id\"\n",
			mentions: "code",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			run := RunTemplateLocally(context.Background(), testCase.document, server.URL, transport)
			if run.Reason == "" {
				t.Fatal("ran a template this runner cannot send, and said nothing")
			}
			if !strings.Contains(run.Reason, testCase.mentions) {
				t.Errorf("reason = %q, want it to name %q", run.Reason, testCase.mentions)
			}
			if run.Matched {
				t.Error("reported a match from a run that never happened")
			}
		})
	}
}

// Матчер із `name:` та `internal: true` — це спосіб корпусу **добути** значення,
// а не знахідку. Виміряно на 700-шаблонній вибірці `flow:`: 366 відмов, у кожній
// сирий блок носив `{{token}}`, якого ніхто не виробив, бо значення жило у внутрішньому
// матчері й ніде більше.
//
// Звірено з оригіналом v3.11.1 на шаблоні, чий єдиний матчер внутрішній:
//
//	nuclei -ms …  →  [internal-capture-probe] [failed]
//
// Тобто збіг внутрішнього матчера — це НЕ знахідка. Мутація: прибрати
// `nonInternalMatches`.
func TestAnInternalMatcherCapturesAValueWithoutBecomingAFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("here is glpat-ABCDEFGHIJKLMNOPQRST ok"))
	}))
	defer server.Close()
	document := `
id: internal-capture
info:
  name: internal matcher capture
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/token"
    matchers:
      - type: regex
        part: body
        name: token
        internal: true
        regex:
          - '\b(glpat-[0-9a-zA-Z_-]{20})(?:\b|$)'
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, server.URL, transport)

	if run.Matched {
		t.Fatal("a document whose only matcher is internal reported a finding; nuclei reports [failed]")
	}
	if run.Dynamic["token"] != "glpat-ABCDEFGHIJKLMNOPQRST" {
		t.Fatalf("the internal matcher captured nothing: %v", run.Dynamic)
	}
}
