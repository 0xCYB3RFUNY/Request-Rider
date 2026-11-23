package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// answer is a trimmed copy of what the engine returns, with the fields the
// formatter reads. The long secret value is the point of the fixture: it is
// longer than every ceiling the rules used to have, so a formatter that trims
// prints something this fixture can catch.
const answer = `{
  "results": [
    {
      "url": "https://cdn.example.test/app.js",
      "kind": "script",
      "status": 200,
      "content_type": "application/javascript",
      "bytes": 4096,
      "ms": 812,
      "js": {
        "bytes": 4096,
        "links": ["/assets/config.json"],
        "endpoints": [
          {
            "url": "https://api.example.test/v1/users/EXPR",
            "method": "GET",
            "types": ["fetch"],
            "query_params": ["page", "per_page"],
            "body_params": ["email", "password"]
          }
        ],
        "secrets": [
          {
            "rule": "slack_token",
            "kind": "slack_token",
            "severity": "high",
            "value": "xoxb-0123456789012345678901234567890123456789012345678901234567890123456789",
            "fingerprint": "xoxb-…6789",
            "line": 4
          }
        ],
        "findings": [
          {
            "kind": "xss_sink",
            "severity": "high",
            "subject": "el.innerHTML",
            "function": "paint",
            "evidence": "el.innerHTML = html;\nel.innerHTML += more;",
            "line": 9,
            "count": 2
          }
        ]
      }
    },
    {
      "url": "https://cdn.example.test/gone.js",
      "kind": "script",
      "error": "the index could not be asked: connection refused"
    }
  ]
}`

const secretValue = "xoxb-0123456789012345678901234567890123456789012345678901234567890123456789"

// fakeEngine answers the route the CLI calls, and records the request it got so
// the test can assert the CLI sends what the gateway sends.
func fakeEngine(t *testing.T) (*httptest.Server, *[]byte) {
	t.Helper()
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/target-js" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		buffer := new(bytes.Buffer)
		if _, err := buffer.ReadFrom(r.Body); err != nil {
			t.Errorf("read request: %v", err)
		}
		body = buffer.Bytes()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(server.Close)
	return server, &body
}

func TestTextOutputCarriesEveryEndpointSecretAndFinding(t *testing.T) {
	server, body := fakeEngine(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-engine", server.URL, "-url", "https://cdn.example.test/app.js", "-referer", "https://site.example.test/"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	text := stdout.String()

	// The endpoint keeps its method, its parameters and its type.
	for _, want := range []string{
		"endpoint GET https://api.example.test/v1/users/EXPR",
		"query: page per_page",
		"body:  email password",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text output misses %q:\n%s", want, text)
		}
	}
	// The finding keeps its kind, severity, subject, enclosing function, line and
	// repeat count, and its evidence's first line.
	for _, want := range []string{
		"finding [xss_sink/high] line 9 el.innerHTML in paint ×2",
		"el.innerHTML = html;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text output misses %q:\n%s", want, text)
		}
	}
	// A failed script is named, not dropped: silence would read as "nothing
	// found there" rather than "the file could not be read".
	if !strings.Contains(text, "connection refused") {
		t.Fatalf("text output does not report the failed script:\n%s", text)
	}
	if !strings.Contains(text, "2 script(s) analysed") {
		t.Fatalf("text output does not count the scripts:\n%s", text)
	}

	// The request is the gateway's: the URLs and the referrer travel together.
	var sent struct {
		URLs    []string `json:"urls"`
		Referer string   `json:"referer"`
	}
	if err := json.Unmarshal(*body, &sent); err != nil {
		t.Fatalf("the CLI sent a body the engine cannot read: %v (%s)", err, *body)
	}
	if len(sent.URLs) != 1 || sent.URLs[0] != "https://cdn.example.test/app.js" {
		t.Fatalf("urls = %#v", sent.URLs)
	}
	if sent.Referer != "https://site.example.test/" {
		t.Fatalf("referer = %q", sent.Referer)
	}
}

// TestTextOutputPrintsTheWholeSecretValue is the one that matters for the owner
// requirement that a found key arrives complete: the fixture value is 74
// characters, far past every ceiling the rules used to have.
func TestTextOutputPrintsTheWholeSecretValue(t *testing.T) {
	server, _ := fakeEngine(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-engine", server.URL, "-url", "https://cdn.example.test/app.js"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), secretValue) {
		t.Fatalf("the secret value is not printed whole (%d characters expected):\n%s",
			len(secretValue), stdout.String())
	}
}

func TestJSONOutputIsTheEngineAnswer(t *testing.T) {
	server, _ := fakeEngine(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-engine", server.URL, "-url", "https://cdn.example.test/app.js", "-format", "json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	var decoded struct {
		Results []struct {
			URL string `json:"url"`
			JS  struct {
				Secrets []struct {
					Value string `json:"value"`
				} `json:"secrets"`
			} `json:"js"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, stdout.String())
	}
	if len(decoded.Results) != 2 || decoded.Results[0].JS.Secrets[0].Value != secretValue {
		t.Fatalf("json output lost a result or a value: %s", stdout.String())
	}
}

func TestOutputFileIsWrittenAndNothingGoesToStdout(t *testing.T) {
	server, _ := fakeEngine(t)
	path := filepath.Join(t.TempDir(), "findings.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-engine", server.URL, "-url", "https://cdn.example.test/app.js", "-format", "json", "-out", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("with -out nothing may go to stdout, got %d bytes", stdout.Len())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(raw), secretValue) {
		t.Fatalf("the written file does not carry the whole value:\n%s", raw)
	}
	// A report is evidence, and evidence is not world-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600: the file holds live keys", mode)
	}
}

func TestURLFileIsReadAndCommentsSkipped(t *testing.T) {
	server, body := fakeEngine(t)
	path := filepath.Join(t.TempDir(), "urls.txt")
	content := "# a comment\n\nhttps://cdn.example.test/app.js\nhttps://cdn.example.test/other.js\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-engine", server.URL, "-urls-from", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	var sent struct {
		URLs []string `json:"urls"`
	}
	if err := json.Unmarshal(*body, &sent); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(sent.URLs) != 2 || sent.URLs[1] != "https://cdn.example.test/other.js" {
		t.Fatalf("urls = %#v", sent.URLs)
	}
}

func TestRefusalsAreExitCodesWithAReason(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{name: "no URLs", args: []string{}, code: 2, want: "at least one -url"},
		{name: "unknown format", args: []string{"-url", "https://a/b.js", "-format", "yaml"}, code: 2, want: "-format must be"},
		{name: "engine unreachable", args: []string{"-engine", "http://127.0.0.1:1", "-url", "https://a/b.js"}, code: 1, want: "ask"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(testCase.args, &stdout, &stderr); code != testCase.code {
				t.Fatalf("exit %d, want %d (stderr: %s)", code, testCase.code, stderr.String())
			}
			if !strings.Contains(stderr.String(), testCase.want) {
				t.Fatalf("stderr does not explain the refusal, want %q: %s", testCase.want, stderr.String())
			}
		})
	}
}

func TestEngineErrorIsReportedWithItsOwnWords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"the index could not be asked"}`))
	}))
	t.Cleanup(server.Close)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-engine", server.URL, "-url", "https://a/b.js"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "the index could not be asked") {
		t.Fatalf("the engine's own error is not in the message: %s", stderr.String())
	}
}

// The service key is gone, and this asserts that on the wire rather than in a
// comment.
//
// The CLI used to read RR_INTERNAL_API_KEY and set X-RequestRider-Internal-Key on
// every call, duplicating the engine's own constants because a `cmd/` package
// cannot import package main. Both are removed; what remains worth asserting is
// that nothing puts the header back — which is the regression a test written only
// for the surviving behaviour would miss.
func TestTheServiceKeyIsNeverSent(t *testing.T) {
	// Set in the environment on purpose: a reader that came back would find it.
	t.Setenv("RR_INTERNAL_API_KEY", strings.Repeat("ab", 32))
	var seen string
	var present bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-RequestRider-Internal-Key")
		_, present = r.Header[http.CanonicalHeaderKey("X-RequestRider-Internal-Key")]
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"results":[]}`)
	}))
	defer server.Close()
	if _, err := ask(server.URL, []string{"http://127.0.0.1/a.js"}, "", 5*time.Second); err != nil {
		t.Fatalf("ask: %v", err)
	}
	if present {
		t.Errorf("the request carried X-RequestRider-Internal-Key=%q; the mechanism was removed "+
			"and must not come back", seen)
	}
}

// The same assertion against the engine's own file: if `internal_auth.go` ever
// declares the check again, the CLI and the engine would disagree about what a
// valid call is, which is the exact failure this pair of constants used to hide.
func TestTheEngineNoLongerDeclaresAServiceKey(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "internal_auth.go"))
	if err != nil {
		t.Fatalf("read the engine's internal_auth.go: %v", err)
	}
	text := string(source)
	for _, unwanted := range []string{
		"internalKeyEnv",
		"internalKeyHeader",
		"internalAPIKey",
		"FORBIDDEN_ORIGIN",
	} {
		if strings.Contains(text, unwanted) {
			t.Errorf("engine/internal_auth.go declares %q again; this package sends no key, "+
				"so the engine would refuse every call this CLI makes", unwanted)
		}
	}
}
