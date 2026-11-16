package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// A newline inside a logged value splits the entry into a line nobody wrote.
// RequestRider logs operator- and target-supplied text, so this is reachable from
// the outside: a URL carrying `%0d%0a` was measured writing a forged line into
// engine.log that read exactly like a recorded successful attack. These tests
// pin the fix at the value level, which is where the entry is assembled.

func TestSanitizeLogValueEscapesLineBreaks(t *testing.T) {
	// The forged line from the audit, verbatim.
	got := sanitizeLogValue("forged\r\n2026/01/01 00:00:00 [REQUEST] complete method=POST host=evil.example status=200")

	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitised value still contains a line break: %q", got)
	}
	// Escaped, not dropped: the evidence has to survive in the log.
	if !strings.Contains(got, `\r\n`) {
		t.Fatalf("control characters must keep their escape spelling, got %q", got)
	}
	if !strings.Contains(got, "host=evil.example") {
		t.Fatalf("sanitising must not drop the payload text, got %q", got)
	}
}

func TestSanitizeLogValueCoversTheC0Range(t *testing.T) {
	cases := map[string]string{
		"a\nb":   `a\nb`,
		"a\rb":   `a\rb`,
		"a\tb":   `a\tb`,
		"a\x00b": `a\x00b`,
		"a\x1bb": `a\x1bb`,
		"a\x7fb": `a\x7fb`,
	}
	for input, want := range cases {
		if got := sanitizeLogValue(input); got != want {
			t.Errorf("sanitizeLogValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSanitizeLogValueLeavesOrdinaryTextUntouched(t *testing.T) {
	// Over-sanitising would make the log unreadable, so an unchanged value must
	// come back identical — including multi-byte runes.
	const plain = "/api/v1/users?page=2 — запрос ✓"
	if got := sanitizeLogValue(plain); got != plain {
		t.Fatalf("ordinary value was modified: %q", got)
	}
}

func TestLogPathNeverEmitsMoreThanOneLine(t *testing.T) {
	// The exact shape used in the measurement: the CRLF arrives percent-encoded
	// and is decoded into a real control character by the time it is logged.
	raw := "http://127.0.0.1:9/forged%0d%0a2026/01/01 00:00:00 [REQUEST] complete method=POST host=evil.example"
	decoded, err := url.PathUnescape("forged%0d%0a2026/01/01 00:00:00 [REQUEST] complete")
	if err != nil {
		t.Fatalf("fixture is not valid percent-encoding: %v", err)
	}
	if strings.ContainsAny(decoded, "\r\n") == false {
		t.Fatal("fixture must contain real control characters, otherwise the test proves nothing")
	}

	got := logPath(raw)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("logPath returned a value with a line break: %q", got)
	}
}

func TestLogHostAndLogErrorAreSingleLine(t *testing.T) {
	if got := logHost("http://host.local/path"); got != "host.local" {
		t.Errorf("logHost = %q, want %q", got, "host.local")
	}

	// `*url.Error` embeds the request URL, query string included, so it carries
	// whatever the caller supplied — this is the other half of the finding.
	_, parseErr := url.Parse("http://127.0.0.1:9/forged\r\nfake line")
	if parseErr == nil {
		t.Fatal("fixture URL should have been rejected by net/url, otherwise it proves nothing")
	}
	wrapped := &url.Error{Op: "Get", URL: "http://127.0.0.1:9/forged\r\nfake line", Err: parseErr}
	if got := logError(wrapped); strings.ContainsAny(got, "\r\n") {
		t.Errorf("logError returned a value with a line break: %q", got)
	}
	if got := logError(nil); got != "" {
		t.Errorf("logError(nil) = %q, want empty string", got)
	}
}

// TestRequestHostIsStillADataValue pins the decision not to sanitise the data
// path. last_byte.go stores requestHost's result in an event, so "fixing" the log
// by changing requestHost would silently alter stored data.
func TestRequestHostIsStillADataValue(t *testing.T) {
	if got := requestHost("http://host.local:8080/p"); got != "host.local:8080" {
		t.Errorf("requestHost = %q, want %q", got, "host.local:8080")
	}
}

// --- A09-03: a token in the query must not reach the log ---------------------
//
// `*url.Error` embeds the whole request URL, so `Error()` printed
// `Get "https://host/p?access_token=…": dial tcp: …` verbatim. The structured fields
// went through `requestHost`/`requestPath`, but the error string bypassed both, and
// this is where the query had to be closed.
func TestLogErrorDropsTheQueryString(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://api.acme.test/v1/token?access_token=SUPERSECRET&scope=admin",
		Err: errors.New("dial tcp: connection refused"),
	}
	line := logError(err)
	if strings.Contains(line, "SUPERSECRET") {
		t.Fatalf("the query value reached the log line: %s", line)
	}
	if strings.Contains(line, "access_token") || strings.Contains(line, "scope=admin") {
		t.Fatalf("the query itself reached the log line: %s", line)
	}
	// The line has to stay useful: which operation, which host, which path, which cause.
	for _, want := range []string{"Get", "api.acme.test", "/v1/token", "connection refused"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line lost %q, which is what makes it readable: %s", want, line)
		}
	}
}

func TestLogErrorDropsUserinfoToo(t *testing.T) {
	// `https://user:password@host/` — credentials live in the authority, not the query.
	line := logError(&url.Error{
		Op:  "Post",
		URL: "https://admin:HUNTER2@api.acme.test/v1/x",
		Err: errors.New("EOF"),
	})
	if strings.Contains(line, "HUNTER2") || strings.Contains(line, "admin:") {
		t.Fatalf("credentials reached the log line: %s", line)
	}
	if !strings.Contains(line, "/v1/x") {
		t.Fatalf("the path should still be readable: %s", line)
	}
}

func TestLogErrorRecursesThroughNestedURLErrors(t *testing.T) {
	// Go nests these: a dial failure inside a request failure, each with its own URL.
	inner := &url.Error{Op: "dial", URL: "http://inner.acme.test:9/p?token=INNERSECRET", Err: errors.New("connection refused")}
	outer := &url.Error{Op: "Get", URL: "https://outer.acme.test/p?token=OUTERSECRET", Err: inner}

	line := logError(outer)
	for _, secret := range []string{"INNERSECRET", "OUTERSECRET"} {
		if strings.Contains(line, secret) {
			t.Fatalf("%s reached the log line: %s", secret, line)
		}
	}
	if !strings.Contains(line, "connection refused") {
		t.Fatalf("the cause must survive: %s", line)
	}
}

func TestLogErrorHandlesAWrappedURLError(t *testing.T) {
	// `errors.As` rather than a type assertion: a wrapped `*url.Error` is still one,
	// and a type assertion would let this exact leak through a `fmt.Errorf("%w")`.
	wrapped := fmt.Errorf("send request: %w", &url.Error{
		Op:  "Get",
		URL: "https://api.acme.test/v1?token=WRAPPEDSECRET",
		Err: errors.New("timeout"),
	})
	if line := logError(wrapped); strings.Contains(line, "WRAPPEDSECRET") {
		t.Fatalf("a wrapped url.Error leaked its query: %s", line)
	}
}

func TestLogErrorOmitsTheURLWhenThereIsNone(t *testing.T) {
	// An inner `dial` error carries no URL. Printing `dial "-/":` would be noise.
	line := logError(&url.Error{Op: "dial", Err: errors.New("i/o timeout")})
	if strings.Contains(line, `"/`) {
		t.Fatalf("an absent URL should not print a placeholder: %s", line)
	}
	if line != "dial: i/o timeout" {
		t.Fatalf("unexpected rendering: %s", line)
	}
}

func TestLogErrorKeepsOrdinaryErrorsIntact(t *testing.T) {
	// Over-guarding is its own defect: a plain error must read exactly as before.
	const message = "dial tcp 127.0.0.1:9: connect: connection refused"
	if line := logError(errors.New(message)); line != message {
		t.Fatalf("a plain error changed: %q -> %q", message, line)
	}
	if line := logError(nil); line != "" {
		t.Fatalf("nil must stay empty, got %q", line)
	}
}

func TestLogErrorStillNeverEmitsMoreThanOneLine(t *testing.T) {
	// The A09-01 guarantee has to survive the A09-03 change: redaction must not have
	// been bought by dropping the CRLF escaping.
	line := logError(&url.Error{
		Op:  "Get",
		URL: "https://api.acme.test/a%0d%0aForged:%20status=200",
		Err: errors.New("forged\r\nstatus=200 host=evil.example"),
	})
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("the error line can still be forged: %q", line)
	}
}
