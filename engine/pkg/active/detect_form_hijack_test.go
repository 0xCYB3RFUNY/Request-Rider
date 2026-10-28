package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFormActionHijackingDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("next")
		if target == "" {
			target = "/dashboard"
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>
			<form action="`+target+`" method="POST">
				<input type="text" name="username">
				<input type="password" name="password">
				<input type="submit" value="Login">
			</form>
		</body></html>`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := FormHijack{}
	p := Point{
		URL:    server.URL + "/login",
		Method: http.MethodGet,
		Param:  "next",
		Values: url.Values{"next": {"/dashboard"}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `<html><body><form action="/dashboard" method="POST"><input type="password"></form></body></html>`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) == 0 {
		t.Fatalf("expected form hijack finding, got 0")
	}

	if !strings.Contains(findings[0].Title, "Form Action Hijacking") {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh for password form hijack, got: %v", findings[0].Severity)
	}
}
