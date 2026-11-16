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

func TestCSSInjectionReflected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		color := r.URL.Query().Get("theme")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head><style>body { color: `+color+`; }</style></head><body><h1>Hello</h1></body></html>`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := CSSInjection{}
	p := Point{
		URL:    server.URL + "/profile",
		Method: http.MethodGet,
		Param:  "theme",
		Values: url.Values{"theme": {"blue"}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `<html><head><style>body { color: blue; }</style></head><body><h1>Hello</h1></body></html>`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) == 0 {
		t.Fatalf("expected CSS injection finding, got 0")
	}

	if !strings.Contains(findings[0].Title, "CSS Injection") {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}
