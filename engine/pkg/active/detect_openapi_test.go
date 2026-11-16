package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPIDefinitionFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"swagger":"2.0","info":{"title":"Juice Shop API"},"paths":{"/api/Users":{"get":{}}}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := OpenAPI{}
	p := Point{
		URL:    server.URL + "/swagger.json",
		Method: http.MethodGet,
	}

	findings := detector.Scan(context.Background(), transport, p, nil)
	if len(findings) == 0 {
		t.Fatalf("expected OpenAPI finding, got 0")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "OpenAPI/Swagger") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing OpenAPI finding in: %+v", findings)
	}
}
