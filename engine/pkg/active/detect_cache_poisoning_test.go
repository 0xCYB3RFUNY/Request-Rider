package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCachePoisoningConfirmed(t *testing.T) {
	var mu sync.Mutex
	cachedBody := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Cache-Control", "public, max-age=3600")

		// If cache is already poisoned, return it!
		if cachedBody != "" {
			w.Header().Set("X-Cache", "HIT")
			_, _ = io.WriteString(w, cachedBody)
			return
		}

		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			cachedBody = `<html><script src="https://` + host + `/app.js"></script></html>`
			w.Header().Set("X-Cache", "MISS")
			_, _ = io.WriteString(w, cachedBody)
			return
		}

		_, _ = io.WriteString(w, `<html><script src="https://example.com/app.js"></script></html>`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := CachePoisoning{}
	p := Point{
		URL:    server.URL + "/page",
		Method: http.MethodGet,
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `<html><script src="https://example.com/app.js"></script></html>`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) == 0 {
		t.Fatalf("expected Cache Poisoning finding, got 0")
	}

	foundConfirmed := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Confirmed") {
			foundConfirmed = true
		}
	}
	if !foundConfirmed {
		t.Errorf("expected Confirmed cache poisoning finding, got: %+v", findings)
	}
}
