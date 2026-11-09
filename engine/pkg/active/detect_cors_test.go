package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORSArbitraryOriginWithCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Vulnerable backend reflects any origin and enables credentials!
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"secret":"top-secret-user-data"}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := CORS{}
	p := Point{
		URL:    server.URL + "/api/user",
		Method: http.MethodGet,
	}

	findings := detector.Scan(context.Background(), transport, p, nil)
	if len(findings) == 0 {
		t.Fatalf("expected CORS findings, got 0")
	}

	foundCreds := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Credentials") {
			foundCreds = true
		}
	}
	if !foundCreds {
		t.Errorf("expected CORS with Credentials finding, got: %+v", findings)
	}
}

func TestCORSNullOriginTrusted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := CORS{}
	p := Point{
		URL:    server.URL + "/data",
		Method: http.MethodGet,
	}

	findings := detector.Scan(context.Background(), transport, p, nil)
	foundNull := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Null Origin") {
			foundNull = true
		}
	}
	if !foundNull {
		t.Errorf("expected CORS Null Origin finding, got: %+v", findings)
	}
}

func TestCORSSecureAllowlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strict allowlist
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted-domain.com")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := CORS{}
	p := Point{
		URL:    server.URL + "/data",
		Method: http.MethodGet,
	}

	findings := detector.Scan(context.Background(), transport, p, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for static allowlist, got %d: %+v", len(findings), findings)
	}
}
