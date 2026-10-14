package active

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func makeTestJWT(alg string, signature string) string {
	head := `{"alg":"` + alg + `","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"Alice","admin":false}`
	h64 := base64.RawURLEncoding.EncodeToString([]byte(head))
	p64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return h64 + "." + p64 + "." + signature
}

func TestJWTNoneAlgorithmVulnerable(t *testing.T) {
	origToken := makeTestJWT("HS256", "valid_real_signature_123")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		headBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		head := string(headBytes)

		// Vulnerable backend logic: accepts valid signature OR alg:none!
		if strings.Contains(strings.ToLower(head), `"none"`) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok","user":"Alice"}`)
			return
		}

		if parts[2] == "valid_real_signature_123" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok","user":"Alice"}`)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid signature"}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := JWT{}
	p := Point{
		URL:    server.URL + "/api/profile",
		Method: http.MethodGet,
		Param:  "token",
		Values: url.Values{"token": {origToken}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `{"status":"ok","user":"Alice"}`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) == 0 {
		t.Fatalf("expected JWT 'none' algorithm finding, got 0")
	}

	foundNone := false
	for _, f := range findings {
		if strings.Contains(f.Title, "none") {
			foundNone = true
		}
	}
	if !foundNone {
		t.Errorf("expected JWT 'none' finding in: %+v", findings)
	}
}

func TestJWTSecureBackendDoesNotReport(t *testing.T) {
	origToken := makeTestJWT("HS256", "valid_real_signature_123")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		parts := strings.Split(token, ".")
		if len(parts) == 3 && parts[2] == "valid_real_signature_123" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid signature"}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := JWT{}
	p := Point{
		URL:    server.URL + "/api/profile",
		Method: http.MethodGet,
		Param:  "token",
		Values: url.Values{"token": {origToken}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `{"status":"ok"}`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secure backend, got %d: %+v", len(findings), findings)
	}
}
