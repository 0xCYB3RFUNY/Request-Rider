package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func jwksTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport
}

func TestJsonWebKeySetReadsAPublishedKeySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>home</body></html>"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig"},` +
			`{"kty":"oct","kid":"k2","alg":"HS256"}]}`))
	}))
	defer server.Close()

	findings := (JsonWebKeySet{}).Scan(context.Background(), jwksTransport(t),
		Point{URL: server.URL + "/", Method: http.MethodGet},
		&Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	// The severity that leaves the detector is the tier-capped one, and a
	// verified claim at informational severity is what an information row is.
	if findings[0].Severity != SeverityInfo || findings[0].Tier != TierVerified {
		t.Errorf("severity = %q, tier = %q; want info at verified", findings[0].Severity, findings[0].Tier)
	}
}

// A JSON error page parses, and a detector that reported one would be reporting
// every 200 in the application. The test hands it a body that is JSON and has no
// key array.
func TestJsonWebKeySetIgnoresAJSONErrorPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"not found","status":404}`))
	}))
	defer server.Close()

	findings := (JsonWebKeySet{}).Scan(context.Background(), jwksTransport(t),
		Point{URL: server.URL + "/", Method: http.MethodGet},
		&Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}})
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
