package active

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The echo is the finding: an address the client invented, written back into
// the response, means every control that trusts a header-supplied address is a
// control a caller can set.
func TestHeaderBehaviorSpoofableClientIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<html><body><p>your address is `+
			r.Header.Get("X-Forwarded-For")+`</p></body></html>`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := HeaderBehavior{}
	p := Point{URL: server.URL + "/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       `<html><body><p>your address is </p></body></html>`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Spoofable Client IP") {
			found = true
			if f.Tier != TierVerified {
				t.Errorf("an echo of a per-run token is verified, got tier %v", f.Tier)
			}
			if !strings.Contains(f.Evidence, "203.0.113.") && !strings.Contains(f.Evidence, "198.51.100.") {
				t.Errorf("evidence should carry the address the scan sent: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected a spoofable-IP row, got: %+v", findings)
	}
}

// A page that renders a fresh nonce on every request differs from itself, and
// the control is what tells that apart from a header-dependent page. Without
// this guard the row would fire on every dynamic site the scanner meets.
func TestHeaderBehaviorDynamicPageIsNotAHeaderDependency(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<html><body><p>request %d served at this instant</p>%s</body></html>`,
			hits, strings.Repeat("x", 200))
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := HeaderBehavior{}
	p := Point{URL: server.URL + "/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       `<html><body><p>request 0 served at this instant</p>` + strings.Repeat("x", 200) + `</body></html>`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	for _, f := range findings {
		if strings.Contains(f.Title, "Dependent Response") {
			t.Fatalf("a page that moves on its own must not be reported as header-dependent: %+v", f)
		}
	}
}

// The other half of the same measurement: a page that really does serve a
// different body to a different User-Agent, and says so in its evidence with the
// byte counts that decided the row.
func TestHeaderBehaviorUserAgentDependentResponse(t *testing.T) {
	var narrow = `<html><body><p>standard layout for a desktop browser</p>` +
		strings.Repeat("a", 300) + `</body></html>`
	var wide = `<html><body><p>compact layout for a small screen client</p>` +
		strings.Repeat("b", 500) + `</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.Header.Get("User-Agent"), "Mozilla") {
			_, _ = io.WriteString(w, wide)
			return
		}
		_, _ = io.WriteString(w, narrow)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := HeaderBehavior{}
	p := Point{URL: server.URL + "/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       narrow,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "User-Agent-Dependent Response") {
			found = true
			if !strings.Contains(f.Evidence, "bytes") {
				t.Errorf("the row should state the measurement that decided it: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected a User-Agent-dependent row, got: %+v", findings)
	}
}
