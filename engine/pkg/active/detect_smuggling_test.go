package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSmugglingNormalEndpointDoesNotReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := Smuggling{}
	p := Point{URL: server.URL + "/api/test", Method: http.MethodPost}
	baseline := &Response{StatusCode: http.StatusOK, Duration: 10 * time.Millisecond}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) != 0 {
		t.Errorf("expected 0 smuggling findings on standard server, got %d: %+v", len(findings), findings)
	}
}

func TestSmugglingTimeoutDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// When probe is received, simulate timeout
		if r.Method == http.MethodPost {
			time.Sleep(4100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := Smuggling{}
	p := Point{URL: server.URL + "/api/test", Method: http.MethodPost}
	baseline := &Response{StatusCode: http.StatusOK, Duration: 10 * time.Millisecond}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) == 0 {
		t.Fatalf("expected smuggling finding on hanging endpoint, got 0")
	}

	foundSmuggling := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Smuggling") {
			foundSmuggling = true
		}
	}
	if !foundSmuggling {
		t.Errorf("expected Smuggling in findings: %+v", findings)
	}
}
