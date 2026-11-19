package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitDetectsUnthrottledLoginEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{URL: srv.URL + "/api/login", Method: http.MethodPost, Param: "password"}
	baseline := &Response{StatusCode: http.StatusUnauthorized, Body: `{"error":"invalid credentials"}`}

	findings := (RateLimit{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 rate_limit finding, got %d", len(findings))
	}
	if findings[0].CWE != "CWE-307" {
		t.Fatalf("expected CWE-307, got %q", findings[0].CWE)
	}
}

func TestRateLimitRespects429Throttling(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) >= 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many attempts"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{MaxBackoff: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{URL: srv.URL + "/login", Method: http.MethodPost, Param: "password"}
	baseline := &Response{StatusCode: http.StatusUnauthorized}

	findings := (RateLimit{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when endpoint throttles with 429, got %d", len(findings))
	}
}
