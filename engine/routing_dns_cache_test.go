package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedDirectDialerDeduplicatesConcurrentAndRepeatedLookups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	var lookups atomic.Int32
	c := &cachedDirectDialer{
		dialer: &net.Dialer{Timeout: 2 * time.Second},
		ttl:    60 * time.Second,
		lookupFn: func(ctx context.Context, host string) ([]string, error) {
			lookups.Add(1)
			time.Sleep(15 * time.Millisecond)
			return []string{"127.0.0.1"}, nil
		},
		entries:  make(map[string]dnsCacheEntry),
		inflight: make(map[string]*dnsInflight),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, derr := c.DialContext(context.Background(), "tcp", net.JoinHostPort("example.local", port))
			if derr != nil {
				t.Errorf("DialContext failed: %v", derr)
				return
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()

	if got := lookups.Load(); got != 1 {
		t.Fatalf("expected exactly 1 DNS lookup across 20 concurrent dials, got %d", got)
	}
}
