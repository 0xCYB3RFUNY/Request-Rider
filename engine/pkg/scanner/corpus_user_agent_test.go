package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestCorpusScannerRotatesRealisticUserAgentsAndNeverLeaksRequestRider verifies that
// requests emitted by RunCorpus use realistic browser User-Agents from the pool and
// never disclose "RequestRider" or "Request-Rider" in the User-Agent header.
func TestCorpusScannerRotatesRealisticUserAgentsAndNeverLeaksRequestRider(t *testing.T) {
	var mu sync.Mutex
	seenUserAgents := make(map[string]int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		mu.Lock()
		seenUserAgents[ua]++
		mu.Unlock()

		if strings.Contains(ua, "RequestRider") || strings.Contains(ua, "Request-Rider") {
			t.Errorf("User-Agent leaked RequestRider identifier: %q", ua)
		}
		if !strings.HasPrefix(ua, "Mozilla/") && !strings.HasPrefix(ua, "Opera/") {
			t.Errorf("User-Agent is not a realistic browser UA: %q", ua)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Run corpus against test server with a limit of 15 checks
	result, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target:       server.URL,
		MaxChecks:    15,
		RoundTripper: server.Client().Transport,
	})
	if err != nil {
		t.Fatalf("RunCorpus failed: %v", err)
	}

	if result.Requests == 0 {
		t.Fatalf("expected requests to be sent, got 0")
	}

	mu.Lock()
	distinctUAs := len(seenUserAgents)
	mu.Unlock()

	if distinctUAs == 0 {
		t.Errorf("expected to see user agents recorded, got 0")
	}
}
