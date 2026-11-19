package passive

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The complaint this covers: a tool run fills its own answer with the exit
// address and leaves every recorded row empty. Measured on the operator's export
// of 2026-10-10 — 319 exchanges, one of them with `source_ip`, and that one came
// through the proxy rather than the tool. `captureTransport` had no reference to
// the resolver at all, so every scanner, OSINT, AI, automation and corpus exchange
// was recorded without the field.

func newCaptureRoundTripper(body string) http.RoundTripper {
	return roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Request:    request,
		}, nil
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

// waitForSourceIP polls the recorded event until the address lands. The lookup
// runs on its own goroutine by design, so "not there yet" is a normal state and
// not a failure; a missing field after the deadline is the failure.
func waitForSourceIP(t *testing.T, store *Store, eventID uint64) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events := store.List()
		for _, event := range events {
			if event.ID == eventID && event.SourceIP != "" {
				return event.SourceIP
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the recorded exchange never received a source_ip")
	return ""
}

func eventsOf(store *Store) []Event { return store.List() }

// A recorded exchange carries the address, which is the whole point.
func TestCaptureTransportRecordsTheSourceIP(t *testing.T) {
	store := NewStore()
	var calls int32
	var mu sync.Mutex
	resolver := func(context.Context) string {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return "203.0.113.5"
	}
	transport := NewCaptureTransport(newCaptureRoundTripper("ok"), store, "probe-1", resolver)

	request, err := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	events := eventsOf(store)
	if len(events) != 1 {
		t.Fatalf("recorded %d exchange(s), want 1", len(events))
	}
	if got := waitForSourceIP(t, store, events[0].ID); got != "203.0.113.5" {
		t.Fatalf("recorded source_ip = %q, want the resolver's answer", got)
	}
}

// The request must not wait for the lookup. An endpoint that stalls is a normal
// outage, and a tool whose every request is serialized behind it would look hung.
func TestCaptureTransportDoesNotBlockOnTheLookup(t *testing.T) {
	store := NewStore()
	release := make(chan struct{})
	resolver := func(context.Context) string {
		<-release
		return "203.0.113.5"
	}
	transport := NewCaptureTransport(newCaptureRoundTripper("ok"), store, "probe-2", resolver)

	request, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	started := time.Now()
	response, err := transport.RoundTrip(request)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	if elapsed > time.Second {
		t.Fatalf("the request waited %s for the lookup; it must not wait at all", elapsed)
	}
	close(release)
	waitForSourceIP(t, store, eventsOf(store)[0].ID)
}

// A failing lookup leaves the field empty and changes nothing else. An unreachable
// endpoint must not turn into an error on an exchange that itself succeeded.
func TestCaptureTransportSurvivesAFailedLookup(t *testing.T) {
	store := NewStore()
	transport := NewCaptureTransport(newCaptureRoundTripper("ok"), store, "probe-3",
		func(context.Context) string { return "" })

	request, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("a failed lookup broke the request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	time.Sleep(150 * time.Millisecond)
	events := eventsOf(store)
	if len(events) != 1 {
		t.Fatalf("recorded %d exchange(s), want 1", len(events))
	}
	if events[0].Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", events[0].Status)
	}
	if events[0].SourceIP != "" {
		t.Fatalf("source_ip = %q after a failed lookup, want it empty", events[0].SourceIP)
	}
}

// Without a resolver the run is still recorded. Some callers pass none, and a
// missing address may not cost the operator the exchange itself.
func TestCaptureTransportRecordsWithoutAResolver(t *testing.T) {
	store := NewStore()
	transport := NewCaptureTransport(newCaptureRoundTripper("ok"), store, "probe-4", nil)

	request, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	events := eventsOf(store)
	if len(events) != 1 {
		t.Fatalf("recorded %d exchange(s), want 1", len(events))
	}
	if events[0].SourceIP != "" {
		t.Fatalf("source_ip = %q with no resolver, want it empty", events[0].SourceIP)
	}
}

// The address is asked for per exchange, not once for the run, so a route that
// changes mid-run cannot leave later rows claiming the previous exit.
func TestCaptureTransportAsksTheResolverPerExchange(t *testing.T) {
	store := NewStore()
	var mu sync.Mutex
	seen := 0
	resolver := func(context.Context) string {
		mu.Lock()
		defer mu.Unlock()
		seen++
		return "203.0.113.5"
	}
	transport := NewCaptureTransport(newCaptureRoundTripper("ok"), store, "probe-5", resolver)

	for i := 0; i < 3; i++ {
		request, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := seen
		mu.Unlock()
		if got >= 3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the resolver was asked %d time(s) for 3 exchanges; a run must not answer from one lookup", seen)
}