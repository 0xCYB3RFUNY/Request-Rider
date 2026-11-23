package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sourceIPLookupConcurrency reads one environment variable every call, so a test
// can set and unset it without a rebuild. The semaphore, by contrast, is built
// once at process start — so the tests that need a known capacity install and
// restore it themselves rather than depending on the ambient environment.
func TestSourceIPLookupConcurrencyHonoursTheEnvironment(t *testing.T) {
	t.Setenv("RR_SOURCE_IP_LOOKUP_CONCURRENCY", "")
	if got := sourceIPLookupConcurrency(); got != sourceIPLookupConcurrencyDefault {
		t.Fatalf("empty env: got %d, want the default %d", got, sourceIPLookupConcurrencyDefault)
	}
	for _, bad := range []string{"0", "-4", "abc", "12.5", "  "} {
		t.Setenv("RR_SOURCE_IP_LOOKUP_CONCURRENCY", bad)
		if got := sourceIPLookupConcurrency(); got != sourceIPLookupConcurrencyDefault {
			t.Fatalf("env=%q: got %d, want the default %d", bad, got, sourceIPLookupConcurrencyDefault)
		}
	}
	for _, value := range []string{"1", "16", " 64 "} {
		t.Setenv("RR_SOURCE_IP_LOOKUP_CONCURRENCY", value)
		want := 0
		for _, r := range strings.TrimSpace(value) {
			want = want*10 + int(r-'0')
		}
		if got := sourceIPLookupConcurrency(); got != want {
			t.Fatalf("env=%q: got %d, want %d", value, got, want)
		}
	}
}

// The bound has to be visible, or it is the kind of limit the operator can neither
// find nor change. This reads the same map the engine serves in its `bound` block.
func TestSourceIPLookupBoundIsReportedWithItsOverride(t *testing.T) {
	t.Setenv("RR_SOURCE_IP_LOOKUP_CONCURRENCY", "12")
	described := loadTransportBounds().describe()

	value, ok := described["source_ip_lookup_concurrency"]
	if !ok {
		t.Fatal("source_ip_lookup_concurrency is missing from the reported bounds")
	}
	if value != 12 {
		t.Fatalf("reported %v, want the 12 the environment asked for", value)
	}
	overrides, _ := described["overrides"].([]string)
	for _, name := range overrides {
		if name == "RR_SOURCE_IP_LOOKUP_CONCURRENCY" {
			return
		}
	}
	t.Fatalf("RR_SOURCE_IP_LOOKUP_CONCURRENCY is not listed among the overrides: %v", overrides)
}

// The bound has to actually bound: with every slot taken, a lookup cannot open a
// request, and it gives up on its own deadline rather than waiting forever.
func TestSourceIPLookupRefusedWhenEverySlotIsBusy(t *testing.T) {
	transport := &sourceIPRoundTripper{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}

	restore := fillSourceIPLookupSlots()
	defer restore()
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "120")

	started := time.Now()
	ip := engine.ensureSourceIP(context.Background())
	elapsed := time.Since(started)

	if ip != "" {
		t.Fatalf("a lookup with no free slot returned %q; it must return nothing", ip)
	}
	if transport.calls != 0 {
		t.Fatalf("a lookup with no free slot still made %d request(s); the bound did not hold", transport.calls)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("a refused lookup took %s; it must give up on its own deadline", elapsed)
	}
}

// The other caller must not wait at all. ensureSourceIP is what an operator-
// facing action goes through — starting a scan, running a tool, opening a
// listener — and what the passive proxy calls for each exchange's metadata.
//
// This test was briefly inverted to demand the opposite ("it waits"), and that
// inversion was reverted on 2026-10-10 because it starved the tools: a corpus of
// 11654 templates sent 153672 requests, every one of them reaching this function,
// and each waiting caller was holding a route lease while it stood still — so the
// scan queued instead of scanning, and exchanges came back late, then empty.
// A full semaphore means "this event carries no source_ip", never "this request
// is late".
func TestEnsureSourceIPNeverWaitsForASlot(t *testing.T) {
	transport := &sourceIPRoundTripper{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}

	restore := fillSourceIPLookupSlots()
	defer restore()
	// A generous deadline: the point is that it is not consulted at all.
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "30000")

	started := time.Now()
	ip := engine.ensureSourceIP(context.Background())
	elapsed := time.Since(started)

	if ip != "" {
		t.Fatalf("ensureSourceIP with no free slot returned %q; it must return nothing", ip)
	}
	if transport.calls != 0 {
		t.Fatalf("ensureSourceIP with no free slot still made %d request(s)", transport.calls)
	}
	if elapsed > time.Second {
		t.Fatalf("ensureSourceIP waited %s for a slot; it must never wait", elapsed)
	}
}

// A slot taken must be given back, or the bound is a one-way ratchet that silences
// the field after the first N exchanges of a long scan. Two sequential lookups
// both succeeding is what proves the release.
func TestSourceIPLookupReleasesItsSlot(t *testing.T) {
	transport := &sourceIPRoundTripper{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	first := engine.ensureSourceIP(context.Background())
	second := engine.ensureSourceIP(context.Background())

	if first == "" || second == "" {
		t.Fatalf("sequential lookups returned %q then %q; a slot was not released", first, second)
	}
	if transport.calls != 2 {
		t.Fatalf("made %d request(s) for two lookups; a slot was not released", transport.calls)
	}
}

// Under load the number of lookups in flight stays at the bound. The maximum is
// the assertion, not the total: callers that arrive together share one request,
// and every one of them still gets an answer.
func TestSourceIPLookupNeverExceedsItsBound(t *testing.T) {
	const bound = 4
	transport := &peakRoundTripper{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}

	restore := swapSourceIPLookupSlots(bound)
	defer restore()
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	const callers = 32
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			engine.ensureSourceIP(context.Background())
		}()
	}
	group.Wait()

	if peak := transport.peak(); peak > bound {
		t.Fatalf("peak in-flight lookups was %d, above the bound of %d", peak, bound)
	}
	// Callers that overlapped shared their request, so the number of requests is
	// a lower bound on the callers and never above it.
	if total := transport.count(); total > callers {
		t.Fatalf("made %d request(s) for %d callers; a caller opened more than one", total, callers)
	}
}

// fillSourceIPLookupSlots installs a semaphore of the current capacity that is
// already full, and returns a function that puts the process-wide one back. The
// original channel is never touched, so the restore is exact.
func fillSourceIPLookupSlots() func() {
	capacity := cap(sourceIPLookupSlots)
	previous := sourceIPLookupSlots
	full := make(chan struct{}, capacity)
	for i := 0; i < capacity; i++ {
		full <- struct{}{}
	}
	sourceIPLookupSlots = full
	return func() { sourceIPLookupSlots = previous }
}

// swapSourceIPLookupSlots installs an EMPTY semaphore of the given capacity and
// returns a function that puts the process-wide one back. Empty is what a
// bounded test needs: the point is how many lookups may start at once, not that
// none may start at all.
func swapSourceIPLookupSlots(capacity int) func() {
	previous := sourceIPLookupSlots
	sourceIPLookupSlots = make(chan struct{}, capacity)
	return func() { sourceIPLookupSlots = previous }
}

// peakRoundTripper counts requests and remembers the highest number that were
// ever inside RoundTrip at once. The existing sourceIPRoundTripper is not usable
// here: its counters are plain ints, and this test is exactly the one that would
// race on them.
type peakRoundTripper struct {
	inFlight atomic.Int64
	peakSeen atomic.Int64
	requests atomic.Int64
}

func (p *peakRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	p.requests.Add(1)
	current := p.inFlight.Add(1)
	for {
		seen := p.peakSeen.Load()
		if current <= seen || p.peakSeen.CompareAndSwap(seen, current) {
			break
		}
	}
	// Long enough that overlapping lookups really overlap, short enough that the
	// test does not wait on it.
	time.Sleep(20 * time.Millisecond)
	p.inFlight.Add(-1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (p *peakRoundTripper) peak() int64  { return p.peakSeen.Load() }
func (p *peakRoundTripper) count() int64 { return p.requests.Load() }
