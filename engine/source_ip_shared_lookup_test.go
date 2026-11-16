package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The defect this file covers, measured on the operator's own export of
// 2026-10-10: 1500 exchanges inside 112ms, `source_ip` present on 210 of them.
// The lookup cost about three seconds each — DNS 0.86s, TCP 0.54s, TLS 0.84s,
// response 0.79s — so eight slots sustained 2.2 lookups a second against a burst
// of roughly thirteen thousand exchanges a second, and every lookup that could not
// take a slot returned an empty string rather than an address.
//
// Two things changed: the request now travels on a pooled connection, and callers
// that arrive while one is in flight share its answer. Neither of them keeps a
// value between flights, which is the property the removed cache violated.

// countingSourceIPTransport answers with a fixed body and counts requests. The
// delay is what makes a second request overlap the first, which is the condition
// coalescing exists to handle.
type countingSourceIPTransport struct {
	delay   time.Duration
	body    string
	calls   atomic.Int64
	inFlt   atomic.Int64
	peak    atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (c *countingSourceIPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	current := c.inFlt.Add(1)
	for {
		seen := c.peak.Load()
		if current <= seen || c.peak.CompareAndSwap(seen, current) {
			break
		}
	}
	if c.entered != nil {
		select {
		case c.entered <- struct{}{}:
		default:
		}
	}
	if c.release != nil {
		<-c.release
	} else if c.delay > 0 {
		time.Sleep(c.delay)
	}
	c.inFlt.Add(-1)
	body := c.body
	if body == "" {
		body = `{"IsTor":false,"IP":"203.0.113.77"}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       httpBody(body),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// Simultaneous callers must produce one request, not one request each. This is
// the assertion the export failed: 1500 exchanges, 210 answers.
func TestConcurrentSourceIPLookupsShareOneRequest(t *testing.T) {
	transport := &countingSourceIPTransport{
		delay:   40 * time.Millisecond,
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	const callers = 64
	results := make([]string, callers)
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index] = engine.ensureSourceIP(context.Background())
		}(i)
	}
	// Hold the single request open until every caller has had time to arrive and
	// join it. Without this the test would race the goroutines and could pass
	// simply because each one happened to start after the previous had finished.
	select {
	case <-transport.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no request was ever made")
	}
	time.Sleep(60 * time.Millisecond)
	close(transport.release)
	group.Wait()

	if calls := transport.calls.Load(); calls != 1 {
		t.Fatalf("made %d request(s) for %d simultaneous callers; they must share one", calls, callers)
	}
	for i, ip := range results {
		if ip != "203.0.113.77" {
			t.Fatalf("caller %d got %q; a shared lookup must give every caller the answer", i, ip)
		}
	}
}

// The shared answer must never outlive the request that produced it. A caller
// arriving after the flight has closed gets a NEW lookup, not the previous value
// — this is the staleness the cache had and the reason it was removed.
func TestSourceIPLookupIsNotRememberedAfterTheFlight(t *testing.T) {
	first := &countingSourceIPTransport{}
	first.entered = make(chan struct{}, 1)
	first.release = make(chan struct{})
	engine := &server{transport: &http.Transport{}, sourceIPTransport: first}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	go func() {
		select {
		case <-first.entered:
		case <-time.After(3 * time.Second):
		}
		close(first.release)
	}()
	if got := engine.ensureSourceIP(context.Background()); got != "203.0.113.77" {
		t.Fatalf("first lookup returned %q", got)
	}

	// The transport now answers with a different address, which is what a route
	// that changed looks like from here.
	second := &countingSourceIPTransport{body: `{"IsTor":false,"IP":"198.51.100.9"}`}
	engine.sourceIPTransport = second
	if got := engine.ensureSourceIP(context.Background()); got != "198.51.100.9" {
		t.Fatalf("after the first flight closed the lookup returned %q; it must ask again, not remember", got)
	}
	if calls := second.calls.Load(); calls != 1 {
		t.Fatalf("the second lookup made %d request(s); it must open its own", calls)
	}
}

// A failed lookup shares its failure with the callers already waiting, because
// they would all have failed against the same unreachable endpoint anyway. What
// it must not do is hand out a previous success.
func TestFailedSharedLookupReturnsEmptyToEveryone(t *testing.T) {
	failing := &failingSourceIPTransport{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: failing}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	const callers = 16
	results := make([]string, callers)
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index] = engine.ensureSourceIP(context.Background())
		}(i)
	}
	group.Wait()

	for i, ip := range results {
		if ip != "" {
			t.Fatalf("caller %d got %q from a failing endpoint; it must be empty", i, ip)
		}
	}
}

// The pool is what makes the lookup cheap, and it must be reused rather than
// rebuilt: keep-alive on, and a connection worth holding.
func TestLookupTransportKeepsItsConnectionAndFollowsTheRoute(t *testing.T) {
	manager := newTestRouteManager(t, "")
	transport := manager.lookupTransport()

	if transport.DisableKeepAlives {
		t.Fatal("the lookup transport disables keep-alive; every lookup would pay a fresh handshake again")
	}
	if transport.MaxIdleConnsPerHost < sourceIPLookupConcurrencyDefault {
		t.Fatalf("pool holds %d idle connections for one host, fewer than the %d lookups it may run",
			transport.MaxIdleConnsPerHost, sourceIPLookupConcurrencyDefault)
	}
	if again := manager.lookupTransport(); again != transport {
		t.Fatal("each call built a new transport; the pool is not reused")
	}
	// A route change replaces the pool, so a socket opened through the previous
	// exit is never handed to a lookup that runs under the new one.
	if err := manager.set(routeConfig{Address: ""}); err != nil {
		t.Fatalf("route change: %v", err)
	}
	if swapped := manager.lookupTransport(); swapped == transport {
		t.Fatal("the lookup transport survived a route change; it may keep the old exit's socket")
	}
}

// A refused lookup must still refuse — coalescing waits for an in-flight answer,
// it does not turn "no slot" into a request. The bound keeps its meaning, and so
// does the refusal: waiting instead is what starved the tools on 2026-10-10.
func TestCoalescingDoesNotBypassTheBound(t *testing.T) {
	transport := &countingSourceIPTransport{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}

	restore := fillSourceIPLookupSlots()
	defer restore()
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	started := time.Now()
	if got := engine.ensureSourceIP(context.Background()); got != "" {
		t.Fatalf("a lookup with no free slot returned %q", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("a lookup with no free slot waited %s; it must refuse at once", elapsed)
	}
	if calls := transport.calls.Load(); calls != 0 {
		t.Fatalf("a lookup with no free slot still made %d request(s)", calls)
	}
}

// The per-request deadline must survive the move into the shared flight: a stalled
// endpoint may not hold the flight open, because everything waiting on it waits
// behind that same request.
func TestSharedLookupObeysItsDeadline(t *testing.T) {
	stalled := &stallingSourceIPTransport{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: stalled}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "150")

	started := time.Now()
	ip := engine.ensureSourceIP(context.Background())
	elapsed := time.Since(started)

	if ip != "" {
		t.Fatalf("a stalled endpoint produced %q", ip)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("the shared lookup ran for %s; it must give up on its own deadline", elapsed)
	}
}

// A caller that arrives during a slow lookup waits for that answer, and the wait
// is bounded by that lookup's own deadline rather than being unbounded.
func TestCallerJoinsTheFlightInsteadOfDroppingOut(t *testing.T) {
	slow := &countingSourceIPTransport{
		delay:   250 * time.Millisecond,
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: slow}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	firstDone := make(chan string, 1)
	go func() { firstDone <- engine.ensureSourceIP(context.Background()) }()
	select {
	case <-slow.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the first lookup never started")
	}

	secondDone := make(chan string, 1)
	go func() { secondDone <- engine.ensureSourceIP(context.Background()) }()
	time.Sleep(40 * time.Millisecond)
	close(slow.release)

	select {
	case got := <-secondDone:
		if got != "203.0.113.77" {
			t.Fatalf("the joining caller got %q; it must receive the in-flight answer", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the joining caller never returned")
	}
	if got := <-firstDone; got != "203.0.113.77" {
		t.Fatalf("the first caller got %q", got)
	}
	if calls := slow.calls.Load(); calls != 1 {
		t.Fatalf("two callers made %d request(s); the second must join the first", calls)
	}
}

// The shared answer is scoped to a route generation. A lookup that started before
// a swap reports the old exit's address, so it must not be handed to a caller
// that arrives after the swap — that is precisely the stale value the cache gave.
func TestFlightsAreScopedToTheRouteGeneration(t *testing.T) {
	manager := newTestRouteManager(t, "")
	transport := &countingSourceIPTransport{}
	engine := &server{
		transport:         &http.Transport{},
		sourceIPTransport: transport,
		routes:            manager,
	}
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "5000")

	before := engine.sourceIPLookupRoute()
	if err := manager.set(routeConfig{Address: ""}); err != nil {
		t.Fatalf("route change: %v", err)
	}
	after := engine.sourceIPLookupRoute()

	if before == after {
		t.Fatal("the route generation did not change; the test cannot tell two routes apart")
	}
	if _, stale := lookupFlightForTesting(before); stale {
		t.Fatal("a flight from the previous generation is still registered")
	}
}

// httpBody keeps the response constructors readable.
func httpBody(content string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(content))
}

// newTestRouteManager builds a manager with a Direct route installed, so a test
// can exercise the real install path rather than a hand-built struct.
func newTestRouteManager(t *testing.T, address string) *routeManager {
	t.Helper()
	manager := &routeManager{}
	if err := manager.set(routeConfig{Address: address}); err != nil {
		t.Fatalf("install route %q: %v", address, err)
	}
	return manager
}

// lookupFlightForTesting reports whether a flight is registered for a route
// generation. A flight that has closed is removed, so this reads as "an answer
// from this generation is available right now".
func lookupFlightForTesting(route uint64) (*sourceIPFlight, bool) {
	sourceIPFlightsMu.Lock()
	defer sourceIPFlightsMu.Unlock()
	flight, ok := sourceIPFlights[route]
	return flight, ok
}

type failingSourceIPTransport struct{ calls atomic.Int64 }

func (f *failingSourceIPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, context.DeadlineExceeded
}

type stallingSourceIPTransport struct{}

func (stallingSourceIPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}