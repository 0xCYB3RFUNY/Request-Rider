package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A bounded pool is only worth having if a cancelled phase actually releases
// everything it took. The three properties below are the ones an operator
// actually loses when a worker outlives its job, and each test proves one of
// them rather than counting goroutines and calling that enough:
//
//	Confidentiality — an abandoned worker keeps a target's socket, and with it the
//	  TLS session, the headers and the body that were in flight. Nothing is
//	  returned to the report, so the leak is invisible: the evidence simply
//	  outlives the job that collected it.
//	Integrity — work that continues after cancel means the operator stopped
//	  something that kept happening, and the ledger says one thing while requests
//	  keep going out. A cancelled phase must issue no further request, and the
//	  answer must contain only names that really resolved.
//	Availability — a pinned dead socket is the failure the pool exists to
//	  prevent: the next job cannot open a connection because this one is still
//	  holding the descriptors. So the assertion is on open connections at the
//	  fixture, not on Go's goroutine count.
//
// The cancellation always lands while candidates are in flight: that is the case
// a leak hides in, because completion would rewind every worker by itself.

type leakProbe struct {
	started  atomic.Int64
	release  chan struct{}
	once     sync.Once
	inFlight atomic.Int64
	peak     atomic.Int64

	mu           sync.Mutex
	answered     map[string]bool
	afterRelease atomic.Int64
	stopped      chan struct{}
}

func newLeakProbe() *leakProbe {
	return &leakProbe{
		release:  make(chan struct{}),
		answered: map[string]bool{},
		stopped:  make(chan struct{}),
	}
}

func (probe *leakProbe) enter() {
	probe.started.Add(1)
	current := probe.inFlight.Add(1)
	for {
		peak := probe.peak.Load()
		if current <= peak || probe.peak.CompareAndSwap(peak, current) {
			return
		}
	}
}

// forget marks the point after which any request is a contract violation, and
// unblock releases the workers so a test can prove the pool is not stuck.
func (probe *leakProbe) forget() {
	probe.once.Do(func() { close(probe.stopped) })
	probe.unblock()
}

func (probe *leakProbe) unblock() {
	probe.once.Do(func() { close(probe.release) })
}

func (probe *leakProbe) countLate() int64 {
	select {
	case <-probe.stopped:
	default:
		return 0
	}
	return probe.afterRelease.Load()
}

func (probe *leakProbe) lookup(ctx context.Context, candidate string) ([]string, error) {
	select {
	case <-probe.stopped:
		probe.afterRelease.Add(1)
	default:
	}
	probe.enter()
	defer probe.inFlight.Add(-1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-probe.release:
		probe.mu.Lock()
		probe.answered[candidate] = true
		probe.mu.Unlock()
		return []string{"127.0.0.1"}, nil
	}
}

func (probe *leakProbe) head(ctx context.Context, rawURL, _ string) (int, bool) {
	select {
	case <-probe.stopped:
		probe.afterRelease.Add(1)
	default:
	}
	probe.enter()
	defer probe.inFlight.Add(-1)
	select {
	case <-ctx.Done():
		return 0, false
	case <-probe.release:
		probe.mu.Lock()
		probe.answered[rawURL] = true
		probe.mu.Unlock()
		return http.StatusNotFound, true
	}
}

func (probe *leakProbe) resolved() map[string]bool {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	copied := make(map[string]bool, len(probe.answered))
	for name := range probe.answered {
		copied[name] = true
	}
	return copied
}

func settledPoolGoroutineCount() int {
	for attempt := 0; attempt < 20; attempt++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// leakTestCollector builds the collector the way the job builds it — a gate
// behind every checkpoint — so the phase under test runs its real pause path
// instead of a stand-in that would hide the cancellation being exercised.
func leakTestCollector(ctx context.Context) *transformCollector {
	return &transformCollector{
		job:      &osintJob{ID: "osint-leak-probe", done: make(chan struct{}), gate: newPauseGate()},
		indexes:  1,
		ctx:      ctx,
		stop:     make(chan struct{}),
		progress: func(transformProgress) {},
	}
}

type phaseResult struct {
	hits    []dnsGuess
	applied int
}

func runCancelledPhase(t *testing.T, probe *leakProbe, phase func(ctx context.Context, collector *transformCollector) phaseResult) phaseResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	collector := leakTestCollector(ctx)
	result := make(chan phaseResult, 1)
	go func() { result <- phase(ctx, collector) }()
	for attempt := 0; attempt < 400 && probe.started.Load() < int64(bruteForceDefaultWorkers); attempt++ {
		time.Sleep(5 * time.Millisecond)
	}
	if probe.started.Load() == 0 {
		cancel()
		waitForPoolPhase(t, result)
		t.Fatal("the phase never reached the network, so nothing was measured")
	}
	cancel()
	return waitForPoolPhase(t, result)
}

func waitForPoolPhase(t *testing.T, result <-chan phaseResult) phaseResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(15 * time.Second):
		t.Fatal("a cancelled phase did not return: its workers are stuck")
		return phaseResult{}
	}
}

func TestBruteForceSubdomainsReleasesItsWorkersAfterCancel(t *testing.T) {
	words := make([]string, 0, 512)
	for index := 0; index < 512; index++ {
		words = append(words, fmt.Sprintf("candidate-%03d", index))
	}
	probe := newLeakProbe()
	phase := func(ctx context.Context, collector *transformCollector) phaseResult {
		hits, applied := bruteForceSubdomains(ctx, collector, probe.lookup, "example.test", words, map[string]bool{}, bruteForceDefaultWorkers)
		return phaseResult{hits: hits, applied: applied}
	}

	// The first cancelled run is the baseline: it pays for whatever the phase
	// starts in the runtime, so the comparison measures the second run only.
	runCancelledPhase(t, probe, phase)
	before := settledPoolGoroutineCount()
	result := runCancelledPhase(t, probe, phase)
	after := settledPoolGoroutineCount()

	if after > before+3 {
		t.Fatalf("a cancelled DNS phase left goroutines behind: %d settled before, %d after", before, after)
	}
	if peak := probe.peak.Load(); peak > int64(bruteForceDefaultWorkers) {
		t.Fatalf("%d candidates were resolved at once, so the pool did not bound the phase", peak)
	}
	if result.applied > len(words) {
		t.Fatalf("the phase reports %d applied workers for %d candidates", result.applied, len(words))
	}
	// A bounded pool must not become a way to quietly drop the wordlist, and a
	// cancel must be observed mid-phase rather than after the last candidate.
	if processed := probe.started.Load(); processed >= int64(len(words)) {
		t.Fatalf("the cancelled phase processed %d of %d candidates, so cancel was not observed", processed, len(words))
	}
	probe.forget()
}

func TestBucketChecksReleaseTheirWorkersAfterCancel(t *testing.T) {
	candidates := make([]string, 0, 256)
	for index := 0; index < 256; index++ {
		candidates = append(candidates, fmt.Sprintf("bucket-%03d", index))
	}
	providers := []string{"https://%s.example.invalid/"}
	probe := newLeakProbe()
	phase := func(ctx context.Context, collector *transformCollector) phaseResult {
		answers, applied := checkBucketCandidates(ctx, collector, candidates, providers, bucketCheckDefaultWorkers, probe.head)
		_ = answers
		return phaseResult{applied: applied}
	}

	runCancelledPhase(t, probe, phase) // baseline
	before := settledPoolGoroutineCount()
	runCancelledPhase(t, probe, phase)
	after := settledPoolGoroutineCount()

	if after > before+3 {
		t.Fatalf("a cancelled bucket phase left goroutines behind: %d settled before, %d after", before, after)
	}
	if peak := probe.peak.Load(); peak > int64(bucketCheckDefaultWorkers) {
		t.Fatalf("%d bucket endpoints were probed at once, so the pool did not bound the phase", peak)
	}
	probe.forget()
}

// Integrity: work that continues after cancel means the operator stopped
// something that kept happening. The phase is cancelled, then the workers are
// released, and any request that still reaches the probe is counted.
func TestACancelledPhaseIssuesNoRequestAfterItReturns(t *testing.T) {
	words := make([]string, 0, 256)
	for index := 0; index < 256; index++ {
		words = append(words, fmt.Sprintf("late-%03d", index))
	}
	probe := newLeakProbe()
	phase := func(ctx context.Context, collector *transformCollector) phaseResult {
		hits, applied := bruteForceSubdomains(ctx, collector, probe.lookup, "example.test", words, map[string]bool{}, bruteForceDefaultWorkers)
		return phaseResult{hits: hits, applied: applied}
	}

	runCancelledPhase(t, probe, phase)
	probe.forget()
	before := probe.countLate()
	time.Sleep(150 * time.Millisecond)
	if late := probe.countLate(); late > before {
		t.Fatalf("%d requests were issued after the phase had returned", late-before)
	}
}

// Integrity: the answer may only contain names that really resolved. A worker
// that kept going after cancel would put a name in the result that no lookup
// ever answered, and the report would attribute it to the target.
func TestACancelledPhaseAnswersOnlyWhatItResolved(t *testing.T) {
	words := make([]string, 0, 128)
	for index := 0; index < 128; index++ {
		words = append(words, fmt.Sprintf("answer-%03d", index))
	}
	probe := newLeakProbe()
	result := runCancelledPhase(t, probe, func(ctx context.Context, collector *transformCollector) phaseResult {
		hits, applied := bruteForceSubdomains(ctx, collector, probe.lookup, "example.test", words, map[string]bool{}, bruteForceDefaultWorkers)
		return phaseResult{hits: hits, applied: applied}
	})
	resolved := probe.resolved()
	probe.forget()

	if len(result.hits) > len(resolved) {
		t.Fatalf("the answer holds %d names but only %d lookups ever answered", len(result.hits), len(resolved))
	}
	for _, hit := range result.hits {
		if !resolved[hit.name] {
			t.Fatalf("the answer names %q, which no lookup ever resolved", hit.name)
		}
		if len(hit.ips) == 0 {
			t.Fatalf("the answer names %q with no addresses", hit.name)
		}
	}
	if !sort.SliceIsSorted(result.hits, func(left, right int) bool { return result.hits[left].name < result.hits[right].name }) {
		t.Fatal("the answer is not ordered by name, so two runs of the same evidence would differ")
	}
}

// Availability: a pinned dead socket is what the pool exists to prevent. The
// phase resolves through a real transport against a real server that never
// answers, and the assertion is on the connections the server still sees open
// after the cancel — goroutines can exit while a socket is still pinned.
func TestACancelledPhaseLeavesNoConnectionOpen(t *testing.T) {
	var open atomic.Int64
	// The hook is installed on an unstarted server: writing Config.ConnState
	// after Start would be a write the serving goroutine is already reading.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// The handler waits for the client to go away, so an abandoned request
		// keeps both the connection and this goroutine alive.
		<-request.Context().Done()
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}
	server.Start()
	defer server.Close()
	// The dialer names its own resolver instead of reading the global one: other
	// tests in this package swap `net.DefaultResolver` in their cleanup, and a
	// dial in flight is a read of that global. Owning the resolver here keeps this
	// test out of their cleanup window.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Resolver: &net.Resolver{PreferGo: true},
		}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	words := make([]string, 0, 64)
	for index := 0; index < 64; index++ {
		words = append(words, fmt.Sprintf("socket-%03d", index))
	}
	lookup := func(ctx context.Context, candidate string) ([]string, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/"+candidate, nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		response.Body.Close()
		return []string{"127.0.0.1"}, nil
	}

	// The fixture is the evidence here, not the probe: the phase is cancelled
	// while the server still holds connections, because those connections are
	// exactly what a worker can pin.
	ctx, cancel := context.WithCancel(context.Background())
	collector := leakTestCollector(ctx)
	returned := make(chan phaseResult, 1)
	go func() {
		hits, applied := bruteForceSubdomains(ctx, collector, lookup, "example.test", words, map[string]bool{}, bruteForceDefaultWorkers)
		returned <- phaseResult{hits: hits, applied: applied}
	}()
	if seen := waitForConnectionsToReach(t, &open, int64(bruteForceDefaultWorkers)); seen < int64(bruteForceDefaultWorkers) {
		cancel()
		waitForPoolPhase(t, returned)
		t.Fatalf("only %d connections were opened, so the pool bound nothing", seen)
	}
	cancel()
	waitForPoolPhase(t, returned)

	if settled := waitForConnectionsToReach(t, &open, 0); settled != 0 {
		t.Fatalf("%d connections were still open after the phase was cancelled, so the next job has fewer sockets to use", settled)
	}
}

// waitForConnectionsToReach samples the fixture's open-connection count until it
// reaches want, or the budget runs out; the sampled value is what the caller
// asserts on, so a timeout reports the real number instead of a bare failure.
func waitForConnectionsToReach(t *testing.T, open *atomic.Int64, want int64) int64 {
	t.Helper()
	value := open.Load()
	for attempt := 0; attempt < 120 && value != want; attempt++ {
		time.Sleep(25 * time.Millisecond)
		value = open.Load()
	}
	return value
}
