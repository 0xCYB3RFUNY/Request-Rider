package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// jobFixture is a local certificate index whose answer can be slowed down, so
// a pause and a cancel can be observed while the transform is still running.
type jobFixture struct {
	mutex     sync.Mutex
	served    int
	names     int
	delay     time.Duration
	stopped   bool
	lastAfter string
}

func (fixture *jobFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.mutex.Lock()
	fixture.served++
	fixture.lastAfter = r.URL.Query().Get("after")
	delay := fixture.delay
	fixture.mutex.Unlock()

	if delay > 0 {
		// One name per line with a pause between them, so the transform is
		// genuinely still collecting when the control action arrives.
		w.Header().Set("Content-Type", "text/plain")
		flusher, _ := w.(http.Flusher)
		for index := 0; index < fixture.names; index++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
			if _, err := fmt.Fprintf(w, "host%d.example.test\n", index); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		return
	}
	// The same answer in one shot, in the line format this index serves.
	var body strings.Builder
	for index := 0; index < fixture.names; index++ {
		fmt.Fprintf(&body, "host%d.example.test\n", index)
	}
	_, _ = io.WriteString(w, body.String())
}

func (fixture *jobFixture) count() int {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()
	return fixture.served
}

func jobSource(base string) certificateSource {
	return certificateSource{
		name:   "crt.name",
		query:  base + "/?apex=example.test",
		accept: "text/plain",
		page:   readLineNames,
	}
}

// offlineResolver points the default resolver at a stub that answers NXDOMAIN
// without touching the network, so a transform that probes wildcard DNS and
// resolves a wordlist does not spend the test's time on real DNS.
func offlineResolver(t *testing.T) {
	t.Helper()
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "no network in tests", Name: address, IsNotFound: true}
		},
	}
}

// runJob starts a background subdomains transform against the local fixture.
//
// The brute force wordlist is pinned to one name and the resolver is offline, so
// the test never depends on real DNS: what is under test is the job lifecycle,
// not the resolver.
func runJob(t *testing.T, engine *server, fixture *jobFixture) *osintJob {
	t.Helper()
	offlineResolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return engine.startOSINTJob(ctx, osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-host-for-tests"}},
	}, func() {})
}

func TestOSINTJobRunsToCompletion(t *testing.T) {
	fixture := &jobFixture{names: 40}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := newJobEngine(httpServer.URL)

	job := runJob(t, engine, fixture)
	waitForPhase(t, job, osintJobCompleted)
	snapshot := job.Snapshot()
	if snapshot.Result == nil {
		t.Fatalf("a completed transform produced no result: %#v", snapshot)
	}
	names := 0
	for _, item := range snapshot.Result.Entities {
		if item.Type == "subdomain" {
			names++
		}
	}
	if names != fixture.names {
		t.Fatalf("subdomains = %d, want %d", names, fixture.names)
	}
	if snapshot.Progress.ElapsedMS < 0 {
		t.Fatalf("elapsed = %d", snapshot.Progress.ElapsedMS)
	}
	if strings.Contains(snapshot.Error, "http") {
		t.Fatalf("a completed transform reported an error: %q", snapshot.Error)
	}
}

func TestOSINTJobPauseSuspendsCollectionAndResumeContinuesIt(t *testing.T) {
	// The answer is long enough that the progress report lands while the phase
	// is still streaming, so the pause suspends a running collector instead of
	// arriving after the transform already finished.
	fixture := &jobFixture{names: 500, delay: 5 * time.Millisecond}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := newJobEngine(httpServer.URL)

	job := runJob(t, engine, fixture)
	// Let the transform collect something before it is suspended.
	waitForNames(t, job, 1)
	if err := pauseOSINTJob(job.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if snapshot := job.Snapshot(); snapshot.State != osintJobPaused {
		t.Fatalf("state after pause = %q", snapshot.State)
	}
	// A paused transform keeps what it collected and stops collecting more.
	frozen := job.Snapshot().Progress.Names
	time.Sleep(200 * time.Millisecond)
	if grown := job.Snapshot().Progress.Names; grown > frozen+reportEvery {
		t.Fatalf("a paused transform kept collecting: %d -> %d", frozen, grown)
	}
	if snapshot := job.Snapshot(); snapshot.State != osintJobPaused {
		t.Fatalf("state while paused = %q", snapshot.State)
	}
	if err := resumeOSINTJob(job.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	waitForPhase(t, job, osintJobCompleted)
	if got := job.Snapshot().Progress.Names; got < frozen {
		t.Fatalf("resume lost collected names: %d < %d", got, frozen)
	}
}

func TestOSINTJobCancelStopsTheTransform(t *testing.T) {
	fixture := &jobFixture{names: 500, delay: 5 * time.Millisecond}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := newJobEngine(httpServer.URL)

	job := runJob(t, engine, fixture)
	waitForNames(t, job, 1)
	if !cancelOSINTJob(job.ID) {
		t.Fatal("cancel reported the job as already finished")
	}
	waitForPhase(t, job, osintJobCancelled)
	snapshot := job.Snapshot()
	if snapshot.Result != nil {
		t.Fatalf("a cancelled transform produced a result: %#v", snapshot.Result)
	}
	// Cancelling twice is not silently accepted.
	if cancelOSINTJob(job.ID) {
		t.Fatal("a second cancel was accepted")
	}
}

func TestOSINTJobCancelWorksWhilePaused(t *testing.T) {
	fixture := &jobFixture{names: 500, delay: 5 * time.Millisecond}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := newJobEngine(httpServer.URL)

	job := runJob(t, engine, fixture)
	waitForNames(t, job, 1)
	if err := pauseOSINTJob(job.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	// A paused collector waits on the gate, so a cancel has to release it or
	// the job would never observe the cancellation.
	if !cancelOSINTJob(job.ID) {
		t.Fatal("cancel of a paused transform was refused")
	}
	waitForPhase(t, job, osintJobCancelled)
}

func TestOSINTJobRejectsControlActionsInTheWrongState(t *testing.T) {
	fixture := &jobFixture{names: 3}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := newJobEngine(httpServer.URL)

	job := runJob(t, engine, fixture)
	waitForPhase(t, job, osintJobCompleted)
	if err := pauseOSINTJob(job.ID); err == nil {
		t.Fatal("a finished transform was paused")
	}
	if err := resumeOSINTJob(job.ID); err == nil {
		t.Fatal("a finished transform was resumed")
	}
	if err := pauseOSINTJob("osint-does-not-exist"); err == nil {
		t.Fatal("an unknown transform was paused")
	}
}

func TestOSINTJobSnapshotForUnknownJob(t *testing.T) {
	if _, ok := osintJobSnapshotFor("osint-nothing"); ok {
		t.Fatal("an unknown transform reported a snapshot")
	}
}

func TestOSINTJobSweepsFinishedTransforms(t *testing.T) {
	job := &osintJob{
		ID:        "osint-old",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		progress:  osintJobProgress{Phase: osintJobCompleted},
		done:      make(chan struct{}),
		gate:      newPauseGate(),
	}
	osintJobs.add(job)
	osintJobs.sweepFinished(30 * time.Minute)
	if _, ok := osintJobs.get("osint-old"); ok {
		t.Fatal("a finished transform was not swept")
	}
	// A running transform is never swept, however old it is.
	running := &osintJob{
		ID:        "osint-running",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		progress:  osintJobProgress{Phase: osintJobRunning},
		done:      make(chan struct{}),
		gate:      newPauseGate(),
	}
	osintJobs.add(running)
	osintJobs.sweepFinished(30 * time.Minute)
	if _, ok := osintJobs.get("osint-running"); !ok {
		t.Fatal("a running transform was swept away")
	}
	delete(osintJobs.jobs, "osint-running")
}

func TestPauseGateHonoursCancellationWhilePaused(t *testing.T) {
	gate := newPauseGate()
	ctx, cancel := context.WithCancel(context.Background())
	gate.pause()
	released := make(chan error, 1)
	go func() { released <- gate.checkpoint(ctx) }()
	// The gate is paused, so the checkpoint cannot return on its own.
	select {
	case <-released:
		t.Fatal("a paused gate let a checkpoint through")
	case <-time.After(100 * time.Millisecond):
	}
	// A cancelled route ends a paused transform instead of hanging on it.
	cancel()
	select {
	case err := <-released:
		if err == nil {
			t.Fatal("a cancelled checkpoint reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a paused gate ignored the cancellation")
	}
	gate.resume()
}

func TestValidateTransformInputRejectsUnusableRequests(t *testing.T) {
	cases := []struct {
		name  string
		input osintTransformInput
		code  string
	}{
		{"empty value", osintTransformInput{Transform: "subdomains"}, "INVALID_VALUE"},
		{"unknown transform", osintTransformInput{Transform: "nope", Value: "example.test"}, "UNKNOWN_TRANSFORM"},
		{"network without confirmation", osintTransformInput{Transform: "subdomains", Value: "example.test"}, "NETWORK_CONFIRMATION_REQUIRED"},
		{"case is normalised", osintTransformInput{Transform: "  SubDomains ", Value: "example.test", ConfirmNetwork: true}, ""},
		{"local transform needs no confirmation", osintTransformInput{Transform: "domain_normalize", Value: "Example.test"}, ""},
	}
	for _, testCase := range cases {
		input := testCase.input
		code, _, ok := validateTransformInput(&input)
		if testCase.code == "" {
			if !ok {
				t.Fatalf("%s: was rejected with %q", testCase.name, code)
			}
			continue
		}
		if ok || code != testCase.code {
			t.Fatalf("%s: code = %q ok = %v, want %q", testCase.name, code, ok, testCase.code)
		}
	}
}

func waitForPhase(t *testing.T, job *osintJob, phase string) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		if snapshot := job.Snapshot(); snapshot.State == phase {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("transform stayed in %q, want %q", job.Snapshot().State, phase)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitForNames(t *testing.T, job *osintJob, names int) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		if job.Snapshot().Progress.Names >= names {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("transform collected %d names, want %d", job.Snapshot().Progress.Names, names)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// newJobEngine builds an engine whose certificate chain is a single local
// index, so a background transform never reaches the public network.
func newJobEngine(baseURL string) *server {
	engine := &server{transport: &http.Transport{}}
	engine.certificateIndexList = func(domain string) []certificateSource {
		return []certificateSource{jobSource(baseURL)}
	}
	return engine
}

// The DNS phase is a pause point like the certificate phase, so a paused job
// suspends between candidates instead of resolving the whole wordlist, and a
// resume continues the wordlist instead of dropping it.
func TestBruteForceSubdomainsHonoursThePauseGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resolved := 0
	var mutex sync.Mutex
	lookup := func(context.Context, string) ([]string, error) {
		mutex.Lock()
		resolved++
		mutex.Unlock()
		// A real resolver is not instantaneous.
		time.Sleep(2 * time.Millisecond)
		return nil, fmt.Errorf("NXDOMAIN")
	}
	gate := newPauseGate()
	job := &osintJob{ID: "osint-dns", done: make(chan struct{}), gate: gate}
	collector := &transformCollector{
		job:      job,
		indexes:  5,
		ctx:      ctx,
		stop:     make(chan struct{}),
		progress: func(transformProgress) {},
	}
	words := make([]string, 0, 120)
	for index := 0; index < 120; index++ {
		words = append(words, fmt.Sprintf("host%03d", index))
	}
	// The gate is closed before the phase starts, so a paused phase must
	// resolve nothing at all.
	gate.pause()
	done := make(chan []dnsGuess, 1)
	go func() {
		done <- bruteForceSubdomains(ctx, collector, lookup, "example.test", words, map[string]bool{})
	}()
	select {
	case hits := <-done:
		t.Fatalf("a paused phase ran to the end: %#v", hits)
	case <-time.After(150 * time.Millisecond):
	}
	mutex.Lock()
	paused := resolved
	mutex.Unlock()
	if paused > bruteForceWorkerCount {
		t.Fatalf("a paused phase resolved %d candidates", paused)
	}
	// The resume releases it and the whole wordlist is still resolved, so the
	// pause suspends the work instead of discarding it.
	gate.resume()
	hits := <-done
	if len(hits) != 0 {
		t.Fatalf("every candidate is NXDOMAIN, hits = %#v", hits)
	}
	mutex.Lock()
	total := resolved
	mutex.Unlock()
	if total != len(words) {
		t.Fatalf("the resumed phase resolved %d of %d candidates", total, len(words))
	}
}

// The progress panel counts the queries a run really performs: the certificate
// indexes multiplied by the zone chain the input resolves to.
func TestOSINTJobCountsTheZoneChainOfItsIndexes(t *testing.T) {
	engine := newJobEngine("http://127.0.0.1:1")
	// A host input asks every index about the host and about the zone above it.
	if total := engine.certificateQueryTotal(osintTransformInput{Transform: subdomainTransform, Value: "www.example.test"}); total != 2 {
		t.Fatalf("queries for a host input = %d, want 2", total)
	}
	// An apex input is one zone, so it costs one round of queries.
	if total := engine.certificateQueryTotal(osintTransformInput{Transform: subdomainTransform, Value: "example.test"}); total != 1 {
		t.Fatalf("queries for an apex input = %d, want 1", total)
	}
	// A transform that queries no certificate index promises none, so the panel
	// shows no index counter for it.
	if total := engine.certificateQueryTotal(osintTransformInput{Transform: "wayback_urls", Value: "example.test"}); total != 0 {
		t.Fatalf("queries for an archive transform = %d, want 0", total)
	}
}

// A names counter is only real for a transform that streams names through the
// collector. Reporting a structural zero for the others would make the panel
// claim "0 names" during a reverse DNS lookup that never counts names.
func TestOSINTJobStatesWhetherItCollectsNames(t *testing.T) {
	engine := newJobEngine("http://127.0.0.1:1")
	offlineResolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	collecting := engine.startOSINTJob(ctx, osintTransformInput{
		Transform: subdomainTransform, Value: "example.test", ConfirmNetwork: true,
	}, func() {})
	if !collecting.Snapshot().Progress.CollectsNames {
		t.Fatalf("a subdomains run must report a names counter")
	}
	collecting.cancel()
	<-collecting.done

	other := engine.startOSINTJob(ctx, osintTransformInput{
		Transform: "reverse_dns", Value: "198.51.100.4", ConfirmNetwork: true,
	}, func() {})
	if other.Snapshot().Progress.CollectsNames {
		t.Fatalf("a reverse DNS run must not report a names counter")
	}
	other.cancel()
	<-other.done
}
