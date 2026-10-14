package main

import (
	"context"
	"crypto/tls"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The bounds protect a connection from being left half-open. A test that only
// checked the constants would pass even if nothing applied them, so every case
// here reads the value back off a real transport or measures a real stall.

func TestEveryBuiltTransportCarriesTheBounds(t *testing.T) {
	// The dialer is never invoked here: this asserts the fields a transport was
	// built with, and a nil route dialer would only matter if a request were made.
	manager := &routeManager{}
	bounds := loadTransportBounds()

	transports := map[string]*http.Transport{
		"generation": manager.newTransportLocked(),
		"shared":     manager.newSharedTransportLocked(),
		"ephemeral":  manager.ephemeralTransport(),
	}
	for name, transport := range transports {
		if transport.TLSHandshakeTimeout != bounds.TLSHandshakeTimeout {
			t.Fatalf("%s transport handshake timeout = %v, want %v", name, transport.TLSHandshakeTimeout, bounds.TLSHandshakeTimeout)
		}
		if transport.ResponseHeaderTimeout != bounds.ResponseHeaderTimeout {
			t.Fatalf("%s transport response header timeout = %v, want %v", name, transport.ResponseHeaderTimeout, bounds.ResponseHeaderTimeout)
		}
		if transport.IdleConnTimeout != bounds.IdleConnTimeout {
			t.Fatalf("%s transport idle conn timeout = %v, want %v", name, transport.IdleConnTimeout, bounds.IdleConnTimeout)
		}
	}
}

func TestTransportBoundsFallBackToTheDocumentedDefault(t *testing.T) {
	// A typo must not remove a bound: a removed bound looks exactly like a slow
	// target until the process wedges. Every unusable value therefore has to land
	// on the default, and never on zero.
	cases := map[string]string{
		"unparseable": "soon",
		"zero":        "0",
		"negative":    "-1",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("RR_DIAL_TIMEOUT_MS", value)
			if got := positiveDurationEnv("RR_DIAL_TIMEOUT_MS", defaultDialTimeout); got != defaultDialTimeout {
				t.Fatalf("got %v, want the documented default %v", got, defaultDialTimeout)
			}
		})
	}
	t.Run("unset", func(t *testing.T) {
		if got := positiveDurationEnv("RR_UNUSED_TEST_VARIABLE", defaultDialTimeout); got != defaultDialTimeout {
			t.Fatalf("got %v, want %v", got, defaultDialTimeout)
		}
	})
	t.Run("explicit value wins", func(t *testing.T) {
		t.Setenv("RR_DIAL_TIMEOUT_MS", "2500")
		if got := positiveDurationEnv("RR_DIAL_TIMEOUT_MS", defaultDialTimeout); got != 2500*time.Millisecond {
			t.Fatalf("got %v, want 2.5s", got)
		}
	})
}

// A raise is not clamped. An operator whose target legitimately needs a minute
// and a half to answer must be able to say so, or the bound becomes the cap the
// project rules forbid.
func TestTransportBoundsAreNotCapped(t *testing.T) {
	t.Setenv("RR_RESPONSE_HEADER_TIMEOUT_MS", "600000")
	if got := positiveDurationEnv("RR_RESPONSE_HEADER_TIMEOUT_MS", defaultResponseHeaderTimeout); got != 10*time.Minute {
		t.Fatalf("got %v, want the full 10 minutes the operator asked for", got)
	}
}

// The header bound is the one that actually needs proving, because a server that
// answers the connection and then says nothing is indistinguishable from a dead
// socket. Before the bound, this request runs until the caller's context ends.
func TestResponseHeaderBoundEndsAStalledResponse(t *testing.T) {
	stalled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Headers are never written and the body never starts, so the client
		// waits exactly where a dead target would leave it.
		w.Header()
		<-stalled
	}))
	defer server.Close()
	defer close(stalled)

	transport := &http.Transport{
		TLSHandshakeTimeout:   time.Second,
		ResponseHeaderTimeout: 300 * time.Millisecond,
		IdleConnTimeout:       time.Second,
	}
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	started := time.Now()
	if _, err := client.Do(request); err == nil {
		t.Fatal("a response that never sent headers returned a result")
	}
	elapsed := time.Since(started)
	if elapsed > 5*time.Second {
		t.Fatalf("the header bound did not apply, the request took %v", elapsed)
	}
}

// The dial bound covers establishing the connection, and the point of it is that
// a black-holed address cannot hold a goroutine for the operating system's
// multi-minute connect timeout. A listener that accepts nothing is not enough:
// the address has to be one that drops the handshake.
func TestDialBoundIsCarriedByTheRouteDialer(t *testing.T) {
	dial, err := buildRouteDialer("")
	if err != nil {
		t.Fatalf("buildRouteDialer: %v", err)
	}
	// The bound has to be readable off the dialer the transport will use, and the
	// route dialer is the only place a connection is ever made.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	// A listener that never accepts leaves the connection in the backlog, so the
	// dial itself completes; this asserts the transport path reaches the route
	// dialer and that the bound did not make it fail early.
	address := listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", address)
	if err == nil {
		_ = conn.Close()
	}
	if ctx.Err() != nil {
		t.Fatal("the route dialer ignored the caller's context")
	}
}

// positiveCount reads a reported bound as the number it stands for.
//
// The reported value's Go type is deliberately not part of the contract: it
// marshals to a JSON number either way, so no consumer can tell `int` from
// `int64`. Asserting a type here would only make the test fail when someone adds
// a bound using the other one, for no reason a user could observe.
func positiveCount(t *testing.T, described map[string]interface{}, key string) int64 {
	t.Helper()
	switch value := described[key].(type) {
	case int:
		if value <= 0 {
			t.Fatalf("%s = %v, want a positive count", key, value)
		}
		return int64(value)
	case int64:
		if value <= 0 {
			t.Fatalf("%s = %v, want a positive count", key, value)
		}
		return value
	default:
		t.Fatalf("%s = %v (%T), want a positive number", key, described[key], described[key])
		return 0
	}
}

func TestTransportBoundsDescriptionReportsMilliseconds(t *testing.T) {
	described := loadTransportBounds().describe()
	for _, key := range []string{
		"dial_timeout_ms", "tls_handshake_timeout_ms",
		"response_header_timeout_ms", "idle_conn_timeout_ms",
		"control_plane_body_limit_bytes", "finished_job_retention_minutes",
	} {
		positiveCount(t, described, key)
	}

	// The names have to be the ones the operator would actually set, and a bound
	// with no name is a bound nobody can find.
	overrides, ok := described["overrides"].([]string)
	if !ok || len(overrides) == 0 {
		t.Fatalf("overrides = %v, want the environment names", described["overrides"])
	}
	seen := map[string]bool{}
	for _, name := range overrides {
		if seen[name] {
			t.Fatalf("%q is listed twice: %v", name, overrides)
		}
		seen[name] = true
	}
	for _, want := range []string{
		"RR_DIAL_TIMEOUT_MS", "RR_TLS_HANDSHAKE_TIMEOUT_MS",
		"RR_RESPONSE_HEADER_TIMEOUT_MS", "RR_IDLE_CONN_TIMEOUT_MS",
		"RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "RR_FINISHED_JOB_RETENTION_MINUTES",
	} {
		if !seen[want] {
			t.Fatalf("%q is not named in the reported overrides %v", want, overrides)
		}
	}

	// Every reported number has a name beside it, so a value can never appear in
	// the report without the operator being told what sets it. The count is not
	// pinned: bounds are added over time, and pinning it would only mean
	// editing this test each time one is added.
	if len(overrides) < len(described)-1 {
		t.Fatalf("%d bounds reported but only %d overrides named", len(described)-1, len(overrides))
	}
}

func TestTransportDialerCarriesKeepAlive(t *testing.T) {
	dialer := loadTransportBounds().dialer()
	if dialer.Timeout <= 0 {
		t.Fatal("the route dialer carries no dial bound")
	}
	if dialer.KeepAlive <= 0 {
		t.Fatal("the route dialer carries no keepalive, so a connection that died silently is never noticed")
	}
	// The TLS floor is a security setting and must survive the bound work.
	if (&tls.Config{MinVersion: tls.VersionTLS12}).MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS floor changed")
	}
}

// The bounds exist to protect resources, so a bound that released the call but
// kept the connection and its read loop alive would defeat the point. A stalled
// target is driven repeatedly through one transport and the client's goroutine
// count has to settle.
//
// The server side is released and drained before the count is taken: a handler
// blocked in the test fixture is a goroutine the test created, and counting it
// would blame the transport for the fixture's own hold.
func TestBoundedStalledResponsesDoNotLeakGoroutines(t *testing.T) {
	transport := &http.Transport{
		TLSHandshakeTimeout:   time.Second,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		IdleConnTimeout:       time.Second,
	}
	client := &http.Client{Transport: transport}
	const attempts = 12

	// stallRound opens a fresh fixture, drives `attempts` requests that can never
	// be answered, and returns once the client is free of them again. A fresh
	// server per round matters: a connection left pooled by the previous round
	// would be reused and the round would not stall at all.
	stallRound := func() {
		release := make(chan struct{})
		var handled atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header()
			<-release
			handled.Add(1)
		}))
		defer server.Close()
		for attempt := 0; attempt < attempts; attempt++ {
			// The caller keeps its own deadline, but it is far longer than the
			// bound: a call that ends because the caller gave up would mean the
			// bound is not doing the work, which is the failure this test exists
			// to catch. A missing bound then fails in seconds instead of hanging
			// until the test binary's own timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				cancel()
				t.Fatalf("request: %v", err)
			}
			started := time.Now()
			response, err := client.Do(request)
			elapsed := time.Since(started)
			cancel()
			if err == nil {
				response.Body.Close()
				t.Fatal("a response that never sent headers returned a result")
			}
			if elapsed >= 3*time.Second {
				t.Fatalf("request %d waited %v for the caller's own deadline, so the response header bound never applied", attempt, elapsed)
			}
		}
		// The fixture is released and drained before the count is taken: a handler
		// blocked in the test is a goroutine the test created, and counting it
		// would blame the transport for the fixture's own hold.
		close(release)
		waitFor(t, func() bool { return handled.Load() == attempts })
		transport.CloseIdleConnections()
	}

	// The first round is the baseline: opening connections starts runtime and
	// transport helpers that legitimately stay for the life of the transport.
	stallRound()
	before := settledGoroutineCount()
	stallRound()
	after := settledGoroutineCount()

	// A read loop per abandoned connection would be `attempts` extra goroutines.
	// The allowance covers runtime helpers, and is far below what a leak produces.
	if after > before+3 {
		t.Fatalf("client goroutines grew from %d to %d across %d stalled responses", before, after, attempts)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the fixture to settle")
}

// settledGoroutineCount samples after giving the runtime and the transport time
// to reap what they are finished with.
func settledGoroutineCount() int {
	for attempt := 0; attempt < 40; attempt++ {
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// The one byte read past the limit is what proves the answer was too large, so
// `limit+1` has to stay a positive number. The largest representable int64 is the
// one value that cannot be used, because the byte read past it has nowhere to go:
// it falls back to the documented default rather than turning every control-plane
// read into a silent failure, because io.LimitReader with a negative count reads
// nothing at all.
func TestControlPlaneLimitAtTheVeryTopOfTheRange(t *testing.T) {
	t.Setenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "9223372036854775807")
	if got := controlPlaneBodyLimit(); got != defaultControlPlaneBodyLimit {
		t.Fatalf("limit = %d, want the documented default because limit+1 is not representable", got)
	}
	// The largest usable value is accepted, and a read still works at it.
	t.Setenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "9223372036854775806")
	if got := controlPlaneBodyLimit(); got != math.MaxInt64-1 {
		t.Fatalf("limit = %d, want the operator value", got)
	}
	body, err := readControlPlaneBody(strings.NewReader("small"))
	if err != nil || string(body) != "small" {
		t.Fatalf("a read at the top of the range failed: %q, %v", body, err)
	}
	// A value past int64 is not a number the engine can use, so it falls back too.
	t.Setenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "9223372036854775808")
	if got := controlPlaneBodyLimit(); got != defaultControlPlaneBodyLimit {
		t.Fatalf("limit = %d, want the documented default for a value past int64", got)
	}
}

func TestControlPlaneBodyLimitRejectsAnOversizedAnswer(t *testing.T) {
	t.Setenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "1024")
	oversized := strings.NewReader(strings.Repeat("a", 2048))
	if _, err := readControlPlaneBody(oversized); err == nil {
		t.Fatal("a service response past the limit was read whole")
	} else if !strings.Contains(err.Error(), "1024") {
		// The message has to carry the number, or the operator cannot tell which
		// limit was hit and whether raising it would help.
		t.Fatalf("error %q does not name the limit", err)
	}
	fits := strings.NewReader(strings.Repeat("a", 1024))
	if data, err := readControlPlaneBody(fits); err != nil || len(data) != 1024 {
		t.Fatalf("a response at the limit was refused: %d bytes, %v", len(data), err)
	}
	// An unusable override falls back to the documented default rather than
	// removing the bound, which is the same rule the deadlines follow.
	t.Setenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "plenty")
	if got := controlPlaneBodyLimit(); got != defaultControlPlaneBodyLimit {
		t.Fatalf("got %d, want the documented default %d", got, defaultControlPlaneBodyLimit)
	}
}

// The bound is not a cap: a provider that genuinely answers with more is not
// second-guessed, because the engine does not decide what a third party may say.
func TestControlPlaneBodyLimitIsNotCapped(t *testing.T) {
	t.Setenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES", "134217728")
	if got := controlPlaneBodyLimit(); got != 134217728 {
		t.Fatalf("got %d, want the full 128 MiB the operator asked for", got)
	}
}

// The bound must never reach a target exchange. A truncated response is a lost
// finding, so the reading path for Repeater, Intruder, Burst and Last-Byte has to
// stay a plain unbounded read even while the service reads beside it are bounded.
func TestTargetResponsesAreStillReadWhole(t *testing.T) {
	oversized := strings.Repeat("a", 3<<20)
	// The control-plane helper is a separate function precisely so this separation
	// is structural: nothing routes a target body through it.
	if _, err := readControlPlaneBody(strings.NewReader(oversized)); err == nil {
		t.Fatal("the control-plane helper accepted a 3 MiB body, so the bound is not being applied")
	}
	// A plain unbounded read is what the target paths use, and it keeps every byte
	// no matter how large the answer is.
	if data, err := io.ReadAll(strings.NewReader(oversized)); err != nil || len(data) != len(oversized) {
		t.Fatalf("the target read path truncated: %d of %d bytes, %v", len(data), len(oversized), err)
	}
	// The separation is per call site, not per file — main.go legitimately holds
	// the bounded external-IP lookup beside the unbounded target read. So the check
	// is that each named target read still uses the plain one.
	for _, callSite := range []struct{ file, want string }{
		{"main.go", "io.ReadAll(resp.Body)"},
		{"burst.go", "io.ReadAll(resp.Body)"},
		{"last_byte.go", "io.ReadAll(response.Body)"},
	} {
		source, err := os.ReadFile(callSite.file)
		if err != nil {
			t.Fatalf("read %s: %v", callSite.file, err)
		}
		if !strings.Contains(string(source), callSite.want) {
			t.Fatalf("%s no longer reads a target response with %q, so the exchange may be truncated", callSite.file, callSite.want)
		}
	}
	// And the bounded helper must stay confined to the engine's own control-plane
	// lookups: the external IP, the OAST provider, the public GitHub API, the two
	// public index transforms, the passive-intel index and ROBTEX passive DNS. A
	// target response is never one of them — that is the truncation this test
	// exists to prevent.
	// Naming the enclosing function is the point: a bare count also passed while a
	// fourth, unreachable copy of the GitHub lookup was still in the file, and
	// that dead duplicate is what made the number look like four.
	//
	// The GitHub entry names `githubAPIGet` rather than `transformGitHubRecon`
	// because that is where the read moved when the transform grew a second and
	// third pass. Every GitHub response — profile, event feed, repository list,
	// commit list — now goes through this one reader, so this is both the name
	// that is true and the name that keeps holding: a new pass that hand-rolled
	// its own request would miss the shared reader and fail here.
	//
	// The two additions are the passive-intel index (`askPassiveIntel`, whose own
	// error text says "the index could not be asked") and ROBTEX passive DNS
	// (`robtexForwardNames`). Both answer a bounded read correctly: they are
	// index responses, not target exchanges, and reading them whole would put a
	// third party's page into memory unbounded.
	//
	// The tally below is *derived* from this list instead of written out as a
	// number. A hard-coded count had gone stale when these two call sites landed —
	// the contract it guards was intact and only the number was wrong, and a test
	// that fails on a correct change trains the reader to ignore it. Derived, it is
	// also stronger: a bounded read in a function that is not named here fails,
	// which is exactly how a target exchange would slip in unannounced.
	declared := []struct{ file, enclosing string }{
		// The external-IP read lives in lookupSourceIPWithSlot rather than in
		// lookupSourceIP itself: the latter now takes a semaphore slot and the
		// caller may or may not wait for it, while the request and the bounded read
		// of its body are one piece of work. The registry names where the read
		// actually is, which is what makes a second unbounded read fail here.
		{"main.go", "func (s *server) lookupSourceIPWithSlot("},
		{"oast.go", "func (s *server) oastJSON("},
		{"osint_transforms.go", "func githubAPIGet("},
		{"osint_transforms.go", "func (s *server) urlscanSearch("},
		{"osint_transforms.go", "func (s *server) filescanVerdicts("},
		{"osint_transforms.go", "func (s *server) askPassiveIntel("},
		{"osint_transforms.go", "func (s *server) robtexForwardNames("},
	}
	for _, callSite := range declared {
		source, err := os.ReadFile(callSite.file)
		if err != nil {
			t.Fatalf("read %s: %v", callSite.file, err)
		}
		if !boundedInside(string(source), callSite.enclosing) {
			t.Fatalf("%s does not bound the body it reads in %s", callSite.file, callSite.enclosing)
		}
	}
	// No other file may reach for it: a target exchange through this helper is
	// precisely the truncation this test exists to prevent.
	bounded := 0
	for _, file := range []string{"main.go", "oast.go", "osint_transforms.go", "last_byte.go", "burst.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		bounded += strings.Count(string(source), "readControlPlaneBody(")
	}
	if bounded != len(declared) {
		t.Fatalf("the bounded helper is called from %d sites, want the %d declared control-plane lookups; "+
			"an undeclared one is a target exchange that would be truncated", bounded, len(declared))
	}
}

// boundedInside reports whether a bounded read appears within the named function,
// which is how the check stays honest when a file holds several lookups.
func boundedInside(source, signature string) bool {
	start := strings.Index(source, signature)
	if start < 0 {
		return false
	}
	rest := source[start+len(signature):]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return strings.Contains(rest, "readControlPlaneBody(")
	}
	return strings.Contains(rest[:end], "readControlPlaneBody(")
}
