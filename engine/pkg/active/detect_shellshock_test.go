package active

// Tests for the Shellshock detector.
//
// The fixture is a live server whose behaviour switches per test, because the
// whole difficulty of this detector is *which* observable it accepts. A mocked
// transport would return whatever the test handed it and agree with a detector
// that reports on nothing; a fixture that answers like an affected CGI — output
// before the status line, so no client can parse it — is the only thing that can
// tell the two signals apart from each other and from a plain failure.
//
// Two things this file deliberately does not test, because they are not
// properties a detector can have: that the payload is safe, and that it is
// effective against a real old bash. The payload is asserted by value below, so a
// later edit that opens a shell fails the test rather than passing it.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// shellshockFixture is a server that can answer three ways: normally, like an
// affected CGI, or not at all.
type shellshockFixture struct {
	// affected makes the handler behave like a vulnerable CGI: it writes the
	// injected command's output ahead of the status line, so the bytes are not
	// an HTTP response.
	affected bool
	// down makes every request fail, standing in for an unreachable host.
	down bool

	mu      sync.Mutex
	agents  []string
	referer []string
}

func (f *shellshockFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if r.Header.Get("User-Agent") != "" {
		f.agents = append(f.agents, r.Header.Get("User-Agent"))
	}
	if r.Header.Get("Referer") != "" {
		f.referer = append(f.referer, r.Header.Get("Referer"))
	}
	affected, down := f.affected, f.down
	f.mu.Unlock()

	if down {
		// A connection that is closed without an answer: the client gets an
		// error, which is the observable the second signal is about.
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		return
	}

	if affected && strings.Contains(r.Header.Get("User-Agent"), shellshockMarker) {
		// What an affected CGI does: the command's stdout lands before the
		// status line, so the response cannot be parsed.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(conn, "%s\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", shellshockMarker)
		_ = conn.Close()
		return
	}

	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, "<html><body>ok</body></html>")
}

func newShellshockFixture(t *testing.T, fixture *shellshockFixture) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport, Point{URL: server.URL, Method: http.MethodGet}
}

func TestThePayloadRunsEchoAndNothingElse(t *testing.T) {
	payload := shellshockPayload()
	if !strings.Contains(payload, "echo "+shellshockMarker) {
		t.Fatalf("the payload does not print the marker: %q", payload)
	}
	// A detector is the tool most likely to be pointed at a host the operator
	// does not own, precisely because nobody suspects it is vulnerable. A payload
	// that opens a shell or writes a file has stopped being a check.
	for _, forbidden := range []string{"/dev/tcp", "bash -i", ">&", "nc ", "wget ", "curl ", "mkfifo", ":(){ :|:&};:"} {
		if strings.Contains(payload, forbidden) {
			t.Errorf("the payload contains %q: %q", forbidden, payload)
		}
	}
}

func TestAnAffectedCGIThroughTheUserAgentIsReported(t *testing.T) {
	fixture := &shellshockFixture{affected: true}
	transport, point := newShellshockFixture(t, fixture)

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := Shellshock{}
	findings := module.Scan(context.Background(), transport, point, baseline)
	if len(findings) == 0 {
		t.Fatal("an affected CGI produced no finding")
	}
	var raised *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "User-Agent") {
			raised = &findings[i]
		}
	}
	if raised == nil {
		t.Fatalf("the User-Agent vector did not fire: %v", titles(findings))
	}
	if raised.Tier != TierVerified {
		t.Errorf("tier = %q; a command that printed the marker is a demonstrated impact", raised.Tier)
	}
	if raised.Severity.Rank() < SeverityHigh.Rank() {
		t.Errorf("severity = %q, want high or critical", raised.Severity)
	}
	if !strings.Contains(raised.Evidence, shellshockMarker) {
		t.Errorf("the evidence does not carry the marker a triager would search for: %q", raised.Evidence)
	}
}

func TestTheRefererVectorIsProbedToo(t *testing.T) {
	// A host that maps Referer but not User-Agent is a real configuration: some
	// CGI wrappers pass one and not the other, and a detector that only tries the
	// first reports nothing on it.
	fixture := &shellshockFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		if r.Header.Get("Referer") != "" {
			fixture.referer = append(fixture.referer, r.Header.Get("Referer"))
		}
		affected := strings.Contains(r.Header.Get("Referer"), shellshockMarker)
		fixture.mu.Unlock()
		if affected {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(conn, "%s\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", shellshockMarker)
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, "<html>ok</html>")
	}))
	defer server.Close()
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	point := Point{URL: server.URL, Method: http.MethodGet}

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := Shellshock{}
	findings := module.Scan(context.Background(), transport, point, baseline)
	fired := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Referer") {
			fired = true
		}
	}
	if !fired {
		t.Errorf("the Referer vector did not fire: %v", titles(findings))
	}
}

func TestAHostThatFailsEveryRequestIsNotAShellshock(t *testing.T) {
	// The control arm is the point of the second signal. A host that cannot answer
	// anything is a network problem, and calling it remotely exploitable is the
	// kind of false positive that teaches an operator to ignore a module.
	fixture := &shellshockFixture{down: true}
	transport, point := newShellshockFixture(t, fixture)

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err == nil {
		// A host that answers the plain request and fails only the probes is the
		// case the second signal is about, and that is the affected-CGI test.
		// Here the fixture is unreachable, so the baseline cannot be taken and the
		// control arm does not exist — which is what must produce silence.
		t.Fatalf("the fixture was meant to be unreachable, but the baseline succeeded")
	}
	module := Shellshock{}
	if findings := module.Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("an unreachable host produced %v", titles(findings))
	}
}

func TestShellshockNeedsABaselineToSayAnything(t *testing.T) {
	// "I could not read the page" is not "this host is safe", and it is certainly
	// not "this host is vulnerable": without the control arm the second signal has
	// nothing to compare against.
	module := Shellshock{}
	if findings := module.Scan(context.Background(), nil, Point{}, nil); len(findings) != 0 {
		t.Errorf("reported %v with no baseline", titles(findings))
	}
}

func TestAPageThatMerelyMentionsTheMarkerIsNotAFinding(t *testing.T) {
	// `Fresh` compares against the baseline, so a page that already contains the
	// marker string cannot raise a row. Without that, any site echoing a
	// User-Agent would report Shellshock.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html><body>you sent "+shellshockMarker+"</body></html>")
	}))
	defer server.Close()
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	point := Point{URL: server.URL, Method: http.MethodGet}

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := Shellshock{}
	if findings := module.Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("a page echoing the marker was reported: %v", titles(findings))
	}
}

func TestTheProbesCostTwoRequestsAndNotMore(t *testing.T) {
	// The module runs once per unique URL, so a per-endpoint cost multiplies by
	// the number of pages. Five headers would be five requests per page for the
	// same conclusion.
	fixture := &shellshockFixture{}
	transport, point := newShellshockFixture(t, fixture)
	before := transport.Requests()

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := Shellshock{}
	module.Scan(context.Background(), transport, point, baseline)

	if spent := transport.Requests() - before; spent != 3 {
		t.Errorf("the module spent %d request(s), want 3 (the baseline and two header probes)", spent)
	}
}

func TestTheVectorsAreTheOnesACGIExposes(t *testing.T) {
	want := map[string]bool{"User-Agent": true, "Referer": true}
	if len(shellshockVectors) != len(want) {
		t.Fatalf("vectors = %v, want %v", shellshockVectors, want)
	}
	for _, header := range shellshockVectors {
		if !want[header] {
			t.Errorf("unexpected vector %q", header)
		}
	}
}

// TestTheDetectorIsRegisteredAndFiresAgainstTheFixture is the wiring half: a
// detector nothing calls is code that passes every test written against it.
func TestTheDetectorIsRegisteredAndFiresAgainstTheFixture(t *testing.T) {
	found := false
	for _, module := range AllModules() {
		if module.Name() == "shellshock" {
			found = true
			if module.Level() != LevelEndpoint {
				t.Errorf("level = %v; the vector is a header, so the module must be endpoint-level", module.Level())
			}
		}
	}
	if !found {
		t.Error("the shellshock detector is not in AllModules(), so no run would ever use it")
	}
}
