package active

// Tests for the OS command injection detector.
//
// Two things about this detector are not like the others, and both are about cost
// rather than detection. The echo technique makes the target run a command; the
// blind technique makes it wait. The tests here pin both, and they pin the case
// that separates a real blind confirmation from a slow application: a target
// that answers every request in six seconds satisfies a fixed threshold and
// would be reported as injectable by any detector that uses one.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// cmdiFixture serves one parameter and records what it received.
type cmdiFixture struct {
	// respond decides the response for a parameter value.
	respond func(value string) (int, string)
	// baseDelay is added to every response, to model a slow application.
	baseDelay time.Duration
	// calls counts the requests the server answered.
	calls int
	mu    sync.Mutex
}

func newCMDiFixture(t *testing.T, baseDelay time.Duration, respond func(string) (int, string)) (*Transport, Point, *cmdiFixture) {
	t.Helper()
	fixture := &cmdiFixture{respond: respond, baseDelay: baseDelay}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.calls++
		fixture.mu.Unlock()
		if fixture.baseDelay > 0 {
			time.Sleep(fixture.baseDelay)
		}
		status, body := fixture.respond(r.URL.Query().Get("host"))
		_, _ = io.WriteString(w, body)
		_ = status
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "host",
		Values: url.Values{"host": {"example.com"}},
	}, fixture
}

func (CMDi) probe(t *testing.T, transport *Transport, p Point, delay time.Duration) []Finding {
	t.Helper()
	detector := CMDi{BlindDelay: delay}
	return detector.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

// A shell that evaluated the arithmetic and returned the product is verified:
// the value was not on the page before the injection.
func TestCMDiReportsEchoBasedInjection(t *testing.T) {
	product := "437"
	transport, point, _ := newCMDiFixture(t, 0, func(value string) (int, string) {
		if strings.Contains(value, "echo $((19*23))") {
			return 200, "<pre>" + product + "</pre>"
		}
		return 200, "<html><body>example.com</body></html>"
	})
	findings := (CMDi{}).probe(t, transport, point, 0)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: the shell's output came back", finding.Tier, TierVerified)
	}
	if finding.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", finding.Severity)
	}
	if !strings.Contains(finding.Evidence, product) {
		t.Errorf("evidence = %q, want the product named", finding.Evidence)
	}
	if !strings.Contains(finding.Payload, "echo $((19*23))") {
		t.Errorf("payload = %q, want the injected expression", finding.Payload)
	}
}

// The page already prints that number. A shell that evaluates arithmetic does not
// make 437 appear from nowhere, and a page that contains 437 on its own proves
// nothing about the shell.
func TestCMDiIgnoresAProductAlreadyOnThePage(t *testing.T) {
	transport, point, _ := newCMDiFixture(t, 0, func(value string) (int, string) {
		return 200, `<html><body><p>Order 437 shipped</p><p>example.com</p></body></html>`
	})
	findings := (CMDi{}).probe(t, transport, point, 0)
	for _, finding := range findings {
		if finding.Tier == TierVerified {
			t.Fatalf("reported %q because the page already contained the product", finding.Title)
		}
	}
}

// The upstream detector reports a time-based finding at high severity. No output
// came back here, so what was demonstrated is that the request took longer — and
// that is a potential, capped, not a proven command execution.
func TestCMDiReportsBlindInjectionAsPotential(t *testing.T) {
	transport, point, _ := newCMDiFixture(t, 0, func(value string) (int, string) {
		if strings.Contains(value, "sleep") {
			time.Sleep(2 * time.Second)
		}
		return 200, "<html><body>ok</body></html>"
	})
	findings := (CMDi{}).probe(t, transport, point, 2*time.Second)
	var blind *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Time-Based") {
			blind = &findings[i]
		}
	}
	if blind == nil {
		t.Fatalf("findings = %d, want a time-based finding", len(findings))
	}
	if blind.Tier != TierPotential {
		t.Errorf("tier = %q, want %q: no command output was returned", blind.Tier, TierPotential)
	}
	if blind.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, want at most medium for a potential", blind.Severity)
	}
	if !blind.Capped {
		t.Error("capped flag not set, so the downgrade is invisible in the report")
	}
	if !strings.Contains(blind.Evidence, "baseline") {
		t.Errorf("evidence = %q, want the measured baseline quoted beside the observed time", blind.Evidence)
	}
}

// The decisive case for a blind technique: an application that is simply slow.
//
// Every request takes six seconds. A detector that compares the response against
// a fixed threshold reads that as an executed sleep and reports command
// injection. Comparing against the application's own measured baseline does not,
// because a slow application is slow with and without the injection.
func TestCMDiDoesNotReportASlowApplicationAsInjectable(t *testing.T) {
	// The application's own latency is below the requested delay, so both an
	// increment-based rule and an absolute-time rule reject it. That is the cheap
	// half of the property; the expensive half — an application slower than the
	// delay itself — is TestBlindProbeRefusesAnApplicationSlowerThanTheDelay.
	transport, point, _ := newCMDiFixture(t, 900*time.Millisecond, func(value string) (int, string) {
		return 200, "<html><body>slow but honest</body></html>"
	})
	findings := (CMDi{}).probe(t, transport, point, 2*time.Second)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Time-Based") {
			t.Fatalf("reported %q on an application that is slow with and without the injection",
				finding.Title)
		}
	}
}

// The case that makes the baseline subtraction load-bearing.
//
// An application that is slower than the delay the probe asks for is the one
// situation where comparing the response time against a fixed threshold reads as
// an executed sleep. Three seconds of honest latency exceeds a two-second delay
// plus its margin, so an absolute rule reports command injection on a server
// that has never run a command. Subtracting the application's own measured
// baseline leaves an increment of approximately zero, which is not a delay.
//
// The probe is called directly rather than through Scan so the test costs two
// requests instead of eleven; the full-scan behaviour of the same case is
// covered above.
func TestBlindProbeRefusesAnApplicationSlowerThanTheDelay(t *testing.T) {
	transport, point, _ := newCMDiFixture(t, 3*time.Second, func(value string) (int, string) {
		// The target is slow but it does not sleep: a large page from a cold
		// cache, an upstream fetch, a slow disk. Nothing is injected.
		return 200, "<html><body>" + strings.Repeat("content ", 200) + "</body></html>"
	})
	baseline := baselineOf(t, transport, point)
	if baseline == nil {
		t.Fatal("baseline unavailable")
	}
	if got := blindProbe(t.Context(), transport, point, baseline, 2*time.Second); got != nil {
		t.Fatalf("reported %q on a %s application that never ran a command",
			got.Title, baseline.Duration.Round(time.Millisecond))
	}
	// The precondition the test relies on, stated so a change to the margin
	// cannot quietly turn this into the cheap case again.
	if baseline.Duration < 2*time.Second+blindNoiseMargin {
		t.Fatalf("baseline is %s, which does not exceed the delay plus its margin; "+
			"this test no longer distinguishes the two rules", baseline.Duration)
	}
}

// An application that is fast normally and slow only when a sleep is injected is
// the positive case of the same distinction.
func TestCMDiDistinguishesInjectedDelayFromGeneralSlowness(t *testing.T) {
	transport, point, fixture := newCMDiFixture(t, 0, func(value string) (int, string) {
		if strings.Contains(value, "sleep") {
			time.Sleep(2 * time.Second)
		}
		return 200, "<html><body>ok</body></html>"
	})
	findings := (CMDi{}).probe(t, transport, point, 2*time.Second)
	found := false
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Time-Based") {
			found = true
		}
	}
	if !found {
		t.Fatal("a delay that only appears with the injection was not detected")
	}
	if fixture.calls == 0 {
		t.Fatal("the fixture recorded no requests")
	}
}

// The echo technique runs first and unconditionally, so a target that reflects
// command output is never delayed. That is the property that keeps the blind
// stage off the overwhelming majority of targets.
func TestCMDiDoesNotDelayATargetThatReflectsOutput(t *testing.T) {
	transport, point, fixture := newCMDiFixture(t, 0, func(value string) (int, string) {
		if strings.Contains(value, "echo $((19*23))") {
			return 200, "437"
		}
		// A sleep payload would be very slow if it were sent, and the test
		// fails on the wall clock rather than on an assertion.
		if strings.Contains(value, "sleep") {
			time.Sleep(3 * time.Second)
		}
		return 200, "<html><body>ok</body></html>"
	})
	start := time.Now()
	findings := (CMDi{}).probe(t, transport, point, 3*time.Second)
	elapsed := time.Since(start)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the echo finding", len(findings))
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("scan took %s; the blind stage ran on a target that reflects output", elapsed)
	}
	// Baseline plus one echo probe. The first shell syntax answers, so no further
	// syntax is tried and the blind stage is never reached.
	if fixture.calls != 2 {
		t.Errorf("server answered %d requests, want 2 (baseline + first echo syntax)", fixture.calls)
	}
}

// The delay is a declared option, not a constant, and the value the operator
// chose is the value the payload carries.
func TestCMDiUsesTheDeclaredDelay(t *testing.T) {
	seen := make(chan string, 8)
	transport, point, _ := newCMDiFixture(t, 0, func(value string) (int, string) {
		if strings.Contains(value, "sleep") {
			select {
			case seen <- value:
			default:
			}
			time.Sleep(2 * time.Second)
		}
		return 200, "<html><body>ok</body></html>"
	})
	(CMDi{}).probe(t, transport, point, 2*time.Second)
	close(seen)
	for payload := range seen {
		if !strings.Contains(payload, "sleep 2") {
			t.Errorf("payload = %q, want the declared two-second delay", payload)
		}
	}
	if DefaultBlindDelay != 2*time.Second {
		t.Errorf("DefaultBlindDelay = %s, want 2s: long enough to exceed jitter, short enough not to be a cost",
			DefaultBlindDelay)
	}
	if blindNoiseMargin <= 0 {
		t.Error("no noise margin, so a slow target is credited with an injected delay")
	}
}

func TestCMDiReportsNothingOnCancellation(t *testing.T) {
	transport, point, _ := newCMDiFixture(t, 0, func(value string) (int, string) {
		return 200, "437"
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (CMDi{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

// Every shell syntax has to be a real one: a syntax table with an entry that
// produces a syntactically invalid command costs a request and learns nothing.
func TestCMDiSyntaxesAreDistinctAndNonEmpty(t *testing.T) {
	if len(cmdSyntaxes) == 0 {
		t.Fatal("no command syntaxes configured")
	}
	seen := map[string]string{}
	for _, syntax := range cmdSyntaxes {
		payload := syntax.make("EXPR")
		if payload == "" {
			t.Errorf("syntax %q produces nothing", syntax.name)
		}
		if !strings.Contains(payload, "EXPR") {
			t.Errorf("syntax %q produced %q, which does not carry the expression", syntax.name, payload)
		}
		if previous, clash := seen[payload]; clash {
			t.Errorf("syntaxes %q and %q produce the same payload %q", previous, syntax.name, payload)
		}
		seen[payload] = syntax.name
	}
}

// The blind list is deliberately a subset of the echo list, and every entry in
// it must actually be able to carry a delay.
func TestCMDiSleepSyntaxesCarryTheDelay(t *testing.T) {
	if len(cmdSleepSyntaxes) == 0 {
		t.Fatal("no sleep syntaxes configured")
	}
	for _, syntax := range cmdSleepSyntaxes {
		payload := syntax.make("5")
		if !strings.Contains(payload, "sleep 5") && !strings.Contains(payload, "sleep 5 )") {
			t.Errorf("syntax %q produced %q, which does not carry the delay", syntax.name, payload)
		}
	}
	// The blind list is the mechanism that makes a target slow, so it must not
	// grow without a decision: the echo list is longer, and the difference is
	// the point.
	if len(cmdSleepSyntaxes) > len(cmdSyntaxes) {
		t.Errorf("blind list (%d) is longer than the echo list (%d); the delay is the expensive one",
			len(cmdSleepSyntaxes), len(cmdSyntaxes))
	}
}
