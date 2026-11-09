package active

// Tests for the ReDoS detector.
//
// The rule under test is a comparison of wall times, so the fixtures are servers
// that really do take longer rather than servers that are told to look slow: a
// mocked clock would make every test pass for the wrong reason, and the whole
// point of the control is that the number came from the network.
//
// Three of these exist to fail against the plausible wrong implementations:
//
//   - a slow endpoint with no slow regex must stay silent, and the control is what
//     makes that true; without it the escalating rule fires on any slow page;
//   - a slow regex on a slow endpoint must still fire, because the *difference*
//     against the control is what is being claimed, not the absolute time;
//   - a single slow request is not a curve, so the middle measurement has to sit
//     between the two ends.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// redosFixture serves a handler whose per-request delay the test controls, and
// records what it was asked for.
//
// `sent` is written from the handler's goroutine and read by the test after the
// scan, and the request that ends the scan does not order those two accesses for
// the race detector: without the mutex this file fails under `-race` on two tests,
// which is the detector reporting a defect in its own harness.
type redosFixture struct {
	// delay answers with this delay when the request carries a shape the test wants
	// slow. It is a function so a test can make the delay grow with the input.
	delay func(value string) time.Duration

	mu   sync.Mutex
	sent []string
}

// record notes what the handler was asked for.
func (f *redosFixture) record(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, value)
}

// requests returns what was asked for, in order.
func (f *redosFixture) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

// redosServer starts a fixture and returns a transport, a point and the recorder.
func redosServer(t *testing.T, delay func(string) time.Duration) (*Transport, Point, *redosFixture) {
	t.Helper()
	fixture := &redosFixture{delay: delay}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		fixture.record(value)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form method="get"><input name="q"></form><p>results</p></body></html>`))
		if d := fixture.delay(value); d > 0 {
			time.Sleep(d)
		}
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}},
	}, fixture
}

func (ReDoS) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	baseline := baselineOf(t, transport, p)
	return ReDoS{}.Scan(t.Context(), transport, p, baseline)
}

// redosStepByLength is a server whose delay grows with the size of the input, which
// is what a validator with a backtracking pattern looks like from outside.
//
// The delay is keyed on the *length* rather than on a prefix: the three probes of a
// family share a prefix by construction, so a prefix-keyed fixture would give all
// three the same delay and the rule would read nothing from them.
func redosStepByLength(value string) time.Duration {
	// The control class is fast whatever its length, and that is the fixture's
	// whole job: a control that grew with the input would be measuring the same
	// regex twice and the comparison would prove nothing.
	if strings.Trim(value, redosControlUnit) == "" && value != "" {
		return time.Millisecond
	}
	switch {
	case len(value) <= redosShortLength:
		return 5 * time.Millisecond
	case len(value) <= redosMediumLength:
		return 60 * time.Millisecond
	}
	return 900 * time.Millisecond
}

// TestReDoSReportsSuperlinearGrowth is the finding itself: an endpoint that answers
// the family of shapes progressively slower while the neutral control stays fast.
func TestReDoSReportsSuperlinearGrowth(t *testing.T) {
	transport, point, _ := redosServer(t, func(value string) time.Duration {
		return redosStepByLength(value)
	})
	findings := (ReDoS{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Module != "redos" {
		t.Errorf("module = %q, want %q", finding.Module, "redos")
	}
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	// The evidence has to carry the numbers: a timing finding whose evidence is the
	// word "slow" cannot be argued with by the reader who has to accept it.
	for _, want := range []string{"10 chars", "30 chars", "60 chars", "control 60 neutral chars"} {
		if !strings.Contains(finding.Evidence, want) {
			t.Errorf("evidence %q does not name %q", finding.Evidence, want)
		}
	}
}

// TestReDoSIsSilentOnASlowEndpoint is the control's own test. The endpoint is slow
// for every input, the escalating rule of upstream would fire on it, and nothing
// here has a slow regex.
func TestReDoSIsSilentOnASlowEndpoint(t *testing.T) {
	transport, point, _ := redosServer(t, func(string) time.Duration {
		// Every input costs the same, which is what "slow endpoint" means.
		return 120 * time.Millisecond
	})
	if findings := (ReDoS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: the endpoint is uniformly slow, its validation is not the problem",
			len(findings))
	}
}

// TestReDoSStillFiresOnASlowEndpoint is the other half of the same pair: absolute
// slowness must not veto a real finding, because the claim is about the difference
// against the control.
func TestReDoSStillFiresOnASlowEndpoint(t *testing.T) {
	transport, point, _ := redosServer(t, func(value string) time.Duration {
		// Every input pays a fixed toll, and the shape pays the growth on top: the
		// claim is about the difference against the control, not about absolute time.
		if strings.Trim(value, redosControlUnit) == "" && value != "" {
			return 200 * time.Millisecond
		}
		return 200*time.Millisecond + redosStepByLength(value)
	})
	if findings := (ReDoS{}).probe(t, transport, point); len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the growth is 700 ms over the control on a slow endpoint too",
			len(findings))
	}
}

// TestReDoSNeedsACurveNotASingleSlowRequest is the clause that keeps the detector
// off a page with one unlucky request: the middle measurement has to sit between
// the two ends.
func TestReDoSNeedsACurveNotASingleSlowRequest(t *testing.T) {
	transport, point, _ := redosServer(t, func(value string) time.Duration {
		switch len(value) {
		case redosShortLength:
			return 2 * time.Millisecond
		case redosMediumLength:
			// The middle is the slow one, so the growth is not monotone and no
			// escalating rule can be read out of it.
			return 300 * time.Millisecond
		}
		return 4 * time.Millisecond
	})
	if findings := (ReDoS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: one slow request is not a curve", len(findings))
	}
}

// TestReDoSNeedsTheGrowthToStartLate pins the clause that distinguishes "the
// endpoint is slow" from "the regex is slow": when the short input is already slow,
// there is no growth to attribute to the validation, and a rule that fires anyway
// reports every parameter of a busy page.
func TestReDoSNeedsTheGrowthToStartLate(t *testing.T) {
	transport, point, _ := redosServer(t, func(value string) time.Duration {
		if strings.Trim(value, redosControlUnit) == "" && value != "" {
			return time.Millisecond
		}
		// Slow from the shortest input on: nothing here is the regex's doing.
		return 900 * time.Millisecond
	})
	if findings := (ReDoS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: the endpoint is slow for a ten-character input too", len(findings))
	}
}

// TestReDoSIsSilentWhenTheControlTimesOut is the timeout clause: a control that
// gave up says nothing about the regex, so the detector says nothing about the
// regex either.
func TestReDoSIsSilentWhenTheControlTimesOut(t *testing.T) {
	fixture := &redosFixture{delay: func(value string) time.Duration {
		if strings.Trim(value, redosControlUnit) == "" && value != "" {
			return 300 * time.Millisecond
		}
		return time.Millisecond
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		fixture.record(value)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form method="get"><input name="q"></form></body></html>`))
		if d := fixture.delay(value); d > 0 {
			time.Sleep(d)
		}
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 120 * time.Millisecond})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}}}
	if findings := (ReDoS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: the control timed out, so the comparison has no numbers",
			len(findings))
	}
	// The request count is the assertion that matters here. A detector that kept
	// going would also report nothing — every probe would time out the same way —
	// so the absence of a finding proves nothing about whether the guard is there.
	// The first entry is the harness's baseline read; nothing after it is a family
	// probe, because a control that gave up has no numbers to compare a family with.
	sent := fixture.requests()
	if len(sent) != 2 {
		t.Errorf("sent %d request(s) %q, want 2: the baseline read and the control, and nothing after them",
			len(sent), sent)
	}
}

// TestReDoSReportsATimeoutOnTheLongShape is the timeout clause, and it is proved
// with a transport whose timeout is shorter than the fixture's delay rather than
// with a real 15-second hang: the rule reads "the long probe gave up", and the
// number that has to be under the timeout is the transport's, not the test's
// patience.
func TestReDoSReportsATimeoutOnTheLongShape(t *testing.T) {
	fixture := &redosFixture{delay: func(value string) time.Duration {
		if len(value) > redosMediumLength && strings.Trim(value, redosControlUnit) != "" {
			return 300 * time.Millisecond
		}
		return time.Millisecond
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		fixture.record(value)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form method="get"><input name="q"></form></body></html>`))
		if d := fixture.delay(value); d > 0 {
			time.Sleep(d)
		}
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}}}
	findings := (ReDoS{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: a long shape that never answers is the strongest signal there is",
			len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "timeout") {
		t.Errorf("evidence = %q, want it to name the timeout: a timeout and a slow answer are different claims",
			findings[0].Evidence)
	}
}

// The control for the row above, and the reason the guard exists: the same server
// with a timeout its slow shapes fit inside must stay silent, or the timeout clause
// would be reporting the timeout rather than the regex.
func TestReDoSIsSilentWhenTheTimeoutIsMerelyGenerous(t *testing.T) {
	fixture := &redosFixture{delay: func(value string) time.Duration {
		if len(value) > redosMediumLength && strings.Trim(value, redosControlUnit) != "" {
			return 300 * time.Millisecond
		}
		return time.Millisecond
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		fixture.record(value)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form method="get"><input name="q"></form></body></html>`))
		if d := fixture.delay(value); d > 0 {
			time.Sleep(d)
		}
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}}}
	if findings := (ReDoS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: nothing timed out, and a slow long shape is still a curve question",
			len(findings))
	}
}

// TestReDoSCostIsOneControlPlusEveryFamily pins the budget, and it is a large one:
// a surface where nothing fires costs one control and all eight families, which is
// what covering eight regex shapes costs. The test names that number instead of
// leaving it to be discovered on a slow target.
func TestReDoSCostIsOneControlPlusEveryFamily(t *testing.T) {
	transport, point, fixture := redosServer(t, func(string) time.Duration { return time.Millisecond })
	(ReDoS{}).probe(t, transport, point)
	// The first entry is the harness's baseline read, which carries the parameter's
	// own value rather than a payload.
	want := 1 + 1 + len(redosFamilies)*3
	sent := fixture.requests()
	if len(sent) != want {
		t.Fatalf("sent %d request(s), want %d: one baseline read, one control, %d families of three",
			len(sent), want, len(redosFamilies))
	}
}

// TestReDoSStopsAtTheFirstFamilyThatFires is the other half of the budget: a
// surface that does fire is not measured by the remaining seven families.
func TestReDoSStopsAtTheFirstFamilyThatFires(t *testing.T) {
	transport, point, fixture := redosServer(t, redosStepByLength)
	findings := (ReDoS{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	// One baseline read, one control, three probes of the first family.
	sent := fixture.requests()
	if len(sent) != 5 {
		t.Errorf("sent %d request(s) %q, want 5: the run stops at the family that fired", len(sent), sent)
	}
}

// TestReDoSControlIsNeutral is what makes the control a control: the payload it
// sends must not match any family, or the comparison would be between a regex and
// itself.
func TestReDoSControlIsNeutral(t *testing.T) {
	payload := strings.Repeat(redosControlUnit, redosLongLength)
	for _, family := range redosFamilies {
		if strings.Contains(family.payload(redosLongLength), redosControlUnit) {
			t.Errorf("control payload %q matches family %q, so the comparison is against itself",
				payload, family.aimsAt)
		}
	}
}

// TestReDoSFamilyPayloadsGrowByLength is the shape itself: the three probes of a
// family differ only in size, because a rule that reads growth cannot read it from
// payloads that differ in more than size.
func TestReDoSFamilyPayloadsGrowByLength(t *testing.T) {
	if len(redosFamilies) != 8 {
		t.Fatalf("families = %d, want the eight lonkero ports", len(redosFamilies))
	}
	for _, family := range redosFamilies {
		short, medium, long := family.payload(redosShortLength), family.payload(redosMediumLength), family.payload(redosLongLength)
		if len(short) != redosShortLength || len(medium) != redosMediumLength || len(long) != redosLongLength {
			t.Errorf("family %q built %d/%d/%d chars, want %d/%d/%d",
				family.aimsAt, len(short), len(medium), len(long),
				redosShortLength, redosMediumLength, redosLongLength)
		}
		// The three payloads differ only in length, which is checked on the repeated
		// body: the terminator sits at the tail, so in the short payload it lands in
		// the middle of what the long one repeats.
		shortBody := strings.TrimSuffix(short, family.terminator)
		mediumBody := strings.TrimSuffix(medium, family.terminator)
		longBody := strings.TrimSuffix(long, family.terminator)
		if !strings.HasPrefix(mediumBody, shortBody) || !strings.HasPrefix(longBody, mediumBody) {
			t.Errorf("family %q payloads are not prefixes of one another, so the growth is not the only variable",
				family.aimsAt)
		}
		if !strings.HasSuffix(long, family.terminator) {
			t.Errorf("family %q lost its terminator at the long length", family.aimsAt)
		}
	}
}

// TestReDoSIsRegistered pins the module into the scanner's parameter level: a
// detector nobody runs is indistinguishable from one that does not work.
func TestReDoSIsRegistered(t *testing.T) {
	var found bool
	for _, module := range modulesFor("", 0) {
		if _, ok := module.(ReDoS); ok {
			found = true
		}
	}
	if !found {
		t.Error("ReDoS is not in the parameter-level module list, so the detector never runs")
	}
}

// TestIsTimeoutRecognisesBothShapes keeps the timeout clause honest: the rule treats
// a timeout as the strongest signal, so the recogniser has to know a timeout from
// both a deadline error and a net.Error, and must not call a plain error one.
func TestIsTimeoutRecognisesBothShapes(t *testing.T) {
	if isTimeout(nil) {
		t.Error("no error is a timeout")
	}
	if isTimeout(errString("connection refused")) {
		t.Error("a refused connection is a failure, not a timeout")
	}
	if !isTimeout(errString("context deadline exceeded")) {
		t.Error("a deadline error must be recognised as a timeout")
	}
}

// errString is an error carrying a message, which is how the transport reports a
// give-up.
type errString string

func (e errString) Error() string { return string(e) }
