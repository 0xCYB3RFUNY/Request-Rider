package runstate

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClassifyNamesTheFaultsAnOperatorActsOnDifferently(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{errors.New("net/http: request canceled while waiting for connection"), ClassPoolExhausted},
		{errors.New("dial tcp 1.2.3.4:443: i/o timeout"), ClassTimeout},
		{errors.New("read tcp 10.0.0.1:1->10.0.0.2:443: read: connection reset by peer"), ClassConnectionReset},
		{errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), ClassConnectionRefused},
		{errors.New("tls: handshake failure"), ClassTLS},
		{errors.New("dial tcp: lookup nowhere.invalid: no such host"), ClassDNS},
		{errors.New("unexpected EOF"), ClassEOF},
		{context.Canceled, ClassCanceled},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := ClassifyTransportError(tc.err); got != tc.want {
			t.Errorf("ClassifyTransportError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	// A typed timeout with a message that names nothing is still a timeout.
	netErr := &net.DNSError{IsTimeout: true, Err: "i/o timeout"}
	if got := ClassifyTransportError(netErr); got != ClassTimeout {
		t.Errorf("typed timeout classified as %q", got)
	}
}

func TestALedgerCountsStreaksAndClearsThemOnSuccess(t *testing.T) {
	ledger := NewLedger(10)
	for i := 0; i < 3; i++ {
		ledger.Record(Failure{Method: "GET", URL: "https://a.test/", Class: ClassTimeout})
	}
	if got := ledger.Consecutive(); got != 3 {
		t.Fatalf("consecutive after three failures = %d, want 3", got)
	}
	ledger.Success("https://a.test/ok")
	if got := ledger.Consecutive(); got != 0 {
		t.Fatalf("consecutive after a success = %d, want 0", got)
	}
	first, ok := firstFailure(ledger)
	if !ok || first.URL != "https://a.test/" {
		t.Fatalf("first failure = %+v ok=%v", first, ok)
	}
	if ledger.Total() != 3 {
		t.Fatalf("total = %d, want 3", ledger.Total())
	}
}

func TestARecordingBoundDropsOldEntriesAndSaysHowMany(t *testing.T) {
	ledger := NewLedger(3)
	for i := 0; i < 10; i++ {
		ledger.Record(Failure{Method: "GET", URL: "https://a.test/" + string(rune('a'+i)), Class: ClassTimeout})
	}
	queue := ledger.Failures()
	if len(queue) != 3 {
		t.Fatalf("queue length = %d, want 3", len(queue))
	}
	if queue[2].URL != "https://a.test/j" {
		t.Errorf("kept the wrong end of the queue: %q", queue[2].URL)
	}
	if ledger.Total() != 10 {
		t.Errorf("total = %d, want 10 — a bound must not stop the counting", ledger.Total())
	}
	if ledger.Dropped() != 7 {
		t.Errorf("dropped = %d, want 7", ledger.Dropped())
	}
	point := ledger.LedgerCheckpoint(0)
	if point.FailureDropped != 7 || point.Recorded != 3 {
		t.Errorf("checkpoint hides the bound: %+v", point)
	}
}

func TestTheFailurePauseFiresOnAStreakAndNotOnASingleFlakyPage(t *testing.T) {
	ledger := NewLedger(50)
	gate := NewGate(ledger, ResolveFailurePause(0))
	// A slow target interleaves failures with answers and must never pause.
	for i := 0; i < 60; i++ {
		if i%3 == 0 {
			ledger.Record(Failure{Class: ClassTimeout, URL: "https://a.test/"})
			continue
		}
		ledger.Success("https://a.test/ok")
		if err := gate.Wait(context.Background()); err != nil {
			t.Fatalf("Wait returned %v", err)
		}
	}
	if paused, _ := gate.Paused(); paused {
		t.Fatal("a run that keeps getting answers paused itself")
	}

	// A dead target does not.
	for i := 0; i < DefaultFailurePause; i++ {
		ledger.Record(Failure{Class: ClassTimeout, URL: "https://a.test/"})
	}
	released := make(chan struct{})
	go func() {
		defer close(released)
		_ = gate.Wait(context.Background())
	}()
	select {
	case <-released:
		t.Fatal("Wait returned while the run should be paused")
	case <-time.After(80 * time.Millisecond):
	}
	paused, reason := gate.Paused()
	if !paused {
		t.Fatal("run did not pause on a failure streak")
	}
	if !strings.Contains(reason, "consecutive transport failures") {
		t.Errorf("pause reason does not name the evidence: %q", reason)
	}
	if !gate.AutoPaused() {
		t.Error("an automatic pause did not say it was automatic")
	}
	if !gate.Resume() {
		t.Error("Resume reported that a paused run was not paused")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after Resume")
	}
}

func TestAPauseDropsTheProbesInFlightAndReportsThem(t *testing.T) {
	ledger := NewLedger(10)
	gate := NewGate(ledger, 0)

	// Two probes that are waiting on a server that never answers.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, release := gate.Child(context.Background())
			defer release()
			req, err := http.NewRequestWithContext(ctx, "GET", slow.URL, nil)
			if err != nil {
				errs[idx] = err
				return
			}
			_, errs[idx] = http.DefaultClient.Do(req)
		}()
	}
	// Wait until both probes really hold a socket.
	deadline := time.Now().Add(2 * time.Second)
	for gate.InFlight() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if gate.InFlight() != 2 {
		t.Fatalf("in flight = %d, want 2", gate.InFlight())
	}

	dropped := gate.Pause("operator")
	if dropped != 2 {
		t.Errorf("pause dropped %d probes, want 2", dropped)
	}
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("probe %d ended with %v, want the cancellation a pause causes", i, err)
		}
	}
	// A second pause is not an error and does not double-count.
	if again := gate.Pause("operator"); again != 2 {
		t.Errorf("second pause reported %d dropped, want the run's total 2", again)
	}
	point := gate.Checkpoint(0)
	if point.DroppedProbes != 2 || !point.Paused || point.PauseReason != "operator" {
		t.Errorf("checkpoint does not carry the pause: %+v", point)
	}
}

func TestAProbeDispatchedWhilePausedCannotLeakARequest(t *testing.T) {
	gate := NewGate(NewLedger(10), 0)
	gate.Pause("operator")

	reached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a paused run reached the target")
	}))
	defer reached.Close()

	ctx, release := gate.Child(context.Background())
	defer release()
	req, err := http.NewRequestWithContext(ctx, "GET", reached.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := http.DefaultClient.Do(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("dispatch during a pause produced %v, want context.Canceled", err)
	}
}

func TestCancelEndsAWaitThatWouldOtherwiseWaitForever(t *testing.T) {
	gate := NewGate(NewLedger(10), 0)
	gate.Pause("operator")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gate.Wait(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait returned %v after a cancel, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait ignored the run's cancellation")
	}
}

func TestAnOperatorTurnsTheAutomaticPauseOff(t *testing.T) {
	ledger := NewLedger(100)
	for i := 0; i < DefaultFailurePause*3; i++ {
		ledger.Record(Failure{Class: ClassTimeout, URL: "https://a.test/"})
	}
	gate := NewGate(ledger, ResolveFailurePause(DisableFailurePause))
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatalf("Wait returned %v", err)
	}
	if paused, _ := gate.Paused(); paused {
		t.Fatal("a run paused itself with the automatic pause turned off")
	}
	if point := gate.Checkpoint(0); point.FailurePause != 0 {
		t.Errorf("checkpoint reports threshold %d while it is off", point.FailurePause)
	}
}

func TestResumeGivesTheThresholdBackToTheOperator(t *testing.T) {
	ledger := NewLedger(100)
	gate := NewGate(ledger, 3)
	for i := 0; i < 3; i++ {
		ledger.Record(Failure{Class: ClassTimeout, URL: "https://a.test/"})
	}
	// The run asks "may I send the next probe?" and blocks there while it is
	// paused, which is the whole point: the test has to be the one that resumes,
	// from another goroutine, exactly as an operator's click would be.
	waiting := make(chan struct{})
	go func() {
		defer close(waiting)
		_ = gate.Wait(context.Background())
	}()
	select {
	case <-waiting:
		t.Fatal("Wait returned while the run should be paused")
	case <-time.After(60 * time.Millisecond):
	}

	if !gate.Resume() {
		t.Fatal("Resume did not resume")
	}
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after Resume")
	}
	// The first failure after a deliberate resume must not pause the run again.
	ledger.Record(Failure{Class: ClassTimeout, URL: "https://a.test/again"})
	if err := gate.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if paused, _ := gate.Paused(); paused {
		t.Error("the run paused on the first failure after a resume")
	}
}

func TestGateWithoutALedgerStillPausesAndResumes(t *testing.T) {
	gate := NewGate(nil, 0)
	gate.Pause("operator")
	if paused, _ := gate.Paused(); !paused {
		t.Fatal("a gate with no ledger did not pause")
	}
	if !gate.Resume() {
		t.Fatal("a gate with no ledger did not resume")
	}
}

func firstFailure(l *Ledger) (Failure, bool) {
	point := l.LedgerCheckpoint(0)
	if point.FirstFailure == nil {
		return Failure{}, false
	}
	return *point.FirstFailure, true
}
