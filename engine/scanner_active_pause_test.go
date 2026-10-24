package main

// Tests for pausing, resuming and resending an active scan.
//
// WHAT IS UNDER TEST
//
// A run that can only be killed is a run whose operator cannot react. The run
// that motivated this work spent thirty minutes against a target that had stopped
// answering: every probe burned the full timeout, and nothing in the product
// could say "it is broken from here on", stop there, or re-send the requests that
// never got an answer.
//
// So these tests drive the real handlers against a live `httptest` target that
// never answers, for the same reason the rest of this package does: a mocked run
// would happily agree with a product that pauses nothing and resends nothing.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"intruder/engine/pkg/runstate"
)

// deadTarget accepts the connection and then never speaks again, which is what a
// target that has stopped answering looks like from the client side.
func deadTarget(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	return server
}

// slowTarget answers every request, but only after a delay. It is what a target
// under load looks like from the client side, and it is the only fixture that can
// prove both halves of a pause: a probe really was in flight to drop, and the run
// can still finish after the resume.
func slowTarget(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/item" method="get"><input name="id"></form>`+
			`<a href="/item?id=1">item</a></body></html>`)
	}))
	t.Cleanup(server.Close)
	return server
}

// dyingTarget answers the first `healthy` requests and then goes silent forever.
//
// It is the fixture the whole change was written for: a target that answers at
// the start of a run and stops answering halfway through is the only shape in
// which a run keeps working against a dead target, which is exactly when the
// failure streak is visible and the operator needs a pause.
func dyingTarget(t *testing.T, healthy int) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	served := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		alive := served <= healthy
		mu.Unlock()
		if !alive {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/item?id=1">item</a></body></html>`)
	}))
	t.Cleanup(server.Close)
	return server
}

// postJobAction calls the handler the gateway calls, with the action the operator
// clicked.
func postJobAction(t *testing.T, s *server, id, action, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/proxy/scanner/active/jobs/%s/%s", id, action), strings.NewReader(body))
	s.scannerActiveJobAction(recorder, request, id, action)
	return recorder
}

// waitUntilPaused blocks until the run reports a pause.
func waitUntilPaused(t *testing.T, job *activeScanJob) runstate.Checkpoint {
	t.Helper()
	var point runstate.Checkpoint
	waitFor(t, func() bool {
		point = job.snapshot().Checkpoint
		return point.Paused
	})
	return point
}

// requirePause posts a pause and insists the engine accepted it, so a test that
// cannot pause says "the pause was refused" rather than "nothing happened later".
func requirePause(t *testing.T, s *server, id string) {
	t.Helper()
	recorder := postJobAction(t, s, id, "pause", "")
	if recorder.Code != http.StatusOK {
		snapshot := ""
		if job, ok := s.activeScanJobByID(id); ok {
			snapshot = fmt.Sprintf("state=%s finished=%v", job.snapshot().State, job.finished())
		}
		t.Fatalf("pause returned %d: %s (%s)", recorder.Code, recorder.Body.String(), snapshot)
	}
}

func TestARunCanBePausedBetweenProbesAndResumedFromWhereItStopped(t *testing.T) {
	// The project's own live fixture. It answers immediately, so the run finishes
	// quickly and the test measures the pause rather than the fixture: how many
	// probes a pause drops is covered separately, against a target slow enough to
	// still hold one.
	target := activeScanTarget(t)
	s := &server{}
	id, code := startActiveScan(t, s, fmt.Sprintf(
		`{"url":%q,"max_pages":1,"max_depth":0,"concurrency":1,"timeout_ms":3000}`, target.URL))
	if code != http.StatusAccepted {
		t.Fatalf("start returned %d", code)
	}
	job, ok := s.activeScanJobByID(id)
	if !ok {
		t.Fatalf("job %q is unknown right after it started", id)
	}

	// Wait until a probe is really in flight, so the pause has something to drop.
	waitFor(t, func() bool { return job.gate.InFlight() > 0 })

	requirePause(t, s, id)
	point := waitUntilPaused(t, job)
	if point.PauseReason == "" {
		t.Error("a pause with no reason leaves the operator nothing to argue with")
	}
	if point.PausedAt.IsZero() {
		t.Error("the checkpoint carries no pause time")
	}

	// The pause releases the sockets the probes were holding. That is the property
	// the old code refused to offer and the one that makes a paused run a quiet
	// run rather than a frozen one.
	waitFor(t, func() bool { return job.gate.InFlight() == 0 })

	// And it is quiet: a paused run spends no more requests than it had already
	// spent. This is the property the old "cancel is the only control" decision
	// was protecting, measured rather than argued: a frozen run would keep the
	// target busy while claiming to be stopped.
	spent := job.snapshot().Checkpoint.FailureTotal
	time.Sleep(250 * time.Millisecond)
	if now := job.snapshot().Checkpoint.FailureTotal; now != spent {
		t.Errorf("a paused run spent more requests: %d → %d", spent, now)
	}

	resume := postJobAction(t, s, id, "resume", "")
	if resume.Code != http.StatusOK {
		t.Fatalf("resume returned %d: %s", resume.Code, resume.Body.String())
	}
	if paused, _ := job.gate.Paused(); paused {
		t.Fatal("the run is still paused after resume")
	}
	// A resumed run works again: it takes probes and finishes its report rather
	// than dying where the pause interrupted it. That is what "continues from
	// where it stopped" means — not that it counts more failures.
	finished := waitForActiveScan(t, s, id)
	if finished.State != activeJobCompleted {
		t.Fatalf("the resumed run ended as %q (%s), want completed", finished.State, finished.Error)
	}
	if finished.Result == nil || finished.Result.Pages == 0 {
		t.Fatal("the resumed run produced no pages: the pause lost the frontier")
	}
}

func TestAPauseThatDropsProbesSaysHowManyItDropped(t *testing.T) {
	target := slowTarget(t, 900*time.Millisecond)
	s := &server{}
	id, _ := startActiveScan(t, s, fmt.Sprintf(
		`{"url":%q,"max_pages":4,"concurrency":2,"timeout_ms":5000}`, target.URL))
	job, _ := s.activeScanJobByID(id)
	waitFor(t, func() bool { return job.gate.InFlight() > 0 })

	requirePause(t, s, id)
	point := waitUntilPaused(t, job)
	if point.DroppedProbes == 0 {
		t.Error("a pause that dropped probes did not report the count")
	}
	if point.Paused != true {
		t.Error("the checkpoint does not say the run is paused")
	}
	postJobAction(t, s, id, "cancel", "")
}

// TestTheAutomaticPauseFiresOnAStreakOfTransportFailures is the case that
// produced this work: a target that has stopped answering, a scanner that would
// otherwise spend the operator's next thirty minutes proving it.
func TestTheAutomaticPauseFiresOnAStreakOfTransportFailures(t *testing.T) {
	target := dyingTarget(t, 2)
	s := &server{}
	// The threshold is the operator's field, and this test uses two so that it
	// proves the mechanism without failing twenty probes to do it.
	id, _ := startActiveScan(t, s, fmt.Sprintf(
		`{"url":%q,"max_pages":4,"concurrency":1,"timeout_ms":300,"failure_pause":2}`, target.URL))
	job, _ := s.activeScanJobByID(id)

	point := waitUntilPaused(t, job)
	if !strings.Contains(point.PauseReason, "consecutive transport failures") {
		t.Errorf("the automatic pause does not name its evidence: %q", point.PauseReason)
	}
	if point.FailurePause != 2 {
		t.Errorf("checkpoint reports threshold %d, want the operator's 2", point.FailurePause)
	}
	// The run's own state has to say so as well, because that is what a browser
	// reads: a paused checkpoint under a "running" state would be a contradiction
	// the panel has to resolve by guessing.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if job.snapshot().State == activeJobPaused {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := job.snapshot().State; got != activeJobPaused {
		t.Errorf("job state = %q while the checkpoint says paused", got)
	}
	postJobAction(t, s, id, "cancel", "")
}

func TestTheThresholdIsTheOperatorsNumberAndItIsReported(t *testing.T) {
	target := deadTarget(t)
	s := &server{}
	id, _ := startActiveScan(t, s, fmt.Sprintf(
		`{"url":%q,"max_pages":1,"concurrency":1,"timeout_ms":1000,"failure_pause":0}`, target.URL))
	job, _ := s.activeScanJobByID(id)
	point := job.snapshot().Checkpoint
	if point.FailurePause != runstate.DefaultFailurePause {
		t.Errorf("an unset threshold reported %d, want the documented default %d",
			point.FailurePause, runstate.DefaultFailurePause)
	}
	postJobAction(t, s, id, "cancel", "")
}

func TestResendReissuesOnlyTheRequestsThatNeverAnswered(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer live.Close()

	s := &server{}
	job := &activeScanJob{
		id: "job-resend", state: activeJobRunning,
		waiters:      map[chan struct{}]struct{}{},
		ledger:       runstate.NewLedger(10),
		outbound:     http.DefaultTransport,
		probeTimeout: 2 * time.Second,
		cancel:       func() {}, release: func() {},
	}
	// Two requests that never answered. A request that DID answer is not in the
	// queue: re-sending it would spend a second real request to learn nothing.
	job.ledger.Record(runstate.Failure{Method: "GET", URL: live.URL + "/one", Class: runstate.ClassTimeout})
	job.ledger.Record(runstate.Failure{Method: "GET", URL: live.URL + "/two", Class: runstate.ClassPoolExhausted})
	s.registerActiveScanJob(job)

	recorder := postJobAction(t, s, job.id, "resend", `{"limit":0,"reason":"operator retry"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("resend returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var answer struct {
		Resend resendReport `json:"resend"`
		Reason string       `json:"reason"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the resend answer is not JSON: %v (%s)", err, recorder.Body.String())
	}
	if answer.Resend.Requested != 2 || answer.Resend.Resent != 2 || answer.Resend.Answered != 2 {
		t.Fatalf("resend report = %+v", answer.Resend)
	}
	if answer.Reason != "operator retry" {
		t.Errorf("the operator's reason was dropped: %q", answer.Reason)
	}
	mu.Lock()
	got := len(seen)
	mu.Unlock()
	if got != 2 {
		t.Fatalf("the target saw %d requests, want exactly the two that failed", got)
	}

	// The queue is consumed: a second resend does not send the same requests again.
	second := postJobAction(t, s, job.id, "resend", "")
	if second.Code != http.StatusOK {
		t.Fatalf("the second resend returned %d", second.Code)
	}
	mu.Lock()
	again := len(seen)
	mu.Unlock()
	if again != 2 {
		t.Errorf("a second resend spent %d more requests", again-2)
	}
}

func TestResendKeepsTheClassWhenTheTargetIsStillDead(t *testing.T) {
	target := deadTarget(t)
	s := &server{}
	job := &activeScanJob{
		id: "job-resend-dead", state: activeJobRunning,
		waiters:      map[chan struct{}]struct{}{},
		ledger:       runstate.NewLedger(10),
		outbound:     http.DefaultTransport,
		probeTimeout: 200 * time.Millisecond,
		cancel:       func() {}, release: func() {},
	}
	job.ledger.Record(runstate.Failure{Method: "GET", URL: target.URL + "/lost", Class: runstate.ClassTimeout})
	s.registerActiveScanJob(job)

	recorder := postJobAction(t, s, job.id, "resend", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("resend returned %d", recorder.Code)
	}
	var answer struct {
		Resend resendReport `json:"resend"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Resend.StillFailing != 1 || answer.Resend.Answered != 0 {
		t.Fatalf("a dead target answered the resend: %+v", answer.Resend)
	}
	if len(answer.Resend.Outcomes) != 1 || answer.Resend.Outcomes[0].Class == "" {
		t.Fatalf("a failure that stayed a failure lost its class: %+v", answer.Resend.Outcomes)
	}
}

func TestResendRefusesANegativeLimitRatherThanReinterpretingIt(t *testing.T) {
	s := &server{}
	job := &activeScanJob{
		id: "job-resend-limit", state: activeJobRunning,
		waiters: map[chan struct{}]struct{}{},
		ledger:  runstate.NewLedger(10), outbound: http.DefaultTransport,
		cancel: func() {}, release: func() {},
	}
	s.registerActiveScanJob(job)
	recorder := postJobAction(t, s, job.id, "resend", `{"limit":-5}`)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("a negative limit answered %d, want 400", recorder.Code)
	}
}

func TestThePollAnswerCarriesTheCheckpoint(t *testing.T) {
	s := &server{}
	ledger := runstate.NewLedger(10)
	gate := runstate.NewGate(ledger, runstate.DefaultFailurePause)
	job := &activeScanJob{
		id: "job-checkpoint", state: activeJobRunning,
		waiters: map[chan struct{}]struct{}{},
		ledger:  ledger, gate: gate,
		cancel: func() {}, release: func() {},
	}
	gate.Pause("operator")
	s.registerActiveScanJob(job)

	point := job.snapshot().Checkpoint
	if !point.Paused || point.PauseReason != "operator" {
		t.Errorf("the snapshot does not carry the pause: %+v", point)
	}
	if point.FailurePause != runstate.DefaultFailurePause {
		t.Errorf("the snapshot reports threshold %d, want %d", point.FailurePause, runstate.DefaultFailurePause)
	}
	encoded, err := json.Marshal(job.snapshot())
	if err != nil {
		t.Fatalf("a snapshot stopped marshalling: %v", err)
	}
	if !strings.Contains(string(encoded), `"checkpoint"`) {
		t.Errorf("the checkpoint is absent from the answer a browser polls: %s", encoded)
	}
}

func TestAnUnknownActionIsRefusedRatherThanGuessed(t *testing.T) {
	s := &server{}
	job := &activeScanJob{
		id: "job-unknown", state: activeJobRunning,
		waiters: map[chan struct{}]struct{}{},
		cancel:  func() {}, release: func() {},
	}
	s.registerActiveScanJob(job)
	recorder := postJobAction(t, s, job.id, "detonate", "{}")
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("an unknown action answered %d, want 400", recorder.Code)
	}
}

func TestAPauseOnAFinishedRunIsRefused(t *testing.T) {
	s := &server{}
	job := &activeScanJob{
		id: "job-finished", state: activeJobCompleted, settled: true,
		waiters: map[chan struct{}]struct{}{},
		ledger:  runstate.NewLedger(10),
		gate:    runstate.NewGate(runstate.NewLedger(10), 0),
		cancel:  func() {}, release: func() {},
	}
	s.registerActiveScanJob(job)
	if recorder := postJobAction(t, s, job.id, "pause", ""); recorder.Code != http.StatusNotFound {
		t.Errorf("pausing a finished run answered %d, want 404", recorder.Code)
	}
}
