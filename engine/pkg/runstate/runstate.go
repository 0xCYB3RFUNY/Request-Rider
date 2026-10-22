// Package runstate makes a long run interruptible and resumable.
//
// # WHAT THIS IS ABOUT
//
// A scan or a crawl that cannot be paused is a run that can only be killed, and a
// killed run throws away everything it proved. The run that motivated this
// package spent thirty minutes against a target that had stopped answering:
// every probe burned the full fifteen-second timeout, nine hundred ninety-nine
// of a thousand exchanges carried an error, and the operator could neither stop
// it at the moment it broke nor return to that moment afterwards.
//
// So this package holds the three facts a run needs and did not have:
//
//   - a **ledger** of every request that never produced a response, classified,
//     with the run's own counters for consecutive failures — because "the target
//     stopped answering" and "the scan is working" must be distinguishable while
//     the run is still going, not afterwards;
//   - a **gate** that pauses a run *between probes* and releases the sockets of
//     the probes already in flight, so a paused run is a quiet run rather than a
//     frozen one that still holds the target's connections;
//   - a **checkpoint** assembled from both, so the operator can see where the
//     run broke and decide what to change before resuming.
//
// # ONE MECHANISM, TWO CALLERS
//
// The active scanner and the static Target crawler are separate loops in
// separate packages, and both need this. They share this package rather than
// growing one ledger each, for the reason this project has already paid for once
// in another shape: two copies of the same mechanism drift, and the drift shows
// up as "it pauses in the scanner but not in the crawler".
//
// # WHAT IS NOT HERE, ON PURPOSE
//
// No hidden ceiling on how much a run may do. `Ledger`'s recording bound is an
// operator-overridable field with a documented default, it is reported in the
// checkpoint, and it is the bound on *memory spent remembering failures*, never
// on work: a run that exceeds it keeps counting (`Dropped`) and keeps going. A
// run cannot be silently shortened by the tool that is supposed to report what it
// did.
package runstate

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultFailurePause is how many **consecutive** transport failures pause a run
// when the operator did not choose a number.
//
// It is a default and not a rule: the request field overrides it in either
// direction, `DisableFailurePause` turns the behaviour off entirely, and the
// value in force is reported in every checkpoint. Twenty was chosen from a
// measured run rather than from taste: a dead host answers a probe either
// instantly with a refusal or not at all, so twenty consecutive timeouts is
// evidence of a dead host rather than of a slow one — while twenty *consecutive*
// successes is what a recovered target looks like, so a single flaky page cannot
// pause a run.
const DefaultFailurePause = 20

// DisableFailurePause turns the automatic pause off.
const DisableFailurePause = -1

// DefaultRecordedFailures is how many failures the ledger keeps for the
// "not sent / hung" queue when the operator did not choose a number. Beyond it
// the ledger keeps counting and drops the oldest entries, which the checkpoint
// reports as `dropped`.
const DefaultRecordedFailures = 200

// UnlimitedFailures keeps every failure. It is the operator's explicit choice,
// set by sending a negative recorded-failures count.
const UnlimitedFailures = -1

// Failure classes. They are stable strings because they travel to a browser, a
// report and a Project export, and a class that changes its name between
// versions makes an old export unreadable rather than merely dated.
const (
	// ClassTimeout is a request that reached its deadline without a response.
	ClassTimeout = "timeout"
	// ClassConnectionRefused is a peer that actively refused the connection.
	ClassConnectionRefused = "connection_refused"
	// ClassConnectionReset is a peer that accepted and then dropped the socket.
	ClassConnectionReset = "connection_reset"
	// ClassPoolExhausted is Go's own client waiting for a free connection while
	// every one of them is held by a request that is itself stuck. It is its own
	// class because it is the symptom that makes a dead target expensive: the run
	// stops spending requests on the network and starts spending them on itself.
	ClassPoolExhausted = "pool_exhausted"
	// ClassDNS is a name that did not resolve.
	ClassDNS = "dns"
	// ClassTLS is a handshake that failed or was refused.
	ClassTLS = "tls"
	// ClassEOF is a connection closed before a full response arrived.
	ClassEOF = "eof"
	// ClassCanceled is the run's own cancellation. It is deliberately not a
	// failure: a cancelled run is not a run that failed.
	ClassCanceled = "canceled"
	// ClassOther is a failure this package cannot name more precisely. It is
	// reported as its own class rather than folded into a neighbour, so "unknown"
	// stays visible instead of being counted as something it is not.
	ClassOther = "other"
)

// Failure is one request that never produced a response.
//
// `Label` is the caller's own name for the probe (a detector and its payload), so
// a queue entry says *which* probe stopped answering rather than only which URL.
// `URL` is the address as sent; `Label` is what the run called it.
type Failure struct {
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	Label      string    `json:"label,omitempty"`
	Class      string    `json:"class"`
	Error      string    `json:"error"`
	DurationMS int64     `json:"duration_ms"`
	At         time.Time `json:"at"`
}

// ClassifyTransportError names a transport failure.
//
// The classification is deliberately shallow — it reads the error the transport
// actually returned and nothing else — because the alternative is guessing from
// a message this package does not own. Every branch names something an operator
// can act on differently from the others: a refused connection and a DNS answer
// are different faults, a TLS failure means something else entirely, and
// `pool_exhausted` is the one that says the run is starving itself.
func ClassifyTransportError(err error) string {
	if err == nil {
		return ""
	}
	// A cancelled context is the run stopping, not the target failing. It is
	// asked first so a cancellation that happens to carry a network message is
	// still reported as a cancellation.
	if errors := contextErrors(err); errors {
		return ClassCanceled
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "canceled while waiting for connection"),
		strings.Contains(text, "waiting for connection"):
		return ClassPoolExhausted
	case strings.Contains(text, "timeout"),
		strings.Contains(text, "deadline exceeded"),
		strings.Contains(text, "timed out"),
		strings.Contains(text, "i/o timeout"):
		return ClassTimeout
	case strings.Contains(text, "connection refused"):
		return ClassConnectionRefused
	case strings.Contains(text, "connection reset"),
		strings.Contains(text, "broken pipe"):
		return ClassConnectionReset
	case strings.Contains(text, "tls"), strings.Contains(text, "x509"),
		strings.Contains(text, "certificate"):
		return ClassTLS
	case strings.Contains(text, "no such host"), strings.Contains(text, "dns"):
		return ClassDNS
	case strings.Contains(text, "eof"), strings.Contains(text, "unexpected end"):
		return ClassEOF
	}
	// A typed error is worth more than its text when the text is generic.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ClassTimeout
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return ClassTimeout
	}
	return ClassOther
}

// ResolveFailurePause is the operator's number, normalised.
//
// The three states are three states: a negative value turns the automatic pause
// off, zero takes the documented default, and a positive value is the operator's
// own count. A run that paused because of a silently-invented ceiling would be a
// run that stopped without being asked, which is the thing this whole package
// exists to end.
func ResolveFailurePause(requested int) int {
	if requested == DisableFailurePause {
		return 0
	}
	if requested <= 0 {
		return DefaultFailurePause
	}
	return requested
}

// ResolveRecordedFailures is the operator's bound, normalised.
//
// Zero takes the documented default, a negative value keeps every failure. The
// result is never zero-by-default, because "keep everything" has to be something
// the operator asked for rather than something a missing field caused.
func ResolveRecordedFailures(requested int) int {
	if requested < 0 {
		return 0
	}
	if requested == 0 {
		return DefaultRecordedFailures
	}
	return requested
}

// Ledger is a run's record of what never answered.
//
// It is safe for concurrent use: probes run on a worker pool, so the writers are
// the workers.
type Ledger struct {
	keep int

	mu          sync.Mutex
	failures    []Failure
	classes     map[string]int
	consecutive int
	total       int64
	dropped     int64
	first       *Failure
	lastOK      string
	lastOKAt    time.Time
}

// NewLedger builds a ledger that keeps `keep` failures (0 keeps every one).
func NewLedger(keep int) *Ledger {
	return &Ledger{keep: keep, classes: map[string]int{}}
}

// Record writes one failure and resets the consecutive counter's successor
// state: the run has just failed, so the next success clears the streak.
func (l *Ledger) Record(f Failure) {
	if l == nil {
		return
	}
	if f.Class == "" {
		f.Class = ClassOther
	}
	if f.At.IsZero() {
		f.At = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total++
	l.consecutive++
	if l.consecutive == 1 || l.first == nil {
		copied := f
		// The first failure is what "where did it break" answers, and it is
		// pinned only when the streak starts: the first failure of a run that then
		// recovered is not where the run broke.
		if l.consecutive == 1 {
			l.first = &copied
		}
	}
	l.classes[f.Class]++
	if l.keep > 0 {
		l.failures = append(l.failures, f)
		if len(l.failures) > l.keep {
			l.failures = append([]Failure(nil), l.failures[len(l.failures)-l.keep:]...)
			l.dropped++
		}
	}
}

// Success records that a probe answered, clearing the consecutive-failure streak.
//
// Clearing on success is what makes the automatic pause evidence rather than a
// timer: a run against a slow target interleaves timeouts and answers forever
// and never pauses, and only a run that is *consistently* unanswered stops.
func (l *Ledger) Success(label string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consecutive = 0
	if label != "" {
		l.lastOK = label
		l.lastOKAt = time.Now().UTC()
	}
}

// Consecutive is how many transport failures have happened since the last
// success.
func (l *Ledger) Consecutive() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.consecutive
}

// Failures is the "not sent / hung" queue, oldest first.
func (l *Ledger) Failures() []Failure {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Failure(nil), l.failures...)
}

// Total is how many requests never answered, recorded or dropped.
func (l *Ledger) Total() int64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Dropped is how many failures the recording bound discarded. They are counted
// rather than lost, because a bound that silently forgets is a bound that lies.
func (l *Ledger) Dropped() int64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// Classes is the per-class tally.
func (l *Ledger) Classes() map[string]int {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int, len(l.classes))
	for name, count := range l.classes {
		out[name] = count
	}
	return out
}

// Take removes and returns the recorded failures, which is how a resend consumes
// the queue without re-sending the same request twice on the next one.
func (l *Ledger) Take() []Failure {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]Failure(nil), l.failures...)
	l.failures = nil
	return out
}

// Checkpoint is everything an operator needs to answer "where did it break, and
// what should I change before I resume".
//
// It is a value, not a live view, and it is what the browser reads: a paused run
// has no progress to report, so the frontier is what tells the operator that the
// run stopped at all.
type Checkpoint struct {
	Paused          bool           `json:"paused"`
	PauseReason     string         `json:"pause_reason,omitempty"`
	PausedAt        time.Time      `json:"paused_at,omitempty"`
	DroppedProbes   int            `json:"dropped_probes"`
	FailurePause    int            `json:"failure_pause"`
	ConsecutiveFail int            `json:"consecutive_failures"`
	FailureTotal    int64          `json:"failures_total"`
	FailureDropped  int64          `json:"failures_dropped"`
	FailureClasses  map[string]int `json:"failure_classes"`
	FirstFailure    *Failure       `json:"first_failure,omitempty"`
	LastSuccess     string         `json:"last_success,omitempty"`
	FailedRequests  []Failure      `json:"failed_requests,omitempty"`
	Recorded        int            `json:"recorded_failures"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// LedgerCheckpoint assembles the checkpoint from the ledger and the gate.
func (l *Ledger) LedgerCheckpoint(queueLimit int) Checkpoint {
	if l == nil {
		return Checkpoint{UpdatedAt: time.Now().UTC()}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	point := Checkpoint{
		FailureTotal:    l.total,
		FailureDropped:  l.dropped,
		FailureClasses:  make(map[string]int, len(l.classes)),
		LastSuccess:     l.lastOK,
		ConsecutiveFail: l.consecutive,
		UpdatedAt:       time.Now().UTC(),
	}
	for name, count := range l.classes {
		point.FailureClasses[name] = count
	}
	if l.first != nil {
		copied := *l.first
		point.FirstFailure = &copied
	}
	queue := l.failures
	if queueLimit > 0 && len(queue) > queueLimit {
		queue = queue[len(queue)-queueLimit:]
	}
	point.FailedRequests = append([]Failure(nil), queue...)
	point.Recorded = len(queue)
	return point
}

// contextErrors reports whether the error is the run's own cancellation.
func contextErrors(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	return strings.Contains(err.Error(), "context canceled")
}
