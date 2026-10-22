package runstate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrPaused is what a request returns when the gate — not the run — cancelled it.
//
// It exists so that a pause cannot be mistaken for a target that failed. A probe
// the operator deliberately dropped is not evidence about the target, and a run
// that recorded it as one would report a clean target as broken (or the other way
// round). The run treats it as "not now": it waits at the gate and tries the same
// surface again after the resume, which is what "continues from where it stopped"
// means in practice.
var ErrPaused = errors.New("runstate: probe dropped by pause")

// Gate pauses a run between probes and releases the probes already in flight.
//
// # WHY IT EXISTS AS A SEPARATE THING FROM THE LEDGER
//
// The ledger knows that a target stopped answering. The gate is what the run does
// about it. Keeping them apart is what lets the automatic pause stay honest: the
// threshold lives with the gate because the gate is the thing it stops, and the
// failures live in the ledger because the failures are the evidence for it.
//
// # PAUSE IS BETWEEN PROBES, NOT DURING ONE
//
// `Wait` is called at the points where a run is about to issue its next request.
// A pause therefore cannot interrupt a probe halfway through, which is exactly
// the property that makes it observable: the operator stops a run and the run
// stops, rather than the run appearing stopped while its workers keep draining
// requests.
//
// # PAUSE RELEASES SOCKETS, AND SAYS SO
//
// A frozen run still holds connections, and a target still sees them. So
// `Pause` cancels every context handed out by `Child`, which closes those
// requests, and reports how many probes it dropped. That number is the difference
// between "the run is paused" and "the run is pretending".
type Gate struct {
	ledger     *Ledger
	threshold  int
	autoPaused bool

	mu       sync.Mutex
	paused   bool
	reason   string
	pausedAt time.Time
	resume   chan struct{}
	// inflight holds the cancel functions of probes currently running. A probe
	// registers itself with `Child` and releases with the returned function; a
	// paused run cancels all of them.
	inflight map[int64]context.CancelFunc
	nextID   int64
	dropped  int
	// observe is called whenever the pause state changes, so a caller can publish
	// the change to a browser without polling.
	observe func(paused bool, reason string, dropped int)
}

// NewGate builds a gate for one run.
//
// `threshold` is already normalised by `ResolveFailurePause`: zero means the run
// never pauses itself, a positive value is how many consecutive failures do it.
func NewGate(ledger *Ledger, threshold int) *Gate {
	return &Gate{
		ledger:    ledger,
		threshold: threshold,
		inflight:  map[int64]context.CancelFunc{},
	}
}

// Observe registers a callback for pause-state changes. It is set once, by the
// run's owner, before the run starts.
func (g *Gate) Observe(fn func(paused bool, reason string, dropped int)) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.observe = fn
	g.mu.Unlock()
}

// Wait blocks while the run is paused, and returns the context's error when the
// run is cancelled instead.
//
// It is called by the run between probes. The automatic pause is evaluated here
// rather than in a watcher goroutine so that the decision is made at a moment the
// run can actually stop, and so a run that never reaches another probe does not
// announce a pause it did not take.
func (g *Gate) Wait(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if !g.paused && g.threshold > 0 && g.ledger != nil &&
		g.ledger.Consecutive() >= g.threshold {
		g.pauseLocked(
			fmt.Sprintf("auto: %d consecutive transport failures (threshold %d)",
				g.ledger.Consecutive(), g.threshold),
		)
		g.autoPaused = true
		// Releasing the probes already in flight is what makes an automatic
		// pause a quiet pause rather than a frozen one, and it is the same
		// property the operator's own Pause has.
		cancels := make([]context.CancelFunc, 0, len(g.inflight))
		for _, cancel := range g.inflight {
			cancels = append(cancels, cancel)
		}
		dropped := len(cancels)
		g.dropped += dropped
		observe := g.observe
		reasonText := g.reason
		g.mu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		if observe != nil {
			observe(true, reasonText, dropped)
		}
		// A run that auto-paused must still wait for its resume, even if it
		// reached this point with no probes left in flight.
		g.mu.Lock()
		resume := g.resume
		g.mu.Unlock()
		select {
		case <-resume:
			return ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !g.paused {
		g.mu.Unlock()
		return ctx.Err()
	}
	resume := g.resume
	g.mu.Unlock()

	select {
	case <-resume:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Child registers one in-flight probe and returns the context it must use plus
// the function that unregisters it.
//
// A probe that does not use the returned context cannot be released by a pause,
// which is why the run threads this context through every request rather than
// only checking `Wait` at the top of a worker.
func (g *Gate) Child(parent context.Context) (context.Context, func()) {
	if g == nil {
		return parent, func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	g.mu.Lock()
	g.nextID++
	id := g.nextID
	// A probe that starts while the run is already paused gets a context that is
	// already cancelled, so a race between pause and dispatch cannot leak a
	// request the operator believes was stopped.
	if g.paused {
		cancel()
	} else {
		g.inflight[id] = cancel
	}
	g.mu.Unlock()
	return ctx, func() {
		cancel()
		g.mu.Lock()
		delete(g.inflight, id)
		g.mu.Unlock()
	}
}

// Pause stops the run between its next probes and drops the probes in flight.
//
// It reports how many probes were dropped, which is also written into the
// checkpoint, because "paused" and "paused after throwing away four probes" are
// different facts and an operator reading only the first would not know that four
// results are missing.
func (g *Gate) Pause(reason string) int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	if g.paused {
		dropped := g.dropped
		g.mu.Unlock()
		return dropped
	}
	g.pauseLocked(reason)
	cancels := make([]context.CancelFunc, 0, len(g.inflight))
	for _, cancel := range g.inflight {
		cancels = append(cancels, cancel)
	}
	dropped := len(cancels)
	g.dropped += dropped
	observe := g.observe
	reasonText := g.reason
	g.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	if observe != nil {
		observe(true, reasonText, dropped)
	}
	return dropped
}

// pauseLocked sets the state. The caller holds the lock.
func (g *Gate) pauseLocked(reason string) {
	g.paused = true
	g.reason = reason
	g.pausedAt = time.Now().UTC()
	g.resume = make(chan struct{})
}

// Resume lets the run continue. It reports whether the run was actually paused.
func (g *Gate) Resume() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	if !g.paused {
		g.mu.Unlock()
		return false
	}
	g.paused = false
	g.autoPaused = false
	reason := g.reason
	g.reason = ""
	close(g.resume)
	g.resume = nil
	observe := g.observe
	g.mu.Unlock()
	// Consecutive failures are cleared so a resumed run gets the threshold again
	// rather than pausing immediately on the first failure it meets — the operator
	// resumed deliberately, and the evidence that made it pause has been seen.
	if g.ledger != nil {
		g.ledger.mu.Lock()
		g.ledger.consecutive = 0
		g.ledger.mu.Unlock()
	}
	if observe != nil {
		observe(false, reason, 0)
	}
	return true
}

// Paused reports whether the run is paused and why.
func (g *Gate) Paused() (bool, string) {
	if g == nil {
		return false, ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused, g.reason
}

// InFlight is how many probes are running right now.
func (g *Gate) InFlight() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.inflight)
}

// Dropped is how many probes a pause cancelled across this run's lifetime.
func (g *Gate) Dropped() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dropped
}

// AutoPaused reports whether the pause came from the failure threshold rather
// than from the operator.
func (g *Gate) AutoPaused() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.autoPaused
}

// Checkpoint is the pause state joined with the ledger's frontier.
func (g *Gate) Checkpoint(queueLimit int) Checkpoint {
	if g == nil {
		return Checkpoint{UpdatedAt: time.Now().UTC()}
	}
	point := g.ledger.LedgerCheckpoint(queueLimit)
	g.mu.Lock()
	point.Paused = g.paused
	point.PauseReason = g.reason
	point.PausedAt = g.pausedAt
	point.DroppedProbes = g.dropped
	point.FailurePause = g.threshold
	point.UpdatedAt = time.Now().UTC()
	g.mu.Unlock()
	return point
}

// Consecutive exposes the ledger's consecutive failure count, so a run's tests
// and callers can read the same evidence the automatic pause reacts to.
func (g *Gate) Consecutive() int {
	if g == nil || g.ledger == nil {
		return 0
	}
	return g.ledger.Consecutive()
}
