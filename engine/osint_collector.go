package main

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
)

// transformProgress is one collector checkpoint: the real counters collected so
// far, reported straight to the job that is showing them.
type transformProgress struct {
	Names        int
	Relations    int
	Indexes      int
	IndexesTotal int
	CurrentIndex string
	Partial      float64
}

// transformCollector lets a running transform report progress and honour a
// pause without knowing anything about jobs.
//
// A collector is what separates the two ways a transform runs: the synchronous
// endpoint passes nil, so the transform behaves exactly as before, and a
// background job passes a real one to get live counters and a pause point.
type transformCollector struct {
	engine   *server
	job      *osintJob
	indexes  int
	progress func(transformProgress)
	// ctx is the job context, kept here so a reader can reach the pause point
	// without threading the context through every reader signature.
	ctx context.Context

	mutex   sync.Mutex
	names   int
	pending int
	// seen holds the names already counted, so the progress counter reports the
	// distinct names of the answer and not the rows every index handed over.
	seen map[string]struct{}
	// last is the most recent report, so a phase that collects no name can
	// still refresh the panel label without inventing counters.
	last transformProgress
	// sinceLastReport throttles the progress callback: a large zone collects
	// thousands of names per second and the browser cannot use every tick.
	sinceLastReport int
	// stop is closed when the transform ends, so the in-flight index
	// goroutines stop reporting into a finished job.
	stop     chan struct{}
	stopOnce sync.Once
	// stopped is set once close ran, which is how a cancel is recognised when
	// the collector stopped before the context did.
	stopped atomic.Bool
}

// jobContext returns the context the transform runs under.
func (collector *transformCollector) jobContext() context.Context {
	if collector == nil || collector.ctx == nil {
		return context.Background()
	}
	return collector.ctx
}

// reportEvery is how many collected names pass between two progress callbacks.
const reportEvery = 250

// checkpoint is the pause point of a transform. A nil collector means the
// synchronous endpoint, where there is nothing to wait for.
func (collector *transformCollector) checkpoint(ctx context.Context) error {
	if collector == nil {
		return ctx.Err()
	}
	select {
	case <-collector.stop:
		return context.Canceled
	default:
	}
	return collector.job.gate.checkpoint(ctx)
}

// distinct records that one name entered the result, counting it once even when
// several certificate indexes hold the same name, then reports progress.
//
// The counter is the number of names the answer actually contains: five indexes
// answering a large zone hand over the same names repeatedly, and adding every
// row of every index would report several times more names than the result has.
func (collector *transformCollector) distinct(ctx context.Context, name string) {
	if collector == nil || name == "" {
		return
	}
	collector.mutex.Lock()
	if collector.seen == nil {
		collector.seen = map[string]struct{}{}
	}
	if _, known := collector.seen[name]; known {
		collector.mutex.Unlock()
		return
	}
	collector.seen[name] = struct{}{}
	collector.names++
	collector.mutex.Unlock()
	// Every name is a pause point, but reporting is throttled so a large zone
	// does not flood the poll.
	if err := collector.checkpoint(ctx); err != nil {
		return
	}
	collector.mutex.Lock()
	collector.sinceLastReport++
	shouldReport := collector.sinceLastReport >= reportEvery
	if shouldReport {
		collector.sinceLastReport = 0
	}
	collector.mutex.Unlock()
	if shouldReport {
		collector.report()
	}
}

// flush reports the counters as they stand. A page or a phase that added names
// shows up in the panel even when the per-name report threshold has not been
// reached, so a short answer is never reported as zero names.
func (collector *transformCollector) flush(ctx context.Context) {
	if collector == nil {
		return
	}
	if err := collector.checkpoint(ctx); err != nil {
		return
	}
	collector.mutex.Lock()
	collector.sinceLastReport = 0
	collector.mutex.Unlock()
	collector.report()
}

// indexDone records that one certificate index finished answering, so the
// progress panel shows which of them are still outstanding.
func (collector *transformCollector) indexDone(ctx context.Context, current string, total, relations int) {
	if collector == nil {
		return
	}
	if err := collector.checkpoint(ctx); err != nil {
		return
	}
	collector.reportState(transformProgress{
		Names:        collector.nameCount(),
		Relations:    relations,
		Indexes:      total,
		IndexesTotal: collector.indexes,
		CurrentIndex: current,
	})
}

// label reports which work item a transform is on without touching its
// counters, so a phase that resolves names one candidate at a time still shows
// that it is moving instead of looking frozen.
func (collector *transformCollector) label(ctx context.Context, current string) {
	if collector == nil {
		return
	}
	if err := collector.checkpoint(ctx); err != nil {
		return
	}
	collector.mutex.Lock()
	update := collector.last
	collector.mutex.Unlock()
	update.Names = collector.nameCount()
	update.CurrentIndex = current
	collector.reportState(update)
}

// reportState publishes one progress update and remembers it, so a later label
// refresh repeats the real counters instead of blanking them.
func (collector *transformCollector) reportState(update transformProgress) {
	if collector == nil {
		return
	}
	collector.mutex.Lock()
	collector.last = update
	collector.mutex.Unlock()
	collector.progress(update)
}

func (collector *transformCollector) report() {
	if collector == nil {
		return
	}
	collector.reportState(transformProgress{
		Names:        collector.nameCount(),
		Indexes:      0,
		IndexesTotal: collector.indexes,
		Partial:      collector.partial(),
	})
}

func (collector *transformCollector) nameCount() int {
	if collector == nil {
		return 0
	}
	collector.mutex.Lock()
	defer collector.mutex.Unlock()
	return collector.names
}

// partial reports how far the finished indexes have carried the transform. The
// certificate indexes do not publish a total, so the panel shows an
// indeterminate length instead of a percentage nobody can compute.
func (collector *transformCollector) partial() float64 {
	if collector == nil || collector.indexes <= 0 {
		return -1
	}
	return -1
}

// close marks the transform as over. It is deliberately separate from
// requestStop: a transform that ran to its end must not look cancelled, and a
// cancelled one must not look finished.
func (collector *transformCollector) close() {
	if collector == nil {
		return
	}
	collector.stopOnce.Do(func() {
		close(collector.stop)
	})
}

// requestStop records that a cancel was asked for. It is the only thing that
// makes a transform cancelled.
func (collector *transformCollector) requestStop() {
	if collector == nil {
		return
	}
	collector.stopped.Store(true)
}

// cancelled reports whether a cancel was asked for, which is how a cancelled
// transform is told apart from one that finished or failed on its own.
func (collector *transformCollector) cancelled() bool {
	return collector != nil && collector.stopped.Load()
}

// isStop checks whether the collector is stopping, so an in-flight index stops
// adding names instead of racing a finished job.
func (collector *transformCollector) isStop() bool {
	if collector == nil {
		return false
	}
	select {
	case <-collector.stop:
		return true
	default:
		return false
	}
}

// certificateIndexName reports the label of a certificate index for the
// progress panel.
func certificateIndexName(source string) string {
	return strings.TrimSpace(source)
}
