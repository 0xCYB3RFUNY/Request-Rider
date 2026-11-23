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
	engine  *server
	job     *osintJob
	indexes int
	// indexesDone is how many of those indexes the transform has finished. It is
	// kept apart from `indexes` because the total can arrive after the job
	// starts — the archive chain is only known once its list has been read — and
	// one number cannot be both the answer and the progress towards it.
	indexesDone int
	progress    func(transformProgress)
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
	collector.indexesDone = total
	collector.reportState(transformProgress{
		Names:        collector.nameCount(),
		Relations:    relations,
		Indexes:      total,
		IndexesTotal: collector.indexes,
		CurrentIndex: current,
	})
}

// setIndexTotal publishes how many work items the transform turned out to
// have, for a transform that only learns the size of its chain after starting.
//
// The archive chain is exactly this case: its length is the number of crawl
// collections the index published, which is not knowable before that list is
// read. Reporting a total of zero until then would show a run of 130 requests
// as a run with nothing to do, and the operator has no way to tell that from a
// job that is stuck.
func (collector *transformCollector) setIndexTotal(ctx context.Context, total int) {
	if collector == nil || total <= 0 {
		return
	}
	if err := collector.checkpoint(ctx); err != nil {
		return
	}
	collector.indexes = total
	collector.report()
}

// indexPosition reports which index of the chain the transform is on, and how
// many it has finished, without touching the name and relation counters.
//
// It is separate from indexDone because an index that is skipped still moved the
// chain along: a collection that publishes nothing was walked, and a counter
// that only advances on a success would leave a 128-index run reporting one
// index done for the whole time.
func (collector *transformCollector) indexPosition(ctx context.Context, current string, done, total int) {
	if collector == nil {
		return
	}
	if err := collector.checkpoint(ctx); err != nil {
		return
	}
	collector.mutex.Lock()
	update := collector.last
	collector.mutex.Unlock()
	collector.indexes = total
	collector.indexesDone = done
	update.Names = collector.nameCount()
	update.Indexes = done
	update.IndexesTotal = total
	update.CurrentIndex = current
	collector.reportState(update)
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
	// The share of the chain is computed here and nowhere else. Every caller
	// that builds a progress update by hand was leaving Partial at its zero
	// value, so a run that knew it was 1 of 2 published 0% — a number that is
	// not merely unknown but wrong, and worse than the indeterminate bar it
	// replaced.
	update.Partial = collector.partial()
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

// partial reports how far the finished indexes have carried the transform, or
// -1 when no total is known.
//
// It used to return -1 on both branches, so the total was published and read
// and then thrown away: the panel showed an indeterminate bar for a chain whose
// length the engine knew exactly. A total that exists is now divided, and a
// total that does not is still an indeterminate bar, because a made-up
// percentage is worse than an honest "cannot say".
func (collector *transformCollector) partial() float64 {
	if collector == nil || collector.indexes <= 0 {
		return -1
	}
	if collector.indexesDone >= collector.indexes {
		return 100
	}
	return float64(collector.indexesDone) / float64(collector.indexes) * 100
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
