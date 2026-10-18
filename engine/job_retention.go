package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultFinishedJobRetention is how long a finished job stays readable.
//
// Every run this engine starts is kept in a map so the browser can poll it and so
// a reload of the workspace can show what happened. Nothing ever removed them, so
// a long session accumulated every attack, crawl, burst, listener and last-byte
// job ever run, each holding its own results — a leak that only shows up as a
// process that slowly stops fitting.
//
// The window has to be generous rather than short. The UI keeps the active
// identifier in local storage and resumes polling after a reload, so a result
// that vanished too early would look like a lost run. An hour is far longer than
// any workflow takes to look at a finished run, and it is a default, not a rule:
// the operator raises it with RR_FINISHED_JOB_RETENTION_MINUTES, and may set it
// to keep jobs for the life of the process.
const defaultFinishedJobRetention = time.Hour

// finishedJobRetention is the applied window.
func finishedJobRetention() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RR_FINISHED_JOB_RETENTION_MINUTES"))
	if raw == "" {
		return defaultFinishedJobRetention
	}
	if value, err := strconv.Atoi(raw); err == nil && value > 0 {
		return time.Duration(value) * time.Minute
	}
	return defaultFinishedJobRetention
}

// finishedJobSweeper releases jobs that reached a terminal state long enough ago.
//
// It is deliberately a single goroutine started with the server rather than a
// timer per job: a timer per job would mean a timer per finished run, which is
// the same growth in a different shape.
type finishedJobSweeper struct {
	// stopOnce makes the stop idempotent. A `select` on the channel with a
	// `default` branch is not enough: two callers can both take the default
	// branch and both close, which panics. The property is worth having because
	// shutdown paths can run more than once.
	stopOnce sync.Once
	stop     chan struct{}
}

// terminalStatus reports whether a job has finished. Only a terminal job is ever
// released, so a running job cannot be swept out from under the browser.
func terminalStatus(status string) bool {
	switch status {
	case "completed", "cancelled", "failed", "error", "interrupted":
		return true
	}
	return false
}

// expired reports whether a terminal job is old enough to release. A job with no
// recorded finish time is left alone: it is either still running or was created by
// a path that never recorded one, and guessing would drop live evidence.
func expired(finishedAt time.Time, now time.Time, retention time.Duration) bool {
	if finishedAt.IsZero() {
		return false
	}
	return now.Sub(finishedAt) >= retention
}

// startFinishedJobSweeper releases finished jobs in the background until the
// process ends. The interval is a fraction of the retention so a short retention
// still releases promptly and a long one does not wake the process often.
func (s *server) startFinishedJobSweeper() {
	interval := finishedJobRetention() / 8
	if interval < time.Second {
		interval = time.Second
	}
	sweeper := &finishedJobSweeper{stop: make(chan struct{})}
	s.sweeper = sweeper
	sweeper.stopOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-sweeper.stop:
					return
				case <-ticker.C:
					s.sweepFinishedJobs(time.Now())
				}
			}
		}()
	})
}

// sweepFinishedJobs releases every job that finished longer ago than the
// retention window allows.
//
// The read is taken under each map's own lock and the delete happens under the
// write lock, so a job that arrives while the sweep runs is either seen or
// missed, never half-removed. A job that finished moments ago is not eligible,
// which is what keeps a just-cancelled run readable.
func (s *server) sweepFinishedJobs(now time.Time) {
	retention := finishedJobRetention()

	s.attacksMu.Lock()
	for id, job := range s.attacks {
		// WHY ONE LOCK INSTEAD OF READ-THEN-WRITE. The previous shape read
		// `finishedAt`/`status` under RLock, decided, released, and only then took the
		// write lock to act on it. Between RUnlock and Lock another goroutine could run
		// `setState` or restart the job, so the decision was made about one state and
		// applied to another: a job restarted in that window would be released — its
		// results and spill file destroyed — while it was live again, and a job that
		// became finished in that window was released without ever having been examined
		// by a fresh decision. Six sites, so it was a pattern rather than a slip.
		//
		// `-race` cannot find this. There is no unsynchronised memory access here, only
		// an interleaving of two correctly locked regions, which is why it survived.
		//
		// One write lock costs nothing here: the sweep holds the map lock throughout
		// already, so contention is with the job's own goroutine, not with the sweep.
		job.mu.Lock()
		if !terminalStatus(job.status) || !expired(job.finishedAt, now, retention) {
			job.mu.Unlock()
			continue
		}
		// The spill file goes with the job. Closing it is not enough: the file
		// would be left in the process temp directory with no job left to reach
		// it, which is the same leak in a different place. Nothing else ever
		// removes these files, so releasing the job has to remove its evidence
		// too — the run is no longer readable either way.
		//
		// The lock is NOT taken again here, and that is the whole point of the
		// paragraph above: this sweep already holds `job.mu` from the check a few
		// lines up, because a decision made under a released lock can be applied to
		// a state that has changed. A second `job.mu.Lock()` on this path is not a
		// no-op — `sync.Mutex` is not reentrant, so it blocks forever on the lock
		// the same goroutine already holds. It was written that way and the whole
		// package timed out at 10 minutes in `TestSweeperReleasesEveryFinishedJobKind`,
		// with the stack parked on this very `Lock()`.
		if job.store != nil {
			job.store.Close()
			job.store.Remove()
			job.store = nil
		}
		job.results = nil
		job.mu.Unlock()
		delete(s.attacks, id)
	}
	s.attacksMu.Unlock()

	s.targetMapsMu.Lock()
	for id, job := range s.targetMaps {
		// WHY ONE LOCK INSTEAD OF READ-THEN-WRITE. The previous shape read
		// `finishedAt`/`status` under RLock, decided, released, and only then took the
		// write lock to act on it. Between RUnlock and Lock another goroutine could run
		// `setState` or restart the job, so the decision was made about one state and
		// applied to another: a job restarted in that window would be released — its
		// results and spill file destroyed — while it was live again, and a job that
		// became finished in that window was released without ever having been examined
		// by a fresh decision. Six sites, so it was a pattern rather than a slip.
		//
		// `-race` cannot find this. There is no unsynchronised memory access here, only
		// an interleaving of two correctly locked regions, which is why it survived.
		//
		// One write lock costs nothing here: the sweep holds the map lock throughout
		// already, so contention is with the job's own goroutine, not with the sweep.
		job.mu.Lock()
		if !terminalStatus(job.status) || !expired(job.finishedAt, now, retention) {
			job.mu.Unlock()
			continue
		}
		job.pages = nil
		job.mu.Unlock()
		delete(s.targetMaps, id)
	}
	s.targetMapsMu.Unlock()

	s.burstsMu.Lock()
	for id, job := range s.bursts {
		// WHY ONE LOCK INSTEAD OF READ-THEN-WRITE. The previous shape read
		// `finishedAt`/`status` under RLock, decided, released, and only then took the
		// write lock to act on it. Between RUnlock and Lock another goroutine could run
		// `setState` or restart the job, so the decision was made about one state and
		// applied to another: a job restarted in that window would be released — its
		// results and spill file destroyed — while it was live again, and a job that
		// became finished in that window was released without ever having been examined
		// by a fresh decision. Six sites, so it was a pattern rather than a slip.
		//
		// `-race` cannot find this. There is no unsynchronised memory access here, only
		// an interleaving of two correctly locked regions, which is why it survived.
		//
		// One write lock costs nothing here: the sweep holds the map lock throughout
		// already, so contention is with the job's own goroutine, not with the sweep.
		job.mu.Lock()
		if !terminalStatus(job.status) || !expired(job.finishedAt, now, retention) {
			job.mu.Unlock()
			continue
		}
		job.results = nil
		job.mu.Unlock()
		delete(s.bursts, id)
	}
	s.burstsMu.Unlock()

	s.lastByteJobsMu.Lock()
	for id, job := range s.lastByteJobs {
		// WHY ONE LOCK INSTEAD OF READ-THEN-WRITE. The previous shape read
		// `finishedAt`/`status` under RLock, decided, released, and only then took the
		// write lock to act on it. Between RUnlock and Lock another goroutine could run
		// `setState` or restart the job, so the decision was made about one state and
		// applied to another: a job restarted in that window would be released — its
		// results and spill file destroyed — while it was live again, and a job that
		// became finished in that window was released without ever having been examined
		// by a fresh decision. Six sites, so it was a pattern rather than a slip.
		//
		// `-race` cannot find this. There is no unsynchronised memory access here, only
		// an interleaving of two correctly locked regions, which is why it survived.
		//
		// One write lock costs nothing here: the sweep holds the map lock throughout
		// already, so contention is with the job's own goroutine, not with the sweep.
		job.mu.Lock()
		if !terminalStatus(job.status) || !expired(job.finishedAt, now, retention) {
			job.mu.Unlock()
			continue
		}
		job.results = nil
		job.mu.Unlock()
		delete(s.lastByteJobs, id)
	}
	s.lastByteJobsMu.Unlock()

	s.oastListenersMu.Lock()
	for id, job := range s.oastListeners {
		// WHY ONE LOCK INSTEAD OF READ-THEN-WRITE. The previous shape read
		// `finishedAt`/`status` under RLock, decided, released, and only then took the
		// write lock to act on it. Between RUnlock and Lock another goroutine could run
		// `setState` or restart the job, so the decision was made about one state and
		// applied to another: a job restarted in that window would be released — its
		// results and spill file destroyed — while it was live again, and a job that
		// became finished in that window was released without ever having been examined
		// by a fresh decision. Six sites, so it was a pattern rather than a slip.
		//
		// `-race` cannot find this. There is no unsynchronised memory access here, only
		// an interleaving of two correctly locked regions, which is why it survived.
		//
		// One write lock costs nothing here: the sweep holds the map lock throughout
		// already, so contention is with the job's own goroutine, not with the sweep.
		job.mu.Lock()
		if !terminalStatus(job.status) || !expired(job.finishedAt, now, retention) {
			job.mu.Unlock()
			continue
		}
		job.events = nil
		job.mu.Unlock()
		delete(s.oastListeners, id)
	}
	s.oastListenersMu.Unlock()

	// The active scanner keeps a finished report and its whole event log, which
	// are the two largest things any of these maps hold: a report carries every
	// finding with its payload and evidence. So this map is swept by the same
	// window and with the same guards as the others rather than by a timer of
	// its own.
	s.activeScansMu.Lock()
	for id, job := range s.activeScans {
		// Same single-lock decision as the maps above; see the long note there. This
		// site reads `state` rather than `status`, which is why it was missed by the
		// first pass and is fixed separately — a pattern applied by search misses the
		// one site whose field name differs.
		job.mu.Lock()
		if !terminalStatus(job.state) || !expired(job.finishedAt, now, retention) {
			job.mu.Unlock()
			continue
		}
		job.report = nil
		job.events = nil
		job.mu.Unlock()
		delete(s.activeScans, id)
	}
	s.activeScansMu.Unlock()
}

// stopFinishedJobSweeper ends the sweep. It is idempotent, because shutdown paths
// can run more than once and a closed channel would panic.
func (s *server) stopFinishedJobSweeper() {
	if s.sweeper == nil {
		return
	}
	s.sweeper.stopOnce.Do(func() { close(s.sweeper.stop) })
}
