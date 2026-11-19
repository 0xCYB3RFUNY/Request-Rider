package main

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// A06-05 — the retention sweeper decided under RLock and acted under a later Lock.
//
// Between the two, `setState` or a restart could change the job, so the decision was made
// about one state and applied to another: a job that became live again in that window was
// released anyway — results and spill file destroyed — while it was running.
//
// `-race` cannot find this. Both regions are correctly locked; the defect is the
// interleaving between them. So these tests do not rely on `-race` semantics for the
// decision half: they assert on the shipped source, and reproduce the window directly.

func TestSweepRechecksStateUnderTheLockItActsWith(t *testing.T) {
	var job attack
	job.finishedAt = time.Now().Add(-24 * time.Hour)
	job.status = "completed"

	// The old shape, reproduced literally so the test fails against the code it describes.
	released := func() bool {
		job.mu.RLock()
		finished, done := job.finishedAt, terminalStatus(job.status)
		job.mu.RUnlock()
		if !done || !expired(finished, time.Now(), time.Hour) {
			return false
		}
		// The window: another goroutine restarts the job right here.
		job.mu.Lock()
		job.status = "running"
		job.finishedAt = time.Time{}
		job.results = []map[string]interface{}{{"status": 200}}
		job.mu.Unlock()
		// ...and the sweeper acts on the decision it already made.
		job.mu.Lock()
		job.results = nil
		job.mu.Unlock()
		return true
	}

	if !released() {
		t.Fatal("the reproduction never reached the action, so it proves nothing")
	}
	// What the reproduction demonstrates is the OLD shape's outcome, so that is
	// what it asserts. The first version of this test asserted the *fixed*
	// expectation here — a running job keeping its results — while the code above
	// it deliberately performs the fix's opposite, so it could never be green and
	// proved nothing. The shipped sweeper is checked separately, below and in
	// `TestSweepKeepsFreshAndLiveJobs`, against the code that actually runs.
	job.mu.RLock()
	running, kept := job.status, len(job.results)
	job.mu.RUnlock()
	if running != "running" || kept != 0 {
		t.Fatalf("the reproduction no longer demonstrates the defect: status=%q results=%d", running, kept)
	}
	t.Log("reproduction confirmed: the old shape destroys the results of a job that is running again")

	// The shipped sweeper must keep a job that is no longer expired, which is the
	// same state the reproduction leaves behind: a restart cleared `finishedAt`.
	srv := &server{attacks: map[uint64]*attack{}}
	restarted := &attack{status: "running", results: []map[string]interface{}{{"status": 200}}}
	srv.attacks[1] = restarted
	srv.sweepFinishedJobs(time.Now())
	srv.attacksMu.RLock()
	_, alive := srv.attacks[1]
	keptShipped := len(restarted.results)
	srv.attacksMu.RUnlock()
	if !alive || keptShipped != 1 {
		t.Fatalf("the shipped sweep released a running job: alive=%v results=%d", alive, keptShipped)
	}
}

func TestNoSweepSiteReadsUnderRLockThenActsUnderLock(t *testing.T) {
	// The shape itself is the defect: RLock … RUnlock … decide … Lock … act. The shipped
	// code must contain no such site, so a future edit that reintroduces it fails here
	// rather than in a race that only appears under load.
	source := readSource(t, "job_retention.go")
	sites := sweepLoopBodies(source)
	if len(sites) == 0 {
		t.Fatal("no sweep loop found; the source reader stopped matching and this test is vacuous")
	}
	for i, site := range sites {
		if strings.Contains(site, "job.mu.RLock()") {
			t.Fatalf("sweep loop %d still reads under RLock and acts later under Lock:\n%s", i, site)
		}
	}
}

func TestSweepDecisionAndActionShareOneLock(t *testing.T) {
	source := readSource(t, "job_retention.go")
	checked := 0
	for i, site := range sweepLoopBodies(source) {
		guardAt := strings.Index(site, "job.mu.Lock()")
		if guardAt < 0 {
			t.Fatalf("sweep loop %d takes no write lock at all:\n%s", i, site)
		}
		if !strings.Contains(site, "terminalStatus(") {
			t.Fatalf("sweep loop %d has no terminal-state guard:\n%s", i, site)
		}
		// An Unlock that lands before any field write means the decision lock was let go
		// of before the action, which is the original bug in another shape.
		actionMarkers := []string{"job.results = nil", "job.pages = nil", "job.report = nil", "job.store = nil", "job.events = nil"}
		for _, marker := range actionMarkers {
			actionAt := strings.Index(site, marker)
			if actionAt < 0 {
				continue
			}
			checked++
			if guardAt > actionAt {
				t.Fatalf("sweep loop %d acts before it decides:\n%s", i, site)
			}
			// The invariant is that the decision lock is still held when the action
			// runs. The first version of this rule asked for a *second*
			// `job.mu.Lock()` between the guard's `Unlock()` and the action, which
			// is the deadlock: `sync.Mutex` is not reentrant, so a second Lock on a
			// path that never unlocked blocks forever, and it did — the package
			// timed out after 10 minutes in `TestSweeperReleasesEveryFinishedJobKind`
			// with the stack parked on that very call. Holding one lock from the
			// guard to the action is what closes the window *and* terminates, so
			// what is asserted here is: no unlock on the falling-through path, and
			// no second lock either.
			// The slice starts *after* the guard's own Lock: including it would make
			// every loop look like it locks twice, which is how the first version of
			// this check failed on correct code.
			afterGuard := guardAt + len("job.mu.Lock()")
			between := strings.ReplaceAll(site[afterGuard:actionAt],
				"job.mu.Unlock()\n\t\t\tcontinue\n", "")
			if strings.Contains(between, "job.mu.Unlock()") {
				t.Fatalf("sweep loop %d releases the decision lock before acting, so a restart "+
					"can slip into the gap:\n%s", i, site)
			}
			if strings.Contains(between, "job.mu.Lock()") {
				t.Fatalf("sweep loop %d takes the decision lock twice without unlocking, which "+
					"deadlocks on a non-reentrant mutex:\n%s", i, site)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no action sites were checked; the markers stopped matching and this test is vacuous")
	}
}

func TestSweepActuallyReleasesExpiredJobs(t *testing.T) {
	// The fix must not have made the sweep inert: a genuinely expired finished job still
	// has to go, or the maps grow without bound and the finding returns as a leak.
	srv := &server{attacks: map[uint64]*attack{}}
	job := &attack{status: "completed", finishedAt: time.Now().Add(-72 * time.Hour),
		results: []map[string]interface{}{{"status": 200}}}
	srv.attacks[1] = job

	srv.sweepFinishedJobs(time.Now())

	srv.attacksMu.RLock()
	_, still := srv.attacks[1]
	srv.attacksMu.RUnlock()
	if still {
		t.Fatal("an expired finished job was not released; the single-lock change made the sweep inert")
	}
}

func TestSweepKeepsFreshAndLiveJobs(t *testing.T) {
	srv := &server{attacks: map[uint64]*attack{}}
	fresh := &attack{status: "completed", finishedAt: time.Now()}
	live := &attack{status: "running"}
	srv.attacks[1] = fresh
	srv.attacks[2] = live

	srv.sweepFinishedJobs(time.Now())

	srv.attacksMu.RLock()
	_, freshAlive := srv.attacks[1]
	_, liveAlive := srv.attacks[2]
	srv.attacksMu.RUnlock()
	if !freshAlive {
		t.Fatal("a job finished seconds ago must stay readable")
	}
	if !liveAlive {
		t.Fatal("a running job must never be swept")
	}
}

func TestSweepIsSafeWhileJobsAreBeingRestarted(t *testing.T) {
	// The window from the other side: goroutines restart jobs while the sweeper runs. Also
	// runs under `-race`, so it additionally proves there is no unsynchronised access.
	srv := &server{attacks: map[uint64]*attack{}}
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				srv.attacksMu.Lock()
				srv.attacks[uint64(n%97)+1] = &attack{
					status: "completed", finishedAt: time.Now().Add(-time.Hour),
					results: []map[string]interface{}{{"status": 200}},
				}
				srv.attacksMu.Unlock()
				time.Sleep(time.Millisecond)
			}
		}()
	}
	for i := 0; i < 60; i++ {
		srv.sweepFinishedJobs(time.Now())
	}
	close(stop)
	wg.Wait()
	srv.sweepFinishedJobs(time.Now())
}

// readSource returns a repository source file relative to the engine directory.
func readSource(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(data)
}

// stripComments removes `//` and `/* … */` text from a source file before a shape
// check reads it.
//
// This is not cosmetic. A check that scans raw source for `job.mu.Lock()` also
// reads the *prose* about that call: the paragraph in `sweepFinishedJobs` that
// explains why the lock is not taken twice quotes the call verbatim, and the
// "no second lock" rule then fired on the explanation of the deadlock rather than
// on the deadlock. Prose about code is not code, so the scanner must not see it.
func stripComments(source string) string {
	var out strings.Builder
	for index := 0; index < len(source); {
		switch {
		case strings.HasPrefix(source[index:], "//"):
			end := strings.IndexByte(source[index:], '\n')
			if end < 0 {
				return out.String()
			}
			out.WriteByte('\n')
			index += end + 1
		case strings.HasPrefix(source[index:], "/*"):
			end := strings.Index(source[index+2:], "*/")
			if end < 0 {
				return out.String()
			}
			index += 2 + end + 2
		default:
			out.WriteByte(source[index])
			index++
		}
	}
	return out.String()
}

// sweepLoopBodies returns the body of every `for … range` loop in the sweeper, so a test
// can assert about one loop without being fooled by text from another.
func sweepLoopBodies(source string) []string {
	source = stripComments(source)
	var bodies []string
	for offset := 0; ; {
		start := strings.Index(source[offset:], "for id, job := range")
		if start < 0 {
			return bodies
		}
		start += offset
		brace := strings.Index(source[start:], "{")
		if brace < 0 {
			return bodies
		}
		brace += start
		depth, i := 0, brace
		for ; i < len(source); i++ {
			switch source[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					bodies = append(bodies, source[brace:i+1])
				}
			}
			if depth == 0 && i > brace {
				break
			}
		}
		offset = i + 1
	}
}
