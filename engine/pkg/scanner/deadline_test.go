package scanner

import (
	"os"
	"strings"
	"testing"
)

// Зупинений на межі батч — це не «бінарник не запустився».
//
// Коли спрацьовує власний дедлайн цього проєкту, батьківський контекст ще
// живий, тому `ctx.Err()` порожній, а вбитий процес падає у `Error` як
// `signal: killed`. Рядок тоді каже «the binary could not be executed» — прямо
// протилежно тому, що сталося: бінарник запустився, відпрацював і був зупинений
// на межі, яку вибрав сам проєкт.
//
// Виміряно на v3.11.1 по корпусу з 98 636 файлів: 38 рядків несли саме цю фразу,
// і всі 38 — з `headless`-батчу, чий браузер на цій машині не завершується.

func stoppedBatch(deadlineSec int, browser bool) batchOutcome {
	outcome := batchOutcome{DeadlineSec: deadlineSec, DrivesBrowser: browser}
	if browser {
		outcome.Args = []string{"-headless"}
	}
	return outcome
}

// The sentence must not claim the binary failed to start, and it must name the
// bound: an operator who cannot see the number cannot act on it.
func TestAStoppedBatchNamesItsDeadlineAndNotAFailureToStart(t *testing.T) {
	batchFile := batchFileWithID("cookie-consent-detection")
	batch := NucleiBatch{Files: []BatchFile{batchFile}}
	reason := notRunReason(stoppedBatch(120, true), batch, batchFile, 0)

	if strings.Contains(reason, "could not be executed") {
		t.Fatalf("the batch was stopped on purpose, not failed to start: %q", reason)
	}
	if !strings.Contains(reason, "120-second") {
		t.Fatalf("the bound this project chose is not named: %q", reason)
	}
	// Both knobs must be offered, and by their real names, or the sentence is a
	// complaint rather than an instruction.
	for _, knob := range []string{"RR_NUCLEI_TIMEOUT_SEC", "RR_NUCLEI_ISOLATED_TIMEOUT_SEC"} {
		if !strings.Contains(reason, knob) {
			t.Fatalf("%s is not offered: %q", knob, reason)
		}
	}
}

// A browser batch gets the short bound because the browser is a *local*
// resource, so the sentence has to say which resource stopped answering. A
// plain batch stopped at the same bound has no such excuse and must not claim one.
func TestAStoppedBrowserBatchNamesTheLocalBrowser(t *testing.T) {
	batchFile := batchFileWithID("headless-one")
	batch := NucleiBatch{Files: []BatchFile{batchFile}}

	browser := notRunReason(stoppedBatch(120, true), batch, batchFile, 0)
	if !strings.Contains(browser, "local browser") {
		t.Fatalf("a browser batch does not say what stopped responding: %q", browser)
	}

	plain := notRunReason(stoppedBatch(3600, false), batch, batchFile, 0)
	if strings.Contains(plain, "local browser") {
		t.Fatalf("a non-browser batch borrowed the browser's excuse: %q", plain)
	}
	if !strings.Contains(plain, "3600-second") {
		t.Fatalf("the run's own bound is not named: %q", plain)
	}
}

// The results that did arrive stay in the report: the sentence says how many
// templates were executed before the bound, so a partial batch is legible rather
// than looking like nothing ran.
func TestAStoppedBatchSaysHowMuchItManaged(t *testing.T) {
	ran, missing := batchFileWithID("ran-fine"), batchFileWithID("never-got-there")
	batch := NucleiBatch{Files: []BatchFile{ran, missing, batchFileWithID("also-ran")}}

	reason := notRunReason(stoppedBatch(120, false), batch, missing, 2)
	if !strings.Contains(reason, "2 of the 3") {
		t.Fatalf("the count of what did run is missing: %q", reason)
	}
	if !strings.Contains(reason, "those results are reported") {
		t.Fatalf("the sentence does not say the earlier results survive: %q", reason)
	}
}

// A batch that never got a template out says 0 of N, and claiming results for it
// would be the same blur the deadline sentence exists to remove.
func TestAStoppedBatchThatRanNothingClaimsNoResults(t *testing.T) {
	batchFile := batchFileWithID("never-started")
	batch := NucleiBatch{Files: []BatchFile{batchFile}}

	reason := notRunReason(stoppedBatch(120, true), batch, batchFile, 0)
	if strings.Contains(reason, "those results are reported") {
		t.Fatalf("results are claimed for a batch that produced none: %q", reason)
	}
	if !strings.Contains(reason, "nothing in it was checked") {
		t.Fatalf("the sentence does not say so plainly: %q", reason)
	}
}

// A batch that finished has no deadline to report, so this branch must not fire
// on an ordinary run: a file the binary never mentioned there is a file the
// binary refused, and that is a different sentence.
func TestAFinishedBatchClaimsNoDeadline(t *testing.T) {
	batchFile := batchFileWithID("ordinary")
	batch := NucleiBatch{Files: []BatchFile{batchFile}}
	reason := notRunReason(batchOutcome{Args: []string{"-code"}}, batch, batchFile, 0)

	if strings.Contains(reason, "deadline") {
		t.Fatalf("a batch that was not stopped claims a deadline: %q", reason)
	}
	if !strings.Contains(reason, "returned no record for template id") {
		t.Fatalf("expected the refusal sentence instead: %q", reason)
	}
}

// The tests above build `batchOutcome` by hand, so they prove what the sentence
// says but not that anything ever *sets* the deadline. This one runs the real
// path: a binary that never returns, stopped by this project's own bound.
//
// Without it the branch is dead code that reads correctly — exactly the kind of
// green that survives a revert. Measured here: reverting
// `outcome.DeadlineSec = batchDeadlineSec` leaves all four hand-built tests
// green, because none of them executes `executeBatch`.
func TestTheDeadlineIsRecordedByTheCodeThatActuallyStopsTheBinary(t *testing.T) {
	dir := t.TempDir()
	// A stand-in for the binary that accepts every flag and never returns. The
	// flags are irrelevant here: what is under test is who stops it and how the
	// outcome says so.
	stub := dir + "/nuclei"
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nsleep 300\n"), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	// One second is long enough for the process to start and far shorter than the
	// 300 s the stub would otherwise sit there.
	t.Setenv("RR_NUCLEI_ISOLATED_TIMEOUT_SEC", "1")

	batchFile := batchFileWithID("never-returns")
	batch := NucleiBatch{
		Index:                     1,
		Dir:                       dir,
		Key:                       capabilityKeyOf([]Capability{isolatedCapability}),
		Files:                     []BatchFile{batchFile},
		MaxTemplateIDMultiplicity: 1,
	}

	outcome, err := executeBatch(t.Context(), batch, "http://127.0.0.1:1/", NucleiRequest{})
	if err != nil {
		t.Fatalf("a stopped batch is not an error of its own: %v", err)
	}
	if outcome.DeadlineSec != 1 {
		t.Fatalf("DeadlineSec = %d, want 1: the bound that stopped the binary is unrecorded", outcome.DeadlineSec)
	}
	if outcome.Error != nil {
		t.Fatalf("a deliberate stop is recorded as a process failure: %v", outcome.Error)
	}

	reason := notRunReason(outcome, batch, batchFile, 0)
	if strings.Contains(reason, "could not be executed") {
		t.Fatalf("the binary did run and was stopped; the row says otherwise: %q", reason)
	}
	if !strings.Contains(reason, "1-second") {
		t.Fatalf("the bound is not named: %q", reason)
	}
}
