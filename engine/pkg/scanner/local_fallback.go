package scanner

// The binary is not the only runner in this project, and a refusal by one runner
// is not the end of a check.
//
// Measured against nuclei v3.11.1 on the official corpus, two document shapes
// come back from a scan with no verdict: a document carrying `info.tags` with
// the reserved token `fuzz` — 37 of 14 072 files — is refused under `-t`,
// `-t -dast` and `-t -fuzz` alike, each answering `[FTL] Could not run nuclei:
// no templates provided for scan` with exit 1, while `nuclei -validate` accepts
// the same file; and a `flow:` document whose expression this binary did not
// compile in this batch produces no record. Both are reported today as a status
// word and nothing else.
//
// That is the whole answer for those files, and it is not a scan. A collection
// scan whose result is "N files were not checked" has not checked N files, and
// the operator cannot tell from the report whether the templates are broken,
// the binary is, or the tool gave up.
//
// This project already has the second runner. `RunTemplateLocally` sends the
// document's own request through the recording transport and scores the answer
// with nuclei's own operators; `runFlow` walks a flow's expression step by step.
// It is reachable over HTTP and the UI never called it, so the capability existed
// and was unused. This file wires it into the scan, so every file the operator
// selected ends the run with a verdict: the binary's when the binary has one,
// the runner's when it does not, and a named limit when neither can.
//
// The design lives here, in `pkg/scanner`, rather than in the server layer,
// because all three entry points funnel through `RunNucleiPlan` — the synchronous
// handler, the chunked upload job the UI actually uses, and `cmd/corpuslive` —
// and putting it there is what makes "every template runs" true of the product
// rather than of one route.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// localFallbackStatuses are the per-file outcomes the binary produced that this
// project's own runner can still perform.
//
// `uncompiled` is a refusal of the binary, not a verdict about the template:
// nothing in the document was checked. `flow` is the same in the case that
// matters here — the document declares an expression and this run's batch
// produced no record for it.
//
// `skipped` is deliberately absent. It also covers a batch that was interrupted,
// a capability the binary rejected and a file that arrived without a staged copy.
// Re-running any of those through this path would replace a true statement with a
// misleading one: a fresh request for a file the operator's batch never reached
// would report a check that did not happen in the run they are reading.
//
// `workflow` is absent for a different reason: a workflow is not a matcher, its
// requests are on the wire, and its findings belong to its subtemplates, which are
// reported under their own ids. There is nothing here for a second runner to add.
//
// `not_matched` is here for the reason measured below, and it is treated more
// carefully than the two above: this project's runner must have something to add
// before the binary's row is touched. See `applyLocalFallback`.
var localFallbackStatuses = map[string]bool{
	TemplateUncompiled: true,
	TemplateFlow:       true,
	TemplateNotMatched: true,
	// `no_request` stays here for local-only JavaScript: this runner has to
	// distinguish a script it can perform from a local protocol module it refuses.
	// Target-facing JavaScript is classified as `not_matched` and bypasses this
	// fallback below, because nuclei itself already executed that protocol.
	TemplateNoRequest: true,
}

// Measured on a 4000-file sample of the official corpus, one target, both runners:
//
//	nuclei → our runner          rows
//	not_matched → not_matched   3064
//	not_matched → refused        913
//	not_matched → matched          1
//
// The binary reports 3 979 of 4 000 files as `not_matched` with an **empty reason**,
// and 913 of those are files it never actually sent a request for — it resolves the
// document's variables, gives up on the placeholders, and writes the result as a
// negative. A report that says `not_matched` about a file no request ever reached is
// a statement the tool cannot back, and the operator cannot tell it from a template
// that was executed and did not match.
//
// So this runner performs those rows too, and the row is rewritten **only** when it
// has something to add: a named refusal (`skipped` with the reason spelled out) or a
// finding the binary missed. Where this project's runner also finds nothing, the
// binary's row is left exactly as it was — one real negative must not be replaced by
// another runner's real negative and called a correction.
const (
	// localRunnerRefusesToOverwrite reports how many rows this project's runner
	// rewrote from the binary's `not_matched` into a named refusal, and how many
	// into a finding. Both are corrections of a statement the binary could not
	// back; neither is a second opinion on a negative that both runners agree on.
	localRunnerRefusalRewrite = "refusals named"
	localRunnerFindingRewrite = "findings the binary missed"
)

// performedByLocalRunner names the path that produced a row, in the report's own
// vocabulary. It is a distinct word from `nuclei` because the two verdicts rest
// on different evidence: a binary row carries nuclei's own JSONL, a runner row
// carries the exchange this engine sent and scored itself. A report that mixed
// them without saying so could not be told apart from a run where one engine did
// everything.
const performedByLocalRunner = "requestrider"

// localFallbackWorkers is how many rows this project's own runner performs at
// once.
//
// It exists because this pass used to be a plain loop over the rows, and one
// row's cost is a full request — plus, for the 596 corpus documents that carry
// `interactsh-url`, a ten-second callback wait on top of it. Serial, those waits
// stack one after another. Measured on `http/exposures` (704 files) against a
// local target on 2026-10-07: nuclei itself reached 100 % in 31 s, and this pass
// then took a further 164 s to perform 25 rows, so the scan through the browser
// cost 195.8 s against 32.9 s for the very same folder and binary in a terminal
// — six times the work for the same verdicts.
//
// The bound is the concurrency the binary runs its own templates with. It is a
// transport detail and not a cap on what may be scanned: every row that the
// serial pass would have touched is still touched, still scored, and still
// reported, and the pass publishes its width so the operator can see it.
const localFallbackWorkers = 25

// fallbackCounters is what one row's performance added to the run statistics.
//
// The counters are collected here and folded in by the caller, in row order, so
// the published numbers do not depend on which worker happened to finish first.
type fallbackCounters struct {
	refusals  int
	findings  int
	performed int
}

// applyLocalFallback re-runs the rows the binary could not perform and returns the
// rows with their real outcome.
//
// It returns the number of rows it performed, which the caller publishes in the
// run statistics, because the counters in `runStatistics` are computed from the
// binary's view alone and would otherwise understate the coverage the report
// actually shows.
//
// The rows are performed by a bounded pool and applied afterwards in upload
// order. Both halves matter: the pool is what removes the stacked per-row waits,
// and applying afterwards is what keeps the report, and the counters that go with
// it, identical to what the serial pass produced.
func applyLocalFallback(
	ctx context.Context,
	run *NucleiRun,
	inputs []StagedFile,
	target string,
	transport http.RoundTripper,
	stats map[string]int,
) int {
	if transport == nil {
		// `RunTemplateLocally` refuses a nil transport on purpose: a scan that
		// runs outside the recording path produces evidence the project cannot
		// show. So a caller that passes none keeps the binary's verdicts and the
		// refusals, and the statistics say the runner was not available.
		return 0
	}
	byPath := make(map[string]StagedFile, len(inputs))
	for _, file := range inputs {
		byPath[stagedKey(file.RelativePath)] = file
	}
	pending := make([]int, 0, len(run.Templates))
	for index := range run.Templates {
		if localFallbackStatuses[run.Templates[index].Status] {
			pending = append(pending, index)
		}
	}
	if len(pending) == 0 {
		return 0
	}
	rows := make([]TemplateResult, len(pending))
	counters := make([]fallbackCounters, len(pending))
	workers := localFallbackWorkers
	if workers > len(pending) {
		workers = len(pending)
	}
	var next int64
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for {
				position := int(atomic.AddInt64(&next, 1)) - 1
				if position >= len(pending) {
					return
				}
				index := pending[position]
				rows[position], counters[position] = performLocalFallbackRow(
					ctx, run.Templates[index], byPath, target, transport)
			}
		}()
	}
	group.Wait()
	performed := 0
	for position, index := range pending {
		run.Templates[index] = rows[position]
		performed += counters[position].performed
		// A counter that did not move is not written at all: the map the caller
		// publishes has to read the same as it did when this pass was serial,
		// where a key appeared only once something had been counted into it.
		// Writing a zero would make "nothing was corrected here" look like a key
		// that had been.
		if stats != nil {
			if counters[position].refusals > 0 {
				stats[localRunnerRefusalRewrite] += counters[position].refusals
			}
			if counters[position].findings > 0 {
				stats[localRunnerFindingRewrite] += counters[position].findings
			}
		}
	}
	return performed
}

// performLocalFallbackRow runs one row's second opinion and returns the row it
// produced together with what that added to the statistics.
//
// It works on a **copy** of the row and never touches the run: the caller applies
// the result after the pool has joined, which is what keeps a concurrent pass
// from writing into the report the browser is streaming.
func performLocalFallbackRow(
	ctx context.Context,
	row TemplateResult,
	byPath map[string]StagedFile,
	target string,
	transport http.RoundTripper,
) (TemplateResult, fallbackCounters) {
	var count fallbackCounters
	file, ok := byPath[stagedKey(row.Path)]
	if !ok || strings.TrimSpace(file.StagedPath) == "" {
		file, ok = stagedFileForBatchPath(byPath, &row)
	}
	if !ok {
		// The row could not be tied back to a staged document. The binary's word
		// is «ran, but checked no URL», and this project's runner has **not** run
		// it, so the row must stop claiming a run. Leaving it untouched is what
		// made a browser scan print «ran» for a check that never happened:
		// measured in a live Firefox at 1356x652 and 1920x1080 — 5 of 5 rows.
		//
		// `skipped` renders as «Not run» / «Не запускався», which is the truth,
		// and the reason names the one thing the operator needs: which file the row
		// is, and that this project's runner did not perform it.
		row.Status = TemplateSkipped
		row.Matches = 0
		row.Findings = nil
		row.PerformedBy = performedByLocalRunner
		row.Reason = joinReasons(row.Reason, fmt.Sprintf(
			"this project's runner did not run this document: its row carries path %q, "+
				"which is not among the %d files staged for this run, so there is nothing "+
				"here to perform", oneLine(row.Path), len(byPath)))
		count.refusals++
		count.performed++
		return row, count
	}
	targetFacingJavaScript := false
	if row.Status == TemplateNotMatched && file.Meta != nil {
		for _, key := range file.Meta.BlockKeys {
			if key == "javascript" && file.Meta.javascriptAddressesTarget() {
				targetFacingJavaScript = true
				break
			}
		}
	}
	if targetFacingJavaScript {
		// Nuclei has already executed this target-facing script. Our local
		// runner does not implement its protocol module, so a second attempt
		// here would turn Nuclei's real negative into a false "not run" result.
		return row, count
	}
	staged := file.StagedPath
	if !stagedFileExists(staged) {
		// A planned run loads templates from per-batch subdirectories, so the path
		// a row carries is `<staging>/<batch>/<file>` while the map is keyed by the
		// upload-relative path. Without this second attempt the lookup missed for
		// **every** row of a planned run — which is every browser scan — and the
		// fallback silently corrected nothing. Measured in a live Firefox at
		// 1356x652: 5 of 5 rows kept the binary's «Template ran, no matches».
		staged = filepath.Join(file.StagedPath, filepath.Base(row.Path))
	}
	content, err := os.ReadFile(staged)
	if err != nil {
		row.Reason = joinReasons(row.Reason,
			fmt.Sprintf("this project's runner could not read the staged document: %s", oneLine(err.Error())))
		return row, count
	}
	local := RunTemplateLocally(ctx, string(content), target, transport)
	// A binary `not_matched` is only corrected by something. This project's
	// runner agreeing that nothing matched is not a correction, and replacing
	// one real negative with another's would dress a second opinion up as a
	// repair.
	onlyCorrects := local.Matched || strings.TrimSpace(local.Reason) != ""
	// A row this runner has nothing new to say about is left exactly as the
	// binary wrote it. That holds for `not_matched` (a negative both runners
	// agree on) and for `no_request` (a document that made no target request and
	// found nothing) alike: rewriting either with a second runner's own
	// negative would dress an agreement up as a correction.
	if (row.Status == TemplateNotMatched || row.Status == TemplateNoRequest) && !onlyCorrects {
		return row, count
	}
	// `no_request` says the document ran without addressing the target. Whether
	// that is true is now
	// this runner's answer to give, because it is the one that performs the
	// document — and a refusal here is the difference between a check that was
	// made and a check that was declined.
	if row.Status == TemplateNoRequest && strings.TrimSpace(local.Reason) != "" {
		row.Status = TemplateSkipped
		row.Matches = 0
		row.Findings = nil
		row.PerformedBy = performedByLocalRunner
		row.Reason = local.Reason
		count.refusals++
		count.performed++
		return row, count
	}
	if local.Reason != "" {
		// The runner has limits of its own, and its sentence is the answer.
		// The binary's refusal stays in the row so nothing is lost.
		//
		// For a binary `not_matched` the row becomes `skipped` rather than
		// keeping a negative the check never produced: the UI's word for
		// `skipped` is «not run» / «пропущено», which is exactly what happened,
		// and the reason says it was this project's runner that did not run it.
		// No new status word was introduced, because the vocabulary is wired
		// through the UI filter, the i18n dictionary, the export stylesheet and
		// the run statistics, and a report word that exists in four of those
		// five places is a status the reader cannot see.
		if row.Status == TemplateNotMatched {
			row.Status = TemplateSkipped
			row.Matches = 0
			row.Findings = nil
			row.PerformedBy = performedByLocalRunner
			// The row now says `not run`, and a row that says it without saying
			// why leaves the operator to guess whether the template is broken,
			// the engine is, or the placeholders never existed. The runner's own
			// sentence is the answer, and it replaces the empty reason the
			// binary left — there was nothing else in the row.
			row.Reason = local.Reason
			count.refusals++
			count.performed++
			return row, count
		}
		row.Reason = joinReasons(row.Reason, local.Reason)
		return row, count
	}
	if ctx.Err() != nil {
		// A cancelled route must not turn into a verdict about a template.
		row.Reason = joinReasons(row.Reason, "the run was cancelled before this runner reached the file")
		return row, count
	}
	row.Status = TemplateNotMatched
	row.Matches = 0
	row.Findings = nil
	if local.Matched {
		// A finding the binary did not report, on a file it recorded as a
		// negative. Counted apart from `performed`, because this is the one
		// case where the two runners disagree about the outcome.
		count.findings++
		row.Status = TemplateMatched
		// One verdict per document is what the runner returns, so one is the
		// honest count. It is not `len(MatcherNames)`: nuclei's matcher map is
		// keyed by matcher *name*, and a `word:` matcher that carries no `name:`
		// fires under no key at all, so a count taken from it reads 0 on a
		// template that did match.
		row.Matches = 1
		row.Findings = localFindings(local)
	}
	row.Reason = ""
	row.PerformedBy = performedByLocalRunner
	count.performed++
	return row, count
}

// stagedKey is the one spelling of a staged file's path both sides of the fallback
// use. `StageUploads` writes slash form from the browser and the rows carry the
// same string, so a mismatch here would silently skip files rather than fail.
func stagedKey(path string) string {
	return filepath.ToSlash(strings.TrimSpace(path))
}

// joinReasons keeps both sentences instead of replacing one with the other. The
// binary's refusal says what the binary did; the runner's says what this project
// did; an operator reading the row needs both to know what was and was not
// checked.
func joinReasons(first, second string) string {
	first = strings.TrimSpace(first)
	second = strings.TrimSpace(second)
	switch {
	case first == "":
		return second
	case second == "":
		return first
	}
	if strings.Contains(first, second) {
		return first
	}
	return first + " — and this project's runner: " + second
}

// localFindings turns a runner verdict into the same finding shape the binary path
// produces, because the report, the export and the SSE stream all read one shape.
//
// The evidence is the exchange this engine sent and scored itself, so it is
// present in full: a match is meaningless without the request that produced it.
// `matched_at` is empty rather than guessed, because this runner has no
// `matched-at` field — nuclei records the URL whose response fired the match, and
// here the answer is the exchange in the same row.
func localFindings(run LocalRun) []map[string]interface{} {
	if !run.Matched {
		return nil
	}
	requestLine := run.Request
	if index := strings.Index(requestLine, "\n\n"); index > 0 {
		requestLine = requestLine[:index]
	}
	title := strings.TrimSpace(run.Name)
	if run.TemplateID != "" {
		title = fmt.Sprintf("[%s] %s", run.TemplateID, title)
	}
	finding := map[string]interface{}{
		"severity":     strings.ToLower(strings.TrimSpace(run.Severity)),
		"title":        title,
		"evidence":     run.Request + "\n" + run.Response,
		"template_id":  run.TemplateID,
		"matcher_name": strings.Join(run.MatcherNames, ", "),
		"type":         "requestrider",
		"engine":       performedByLocalRunner,
	}
	if run.StatusCode > 0 {
		finding["status_code"] = run.StatusCode
	}
	if len(run.Extracts) > 0 {
		finding["extracted"] = run.Extracts
	}
	if strings.TrimSpace(requestLine) != "" {
		finding["request_line"] = requestLine
	}
	return []map[string]interface{}{finding}
}

// stagedFileForBatchPath finds the staged file a row's batch path belongs to.
//
// The batch directory is per template-id (the binary loads one file per id, and a
// second file with the same id is never executed), so the batch path always ends in
// the file's own name. Matching on that name **and** on the staging directory it
// lives in is what keeps two files with the same basename in different folders
// separate — the case the upload contract explicitly preserves.
func stagedFileForBatchPath(byPath map[string]StagedFile, row *TemplateResult) (StagedFile, bool) {
	if strings.TrimSpace(row.Path) == "" {
		return StagedFile{}, false
	}
	base := filepath.Base(row.Path)
	for _, file := range byPath {
		if filepath.Base(file.RelativePath) != base {
			continue
		}
		if stagedFileExists(filepath.Join(file.StagedPath, base)) {
			return file, true
		}
	}
	return StagedFile{}, false
}

// stagedFileExists reports whether a staged path is a readable file.
func stagedFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}
