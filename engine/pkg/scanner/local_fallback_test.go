package scanner

// The binary refused these files and the report said so — and that was the whole
// answer. An operator who selected a folder got back a status word per file and a
// scan that had not checked them, with no way to tell from the report whether the
// templates were broken, the binary was, or the tool gave up.
//
// These tests hold the line that a refusal is not a verdict: every file the
// operator selected must end the run checked by somebody, and the report must say
// which of the two runners checked it.
//
// They run against a live `httptest` server rather than a mocked transport,
// because a mock would agree with a runner that accepts any answer, and the whole
// question here is whether the runner accepts an answer it should not.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The document the binary will not compile: `info.tags` carries the reserved
// token `fuzz`. Measured on nuclei v3.11.1, `-t`, `-t -dast` and `-t -fuzz` all
// answer `[FTL] Could not run nuclei: no templates provided for scan` with exit 1,
// while `nuclei -validate` accepts the same file.
const uncompiledFixture = `id: adminer-panel
info:
  name: Adminer Login Panel
  author: requestrider
  severity: info
  tags: fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "Adminer"
`

// A `flow:` document. The binary compiles many of these — the status is only
// reached when this run's batch produced no record — and the runner walks the
// expression itself, so the file is checked either way.
const flowFixture = `id: adminer-flow
info:
  name: Adminer flow
  author: requestrider
  severity: info
flow: http(1)
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "Adminer"
`

// localFallbackFixture is a target that serves the string the two documents above
// look for, so a correct runner scores them and an incorrect one is caught.
func localFallbackFixture() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>Adminer</title>"))
	}))
}

// stagedFallbackFile writes one document into a temporary staging directory and
// returns the staged file and the input set the fallback reads it back through.
func stagedFallbackFile(t *testing.T, content string) (StagedFile, []StagedFile) {
	t.Helper()
	root := t.TempDir()
	const relative = "panels/adminer-panel.yaml"
	staged := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(staged), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(staged, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	file := StagedFile{UploadName: filepath.Base(relative), RelativePath: relative, StagedPath: staged}
	return file, []StagedFile{file}
}

// A file the binary refused must end the run checked, not merely re-described.
func TestAFileTheBinaryRefusedIsScannedByThisProjectsRunner(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	file, inputs := stagedFallbackFile(t, uncompiledFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: file.UploadName, Path: file.RelativePath,
		Status: TemplateUncompiled,
		Reason: "the binary compiled no template out of this document",
	}}}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, nil)

	if performed != 1 {
		t.Fatalf("performed = %d, want 1: the file was refused and nobody checked it", performed)
	}
	row := run.Templates[0]
	if row.Status != TemplateMatched {
		t.Fatalf("status = %q, want %q: the target serves the string the template looks for, "+
			"and a runner that reports anything else is wrong about the answer", row.Status, TemplateMatched)
	}
	if row.PerformedBy != performedByLocalRunner {
		t.Errorf("performed_by = %q, want %q: the reader cannot tell whose verdict this is", row.PerformedBy, performedByLocalRunner)
	}
	if row.Matches != 1 {
		t.Errorf("matches = %d, want 1: the template matched and the row has to say so", row.Matches)
	}
	if len(row.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: a match without its evidence is not a finding", len(row.Findings))
	}
	// The evidence is the exchange this engine sent and scored. A match is
	// meaningless without the request that produced it.
	evidence, _ := row.Findings[0]["evidence"].(string)
	if !strings.Contains(evidence, "GET ") || !strings.Contains(evidence, "Adminer") {
		t.Errorf("the finding does not carry the exchange: %q", evidence)
	}
}

// The refusal is replaced by a verdict, so the reason that named the refusal must
// not survive on a row that was in fact checked: leaving it would read as "checked,
// and also not".
func TestACheckedRowCarriesNoLeftoverRefusal(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	file, inputs := stagedFallbackFile(t, flowFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: file.UploadName, Path: file.RelativePath,
		Status: TemplateFlow,
		Reason: "no record for this document in its batch",
	}}}
	applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, nil)

	row := run.Templates[0]
	if row.Status != TemplateMatched {
		t.Fatalf("status = %q, want %q", row.Status, TemplateMatched)
	}
	if row.Reason != "" {
		t.Errorf("a row the runner checked still carries a reason: %q", row.Reason)
	}
}

// An honest miss stays an honest miss. The fallback must not turn a file it ran
// and found nothing into a refusal, and must not invent a finding either.
func TestAFlowTheRunnerCheckedAndFoundNothingIsNotMatched(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>nothing here</title>"))
	}))
	defer target.Close()
	file, inputs := stagedFallbackFile(t, flowFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: file.UploadName, Path: file.RelativePath, Status: TemplateFlow,
	}}}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, nil)

	row := run.Templates[0]
	if performed != 1 {
		t.Fatalf("performed = %d, want 1: the file was checked, and that is what performed counts", performed)
	}
	if row.Status != TemplateNotMatched {
		t.Fatalf("status = %q, want %q: the check ran and came back clean", row.Status, TemplateNotMatched)
	}
	if len(row.Findings) != 0 {
		t.Errorf("findings = %d, want 0: a miss must not carry a finding", len(row.Findings))
	}
	if row.PerformedBy != performedByLocalRunner {
		t.Errorf("performed_by = %q, want %q", row.PerformedBy, performedByLocalRunner)
	}
}

// The runner has limits of its own. When it cannot perform the document either,
// the row keeps the binary's verdict and gains the runner's sentence: both say
// what was and was not checked, and neither is dropped to make the row shorter.
func TestADocumentNeitherRunnerCanPerformKeepsBothReasons(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	// A `code:` block runs a local command; the runner refuses it by name.
	file, inputs := stagedFallbackFile(t, `id: code-only
info:
  name: code only
  author: requestrider
  severity: info
  tags: fuzz
code:
  - engine:
      - sh
    source: |
      echo hi
`)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: file.UploadName, Path: file.RelativePath,
		Status: TemplateUncompiled,
		Reason: "the binary compiled no template out of this document",
	}}}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, nil)

	if performed != 0 {
		t.Fatalf("performed = %d, want 0: the runner could not perform it", performed)
	}
	row := run.Templates[0]
	if row.Status != TemplateUncompiled {
		t.Errorf("status = %q, want %q: nothing checked it, so the row must keep saying so", row.Status, TemplateUncompiled)
	}
	if !strings.Contains(row.Reason, "the binary compiled no template") {
		t.Errorf("the binary's reason was dropped: %q", row.Reason)
	}
	if !strings.Contains(row.Reason, "runner") {
		t.Errorf("the runner's reason was dropped: %q", row.Reason)
	}
	if row.PerformedBy != "" {
		t.Errorf("performed_by = %q, want empty: nothing performed this row", row.PerformedBy)
	}
}

// Without a transport the fallback does nothing, and says so, rather than sending
// the request through a bare client whose traffic the project cannot show.
func TestWithoutATransportTheRefusalsAreKeptAndNothingIsSent(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	file, inputs := stagedFallbackFile(t, uncompiledFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: file.UploadName, Path: file.RelativePath,
		Status: TemplateUncompiled,
		Reason: "the binary compiled no template out of this document",
	}}}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, nil, nil)

	if performed != 0 {
		t.Fatalf("performed = %d, want 0", performed)
	}
	row := run.Templates[0]
	if row.Status != TemplateUncompiled || row.PerformedBy != "" {
		t.Errorf("a nil transport must leave the row as the binary left it: %+v", row)
	}
}

// A document whose matcher the target does not satisfy, for the case where both
// runners look and neither finds. It must be a document this project's runner can
// actually perform, or the test below would pass for the wrong reason.
const quietFallbackFixture = `id: nothing-here
info:
  name: a document the target does not satisfy
  author: requestrider
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/nothing-this-page-has"
    matchers:
      - type: word
        words:
          - "A-Word-This-Page-Does-Not-Contain"
`

// The fallback must not touch a row the binary already decided. That verdict came
// from nuclei's own JSONL and is the one the operator's scan is about; overwriting
// it with a second runner's opinion would be a regression, not an improvement.
//
// `not_matched` and `no_request` are deliberately **absent** from this list, and its absence is the
// measured change rather than an oversight. Measured on 4000 corpus files, nuclei
// records 3 979 of them as `not_matched` with an empty reason, and 913 of those are
// files it never sent a request for: it resolves the document's variables, gives up
// on the placeholders, and writes down a negative. A `not_matched` about a file no
// request ever reached is not a verdict, so the row is open to correction — but only
// by something this project's runner established, which is the rule the next test
// pins down.
func TestAVerdictTheBinaryProducedIsNeverOverwritten(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	file, inputs := stagedFallbackFile(t, uncompiledFixture)

	for _, status := range []string{TemplateMatched, TemplateDuplicate, TemplateSkipped, TemplateInvalid, TemplateWorkflow} {
		original := TemplateResult{
			Name: file.UploadName, Path: file.RelativePath,
			Status: status, Matches: 3, Reason: "the binary's own reason",
		}
		run := &NucleiRun{Templates: []TemplateResult{original}}
		applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, nil)

		got := run.Templates[0]
		if got.Status != original.Status || got.Reason != original.Reason ||
			got.Matches != original.Matches || got.PerformedBy != "" {
			t.Errorf("status %q was rewritten: %+v", status, got)
		}
	}
}

// `not_matched` is corrected only by something: a named refusal becomes `skipped`
// with the reason spelled out, and a finding becomes `matched`. Where this project's
// runner also looks and finds nothing, the binary's row stands untouched — one real
// negative must not be replaced by another's and called a correction.
func TestABinaryNotMatchedIsOnlyRewrittenBySomethingEstablished(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()

	// 1. The runner performs the file and matches: the row becomes a finding, and
	//    the disagreement is counted, because a disagreement nobody can see is a
	//    disagreement the operator cannot check.
	matching, matchInputs := stagedFallbackFile(t, uncompiledFixture)
	run := &NucleiRun{Templates: []TemplateResult{{
		Name: matching.UploadName, Path: matching.RelativePath, Status: TemplateNotMatched,
	}}}
	stats := map[string]int{}
	applyLocalFallback(context.Background(), run, matchInputs, target.URL, http.DefaultTransport, stats)
	if run.Templates[0].Status != TemplateMatched {
		t.Fatalf("a not_matched row this runner matched was left as a negative: %+v", run.Templates[0])
	}
	if run.Templates[0].PerformedBy != performedByLocalRunner {
		t.Fatalf("the correction does not say who made it: %+v", run.Templates[0])
	}
	if stats[localRunnerFindingRewrite] != 1 {
		t.Fatalf("the disagreement was not counted: %v", stats)
	}

	// 2. The runner performs the file and finds nothing: the row is untouched, byte
	//    for byte, because the second runner agreed.
	quiet, quietInputs := stagedFallbackFile(t, quietFallbackFixture)
	original := TemplateResult{
		Name: quiet.UploadName, Path: quiet.RelativePath,
		Status: TemplateNotMatched, Reason: "the binary's own reason", Matches: 3,
	}
	run = &NucleiRun{Templates: []TemplateResult{original}}
	stats = map[string]int{}
	applyLocalFallback(context.Background(), run, quietInputs, target.URL, http.DefaultTransport, stats)
	got := run.Templates[0]
	if got.Status != original.Status || got.Reason != original.Reason ||
		got.Matches != original.Matches || got.PerformedBy != "" || len(got.Findings) != 0 {
		t.Fatalf("a not_matched row both runners agree about was rewritten: %+v", got)
	}
	if len(stats) != 0 {
		t.Fatalf("agreeing is not a correction, but it was counted: %v", stats)
	}
}

// A file the runner cannot perform becomes `skipped`, not a negative, and the row
// says the placeholders were never generated. The status word is the one the UI
// already spells «not run» / «пропущено», because the vocabulary is wired through the
// filter, the i18n dictionary, the export stylesheet and the statistics, and a word
// that exists in only some of those is a status the reader cannot see.
func TestANotMatchedRowThisRunnerCannotPerformBecomesSkipped(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	_, inputs := stagedFallbackFile(t, ungeneratedPlaceholderFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: inputs[0].UploadName, Path: inputs[0].RelativePath, Status: TemplateNotMatched,
	}}}
	stats := map[string]int{}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, stats)

	// Counted as performed: this project's runner is what the row now describes, and
	// the summary counts files by which engine worked on them.
	if performed != 1 {
		t.Fatalf("performed = %d, want 1: the row now describes this runner's work", performed)
	}
	got := run.Templates[0]
	if got.Status != TemplateSkipped {
		t.Fatalf("a file no request reached is still reported as a negative: %+v", got)
	}
	if got.PerformedBy != performedByLocalRunner {
		t.Fatalf("the row does not say which runner declined it: %+v", got)
	}
	if strings.TrimSpace(got.Reason) == "" {
		t.Fatal("the row says it was not run and does not say why")
	}
	if stats[localRunnerRefusalRewrite] != 1 {
		t.Fatalf("the refusal was not counted: %v", stats)
	}
}

// A document whose only URL is a placeholder nothing generates — the shape nuclei
// resolves, gives up on, and records as `not_matched`.
const ungeneratedPlaceholderFixture = `id: ungenerated-placeholder
info:
  name: a document whose URL was never generated
  author: requestrider
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{a_value_nothing_generates}}"
    matchers:
      - type: word
        words:
          - "Adminer"
`

// The report's summary counts come from the binary's view, so a run that added a
// thousand runner rows must publish that number or the summary understates the
// coverage the table shows.
func TestTheRunSaysHowManyFilesItsOwnRunnerPerformed(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	_, inputs := stagedFallbackFile(t, uncompiledFixture)

	run := &NucleiRun{
		Stats: map[string]interface{}{},
		Templates: []TemplateResult{{
			Name: inputs[0].UploadName, Path: inputs[0].RelativePath,
			Status: TemplateUncompiled, Reason: "the binary compiled no template out of this document",
		}},
	}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, nil)
	run.Stats["performed_locally"] = performed
	run.Stats["fallback_note"] = "note"

	if got := run.Stats["performed_locally"].(int); got != 1 {
		t.Errorf("performed_locally = %d, want 1", got)
	}
	if _, ok := run.Stats["fallback_note"].(string); !ok {
		t.Error("the run carries no sentence explaining the second runner")
	}
}

// silentNuclei installs a binary that behaves the way nuclei v3.11.1 behaves with
// a document whose `info.tags` carries the reserved token `fuzz`: it accepts the
// document at validation time and produces no record for it in the scan. That is
// the state the fallback exists for, and reproducing it with a stub keeps this
// test hermetic — the real binary never runs.
func silentNuclei(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-silent.sh")
	script := "#!/bin/sh\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$arg\" = '-validate' ]; then exit 0; fi\n" +
		"done\n" +
		// No record for any template: this is what a refused document looks like
		// from the report's side, and it is the only thing the fallback keys on.
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

// The wiring, not just the helper.
//
// Every unit test above calls `applyLocalFallback` directly, so all of them stay
// green if the call site in `RunNucleiPlan` is deleted — and that call site is the
// whole product claim: "every template runs". This test goes through the public
// entry point instead, so removing the call turns it red.
func TestAScanOfARefusedFileEndsWithAVerdictNotARefusal(t *testing.T) {
	silentNuclei(t)
	target := localFallbackFixture()
	defer target.Close()

	dir, staged, err := StageUploads([]UploadFile{{
		Name: "adminer-panel.yaml", Path: "panels/adminer-panel.yaml", Content: uncompiledFixture,
	}})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{
		URL: target.URL, Transport: http.DefaultTransport,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Templates) != 1 {
		t.Fatalf("templates = %d, want 1", len(run.Templates))
	}
	row := run.Templates[0]
	// The binary produced no record, so on its own this run would have reported a
	// refusal. The operator selected this file to scan it.
	if row.Status != TemplateMatched {
		t.Fatalf("status = %q, want %q: the file was selected to be scanned and the scan did not scan it",
			row.Status, TemplateMatched)
	}
	if row.PerformedBy != performedByLocalRunner {
		t.Errorf("performed_by = %q, want %q", row.PerformedBy, performedByLocalRunner)
	}
	// The summary has to describe the rows the table shows. If it still counted
	// only the binary's work, it would claim a folder was not checked while the
	// table beside it shows a match.
	performed, ok := run.Stats["performed_locally"].(int)
	if !ok || performed != 1 {
		t.Errorf("performed_locally = %#v, want 1: the summary has to describe the rows the operator reads", run.Stats["performed_locally"])
	}
	if _, ok := run.Stats["fallback_note"].(string); !ok {
		t.Error("the run carries no sentence explaining the second runner")
	}
	if len(run.Findings) != 1 {
		t.Errorf("findings = %d, want 1: the run-level findings have to carry the runner's match too", len(run.Findings))
	}
}

// A legacy/stale `no_request` row for a script our runner refuses must not keep
// claiming that this project performed the script. Normal target-facing JS now
// stays with nuclei's own verdict; the next test covers that path.
func TestLegacyNoRequestRowOurRunnerRefusesIsNotReportedAsRan(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	_, inputs := stagedFallbackFile(t, nucleiModuleFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: inputs[0].UploadName, Path: inputs[0].RelativePath,
		Status: TemplateNoRequest,
		Reason: "Ran without a target request: legacy JavaScript classification",
	}}}
	stats := map[string]int{}
	applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, stats)

	got := run.Templates[0]
	if got.Status == TemplateNoRequest {
		t.Fatalf("a document our runner refused is still reported as having run: %+v", got)
	}
	if got.Status != TemplateSkipped {
		t.Fatalf("status %q, want %q: a check that did not happen is not a request-less run", got.Status, TemplateSkipped)
	}
	if !strings.Contains(got.Reason, "nuclei/") {
		t.Fatalf("the row does not name what the script needs: %q", got.Reason)
	}
	if got.PerformedBy != performedByLocalRunner {
		t.Fatalf("the row does not say which runner declined it: %+v", got)
	}
	if strings.Contains(got.Reason, "Ran without a target request") {
		t.Fatalf("the binary's sentence survived a refusal and still claims the document ran: %q", got.Reason)
	}
	if stats[localRunnerRefusalRewrite] != 1 {
		t.Fatalf("the refusal was not counted: %v", stats)
	}
}

func TestTargetFacingJavaScriptNegativeKeepsNucleiVerdict(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	_, inputs := stagedFallbackFile(t, nucleiModuleFixture)
	meta, reason := parseTemplateDocument(nucleiModuleFixture)
	if reason != "" {
		t.Fatalf("parse network JavaScript fixture: %s", reason)
	}
	inputs[0].Meta = meta
	if !meta.AddressesTarget() {
		t.Fatal("the nuclei/ssh fixture must be classified as target-facing")
	}

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: inputs[0].UploadName, Path: inputs[0].RelativePath,
		Status: TemplateNotMatched,
	}}}
	stats := map[string]int{}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, stats)

	got := run.Templates[0]
	if performed != 0 {
		t.Fatalf("local fallback performed %d checks, want none after Nuclei's verdict", performed)
	}
	if got.Status != TemplateNotMatched || got.PerformedBy != "" {
		t.Fatalf("Nuclei's target-facing negative was rewritten: %+v", got)
	}
	if len(stats) != 0 {
		t.Fatalf("a skipped local fallback was counted as performed: %v", stats)
	}
}

// A local-only document that our runner performed and did not match stays
// `no_request`: it genuinely made no target request.
func TestANoRequestRowOurRunnerPerformedStaysNoRequest(t *testing.T) {
	target := localFallbackFixture()
	defer target.Close()
	_, inputs := stagedFallbackFile(t, quietFallbackFixture)

	run := &NucleiRun{Templates: []TemplateResult{{
		Name: inputs[0].UploadName, Path: inputs[0].RelativePath, Status: TemplateNoRequest,
		Reason: "Ran without a target request",
	}}}
	stats := map[string]int{}
	applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, stats)

	got := run.Templates[0]
	if got.Status != TemplateNoRequest {
		t.Fatalf("a document that really made no request lost that word: %+v", got)
	}
	if got.Matches != 0 || len(got.Findings) != 0 {
		t.Fatalf("a document that matched nothing reported a finding: %+v", got)
	}
	if len(stats) != 0 {
		t.Fatalf("agreeing is not a correction, but it was counted: %v", stats)
	}
}

// nucleiModuleFixture is the shape of the 138 documents this runner refuses: a
// `javascript:` block that needs a protocol library from nuclei's own runtime.
const nucleiModuleFixture = `id: ssh-enumeration
info:
  name: SSH Enumeration
  author: requestrider
  severity: info
javascript:
  - code: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      Export(c.ConnectSSHInfoMode(Host, Port));
    matchers:
      - type: word
        part: response
        words:
          - SSH-
`

// Браузер доводить, що Guard `transport == nil` не є «чесною відмовою», а мовчазною
// відмовою від власного бігуна.
//
// Виміряно у живому Firefox на 1356×652: `Run templates` дав 5 рядків, усі 5 із
// текстом «Template ran, no matches», і жоден не назвав модуль `nuclei/`. Причина —
// шлях, який браузер використовує для довгих сканів (`StartNucleiJob`), не передавав
// `Transport`, тож `applyLocalFallback` повертав 0 на першому рядку.
//
// Цей тест падає, якщо хтось прибере `Transport: fallbackTransport` із цього
// виклику: він перевіряє сам виклик у `main.go`, а не лише поведінку функції, якій
// передали транспорт.
func TestTheJobEntryPointCarriesTheRecordingTransport(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "corpus_jobs.go"))
	if err != nil {
		t.Fatalf("cannot read corpus_jobs.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "scanner.RunCorpus(")
	if start < 0 {
		t.Fatal("corpus_jobs.go no longer calls scanner.RunCorpus; this guard must be updated, not deleted")
	}
	end := strings.Index(text[start:], "})")
	if end < 0 {
		t.Fatal("cannot find the end of the RunCorpus request literal")
	}
	literal := text[start : start+end]
	if !strings.Contains(literal, "RoundTripper: transport") {
		t.Fatalf("the job entry point builds its request without a recording transport:\n%s\n"+
			"without it this project's runner performs nothing and the report keeps "+
			"claiming that a refused document ran", literal)
	}
}
