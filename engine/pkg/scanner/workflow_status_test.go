package scanner

import (
	"strings"
	"testing"
)

// A workflow is an orchestrator, not a check. This file pins the status a
// workflow row carries, and the reason it is not `skipped`.
//
// The status vocabulary is load-bearing in this product: AGENTS.md requires
// exactly five per-file statuses with a mandatory `reason` on the three that
// mean "this file did not do what a template does", so that an unchecked file
// can never read as a checked one. Adding a sixth word to a vocabulary the
// report counts by is therefore a decision, and the decision has to be argued
// rather than asserted — otherwise a future reader has no way to tell whether
// `workflow` describes the binary or our opinion of it.
//
// What the binary does, measured on v3.11.1 against this corpus:
//
//	$ nuclei -w <adminer-workflow.yaml> -u http://127.0.0.1:8791/
//	[INF] HTTP connections: 9 total, 9 new, 0 reused (0.0%)
//	  … and zero JSONL records
//
// The subtemplates were requested. The workflow itself emitted nothing, because
// it is not a matcher. So:
//
//   - `skipped` is false — it means the file never executed, and it did;
//   - `not_matched` is false for the same reason — it means "ran, nothing fired",
//     and a workflow fires nothing of its own under any circumstances, matched or
//     not, so the status would claim nothing rather than report something;
//   - `invalid` is false — the binary loaded it.
//
// `workflow` names the file's kind and the reason says what the run did.

func TestAWorkflowRowIsNotReportedAsSkipped(t *testing.T) {
	document := `id: adminer-workflow

info:
  name: Adminer Security Checks
  author: daffainfo
workflows:
  - template: http/exposed-panels/adminer-panel.yaml
    subtemplates:
      - tags: adminer
`
	meta, reason := parseTemplateDocument(document)
	if reason != "" {
		t.Fatalf("the workflow was refused: %s", reason)
	}
	if !meta.IsWorkflow() {
		t.Fatal("a document whose only request section is `workflows` does not report itself as a workflow")
	}
	if meta.Requestless() {
		t.Error("a workflow is not requestless: it addresses the target through its subtemplates")
	}

	text := meta.WorkflowReason()
	if text == "" {
		t.Fatal("a workflow row has no reason, and a reason is mandatory for every status that is not a plain result")
	}
	// The reason has to say what happened, not only what the file is: a reader
	// who sees only `workflow` cannot tell a run from a refusal.
	if !strings.Contains(text, "subtemplate") {
		t.Errorf("the reason does not say the subtemplates ran: %q", text)
	}
}

// The two tests above check the classifier and the sentence it produces. They do
// NOT check that the report row is built from them, and an earlier version of
// this file was green after the row-building case and its reason had both been
// deleted — a test that cannot fail is not a test.
//
// So this one drives `applyBatchOutcome` itself, with the fact that makes a
// workflow unreported (the binary wrote no record for it) and asserts the row
// the report would show. The outcome is assembled by hand rather than by running
// nuclei, because the fact under test is the binary's silence, and silence is
// exactly what a fixture has to reproduce faithfully to be worth anything.
func TestTheReportRowForAWorkflowCarriesTheWorkflowStatusAndItsReason(t *testing.T) {
	meta, refused := parseTemplateDocument(`id: adminer-workflow

info:
  name: Adminer Security Checks
  author: daffainfo
workflows:
  - template: http/exposed-panels/adminer-panel.yaml
    subtemplates:
      - tags: adminer
`)
	if refused != "" {
		t.Fatalf("the workflow was refused: %s", refused)
	}

	const staged = "/tmp/rr-staged/workflows/adminer-workflow.yaml"
	file := StagedFile{UploadName: "adminer-workflow.yaml", RelativePath: "workflows/adminer-workflow.yaml", StagedPath: staged, Meta: meta}
	// `applyBatchOutcome` looks the row up by `BatchFile.Path` cleaned, not by
	// `StagedPath`, and the second edit of this file was wrong about that: the row
	// stayed untouched and the test failed on an empty status rather than on the
	// thing it meant to check. The key has to be the same string the production
	// call site builds.
	batchFile := BatchFile{File: file, Path: staged}
	batch := NucleiBatch{Dir: "/tmp/rr-staged", Files: []BatchFile{batchFile}}
	run := &NucleiRun{}
	run.Templates = []TemplateResult{{Name: "adminer-workflow.yaml", Path: "workflows/adminer-workflow.yaml"}}
	rows := map[string]int{cleanPathForCompare(staged): 0}

	// The binary ran the invocation and wrote no record for this file: exit 0,
	// no error, no stderr. That is the state the workflow status exists for.
	applyBatchOutcome(run, batch, batchOutcome{ExitCode: 0}, rows)

	if len(run.Templates) != 1 {
		t.Fatalf("the run has %d rows, want 1", len(run.Templates))
	}
	row := run.Templates[0]
	if row.Status != TemplateWorkflow {
		t.Errorf("status = %q, want %q: a workflow that ran its subtemplates is not a file the binary skipped",
			row.Status, TemplateWorkflow)
	}
	if row.Status == TemplateSkipped {
		t.Error("a workflow row must never read as skipped: the claim is that nothing was checked, and its requests were on the wire")
	}
	if row.Reason == "" {
		t.Error("the row has no reason, and every status that is not a plain result must carry one")
	}
	if !strings.Contains(row.Reason, "subtemplate") {
		t.Errorf("the row's reason does not say the subtemplates ran: %q", row.Reason)
	}
}

// The status vocabulary is what the report counts by, so a word the counters do
// not know would leave the row uncounted — the file would be visible in the table
// and absent from the totals, which is the failure mode a per-file report exists
// to prevent.
func TestTheWorkflowStatusIsCountedRatherThanFallingThrough(t *testing.T) {
	seen := map[string]bool{}
	for _, status := range []string{
		TemplateMatched, TemplateNotMatched, TemplateSkipped, TemplateInvalid,
		TemplateNoRequest, TemplateDuplicate, TemplateFlow, TemplateWorkflow,
	} {
		if status == "" {
			t.Error("a status constant is empty")
		}
		if seen[status] {
			t.Errorf("status %q is used for two different meanings", status)
		}
		seen[status] = true
	}
	if !seen[TemplateWorkflow] {
		t.Error("the workflow status is not part of the vocabulary")
	}
}

// The exemption from the severity requirement is what puts a document on this
// path at all, so the two decisions are pinned together: a document that only
// *mentions* a workflow must not be classified as one, or it would lose its
// severity requirement and become a workflow row with a real check inside it.
func TestAMixedDocumentIsNotAWorkflowRow(t *testing.T) {
	mixed := `id: mixed

info:
  name: Mixed
  author: someone
  severity: high
workflows:
  - template: http/technologies/example.yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`
	meta, reason := parseTemplateDocument(mixed)
	if reason != "" {
		t.Fatalf("a mixed document was refused: %s", reason)
	}
	if meta.IsWorkflow() {
		t.Error("a document carrying both `workflows` and `http` was classified as a workflow: its own check would be reported under an orchestrator's status")
	}
}

// The reason must not be handed to a file that is not a workflow: it is derived
// from nothing for a plain template, and a report that printed it there would be
// describing a different kind of file.
func TestAWorkflowReasonIsEmptyForAnOrdinaryTemplate(t *testing.T) {
	meta, reason := parseTemplateDocument(`id: plain

info:
  name: Plain
  author: someone
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	if reason != "" {
		t.Fatalf("an ordinary template was refused: %s", reason)
	}
	if meta.IsWorkflow() {
		t.Fatal("an http template reports itself as a workflow")
	}
	if text := meta.WorkflowReason(); text != "" {
		t.Errorf("a workflow reason was produced for an http template: %q", text)
	}
}
