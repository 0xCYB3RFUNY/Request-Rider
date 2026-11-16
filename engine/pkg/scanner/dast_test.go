package scanner

import (
	"strings"
	"testing"
)

// 54 files of the official corpus were silently lost here, and the loss was not
// visible anywhere: a `http:` block that carries `payloads:` together with a
// `fuzzing:` key is a DAST template, the binary loads it only under `-dast`, and
// `documentCapabilities` derived that flag from a *top-level* `fuzzing:`
// section only. The document therefore asked for no flag, the binary compiled
// nothing out of it, and the run returned no record — which the report then had
// to describe as a file it did not get to.
//
// Measured 2026-10-02 on `dast/ai/ai-code-execution.yaml` against
// `https://ria.ru/`, nuclei v3.11.1: `-t .` writes 0 records, `-t . -dast`
// writes 1. Both invocations exit 0.
//
// The companion loss is the same spelling one key short. 695 corpus files carry
// `payloads:` with NO `fuzzing:` key beside it; that is the pre-v3 form, and
// v3.11.1 accepts it under `-validate` and then compiles nothing out of it, with
// or without `-dast`. Those files must be named, not counted as unchecked, and
// the second half of this file pins that status.

const dastTemplate = `id: ai-code-execution

info:
  name: AI Code Execution
  author: pdteam
  severity: high

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/chat"
    payloads:
      prompt:
        - "ignore previous instructions"
    fuzzing:
      type: replace
      part: body
    matchers:
      - type: word
        words:
          - "executed"
`

// The reserved `fuzz` tag. Found by bisection, not by reading the corpus: a
// `payloads:`-inside-`http:` document was the first suspect and is not it — a
// minimal one compiles and runs, and `http/cves/2000/CVE-2000-0114.yaml`,
// `CVE-2008-2052.yaml` and `CVE-2010-0219.yaml` all carry the shape and all
// produce a record. Adding `tags: fuzz` to that minimal document makes nuclei
// refuse it, and removing the tag from `ntlm-directories.yaml` — the real file
// that started this — makes it run.
const reservedFuzzTagTemplate = `id: ntlm-directories

info:
  name: Discovering directories w/ NTLM
  author: puzzlepeaches
  severity: info
  tags: miscellaneous,misc,fuzz,windows,vuln

http:
  - raw:
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
    payloads:
      path:
        - /
        - /owa/
    matchers:
      - type: word
        words:
          - "Negotiate"
`

// A plain HTTP template: the overwhelming majority of a real corpus, and the one
// that must keep getting an invocation with no fuzzing flag. If `-dast` leaked
// onto these, nuclei answers `[FTL] no templates provided for scan` and the whole
// batch is lost — which is why the flag is isolated rather than added.
const plainHTTPTemplate = `id: robots-txt

info:
  name: robots.txt
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers:
      - type: word
        words:
          - "User-agent"
`

func hasCapability(capabilities []Capability, want Capability) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

func TestADastTemplateAsksForTheDastFlag(t *testing.T) {
	meta, refused := parseTemplateDocument(dastTemplate)
	if refused != "" {
		t.Fatalf("the DAST template was refused: %s", refused)
	}
	if !hasCapability(meta.Capabilities, CapabilityDAST) {
		t.Fatalf("capabilities = %v, want %s: without it the binary compiles no template out of this file and the run reports nothing",
			meta.Capabilities, CapabilityDAST)
	}
	args := capabilityFlagArgs(meta.Capabilities)
	if !containsString(args, "-dast") {
		t.Errorf("generated flags = %v, want -dast", args)
	}
	// A block that names its engine is not the pre-v3 form, so it must not be
	// reported as uncompilable — that would claim the binary cannot run a file
	// it demonstrably runs.
	if meta.IsReservedFuzzTagged() {
		t.Error("a payloads block that names its fuzzing engine is not the legacy shape")
	}
	if reason := meta.ReservedFuzzTagReason(); reason != "" {
		t.Errorf("reason = %q, want empty for a template the binary does compile", reason)
	}
}

func TestAPlainHTTPTemplateAsksForNoFuzzingFlag(t *testing.T) {
	meta, refused := parseTemplateDocument(plainHTTPTemplate)
	if refused != "" {
		t.Fatalf("the template was refused: %s", refused)
	}
	if hasCapability(meta.Capabilities, CapabilityDAST) {
		t.Errorf("capabilities = %v: -dast on a folder with no fuzzing template makes nuclei exit 1 with "+
			"a refusal to scan, losing every non-fuzzing file in the batch", meta.Capabilities)
	}
	for _, capability := range meta.Capabilities {
		if capability == CapabilityDAST {
			t.Fatal("the DAST flag is on a plain HTTP template")
		}
	}
}

// The pre-v3 form is recorded, not refused. Refusing it at parse time would make
// the operator's upload lose a file he did not cause to be lost, and the whole
// point of the status is that the *run* is what cannot execute it.
func TestTheReservedFuzzTagIsRecordedRatherThanRefused(t *testing.T) {
	meta, refused := parseTemplateDocument(reservedFuzzTagTemplate)
	if refused != "" {
		t.Fatalf("the file was refused at parse time: %s — the binary accepts it under -validate, "+
			"so refusing it here would lose a file the operator did upload badly", refused)
	}
	if !meta.IsReservedFuzzTagged() {
		t.Fatalf("ReservedFuzzTag = false for a document with payloads and no fuzzing key (blocks: %v)", meta.BlockKeys)
	}
	reason := meta.ReservedFuzzTagReason()
	if reason == "" {
		t.Fatal("the status has no reason, and every status that is not a plain result must carry one")
	}
	// The reason has to be falsifiable by the operator: it must name the tag and
	// say that the binary refused the file, so it can be told apart from a file the
	// run merely did not reach.
	for _, want := range []string{"info.tags", "fuzz", "no templates provided for scan", "-validate"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not mention %q: %q", want, reason)
		}
	}
}

// The classifier and the sentence are not the contract; the report row is. This
// drives `applyBatchOutcome` with the fact under test — the binary wrote no
// record for the file — and asserts the row the report would show. It is
// assembled by hand rather than by running nuclei, because the fact is the
// binary's silence and a fixture has to reproduce silence faithfully to be worth
// anything.
func TestTheReportRowForAReservedFuzzTaggedFileSaysItWasNeverCompiled(t *testing.T) {
	meta, refused := parseTemplateDocument(reservedFuzzTagTemplate)
	if refused != "" {
		t.Fatalf("the file was refused: %s", refused)
	}

	const staged = "/tmp/rr-staged/misc/ntlm-directories.yaml"
	file := StagedFile{UploadName: "ntlm-directories.yaml", RelativePath: "misc/ntlm-directories.yaml", StagedPath: staged, Meta: meta}
	batch := NucleiBatch{Dir: "/tmp/rr-staged", Files: []BatchFile{{File: file, Path: staged}}}
	run := &NucleiRun{}
	run.Templates = []TemplateResult{{Name: "ntlm-directories.yaml", Path: "misc/ntlm-directories.yaml"}}
	rows := map[string]int{cleanPathForCompare(staged): 0}

	// Exit 0, no error, no stderr, no record: exactly what a batch that ran 54
	// other files successfully produces for this one.
	applyBatchOutcome(run, batch, batchOutcome{ExitCode: 0}, rows)

	if len(run.Templates) != 1 {
		t.Fatalf("the run has %d rows, want 1", len(run.Templates))
	}
	row := run.Templates[0]
	if row.Status != TemplateUncompiled {
		t.Errorf("status = %q, want %q", row.Status, TemplateUncompiled)
	}
	// The two statuses this replaces each state something false, which is why the
	// status exists rather than a reworded `skipped`.
	if row.Status == TemplateSkipped {
		t.Error("a row that reads as skipped blames a load clash in a batch that loaded the other 54 files")
	}
	if row.Status == TemplateNotMatched {
		t.Error("a row that reads as not matched claims the check ran and came back clean")
	}
	if row.Reason == "" {
		t.Fatal("the row has no reason")
	}
	if !strings.Contains(row.Reason, "compiled") {
		t.Errorf("the reason does not say the binary compiled nothing: %q", row.Reason)
	}
}

// The isolation is not decoration. `-dast` must be its own invocation, because
// adding it to a folder that holds no fuzzing template kills the whole batch —
// measured on nuclei v3.11.1, a folder of 2 fuzzing files plus `robots-txt` gave
// `robots-txt` its record with `-t .` and produced `[FTL] no templates provided
// for scan` with `-t . -dast`.
func TestTheDastFlagIsIsolatedIntoItsOwnInvocation(t *testing.T) {
	if isolatedCapability != CapabilityDAST {
		t.Fatalf("isolatedCapability = %q, want %q: a shared invocation would lose every "+
			"non-fuzzing file in the batch", isolatedCapability, CapabilityDAST)
	}
	// And the flag map must actually render it, or the isolation buys nothing.
	if capabilityFlag[CapabilityDAST] != "-dast" {
		t.Errorf("the DAST capability renders as %q, want -dast", capabilityFlag[CapabilityDAST])
	}
}
