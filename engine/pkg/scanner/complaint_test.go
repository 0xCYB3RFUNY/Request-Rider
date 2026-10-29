package scanner

import (
	"strings"
	"testing"
)

// Причина «не виконано» має називати те, що бінарник сказав про цей файл.
//
// nuclei друкує `[<id>] Could not execute code: cause="exit status 1" …` для
// `code`-шаблонів, чиї движки померли, і не пише для них JSONL-запис — саме
// тому такий файл приходить у `skipped`. Виміряно на v3.11.1: `CVE-2025-6984`
// відповідає саме так, з `ModuleNotFoundError: No module named
// 'langchain_community'` усередині.
//
// Без цього рядок каже лише «nuclei не повернула запису», а причина лежить у
// діагностиці, яку оператор мусить знайти сам: файл не просто «не запустили»,
// його відхилили через відсутній модуль, а це факт про машину, а не про скан.

func batchFileWithID(id string) BatchFile {
	return BatchFile{File: StagedFile{Meta: &TemplateMeta{TemplateID: id}}}
}

func TestNotRunReasonQuotesTheBinaryAboutThisTemplate(t *testing.T) {
	outcome := batchOutcome{
		Stderr: strings.Join([]string{
			"[INF] Loaded 12 templates",
			`[WRN] [CVE-2025-6984] Could not execute code: cause="exit status 1" ` +
				`chain="failed to exec command got: ModuleNotFoundError: No module named 'langchain_community'"`,
			"[INF] Templates loaded: 11",
		}, "\n"),
		Args: []string{"-code", "-t", "/tmp/batch"},
	}
	batch := NucleiBatch{Files: []BatchFile{
		batchFileWithID("CVE-2025-6984"), batchFileWithID("ran-fine-1"), batchFileWithID("ran-fine-2"),
	}}
	reason := notRunReason(outcome, batch, batchFileWithID("CVE-2025-6984"), 11)

	if !strings.Contains(reason, "langchain_community") {
		t.Fatalf("reason does not carry the binary's own cause: %q", reason)
	}
	if !strings.Contains(reason, "11 of the 3") {
		t.Fatalf("reason does not say the batch itself was fine: %q", reason)
	}
	// The generic sentence is what the operator used to be shown instead, and it
	// names no cause at all. Its absence is the point of the fix.
	if strings.Contains(reason, "returned no record for template id") {
		t.Fatalf("reason fell through to the batch-level sentence: %q", reason)
	}
}

// One batch prints one line per template it had trouble with. A row about A must
// never be handed B's cause: both ids are plausible, and only one of them is
// this file.
func TestNotRunReasonKeepsEachTemplatesCauseToItself(t *testing.T) {
	outcome := batchOutcome{
		Stderr: strings.Join([]string{
			`[WRN] [first-template] Could not execute code: cause="exit status 2"`,
			`[WRN] [second-template] Could not execute code: cause="exit status 1"`,
		}, "\n"),
		Args: []string{"-code"},
	}

	first := notRunReason(outcome, NucleiBatch{}, batchFileWithID("first-template"), 1)
	if !strings.Contains(first, "exit status 2") {
		t.Fatalf("first template lost its own cause: %q", first)
	}
	second := notRunReason(outcome, NucleiBatch{}, batchFileWithID("second-template"), 1)
	if !strings.Contains(second, "exit status 1") {
		t.Fatalf("second template lost its own cause: %q", second)
	}
}

// A complaint that names no template is about the invocation, not about this
// file, and must keep falling through to the batch-level sentence.
func TestNotRunReasonIgnoresAnInvocationLevelComplaint(t *testing.T) {
	outcome := batchOutcome{
		Stderr: "[FTL] Could not run nuclei: no templates provided for scan\n",
		Args:   []string{"-code"},
	}
	reason := notRunReason(outcome, NucleiBatch{}, batchFileWithID("some-id"), 0)

	if strings.Contains(reason, "no templates provided for scan") {
		t.Fatalf("an invocation-level complaint was attributed to one file: %q", reason)
	}
	if !strings.Contains(reason, "returned no record for template id") {
		t.Fatalf("expected the batch-level sentence instead: %q", reason)
	}
}

// A `powershell`-only template on a Linux host is refused with a complaint that
// names the file by path, not by id. Measured on the corpus, that is the whole
// of the `skipped` rows that carry no id-scoped complaint.
func TestNotRunReasonQuotesTheRefusalThatNamesThePath(t *testing.T) {
	batchFile := BatchFile{
		File: StagedFile{Meta: &TemplateMeta{TemplateID: "ftp-service-running"}},
		Path: "/tmp/rr-upload-1/batch-00001-code/ftp-service-running.yaml",
	}
	outcome := batchOutcome{
		Stderr: `[WRN] Could not parse template ` +
			`/tmp/rr-upload-1/batch-00001-code/ftp-service-running.yaml: could not compile request: ` +
			`cause="no valid engine found" ` +
			`chain="[ftp-service-running] engines 'powershell,powershell.exe' not available on host"` + "\n",
		Args: []string{"-code"},
	}
	reason := notRunReason(outcome, NucleiBatch{Files: []BatchFile{batchFile}}, batchFile, 3)

	if !strings.Contains(reason, "not available on host") {
		t.Fatalf("reason does not carry the refusal: %q", reason)
	}
	if !strings.Contains(reason, "3 of the 1") {
		t.Fatalf("reason does not say the batch itself was fine: %q", reason)
	}
	if strings.Contains(reason, "returned no record for template id") {
		t.Fatalf("reason fell through to the batch-level sentence: %q", reason)
	}
}

// The real line names the template twice — once as the file, once inside the
// quoted `chain=` — so an id-first reader hands the operator the tail alone and
// drops the sentence saying what was refused. Measured output of the id-first
// order was `nuclei named this template and said: engines 'powershell,…' not
// available on host"`, which names the missing engine but not the refusal.
func TestAPathScopedComplaintKeepsItsWholeSentence(t *testing.T) {
	batchFile := BatchFile{
		File: StagedFile{Meta: &TemplateMeta{TemplateID: "anonymous-sam-enumeration-enabled"}},
		Path: "/tmp/rr-upload-1/batch-00001-code/code/windows/audit/anonymous-sam-enumeration-enabled.yaml",
	}
	outcome := batchOutcome{
		Stderr: `[WRN] Could not parse template ` +
			`/tmp/rr-upload-1/batch-00001-code/code/windows/audit/anonymous-sam-enumeration-enabled.yaml: ` +
			`could not compile request: cause="no valid engine found" ` +
			`chain="[anonymous-sam-enumeration-enabled] engines 'powershell,powershell.exe' not available on host"` + "\n",
		Args: []string{"-code"},
	}
	reason := notRunReason(outcome, NucleiBatch{Files: []BatchFile{batchFile}}, batchFile, 1)

	// The head of the complaint, which the id-first order dropped.
	if !strings.Contains(reason, "could not compile request") {
		t.Fatalf("the refusal sentence was cut away: %q", reason)
	}
	if !strings.Contains(reason, "no valid engine found") {
		t.Fatalf("the machine's cause was cut away: %q", reason)
	}
	if !strings.Contains(reason, "not available on host") {
		t.Fatalf("the missing engine is not named: %q", reason)
	}
	if strings.Contains(reason, "named this template and said") {
		t.Fatalf("the id-scoped reader took a line the path-scoped reader owns: %q", reason)
	}
}

// One batch prints one line per file it could not build, each naming its own
// path. A row must never be handed the neighbour's refusal: both templates sit
// in the same staging directory and only the tail of the path differs.
func TestNotRunReasonKeepsEachPathsRefusalToItself(t *testing.T) {
	first := BatchFile{
		File: StagedFile{Meta: &TemplateMeta{TemplateID: "alpha"}},
		Path: "/tmp/upload/batch-code/alpha.yaml",
	}
	second := BatchFile{
		File: StagedFile{Meta: &TemplateMeta{TemplateID: "beta"}},
		Path: "/tmp/upload/batch-code/beta.yaml",
	}
	outcome := batchOutcome{
		Stderr: "[WRN] Could not parse template /tmp/upload/batch-code/alpha.yaml: " +
			`could not compile request: cause="engines 'powershell' not available on host"` + "\n" +
			"[WRN] Could not parse template /tmp/upload/batch-code/beta.yaml: " +
			`could not compile request: cause="engines 'ruby' not available on host"` + "\n",
		Args: []string{"-code"},
	}
	batch := NucleiBatch{Files: []BatchFile{first, second}}

	if got := notRunReason(outcome, batch, first, 1); !strings.Contains(got, "powershell") {
		t.Fatalf("alpha lost its own refusal: %q", got)
	}
	if got := notRunReason(outcome, batch, second, 1); !strings.Contains(got, "ruby") {
		t.Fatalf("beta lost its own refusal: %q", got)
	}
}

// The binary colours its output, so the id prefix arrives wrapped in escape
// sequences. A reason that quotes a coloured line verbatim is unreadable, and
// one that fails to match it says nothing at all.
func TestNotRunReasonReadsTheIdThroughColourCodes(t *testing.T) {
	outcome := batchOutcome{
		Stderr: "\x1b[93m[WRN]\x1b[0m \x1b[93m[colored-template] Could not parse template \x1b[0m\n",
		Args:   []string{"-code"},
	}
	reason := notRunReason(outcome, NucleiBatch{}, batchFileWithID("colored-template"), 1)

	if !strings.Contains(reason, "Could not parse template") {
		t.Fatalf("colour codes hid the binary's complaint: %q", reason)
	}
	if strings.Contains(reason, "\x1b") {
		t.Fatalf("escape sequences reached the report: %q", reason)
	}
}
