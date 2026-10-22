package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The defect these tests were written for is a measurement, not a reading.
//
// On nuclei v3.11.1, eight documents of the official `javascript/` folder hold
// `payloads:` with an `attack:`, so `BlocksWithoutDeadline()` is true for them and
// `groupByCapability` gave each one a batch of its own. The batch key it built
// started with `dast`, and `executeBatch` read that first token as the capability
// to load — so each of those eight was launched with `-dast` against a
// one-document directory that contains no fuzzing template. The binary answers
// that exact shape with:
//
//	[FTL] Could not run nuclei: no templates provided for scan
//
// exit 1, zero records. Eight real checks performed by nobody, and eight rows in
// the report that could not say why.
//
// The fix separates two questions that were sharing one answer: whether a batch
// needs the reserved FLAG, and whether it must run ALONE.

// An isolated document keeps its own batch and its own deadline, and is given no
// flag it never asked for.
func TestIsolatedBatchCarriesNoFlagItDidNotAskFor(t *testing.T) {
	blocking := blockingStaged(t, "blocking.yaml", blockingTemplate)
	var key capabilityKey
	for groupKey, files := range groupByCapability([]StagedFile{blocking}) {
		if len(files) == 1 {
			key = groupKey
		}
	}
	if key == "" {
		t.Fatal("a document with no deadline of its own did not get a batch of its own")
	}

	// Isolation is what the plan promised, and it is still recognised.
	if !key.runsAlone() {
		t.Fatalf("key %q is not recognised as running alone", key)
	}
	if !key.isolated() {
		t.Fatalf("key %q must still count as isolated, or its bound reverts to the run's own", key)
	}
	// The flag is the part that was wrong. `dast` must not appear in the
	// capability list, or `buildNucleiArgs` would add `-dast` again.
	for _, capability := range key.parseCapabilities() {
		if capability == CapabilityDAST {
			t.Fatalf("key %q reports the reserved flag, so this document would be "+
				"launched with -dast on a directory that holds no fuzzing template", key)
		}
	}
	if got := batchTimeoutSec(NucleiBatch{Key: key}); got >= nucleiTimeoutSec() {
		t.Fatalf("isolated deadline = %d, want less than the run's own %d", got, nucleiTimeoutSec())
	}
}

// A document that really declares the fuzzing capability still gets the flag, on
// an invocation of its own. The separation must not cost the case the flag exists
// for.
func TestAFuzzingDocumentStillGetsTheReservedFlag(t *testing.T) {
	fuzzing := stagingTemplateWithCapabilities(t, "fuzzing.yaml", fuzzingTemplate,
		[]Capability{CapabilityDAST})

	var key capabilityKey
	for groupKey, files := range groupByCapability([]StagedFile{fuzzing}) {
		if len(files) == 1 {
			key = groupKey
		}
	}
	if key == "" {
		t.Fatal("a fuzzing document did not get a group of its own")
	}
	if !key.needsReservedFlag() {
		t.Fatalf("key %q lost the reserved flag, so -dast is dropped and the binary "+
			"refuses the invocation with `no templates provided for scan`", key)
	}
	if !key.isolated() {
		t.Fatalf("key %q must still count as isolated: -dast cancels a shared invocation", key)
	}
}

// The marker is not a capability, and nothing downstream may read it as one.
func TestABatchMarkerIsNotReadAsACapability(t *testing.T) {
	cases := map[string]struct {
		key       capabilityKey
		flag      bool
		alone     bool
		capabilit []Capability
	}{
		"a deadline-blocked code document": {
			key:       capabilityKey("code+cve-2016-8735"),
			flag:      false,
			alone:     true,
			capabilit: []Capability{CapabilityCode},
		},
		"a deadline-blocked javascript document with no capability at all": {
			key:       capabilityKey("mysql-show-databases"),
			flag:      false,
			alone:     true,
			capabilit: nil,
		},
		"a real fuzzing document": {
			key:       capabilityKey("dast"),
			flag:      true,
			alone:     false,
			capabilit: []Capability{CapabilityDAST},
		},
		"a shared browser batch": {
			key:       capabilityKey("headless"),
			flag:      false,
			alone:     false,
			capabilit: []Capability{CapabilityHeadless},
		},
		"a shared plain batch": {
			key:       capabilityKey(""),
			flag:      false,
			alone:     false,
			capabilit: nil,
		},
	}
	for name, test := range cases {
		if got := test.key.needsReservedFlag(); got != test.flag {
			t.Errorf("%s: needsReservedFlag = %v, want %v (key %q)",
				name, got, test.flag, test.key)
		}
		if got := test.key.runsAlone(); got != test.alone {
			t.Errorf("%s: runsAlone = %v, want %v (key %q)", name, got, test.alone, test.key)
		}
		got := test.key.parseCapabilities()
		if len(got) != len(test.capabilit) {
			t.Errorf("%s: parseCapabilities = %v, want %v (key %q)",
				name, got, test.capabilit, test.key)
			continue
		}
		for index := range got {
			if got[index] != test.capabilit[index] {
				t.Errorf("%s: parseCapabilities = %v, want %v (key %q)",
					name, got, test.capabilit, test.key)
				break
			}
		}
		// Whatever the shape, a rendered flag set may only name flags that exist.
		for _, flag := range capabilityFlagArgs(got) {
			if _, known := knownNucleiFlags()[flag]; !known {
				t.Errorf("%s: capabilityFlagArgs produced %q, which is not a nuclei flag", name, flag)
			}
		}
	}
}

// The report says why a batch was isolated, and it names the reserved flag only
// when the flag is actually in the invocation.
func TestTheIsolationReasonNamesTheFlagOnlyWhenItIsThere(t *testing.T) {
	// The plan needs a file on disk, not just a parsed document: a staged entry
	// with no `StagedPath` is refused before it is ever grouped, so a report
	// about a batch would be about a batch that does not exist.
	root := t.TempDir()
	path := filepath.Join(root, "blocking.yaml")
	if err := os.WriteFile(path, []byte(blockingTemplate), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	staged, err := stageTemplateDirInto(t.TempDir(), root)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: staged[0].StagedPath, Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	detail := plan.Describe()["batch_detail"]
	rows, ok := detail.([]map[string]interface{})
	if !ok || len(rows) == 0 {
		t.Fatalf("batch_detail = %#v, want at least one row", detail)
	}
	found := false
	for _, row := range rows {
		if row["isolated"] != true {
			continue
		}
		found = true
		reason, _ := row["isolated_reason"].(string)
		if strings.Contains(reason, "-dast") {
			t.Fatalf("isolated_reason names -dast for a batch that does not carry it: %q", reason)
		}
		if !strings.Contains(reason, "deadline") {
			t.Fatalf("isolated_reason does not name the reason that applies: %q", reason)
		}
	}
	if !found {
		t.Fatal("a document with no deadline of its own was not reported as isolated")
	}
}

// The whole folder, on the corpus itself: every document that asks for the
// reserved flag gets it, and no other document is given it.
//
// This is the assertion the eight lost verdicts would have failed.
func TestTheCorpusFolderGivesTheReservedFlagOnlyWhereItIsDeclared(t *testing.T) {
	corpus := nucleiCorpusFolder(t)
	if corpus == "" {
		t.Skip("the official corpus is not present on this machine")
	}
	staged, err := stageTemplateDirInto(t.TempDir(), corpus)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: t.TempDir(), Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	flagged := map[string]bool{}
	declared := map[string]bool{}
	for _, file := range staged {
		if file.Meta == nil {
			continue
		}
		for _, capability := range file.Meta.Capabilities {
			if capability == CapabilityDAST {
				declared[file.Meta.TemplateID] = true
			}
		}
	}
	for _, batch := range plan.Batches {
		if !batch.Key.needsReservedFlag() {
			continue
		}
		if len(batch.Capabilities) == 0 {
			t.Fatalf("batch %d carries the reserved flag but declares no capability", batch.Index)
		}
		for _, file := range batch.Files {
			if file.File.Meta == nil {
				continue
			}
			flagged[file.File.Meta.TemplateID] = true
		}
	}
	for id := range flagged {
		if !declared[id] {
			t.Fatalf("document %q was launched with the reserved flag but never declared it", id)
		}
	}
	// And the batch must be able to run: a directory whose only document is not a
	// fuzzing template is exactly the shape nuclei refuses.
	for _, batch := range plan.Batches {
		if !batch.Key.needsReservedFlag() {
			continue
		}
		for _, file := range batch.Files {
			if file.File.Meta == nil {
				continue
			}
			hasFuzzing := false
			for _, capability := range file.File.Meta.Capabilities {
				if capability == CapabilityDAST {
					hasFuzzing = true
				}
			}
			if !hasFuzzing {
				t.Fatalf("batch %d holds %q and carries the reserved flag, so the binary "+
					"answers `no templates provided for scan` and the document loses its verdict",
					batch.Index, file.File.Meta.TemplateID)
			}
		}
	}
}

// The end of the whole chain: the binary is actually launched for the documents
// that were isolated, and it answers with records instead of `[FTL]`.
func TestAnIsolatedDeadlineDocumentIsActuallyExecuted(t *testing.T) {
	// `nucleiBinary()` is a bare command name, so it has to be resolved through
	// PATH: stat'ing the name itself would report "not available" on a machine
	// where the binary is installed, and this test would never run.
	if resolved, err := exec.LookPath(nucleiBinary()); err != nil {
		t.Skipf("the nuclei binary is not available on this machine: %v", err)
	} else if _, err := exec.LookPath("node"); err != nil {
		t.Skipf("a javascript document needs `node` to execute: %v", err)
	} else {
		t.Logf("running the real binary: %s", resolved)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// The document is taken from the official corpus rather than written here.
	//
	// A hand-written stand-in cannot prove this: on v3.11.1 a `javascript:` block
	// is refused with `[FTL] no templates provided for scan` unless it carries a
	// `payloads:` block, and a synthetic one without it is refused whether or not
	// `-dast` is passed — so a test built from it would pass for the wrong reason
	// and would have said nothing about the eight lost verdicts.
	//
	// The real file is the evidence. Measured on this machine with the binary
	// directly, one copy of `javascript/enumeration/mysql/mysql-show-databases.yaml`:
	//
	//	nuclei -t <copy> -esc -nss        -> Templates loaded for current scan: 1
	//	nuclei -t <copy> -esc -nss -dast  -> [FTL] no templates provided for scan
	//
	// So the flag is not a harmless extra on this document. It cancels the run.
	source := nucleiCorpusFile(t, "javascript/enumeration/mysql/mysql-show-databases.yaml")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "probe.yaml"), []byte(source), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	staged, err := stageTemplateDirInto(t.TempDir(), root)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: staged[0].StagedPath, Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Batches) != 1 {
		t.Fatalf("plan produced %d batches, want 1", len(plan.Batches))
	}
	batch := plan.Batches[0]
	if batch.Key.needsReservedFlag() {
		t.Fatal("this document declares no fuzzing capability, so the reserved flag must not be added")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	outcome, err := executeBatch(ctx, batch, server.URL, NucleiRequest{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(outcome.Stderr, "[FTL]") {
		t.Fatalf("the binary refused the invocation:\n%s", outcome.Stderr)
	}
	if outcome.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", outcome.ExitCode, outcome.Stderr)
	}
	if !strings.Contains(strings.Join(outcome.Args, " "), "-target "+server.URL) {
		t.Fatalf("the invocation does not name the target: %v", outcome.Args)
	}
}

func knownNucleiFlags() map[string]bool {
	flags := map[string]bool{}
	for _, flag := range capabilityFlag {
		flags[flag] = true
	}
	return flags
}

// fuzzingTemplate declares the reserved capability the flag exists for: a
// `payloads:` block that names its `fuzzing:` engine. nuclei loads such a document
// only under `-dast`, and it refuses an invocation that carries `-dast` while
// holding no such document, which is why the flag needs a batch of its own.
const fuzzingTemplate = `id: rr-fuzzing-probe
info:
  name: rr fuzzing probe
  author: rr
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    payloads:
      value:
        - one
    fuzzing:
      - type: replace
        method: GET
    matchers:
      - type: word
        words:
          - never
`

// stagingTemplateWithCapabilities parses a document and asserts the capability set
// it declares, so a test that depends on the flag cannot pass because the parser
// stopped reading the declaration.
func stagingTemplateWithCapabilities(t *testing.T, name, body string, want []Capability) StagedFile {
	t.Helper()
	meta, reason := parseTemplateDocument(body)
	if reason != "" {
		t.Fatalf("parse %s: %s", name, reason)
	}
	got := map[Capability]bool{}
	for _, capability := range meta.Capabilities {
		got[capability] = true
	}
	for _, capability := range want {
		if !got[capability] {
			t.Fatalf("%s: the parser does not report %q, so this test would pass "+
				"for the wrong reason. Capabilities read: %v", name, capability, meta.Capabilities)
		}
	}
	return StagedFile{UploadName: name, Meta: meta}
}

// nucleiCorpusFolder finds the official corpus's `javascript` folder, which is
// where the eight lost verdicts came from. It is not required: the rest of this
// file runs without it.
func nucleiCorpusFolder(t *testing.T) string {
	t.Helper()
	for _, root := range nucleiCorpusRoots() {
		candidate := filepath.Join(root, "javascript")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

// nucleiCorpusFile reads one document out of the official corpus.
func nucleiCorpusFile(t *testing.T, relative string) string {
	t.Helper()
	for _, root := range nucleiCorpusRoots() {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err == nil {
			return string(content)
		}
	}
	t.Skipf("the official corpus is not present on this machine (%s)", relative)
	return ""
}

// nucleiCorpusRoots are the places this project's own corpus lives: the one the
// binary installs for itself, and the one the repository keeps.
func nucleiCorpusRoots() []string {
	return []string{
		"/home/kali/.local/nuclei-templates",
		filepath.Join("..", "nuclei-templates"),
		filepath.Join("..", "..", "nuclei-templates"),
	}
}
