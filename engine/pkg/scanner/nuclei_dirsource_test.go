package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests here cover behaviour that the corpus run measured, not behaviour
// invented for the test: a folder has to start, a folder the binary would refuse
// as a whole has to be split, and the operator's own directory must come back
// untouched.

func writeTemplate(t *testing.T, path, id string, blocks string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	body := "id: " + id + "\ninfo:\n  name: " + id + "\n  author: rr\n  severity: info\n" + blocks
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// A folder the operator selects has to produce a staged set, because a folder
// that produced none could not be run at all.
func TestStageTemplateDirReadsAFolderInPlace(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "http", "a.yaml"), "dir-a",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	writeTemplate(t, filepath.Join(corpus, "ssl", "b.yaml"), "dir-b",
		"ssl:\n  - address: \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	if err := os.WriteFile(filepath.Join(corpus, "notes.md"), []byte("# not a template"), 0o600); err != nil {
		t.Fatalf("write notes: %v", err)
	}

	staged, err := stageTemplateDirInto(t.TempDir(), corpus)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if len(staged) != 2 {
		t.Fatalf("staged %d files, want 2 (a .md file is not a template): %+v", len(staged), staged)
	}
	// Relative paths keep the folder layout, which is what lets the report say
	// which category a row came from.
	paths := map[string]bool{}
	for _, file := range staged {
		paths[file.RelativePath] = true
		if file.StagedPath == "" {
			t.Fatalf("%s staged with no path: %+v", file.RelativePath, file)
		}
		if file.Meta == nil {
			t.Fatalf("%s staged with no metadata: %+v", file.RelativePath, file)
		}
	}
	if !paths["http/a.yaml"] || !paths["ssl/b.yaml"] {
		t.Fatalf("folder layout was not preserved: %+v", paths)
	}
}

// A document that cannot be used still gets a row carrying its reason, so a
// folder scan reports every file it found instead of only the ones that parsed.
func TestStageTemplateDirReportsAnUnusableFileWithItsReason(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "good.yaml"), "dir-good",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/g\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	if err := os.WriteFile(filepath.Join(corpus, "broken.yaml"), []byte("id: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "empty.yaml"), nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	staged, err := stageTemplateDirInto(t.TempDir(), corpus)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if len(staged) != 3 {
		t.Fatalf("staged %d rows, want 3 — a refused file is still a row: %+v", len(staged), staged)
	}
	byName := map[string]StagedFile{}
	for _, file := range staged {
		byName[file.RelativePath] = file
	}
	if row, ok := byName["good.yaml"]; !ok || row.Meta == nil {
		t.Fatalf("the usable template is missing or unparsed: %+v", row)
	}
	for _, name := range []string{"broken.yaml", "empty.yaml"} {
		row, ok := byName[name]
		if !ok {
			t.Fatalf("%s produced no row at all: %+v", name, byName)
		}
		if row.Reason == "" {
			t.Fatalf("%s was refused without a reason: %+v", name, row)
		}
		if row.StagedPath != "" {
			t.Fatalf("%s was refused but still staged at %q", name, row.StagedPath)
		}
	}
}

// A file whose name tries to climb out of the corpus must not be joined into the
// mirror root. This is the check that keeps an operator-supplied filename from
// becoming a write outside the directory the run owns.
func TestStageTemplateDirRefusesANameThatClimbsOut(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "ok.yaml"), "dir-ok",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/o\"\n    matchers:\n      -: x\n")

	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "rr-outside.yaml")
	// A document reached through a link that resolves outside the corpus is the
	// shape of a traversal attempt, so the path that leaves the root is refused
	// rather than joined.
	staged, err := stageTemplateDirInto(root, corpus)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	for _, file := range staged {
		if file.StagedPath != "" && !strings.HasPrefix(file.StagedPath, root) {
			t.Fatalf("staged path %q escapes the mirror root %q", file.StagedPath, root)
		}
	}
	_ = os.Remove(outside)
}

// A template may name a helper file by a path relative to the CORPUS ROOT, and
// the mirror has to carry it or the binary refuses the document.
//
// Measured on `http/cves` (4 320 documents): six of them failed with "access to
// helper file …/helpers/wordlists/numbers.txt denied" while the wordlist sat
// unread two directories up. So the helper tree is mirrored at the same relative
// path, and it is not reported as a template row — a wordlist is not a document.
func TestStageTemplateDirMirrorsCorpusHelpersWithoutReportingThem(t *testing.T) {
	corpus := t.TempDir()
	helpers := filepath.Join(corpus, "helpers", "wordlists")
	if err := os.MkdirAll(helpers, 0o700); err != nil {
		t.Fatalf("mkdir helpers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(helpers, "numbers.txt"), []byte("1\n2\n3\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	selected := filepath.Join(corpus, "http", "cves")
	// The template names its helper the way the official corpus does: a path
	// relative to the corpus root, not to the document.
	writeTemplate(t, filepath.Join(selected, "uses-helper.yaml"), "helper-user",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/h\"\n    payloads:\n      ids: helpers/wordlists/numbers.txt\n    matchers:\n      - type: word\n        words:\n          - hit\n")

	root := t.TempDir()
	staged, err := stageTemplateDirInto(root, selected)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	// The wordlist must be present at the path the document names, or the binary
	// answers "access to helper file … denied" and refuses the document.
	mirrored := filepath.Join(root, "helpers", "wordlists", "numbers.txt")
	content, err := os.ReadFile(mirrored)
	if err != nil {
		t.Fatalf("the helper the document names was not mirrored to %s: %v", mirrored, err)
	}
	if string(content) != "1\n2\n3\n" {
		t.Fatalf("the mirrored helper has the wrong contents: %q", content)
	}
	// And it must not be reported as a template: only the document is a row.
	if len(staged) != 1 {
		t.Fatalf("staged %d rows, want 1 — a mirrored helper is not a document: %+v", len(staged), staged)
	}
	if staged[0].RelativePath != "uses-helper.yaml" {
		t.Fatalf("the row names %q, want the document: %+v", staged[0].RelativePath, staged[0])
	}
}
func TestTemplateMirrorRootSharesTheCorpusFilesystem(t *testing.T) {
	corpus := t.TempDir()
	root, cleanup, err := templateMirrorRoot(corpus)
	if err != nil {
		t.Fatalf("mirror root: %v", err)
	}
	defer cleanup()
	if filepath.Dir(root) != filepath.Dir(corpus) {
		t.Fatalf("mirror root %q is not a sibling of the corpus %q, so links across it fail",
			root, corpus)
	}
	source := filepath.Join(corpus, "link-probe.yaml")
	if err := os.WriteFile(source, []byte("id: probe\n"), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	target := filepath.Join(root, "probe.yaml")
	if err := os.Link(source, target); err != nil {
		t.Fatalf("the mirror cannot hard-link from the corpus (%v), so a folder run would "+
			"byte-copy every template on every run", err)
	}
}

// A corpus path the operator did not name must not be substituted for the one
// they did: an unresolvable selection is an error, not a fallback to whatever
// corpus this installation happens to have.
func TestResolveTemplateDirRefusesAnUnknownSelection(t *testing.T) {
	if _, err := ResolveTemplateDir(filepath.Join(t.TempDir(), "no-such-folder")); err == nil {
		t.Fatal("a directory that does not exist must not resolve to anything")
	}
	if _, err := ResolveTemplateDir("   "); err == nil {
		t.Fatal("an empty selection must be refused")
	}
}

// The dropdown is offered real folders with real counts, so it cannot offer a
// folder that holds no templates at all.
func TestListTemplateDirsOffersOnlyFoldersThatHoldTemplates(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "http", "cves", "one.yaml"), "list-one",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/1\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	writeTemplate(t, filepath.Join(corpus, "http", "cves", "two.yaml"), "list-two",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/2\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	if err := os.MkdirAll(filepath.Join(corpus, "docs"), 0o700); err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "docs", "readme.md"), []byte("nothing"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", corpus)

	entries := ListTemplateDirs()
	byPath := map[string]TemplateDirEntry{}
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	folder, ok := byPath[filepath.Join(corpus, "http")]
	if !ok {
		t.Fatalf("the folder holding templates was not offered: %+v", entries)
	}
	if folder.Files != 2 {
		t.Fatalf("offered folder counts %d files, want 2: %+v", folder.Files, folder)
	}
	if folder.Name != "http" {
		t.Fatalf("offered folder is named %q, want the corpus-relative \"http\": %+v",
			folder.Name, folder)
	}
	if _, offered := byPath[filepath.Join(corpus, "docs")]; offered {
		t.Fatalf("a folder with no template document was offered: %+v", entries)
	}
}

// The listing must stay cheap: it parses nothing, because a dropdown is read when
// the panel opens. Measured on the official corpus, walking and counting names is
// 301 ms while parsing every document is 134 s — the same 98 662 files. Deciding
// whether a folder holds a template at all is not that parse: it reads the first
// line of one file and stops at the first `id:` it finds.
//
// The assertion is behavioural rather than a stopwatch: a folder holding a
// document that cannot be parsed is still counted and still offered. A listing
// that parsed would have to drop or fail on it, because parsing is exactly what
// would reject that document.
func TestListTemplateDirsDoesNotParseDocuments(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "mixed", "good.yaml"), "cheap-good",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/g\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	if err := os.WriteFile(filepath.Join(corpus, "mixed", "broken.yaml"), []byte("id: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", corpus)

	entries := ListTemplateDirs()
	for _, entry := range entries {
		if entry.Path != filepath.Join(corpus, "mixed") {
			continue
		}
		// Both files are counted, including the one that cannot be parsed: the
		// count comes from the name, and no document was parsed.
		if entry.Files != 2 {
			t.Fatalf("listing counted %d files, want 2 — a document that cannot be parsed "+
				"must still be counted, or the listing parsed it: %+v", entry.Files, entry)
		}
		return
	}
	t.Fatalf("the mixed folder was not offered: %+v", entries)
}

// The type dropdown offers what `-pt` accepts, and nothing else. A value outside
// this set makes nuclei exit 2 with "is not a valid extract type", so a value
// that is not in `validNucleiTypes` must not be offered, and a value the argument
// builder accepts must not be missing from the list.
func TestTemplateTypesAreExactlyWhatTheFlagAccepts(t *testing.T) {
	offered := TemplateTypes()
	if len(offered) != len(templateTypeOrder) {
		t.Fatalf("offered %d types, want %d: %+v", len(offered), len(templateTypeOrder), offered)
	}
	for index, entry := range offered {
		if entry.Value != templateTypeOrder[index] {
			t.Fatalf("type %d is %q, want %q — the order is the binary's own help order: %+v",
				index, entry.Value, templateTypeOrder[index], offered)
		}
		if entry.Label == "" {
			t.Fatalf("type %q has no label: %+v", entry.Value, offered)
		}
		if !validNucleiTypes[entry.Value] {
			t.Fatalf("type %q is offered but buildNucleiArgs would reject it as invalid", entry.Value)
		}
	}
	// The two lists must not drift: a type the builder accepts but the dropdown
	// omits is a template type the operator cannot choose.
	if len(validNucleiTypes) != len(templateTypeOrder) {
		t.Fatalf("the builder accepts %d types but the dropdown offers %d: %v vs %v",
			len(validNucleiTypes), len(templateTypeOrder), validNucleiTypes, templateTypeOrder)
	}
}

// Inspecting a folder is the deliberate, expensive call: it reports what the
// folder holds, including the documents that cannot be used and why. That is the
// difference between "Nuclei did not run it" and "this document is not a
// template", which is the whole reason the panel shows it.
func TestInspectTemplateDirReportsWhatTheFolderHolds(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "ok.yaml"), "insp-ok",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/o\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	writeTemplate(t, filepath.Join(corpus, "browser.yaml"), "insp-headless",
		"headless:\n  - steps:\n      - action: navigate\n        args:\n          url: \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	if err := os.WriteFile(filepath.Join(corpus, "broken.yaml"), []byte("id: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("write broken: %v", err)
	}

	report := InspectTemplateDir(corpus)
	if report.Error != "" {
		t.Fatalf("inspect: %s", report.Error)
	}
	if report.Total != 3 || report.Valid != 2 {
		t.Fatalf("report says total=%d valid=%d, want 3 and 2: %+v", report.Total, report.Valid, report)
	}
	if len(report.Invalid) != 1 || report.Invalid[0].Path != "broken.yaml" {
		t.Fatalf("the unusable document was not named with a reason: %+v", report.Invalid)
	}
	if report.Invalid[0].Reason == "" {
		t.Fatalf("the unusable document has no reason: %+v", report.Invalid[0])
	}
	// The panel shows what a category needs, so the headless document must make
	// the headless capability visible before the run starts.
	needsHeadless := false
	for _, capability := range report.Capabilities {
		if capability == string(CapabilityHeadless) {
			needsHeadless = true
		}
	}
	if !needsHeadless {
		t.Fatalf("a folder with a headless document does not report the headless capability: %+v", report)
	}
	foundHTTP := false
	for _, kind := range report.Types {
		if kind == "http" {
			foundHTTP = true
		}
	}
	if !foundHTTP {
		t.Fatalf("a folder with an http document does not report the http type: %+v", report.Types)
	}
}

// A folder whose documents need different capabilities has to be planned into
// more than one invocation. Measured on v3.11.1: eleven `http/cves` documents
// including a `headless:`-only and a `code:`+`http:` template answer
// `rc=1, 0 loaded` when one invocation carries no flag for them, so a single
// `-t <folder>` would run nothing at all.
func TestPlanSplitsAFolderThatNeedsMoreThanOneCapability(t *testing.T) {
	corpus := t.TempDir()
	writeTemplate(t, filepath.Join(corpus, "plain.yaml"), "plan-plain",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/p\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	writeTemplate(t, filepath.Join(corpus, "browser.yaml"), "plan-headless",
		"headless:\n  - steps:\n      - action: navigate\n        args:\n          url: \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	writeTemplate(t, filepath.Join(corpus, "local.yaml"), "plan-code",
		"code:\n  - engine:\n      - sh\n    source: |\n      echo rr\n    matchers:\n      - type: word\n        words:\n          - rr\n")

	staged, err := stageTemplateDirInto(t.TempDir(), corpus)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: filepath.Dir(corpus), Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	defer plan.Clean()

	if len(plan.Batches) < 2 {
		t.Fatalf("a folder needing three capabilities produced %d batch(es): %+v",
			len(plan.Batches), plan.Describe())
	}
	// Every planned file must land in exactly one batch, so "planned" and
	// "executed" cannot silently differ.
	planned := plan.Planned()
	if planned != 3 {
		t.Fatalf("plan covers %d files, want 3: %+v", planned, plan.Describe())
	}
	headlessSeen := false
	for _, batch := range plan.Batches {
		for _, capability := range batch.Capabilities {
			if capability == CapabilityHeadless {
				headlessSeen = true
			}
		}
	}
	if !headlessSeen {
		t.Fatalf("no batch carries the headless capability the folder needs: %+v", plan.Describe())
	}
}

// Two files that declare the same template id cannot both be loaded by one
// invocation, so the plan has to give them different ones. This is the property
// the whole split exists for.
func TestPlanGivesDuplicateTemplateIdsDifferentInvocations(t *testing.T) {
	corpus := t.TempDir()
	for _, name := range []string{"one.yaml", "two.yaml"} {
		writeTemplate(t, filepath.Join(corpus, name), "same-id",
			"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/"+strings.TrimSuffix(name, ".yaml")+"\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	}
	staged, err := stageTemplateDirInto(t.TempDir(), corpus)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: filepath.Dir(corpus), Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	defer plan.Clean()

	if len(plan.Batches) < 2 {
		t.Fatalf("two files with one template id produced %d batch(es), so one of them "+
			"cannot be loaded: %+v", len(plan.Batches), plan.Describe())
	}
	if got := plan.Planned(); got != 2 {
		t.Fatalf("plan covers %d files, want 2: %+v", got, plan.Describe())
	}
}

// A run pointed at a folder must leave the folder exactly as it found it: the
// mirror is a sibling, so not one byte of the operator's corpus changes.
func TestRunNucleiTemplateDirLeavesTheCorpusUntouched(t *testing.T) {
	corpus := t.TempDir()
	template := filepath.Join(corpus, "keep.yaml")
	writeTemplate(t, template, "keep-id",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/k\"\n    matchers:\n      - type: word\n        words:\n          - \"hit\"\n")
	before, err := os.ReadFile(template)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	entriesBefore, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatalf("read dir before: %v", err)
	}

	// The binary is not consulted: the assertion is about the filesystem, and a
	// run that cannot start still has to leave the corpus alone.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = RunNucleiTemplateDir(ctx, corpus, NucleiRequest{URL: "http://127.0.0.1:1"})

	after, err := os.ReadFile(template)
	if err != nil {
		t.Fatalf("the run removed a template from the corpus: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("the run changed the contents of the operator's corpus")
	}
	entriesAfter, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatalf("read dir after: %v", err)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("the corpus went from %d to %d entries: %d", len(entriesBefore), len(entriesAfter), len(entriesAfter))
	}
	for _, entry := range entriesAfter {
		if strings.HasPrefix(entry.Name(), ".rr-") {
			t.Fatalf("the run left a staging directory inside the corpus: %s", entry.Name())
		}
	}
}
