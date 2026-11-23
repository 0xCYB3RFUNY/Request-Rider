package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The operator names a folder and expects that folder's absolute path after
// `-t`. That is what the binary receives for every folder whose documents fit one
// invocation, and it is the shape a person reading `stats.args` recognises as
// their own folder rather than as an implementation detail of ours.
//
// A folder that needs more than one invocation keeps the mirror, because nuclei
// loads one file per `template-id` and a second document with the same id silently
// never runs. So the test is not "no mirror ever" — it is "the mirror exists only
// when a split needs it, and the run says which case it was".

// A corpus where every document has its own id and no capability is needed: the
// common case, and the one where the operator's folder is the batch directory.
func TestASingleInvocationRunPointsAtTheChosenFolder(t *testing.T) {
	dir := writePlainFolder(t, map[string]string{
		"one.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/1\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
		"two.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/2\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
	})

	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: stageInPlace(t, dir)})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Batches) != 1 {
		t.Fatalf("this folder plans to %d invocations, so it is not the single-invocation "+
			"case this test is about: %+v", len(plan.Batches), plan.Batches)
	}
	// The batch directory is what `-t` names. For a one-invocation folder it must
	// BE the folder, so `materialiseBatch` has to be able to keep a single batch in
	// place rather than always creating `batch-00001` inside it.
	if plan.Batches[0].Dir != dir {
		t.Fatalf("a one-invocation folder is staged into %q, so `-t` would name a copy "+
			"instead of the folder the operator chose: %+v", plan.Batches[0].Dir, plan)
	}
	for _, file := range plan.Batches[0].Files {
		if filepath.Dir(file.Path) != dir {
			t.Fatalf("template %q is staged at %q, outside the folder that was chosen", file.Path, file.Path)
		}
	}
}

// Two documents sharing a template-id cannot run in one invocation, so that folder
// must be split — and the split is why the mirror is allowed to exist at all. If
// this ever stopped being true, the single-invocation shortcut would silently start
// losing templates.
func TestASharedTemplateIDStillForcesTheSplit(t *testing.T) {
	dir := t.TempDir()
	// The SAME id in both files: nuclei loads one file per template-id, so the
	// second would silently never run if they shared an invocation.
	for _, name := range []string{"a.yaml", "b.yaml"} {
		writeRawTemplate(t, filepath.Join(dir, name),
			"id: shared-id\ninfo:\n  name: "+strings.TrimSuffix(name, ".yaml")+
				"\n  author: rr\n  severity: info\nhttp:\n  - method: GET\n    path:\n"+
				"      - \"{{BaseURL}}/"+strings.TrimSuffix(name, ".yaml")+
				"\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	}

	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: stageInPlace(t, dir)})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Batches) < 2 {
		t.Fatalf("two documents share a template-id and must be spread over two invocations, "+
			"but the plan made %d: %+v", len(plan.Batches), plan.Batches)
	}
	for _, batch := range plan.Batches {
		if batch.Dir == dir {
			t.Fatalf("a split run must not point an invocation at the whole folder, or the "+
				"shared id would collide again: %+v", batch)
		}
	}
}

// The folder the operator chose must be readable as an absolute path in the report,
// whichever case the run took. `stats.args` alone answers "what did the binary run";
// `source_dir` answers "which folder did I pick", and without it the two cannot be
// told apart in a split run.
func TestTheChosenFolderIsNamedInTheStats(t *testing.T) {
	run := NucleiRun{Stats: map[string]interface{}{}}
	recordSourceDir(&run, "/corpus/http/cves")
	if got := run.Stats["source_dir"]; got != "/corpus/http/cves" {
		t.Fatalf("stats name the mirror instead of the folder the operator chose: %v", run.Stats)
	}

	// A run with no stats yet must not panic: the map is created rather than
	// assigned into.
	empty := NucleiRun{}
	recordSourceDir(&empty, "/corpus/dns")
	if empty.Stats["source_dir"] != "/corpus/dns" {
		t.Fatalf("a run with no stats did not get the folder: %+v", empty.Stats)
	}

	// No folder named, nothing written: an empty answer is not a folder name.
	none := NucleiRun{Stats: map[string]interface{}{}}
	recordSourceDir(&none, "")
	if _, present := none.Stats["source_dir"]; present {
		t.Fatalf("an empty folder was recorded as the source: %+v", none.Stats)
	}
}

// The mirror is a copy of the operator's folder, so the files it carries must be
// the same bytes. A shortcut that pointed at the mirror must not have changed the
// file the report names, which is what the row is for.
func TestTheSingleInvocationPathReportsTheOperatorsOwnFile(t *testing.T) {
	dir := writePlainFolder(t, map[string]string{
		"only.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/only\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
	})
	staged := stageInPlace(t, dir)
	for _, file := range staged {
		if !strings.HasPrefix(file.StagedPath, dir) {
			t.Fatalf("the single-invocation staging put %q outside the chosen folder %q",
				file.StagedPath, dir)
		}
		if _, err := os.Stat(file.StagedPath); err != nil {
			t.Fatalf("staged path %q is not a real file: %v", file.StagedPath, err)
		}
	}
}

// A single-invocation folder is used in place instead of being copied, so the
// plan's own cleanup now points at the operator's corpus. `Clean` must not remove
// it: this is the exact path where a wrong `os.RemoveAll` deletes the folder a run
// was pointed at, and the plan's cleanup is the only code that would do it.
func TestCleanLeavesAFolderUsedInPlace(t *testing.T) {
	dir := writePlainFolder(t, map[string]string{
		"one.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/1\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
	})
	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: stageInPlace(t, dir)})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if !plan.Batches[0].InPlace {
		t.Fatalf("this folder was expected to be used in place, so the cleanup path "+
			"that would delete it is not covered: %+v", plan.Batches[0])
	}
	plan.Clean()
	if _, err := os.Stat(filepath.Join(dir, "one.yaml")); err != nil {
		t.Fatalf("Clean removed the operator's own template: %v", err)
	}
	// And the folder itself, not just the file: the plan must not have emptied it.
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Clean removed the folder the run was pointed at: %v", err)
	}
}

// The mirror a split run uses is still this plan's to remove: `InPlace` is scoped
// to the single batch that IS the selection, and a mirror is not.
func TestCleanStillRemovesTheMirrorOfASplitRun(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yaml"} {
		writeRawTemplate(t, filepath.Join(root, name),
			"id: shared\ninfo:\n  name: "+strings.TrimSuffix(name, ".yaml")+
				"\n  author: rr\n  severity: info\nhttp:\n  - method: GET\n    path:\n"+
				"      - \"{{BaseURL}}/x\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	}
	staged, err := stageTemplateDirForRun(root)
	if err != nil {
		t.Fatalf("stage in place: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: root, Staged: staged})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Batches) < 2 {
		t.Fatalf("a shared template-id must split the run, got %d batches", len(plan.Batches))
	}
	for _, batch := range plan.Batches {
		if batch.InPlace {
			t.Fatalf("a split batch must never be marked in place: %+v", batch)
		}
	}
	// The corpus itself survives — the batch directories are what goes.
	plan.Clean()
	if _, err := os.Stat(filepath.Join(root, "a.yaml")); err != nil {
		t.Fatalf("Clean removed the corpus: %v", err)
	}
	for _, batch := range plan.Batches {
		if _, err := os.Stat(batch.Dir); err == nil {
			t.Fatalf("the batch directory %q survived Clean, so it would be left behind "+
				"on disk after every run", batch.Dir)
		}
	}
}

// writePlainFolder builds a folder of documents that are all `http` and all carry
// their own id, which is the shape that plans to one invocation.
func writePlainFolder(t *testing.T, bodies map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range bodies {
		id := strings.TrimSuffix(name, ".yaml")
		writeRawTemplate(t, filepath.Join(dir, name),
			"id: "+id+"\ninfo:\n  name: "+id+"\n  author: rr\n  severity: info\n"+body)
	}
	return dir
}

// stageInPlace reads a folder the way the single-invocation path does.
func stageInPlace(t *testing.T, dir string) []StagedFile {
	t.Helper()
	staged, err := stageTemplateDirForRun(dir)
	if err != nil {
		t.Fatalf("stage in place: %v", err)
	}
	if len(staged) == 0 {
		t.Fatalf("no documents were staged from %q", dir)
	}
	return staged
}
