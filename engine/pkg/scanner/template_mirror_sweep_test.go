package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// buildCorpus makes a folder that looks like a real template corpus: the sweep
// resolves the path the same way a scan does, and that resolution is part of what
// is being tested.
func buildCorpus(t *testing.T) (corpus string, parent string) {
	t.Helper()
	parent = t.TempDir()
	corpus = filepath.Join(parent, "http")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatalf("create corpus: %v", err)
	}
	template := filepath.Join(corpus, "check.yaml")
	if err := os.WriteFile(template, []byte("id: check\n"), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	return corpus, parent
}

func makeLeftover(t *testing.T, parent string) string {
	t.Helper()
	leftover := filepath.Join(parent, templateMirrorPrefix+"leftover")
	if err := os.MkdirAll(filepath.Join(leftover, "batch-00001"), 0o755); err != nil {
		t.Fatalf("create leftover: %v", err)
	}
	return leftover
}

// MEASURED 2026-10-10: an engine killed while a job was staged left 986 copied
// templates inside nuclei-templates/http/, and the next scan loaded them again.
func TestStaleTemplateMirrorIsCleared(t *testing.T) {
	corpus, parent := buildCorpus(t)
	leftover := makeLeftover(t, parent)

	if removed := SweepStaleTemplateMirrors(corpus); removed != 1 {
		t.Fatalf("sweep removed %d, want 1", removed)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("the leftover mirror survived the sweep: %v", err)
	}
}

// The corpus itself must come through untouched. A sweep that ate real templates
// would be worse than the leak it fixes.
func TestSweepLeavesTheCorpusAlone(t *testing.T) {
	corpus, parent := buildCorpus(t)
	makeLeftover(t, parent)

	if removed := SweepStaleTemplateMirrors(corpus); removed != 1 {
		t.Fatalf("sweep removed %d, want 1", removed)
	}
	if _, err := os.Stat(filepath.Join(corpus, "check.yaml")); err != nil {
		t.Fatalf("the sweep touched the corpus: %v", err)
	}
	if _, err := os.Stat(corpus); err != nil {
		t.Fatalf("the sweep removed the corpus: %v", err)
	}
}

// A mirror this process is using is staging for a job that is still running, and
// a scan of a large collection legitimately runs for tens of minutes. The sweep
// must not be able to take it, however old it is.
func TestLiveTemplateMirrorSurvivesTheSweep(t *testing.T) {
	corpus, parent := buildCorpus(t)
	live := filepath.Join(parent, templateMirrorPrefix+"live")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatalf("create live mirror: %v", err)
	}
	markTemplateMirrorLive(live)
	defer releaseTemplateMirror(live)

	if removed := SweepStaleTemplateMirrors(corpus); removed != 0 {
		t.Fatalf("sweep removed %d, want 0 — it ate a running job's staging", removed)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("a live mirror was removed: %v", err)
	}
}

// The ordinary path: a mirror is registered when it is created and gone when the
// run that owns it ends. This is the path that does not leak, and it is the one a
// cancel uses — reproduced live, a cancelled job left nothing behind.
func TestTemplateMirrorIsReleasedWhenTheRunEnds(t *testing.T) {
	corpus, _ := buildCorpus(t)

	root, cleanup, err := templateMirrorRoot(corpus)
	if err != nil {
		t.Fatalf("create mirror: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("mirror was not created: %v", err)
	}
	if !templateMirrorIsLive(root) {
		t.Fatal("a mirror this process just created is not registered as live")
	}
	if removed := SweepStaleTemplateMirrors(corpus); removed != 0 {
		t.Fatalf("the sweep removed a mirror that was just created: removed %d", removed)
	}

	cleanup()

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("the mirror outlived its cleanup: %v", err)
	}
	if templateMirrorIsLive(root) {
		t.Fatal("a released mirror is still registered as live")
	}
	// And once released it is a leftover like any other, so the next startup
	// sweep is what finally clears it.
	if removed := SweepStaleTemplateMirrors(corpus); removed != 0 {
		t.Fatalf("sweep removed %d after cleanup, want 0 — the path is already gone", removed)
	}
}

// The leftover is not necessarily beside the corpus root. A scan of
// `http/misconfiguration` stages into `http/`, so that is where its leftover sits
// — and a sweep that looked only beside the root left it there, which is what the
// first version of this fix did.
func TestStaleMirrorNestedInsideTheCorpusIsCleared(t *testing.T) {
	corpus, _ := buildCorpus(t)
	nested := filepath.Join(corpus, "http", "misconfiguration")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("create nested folder: %v", err)
	}
	leftover := filepath.Join(corpus, "http", templateMirrorPrefix+"leftover")
	if err := os.MkdirAll(filepath.Join(leftover, "batch-00001"), 0o755); err != nil {
		t.Fatalf("create nested leftover: %v", err)
	}
	if err := os.WriteFile(filepath.Join(leftover, "batch-00001", "check.yaml"), []byte("id: check\n"), 0o644); err != nil {
		t.Fatalf("stage a template: %v", err)
	}

	if removed := SweepStaleTemplateMirrors(corpus); removed != 1 {
		t.Fatalf("sweep removed %d, want 1 — the nested leftover survived", removed)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("the nested leftover survived: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("the sweep removed a real corpus folder: %v", err)
	}
}

// A second sweep over the same parent has nothing left to do, and must not report
// work it did not do.
func TestSweepIsIdempotent(t *testing.T) {
	corpus, parent := buildCorpus(t)
	makeLeftover(t, parent)

	if removed := SweepStaleTemplateMirrors(corpus); removed != 1 {
		t.Fatalf("first sweep removed %d, want 1", removed)
	}
	if removed := SweepStaleTemplateMirrors(corpus); removed != 0 {
		t.Fatalf("second sweep removed %d, want 0", removed)
	}
}
