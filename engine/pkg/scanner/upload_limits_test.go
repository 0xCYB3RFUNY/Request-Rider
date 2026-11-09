package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An unbounded template document is a memory-exhaustion path: `yaml.Unmarshal`
// expands anchors inside the engine process, which holds every job's state. The
// bound lives on this path only — Intruder legitimately sends huge raw requests,
// so a global cap would break it. These tests run the shipped staging code.

func TestStageUploadsRefusesAnOversizedDocument(t *testing.T) {
	oversized := "id: big\ninfo:\n  name: big\n  author: rr\n  severity: info\n" +
		strings.Repeat("# padding\n", maxTemplateBytes())
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "big.yaml", Content: oversized},
		{Name: "ok.yaml", Content: validTemplate},
	})
	if err != nil {
		t.Fatalf("an oversized file must be a per-file refusal, not a request error: %v", err)
	}
	defer os.RemoveAll(dir)
	if len(staged) != 2 {
		t.Fatalf("staged = %d results, want 2", len(staged))
	}
	if staged[0].Meta != nil || !strings.Contains(staged[0].Reason, "TEMPLATE_TOO_LARGE") {
		t.Fatalf("oversized file = %+v, want an invalid row naming TEMPLATE_TOO_LARGE", staged[0])
	}
	if staged[0].StagedPath == "" {
		t.Fatal("oversized template was removed from the selected source directory")
	}
	if info, err := os.Stat(staged[0].StagedPath); err != nil || info.Size() != int64(len(oversized)) {
		t.Fatalf("oversized source file was not preserved intact: info=%v err=%v", info, err)
	}
	if staged[1].Meta == nil {
		t.Fatalf("the small file must still stage: %+v", staged[1])
	}
}

func TestStageUploadsHonoursTheConfiguredLimit(t *testing.T) {
	t.Setenv("RR_NUCLEI_MAX_TEMPLATE_BYTES", "1024")
	if got := maxTemplateBytes(); got != 1024 {
		t.Fatalf("maxTemplateBytes = %d, want 1024", got)
	}
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "x.yaml", Content: "id: x\n" + strings.Repeat("a", 2048)},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	if !strings.Contains(staged[0].Reason, "TEMPLATE_TOO_LARGE") {
		t.Fatalf("2048-byte file under a 1024-byte limit = %+v", staged[0])
	}
}

func TestDefaultTemplateBoundClearsTheShippedCorpus(t *testing.T) {
	// A bound that refuses the operator's own corpus reduces the tool instead of
	// protecting it. Measured 2026-10-07 on `nuclei-templates` as shipped: at the
	// old 8 MiB default exactly one document was over the line —
	// `http/technologies/wordpress/plugins/wordpress-plugin-detect.yaml`,
	// 10 079 081 bytes — and because the Django gateway raises on the whole chunk
	// that carries it, the browser's upload of the 11 664-file `http` folder
	// stopped at chunk 18 of 26 and every other template in that chunk was lost
	// with it. The file is named and measured here, so the next corpus update that
	// outgrows the default fails in this test rather than in the upload panel.
	t.Setenv("RR_NUCLEI_MAX_TEMPLATE_BYTES", "")
	corpus := os.Getenv("RR_NUCLEI_TEMPLATE_DIR")
	if corpus == "" {
		t.Skip("RR_NUCLEI_TEMPLATE_DIR is not set: the shipped corpus is not on this machine")
	}
	largest := filepath.Join(corpus, "http", "technologies", "wordpress", "plugins",
		"wordpress-plugin-detect.yaml")
	info, err := os.Stat(largest)
	if err != nil {
		t.Skipf("the corpus template this bound was sized against is missing: %v", err)
	}
	if got := maxTemplateBytes(); got <= int(info.Size()) {
		t.Fatalf("default per-template bound %d does not fit %s (%d bytes)", got, largest, info.Size())
	}
}

func TestUploadSessionTotalIsBounded(t *testing.T) {
	t.Setenv("RR_NUCLEI_MAX_UPLOAD_BYTES", "4096")
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "a.yaml", Content: validTemplate},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	id, err := uploads.Add(dir, staged)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("add: %v", err)
	}
	// The second chunk would push the session past the 4 KB ceiling.
	_, _, err = uploads.Append(id, []UploadFile{
		{Name: "b.yaml", Content: validTemplate + strings.Repeat("# p\n", 2048)},
	})
	if err == nil || !strings.Contains(err.Error(), "TEMPLATE_TOO_LARGE") {
		os.RemoveAll(dir)
		t.Fatalf("session over the limit was accepted: %v", err)
	}
	session, ok := uploads.Take(id)
	if !ok {
		t.Fatal("session vanished")
	}
	defer os.RemoveAll(session.Dir)
	if len(session.Staged) != 1 {
		t.Fatalf("rejected chunk left %d staged files, want 1", len(session.Staged))
	}
}
