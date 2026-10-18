package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// folderTemplate is a complete document with a caller-chosen id, so one test can
// stage a whole tree and know exactly what every file declares.
func folderTemplate(id string) string {
	return strings.Replace(validTemplate, "rr-demo-check", id, 1)
}

// TestStageUploadsReportsTemplatePaths proves that a folder upload keeps its
// template layout in the report while support files remain in the source tree
// without masquerading as template results.
func TestStageUploadsReportsTheFolderOfEveryFile(t *testing.T) {
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "CVE-2024-1.yaml", Path: "templates/http/cves/2024/CVE-2024-1.yaml", Content: folderTemplate("rr-cve")},
		{Name: "detect.yaml", Path: "templates/dns/detect.yaml", Content: folderTemplate("rr-dns")},
		{Name: "broken.yaml", Path: "templates/http/misconfig/broken.yaml", Content: missingAuthorTemplate},
		{Name: "notes.txt", Path: "templates/http/notes.txt", Content: "ignored"},
		{Name: "empty.yaml", Path: "templates/http/empty.yaml", Content: "  "},
		{Name: "loose.yaml", Content: folderTemplate("rr-loose")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)

	wantStaged := []string{
		"templates/http/cves/2024/CVE-2024-1.yaml",
		"templates/dns/detect.yaml",
		"templates/http/misconfig/broken.yaml",
		"templates/http/notes.txt",
		"templates/http/empty.yaml",
		"loose.yaml",
	}
	if len(staged) != len(wantStaged) {
		t.Fatalf("staged = %d, want %d", len(staged), len(wantStaged))
	}
	for index, expected := range wantStaged {
		if staged[index].RelativePath != expected {
			t.Fatalf("staged[%d].RelativePath = %q, want %q", index, staged[index].RelativePath, expected)
		}
		if strings.Contains(staged[index].RelativePath, "..") || filepath.IsAbs(staged[index].RelativePath) {
			t.Fatalf("staged[%d] report path %q leaks a location", index, staged[index].RelativePath)
		}
	}
	if !staged[3].Support {
		t.Fatalf("notes file = %+v, want a staged support file", staged[3])
	}
	content, err := os.ReadFile(filepath.Join(dir, "templates/http/notes.txt"))
	if err != nil || string(content) != "ignored" {
		t.Fatalf("support file content = %q, err=%v; want original bytes", content, err)
	}

	// The upload endpoint returns the same per-file report, so a folder scan
	// shows the layout while the remaining chunks are still arriving.
	report := TemplatesReport(staged)
	wantReport := []string{
		wantStaged[0], wantStaged[1], wantStaged[2], wantStaged[4], wantStaged[5],
	}
	if len(report) != len(wantReport) {
		t.Fatalf("report = %d rows, want %d template rows", len(report), len(wantReport))
	}
	for index, expected := range wantReport {
		if report[index].Path != expected {
			t.Fatalf("report[%d].Path = %q, want %q", index, report[index].Path, expected)
		}
		if report[index].Name == "" {
			t.Fatalf("report[%d] lost its file name", index)
		}
	}
}

// TestRunNucleiDirReportsTheFolderOfEveryResult proves the finished report, not
// only the upload preview, carries the folder each result belongs to.
func TestRunNucleiDirReportsTheFolderOfEveryResult(t *testing.T) {
	stubNuclei(t)
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "a.yaml", Path: "templates/http/cves/2024/CVE-2024-1.yaml", Content: folderTemplate("rr-cve")},
		{Name: "b.yaml", Path: "templates/dns/detect.yaml", Content: folderTemplate("rr-dns")},
		{Name: "c.yaml", Path: "templates/http/broken.yaml", Content: missingAuthorTemplate},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Templates) != 3 {
		t.Fatalf("templates = %d, want one row per uploaded file", len(run.Templates))
	}
	folders := map[string]bool{}
	for _, item := range run.Templates {
		cut := strings.LastIndex(item.Path, "/")
		if cut < 0 {
			t.Fatalf("%q has no folder in %q", item.Name, item.Path)
		}
		folders[item.Path[:cut]] = true
	}
	for _, expected := range []string{
		"templates/http/cves/2024",
		"templates/dns",
		"templates/http",
	} {
		if !folders[expected] {
			t.Fatalf("folder %q missing from the report: %v", expected, folders)
		}
	}
	// The rejected file keeps its folder too, which is the whole point: an
	// invalid file is still part of the folder the operator uploaded.
	for _, item := range run.Templates {
		if item.Status == TemplateInvalid && item.Path != "templates/http/broken.yaml" {
			t.Fatalf("invalid result path = %q, want its uploaded folder", item.Path)
		}
	}
}

// TestDisplayRelativePathNeverEchoesATraversal proves the reporting helper is
// total and stays inside the uploaded layout: a hostile or empty path is reduced
// to something safe to show and to group by, never refused and never echoed.
func TestDisplayRelativePathNeverEchoesATraversal(t *testing.T) {
	cases := map[string]struct {
		raw      string
		fallback string
		want     string
	}{
		"nested folder":     {"templates/http/a.yaml", "a.yaml", "templates/http/a.yaml"},
		"backslash layout":  {`templates\http\a.yaml`, "a.yaml", "templates/http/a.yaml"},
		"absolute path":     {"/etc/passwd", "a.yaml", "etc/passwd"},
		"traversal":         {"../../etc/passwd", "a.yaml", "a.yaml"},
		"traversal in name": {"templates/a.yaml", "../../etc/passwd", "templates/a.yaml"},
		"empty raw":         {"", "a.yaml", "a.yaml"},
		"empty everything":  {"", "", ""},
		"dot segments":      {"./templates/./a.yaml", "a.yaml", "templates/a.yaml"},
	}
	for name, testCase := range cases {
		got := displayRelativePath(testCase.raw, testCase.fallback)
		if got != testCase.want {
			t.Fatalf("%s: displayRelativePath(%q, %q) = %q, want %q",
				name, testCase.raw, testCase.fallback, got, testCase.want)
		}
		if strings.Contains(got, "..") || filepath.IsAbs(got) {
			t.Fatalf("%s: %q leaks a location", name, got)
		}
	}
}

// TestStreamedTemplateEventCarriesTheFolder proves a live row is filed under its
// folder while nuclei is still working, not only in the final report.
func TestStreamedTemplateEventCarriesTheFolder(t *testing.T) {
	job := &NucleiJob{}
	meta := &TemplateMeta{TemplateID: "rr-cve", Name: "CVE", Severity: "high"}
	event := job.templateEvent(StagedFile{
		UploadName:   "CVE-2024-1.yaml",
		RelativePath: "templates/http/cves/2024/CVE-2024-1.yaml",
		Meta:         meta,
	}, TemplateMatched, "")
	if event.Path != "templates/http/cves/2024/CVE-2024-1.yaml" {
		t.Fatalf("event path = %q, want the uploaded folder layout", event.Path)
	}
	if event.Name != "CVE-2024-1.yaml" {
		t.Fatalf("event name = %q, want the file name unchanged", event.Name)
	}
}

// TestDuplicateCopiesAreReportedAsDuplicatesNotSkips proves that a byte-identical
// copy gets its own truthful status. It is not `skipped` — nothing failed — and it
// is not `not_matched` — no check was made against the target. It is the same
// template under a second name, and the report has to say which file it is a copy
// of, or a folder of collected templates looks like it lost those checks.
func TestDuplicateCopiesAreReportedAsDuplicatesNotSkips(t *testing.T) {
	dedupeStub(t)
	document := idTemplateAt("rr-once", "/only")
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "original.yaml", Path: "pack-a/original.yaml", Content: document},
		{Name: "copy-one.yaml", Path: "pack-b/copy-one.yaml", Content: document},
		{Name: "copy-two.yaml", Path: "pack-c/copy-two.yaml", Content: document},
		{Name: "different.yaml", Path: "pack-c/different.yaml", Content: idTemplateAt("rr-other", "/other")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Templates) != 4 {
		t.Fatalf("templates = %d, want one row per uploaded file", len(run.Templates))
	}
	byName := map[string]TemplateResult{}
	for _, item := range run.Templates {
		byName[item.Name] = item
	}
	if got := byName["original.yaml"]; got.Status != TemplateNotMatched {
		t.Fatalf("original = %q with reason %q, want not_matched: it is the copy that runs",
			got.Status, got.Reason)
	}
	if got := byName["different.yaml"]; got.Status != TemplateNotMatched {
		t.Fatalf("a distinct document = %q, want not_matched", got.Status)
	}
	for _, name := range []string{"copy-one.yaml", "copy-two.yaml"} {
		item, known := byName[name]
		if !known {
			t.Fatalf("%s has no row", name)
		}
		if item.Status != TemplateDuplicate {
			t.Fatalf("%s = %q, want duplicate: it is byte-identical to another file", name, item.Status)
		}
		if !strings.Contains(item.Reason, "byte-identical") {
			t.Fatalf("%s reason = %q, want it to explain the copy", name, item.Reason)
		}
		// The report names the file that took its place, so the operator can find
		// the twin in a folder that holds hundreds of thousands of files.
		if !strings.Contains(item.Reason, "pack-a/original.yaml") {
			t.Fatalf("%s reason = %q, want it to name the file it collapses into", name, item.Reason)
		}
	}
	if run.Stats["duplicate"] != 2 {
		t.Fatalf("duplicate counter = %v, want 2", run.Stats["duplicate"])
	}
	dedup, _ := run.Stats["deduplication"].(map[string]interface{})
	if dedup == nil {
		t.Fatalf("deduplication summary missing: %#v", run.Stats)
	}
	if dedup["files_uploaded"] != 4 || dedup["unique_content"] != 2 || dedup["collapsed"] != 2 {
		t.Fatalf("deduplication summary = %#v, want 4 files, 2 unique, 2 collapsed", dedup)
	}
}

// TestDuplicateDetectionComparesContentNotName proves the comparison is over the
// document bytes. Two files with different names, different folders and different
// ids but identical bodies are one template; two files with the same name and
// folder but different bodies are two.
func TestDuplicateDetectionComparesContentNotName(t *testing.T) {
	shared := idTemplateAt("id-one", "/x")
	dir, staged, err := StageUploads([]UploadFile{
		// Same bytes, different name and different folder: one template.
		{Name: "one.yaml", Path: "a/one.yaml", Content: shared},
		{Name: "two.yaml", Path: "b/two.yaml", Content: shared},
		// Same name and folder as the first, different bytes: a second template.
		{Name: "three.yaml", Path: "c/three.yaml", Content: idTemplateAt("id-one", "/y")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	kept, report := DedupeStaged(staged)
	if report.Files != 3 || report.Unique != 2 || report.TotalCollapsed != 1 {
		t.Fatalf("dedup = %#v, want 3 files, 2 unique, 1 collapsed", report)
	}
	if len(report.Groups) != 1 || report.Groups[0].Size() != 2 {
		t.Fatalf("groups = %#v, want one group of two", report.Groups)
	}
	if report.Groups[0].Kept != "a/one.yaml" {
		t.Fatalf("kept = %q, want the first occurrence by upload order", report.Groups[0].Kept)
	}
	if len(kept) != 3 {
		t.Fatalf("kept rows = %d, want 3: the copy is reported, not deleted", len(kept))
	}
}
