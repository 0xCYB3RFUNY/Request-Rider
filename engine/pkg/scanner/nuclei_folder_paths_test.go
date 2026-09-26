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

// TestStageUploadsReportsTheFolderOfEveryFile proves that a folder upload keeps
// its layout in the report. The browser groups the per-file result by this path,
// so a file that is rejected, empty or not a template at all still has to say
// which folder it came from — otherwise an unusable file would vanish from the
// folder summary.
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

	want := []string{
		"templates/http/cves/2024/CVE-2024-1.yaml",
		"templates/dns/detect.yaml",
		"templates/http/misconfig/broken.yaml",
		"templates/http/notes.txt",
		"templates/http/empty.yaml",
		"loose.yaml",
	}
	if len(staged) != len(want) {
		t.Fatalf("staged = %d, want %d", len(staged), len(want))
	}
	for index, expected := range want {
		if staged[index].RelativePath != expected {
			t.Fatalf("staged[%d].RelativePath = %q, want %q", index, staged[index].RelativePath, expected)
		}
		if strings.Contains(staged[index].RelativePath, "..") || filepath.IsAbs(staged[index].RelativePath) {
			t.Fatalf("staged[%d] report path %q leaks a location", index, staged[index].RelativePath)
		}
	}

	// The upload endpoint returns the same per-file report, so a folder scan
	// shows the layout while the remaining chunks are still arriving.
	report := TemplatesReport(staged)
	if len(report) != len(want) {
		t.Fatalf("report = %d rows, want %d", len(report), len(want))
	}
	for index, expected := range want {
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

// TestSkippedReasonNamesTheSiblingByItsPath proves the "not run" evidence points
// at the exact file that kept the template id. A templates folder repeats base
// names, so a bare name would be an ambiguous accusation.
func TestSkippedReasonNamesTheSiblingByItsPath(t *testing.T) {
	document := idTemplate("rr-dup")
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "shared.yaml", Path: "templates/http/cves/shared.yaml", Content: document},
		{Name: "shared.yaml", Path: "templates/dns/shared.yaml", Content: document},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	winner := "templates/http/cves/shared.yaml"
	executed := map[string]bool{filepath.Clean(staged[0].StagedPath): true}
	named := executedSibling(staged, []int{0, 1}, staged[1], executed)
	if named != winner {
		t.Fatalf("sibling = %q, want %q", named, winner)
	}
	// A same-named sibling must not be mistaken for the file itself, and a file
	// that is not in the group never gets named.
	if executedSibling(staged, []int{0}, staged[0], executed) != "" {
		t.Fatal("executedSibling named the file itself")
	}
	if executedSibling(staged, []int{1}, staged[1], executed) != "" {
		t.Fatal("executedSibling named a file the binary did not execute")
	}
}
