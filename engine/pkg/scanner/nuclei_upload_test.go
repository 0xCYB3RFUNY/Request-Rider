package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const chunkTemplate = `id: %s
info:
  name: %s
  author: requestrider
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status: [200]
`

// stubNucleiWriter installs a binary that reports one match for every staged
// template, so a chunked run can be verified without a real scan.
func stubNucleiWriter(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-stub.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		": > \"$out\"\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  id=$(basename \"$f\" .yaml)\n" +
		"  printf '{\"template-id\":\"%s\",\"template-path\":\"%s\",\"info\":{\"name\":\"%s\",\"author\":[\"requestrider\"],\"severity\":\"info\"},\"host\":\"http://target.test\",\"matched-at\":\"http://target.test/probe\"}\\n' \"$id\" \"$f\" \"$id\" >> \"$out\"\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

func chunkFiles(ids ...string) []UploadFile {
	files := make([]UploadFile, 0, len(ids))
	for _, id := range ids {
		files = append(files, UploadFile{
			Name:    id + ".yaml",
			Path:    id + ".yaml",
			Content: strings.ReplaceAll(chunkTemplate, "%s", id),
		})
	}
	return files
}

func TestStageNucleiUploadAccumulatesChunksIntoOneSession(t *testing.T) {
	stubNucleiWriter(t)
	ids := []string{"alpha", "bravo", "charlie", "delta", "echo"}

	// A whole folder arrives over several requests; every chunk after the first
	// reuses the session id. All of them must end up in one run.
	uploadID := ""
	for index, id := range ids {
		got, staged, total, err := StageNucleiUpload(uploadID, chunkFiles(id))
		if err != nil {
			t.Fatalf("chunk %d: %v", index, err)
		}
		if len(staged) != 1 {
			t.Fatalf("chunk %d staged %d files, want 1", index, len(staged))
		}
		if index == 0 {
			uploadID = got
			if got == "" {
				t.Fatal("first chunk did not return an upload id")
			}
		} else if got != uploadID {
			t.Fatalf("chunk %d returned a new upload id %q, want %q", index, got, uploadID)
		}
		if want := index + 1; total != want {
			t.Fatalf("chunk %d reported %d staged files, want %d", index, total, want)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run, err := RunNucleiUpload(ctx, uploadID, NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Templates) != len(ids) {
		t.Fatalf("run reported %d template rows, want %d: %#v", len(run.Templates), len(ids), run.Templates)
	}
	matched, _ := run.CountStatus(TemplateMatched)
	if matched != len(ids) {
		t.Fatalf("matched = %d, want %d", matched, len(ids))
	}
	for _, id := range ids {
		found := false
		for _, item := range run.Templates {
			if item.TemplateID == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("template %q missing from the run: %#v", id, run.Templates)
		}
	}
}

func TestRunNucleiUploadRejectsUnknownAndSecondUse(t *testing.T) {
	stubNucleiWriter(t)
	if _, err := RunNucleiUpload(context.Background(), "does-not-exist", NucleiRequest{URL: "http://target.test/"}); err == nil {
		t.Fatal("an unknown upload id was accepted")
	}
	uploadID, _, _, err := StageNucleiUpload("", chunkFiles("solo"))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := RunNucleiUpload(ctx, uploadID, NucleiRequest{URL: "http://target.test/"}); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := RunNucleiUpload(ctx, uploadID, NucleiRequest{URL: "http://target.test/"}); err == nil {
		t.Fatal("a consumed upload was replayed")
	}
}

func TestRunNucleiDirSurfacesFlagErrorsWrittenToStdout(t *testing.T) {
	// Nuclei reports a rejected flag on stdout, not stderr. A run must not
	// degrade to a bare "exit status 2" when the operator mistyped an option.
	stub := filepath.Join(t.TempDir(), "nuclei-badflag.sh")
	script := "#!/bin/sh\n" +
		"echo 'invalid value \"bogus\" for flag -pt' \n" +
		"exit 2\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	dir, staged, err := StageUploads([]UploadFile{{Name: "a.yaml", Content: validTemplate}})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	run, err := RunNucleiDir(context.Background(), dir, staged, NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("a non-zero exit must not discard the report: %v", err)
	}
	if run.Stats["exit_code"] != 2 {
		t.Fatalf("stats = %#v", run.Stats)
	}
	message, _ := run.Stats["stdout"].(string)
	if !strings.Contains(message, "not a valid") && !strings.Contains(message, "invalid value") {
		t.Fatalf("stdout diagnostics lost: %#v", run.Stats)
	}
}

func TestStageNucleiUploadRejectsEmptyChunk(t *testing.T) {
	if _, _, _, err := StageNucleiUpload("", nil); err == nil {
		t.Fatal("an empty chunk was accepted")
	}
}
