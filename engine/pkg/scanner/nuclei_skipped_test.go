package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dedupeStub mimics the real binary's template-id deduplication: it loads one
// file per id, in path order, and writes a matcher-status record for each
// template it actually executed.
func dedupeStub(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-dedupe.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		": > \"$out\"\n" +
		"seen=''\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  case \" $seen \" in *\" $id \"*) continue ;; esac\n" +
		"  seen=\"$seen $id\"\n" +
		"  printf '%s\\n' \"{\\\"template-id\\\":\\\"$id\\\",\\\"template-path\\\":\\\"$f\\\",\\\"host\\\":\\\"http://target.test\\\",\\\"matched-at\\\":\\\"http://target.test/p\\\",\\\"matcher-status\\\":false}\" >> \"$out\"\n" +
		"done\n" +
		"echo '[INF] Using Nuclei Engine Version: v3.11.1' >&2\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

func idTemplate(id string) string {
	return fmt.Sprintf(
		"id: %s\ninfo:\n  name: %s\n  author: requestrider\n  severity: info\n"+
			"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/p\"\n"+
			"    matchers:\n      - type: status\n        status: [200]\n", id, id)
}

func TestRunNucleiDirReportsDuplicateTemplateIDsAsSkipped(t *testing.T) {
	// Three files declare the same id as an earlier file. Nuclei loads one file
	// per id, so the later ones never run and the report has to say so instead
	// of claiming they were scanned and matched nothing.
	dedupeStub(t)
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "alpha.yaml", Content: idTemplate("dup-id")},
		{Name: "beta.yaml", Content: idTemplate("other-id")},
		{Name: "gamma.yaml", Content: idTemplate("dup-id")},
		{Name: "delta.yaml", Content: idTemplate("other-id")},
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
	if len(run.Templates) != 4 {
		t.Fatalf("templates = %d, want one row per uploaded file", len(run.Templates))
	}
	ran, skipped := 0, 0
	for _, item := range run.Templates {
		switch item.Status {
		case TemplateNotMatched:
			ran++
		case TemplateSkipped:
			skipped++
			if item.Reason == "" {
				t.Fatalf("%s was skipped without a reason", item.Name)
			}
		default:
			t.Fatalf("%s has status %q, want not_matched or skipped", item.Name, item.Status)
		}
	}
	if ran != 2 || skipped != 2 {
		t.Fatalf("ran = %d, skipped = %d, want 2 and 2", ran, skipped)
	}
	// The reason names the file that kept the id, so the operator can act on it.
	gamma := run.Templates[2]
	if !strings.Contains(gamma.Reason, "alpha.yaml") || !strings.Contains(gamma.Reason, "dup-id") {
		t.Fatalf("gamma reason = %q, want it to name alpha.yaml and the id", gamma.Reason)
	}
	delta := run.Templates[3]
	if !strings.Contains(delta.Reason, "beta.yaml") {
		t.Fatalf("delta reason = %q, want it to name beta.yaml", delta.Reason)
	}
	if len(run.Findings) != 0 {
		t.Fatalf("findings = %#v, want none", run.Findings)
	}
	if run.Stats["executed"] != 2 || run.Stats["skipped"] != 2 {
		t.Fatalf("stats executed/skipped = %v/%v, want 2/2", run.Stats["executed"], run.Stats["skipped"])
	}
}

// argEchoStub records the flags it was given into the JSONL report file, so a
// test can prove the run asked the binary for the evidence it needs.
func argEchoStub(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-args.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"f=$(find \"$templates\" -name '*.yaml' | sort | head -1)\n" +
		"id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"printf '%s\\n' \"{\\\"template-id\\\":\\\"$id\\\",\\\"template-path\\\":\\\"$f\\\",\\\"matcher-status\\\":false}\" > \"$out\"\n" +
		"echo \"$*\" >&2\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

func TestRunNucleiDirAlwaysRequestsMatcherStatusRecords(t *testing.T) {
	// Without -ms the binary writes a record only for templates that matched,
	// so the report could not tell "ran and matched nothing" from "never ran".
	// The flag is therefore part of the run, not an option the caller may skip.
	argEchoStub(t)
	dir, staged, err := StageUploads([]UploadFile{{Name: "solo.yaml", Content: idTemplate("solo")}})
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
	args := fmt.Sprint(run.Stats["args"])
	if !strings.Contains(args, " -ms ") {
		t.Fatalf("args = %q, want -ms so the report can prove what ran", args)
	}
	if run.Templates[0].Status != TemplateNotMatched {
		t.Fatalf("status = %q, want not_matched from the matcher-status record", run.Templates[0].Status)
	}
}

func TestRunNucleiDirKeepsBinaryOutputOnSuccess(t *testing.T) {
	// A successful run still has to carry the binary's own output: it is the
	// evidence for anything the operator has to judge later.
	dedupeStub(t)
	dir, staged, err := StageUploads([]UploadFile{{Name: "solo.yaml", Content: idTemplate("solo")}})
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
	if run.Stats["exit_status"] != "ok" {
		t.Fatalf("exit status = %v", run.Stats["exit_status"])
	}
	if !strings.Contains(fmt.Sprint(run.Stats["stderr"]), "Using Nuclei Engine Version") {
		t.Fatalf("stderr = %v, want the binary's own log lines", run.Stats["stderr"])
	}
	if args, ok := run.Stats["args"].([]string); !ok || len(args) == 0 {
		t.Fatalf("args = %#v, want the exact flags the run used", run.Stats["args"])
	}
	if run.Templates[0].Status != TemplateNotMatched {
		t.Fatalf("status = %q, want not_matched", run.Templates[0].Status)
	}
}
