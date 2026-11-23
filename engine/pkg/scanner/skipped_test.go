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
		"out=''\ntemplates=''\nprev=''\nvalidate=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-validate' ]; then validate='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		// This stub accepts every document, which is what the real binary does for
		// a folder it can load: validation says nothing and exits 0.
		"if [ -n \"$validate\" ]; then exit 0; fi\n" +
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

// idTemplateAt is idTemplate with a path inside the request, so two documents can
// share a template id and still be different templates — which is exactly the
// situation a merged community collection produces.
func idTemplateAt(id, path string) string {
	return fmt.Sprintf(
		"id: %s\ninfo:\n  name: %s\n  author: requestrider\n  severity: info\n"+
			"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}%s\"\n"+
			"    matchers:\n      - type: status\n        status: [200]\n", id, id, path)
}

// TestRunNucleiDirRunsEveryFileThatSharesATemplateID is the fix for the largest
// silent loss. The binary loads exactly one file per template id and drops the
// rest without a word; measured on 382 396 unique documents there were 76 731 ids
// carrying more than one document. The plan therefore spreads the members of an id
// group across separate invocations, and every one of them runs.
func TestRunNucleiDirRunsEveryFileThatSharesATemplateID(t *testing.T) {
	dedupeStub(t)
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "alpha.yaml", Content: idTemplateAt("dup-id", "/alpha")},
		{Name: "beta.yaml", Content: idTemplateAt("other-id", "/beta")},
		{Name: "gamma.yaml", Content: idTemplateAt("dup-id", "/gamma")},
		{Name: "delta.yaml", Content: idTemplateAt("other-id", "/delta")},
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
	// Two ids, two members each: the plan needs two invocations and every file
	// has to come out of them as a template that ran.
	ran := 0
	for _, item := range run.Templates {
		if item.Status != TemplateNotMatched {
			t.Fatalf("%s has status %q with reason %q, want not_matched: a file that "+
				"shares a template id with another file must still be executed",
				item.Name, item.Status, item.Reason)
		}
		ran++
	}
	if ran != 4 {
		t.Fatalf("ran = %d, want 4", ran)
	}
	if run.Stats["batches"] != 2 {
		t.Fatalf("batches = %v, want 2 — the binary keeps one file per id", run.Stats["batches"])
	}
	if run.Stats["id_multiplicity"] != 2 {
		t.Fatalf("id multiplicity = %v, want 2", run.Stats["id_multiplicity"])
	}
	if run.Stats["skipped"] != 0 || run.Stats["executed"] != 4 {
		t.Fatalf("stats executed/skipped = %v/%v, want 4/0", run.Stats["executed"], run.Stats["skipped"])
	}
	if len(run.Findings) != 0 {
		t.Fatalf("findings = %#v, want none", run.Findings)
	}
	// The four files live in two invocations, two each, and no invocation holds
	// two files of the same id.
	invocations, _ := run.Stats["invocations"].([]map[string]interface{})
	if len(invocations) != 2 {
		t.Fatalf("invocations = %#v, want one entry per batch", run.Stats["invocations"])
	}
	byBatch := map[int][]string{}
	for _, item := range run.Templates {
		byBatch[item.Batch] = append(byBatch[item.Batch], item.TemplateID)
	}
	for batch, ids := range byBatch {
		seen := map[string]int{}
		for _, id := range ids {
			seen[id]++
		}
		for id, count := range seen {
			if count > 1 {
				t.Fatalf("batch %d holds %d files with id %q: the binary would drop them", batch, count, id)
			}
		}
	}
}

// argEchoStub records the flags it was given into the JSONL report file, so a
// test can prove the run asked the binary for the evidence it needs.
func argEchoStub(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-args.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\nvalidate=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-validate' ]; then validate='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"if [ -n \"$validate\" ]; then exit 0; fi\n" +
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
