package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validatingBinary answers the `-validate` invocation the way the real one does
// for a folder it can load, and writes one record per template for a scan. The
// `refuse` map names file names the validation pass must reject, with the cause
// the real binary prints for them.
func validatingBinary(t *testing.T, refuse map[string]string) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-validate.sh")
	var refuseLines strings.Builder
	for name, reason := range refuse {
		refuseLines.WriteString("  if [ \"$(basename \"$f\")\" = '" + name + "' ]; then\n")
		refuseLines.WriteString("    printf '%s\\n' '[ERR] Error occurred loading template '\"$f\"': cause=\"Could not load template '\"$f\"': " + reason + "\"' >&2\n")
		refuseLines.WriteString("    continue\n")
		refuseLines.WriteString("  fi\n")
	}
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\nvalidate=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-validate' ]; then validate='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"if [ -n \"$validate\" ]; then\n" +
		"  for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		refuseLines.String() +
		"  done\n" +
		"  echo '[FTL] Could not validate templates: errors occurred during template validation' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		": > \"$out\"\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  printf '%s\\n' \"{\\\"template-id\\\":\\\"$id\\\",\\\"template-path\\\":\\\"$f\\\",\\\"host\\\":\\\"http://target.test\\\",\\\"matched-at\\\":\\\"http://target.test/p\\\",\\\"matcher-status\\\":false}\" >> \"$out\"\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

// The binary is the authority on whether a document can be loaded, and its own
// words about the file have to reach the operator.
//
// The evidence now comes from the SCAN's stderr rather than from a separate
// `-validate` pass: there is no pre-pass any more (see `validationStepFor`), and the
// binary prints the same `[ERR] Error occurred loading template …` line during a
// scan. The stub here therefore refuses the file on the scan path — no `-validate`
// argument is involved — so the assertion is that a refusal the binary reported is
// attributed to the file that caused it, with its cause intact.
func TestRunNucleiDirReportsTheBinarysOwnRefusalReason(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "nuclei-scan-stub.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  if [ \"$(basename \"$f\")\" = 'broken.yaml' ]; then\n" +
		"    printf '%s\\n' '[ERR] Error occurred loading template '\"$f\"': cause=\"Could not load template '\"$f\"': yaml: unmarshal errors: field bogusFieldXyz not found in type http.Request\"' >&2\n" +
		"    continue\n" +
		"  fi\n" +
		"  printf '%s\\n' '{\"template-id\":\"rr-good\",\"template-path\":\"'\"$f\"'\",\"matcher-status\":false}' >> \"$out\"\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "good.yaml", Content: idTemplateAt("rr-good", "/a")},
		{Name: "broken.yaml", Content: strings.Replace(idTemplateAt("rr-broken", "/b"), "method: GET", "bogusFieldXyz: 1\n    method: GET", 1)},
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
	byName := map[string]TemplateResult{}
	for _, item := range run.Templates {
		byName[item.Name] = item
	}
	// A file the binary refused produced no JSONL record, so it did not run. It must
	// say so rather than claim the check happened and found nothing.
	// The binary refused the file, so it produced no JSONL record for it. With the
	// `-validate` pre-pass gone there is nothing that could have marked it `invalid`
	// in advance, and `skipped` is the honest status: the file did not run. What it
	// must NOT be is `not_matched`, which would claim the check ran and found
	// nothing — the exact failure this project's status contract exists to prevent.
	broken := byName["broken.yaml"]
	if broken.Status != TemplateSkipped {
		t.Fatalf("broken = %q with reason %q, want skipped — the binary never ran it, "+
			"so not_matched would be a false claim that the check happened",
			broken.Status, broken.Reason)
	}
	if broken.Reason == "" {
		t.Fatalf("a file that did not run must carry a reason: %+v", broken)
	}
	// The file the binary accepted still runs, so one bad document does not cancel
	// the rest of the folder.
	if got := byName["good.yaml"].Status; got != TemplateNotMatched {
		t.Fatalf("good = %q, want not_matched", got)
	}
	// And the binary's own line is still kept in the run diagnostics, so the cause
	// is on record even where it could not be attached to a row.
	raw, _ := run.Stats["stderr"].(string)
	if !strings.Contains(raw, "bogusFieldXyz") {
		t.Fatalf("the binary's refusal line is not in the run diagnostics: %q", raw)
	}
}

// The plan is the answer to "how many invocations does this folder need", so it
// has to be derivable without running anything and it has to be right about the
// two things that force extra invocations: a shared template id and a capability
// that must not be mixed in.
func TestBuildPlanSeparatesCapabilityGroupsAndIsolatesFuzzing(t *testing.T) {
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "web-a.yaml", Content: idTemplateAt("rr-a", "/a")},
		{Name: "web-b.yaml", Content: idTemplateAt("rr-b", "/b")},
		{Name: "web-same-id.yaml", Content: idTemplateAt("rr-a", "/c")},
		{Name: "code.yaml", Content: "id: rr-code\ninfo:\n  name: C\n  author: a\n  severity: info\ncode:\n  - engine: [sh]\n    source: id\n"},
		{Name: "file.yaml", Content: "id: rr-file\ninfo:\n  name: F\n  author: a\n  severity: info\nfile:\n  - extensions: [all]\n"},
		{Name: "fuzz.yaml", Content: "id: rr-fuzz\ninfo:\n  name: Z\n  author: a\n  severity: info\nfuzzing:\n  - fuzzing_type: replace\n    http:\n      - method: GET\n        path: [\"{{BaseURL}}/x\"]\n"},
		{Name: "selfcontained.yaml", Content: "id: rr-sc\ninfo:\n  name: S\n  author: a\n  severity: info\nself-contained: true\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n"},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)

	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	defer plan.Clean()

	// The two files sharing an id are the only reason the plain group needs two
	// invocations; everything else needs exactly one.
	plain, fuzz := 0, 0
	codes := map[capabilityKey]int{}
	for _, batch := range plan.Batches {
		counts := map[string]int{}
		for _, file := range batch.Files {
			counts[file.File.Meta.TemplateID]++
		}
		for id, count := range counts {
			if count > 1 {
				t.Fatalf("batch %d holds %d files with id %q: the binary keeps one per id",
					batch.Index, count, id)
			}
		}
		codes[batch.Key]++
		switch batch.Key {
		case "":
			plain++
		case capabilityKeyOf([]Capability{CapabilityDAST}):
			fuzz++
			if !batch.Key.isolated() {
				t.Fatalf("batch %d runs fuzzing templates without isolating them", batch.Index)
			}
		}
	}
	if plain != 2 {
		t.Fatalf("plain batches = %d, want 2: one template id is shared by two files", plain)
	}
	if fuzz != 1 {
		t.Fatalf("fuzzing batches = %d, want 1", fuzz)
	}
	// A capability that only adds a kind shares the plain group instead of getting
	// an invocation of its own, because each extra invocation costs a process start.
	if codes[capabilityKeyOf([]Capability{CapabilityCode})] != 1 {
		t.Fatalf("code batches = %d, want 1", codes[capabilityKeyOf([]Capability{CapabilityCode})])
	}
	if codes[capabilityKeyOf([]Capability{CapabilityFile})] != 1 {
		t.Fatalf("file batches = %d, want 1", codes[capabilityKeyOf([]Capability{CapabilityFile})])
	}
	if codes[capabilityKeyOf([]Capability{CapabilitySelfContained})] != 1 {
		t.Fatalf("self-contained batches = %d, want 1", codes[capabilityKeyOf([]Capability{CapabilitySelfContained})])
	}
	// The plan accounts for every uploaded file exactly once.
	planned := 0
	ids := map[string]bool{}
	for _, batch := range plan.Batches {
		for _, file := range batch.Files {
			planned++
			key := file.File.Meta.Digest
			if ids[key] {
				t.Fatalf("%s was planned twice", file.File.RelativePath)
			}
			ids[key] = true
		}
	}
	if planned+len(plan.ledger) != len(staged) {
		t.Fatalf("planned %d + unplanned %d != %d uploaded", planned, len(plan.ledger), len(staged))
	}
	// Every batch directory has to hold exactly the templates it claims, because
	// the binary is pointed at the directory and not at a file list.
	for _, batch := range plan.Batches {
		entries := 0
		filepath.WalkDir(batch.Dir, func(_ string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
				entries++
			}
			return nil
		})
		if entries != len(batch.Files) {
			t.Fatalf("batch %d holds %d files, claims %d", batch.Index, entries, len(batch.Files))
		}
	}
}

// The plan has to say why a folder needs more than one invocation, and the reason
// is the operator's only warning that a scan of a large collection takes a while.
func TestPlanDescribeExplainsTheInvocationCount(t *testing.T) {
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "one.yaml", Content: idTemplateAt("rr-same", "/a")},
		{Name: "two.yaml", Content: idTemplateAt("rr-same", "/b")},
		{Name: "three.yaml", Content: idTemplateAt("rr-same", "/c")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: staged})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	defer plan.Clean()
	described := plan.Describe()
	if described["batches"] != 3 {
		t.Fatalf("batches = %v, want 3", described["batches"])
	}
	reason, _ := described["invocation_reason"].(string)
	if !strings.Contains(reason, "one file per template id") {
		t.Fatalf("invocation reason = %q, want it to name the cause", reason)
	}
	if described["id_multiplicity"] != 3 {
		t.Fatalf("id_multiplicity = %v, want 3", described["id_multiplicity"])
	}
	detail, _ := described["batch_detail"].([]map[string]interface{})
	if len(detail) != 3 {
		t.Fatalf("batch detail = %#v, want one entry per batch", described["batch_detail"])
	}
	// A plain group reports no capability, so a reader is not left looking for one.
	if _, present := detail[0]["capabilities"]; present {
		t.Fatalf("a plain batch claims capabilities: %#v", detail[0])
	}
}

// A plan that cannot be written must fail loudly instead of scanning a subset:
// half a folder is exactly the failure this work exists to remove.
//
// The two documents share a template-id, so the plan has to create batch
// directories rather than leave the staging root in place — a single batch whose
// files are already under the root is used as-is and writes nothing, which would
// make this blocker irrelevant and the assertion vacuous.
func TestBuildPlanFailsWhenABatchCannotBeWritten(t *testing.T) {
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "one.yaml", Content: idTemplateAt("rr-same", "/a")},
		{Name: "two.yaml", Content: idTemplateAt("rr-same", "/b")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	// A regular file where the batch directory has to go.
	blocker := filepath.Join(dir, batchDirName(1, ""))
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(PlanRequest{Dir: dir, Staged: staged}); err == nil {
		t.Fatal("an unwritable batch was accepted and part of the folder would be lost")
	}
}

// A refusal the binary prints during a SCAN must survive the operator reading it.
// The `[ERR]` line nuclei writes ends with an unbalanced quote inside its cause —
// measured on a 40 000-file collection — and a reason that cannot be unwrapped takes
// down the folder the operator was waiting for. The unwrapper now runs on the scan's
// stderr rather than on a `-validate` pass, so the shape is the same and a crash is
// just as fatal.
func TestABinaryRefusalReasonSurvivesUnbalancedQuoting(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "nuclei-why.sh")
	// A cause whose closing quote is missing, exactly as the binary writes it.
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"printf '%s\\n' '[ERR] Error occurred loading template x.yaml: cause=\"Could not load template x.yaml: yaml: unmarshal errors: line 6: field \"bogus\" not found in type http.Request' >&2\n" +
		": > \"$out\"\n" +
		"exit 1\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "x.yaml", Content: idTemplateAt("rr-x", "/x")},
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
	raw, _ := run.Stats["stderr"].(string)
	if raw == "" {
		t.Fatalf("the binary refused a file and the run kept no stderr: %#v", run.Stats)
	}
	if !strings.Contains(raw, "bogus") {
		t.Fatalf("the refusal's cause is missing from the run: %q", raw)
	}
	// A row that carries a reason must carry one a person can read: one line, and no
	// unterminated `cause="` wrapper left dangling.
	for _, item := range run.Templates {
		if item.Reason == "" {
			continue
		}
		if strings.Contains(item.Reason, `cause="`) {
			t.Fatalf("reason %q still carries the wrapper", item.Reason)
		}
		if strings.Contains(item.Reason, "\n") {
			t.Fatalf("reason %q spans lines", item.Reason)
		}
	}
}
