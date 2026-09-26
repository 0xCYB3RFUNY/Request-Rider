package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validTemplate is a minimal document the real Nuclei engine accepts.
const validTemplate = `id: rr-demo-check
info:
  name: RR Demo Check
  author: requestrider
  severity: high
  tags: demo,rce
  classification:
    cve-id: CVE-2024-0001
    cwe-id: cwe-78
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status:
          - 200
`

// missingAuthorTemplate is the document that silently breaks a run: nuclei
// drops it as invalid_template and then exits 1 with no templates left.
const missingAuthorTemplate = `id: rr-no-author
info:
  name: RR No Author
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status:
          - 200
`

// stubNuclei installs a fake nuclei binary that echoes a JSONL finding for the
// template path it was asked to scan. Tests stay hermetic: the real binary
// never runs.
func stubNuclei(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-stub.sh")
	script := "#!/bin/sh\n" +
		"out=''\n" +
		"prev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"templates=''\n" +
		"prev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"first=$(find \"$templates\" -name '*.yaml' | sort | head -1)\n" +
		"if [ -z \"$first\" ]; then echo 'no templates provided for scan' >&2; exit 1; fi\n" +
		"printf '%s\\n' \"{\\\"template-id\\\":\\\"stub-check\\\",\\\"template-path\\\":\\\"$first\\\",\\\"info\\\":{\\\"name\\\":\\\"Stub Check\\\",\\\"author\\\":[\\\"requestrider\\\"],\\\"severity\\\":\\\"high\\\",\\\"classification\\\":{\\\"cve-id\\\":[\\\"CVE-2024-9999\\\"],\\\"cwe-id\\\":[\\\"cwe-79\\\"]}},\\\"matcher-name\\\":\\\"probe\\\",\\\"host\\\":\\\"http://target.test\\\",\\\"matched-at\\\":\\\"http://target.test/probe\\\",\\\"curl-command\\\":\\\"curl http://target.test/probe\\\",\\\"extracted-results\\\":[\\\"1.2.3\\\"]}\" > \"$out\"\n" +
		// The real binary writes a matcher-status record for every template it
		// executes, which is how the report tells "ran, no match" apart from
		// "never ran". The stub mirrors that for every remaining template.
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  if [ \"$f\" = \"$first\" ]; then continue; fi\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  printf '%s\\n' \"{\\\"template-id\\\":\\\"$id\\\",\\\"template-path\\\":\\\"$f\\\",\\\"host\\\":\\\"http://target.test\\\",\\\"matched-at\\\":\\\"http://target.test/probe\\\",\\\"matcher-status\\\":false}\" >> \"$out\"\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

func TestParseTemplateDocumentAcceptsCompleteTemplate(t *testing.T) {
	meta, reason := parseTemplateDocument(validTemplate)
	if reason != "" {
		t.Fatalf("valid template rejected: %s", reason)
	}
	if meta.TemplateID != "rr-demo-check" || meta.Severity != "HIGH" {
		t.Fatalf("meta = %#v", meta)
	}
	if len(meta.CVE) != 1 || meta.CVE[0] != "CVE-2024-0001" {
		t.Fatalf("cve = %#v", meta.CVE)
	}
	if len(meta.CWE) != 1 || meta.CWE[0] != "cwe-78" {
		t.Fatalf("cwe = %#v", meta.CWE)
	}
	if meta.Protocol != "http" {
		t.Fatalf("protocol = %q, want http", meta.Protocol)
	}
}

// A `code`, `file` or `javascript` template runs against the local machine, not
// against a URL. In a real nuclei-templates folder these are over a fifth of the
// set — 960 code, 447 file, 192 javascript against 14021 files — so the protocol
// has to be read from the document or the report credits the run with checks it
// never made.
func TestParseTemplateDocumentReadsTheProtocol(t *testing.T) {
	cases := map[string]string{
		"http":       "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n",
		"dns":        "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\ndns:\n  - name: \"{{FQDN}}\"\n    type: A\n",
		"network":    "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nnetwork:\n  - host: \"{{Host}}\"\n",
		"file":       "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nfile:\n  - extensions: [all]\n",
		"headless":   "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nheadless:\n  - steps: []\n",
		"ssl":        "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nssl:\n  - address: \"{{Host}}:443\"\n",
		"whois":      "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nwhois:\n  - query: \"{{Host}}\"\n",
		"code":       "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\ncode:\n  - engine:\n      - sh\n    source: |\n      id\n",
		"javascript": "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\njavascript:\n  - code: \"1+1\"\n",
	}
	for want, content := range cases {
		meta, reason := parseTemplateDocument(content)
		if reason != "" {
			t.Fatalf("%s template rejected: %s", want, reason)
		}
		if meta.Protocol != want {
			t.Fatalf("protocol = %q, want %q", meta.Protocol, want)
		}
	}
}

// A local template that ran must never be reported as a miss against the target.
// This is the exact case the operator hit: 7030 templates, every one of them
// "not matched", while the binary counted far fewer requests. The status is
// decided from the report plus the document's own protocol, so the two cannot
// disagree.
func TestRunNucleiDirNeverCallsALocalTemplateAMiss(t *testing.T) {
	localTemplate := func(id, protocol string) string {
		return fmt.Sprintf(
			"id: %s\ninfo:\n  name: %s\n  author: requestrider\n  severity: info\n%s:\n  - engine:\n      - sh\n    source: |\n      id\n",
			id, id, protocol)
	}
	// A stub that behaves like the real binary for local templates: it loads them
	// only when the flag is present, and writes no record of its own for them.
	stub := filepath.Join(t.TempDir(), "nuclei-local.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\ncode=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-code' ]; then code='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		": > \"$out\"\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  # A local template produces no record of its own, exactly like the real\n" +
		"  # binary, and a code template is not loaded at all without -code.\n" +
		"  if grep -qE '^(code|file|javascript):' \"$f\"; then\n" +
		"    if grep -q '^code:' \"$f\" && [ \"$code\" != 'yes' ]; then continue; fi\n" +
		"    continue\n" +
		"  fi\n" +
		"  printf '%s\\n' \"{\\\"template-id\\\":\\\"$id\\\",\\\"template-path\\\":\\\"$f\\\",\\\"host\\\":\\\"http://target.test\\\",\\\"matched-at\\\":\\\"http://target.test/p\\\",\\\"matcher-status\\\":false}\" >> \"$out\"\n" +
		"done\n" +
		"echo '[INF] Using Nuclei Engine Version: v3.11.1' >&2\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)

	dir, staged, err := StageUploads([]UploadFile{
		{Name: "targeting.yaml", Content: idTemplate("web-check")},
		{Name: "local.yaml", Content: localTemplate("local-shell", "code")},
		{Name: "reading.yaml", Content: localTemplate("local-file", "file")},
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

	byName := map[string]TemplateResult{}
	for _, item := range run.Templates {
		byName[item.Name] = item
	}
	if got := byName["targeting.yaml"].Status; got != TemplateNotMatched {
		t.Fatalf("an http template that ran = %q, want not_matched", got)
	}
	for _, name := range []string{"local.yaml", "reading.yaml"} {
		item, known := byName[name]
		if !known {
			t.Fatalf("%s has no row", name)
		}
		if item.Status == TemplateNotMatched {
			t.Fatalf("%s is a local template and must never be reported as a miss", name)
		}
		if item.Status != TemplateSkipped {
			t.Fatalf("%s = %q, want skipped: the stub loads no local template without its flag", name, item.Status)
		}
		if item.Reason == "" {
			t.Fatalf("%s was skipped without a reason", name)
		}
	}
	// The counts a reader sees must add up to the files handed in.
	matched, total := run.CountStatus(TemplateMatched)
	notMatched, _ := run.CountStatus(TemplateNotMatched)
	skipped, _ := run.CountStatus(TemplateSkipped)
	if matched+notMatched+skipped != total {
		t.Fatalf("statuses do not cover every file: %d+%d+%d != %d", matched, notMatched, skipped, total)
	}
}

// A file the binary never reported, where the reason is knowable from the
// document, is a template the type filter kept out. On the installed
// nuclei v10.4.9 a folder of only `code` templates makes the binary exit 1 with
// "no templates provided for scan", which without this would be reported per file
// as the opaque "Nuclei returned no record". Naming the missing flag is what
// makes the row actionable.
func TestUnmetProtocolReasonNamesTheMissingFlag(t *testing.T) {
	base := []string{"-duc", "-silent", "-u", "http://target.test/", "-ms", "-or"}

	for _, protocol := range []string{"code", "file", "headless"} {
		reason := unmetProtocolReason(&TemplateMeta{Protocol: protocol}, base)
		if reason == "" {
			t.Fatalf("%q must explain itself when its flag is absent", protocol)
		}
		if want := protocolsNeedingFlag[protocol].flag; !strings.Contains(reason, want) {
			t.Fatalf("%q reason must name %q: %s", protocol, want, reason)
		}
		// A type that needs `-pt` must warn that the flag replaces the default
		// set, because that is the trap that silently drops the web templates.
		if protocolsNeedingFlag[protocol].flag == "-pt" &&
			!strings.Contains(reason, "the default type set") {
			t.Fatalf("%q reason must explain that -pt replaces the default set: %s", protocol, reason)
		}
		if !strings.Contains(reason, protocol) {
			t.Fatalf("%q reason must name the protocol: %s", protocol, reason)
		}
	}

	// A type the binary loads by default has nothing to explain.
	if reason := unmetProtocolReason(&TemplateMeta{Protocol: "http"}, base); reason != "" {
		t.Fatalf("http needs no flag and must leave the generic message: %s", reason)
	}
	if reason := unmetProtocolReason(nil, base); reason != "" {
		t.Fatalf("a file with no parsed document has nothing to explain: %s", reason)
	}

	// An explicit type set is the operator's own choice, so a missing type there
	// is explained by the generic message instead of by a missing flag.
	withTypes := append(append([]string{}, base...), "-pt", "http")
	if reason := unmetProtocolReason(&TemplateMeta{Protocol: "code"}, withTypes); reason != "" {
		t.Fatalf("an explicit type set is the operator's choice: %s", reason)
	}
	// A type the operator did name is satisfied, and so is a mixed set containing
	// it — the flag is passed as one comma-separated value.
	for _, types := range []string{"http", "http,dns", "CODE"} {
		args := append(append([]string{}, base...), "-pt", types)
		if reason := unmetProtocolReason(&TemplateMeta{Protocol: "code"}, args); reason != "" {
			t.Fatalf("-pt %q is an explicit choice, not a missing flag: %s", types, reason)
		}
	}
	// `-code` and `-esc` both enable code templates outright.
	for _, flag := range []string{"-code", "-esc", "-enable-self-contained"} {
		args := append(append([]string{}, base...), flag)
		if reason := unmetProtocolReason(&TemplateMeta{Protocol: "code"}, args); reason != "" {
			t.Fatalf("%s enables code templates, so no explanation is needed: %s", flag, reason)
		}
	}
}

// Picking a folder means every file in it gets a chance to run. Nuclei does not
// load a `code` template on its own: a folder of only `code` files makes the
// binary exit 1 with "no templates provided for scan", and a mixed folder reports
// nothing for those files while the rest report normally. The flag comes from the
// chosen documents, and only from those, so a web-only folder keeps the exact
// command line it had.
//
// `file` and `headless` are deliberately not enabled. `-pt` *replaces* the
// binary's default type set — measured: `-pt file` on a folder that also holds an
// `http` template loads nothing and exits 1 — and even when loaded they write no
// record at all for a URL target, so the flag would buy a silently empty run.
func TestBuildNucleiArgsLoadsTheTypesTheChosenFilesNeed(t *testing.T) {
	web, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []string{"http", "dns", "ssl", "javascript"},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(web, "-pt") {
		t.Fatalf("a folder of types nuclei loads by default needs no type flag: %v", web)
	}
	if hasArg(web, "-code") {
		t.Fatalf("-code runs local commands and must never be inferred for web templates: %v", web)
	}

	// A `javascript` template loads on its own, so naming it must not add
	// anything: a `-pt` here would drop every type it does not list.
	for _, protocol := range []string{"javascript", "dns", "ssl", "network", "http"} {
		args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
			Protocols: []string{protocol},
		})
		if err != nil {
			t.Fatalf("build args: %v", err)
		}
		if hasArg(args, "-pt") || hasArg(args, "-code") {
			t.Fatalf("%q loads without a flag, so the run must be untouched: %v", protocol, args)
		}
	}

	local, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []string{"http", "code", "file", "javascript"},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if !hasArg(local, "-code") {
		t.Fatalf("a chosen code template must be loaded: %v", local)
	}
	// `file` needs `-pt`, and `-pt` would cost every other type. It is reported
	// as `no_request` with the flag named instead of silently narrowing the run.
	if hasArg(local, "-pt") {
		t.Fatalf("-pt replaces the default type set and must stay out of a run: %v", local)
	}

	// An explicit type set is the operator's decision and is never widened.
	explicit, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []string{"http", "code"},
		Options:   NucleiOptions{Types: []string{"http"}},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(explicit, "-code") {
		t.Fatalf("an explicit type set must not gain flags behind the operator's back: %v", explicit)
	}
	if value := argValue(t, explicit, "-pt"); value != "http" {
		t.Fatalf("-pt = %q, want exactly what was asked for", value)
	}

	// Naming the type is the one case where the flag belongs: the operator asked
	// for it, so the run has to be able to load it.
	named, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []string{"http", "code"},
		Options:   NucleiOptions{Types: []string{"http", "code"}},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if !hasArg(named, "-code") {
		t.Fatalf("a type the operator named has to be loadable: %v", named)
	}
}

// The reason a request-less template was not checked has to name the flag that
// would load it, otherwise the report leaves the operator guessing. Measured
// against the installed binary: `code` loads with `-code` alone, `file` needs a
// type set that then has to name every other type too, and `headless` needs the
// browser engine rather than plain HTTP.
func TestProtocolsNeedingFlagMatchesTheMeasuredBinary(t *testing.T) {
	for _, loaded := range []string{"http", "dns", "ssl", "network", "javascript"} {
		if _, known := ProtocolsNeedingFlag[loaded]; known {
			t.Fatalf("%q loads without a flag, so naming it would shrink the run", loaded)
		}
	}
	for _, needs := range []string{"code", "file", "headless"} {
		if _, known := ProtocolsNeedingFlag[needs]; !known {
			t.Fatalf("%q does not load without a flag", needs)
		}
	}
}

// The three protocols that never address a target are the ones a URL scan cannot
// say anything about, and that set is what decides the `no_request` status.
func TestRequestLessProtocolsCoverExactlyTheLocalOnes(t *testing.T) {
	for _, protocol := range []string{"code", "file", "javascript"} {
		if !requestLessProtocols[protocol] {
			t.Fatalf("%q must be reported as checking no URL", protocol)
		}
	}
	// Everything that does talk to the target has to stay a normal result, or a
	// real check would be reported as "checked no URL".
	for _, protocol := range []string{"http", "dns", "network", "headless", "ssl", "websocket", "whois", "multipart"} {
		if requestLessProtocols[protocol] {
			t.Fatalf("%q addresses a target and must stay a normal result", protocol)
		}
	}
	// `file`, `code` and `javascript` are all request blocks and all inspect the
	// local machine, so the two lists are expected to meet on exactly those three
	// and nowhere else.
	overlap := 0
	for _, protocol := range protocolBlocks {
		if requestLessProtocols[protocol] {
			overlap++
		}
	}
	if overlap != 3 {
		t.Fatalf("expected exactly three overlapping protocols, got %d", overlap)
	}
}

func TestParseTemplateDocumentExplainsRejections(t *testing.T) {
	cases := map[string]struct {
		content string
		want    string
	}{
		"missing author": {missingAuthorTemplate, "info.author"},
		"missing id":     {"info:\n  name: X\n  author: a\n  severity: info\nhttp: []\n", "top-level id"},
		"missing name":   {"id: x\ninfo:\n  author: a\n  severity: info\nhttp: []\n", "info.name"},
		"bad severity":   {"id: x\ninfo:\n  name: X\n  author: a\n  severity: nasty\nhttp: []\n", "info.severity"},
		"no requests":    {"id: x\ninfo:\n  name: X\n  author: a\n  severity: info\n", "request block"},
		"broken yaml":    {"id: [unclosed\n", "invalid YAML"},
	}
	for name, testCase := range cases {
		meta, reason := parseTemplateDocument(testCase.content)
		if meta != nil {
			t.Fatalf("%s: accepted %+v", name, meta)
		}
		if !strings.Contains(reason, testCase.want) {
			t.Fatalf("%s: reason %q does not mention %q", name, reason, testCase.want)
		}
	}
}

func TestStageUploadsKeepsFolderLayoutAndReportsPerFile(t *testing.T) {
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "a.yaml", Path: "http/cves/2024/CVE-2024-1.yaml", Content: validTemplate},
		{Name: "a.yaml", Path: "ssl/other/CVE-2024-1.yaml", Content: validTemplate},
		{Name: "b.yaml", Content: missingAuthorTemplate},
		{Name: "notes.txt", Content: "ignored"},
		{Name: "empty.yaml", Content: "  "},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	if len(staged) != 5 {
		t.Fatalf("staged = %d results, want 5", len(staged))
	}
	if staged[0].StagedPath != filepath.Join(dir, "http/cves/2024/CVE-2024-1.yaml") {
		t.Fatalf("first path = %q", staged[0].StagedPath)
	}
	if staged[0].StagedPath == staged[1].StagedPath {
		t.Fatal("same basename in different directories collided")
	}
	if _, err := os.Stat(staged[1].StagedPath); err != nil {
		t.Fatalf("second template not staged: %v", err)
	}
	for _, index := range []int{2, 3, 4} {
		if staged[index].Meta != nil || staged[index].Reason == "" {
			t.Fatalf("staged[%d] = %+v, want a rejection reason", index, staged[index])
		}
	}
}

func TestStageUploadsRejectsTraversal(t *testing.T) {
	dir, _, err := StageUploads([]UploadFile{{Name: "x.yaml", Path: "../../etc/x.yaml", Content: validTemplate}})
	if err == nil {
		os.RemoveAll(dir)
		t.Fatal("path traversal was accepted")
	}
	if _, _, err := StageUploads(nil); err == nil {
		t.Fatal("empty upload set was accepted")
	}
}

func TestRunNucleiDirAttributesFindingsToFiles(t *testing.T) {
	stubNuclei(t)
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "a.yaml", Path: "http/CVE-2024-1.yaml", Content: validTemplate},
		{Name: "b.yaml", Path: "dns/detect.yaml", Content: validTemplate},
		{Name: "c.yaml", Content: missingAuthorTemplate},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: "http://target.test/", Tags: []string{"demo"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Templates) != 3 {
		t.Fatalf("templates = %d, want 3", len(run.Templates))
	}
	// The stub reports a match for the alphabetically first staged template, so
	// the expectation is derived from the staged paths rather than hard-coded:
	// this is what proves attribution happens through the template path.
	wantMatched := 0
	for index, file := range staged {
		if filepath.Base(file.StagedPath) == "detect.yaml" {
			wantMatched = index
		}
	}
	matched, _ := run.CountStatus(TemplateMatched)
	if matched != 1 {
		t.Fatalf("matched = %d, want 1", matched)
	}
	hit := run.Templates[wantMatched]
	if hit.Status != TemplateMatched || hit.Matches != 1 {
		t.Fatalf("attributed template = %+v, want one match", hit)
	}
	if len(hit.CVE) != 1 || hit.CVE[0] != "CVE-2024-0001" {
		t.Fatalf("template CVE not reported: %+v", hit)
	}
	if len(hit.Findings) != 1 || hit.Findings[0]["template_id"] != "stub-check" {
		t.Fatalf("per-file findings = %+v", hit.Findings)
	}
	notMatched, _ := run.CountStatus(TemplateNotMatched)
	invalid, _ := run.CountStatus(TemplateInvalid)
	if notMatched != 1 || invalid != 1 {
		t.Fatalf("per-file statuses = matched %d, not_matched %d, invalid %d", matched, notMatched, invalid)
	}
	if run.Templates[2].Status != TemplateInvalid || run.Templates[2].Reason == "" {
		t.Fatalf("third template = %+v, want invalid with a reason", run.Templates[2])
	}
	if len(run.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(run.Findings))
	}
	finding := run.Findings[0]
	if finding["template_id"] != "stub-check" || finding["severity"] != "HIGH" {
		t.Fatalf("finding = %#v", finding)
	}
	if finding["matcher_name"] != "probe" || finding["curl_command"] == "" {
		t.Fatalf("evidence fields missing: %#v", finding)
	}
	if cve, ok := finding["cve"].([]string); !ok || len(cve) != 1 || cve[0] != "CVE-2024-9999" {
		t.Fatalf("finding CVE missing: %#v", finding)
	}
	if run.Stats["matched"] != 1 {
		t.Fatalf("stats = %#v", run.Stats)
	}
	if run.Stats["invalid"] != 1 || run.Stats["not_matched"] != 1 {
		t.Fatalf("per-file stats missing: %#v", run.Stats)
	}
}

func TestRunNucleiDirSurfacesBinaryDiagnostics(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "nuclei-fail.sh")
	script := "#!/bin/sh\n" +
		"echo \"\\033[31mFTL\\033[0m Could not run nuclei: no templates provided for scan\" >&2\n" +
		"exit 1\n"
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
	if run.Stats["exit_status"] != "failed" || run.Stats["exit_code"] != 1 {
		t.Fatalf("stats = %#v", run.Stats)
	}
	message, _ := run.Stats["stderr"].(string)
	if !strings.Contains(message, "no templates provided for scan") {
		t.Fatalf("stderr not reported: %#v", run.Stats)
	}
	if strings.Contains(message, "\x1b") {
		t.Fatalf("ANSI escapes survived: %q", message)
	}
}

func TestRunNucleiDirRejectsBadInput(t *testing.T) {
	stubNuclei(t)
	dir, staged, err := StageUploads([]UploadFile{{Name: "a.yaml", Content: validTemplate}})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	ctx := context.Background()
	if _, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: ""}); err == nil {
		t.Fatal("empty target was accepted")
	}
	if _, err := RunNucleiDir(ctx, "", staged, NucleiRequest{URL: "http://target.test/"}); err == nil {
		t.Fatal("empty directory was accepted")
	}
	if _, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: "http://target.test/", Severity: []string{"nonsense"}}); err == nil {
		t.Fatal("invalid severity was accepted")
	}
	_, invalid, err := StageUploads([]UploadFile{{Name: "a.yaml", Content: missingAuthorTemplate}})
	if err != nil {
		t.Fatalf("stage invalid: %v", err)
	}
	skipped, err := RunNucleiDir(ctx, dir, invalid, NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("an all-invalid upload must be reported, not errored: %v", err)
	}
	if skipped.Stats["exit_status"] != "skipped" {
		t.Fatalf("stats = %#v", skipped.Stats)
	}
	if len(skipped.Templates) != 1 || skipped.Templates[0].Reason == "" {
		t.Fatalf("per-file reason lost: %#v", skipped.Templates)
	}
}

func TestRunNucleiDirPropagatesCancellation(t *testing.T) {
	// A route switch cancels the context. A killed process also reports an
	// *exec.ExitError, so the run must surface the cancellation instead of
	// passing a non-zero exit off as an ordinary scan result.
	stub := filepath.Join(t.TempDir(), "nuclei-hang.sh")
	script := "#!/bin/sh\n" +
		"sleep 30\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	dir, staged, err := StageUploads([]UploadFile{{Name: "a.yaml", Content: validTemplate}})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: "http://target.test/"})
	if err == nil {
		t.Fatalf("a cancelled run was reported as a result: %#v", run.Stats)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context cancellation", err)
	}
}

func TestRunNucleiDirIgnoresMatcherStatusFailures(t *testing.T) {
	// With -ms Nuclei writes a record for every executed template, including
	// matcher failures marked "matcher-status": false. Those are not findings
	// and must never reach the report.
	stub := filepath.Join(t.TempDir(), "nuclei-ms.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"real=\"$templates/real.yaml\"\n" +
		"failed=\"$templates/failed.yaml\"\n" +
		"printf '%s\\n' " +
		"'{\"template-id\":\"real-hit\",\"template-path\":\"'\"$real\"'\",\"info\":{\"name\":\"Real\",\"severity\":\"high\"},\"matcher-name\":\"probe\",\"host\":\"http://target.test\",\"matched-at\":\"http://target.test/a\",\"matcher-status\":true}' " +
		"'{\"template-id\":\"ran-but-failed\",\"template-path\":\"'\"$failed\"'\",\"info\":{\"name\":\"Failed\",\"severity\":\"critical\"},\"type\":\"http\",\"host\":\"127.0.0.1\",\"url\":\"http://127.0.0.1/\",\"matcher-status\":false}' " +
		"'{not json at all}' " +
		"> \"$out\"\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.yaml"), []byte(validTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "failed.yaml"), []byte(validTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := []StagedFile{
		{UploadName: "real.yaml", StagedPath: filepath.Join(dir, "real.yaml"), Meta: &TemplateMeta{TemplateID: "real-hit", Severity: "HIGH"}},
		{UploadName: "failed.yaml", StagedPath: filepath.Join(dir, "failed.yaml"), Meta: &TemplateMeta{TemplateID: "ran-but-failed", Severity: "CRITICAL"}},
	}
	run, err := RunNucleiDir(context.Background(), dir, staged, NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Findings) != 1 || run.Findings[0]["template_id"] != "real-hit" {
		t.Fatalf("matcher failures leaked into findings: %#v", run.Findings)
	}
	if run.Templates[1].Status != TemplateNotMatched {
		t.Fatalf("failed matcher reported as matched: %#v", run.Templates[1])
	}
	if run.Stats["matched"] != 1 || run.Stats["not_matched"] != 1 {
		t.Fatalf("stats = %#v", run.Stats)
	}
}

func TestRunNucleiRequiresConfiguredBinary(t *testing.T) {
	t.Setenv("RR_NUCLEI_BINARY", "/nonexistent-nuclei-binary")
	dir, staged, err := StageUploads([]UploadFile{{Name: "a.yaml", Content: validTemplate}})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: "http://target.test/"}); err == nil {
		t.Fatal("missing binary was accepted")
	}
}
