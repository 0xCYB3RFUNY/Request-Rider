package scanner

import (
	"context"
	"encoding/base64"
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
		"validate=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-validate' ]; then validate='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		// Validation is a separate invocation with no -o. This stub accepts every
		// document, so it answers with silence and exit 0, which is what the real
		// binary does for a folder it can load.
		"if [ -n \"$validate\" ]; then exit 0; fi\n" +
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

// `code` and `file` templates use local capabilities. JavaScript is different:
// the same block may use local helpers or make a target-facing protocol call, so
// its behavior must be read from the script rather than inferred from the type.
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

// A document whose only request section is one the old scanner did not know about
// was rejected outright and never staged. Measured on the 382 396 unique
// documents of a merged community collection, that cost 59 829 templates:
// 39 617 legacy `requests`, 15 694 `tcp` and 489 `workflows`. The block list now
// comes from the binary's own parser, so a section it reads is a section we read.
func TestParseTemplateDocumentAcceptsEveryBlockTheBinaryReads(t *testing.T) {
	cases := map[string]struct {
		content string
		// protocol is the type a JSONL record reports for the block.
		protocol string
		// capabilities are the flags the document needs to be loaded.
		capabilities []Capability
	}{
		"http": {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n", protocol: "http"},
		// The deprecated spelling of `http`. nuclei v3.11.1 parses it and reports
		// the result as type=http, which the earlier block list did not know.
		"requests": {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nrequests:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n", protocol: "http"},
		"dns":      {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\ndns:\n  - name: \"{{FQDN}}\"\n    type: A\n", protocol: "dns"},
		// `tcp` is what `network` was renamed to, and it is the spelling 15 694 of
		// the collected documents actually use.
		"tcp":             {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\ntcp:\n  - host: [\"{{Host}}\"]\n", protocol: "tcp"},
		"network":         {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nnetwork:\n  - host: [\"{{Host}}\"]\n", protocol: "network"},
		"ssl":             {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nssl:\n  - address: \"{{Host}}:443\"\n", protocol: "ssl"},
		"websocket":       {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nwebsocket:\n  - host: \"{{Host}}\"\n", protocol: "websocket"},
		"whois":           {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nwhois:\n  - query: \"{{Host}}\"\n", protocol: "whois"},
		"headless":        {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nheadless:\n  - steps: []\n", protocol: "headless", capabilities: []Capability{CapabilityHeadless}},
		"code":            {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\ncode:\n  - engine: [sh]\n    source: |\n      id\n", protocol: "code", capabilities: []Capability{CapabilityCode}},
		"file":            {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nfile:\n  - extensions: [all]\n", protocol: "file", capabilities: []Capability{CapabilityFile}},
		"javascript":      {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\njavascript:\n  - code: \"1+1\"\n", protocol: "javascript"},
		"fuzzing":         {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nfuzzing:\n  - fuzzing_type: replace\n    http:\n      - method: GET\n        path: [\"{{BaseURL}}/x\"]\n", protocol: "fuzzing", capabilities: []Capability{CapabilityDAST}},
		"workflows":       {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nworkflows:\n  - template: other.yaml\n", protocol: "workflow"},
		"self-contained":  {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nself-contained: true\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n", protocol: "http", capabilities: []Capability{CapabilitySelfContained}},
		"global matchers": {content: "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nglobal-matchers: true\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n", protocol: "http", capabilities: []Capability{CapabilityGlobalMatchers}},
		// A document can mix sections; the first in the documented order names the
		// protocol and every section travels with the row.
		"http plus code": {
			content:      "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\ncode:\n  - engine: [sh]\n    source: id\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n",
			protocol:     "http",
			capabilities: []Capability{CapabilityCode},
		},
	}
	for name, testCase := range cases {
		meta, reason := parseTemplateDocument(testCase.content)
		if reason != "" {
			t.Fatalf("%s: rejected a block nuclei reads: %s", name, reason)
		}
		if meta.Protocol != testCase.protocol {
			t.Fatalf("%s: protocol = %q, want %q", name, meta.Protocol, testCase.protocol)
		}
		if name == "code" {
			if meta.Requestless() == false {
				t.Fatal("a code template must be reported as running without a target request")
			}
			args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
				Protocols: meta.Capabilities,
			})
			if err != nil {
				t.Fatalf("build code-template args: %v", err)
			}
			if !hasArg(args, "-code") {
				t.Fatalf("a parsed code template must launch with -code: %v", args)
			}
		}
		if len(meta.Capabilities) != len(testCase.capabilities) {
			t.Fatalf("%s: capabilities = %#v, want %#v", name, meta.Capabilities, testCase.capabilities)
		}
		for index, capability := range testCase.capabilities {
			if meta.Capabilities[index] != capability {
				t.Fatalf("%s: capabilities = %#v, want %#v", name, meta.Capabilities, testCase.capabilities)
			}
		}
		if len(meta.BlockKeys) == 0 {
			t.Fatalf("%s: no block keys recorded", name)
		}
		if meta.Digest == "" {
			t.Fatalf("%s: no content digest recorded", name)
		}
	}
}

// A YAML file in a templates tree is not always a template. A merged community
// collection carries GitHub issue forms, CI configs and nuclei template profiles
// next to the templates, and calling those "no request block" sends the operator
// looking for an `http:` that was never supposed to be there.
func TestParseTemplateDocumentNamesNonTemplateFiles(t *testing.T) {
	cases := map[string]struct {
		content string
		path    string
		want    string
	}{
		"profile by selection": {
			content: "templates:\n  - http/cves/2024/\ntags:\n  - cve\n",
			path:    "profiles/pentest.yml",
			want:    "template profile",
		},
		"profile by location": {
			content: "templates:\n  - ssl/\n",
			path:    "profiles/recommended.yml",
			want:    "template profile",
		},
		"github issue form": {
			content: "name: Bug report\nbody: []\nlabels: []\n",
			path:    ".github/ISSUE_TEMPLATE/config.yml",
			want:    "repository configuration file",
		},
		"unknown yaml": {
			content: "alpha: 1\nbeta: 2\n",
			path:    "misc/notes.yaml",
			want:    "not a nuclei template",
		},
	}
	for name, testCase := range cases {
		meta, reason := parseTemplateDocumentWithPath(testCase.content, testCase.path)
		if meta != nil {
			t.Fatalf("%s: accepted %+v", name, meta)
		}
		if !strings.Contains(reason, testCase.want) {
			t.Fatalf("%s: reason %q does not mention %q", name, reason, testCase.want)
		}
	}
	// A real template that merely forgot its id is still a broken template, not a
	// profile: sending the operator to a profile they did not upload would be a
	// worse answer than naming the missing key.
	if _, reason := parseTemplateDocumentWithPath("http:\n  - method: GET\n", "http/x.yaml"); !strings.Contains(reason, "top-level id") {
		t.Fatalf("a template without an id must be reported as such, got %q", reason)
	}
}

// A local template that ran must never be reported as a miss against the target.
// This is the exact case the operator hit: thousands of templates, every one of
// them "not matched", while the binary counted far fewer requests. The status is
// decided from the report plus the document's own section, so the two cannot
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

// A capability is an opt-in template kind, and the binary documents one flag per
// capability. Those flags *widen* a run — they add a kind and leave the default
// type set alone — which is what makes deriving them from the selected documents
// safe. `-dast` is the exception and is never added to a shared invocation.
func TestCapabilityFlagIsTheDocumentedFlagForEachCapability(t *testing.T) {
	want := map[Capability]string{
		CapabilityCode:           "-code",
		CapabilityFile:           "-file",
		CapabilityHeadless:       "-headless",
		CapabilityDAST:           "-dast",
		CapabilityGlobalMatchers: "-egm",
		CapabilitySelfContained:  "-esc",
	}
	for capability, flag := range want {
		if capabilityFlag[capability] != flag {
			t.Fatalf("%q maps to %q, want %q", capability, capabilityFlag[capability], flag)
		}
		// Every capability must be reachable from the evaluation order, or a
		// document requiring it would silently get no flag.
		found := false
		for _, known := range allCapabilities {
			if known == capability {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q is missing from allCapabilities", capability)
		}
	}
	// The isolated capability is the one that aborts a run it does not belong to,
	// and it must never appear in a flag set a shared invocation uses.
	if isolatedCapability != CapabilityDAST {
		t.Fatalf("isolated capability = %q, want the measured -dast", isolatedCapability)
	}
	for _, arg := range isolatedFreeFlags(allCapabilities) {
		if arg == capabilityFlag[isolatedCapability] {
			t.Fatalf("%s must not be added to a shared invocation: %v", arg, arg)
		}
	}
	// A key that carries the isolated capability is flagged as its own group, so
	// the plan cannot put it next to anything else.
	if !capabilityKeyOf([]Capability{CapabilityDAST}).isolated() {
		t.Fatal("a fuzzing group must be isolated")
	}
	if capabilityKeyOf([]Capability{CapabilityCode, CapabilityFile}).isolated() {
		t.Fatal("a code+file group must not be isolated")
	}
}

// A selected folder category is a filesystem filter, not a Nuclei protocol-type
// flag. Execution capabilities come from the templates that remain in that
// category, while `-pt` is never emitted because it replaces Nuclei's defaults.
func TestBuildNucleiArgsUsesCapabilitiesWithoutProtocolTypeFilter(t *testing.T) {
	web, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(web, "-pt") {
		t.Fatalf("a folder of types nuclei loads by default needs no type flag: %v", web)
	}
	if hasArg(web, "-code") || hasArg(web, "-file") || hasArg(web, "-headless") {
		t.Fatalf("a web-only folder must gain no capability flag: %v", web)
	}

	// Each capability the documents asked for is added, and nothing else is.
	for _, capability := range allCapabilities {
		request := NucleiRequest{Protocols: []Capability{capability}}
		if capability == isolatedCapability {
			request.IsolatedProtocol = capability
		}
		args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
			Protocols:        request.Protocols,
			IsolatedProtocol: request.IsolatedProtocol,
		})
		if err != nil {
			t.Fatalf("build args for %s: %v", capability, err)
		}
		flag := capabilityFlag[capability]
		if !hasArg(args, flag) {
			t.Fatalf("%s was required and not added: %v", flag, args)
		}
		if hasArg(args, "-pt") {
			t.Fatalf("-pt replaces the default type set and must stay out of a run: %v", args)
		}
	}

	// Several capabilities combine into one command line.
	mixed, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []Capability{CapabilityCode, CapabilityFile, CapabilitySelfContained, CapabilityDAST},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	for _, flag := range []string{"-code", "-file", "-esc"} {
		if !hasArg(mixed, flag) {
			t.Fatalf("%s was required and not added: %v", flag, mixed)
		}
	}
	if hasArg(mixed, "-dast") || hasArg(mixed, "-pt") {
		t.Fatalf("an isolated capability must not be mixed into a shared run: %v", mixed)
	}

	if value := argValue(t, web, "-target"); value != "http://target.test/" {
		t.Fatalf("-target = %q, want the selected target", value)
	}
	if value := argValue(t, web, "-t"); value != "/tmp/staged" {
		t.Fatalf("-t = %q, want the absolute selected-category directory", value)
	}
}

// The sections that never address a target are the ones a URL scan cannot say
// anything about, and that set is what decides the `no_request` status. It is
// read from the document, not from a hard-coded list, so a section the binary
// added later cannot be silently reported as "checked the target".
func TestRequestlessSectionsCoverExactlyTheLocalOnes(t *testing.T) {
	local := []string{"code", "file"}
	for _, key := range local {
		block, known := blockByKey[key]
		if !known {
			t.Fatalf("%q is not a known section", key)
		}
		if !block.requestless || block.addressesTarget {
			t.Fatalf("%q must be reported as not addressing the target: %+v", key, block)
		}
	}
	// Everything that does talk to the target has to stay a normal result, or a
	// real check would be reported as not addressing the target.
	for _, key := range blockKeys {
		if containsString(local, key) || key == "javascript" {
			continue
		}
		block := blockByKey[key]
		if block.requestless || !block.addressesTarget {
			t.Fatalf("%q addresses a target and must stay a normal result: %+v", key, block)
		}
	}
	// JavaScript is classified from its imports rather than as a static section.
	if blockByKey["javascript"].requestless || blockByKey["javascript"].addressesTarget {
		t.Fatalf("javascript must be classified from its body: %+v", blockByKey["javascript"])
	}
	// The static requestless list contains exactly code and file.
	overlap := 0
	for _, block := range protocolBlocks {
		if block.requestless {
			overlap++
		}
	}
	if overlap != len(local) {
		t.Fatalf("expected exactly %d request-less sections, got %d", len(local), overlap)
	}
}

func TestJavaScriptRequestClassificationUsesItsCapabilities(t *testing.T) {
	template := func(script string) string {
		return "id: js-classification\ninfo:\n  name: JS classification\n  author: test\n  severity: info\njavascript:\n  - code: |\n" +
			script
	}
	tests := []struct {
		name            string
		script          string
		addressesTarget bool
	}{
		{name: "local expression", script: "      1 + 1\n"},
		{name: "local bytes module", script: "      var bytes = require(\"nuclei/bytes\");\n      bytes.ToHex(\"x\")\n"},
		{name: "local filesystem module", script: "      var fs = require(\"nuclei/fs\");\n      fs.ReadFile(\"x\")\n"},
		{name: "UDP network module", script: "      var net = require(\"nuclei/net\");\n      net.Open(\"udp\", \"{{Host}}:500\")\n", addressesTarget: true},
		{name: "SSH network module", script: "      var ssh = require(\"nuclei/ssh\");\n      ssh.Connect(\"{{Host}}:22\")\n", addressesTarget: true},
		{name: "built-in UDP probe", script: "      isUDPPortOpen(500)\n", addressesTarget: true},
		{name: "unknown nuclei module", script: "      require(\"nuclei/unknown\").Connect(\"{{Host}}\")\n", addressesTarget: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meta, reason := parseTemplateDocument(template(test.script))
			if reason != "" {
				t.Fatalf("parse: %s", reason)
			}
			if got := meta.AddressesTarget(); got != test.addressesTarget {
				t.Fatalf("AddressesTarget() = %t, want %t", got, test.addressesTarget)
			}
			if got := meta.Requestless(); got == test.addressesTarget {
				t.Fatalf("Requestless() = %t, inconsistent with AddressesTarget() = %t", got, test.addressesTarget)
			}
		})
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestParseTemplateDocumentExplainsRejections(t *testing.T) {
	cases := map[string]struct {
		content string
		want    string
	}{
		"missing author": {missingAuthorTemplate, "info.author"},
		// An empty `http: []` is a section that declares nothing, so this document
		// has no request section at all — which is the shape
		// `classifyNonTemplate` describes before the id is ever checked. The case
		// is kept because it pins that order: the refusal names what is missing
		// first, and "top-level id" is what a document WITH a section is told.
		"missing id":      {"info:\n  name: X\n  author: a\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n", "top-level id"},
		"missing name":    {"id: x\ninfo:\n  author: a\n  severity: info\nhttp: []\n", "info.name"},
		"bad severity":    {"id: x\ninfo:\n  name: X\n  author: a\n  severity: nasty\nhttp: []\n", "info.severity"},
		"no requests":     {"id: x\ninfo:\n  name: X\n  author: a\n  severity: info\n", "request block"},
		"broken yaml":     {"id: [unclosed\n", "invalid YAML"},
		"not a template":  {"node.js: nodejs\n", "not a nuclei template"},
		"swagger payload": {"swagger: '2.0'\ninfo:\n  title: API\npaths:\n  /a:\n    post: {}\n", "Swagger/OpenAPI"},
		"a profile":       {"tags:\n  - cves\n", "profile"},
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
	if !staged[3].Support {
		t.Fatalf("notes file = %+v, want an unreported support file", staged[3])
	}
	if got := TemplatesReport(staged); len(got) != 4 {
		t.Fatalf("template report has %d rows, want helper file omitted: %+v", len(got), got)
	}
	for _, index := range []int{2, 4} {
		if staged[index].Meta != nil || staged[index].Reason == "" {
			t.Fatalf("staged[%d] = %+v, want a rejection reason", index, staged[index])
		}
	}
}

func TestStageUploadsPreservesBinarySupportFiles(t *testing.T) {
	want := []byte{0x00, 0x7f, 0x80, 0xff}
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "check.yaml", Path: "templates/http/check.yaml", Content: validTemplate},
		{
			Name:     "payload.bin",
			Path:     "templates/http/helpers/payload.bin",
			Content:  base64.StdEncoding.EncodeToString(want),
			Encoding: "base64",
		},
	})
	if err != nil {
		t.Fatalf("stage folder: %v", err)
	}
	defer os.RemoveAll(dir)
	if len(staged) != 2 || !staged[1].Support {
		t.Fatalf("staged files = %+v, want one template and one support file", staged)
	}
	got, err := os.ReadFile(filepath.Join(dir, "templates/http/helpers/payload.bin"))
	if err != nil {
		t.Fatalf("read staged support file: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("staged bytes = %v, want %v", got, want)
	}
	if report := TemplatesReport(staged); len(report) != 1 || report[0].Name != "check.yaml" {
		t.Fatalf("support file leaked into template report: %+v", report)
	}
}

func TestBuildPlanUsesSelectedFolderAndKeepsSupportFilesInSource(t *testing.T) {
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "check.yaml", Path: "templates/http/check.yaml", Content: validTemplate},
		{Name: "payload.txt", Path: "templates/http/helpers/payload.txt", Content: "one\ntwo\n"},
		{Name: "dns.yaml", Path: "templates/dns/dns.yaml", Content: validTemplate},
	})
	if err != nil {
		t.Fatalf("stage folder: %v", err)
	}
	defer os.RemoveAll(dir)
	selectedDir, err := resolveTemplateCategory(dir, "templates/http")
	if err != nil {
		t.Fatalf("resolve selected folder: %v", err)
	}
	selectedFiles, err := filterStagedTemplatesByCategory(staged, "templates/http")
	if err != nil {
		t.Fatalf("select report rows: %v", err)
	}
	plan, err := BuildPlan(PlanRequest{Dir: selectedDir, Staged: selectedFiles})
	if err != nil {
		t.Fatalf("build direct plan: %v", err)
	}
	if len(plan.Batches) != 1 {
		t.Fatalf("batches = %d, want one direct folder invocation", len(plan.Batches))
	}
	batch := plan.Batches[0]
	wantDir, err := filepath.Abs(selectedDir)
	if err != nil {
		t.Fatalf("resolve expected folder: %v", err)
	}
	if !batch.InPlace || batch.Dir != wantDir {
		t.Fatalf("batch source = %+v, want selected folder %q used in place", batch, wantDir)
	}
	if len(batch.Files) != 1 || len(plan.Inputs) != 1 || plan.TotalFiles != 1 {
		t.Fatalf("support or unselected files entered the template report: plan=%+v", plan)
	}
	args, err := buildNucleiArgs("http://target.test/", batch.Dir, NucleiRequest{
		Protocols: batch.Capabilities,
	})
	if err != nil {
		t.Fatalf("build Nuclei args: %v", err)
	}
	if !hasArg(args, "-esc") || !hasArg(args, "-nss") || hasArg(args, "-pt") {
		t.Fatalf("mandatory/no-protocol-type flags violated: %v", args)
	}
	for index, arg := range args {
		if arg == "-t" && index+1 < len(args) {
			if args[index+1] != wantDir {
				t.Fatalf("-t path = %q, want selected folder %q", args[index+1], wantDir)
			}
			return
		}
	}
	t.Fatalf("Nuclei args have no -t source: %v", args)
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
	// Two distinct documents with distinct template ids, so neither is a content
	// copy of the other and neither needs its own invocation: this test is about
	// attributing a finding to the file that produced it, not about the plan.
	dir, staged, err := StageUploads([]UploadFile{
		{Name: "a.yaml", Path: "http/CVE-2024-1.yaml", Content: folderTemplate("rr-http")},
		{Name: "b.yaml", Path: "dns/detect.yaml", Content: strings.Replace(folderTemplate("rr-dns"), "/probe", "/probe-dns", 1)},
		{Name: "c.yaml", Path: "z/c.yaml", Content: missingAuthorTemplate},
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
