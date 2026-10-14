package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeNucleiStub installs a fake binary that reports one match for the first
// staged template, so the endpoint test never runs the real scanner.
func writeNucleiStub(t *testing.T, dir string) string {
	t.Helper()
	stub := filepath.Join(dir, "nuclei-stub.sh")
	script := "#!/bin/sh\n" +
		"out=''\nprev=''\ntemplates=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"first=$(find \"$templates\" -name '*.yaml' | sort | head -1)\n" +
			// The file the binary would really load. Picking it by name order
			// picked `broken.yaml` — the document the run refuses for having no
			// `info.author` — so the one record that carries a match was
			// attributed to a file that never executes, and the run reported
			// `matched: 0` on a stub that had just reported a match. Measured:
			// stats said `executed: 2, matched: 0, not_matched: 2, invalid: 1`
			// while the JSONL plainly held a finding. The binary skips a
			// document without an author, so the stub asks the same question.
			"first=$(grep -l '^[[:space:]]*author:' $(find \"$templates\" -name '*.yaml' | sort) | head -1)\n" +
			"if [ -z \"$first\" ]; then first=$(find \"$templates\" -name '*.yaml' | sort | head -1); fi\n" +
		"if [ -z \"$first\" ]; then echo 'no templates provided for scan' >&2; exit 1; fi\n" +
		"printf '%s\\n' '{\"template-id\":\"CVE-2024-0001\",\"template-path\":\"'\"$first\"'\",\"info\":{\"name\":\"Fixture\",\"author\":[\"requestrider\"],\"severity\":\"critical\",\"classification\":{\"cve-id\":[\"CVE-2024-0001\"]}},\"matcher-name\":\"probe\",\"host\":\"http://target.test/\",\"matched-at\":\"http://target.test/a\",\"curl-command\":\"curl http://target.test/a\"}' > \"$out\"\n" +
		// The real binary writes a matcher-status record for every template it
		// executes, which is how the report knows the difference between a file
		// that ran without matching and a file that never ran.
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  if [ \"$f\" = \"$first\" ]; then continue; fi\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  printf '%s\\n' '{\"template-id\":\"'\"$id\"'\",\"template-path\":\"'\"$f\"'\",\"host\":\"http://target.test/\",\"matched-at\":\"http://target.test/a\",\"matcher-status\":false}' >> \"$out\"\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return stub
}

const nucleiValidTemplate = `id: rr-fixture
info:
  name: Fixture
  author: requestrider
  severity: critical
  classification:
    cve-id: CVE-2024-0001
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
    matchers:
      - type: status
        status: [200]
`

// nucleiTarget stands in for the scanned host: a real server on loopback.
//
// It answers 404 on purpose. This project's runner performs every template the
// binary left without a verdict, so a target that cannot be reached is not
// neutral: the runner cannot perform the check, and the row is honestly reported
// as `skipped` with the transport's own refusal. A row that says «Not run» is
// the truth for an unreachable host, and the report is right to say it — the
// fixture is what was wrong. Pointing these tests at `target.test`, which
// resolves nowhere, therefore failed them while asserting that a negative was
// reported for a check that never ran.
//
// 404 rather than 200 so the template's `status: [200]` matcher finds nothing:
// the point of these tests is the per-file report and the deduplication, not a
// finding. A 200 would let the local runner match every file and turn the rows
// into `matched`, which is a different test entirely.
func nucleiTarget(t *testing.T) *httptest.Server {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!doctype html><title>Not found</title></body></html>"))
	}))
	t.Cleanup(target.Close)
	return target
}

func nucleiUpload(name, path, content string) string {
	upload := map[string]string{"name": name, "content": content}
	if path != "" {
		upload["path"] = path
	}
	encoded, err := json.Marshal(upload)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// writeDedupeNucleiStub mimics the binary's template-id deduplication: one file
// per id, in path order, with a matcher-status record for each executed one.
func writeDedupeNucleiStub(t *testing.T, dir string) string {
	t.Helper()
	stub := filepath.Join(dir, "nuclei-dedupe-stub.sh")
	script := "#!/bin/sh\n" +
		"out=''\nprev=''\ntemplates=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-validate' ]; then validate='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		// Validation is a separate invocation with no -o. This binary accepts every
		// document, so it answers at once and says nothing.
		"if [ -n \"$validate\" ]; then exit 0; fi\n" +
		": > \"$out\"\n" +
		"seen=''\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  case \" $seen \" in *\" $id \"*) continue ;; esac\n" +
		"  seen=\"$seen $id\"\n" +
		"  printf '%s\\n' '{\"template-id\":\"'\"$id\"'\",\"template-path\":\"'\"$f\"'\",\"host\":\"http://target.test/\",\"matched-at\":\"http://target.test/a\",\"matcher-status\":false}' >> \"$out\"\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return stub
}

func TestScannerNucleiEndpointReportsFilesNucleiNeverRan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RR_NUCLEI_BINARY", writeDedupeNucleiStub(t, dir))

	// Three files, each a different case the report has to tell apart:
	//   alpha  — the original, which runs
	//   beta   — a different body under a different id, which also runs
	//   gamma  — a byte-identical copy of alpha under another name
	//   delta  — alpha's id with a different body, which is a different template
	//            that the binary would otherwise drop for sharing an id with alpha
	shared := nucleiValidTemplate
	other := strings.Replace(nucleiValidTemplate, "id: rr-fixture", "id: rr-other", 1)
	sameIDNewBody := strings.Replace(shared, "{{BaseURL}}/a", "{{BaseURL}}/other-probe", 1)
	target := nucleiTarget(t)
	body := `{"url":"` + target.URL + `/","files":[` +
		nucleiUpload("alpha.yaml", "", shared) + `,` +
		nucleiUpload("beta.yaml", "", other) + `,` +
		nucleiUpload("gamma.yaml", "", shared) + `,` +
		nucleiUpload("delta.yaml", "", sameIDNewBody) + `]}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/nuclei", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	(&server{}).scannerNuclei(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("nuclei endpoint = %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Templates []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"templates"`
		Stats map[string]interface{} `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Templates) != 4 {
		t.Fatalf("templates = %d, want one row per uploaded file", len(payload.Templates))
	}
	byName := map[string]int{}
	for index, item := range payload.Templates {
		byName[item.Name] = index
	}
	// The report reads in upload order, so the rows keep the order the browser
	// sent them in no matter which batch the plan chose.
	for index, name := range []string{"alpha.yaml", "beta.yaml", "gamma.yaml", "delta.yaml"} {
		if payload.Templates[index].Name != name {
			t.Fatalf("row %d = %q, want %q: the report has to read in upload order",
				index, payload.Templates[index].Name, name)
		}
		if byName[name] != index {
			t.Fatalf("row index for %q = %d, want %d", name, byName[name], index)
		}
	}
	alpha := payload.Templates[byName["alpha.yaml"]]
	beta := payload.Templates[byName["beta.yaml"]]
	gamma := payload.Templates[byName["gamma.yaml"]]
	delta := payload.Templates[byName["delta.yaml"]]
	if alpha.Status != "not_matched" || beta.Status != "not_matched" {
		t.Fatalf("executed files = %+v / %+v, want both not_matched", alpha, beta)
	}
	// Delta shares alpha's template id but is a different template. The binary
	// loads one file per id, so the plan gives the two of them separate
	// invocations and delta runs instead of being reported as never attempted.
	if delta.Status != "not_matched" {
		t.Fatalf("delta = %+v, want not_matched: a file sharing a template id with another file still runs", delta)
	}
	// Gamma is byte-identical to alpha: the same template under a second name.
	// That is not a failure and not a check against the target, so it is reported
	// as the duplicate it is, naming the file that takes its place.
	if gamma.Status != "duplicate" {
		t.Fatalf("gamma = %+v, want duplicate", gamma)
	}
	if !strings.Contains(gamma.Reason, "byte-identical") || !strings.Contains(gamma.Reason, "alpha.yaml") {
		t.Fatalf("gamma reason = %q, want it to name alpha.yaml as the file it collapses into", gamma.Reason)
	}
	if statNumber(payload.Stats["batches"]) != 2 {
		t.Fatalf("batches = %v, want 2: the binary keeps one file per template id", payload.Stats["batches"])
	}
	// The stats arrive as JSON, so the counts are float64 rather than int.
	if statNumber(payload.Stats["executed"]) != 3 || statNumber(payload.Stats["duplicate"]) != 1 {
		t.Fatalf("stats executed/duplicate = %v/%v, want 3/1", payload.Stats["executed"], payload.Stats["duplicate"])
	}
	if statNumber(payload.Stats["skipped"]) != 0 {
		t.Fatalf("nothing may be left unrun: skipped = %v", payload.Stats["skipped"])
	}
	dedup, _ := payload.Stats["deduplication"].(map[string]interface{})
	if dedup == nil || statNumber(dedup["collapsed"]) != 1 {
		t.Fatalf("deduplication summary = %#v, want one collapsed copy", payload.Stats["deduplication"])
	}
}

// statNumber reads a count out of a decoded JSON stats object.
func statNumber(value interface{}) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case nil:
		return -1
	}
	return -1
}

func TestScannerNucleiEndpointReportsEveryUploadedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RR_NUCLEI_BINARY", writeNucleiStub(t, dir))
	target := nucleiTarget(t)

	body := `{"url":"` + target.URL + `/","files":[` +
		nucleiUpload("CVE-2024-0001.yaml", "http/cves/2024/CVE-2024-0001.yaml", nucleiValidTemplate) + `,` +
		// A distinct id, so this file really is executed and reports nothing
		// rather than losing a template-id clash.
		nucleiUpload("quiet.yaml", "http/misconfig/quiet.yaml", strings.Replace(nucleiValidTemplate, "id: rr-fixture", "id: rr-fixture-quiet", 1)) + `,` +
		nucleiUpload("broken.yaml", "", "id: broken\ninfo:\n  name: Broken\n  severity: info\nhttp: []\n") + `]}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/nuclei", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	(&server{}).scannerNuclei(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("nuclei endpoint = %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Findings  []map[string]interface{} `json:"findings"`
		Templates []struct {
			Name    string   `json:"name"`
			Status  string   `json:"status"`
			Reason  string   `json:"reason"`
			Matches int      `json:"matches"`
			CVE     []string `json:"cve"`
		} `json:"templates"`
		Stats map[string]interface{} `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Templates) != 3 {
		t.Fatalf("templates = %#v, want one entry per uploaded file", payload.Templates)
	}
	if payload.Templates[0].Name != "CVE-2024-0001.yaml" ||
		payload.Templates[0].Status != "matched" ||
		payload.Templates[0].Matches != 1 ||
		len(payload.Templates[0].CVE) != 1 {
		t.Fatalf("matched file not reported: %#v", payload.Templates[0])
	}
	if payload.Templates[1].Status != "not_matched" || payload.Templates[1].Matches != 0 {
		t.Fatalf("quiet file not reported: %#v", payload.Templates[1])
	}
	if payload.Templates[2].Status != "invalid" || !strings.Contains(payload.Templates[2].Reason, "info.author") {
		t.Fatalf("invalid file not explained: %#v", payload.Templates[2])
	}
	if len(payload.Findings) != 1 || payload.Findings[0]["template_id"] != "CVE-2024-0001" {
		t.Fatalf("findings = %#v", payload.Findings)
	}
	if payload.Stats["files"] != float64(3) || payload.Stats["matched"] != float64(1) {
		t.Fatalf("stats = %#v", payload.Stats)
	}
}

func TestScannerNucleiEndpointExplainsFullyInvalidUpload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RR_NUCLEI_BINARY", writeNucleiStub(t, dir))

	// Two templates without info.author: nuclei drops both and exits 1. The
	// endpoint must explain the upload instead of reporting a bare exit status.
	body := `{"url":"http://target.test/","files":[` +
		nucleiUpload("a.yaml", "", "id: a\ninfo:\n  name: A\n  severity: info\nhttp: []\n") + `,` +
		nucleiUpload("b.yaml", "", "id: b\ninfo:\n  name: B\n  severity: info\nhttp: []\n") + `]}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/nuclei", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	(&server{}).scannerNuclei(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("nuclei endpoint = %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Error     string `json:"error"`
		Reason    string `json:"reason"`
		Templates []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Reason != "SCANNER_NUCLEI_NO_VALID_TEMPLATES" {
		t.Fatalf("reason = %q", payload.Reason)
	}
	if len(payload.Templates) != 2 {
		t.Fatalf("per-file reasons lost: %#v", payload)
	}
	for _, item := range payload.Templates {
		if item.Status != "invalid" || !strings.Contains(item.Reason, "info.author") {
			t.Fatalf("template not explained: %#v", item)
		}
	}
}

func TestScannerNucleiEndpointRejectsBadInput(t *testing.T) {
	for _, body := range []string{
		`{"url":"http://target.test/"}`,
		`{"url":"http://target.test/","files":[]}`,
		`{"url":"http://target.test/","files":[{"name":"evil.sh","content":"x"}]}`,
		`{"url":"not-a-url","files":[{"name":"a.yaml","content":"id: a"}]}`,
		`{"url":"http://target.test/","files":[{"name":"a.yaml","path":"../../escape.yaml","content":"id: a"}]}`,
		`{invalid`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/nuclei", strings.NewReader(body))
		recorder := httptest.NewRecorder()
		(&server{}).scannerNuclei(recorder, request)
		if recorder.Code == http.StatusOK {
			t.Fatalf("accepted: %s -> %s", body, recorder.Body.String())
		}
	}
}
