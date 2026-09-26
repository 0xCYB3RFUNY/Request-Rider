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
		"  prev=\"$arg\"\n" +
		"done\n" +
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

	shared := nucleiValidTemplate
	other := strings.Replace(nucleiValidTemplate, "id: rr-fixture", "id: rr-other", 1)
	body := `{"url":"http://target.test/","files":[` +
		nucleiUpload("alpha.yaml", "", shared) + `,` +
		nucleiUpload("beta.yaml", "", other) + `,` +
		nucleiUpload("gamma.yaml", "", shared) + `]}`
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
	if len(payload.Templates) != 3 {
		t.Fatalf("templates = %d, want one row per uploaded file", len(payload.Templates))
	}
	byName := map[string]int{}
	for index, item := range payload.Templates {
		byName[item.Name] = index
	}
	alpha, beta, gamma := payload.Templates[byName["alpha.yaml"]], payload.Templates[byName["beta.yaml"]], payload.Templates[byName["gamma.yaml"]]
	if alpha.Status != "not_matched" || beta.Status != "not_matched" {
		t.Fatalf("executed files = %+v / %+v, want both not_matched", alpha, beta)
	}
	if gamma.Status != "skipped" {
		t.Fatalf("gamma = %+v, want skipped", gamma)
	}
	if !strings.Contains(gamma.Reason, "alpha.yaml") || !strings.Contains(gamma.Reason, "rr-fixture") {
		t.Fatalf("gamma reason = %q, want it to name alpha.yaml and the id", gamma.Reason)
	}
	// The stats arrive as JSON, so the counts are float64 rather than int.
	if statNumber(payload.Stats["executed"]) != 2 || statNumber(payload.Stats["skipped"]) != 1 {
		t.Fatalf("stats executed/skipped = %v/%v, want 2/1", payload.Stats["executed"], payload.Stats["skipped"])
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

	body := `{"url":"http://target.test/","files":[` +
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
