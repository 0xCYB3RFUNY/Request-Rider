package scanner

import "testing"

func TestDataOnlyHTTPClassificationInYAMLPreview(t *testing.T) {
	httpOnlyYAML := `id: data-only-health
info:
  name: Data Only HTTP Check
  author: tester
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/health"
    matchers:
      - type: status
        status:
          - 200
`
	meta, reason := ParseTemplateDocumentWithPath(httpOnlyYAML, "http/health.yaml")
	if reason != "" || meta == nil {
		t.Fatalf("expected valid HTTP template, got reason=%q", reason)
	}
	if !meta.IsDataOnlyHTTP() {
		t.Fatalf("expected IsDataOnlyHTTP()=true for pure HTTP template")
	}

	codeYAML := `id: code-exec-check
info:
  name: Code Check
  author: tester
  severity: high
code:
  - engine:
      - sh
    source: id
`
	codeMeta, reason2 := ParseTemplateDocumentWithPath(codeYAML, "code/check.yaml")
	if reason2 != "" || codeMeta == nil {
		t.Fatalf("expected valid code template, got reason=%q", reason2)
	}
	if codeMeta.IsDataOnlyHTTP() {
		t.Fatalf("expected IsDataOnlyHTTP()=false for code template")
	}
}
