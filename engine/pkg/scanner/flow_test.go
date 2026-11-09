package scanner

// A `flow:` file is a definition, not a runnable template, and the one claim
// this report must never make is that a file was checked when it was not. These
// tests hold that line.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Measured on nuclei v3.11.1: passing a flow file to `-t` loads no runnable
// body and the binary exits with "no templates provided for scan", while
// `nuclei -validate` calls the same file valid. A flow therefore has to be
// recognised at parse time, before any run, or the report can only describe it
// with a status that is already wrong.
const flowTemplate = `id: postman-login-check
info:
  name: Postman login check
  author: test
  severity: medium
flow: http(1) || http(2)
http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    matchers:
      - type: word
        words:
          - "token"
`

func TestAFlowDocumentIsRecognisedAsAFlow(t *testing.T) {
	meta, reason := parseTemplateDocumentWithPath(flowTemplate, "http/postman-login-check.yaml")
	if reason != "" {
		t.Fatalf("a flow file was refused at parse time: %s", reason)
	}
	if !meta.IsFlow() {
		t.Error("IsFlow() is false, so the report would call this file one that ran and matched nothing")
	}
	if meta.Flow != "http(1) || http(2)" {
		t.Errorf("flow = %q, want the document's own expression", meta.Flow)
	}
}

// The sentence must say what happened in THIS run, not what a flow is. Until
// 2026-09-29 it read "not a runnable template", which is false: measured against
// nuclei v3.11.1 a flow template is loaded and executed, and it is the missing
// record — not the file's kind — that means nothing in it was checked. A test
// that pins the wrong sentence pins the wrong claim.
func TestAFlowReasonSaysItWasNotChecked(t *testing.T) {
	meta, reason := parseTemplateDocumentWithPath(flowTemplate, "http/postman-login-check.yaml")
	if reason != "" {
		t.Fatalf("refused at parse time: %s", reason)
	}
	text := meta.FlowReason()
	for _, want := range []string{"flow", "no record", "nothing in it was checked"} {
		if !strings.Contains(text, want) {
			t.Errorf("reason = %q, want it to contain %q", text, want)
		}
	}
	// The old wording asserted that nuclei cannot execute a flow at all. Keeping
	// the check means a future edit cannot quietly bring the false claim back.
	for _, unwanted := range []string{"not a runnable template", "nuclei does not execute"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("reason = %q repeats the disproved claim %q", text, unwanted)
		}
	}
}

func TestAnOrdinaryTemplateIsNotAFlow(t *testing.T) {
	document := `id: plain
info:
  name: Plain
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`
	meta, reason := parseTemplateDocumentWithPath(document, "http/plain.yaml")
	if reason != "" {
		t.Fatalf("refused at parse time: %s", reason)
	}
	if meta.IsFlow() {
		t.Error("a plain template was reported as a flow, which would hide it from the run")
	}
	if meta.FlowReason() != "" {
		t.Errorf("FlowReason() = %q for a template that is not a flow", meta.FlowReason())
	}
}

// The local runner has to refuse a flow with the same name, so the two paths
// cannot disagree about what a flow is. The transport is a real one: with a nil
// transport the runner refuses earlier, for a different and equally correct
// reason, and the test would pass without ever reaching the flow check.
func TestTheLocalRunnerRefusesAFlowByName(t *testing.T) {
	server := localFixture()
	defer server.Close()
	run := RunTemplateLocally(context.Background(), flowTemplate, server.URL,
		&countingTransport{inner: http.DefaultTransport})
	if !strings.Contains(run.Reason, "flow") {
		t.Errorf("reason = %q, want it to name the flow", run.Reason)
	}
	if run.Matched {
		t.Error("reported a match for a file that was never sent")
	}
}
