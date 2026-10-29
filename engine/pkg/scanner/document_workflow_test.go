package scanner

import (
	"os"
	"strings"
	"testing"
)

// A nuclei workflow is an orchestrator, not a check. It names the templates to
// run and matches their results, so it produces no finding of its own and
// declares no severity — which is exactly how the upstream corpus writes them:
//
//	info:
//	  name: 74cms Security Checks
//	  author: daffainfo
//	workflows:
//	  - template: http/technologies/fingerprinthub-web-fingerprints.yaml
//
// This file pins the header rule that follows from that. It is here because the
// rule was wrong in a way only a real corpus could show: the parser demanded
// `info.severity` from every document, so all 207 workflow files in
// `nuclei-templates/workflows` were refused while `nuclei -validate` accepted
// every one of them. The binary is the authority on what it accepts, and the
// comparison that found this is recorded in DEVELOPMENT_LOG.md.

const workflowDocument = `id: 74cms-workflow

info:
  name: 74cms Security Checks
  author: daffainfo
  description: A simple workflow that runs all 74cms related nuclei templates on a given target.
workflows:
  - template: http/technologies/fingerprinthub-web-fingerprints.yaml
    matchers:
      - name: 74cms
        subtemplates:
          - tags: 74cms
`

func TestAWorkflowTemplateCarriesNoSeverityAndIsStillAccepted(t *testing.T) {
	meta, reason := parseTemplateDocument(workflowDocument)
	if reason != "" {
		t.Fatalf("a workflow the binary accepts was refused: %s", reason)
	}
	if meta == nil {
		t.Fatal("no template metadata was produced")
	}
	if meta.TemplateID != "74cms-workflow" {
		t.Errorf("template id = %q, want 74cms-workflow", meta.TemplateID)
	}
	// An empty severity is the honest reading: the document declared none, so
	// reporting `unknown` would claim the tool had an opinion where it has none.
	if meta.Severity != "" {
		t.Errorf("severity = %q, want an empty string: a workflow declares none", meta.Severity)
	}
	if meta.Protocol != "workflow" {
		t.Errorf("protocol = %q, want workflow", meta.Protocol)
	}
}

// The exemption is narrow on purpose. A document that mixes a workflow with a
// real request section does produce findings, and those findings carry a
// severity, so that document still has to declare one.
func TestADocumentThatOnlyMentionsAWorkflowStillNeedsASeverity(t *testing.T) {
	mixed := `id: mixed-workflow

info:
  name: Mixed
  author: someone
workflows:
  - template: http/technologies/example.yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`
	_, reason := parseTemplateDocument(mixed)
	if !strings.Contains(reason, "missing info.severity") {
		t.Fatalf("reason = %q, want the missing-severity refusal: a real request section produces findings", reason)
	}
}

// The requirement itself is unchanged for every ordinary template. This is the
// test that would go red if the exemption had been written as "severity is
// optional", which is the shape of the mistake that would silently downgrade
// every check in the corpus to an unweighed row.
func TestAnOrdinaryTemplateStillHasToDeclareItsSeverity(t *testing.T) {
	withoutSeverity := `id: plain-check

info:
  name: Plain Check
  author: someone
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`
	_, reason := parseTemplateDocument(withoutSeverity)
	if !strings.Contains(reason, "missing info.severity") {
		t.Fatalf("reason = %q, want the missing-severity refusal", reason)
	}

	// And a severity outside the vocabulary is still refused rather than folded
	// into a known word, so the report's counters cannot claim a level the
	// template never declared.
	alienSeverity := strings.Replace(withoutSeverity, "  author: someone",
		"  author: someone\n  severity: apocalyptic", 1)
	_, reason = parseTemplateDocument(alienSeverity)
	if !strings.Contains(reason, "unknown info.severity") {
		t.Fatalf("reason = %q, want the unknown-severity refusal", reason)
	}
}

// The header parser is only the first gate; `nuclei -validate` is the second.
// Both agreeing is the condition that made this fix safe to make, so the test
// states it rather than assuming it.
func TestTheCorpusWorkflowsAreAcceptedByTheHeaderParser(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("RR_NUCLEI_CORPUS_WORKFLOWS"))
	if root == "" {
		t.Skip("set RR_NUCLEI_CORPUS_WORKFLOWS to the workflows directory of a nuclei corpus")
	}
	paths, err := corpusFiles(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(paths) == 0 {
		t.Skipf("no template files under %s", root)
	}
	refused := 0
	for _, path := range paths {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		if _, reason := parseTemplateDocumentWithPath(string(payload), corpusRelative(root, path)); reason != "" {
			refused++
			if refused <= 3 {
				t.Errorf("refused %s: %s", path, reason)
			}
		}
	}
	if refused != 0 {
		t.Fatalf("%d of %d workflow templates were refused; nuclei accepts these", refused, len(paths))
	}
	t.Logf("every workflow template under %s was accepted (%d files)", root, len(paths))
}
