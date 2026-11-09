package scanner

import (
	"os"

	"strings"
	"testing"
)

// The corpus refuses 22 files. Every one of those refusals used to be reported
// with a reason that was either wrong or unreadable, and this file pins what the
// operator is actually told.
//
// The reason matters as much as the refusal: a run that dropped 7 profiles
// because they "have no `id`" reads as seven broken templates, and the operator
// goes looking for a corpus problem that does not exist. They are profiles, and
// nuclei loads them with `-profile`, which is what the sentence has to say.
//
// The binary is the authority on what it accepts, and it was measured for each
// case below: `nuclei -profile <file> -validate` loads these, while
// `nuclei -t <file>` refuses the same files with "Could not find template".

func TestAProfileCarryingOnlyCodeAndVarIsNamedAProfile(t *testing.T) {
	// Verbatim shape of nuclei-templates/profiles/alibaba-cloud-config.yml, which
	// is the file that produced `missing top-level id`.
	document := `# Nuclei Configuration Profile for Scanning aliyun ACLs
code: true # enable code templates
tags:
  - alibaba-cloud-config # filter templates with "alibaba-cloud-config" tags
var:
  - region=cn-hangzhou # template input for "region" variable
`
	_, reason := parseTemplateDocumentWithPath(document, "profiles/alibaba-cloud-config.yml")
	if !strings.Contains(reason, "profile") {
		t.Fatalf("reason = %q, want a refusal naming the file a profile", reason)
	}
	if strings.Contains(reason, "missing top-level id") {
		t.Errorf("reason = %q: a profile reported as a template missing its id", reason)
	}
}

// `var:` is template input, not a selection, so a document carrying only it
// selects nothing and is not a profile — it is simply not a template. The
// distinction matters because the profile sentence tells the operator what to do
// next, and "load the templates it points at" is wrong advice for a file that
// points at nothing.
func TestADocumentWithOnlyVarIsNotCalledAProfile(t *testing.T) {
	document := "var:\n  - region=cn-hangzhou\n"
	_, reason := parseTemplateDocumentWithPath(document, "profiles/only-var.yml")
	if strings.Contains(reason, "profile") {
		t.Errorf("reason = %q: nothing here selects templates, so the profile advice is wrong", reason)
	}
	if !strings.Contains(reason, "not a nuclei template") {
		t.Errorf("reason = %q, want the plain not-a-template refusal", reason)
	}
}

// The keys that were missing from the vocabulary are named here individually,
// because the failure they caused was silent: a file stopped being recognised
// as a profile without anything saying so.
func TestEveryProfileKeyObservedInTheCorpusIsInTheVocabulary(t *testing.T) {
	// Top-level keys of the 20 files under nuclei-templates/profiles, measured
	// with `grep -hoE '^[a-z][a-z0-9-]*:' profiles/*.yml | sort -u`.
	for _, key := range []string{
		"templates", "tags", "include-tags", "exclude-tags", "exclude-id",
		"severity", "type", "code", "var",
	} {
		if !profileKeys[key] {
			t.Errorf("profile key %q is not in the vocabulary: a file carrying only it is reported as a broken template", key)
		}
	}
}

// A template that merely forgot its `id` must still be reported as a malformed
// template, never as a profile. This is the guard on the guard: the profile rule
// reads "every key is a profile key", so a file made entirely of profile keys is
// indistinguishable from a profile by shape alone, and only the fact that it
// also selects nothing distinguishes them.
func TestATemplateThatForgotItsIdIsStillAMalformedTemplate(t *testing.T) {
	document := `info:
  name: No Id Here
  author: someone
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`
	_, reason := parseTemplateDocument(document)
	if reason != "missing top-level id" {
		t.Fatalf("reason = %q, want missing top-level id", reason)
	}
}

// The sentence lists what the file actually carries, so an operator reading it
// learns which selection the profile makes. A generic sentence made every
// profile read the same.
func TestTheProfileRefusalNamesTheSelectionKeys(t *testing.T) {
	_, reason := parseTemplateDocumentWithPath("tags:\n  - cves\n", "profiles/cves.yml")
	if !strings.Contains(reason, "tags") {
		t.Errorf("reason = %q, want it to name the selection key the profile carries", reason)
	}
}

// The two non-profile refusals in the corpus are not templates and never were:
// `helpers/payloads/swagger.yml` is an OpenAPI document (it starts `swagger: '2.0'`
// and has `info:` and `paths:`), and `http/technologies/wappalyzer-mapping.yml` is
// a technology-name mapping (`node.js: nodejs`). The binary refuses both the same
// way — `nuclei -validate -t <file>` answers "Could not find template" — so the
// refusal is correct and the sentence has to say what the file is, because both
// sit inside template directories and read as lost templates.
// A dotfile at the root of an uploaded tree is the repository's own
// configuration, not a template. `.pre-commit-config.yml` is the one in the
// official corpus, and it was reported as a template missing an `id` — which
// reads as a corrupt upload rather than as a file that never was a template.
func TestARootDotfileIsNamedARepositoryConfiguration(t *testing.T) {
	cases := []string{".pre-commit-config.yml", ".github/workflows/ci.yml", ".gitlab-ci.yml"}
	for _, path := range cases {
		_, reason := parseTemplateDocumentWithPath("repos:\n  - repo: https://example.test\n", path)
		if !strings.Contains(reason, "repository configuration") {
			t.Errorf("%s: reason = %q, want it named a repository configuration file", path, reason)
		}
	}
}

// A dotted path segment further down is not a repository configuration: a
// template may legitimately live in a directory whose name starts with a dot.
func TestADotSegmentBelowTheRootIsNotCalledARepositoryConfiguration(t *testing.T) {
	document := "id: x\ninfo:\n  name: X\n  author: a\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
	meta, reason := parseTemplateDocumentWithPath(document, "http/.archive/x.yaml")
	if reason != "" {
		t.Fatalf("reason = %q, want the template accepted", reason)
	}
	if meta == nil {
		t.Error("no metadata for a valid template in a dotted directory")
	}
}

func TestTheCorpusNonTemplatesAreNamedForWhatTheyAre(t *testing.T) {
	cases := []struct {
		name     string
		document string
		path     string
		want     string
	}{
		{
			name:     "swagger payload",
			document: "swagger: '2.0'\ninfo:\n  title: API\npaths:\n  /signin:\n    post: {}\n",
			path:     "helpers/payloads/swagger.yml",
			want:     "not a nuclei template",
		},
		{
			name:     "wappalyzer mapping",
			document: "node.js: nodejs\n",
			path:     "http/technologies/wappalyzer-mapping.yml",
			want:     "not a nuclei template",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, reason := parseTemplateDocumentWithPath(item.document, item.path)
			if !strings.Contains(reason, item.want) {
				t.Errorf("reason = %q, want it to contain %q", reason, item.want)
			}
			// The refusal must stay a refusal: neither file is runnable, and the
			// binary agrees.
			if reason == "" {
				t.Error("the file was accepted, but nuclei -validate refuses it")
			}
		})
	}
}

// The real corpus is the only place the vocabulary can be checked against every
// file the project will actually be handed, so this one reads it when named.
func TestEveryRefusalInTheCorpusIsNamedForWhatItIs(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("RR_NON_TEMPLATE_CORPUS"))
	if root == "" {
		t.Skip("set RR_NON_TEMPLATE_CORPUS to a nuclei corpus")
	}
	var wrong []string
	paths, err := corpusFiles(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, path := range paths {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		relative := corpusRelative(root, path)
		_, reason := parseTemplateDocumentWithPath(string(payload), relative)
		if reason == "" {
			continue
		}
		// Every refusal has to name what the file is. "missing top-level id" is
		// the one that cannot be acted on: it says the file is broken when it is
		// a profile the binary loads with -profile.
		if reason == "missing top-level id" {
			wrong = append(wrong, relative+": "+reason)
		}
		if !strings.Contains(reason, "not a nuclei template") &&
			!strings.Contains(reason, "profile") &&
			!strings.Contains(reason, "repository configuration") {
			wrong = append(wrong, relative+": "+reason)
		}
	}
	if len(wrong) > 0 {
		t.Fatalf("%d refusals do not name what the file is:\n  %s",
			len(wrong), strings.Join(wrong, "\n  "))
	}

}
