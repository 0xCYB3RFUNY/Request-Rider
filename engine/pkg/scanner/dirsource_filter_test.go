package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRawTemplate writes a `.yaml` file verbatim. `writeTemplate` builds a
// well-formed nuclei document, and the folders this test is about are the ones
// holding `.yaml` files that are not templates, so they need an author that does
// not help them.
func writeRawTemplate(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// offeredIn returns the entries that belong to one corpus root.
//
// `ListTemplateDirs` deliberately walks every configured root, not only the one
// `RR_NUCLEI_TEMPLATE_DIR` names, so a test that reads the whole listing also
// reads whatever corpora this machine happens to have. Keying by `Path` rather
// than by `Name` keeps the assertion about the folder this test built.
func offeredIn(corpus string) map[string]int {
	offered := map[string]int{}
	for _, entry := range ListTemplateDirs() {
		if entry.Path == corpus {
			offered[filepath.Base(entry.Path)] = entry.Files
		}
	}
	return offered
}

func offeredPathsIn(corpus string) map[string]int {
	offered := map[string]int{}
	for _, entry := range ListTemplateDirs() {
		if len(entry.Path) > len(corpus) && strings.HasPrefix(entry.Path, corpus+string(filepath.Separator)) {
			offered[strings.TrimPrefix(entry.Path, corpus+string(filepath.Separator))] = entry.Files
		}
	}
	return offered
}

// A corpus root is not only templates. The official one carries
// `.github/ISSUE_TEMPLATE/`, `.github/workflows/`, `profiles/` and
// `helpers/payloads/`, and every one of those folders holds `.yaml` files, so a
// listing that counts names offers them. Picking one is a run that answers
// `[FTL] Could not run nuclei: no templates provided for scan`, which is the
// operator choosing a folder and getting nothing back.
//
// The rule is measured, not a name list: a folder is offered when at least one
// of the documents in it opens a top-level `id:` key — the one key a nuclei
// template cannot compile without. A hardcoded denylist would have to be
// rewritten for every collection an operator keeps next to their templates, and
// would silently hide a folder whose name happens to match.

func TestListingOffersTemplateFoldersAndSkipsTheRest(t *testing.T) {
	corpus := t.TempDir()

	// A real category, three levels deep, because the corpus nests.
	writeTemplate(t, filepath.Join(corpus, "http", "cves", "2025", "CVE-2025-1.yaml"),
		"cve-2025-1", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")

	// The folders a corpus root actually carries besides its templates.
	for _, folder := range []string{
		filepath.Join(corpus, ".github", "ISSUE_TEMPLATE"),
		filepath.Join(corpus, ".github", "workflows"),
		filepath.Join(corpus, "profiles"),
		filepath.Join(corpus, "helpers", "payloads"),
	} {
		writeRawTemplate(t, filepath.Join(folder, "not-a-template.yaml"), "name: fingerprint list\nvalues:\n  - a\n  - b\n")
	}

	// The root itself holds the same kind of file when a corpus is checked out
	// flat, and it is offered by the walk like any other folder.
	writeRawTemplate(t, filepath.Join(corpus, "README.yaml"), "title: readme\n")

	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", corpus)

	offered := offeredPathsIn(corpus)

	for _, skipped := range []string{
		".github", ".github/ISSUE_TEMPLATE", ".github/workflows",
		"profiles", "helpers", "helpers/payloads",
	} {
		if files, present := offered[filepath.ToSlash(skipped)]; present {
			t.Fatalf("%q holds no template and must not be offered, but it is with %d files: %+v",
				skipped, files, offered)
		}
	}
	for _, wanted := range []string{"http", "http/cves", "http/cves/2025"} {
		if files := offered[wanted]; files != 1 {
			t.Fatalf("%q holds the one real template and must be offered with it: %+v", wanted, offered)
		}
	}
}

// The filter must not become the parse the listing refused to do. A folder that
// holds a template is decided by one line of one file; the rest of the count
// still comes from names, and no document is parsed. That is the difference
// between a dropdown that answers in 301 ms on the 98 662-document corpus and one
// that answers in 134 s.
func TestQualifyingAFolderReadsOneLineAndCountsByName(t *testing.T) {
	corpus := t.TempDir()
	// The template sorts after the junk by name, so a filter that stops at the
	// first file it reads would reject the folder.
	writeRawTemplate(t, filepath.Join(corpus, "aaa-junk.yaml"), "name: junk\n")
	writeTemplate(t, filepath.Join(corpus, "zzz-real.yaml"), "real",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	// A document that cannot be parsed is still counted and does not make the
	// folder unusable: the run names it `invalid` with the reason.
	if err := os.WriteFile(filepath.Join(corpus, "unclosed.yaml"), []byte("id: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("write unclosed: %v", err)
	}

	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", corpus)

	if files := offeredIn(corpus)[filepath.Base(corpus)]; files != 3 {
		t.Fatalf("listing counted %d files, want 3 — the count comes from the name, "+
			"so a document that cannot be parsed must still be counted: %+v", files, ListTemplateDirs())
	}
}

// `id:` is a top-level key, so an `id:` that belongs to something else — a
// comment, a value inside a list, a key whose name merely starts with these two
// letters — must not make a folder a template folder.
func TestOnlyATopLevelIDKeyMakesAFolderATemplateFolder(t *testing.T) {
	for name, content := range map[string]string{
		"id inside a comment":  "# id: not-a-template\nname: x\n",
		"id as a list value":   "values:\n  - id: not-a-template\n",
		"key merely starts":    "identify: true\nname: x\n",
		"indented under a key": "info:\n  id: not-a-template\n",
		"no id at all":         "name: x\nseverity: info\n",
	} {
		corpus := t.TempDir()
		if err := os.MkdirAll(corpus, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(corpus, "only.yaml"), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		t.Setenv("RR_NUCLEI_TEMPLATE_DIR", corpus)
		if offered := offeredIn(corpus); len(offered) != 0 {
			t.Fatalf("%s: a folder holding only that document was offered: %+v", name, offered)
		}
	}
}

// A template's `id:` sits in its first lines, but the key must still be found
// when the document opens with something else, and a line longer than the
// default scanner buffer must not end the scan early.
func TestIDIsFoundAfterOtherKeysAndAfterALongLine(t *testing.T) {
	corpus := t.TempDir()
	long := strings.Repeat("x", 1<<17)
	writeRawTemplate(t, filepath.Join(corpus, "later.yaml"),
		"info:\n  name: later\ndescription: "+long+"\nid: later\n")
	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", corpus)

	if files := offeredIn(corpus)[filepath.Base(corpus)]; files != 1 {
		t.Fatalf("a folder whose `id:` is not on the first line was not offered: %+v", ListTemplateDirs())
	}
}
