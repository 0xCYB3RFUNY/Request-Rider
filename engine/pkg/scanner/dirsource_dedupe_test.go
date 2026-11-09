package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two roots holding the same category is the normal case, not an edge: the
// operator keeps their own corpus and the official one is also installed, and
// both have `http`. `ResolveTemplateDir` answers a relative name against the
// roots in order, so a listing that offers the same name twice puts a row in the
// dropdown that cannot be selected — picking the second `http` sends the name and
// runs the FIRST root's folder, while the file count on screen belongs to the
// second. One row per name, from the root that wins, is what the run does.

func TestAListingOffersANameOnceFromTheRootThatWillRun(t *testing.T) {
	primary := t.TempDir()
	secondary := t.TempDir()

	writeTemplate(t, filepath.Join(primary, "http", "cves", "one.yaml"), "primary-one",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/1\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	// The same category in the second root, with a different count, so the row
	// that survives can be told apart by the count as well as by the path.
	writeTemplate(t, filepath.Join(secondary, "http", "cves", "one.yaml"), "secondary-one",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/1\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	writeTemplate(t, filepath.Join(secondary, "http", "cves", "two.yaml"), "secondary-two",
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/2\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	// A category only the second root has must still be offered: deduplicating by
	// name must not become "only look at the first root".
	writeTemplate(t, filepath.Join(secondary, "dns", "only-here.yaml"), "only-here",
		"dns:\n  - name: \"{{FQDN}}\"\n    type: A\n    matchers:\n      - type: word\n        words:\n          - hit\n")

	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", primary+string(os.PathListSeparator)+secondary)

	entries := ListTemplateDirs()
	byName := map[string][]TemplateDirEntry{}
	for _, entry := range entries {
		if underAnyRoot(entry.Path, primary, secondary) {
			byName[entry.Name] = append(byName[entry.Name], entry)
		}
	}

	if rows := byName["http/cves"]; len(rows) != 1 {
		t.Fatalf("`http/cves` is offered %d times, want once: %+v", len(rows), rows)
	}
	// The surviving row must be the folder `ResolveTemplateDir` answers, because a
	// row that counts a folder nobody will run is a lie with a number on it.
	resolved, err := ResolveTemplateDir("http/cves")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if byName["http/cves"][0].Path != resolved {
		t.Fatalf("the offered row is %s but `ResolveTemplateDir` answers %s — picking that "+
			"row would run a different folder than the one on screen: %+v",
			byName["http/cves"][0].Path, resolved, byName["http/cves"])
	}
	if rows := byName["dns"]; len(rows) != 1 {
		t.Fatalf("a category only the second root holds must still be offered once: %+v", rows)
	}
}

// The dedupe must not depend on which root happens to sort first by path: the
// order that decides the winner is `templateDirRoots`' order, which is the order
// `ResolveTemplateDir` searches.
func TestTheRootThatWinsIsTheOneResolveTemplateDirSearchesFirst(t *testing.T) {
	// `a-first` and `z-second` sort the other way round as paths, so a listing
	// that grouped roots by path would offer the wrong row.
	first := filepath.Join(t.TempDir(), "z-first")
	second := filepath.Join(t.TempDir(), "a-second")
	for _, dir := range []string{first, second} {
		if err := os.MkdirAll(filepath.Join(dir, "http"), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		writeTemplate(t, filepath.Join(dir, "http", "only.yaml"), "t-"+filepath.Base(dir),
			"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: word\n        words:\n          - hit\n")
	}

	t.Setenv("RR_NUCLEI_TEMPLATE_DIR", first+string(os.PathListSeparator)+second)

	resolved, err := ResolveTemplateDir("http")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var offered []TemplateDirEntry
	for _, entry := range ListTemplateDirs() {
		if entry.Name == "http" && underAnyRoot(entry.Path, first, second) {
			offered = append(offered, entry)
		}
	}
	if len(offered) != 1 {
		t.Fatalf("`http` is offered %d times, want once: %+v", len(offered), offered)
	}
	if offered[0].Path != resolved {
		t.Fatalf("offered %s, resolve answers %s: %+v", offered[0].Path, resolved, offered)
	}
}

// underAnyRoot reports whether path is one of the given roots or inside it.
//
// `ListTemplateDirs` walks every configured root on this machine, not only the
// ones a test names, so an assertion has to say which rows it is talking about.
func underAnyRoot(path string, roots ...string) bool {
	for _, root := range roots {
		if path == root {
			return true
		}
		if len(path) > len(root) && strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
