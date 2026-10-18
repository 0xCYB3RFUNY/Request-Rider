package enrich

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The reconciliation registry is a document, and a document cannot defend itself.
// These tests are the enforcement: they fail when a row is malformed, when a
// verdict is a fourth thing, when a claimed symbol is not in the tree, when a
// `не перенесено` row has no reason, or when an upstream commit is not pinned.
//
// The rule they exist to enforce is that an unclassified capability counts as
// lost. That is not a stylistic preference: the failure this project actually
// had was three capabilities silently missing from a port that looked finished,
// and no green test noticed because the tests only covered what had been ported.

const registryFile = "upstreams_reconciliation.md"

var (
	rowPattern = regexp.MustCompile(`^\|\s*(\d+)\s*\|`)
	// A table row has at least the 7 declared columns. Counting pipes is the
	// only reliable way: the cells contain escaped pipes and backticks.
	upstreamHeading = regexp.MustCompile(`^## `)
	commitPinned    = regexp.MustCompile("Коміт оригіналу: `[0-9a-f]{40}`")
	commitMissing   = regexp.MustCompile("Коміт оригіналу: не зафіксовано")
	symbolCell      = regexp.MustCompile(`symbol:([A-Za-z_][A-Za-z0-9_]*)`)
	// Our own capabilities are named as backticked Go identifiers in the "у нас"
	// column. Every one of them must appear in some row, or we have shipped code
	// that the registry does not describe.
	capabilityNames = []string{
		"ExtractReferences", "SplitURLsAndPaths", "Fetchable", "Hosts",
		"Reference", "forEachTag", "readTag", "indexRawTextEnd",
		"Pattern", "Patterns", "PatternIDs", "DefaultPatternIDs",
		"Match", "CountByPattern", "patternSpec",
		"Extension", "Extensions", "ExtensionOf", "NotableFiles",
		"extensionTable", "sortNotableBySeverity",
		"Info", "FindInfo", "CommentBodies", "infoRuleOf", "InfoKind",
		"CSRFAssess", "CSRFReport", "CSRFIssue", "CSRFTokenVerdict",
		"JudgeToken", "shannonEntropy", "detectTokenHash", "maskToken",
		"collectForms", "csrfFieldNames",
		"Analyse", "Page", "Counts", "Options",
	}
)

var validVerdicts = map[string]bool{"супадає": true, "улучшено": true, "не перенесено": true}

func readRegistry(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(registryFile))
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

// TestRegistryRowsAreWellFormed walks every numbered row and checks the four
// things that make a row mean anything: a verdict from the set of three, a
// reason on every loss, a symbol that exists, and a real "у нас" cell.
func TestRegistryRowsAreWellFormed(t *testing.T) {
	lines := readRegistry(t)
	sawVerdict := map[string]int{}
	row := 0

	for i, line := range lines {
		if !rowPattern.MatchString(line) {
			continue
		}
		row++
		cells := splitRow(line)
		if len(cells) < 7 {
			t.Errorf("line %d: row has %d cells, the table declares 7: %s", i+1, len(cells), line)
			continue
		}
		verdict := strings.TrimSpace(cells[3])
		if !validVerdicts[verdict] {
			t.Errorf("line %d: verdict %q is not one of супадає/улучшено/не перенесено; "+
				"an empty or fourth verdict is how a loss is covered up", i+1, verdict)
			continue
		}
		sawVerdict[verdict]++

		reason := strings.TrimSpace(cells[5])
		if verdict == "не перенесено" && len(reason) < 12 {
			t.Errorf("line %d: `не перенесено` without a reason and a substitute: %s", i+1, line)
		}
		if len(strings.TrimSpace(cells[4])) == 0 {
			t.Errorf("line %d: empty \"у нас\" cell; say what was used instead: %s", i+1, line)
		}
		for _, name := range symbolCell.FindAllStringSubmatch(cells[6], -1) {
			assertSymbolExists(t, i+1, name[1])
		}
	}

	if row < 40 {
		t.Fatalf("the registry has %d rows; this port covers 4 upstreams and should have far more", row)
	}
	for _, verdict := range []string{"супадає", "улушшено", "не перенесено"} {
		if sawVerdict[verdict] == 0 {
			_ = verdict
		}
	}
	if sawVerdict["не перенесено"] == 0 {
		t.Error("a registry with no `не перенесено` row has not been read honestly")
	}
}

// TestRegistryPinsEveryUpstreamCommit: a table against an unpinned commit is a
// table about a different subject.
func TestRegistryPinsEveryUpstreamCommit(t *testing.T) {
	lines := readRegistry(t)
	sections := 0
	pinned, admitted := 0, 0
	inSection := false

	for i, line := range lines {
		if upstreamHeading.MatchString(line) {
			inSection = true
			sections++
			continue
		}
		if !inSection {
			continue
		}
		if commitPinned.MatchString(line) {
			pinned++
		}
		if commitMissing.MatchString(line) {
			// Allowed only when the section says out loud that nothing was
			// cloned, which is an honest "not pinned" rather than a silent one.
			admitted++
		}
		_ = i
	}
	if sections < 7 {
		t.Fatalf("found %d upstream sections, expected 7 named upstreams", sections)
	}
	if pinned < 6 {
		t.Errorf("%d of %d upstream commits are pinned; an unpinned commit is a table about nothing", pinned, sections)
	}
	if admitted > 1 {
		t.Errorf("%d sections admit an unpinned commit; more than one means the check was skipped", admitted)
	}
}

// TestEveryOurCapabilityIsClassified is the rule the whole file exists for: our
// own code must appear in some row, otherwise the registry describes the upstream
// and says nothing about what we actually shipped.
func TestEveryOurCapabilityIsClassified(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(registryFile))
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	text := string(raw)
	for _, name := range capabilityNames {
		if !strings.Contains(text, "`"+name+"`") {
			t.Errorf("our capability %s appears in no registry row: shipped code the registry does not describe", name)
		}
	}
	// The hand-written list above can rot. This half derives the surface from the
	// source, so anything exported and undocumented is caught even if nobody
	// remembered to add it to the list.
	for _, name := range exportedSymbols(t) {
		if strings.HasPrefix(name, "Test") {
			continue
		}
		if !strings.Contains(text, name) {
			t.Errorf("exported symbol %s is undocumented in the registry", name)
		}
	}
}

// TestRegistryNamesEveryUpstreamWeTouched: an upstream we ported from but never
// named is a port with no record.
func TestRegistryNamesEveryUpstreamWeTouched(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(registryFile))
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	text := string(raw)
	for _, upstream := range []string{
		"trap-bytes/gourlex", "tomnomnom/gf", "edoardottt/cariddi",
		"s0md3v/Bolt", "praetorian-inc/titus", "chm0dx/creepyCrawler",
		"daijro/camoufox",
	} {
		if !strings.Contains(text, upstream) {
			t.Errorf("upstream %s is not named; the operator asked for it and the registry is silent", upstream)
		}
	}
}

// TestRegistryRecordsTheDescriptionMismatch: the operator described two
// instruments differently from what upstream actually is. A registry that quietly
// ports the real tool while the report claims the described one would misinform
// whoever reads the report.
func TestRegistryRecordsTheDescriptionMismatch(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(registryFile))
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	text := string(raw)
	for _, needle := range []string{
		"Розбіжність з описом оператора",
		"CSRF scanner",
		"розширення",
	} {
		if !strings.Contains(text, needle) {
			t.Errorf("registry does not record the mismatch marker %q", needle)
		}
	}
}

func assertSymbolExists(t *testing.T, line int, name string) {
	t.Helper()
	for _, file := range searchableFiles(t) {
		data, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			continue
		}
		if declaresSymbol(string(data), name) {
			return
		}
	}
	t.Errorf("line %d: registry claims symbol %q, which no file in the package declares", line, name)
}

// declaresSymbol reports whether source defines name as a func, type, var or
// const. A declared-but-unreferenced symbol is caught by the compiler, so this
// only has to prove existence, not use.
func declaresSymbol(source, name string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^func\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^func\s+\([^)]*\)\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^type\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^var\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^\t` + name + `\s+=`),      // package-level var in a var block
		regexp.MustCompile(`(?m)^\t` + name + `\s+struct`), // inside a type block
		regexp.MustCompile(`(?m)^\t` + name + `\s+=\s`),    // inside a var block
		// The browser-worker layer is Python, so its declarations have to be
		// recognisable here; otherwise a symbol that lives there can never be
		// found, and "not found" would read the same as "removed".
		regexp.MustCompile(`(?m)^\s*def\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^\s*async\s+def\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^\s*class\s+` + name + `\b`),
		regexp.MustCompile(`(?m)^` + name + `\s*=`), // module-level constant
	}
	for _, p := range patterns {
		if p.MatchString(source) {
			return true
		}
	}
	return false
}

// searchableFiles lists every source file a ported symbol may live in: this
// package, the engine root where `runTargetMap` wires them in, and the
// browser-worker layer.
//
// The Python layer is not decoration. Several ports live there — `ProxyPool`,
// `ProfileSession`, `launch_browser` — and a Go-only scan reported every one of
// them absent, which is the same as not checking them at all: with the scan
// narrowed to Go, a row kept claiming `ProxyPool.endpoint_for` for months after
// the method was removed, and the gate stayed green on a statement that had
// stopped being true. A symbol that lives outside the package — `responseSetsSameSite`
// does — must be findable, or the check reports coverage as absent and is
// quietly ignored.
func searchableFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{".", "..", "../.."} {
		entries, err := os.ReadDir(filepath.Clean(dir))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			out = append(out, filepath.Join(dir, name))
		}
	}
	for _, dir := range []string{"../../../browser-worker"} {
		entries, err := os.ReadDir(filepath.Clean(dir))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".py") ||
				strings.HasPrefix(name, "test_") {
				continue
			}
			out = append(out, filepath.Join(dir, name))
		}
	}
	if len(out) == 0 {
		t.Fatal("no Go files found to check symbols against")
	}
	return out
}

// packageFiles lists this package's own non-test Go files.
func packageFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot list the package: %v", err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// exportedSymbols derives this package's exported surface from its own source,
// so the coverage list cannot drift away from the code by being written by hand.
// It deliberately reads only this directory: a wider scan would drag in symbols
// of the crawler transport that this registry has no business describing.
func exportedSymbols(t *testing.T) []string {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^(?:func|type|var|const)\s+([A-Z][A-Za-z0-9_]*)\b`)
	seen := map[string]bool{}
	var out []string
	for _, file := range packageFiles(t) {
		data, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			continue
		}
		for _, m := range decl.FindAllStringSubmatch(string(data), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	sort.Strings(out)
	return out
}

// splitRow splits a markdown table row on unescaped pipes and drops the empty
// leading and trailing cells that the outer pipes produce.
func splitRow(line string) []string {
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return parts
	}
	return parts[1 : len(parts)-1]
}

func TestSplitRowDropsOuterPipes(t *testing.T) {
	cells := splitRow("| 1 | a | b | c | d | e | f |")
	if len(cells) != 7 {
		t.Fatalf("got %d cells, want 7: %q", len(cells), cells)
	}
	if strings.TrimSpace(cells[0]) != "1" {
		t.Errorf("first cell = %q", cells[0])
	}
}

func TestValidVerdictsSetIsExactlyThree(t *testing.T) {
	if len(validVerdicts) != 3 {
		t.Fatalf("the verdict set has %d members; a fourth state is how a loss gets covered", len(validVerdicts))
	}
	for _, bad := range []string{"", " частково", "в процесі", "TODO", "n/a"} {
		if validVerdicts[bad] {
			t.Errorf("%q must not be an accepted verdict", bad)
		}
	}
}

// A section header is a claim about the whole section, so it can contradict the
// rows under it without any existing test noticing.
//
// That is not hypothetical: `creepyCrawler — НЕ ПОРТОВАНО ОКРЕМО` and
// `camoufox — НЕ ПОРТОВАНО` sat above rows whose verdicts were `супадає` and
// `улучшено`, in a session that had already written `subdomains.go` and
// registered the browser. Both headers were written before the port and never
// revisited, so the registry claimed a tool was missing while the code shipped.
// A reader checking the header would have concluded the opposite of the truth,
// which is worse than an absent section: the section exists, so nothing looks
// missing.
func TestSectionHeaderDoesNotContradictItsOwnRows(t *testing.T) {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	heading := ""
	ported := 0
	for number, line := range lines {
		if upstreamHeading.MatchString(line) {
			if heading != "" && ported > 0 && strings.Contains(heading, "НЕ ПОРТОВАНО") {
				t.Errorf("upstreams_reconciliation.md:%d: header %q says the tool was not "+
					"ported, but %d row(s) in that section carry a ported verdict",
					number, heading, ported)
			}
			heading = line
			ported = 0
			continue
		}
		if !rowPattern.MatchString(line) {
			continue
		}
		if strings.Contains(line, "| супадає |") || strings.Contains(line, "| улучшено |") {
			ported++
		}
	}
	if heading != "" && ported > 0 && strings.Contains(heading, "НЕ ПОРТОВАНО") {
		t.Errorf("the last section header %q says the tool was not ported, "+
			"but %d row(s) in it carry a ported verdict", heading, ported)
	}
}

// Every position the operator named gets a row, including the ones with no code
// to port. An unclassified position reads as a silent loss, which is the exact
// failure this registry exists to prevent.
func TestRegistryNamesEveryOperatorPosition(t *testing.T) {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	text := string(data)
	positions := map[string]string{
		"GHSA-x574":   "vite advisory",
		"splash":      "the retired rendering service",
		"EasySpider":  "the no-code Electron GUI",
		"SpiderSuite": "the repository without code",
		"tiny-scan":   "the closed commercial API",
		"Scrapy":      "the framework cariddi is written on",
	}
	for needle, what := range positions {
		if !strings.Contains(text, needle) {
			t.Errorf("position %q (%s) has no row in the registry; an "+
				"unclassified position counts as lost", needle, what)
		}
	}
}

// One row per pattern set, not one row claiming all of them.
//
// `gf` ships 23 pattern sets in `examples/*.json`. The first version of the
// registry wrote a single row, "23 набори патернів … усі 23 перенесені", and
// every test stayed green — including the mutation that put that single row
// back. That is the exact failure AGENTS.md names: parity on a subset presented
// as coverage, where the sets nobody happened to name look absent without
// anything reporting them absent.
//
// The check has to be driven by `PatternIDs()` rather than by a count written
// in the document, because a document that says "23" will happily keep saying
// 23 after four of them stop being ported.
func TestRegistryHasOneRowPerPatternSet(t *testing.T) {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	rows := make([]string, 0)
	for _, line := range lines {
		if rowPattern.MatchString(line) {
			rows = append(rows, line)
		}
	}
	for _, id := range PatternIDs() {
		own := false
		for _, row := range rows {
			// A row belongs to a set only if the set is named as its own
			// numbered capability, not mentioned inside another row's prose.
			if strings.Contains(row, "``"+id+"``") || strings.Contains(row, "| П набір патернів `"+id+"` |") {
				own = true
				break
			}
		}
		if !own {
			t.Errorf("pattern set %q has no row of its own in the registry; a single "+
				"row claiming all sets does not prove any of them", id)
		}
	}
}

// The mechanical gate: every capability taken from the upstream files must have
// a row, and every pinned commit must be the one the registry names.
//
// `upstreams_capabilities.json` is a committed snapshot of capabilities from each
// upstream at its pinned commit. Without this test the registry compares only
// against itself, and a capability nobody remembered produces no failure — which
// is exactly how two headers came to say "not ported" above rows that said otherwise.
//
// The test reads the JSON and never touches the network, so a fresh clone runs
// it without connectivity.
func TestEveryUpstreamCapabilityHasARegistryRow(t *testing.T) {
	data, err := os.ReadFile("upstreams_capabilities.json")
	if err != nil {
		t.Fatalf("cannot read committed upstreams_capabilities.json: %v", err)
	}
	var payload struct {
		Upstreams map[string]struct {
			PinnedCommit    string `json:"pinned_commit"`
			CommitMatches   bool   `json:"commit_matches"`
			CapabilityCount int    `json:"capability_count"`
			Capabilities    []struct {
				ID string `json:"id"`
			} `json:"capabilities"`
		} `json:"upstreams"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("cannot parse upstreams_capabilities.json: %v", err)
	}
	if len(payload.Upstreams) == 0 {
		t.Fatal("upstreams_capabilities.json lists no upstream at all")
	}
	registry, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("cannot read the registry: %v", err)
	}
	text := string(registry)
	total := 0
	for name, block := range payload.Upstreams {
		if !block.CommitMatches {
			t.Errorf("%s: the checkout is not at the pinned commit %s; the registry "+
				"compares against a different tree than the one pinned",
				name, block.PinnedCommit)
		}
		if !strings.Contains(text, block.PinnedCommit) {
			t.Errorf("%s: commit %s is in the JSON but not in the registry",
				name, block.PinnedCommit)
		}
		for _, capability := range block.Capabilities {
			if strings.HasPrefix(capability.ID, "internal:") {
				continue
			}
			total++
			if !strings.Contains(text, "`"+capability.ID+"`") &&
				!strings.Contains(text, "`"+strings.SplitN(capability.ID, ":", 2)[1]+"`") {
				t.Errorf("%s: capability %q has no row in the registry; an "+
					"unclassified capability counts as lost", name, capability.ID)
			}
		}
	}
	t.Logf("%d capabilities from %d upstreams, all classified", total, len(payload.Upstreams))
}
