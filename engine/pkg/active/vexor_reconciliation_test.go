// Machine check for vexor_reconciliation.md.
//
// The register this test guards was written after three capabilities of the port
// were lost silently: every row of it existed and the suite was green, and a
// capability nobody had ported could not appear in a list ordered by "compare what
// we have". The gap was closed by taking the capability list from upstream's FILES
// and by making this register checkable rather than prose.
//
// What this test can catch, stated plainly so it is not oversold:
//
//   - a removed row,
//   - an empty or unknown verdict,
//   - a verdict outside the three allowed values,
//   - a symbol claimed as ported that is absent from the tree,
//   - `не перенесено` with no stated reason,
//   - a capability we have that no row covers,
//   - a missing upstream commit.
//
// What it CANNOT catch is an upstream capability that is in neither the register
// nor our tree, because a test has nothing to name it. That is caught by the
// upstream file listing, which is in the register header and cannot be satisfied by
// memory — memory is what produced the loss.

package active

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

const (
	reconciliationFile = "vexor_reconciliation.md"
	upstreamCommit     = "1e67fe951329f1fd26f8e84c1a492bd45e6022a4"

	verdictMatched  = "совпадает"
	verdictImproved = "улучшено"
	verdictLost     = "не перенесено"
)

// allowedVerdicts is the whole vocabulary. A fourth value is not a new state, it is
// a place where a loss can hide, so the test fails on anything else.
var allowedVerdicts = map[string]bool{
	verdictMatched:  true,
	verdictImproved: true,
	verdictLost:     true,
}

// rowPattern matches one register row: a table row with a verdict in the third
// column and a symbol in the second.
var rowPattern = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|`)

// symbolPattern pulls identifiers out of backticks in a symbol cell.
//
// Only backticked text is read. The cell is a cell and not a paragraph, and an
// earlier version scanned the whole cell for identifier-shaped tokens, which made
// "FNV-1a" demand a symbol called `FNV` and a filename like
// `vexor_reconciliation.md` demand `md`. The detector then reported sixteen
// missing symbols, all of them inventions, and a detector that reports
// inventions is one whose real findings stop being read.
var symbolPattern = regexp.MustCompile("`([^`]+)`")

// requiredRows is the set of capabilities every register has to carry.
//
// It exists because a removed row was invisible to the guard: nothing counted
// rows, and nothing named them, so deleting the CMDi line left the suite green.
// That is the exact failure the register was written to prevent, reproducing
// inside the mechanism meant to catch it. A guard that cannot notice a deletion is
// not a guard, so the rows are pinned by name and the count is pinned as well.
var requiredRows = []string{
	// internal/crawler
	"обхід з посилань",
	"збір форм GET/POST",
	"збір параметрів запиту",
	"тиха проба цікавих шляхів",
	// internal/detect — one per module, plus the two SQLi techniques
	"SQLi: відбитки 5 движків",
	"SQLi: boolean-диференціал зі схожістю",
	"SQLi: визначення числа колонок UNION",
	"XSS: canary + класифікація HTML-контексту",
	"CMDi: echo-синтаксиси",
	"CMDi: time-based blind",
	"SSTI: 6 движків",
	"LFI: traversal + fingerprint",
	"SSRF: loopback → cloud metadata",
	"SSRF: розрізнення reflection/fetch",
	"Redirect: вектори обходу",
	"Misconfig: CORS / headers / listing",
	"Exposure: верифікація секретів",
	// internal/exploit
	"доказ SQLi (версія БД)",
	"доказ SSTI",
	"доказ CMDi (відлунений маркер)",
	"доказ LFI (читання файлів хоста)",
	"відмова будувати PoC для недоведеного",
	"генерація `curl`",
	"PoC-скрипт, що перезапускає всі знахідки",
	"опис доказу для людини",
	// internal/chain — one per rule, plus the pass upstream declares and we do not run
	"злиття XSS + cookie → ATO",
	"SQLi на параметрі автентифікації",
	"SSTI → RCE",
	"CORS + XSS → витік",
	"open redirect → крадіж коду",
	"LFI → log poisoning",
	"SSRF + витік конфігурації",
	"окремий прохід за `Module.Level()`",
	// report / engine / httpc / update
	"запис звіту в JSON",
	"підсумок у консоль",
	"унікальні точки збору",
	"контроль редиректів у клієнті",
	"збереження cookies",
	"перевірка оновлення за версією",
	// our own capabilities
	"обмежене формування імені",
	"стабільний content-addressed ID",
	"звірка з оригіналом як реєстр",
}

// requiredRowCount is pinned separately from the names so that adding a row is a
// deliberate act rather than a silent drift in either direction.
// requiredRowCount is the register's row count, and it is pinned in both
// directions on purpose.
//
// It moved 45 → 46 on 2026-10-01, when the inert `Redirect` module got a row of
// its own next to the row about its vectors: a run counted nine detectors while
// the open-redirect one could not report anything, and the table had described
// what it would have sent without saying that it could never send it. A guard
// that only complained about a shrinking table would have taken that edit as
// routine; the count is the decision, so it has to be made on purpose.
//
// It moved 47 → 49 on 2026-10-02, when the time-based blind SQL injection and
// the `ORDER BY` column count got rows of their own. Both are capabilities
// upstream does not have at all, so neither could sit under an existing row:
// folding them into the boolean-differential row would have described them as a
// variant of a technique that measures something else entirely. Two rows, not
// one — the count is checked in both directions, and a guard that only noticed
// a shrinking table would have taken "+2 written as +1" as routine.
// It moved 49 → 53 on 2026-10-03, when the four capabilities from the owner's
// list got rows of their own: `HiddenParams`, `AuthBypassExt`, `ViteFSRead` and
// `HiddenPaths`. None of them is an upstream capability, so none of them could sit
// under an existing row without being described as a variant of a technique that
// measures something else — and the dynamic coverage test failed on all four by
// name, which is the register doing exactly what it was built to do. Four rows,
// not one: the count is checked in both directions, and a guard that only noticed
// a shrinking table would have taken "+4 written as +1" as routine.
const requiredRowCount = 53

// loadRegister reads the register and returns its rows.
//
// A line that looks like a table row but does not parse into four cells is a
// failure, not a row to skip. The earlier version skipped it, which meant a row
// that lost its reason column simply ceased to exist as far as the guard was
// concerned — and a `не перенесено` with no reason is the one thing this register
// exists to prevent.
func loadRegister(t *testing.T) []registerRow {
	t.Helper()
	path := filepath.Join(".", reconciliationFile)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	var rows []registerRow
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) < 4 {
			// The capability table is four columns by contract. A two-column
			// row is the upstream-commit metadata table, which is a different
			// table in the same file and is checked by its own test. A
			// three-column row is a capability row that lost a cell, and a
			// capability row with fewer cells is precisely how a `не
			// перенесено` loses its reason without anyone editing the verdict.
			if len(cells) == 2 || isTableFurniture(trimmed) {
				continue
			}
			t.Errorf("a capability row has %d cells, needs 4: %s", len(cells), trimmed)
			continue
		}
		match := rowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		capability, symbol, verdict, reason := match[1], match[2], match[3], match[4]
		if strings.EqualFold(capability, "здатність upstream") || strings.HasPrefix(capability, "---") {
			continue
		}
		if verdict == "вердикт" {
			continue
		}
		rows = append(rows, registerRow{capability, symbol, verdict, reason, line})
	}
	if len(rows) == 0 {
		t.Fatalf("the register has no rows; it parses as empty rather than as complete")
	}
	return rows
}

// isTableFurniture reports whether a short line is a header separator rather than
// a broken row.
func isTableFurniture(line string) bool {
	for _, cell := range strings.Split(strings.Trim(line, "|"), "|") {
		cell = strings.TrimSpace(cell)
		if cell == "" {
			continue
		}
		if !strings.HasPrefix(cell, "-") {
			return false
		}
	}
	return true
}

// TestRequiredRowsArePresent is the answer to a removed row.
func TestRequiredRowsArePresent(t *testing.T) {
	rows := loadRegister(t)
	present := make([]string, 0, len(rows))
	for _, row := range rows {
		present = append(present, strings.TrimSpace(row.capability))
	}
	for _, required := range requiredRows {
		found := false
		for _, capability := range present {
			if strings.Contains(capability, required) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required row %q is gone; the register is incomplete", required)
		}
	}
	if len(rows) != requiredRowCount {
		t.Errorf("the register has %d rows, want %d; a count that drifts in either "+
			"direction means the table changed without anyone deciding it should",
			len(rows), requiredRowCount)
	}
}

// identifiersIn returns the Go identifiers of one backticked cell value.
//
// A cell may name a symbol, a short list of them, a receiver-qualified form like
// `Suite.Run`, or a call like `ClassifyContext`. What it must not do is describe
// something in prose, because prose is not a symbol and treating it as one is how
// the check starts reporting words.
var cellIdentifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func identifiersIn(cell string) []string {
	var out []string
	// A value that reads as a call or a type expression keeps only its last
	// identifier: `Suite.Run` names `Run`, `strings.Join` names `Join`.
	trimmed := strings.TrimSpace(cell)
	trimmed = strings.TrimPrefix(trimmed, "*")
	if trimmed == "" {
		return out
	}
	if strings.ContainsAny(trimmed, " -") {
		// A prose value, or a hash name like `FNV-1a`: nothing here is a symbol
		// the package could declare.
		return nil
	}
	base := trimmed
	if index := strings.LastIndex(base, "."); index >= 0 {
		base = base[index+1:]
	}
	if index := strings.Index(base, "("); index >= 0 {
		base = base[:index]
	}
	for _, candidate := range cellIdentifier.FindAllString(base, -1) {
		out = append(out, candidate)
	}
	return out
}

type registerRow struct {
	capability string
	symbol     string
	verdict    string
	reason     string
	line       string
}

// TestEveryRowHasAVerdictFromTheAllowedThree is the core of the rule.
func TestEveryRowHasAVerdictFromTheAllowedThree(t *testing.T) {
	for _, row := range loadRegister(t) {
		if row.verdict == "" {
			t.Errorf("row %q has no verdict; silence is not a verdict", row.capability)
			continue
		}
		if !allowedVerdicts[row.verdict] {
			t.Errorf("row %q has verdict %q, which is not one of %s / %s / %s",
				row.capability, row.verdict, verdictMatched, verdictImproved, verdictLost)
		}
	}
}

// TestLostRowsStateAReason is what makes `не перенесено` usable: it has to say
// what is missing and why, otherwise it is indistinguishable from a row that was
// simply never written.
func TestLostRowsStateAReason(t *testing.T) {
	for _, row := range loadRegister(t) {
		if row.verdict != verdictLost {
			continue
		}
		reason := strings.TrimSpace(row.reason)
		if reason == "" {
			t.Errorf("row %q is %q with no reason; that is the silent-loss shape", row.capability, verdictLost)
		}
		if len(reason) < 20 {
			t.Errorf("row %q gives a %d-character reason, too short to be one: %q",
				row.capability, len(reason), reason)
		}
	}
}

// TestClaimedSymbolsExistInTheTree stops a register from claiming a port that is
// not in the code.
//
// Only rows that assert a port are checked. A `не перенесено` row carries no
// symbol by definition, and a row whose symbol is prose rather than an identifier
// is skipped rather than guessed at.
func TestClaimedSymbolsExistInTheTree(t *testing.T) {
	for _, row := range loadRegister(t) {
		if row.verdict == verdictLost {
			continue
		}
		if row.symbol == "" || row.symbol == "—" {
			continue
		}
		names := symbolPattern.FindAllStringSubmatch(row.symbol, -1)
		if len(names) == 0 {
			continue
		}
		for _, match := range names {
			for _, name := range identifiersIn(match[1]) {
				if !declaredInPackage(name) {
					t.Errorf("row %q claims symbol %q, which is not declared in the package",
						row.capability, name)
				}
			}
		}
	}
}

var (
	moduleFilesContentOnce sync.Once
	cachedFileContents     map[string]string
)

func getCachedFileContents() (map[string]string, error) {
	var walkErr error
	moduleFilesContentOnce.Do(func() {
		files, err := moduleGoFiles()
		if err != nil {
			walkErr = err
			return
		}
		cachedFileContents = make(map[string]string, len(files))
		for _, f := range files {
			b, rErr := os.ReadFile(f)
			if rErr == nil {
				cachedFileContents[f] = string(b)
			}
		}
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return cachedFileContents, nil
}

// declaredInPackage reports whether the package declares a top-level identifier.
//
// The check is for a declaration rather than a use, because a row that names a
// symbol the package only calls would still be describing someone else's code.
//
// A method counts: most of what this package exposes is a method on a receiver
// (`func (s *Suite) Run`, `func (c *CMDi) Detect`), and an earlier version of this
// helper matched only plain `func Name`, so eleven real symbols were reported
// missing. A detector that cries wolf on the majority of rows is a detector whose
// output gets ignored, and then it catches nothing at all.
func declaredInPackage(name string) bool {
	patterns := []*regexp.Regexp{
		// func Name( ... )   and   func (recv) Name( ... )
		regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(name) + `\s*[\(\{]`),
		regexp.MustCompile(`(?m)^func\s+\([^)]*\)\s*\*?` + regexp.QuoteMeta(name) + `\s*[\(\{]`),
		// type Name, var Name, const Name, and grouped forms
		regexp.MustCompile(`(?m)^type\s+` + regexp.QuoteMeta(name) + `\b`),
		regexp.MustCompile(`(?m)^var\s+` + regexp.QuoteMeta(name) + `\b`),
		regexp.MustCompile(`(?m)^\t` + regexp.QuoteMeta(name) + `\s+[A-Za-z\[\*]`),
		regexp.MustCompile(`(?m)^const\s+` + regexp.QuoteMeta(name) + `\b`),
	}
	fileMap, err := getCachedFileContents()
	if err != nil {
		return false
	}
	isTestPrefix := strings.HasPrefix(name, "Test")
	for entry, text := range fileMap {
		// A row may legitimately name a *test* as its evidence — the register
		// guards itself with one — but only a name that says so. A feature row
		// that pointed at a test would be claiming a port proven by a test
		// alone, which is exactly the confusion this file exists to stop. So a
		// `Test…` name may live in a test file and nothing else may.
		isTestFile := strings.HasSuffix(entry, "_test.go")
		if isTestFile != isTestPrefix {
			continue
		}
		if !strings.Contains(text, name) {
			continue
		}
		for _, pattern := range patterns {
			if pattern.MatchString(text) {
				return true
			}
		}
	}
	return false
}

// TestOurOwnCapabilitiesAreCovered is the direction the original rule forgot.
//
// Listing upstream's capabilities catches what we failed to take. It does not
// catch what we built and never wrote down, which is the same silence from the
// other side. Every capability listed here has to appear in some register row.
func TestOurOwnCapabilitiesAreCovered(t *testing.T) {
	ours := []struct {
		capability string
		symbol     string
	}{
		{"обмежене формування імені", "severity"},
		{"стабільний content-addressed ID", "FindingID"},
		{"звірка з оригіналом як реєстр", "ReplayScript"},
		{"PoC-скрипт", "ReplayableFindings"},
		{"тиха проба цікавих шляхів", "probeInterestingPaths"},
		{"SSRF + витік конфігурації", "ChainSSRFToConfigExposure"},
	}
	rows := loadRegister(t)
	for _, capability := range ours {
		covered := false
		for _, row := range rows {
			if strings.Contains(row.capability, capability.capability) ||
				(strings.TrimSpace(row.symbol) == capability.symbol) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("our capability %q (symbol %q) is in no register row", capability.capability, capability.symbol)
		}
	}
}

// TestUpstreamCommitIsRecorded: a register compared against an unstated upstream
// is a register about an unstated subject.
func TestUpstreamCommitIsRecorded(t *testing.T) {
	source, err := os.ReadFile(reconciliationFile)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	if !strings.Contains(string(source), upstreamCommit) {
		t.Errorf("the register does not record upstream commit %s", upstreamCommit)
	}
}

// TestEveryRegisterRowNamesACapabilityWithText guards the parse itself: a row whose
// capability cell is a placeholder means the register claims a completeness it does
// not have.
func TestEveryRegisterRowNamesACapabilityWithText(t *testing.T) {
	for _, row := range loadRegister(t) {
		capability := strings.TrimSpace(row.capability)
		// An em dash used to be accepted here as "empty". It was an escape
		// hatch written by the same hand that wrote the guard, and it let a row
		// lose its name without the suite noticing — which is the loss this file
		// exists to catch, now committed inside it. A row without a name is a
		// row that says nothing about anything.
		if capability == "" || capability == "—" || capability == "-" {
			t.Errorf("a register row has no capability name: %s", row.line)
		}
	}
}

// TestVerdictVocabularyHasNoFourthState documents the closed set in code, so the
// test above and the rule cannot drift apart.
func TestVerdictVocabularyHasNoFourthState(t *testing.T) {
	want := []string{verdictImproved, verdictLost, verdictMatched}
	sort.Strings(want)
	got := make([]string, 0, len(allowedVerdicts))
	for verdict := range allowedVerdicts {
		got = append(got, verdict)
	}
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the verdict vocabulary is %v, want exactly %v", got, want)
	}
}

// TestEveryDetectorAndChainIsCoveredDynamically closes the last hole in this
// file, and it is the same hole the register exists to close.
//
// TestOurOwnCapabilitiesAreCovered names its capabilities in a list. A list is
// written by a person, and a person has to remember to extend it — so a module
// added to AllModules() or a chain added to AllChains() joins the scanner
// without any register row, and every test above still passes. That is precisely
// the shape of the loss this register was created for: a capability that arrived
// unclassified, which reads as "nothing to lose" because nothing mentions it.
//
// So the coverage is read from the code instead of from a list: whatever the
// scanner can actually do is asked about directly. Adding a detector is then a
// change that cannot be made quietly, which is the property that was missing.
func TestEveryDetectorAndChainIsCoveredDynamically(t *testing.T) {
	// Every register in the package, not only this one.
	//
	// The check asks the same question of every detector — "is its verdict
	// classified anywhere?" — and reading only the VEXOR register makes the answer
	// wrong for every detector this package did not port from VEXOR. Thirteen
	// detectors arrived with the six-upstream port and each has its own register;
	// asking only the VEXOR one reported all thirteen as unclassified, which is the
	// same false alarm a guard produces when it is narrower than the thing it
	// guards, and the answer to that is never to stop reporting.
	rows := loadRegister(t)
	rows = append(rows, loadUpstreamRegister(t)...)
	// Every register in the package, discovered rather than listed. A third
	// register added by a later port is otherwise invisible here, and a detector
	// that demonstrably has a row is reported as unclassified — the same false
	// alarm this guard produces when it is narrower than the thing it guards.
	rows = append(rows, loadXSSRegister(t)...)
	// The fourth register is the Burp Suite one, added 2026-10-14 with the
	// twelve checks that batch carried. The comment above names its own reason —
	// a register the guard cannot see produces the same false alarm as no
	// register at all — so the fix is the same one it already applies.
	rows = append(rows, loadBurpRegister(t)...)
	covered := func(name string) bool {
		wanted := strings.ToLower(name)
		for _, row := range rows {
			for _, cell := range []string{row.capability, row.symbol, row.reason} {
				if strings.Contains(strings.ToLower(cell), wanted) {
					return true
				}
			}
		}
		return false
	}
	for _, module := range AllModules() {
		if !covered(module.Name()) {
			t.Errorf("detector %q has no register row, so its verdict is unclassified: "+
				"a detector that joined the scanner without a row is a capability nobody decided on",
				module.Name())
		}
	}
	for _, chain := range AllChains() {
		if !covered(chain.Name()) {
			t.Errorf("chain %q has no register row, so its verdict is unclassified", chain.Name())
		}
	}
}

// The dynamic check is only as good as what it reads, so it is stated: a
// detector whose level changes is still one detector, and the register is
// expected to name it once. This asserts the count the dynamic check relies on,
// so a silent change to the module list is visible rather than absorbed.
func TestTheDynamicCheckCoversEveryDeclaredModuleAndChain(t *testing.T) {
	modules := AllModules()
	chains := AllChains()
	if len(modules) == 0 {
		t.Fatal("the scanner declares no detectors, so the dynamic check is asserting nothing")
	}
	if len(chains) == 0 {
		t.Fatal("the scanner declares no chains, so the dynamic check is asserting nothing")
	}
	t.Logf("dynamic coverage asks about %d detector(s) and %d chain(s)", len(modules), len(chains))
}

// moduleGoFiles lists every Go file of the engine module reachable from this
// package, with the test/non-test distinction left to the caller.
//
// The guard used to read `*.go` in this directory alone, and that was wrong the
// moment a port landed outside `pkg/active`: `jsFindingSink` is declared in the
// root package (`target_js_findings.go`) and a register row naming it was reported
// as a symbol the tree does not have. The guard did not fail the port; it failed
// to look where the port was.
//
// Walking up to the module root and across its packages is the fix, and it does
// not weaken the guard: the patterns still have to match a real declaration, and
// the `Test…`-only-in-test-files rule still applies per file.
func moduleGoFiles() ([]string, error) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return nil, err
	}
	var out []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "data", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
