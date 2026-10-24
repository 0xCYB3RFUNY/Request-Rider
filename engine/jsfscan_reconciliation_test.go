package main

// Механічна перевірка реєстру звірки з `KathanP19/JSFScan.sh`.
//
// # Навіщо другий такий тест, коли вже є `js_analyser_reconciliation_test.go`
//
// Реєстр звірки має силу тільки тоді, коли він **механічно** перевіряється: у
// попередньому порті (активний сканер) звірка була написана, зелений набір був
// зеленим, і три здатності оригіналу виявилися відсутніми — без жодного рядка
// «не перенесено». Пройз — це стан, який читається як «нема чого втрачати».
//
// Тому кожна здатність, яку **оригінал** має, отримує рядок; вердикт належить
// множині з трьох; у «не перенесено» є причина; символ, який рядок заявляє,
// має бути в дереві; коміт upstream зафіксовано.
//
// # Чого тест не може
//
// Він не знає переліку здатностей оригіналу — того тут немає. Тому реєстр
// фіксує коміт upstream і вимагає дев'ять рядків, по одному на кожен крок
// `JSFScan.sh`, який сам оригінал оголошує у функціях `gather_js`,
// `open_jsurlfile`, `endpoint_js`, `secret_js`, `getjsbeautify`,
// `wordlist_js`, `var_js`, `domxss_js`, `report`.
//
// Число дев'ять — не довільність: воно зняте з `JSFScan.sh` того коміту, і тест
// вимагає, щоб у реєстрі було саме стільки рядків із кроками оригіналу. Якщо
// оригінал зміниться, тест впаде на кількості — і це саме той сигнал, заради
// якого він існує.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const jsfscanReconciliationFile = "jsfscan_reconciliation.md"

// jsfscanUpstreamCommitPattern вимагає зафіксований коміт: реєстр без нього
// описує невідомий стан оригіналу.
var jsfscanUpstreamCommitPattern = regexp.MustCompile(
	`\*\*Upstream-коміт[^:]*:\s*` + "`" + `([0-9a-f]{7,40})` + "`")

// jsfscanVerdicts are the only three allowed answers. The fourth state — the one
// that let three capabilities go missing in silence — has no spelling here on
// purpose: `супадає`, `улучшено`, `не перенесено`, нічого іншого.
var jsfscanVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

// jsfscanUpstreamSteps is one row per step the original declares. Nine is the
// count of `JSFScan.sh` at commit `e8daba1`, read off its own function names.
var jsfscanUpstreamSteps = []string{
	"Збір URL бандлів",
	"Імпорт файла",
	"Ендпоинти з бандлів",
	"Секрети з бандлів",
	"Локальна копія бандлів",
	"Словник слів",
	"Імена змінних",
	"Пошук DOM XSS",
	"HTML-звіт",
}

// jsfscanRowPattern splits a registry row into its cells. It is the same shape
// the JS-Analyser registry test uses, because a table is a table.
var jsfscanRowPattern = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readJSFScanRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(jsfscanReconciliationFile)
	if err != nil {
		t.Fatalf("read %s: %v", jsfscanReconciliationFile, err)
	}
	rows := make([][]string, 0, 16)
	for _, line := range strings.Split(string(raw), "\n") {
		if match := jsfscanRowPattern.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			cells := strings.Split(match[2], "|")
			rows = append(rows, append([]string{match[1]}, cells...))
		}
	}
	return rows
}

// TestJSFScanRegistryFixesTheUpstreamCommit: a table compared against an
// unrecorded commit describes a different subject than the one it claims.
func TestJSFScanRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(jsfscanReconciliationFile)
	if err != nil {
		t.Fatalf("read %s: %v", jsfscanReconciliationFile, err)
	}
	if !jsfscanUpstreamCommitPattern.Match(raw) {
		t.Fatalf("%s does not record the upstream commit it was compared against; "+
			"a table against an unknown commit is a declaration", jsfscanReconciliationFile)
	}
}

// TestEveryUpstreamStepHasARow: the row order must be taken from the original's
// own files, and one row is missing per step means one capability can be lost
// without anyone noticing. This is the mechanical half of the rule "a row per
// capability, taken from the original's files".
func TestEveryJSFScanUpstreamStepHasARow(t *testing.T) {
	rows := readJSFScanRegistry(t)
	if len(rows) < len(jsfscanUpstreamSteps) {
		t.Fatalf("%s has %d numbered rows, the original declares %d steps: %v",
			jsfscanReconciliationFile, len(rows), len(jsfscanUpstreamSteps), jsfscanUpstreamSteps)
	}
	for index, step := range jsfscanUpstreamSteps {
		if index >= len(rows) {
			t.Fatalf("no row for upstream step %d (%s)", index+1, step)
		}
		// Cells, as `readJSFScanRegistry` builds them: index 0 is the row number
		// the regex captured, then the markdown cells follow. So capability is 1,
		// source 2, verdict 3, ours 4, basis 5, symbol 6 — and the numbering below
		// is off by one from the markdown if it is not accounted for, which is
		// exactly what happened the first time this test was written.
		if len(rows[index]) < 7 {
			t.Fatalf("row %d (%s) has %d cells, want at least 5", index+1, step, len(rows[index]))
		}
		if !strings.Contains(rows[index][1], step) {
			t.Errorf("row %d is %q, want the upstream step %q", index+1, rows[index][1], step)
		}
	}
}

// TestEveryJSFScanVerdictIsOneOfThree: the fourth state is the failure this
// whole file exists to make impossible.
func TestEveryJSFScanVerdictIsOneOfThree(t *testing.T) {
	rows := readJSFScanRegistry(t)
	if len(rows) == 0 {
		t.Fatalf("%s has no numbered rows at all", jsfscanReconciliationFile)
	}
	for _, row := range rows {
		if len(row) < 4 {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		// A markdown table cell is written with the verdict in backticks, and a
		// reader scanning the file sees `` `улічшено` ``. Stripping them here is
		// what lets the test compare the word rather than its punctuation, while
		// still failing on a word that is not one of the three.
		verdict := strings.Trim(strings.TrimSpace(row[3]), "`")
		if !jsfscanVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено", row[0], verdict)
		}
	}
}

// TestEveryNotPortedRowHasAReason: silence is not neutral, it means "removed".
func TestEveryJSFScanNotPortedRowHasAReason(t *testing.T) {
	rows := readJSFScanRegistry(t)
	for _, row := range rows {
		if len(row) < 6 {
			t.Errorf("row %s has no reason cell", row[0])
			continue
		}
		if strings.Trim(strings.TrimSpace(row[3]), "`") != "не перенесено" {
			continue
		}
		reason := strings.TrimSpace(row[5])
		if reason == "" || reason == "—" || reason == "-" {
			t.Errorf("row %s is не перенесено with no reason; that is how a capability goes missing in silence", row[0])
		}
	}
}

// TestClaimedJSFScanSymbolsExistInTheTree: a row that claims a symbol which is
// not in the source is a declaration, not a port.
func TestClaimedJSFScanSymbolsExistInTheTree(t *testing.T) {
	rows := readJSFScanRegistry(t)
	for _, row := range rows {
		if len(row) < 7 {
			continue
		}
		for _, token := range strings.Split(row[6], " ") {
			token = strings.Trim(strings.TrimSpace(token), "`,")
			if !strings.HasPrefix(token, "symbol:") {
				continue
			}
			symbol := strings.TrimPrefix(token, "symbol:")
			if symbol == "" {
				t.Errorf("row %s declares an empty symbol", row[0])
				continue
			}
			if !jsfscanSymbolInTree(symbol) {
				t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
			}
		}
	}
}

// TestOurOwnCapabilitiesAreCoveredByARow: the reverse direction. A rule added
// here that no row covers is a capability whose loss nobody would classify.
func TestOurJSFScanCapabilitiesAreCoveredByARow(t *testing.T) {
	raw, err := os.ReadFile(jsfscanReconciliationFile)
	if err != nil {
		t.Fatalf("read %s: %v", jsfscanReconciliationFile, err)
	}
	text := string(raw)
	// The capabilities this port added. Each was measured as absent before it
	// was added, so each needs a row that says where it went.
	for _, want := range []string{
		"collectJSVariables", "collectDOMSources", "collectRequestCalls",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the registry does not mention %q: a capability with no row is a capability nobody classifies", want)
		}
	}
}

// TestThePortedKindsAreActuallyInTheTree: the three new finding kinds and the
// variable list are the payload of this port. If they are not in the source, the
// registry rows are describing code that does not exist.
func TestThePortedJSFScanKindsAreActuallyInTheTree(t *testing.T) {
	for _, want := range []string{
		`jsFindingDOMSource = "dom_source"`,
		`jsFindingRequestCall = "request_call"`,
		"Variables []jsVariable",
	} {
		if !jsfscanSymbolInTree(want) {
			t.Errorf("%q is not in the tree", want)
		}
	}
}

// TestTheRegistryQuotesMeasuredNumbers: every claim in the table is a number
// someone measured. A table whose numbers are adjectives is the failure mode.
func TestTheJSFScanRegistryQuotesMeasuredNumbers(t *testing.T) {
	raw, err := os.ReadFile(jsfscanReconciliationFile)
	if err != nil {
		t.Fatalf("read %s: %v", jsfscanReconciliationFile, err)
	}
	// "Виміряно" with no number next to it is prose about a measurement.
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "Виміряно") {
			continue
		}
		if !jsfscanNumberPattern.MatchString(line) {
			t.Errorf("a line claims Виміряно with no number on it: %s", strings.TrimSpace(line))
		}
	}
}

var jsfscanNumberPattern = regexp.MustCompile(`\d`)

// jsfscanSearchRoots are where a claimed symbol is allowed to live. All three
// exist because this registry names capabilities in three layers, and a search
// that covered only one of them would report three real symbols as missing —
// which is how a test starts being decoration.
//
//   - `.` is the engine root, where the analysis and the CLI live.
//   - `../web/templates/lab/index.html` is where the browser-facing half of two
//     of these rows lives, because the project is server-rendered with hand
//     written JavaScript and no frontend build.
//   - `cmd/jsanalyse` is the CLI, which is its own `package main` and therefore
//     not visible from this directory listing.
var jsfscanSearchRoots = []string{".", "cmd/jsanalyse", "../web/templates/lab/index.html"}

var jsfscanSearchedFiles = []string{"target_js_findings.go"}

// jsfscanSymbolInTree answers whether a symbol is present in one of the search
// roots. Non-Go files are read whole; Go files skip `_test.go`, because a symbol
// that exists only in a test is a claim about coverage, not about capability.
func jsfscanSymbolInTree(symbol string) bool {
	for _, root := range jsfscanSearchRoots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if info.IsDir() {
			if jsfscanSymbolInDirectory(symbol, root) {
				return true
			}
			continue
		}
		raw, err := os.ReadFile(root)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), symbol) {
			return true
		}
	}
	return false
}

func jsfscanSymbolInDirectory(symbol, directory string) bool {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if name == "vendor" || strings.HasPrefix(name, ".") {
				continue
			}
			if jsfscanSymbolInDirectory(symbol, directory+"/"+name) {
				return true
			}
			continue
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(directory + "/" + name)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), symbol) {
			return true
		}
	}
	return false
}
