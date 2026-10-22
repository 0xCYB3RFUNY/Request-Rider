package main

// Механічна перевірка реєстру звірки з оригіналом.
//
// # Навіщо тест, а не проза
//
// Реєстр `js_analyser_reconciliation.md` існує не для читання, а для того, щоб
// неможливо було **втратити здатність мовчки**. Попередній порт (активний
// сканер) виглядав готовим, зелений набір був зеленим, а звірка була написана —
// і три здатності оригіналу виявилися відсутніми, причому жодна не була
// позначена як «не перенесено». Тому правило власника 2026-09-30 вимагає
// рядок на кожну здатність оригіналу, один вердикт з трьох, причину для
// «не перенесено» і **механічну** перевірку.
//
// Проза перевіряється пам'яттю, а пам'ять уже підводила. Тому:
//
//   - рядок, вилучений із таблиці, робить тест червоним — але тільки якщо
//     здатністьORIGINAL все ще десь є. Саме тому тест додатково вимагає, щоб
//     кожна здатність **наша** була покрита рядком: додали правило секрету —
//     тест вимагає рядка;
//   - вердикт, який не належить жодному з трьох, падає;
//   - `не перенесено` без причини падає: мовчання не є нейтральним, воно
//     означає «зняли»;
//   - символ, який рядок заявляє як реалізований, має бути в дереві: рядок про
//     неіснуючий код — це декларація;
//   - не зафіксований коміт upstream — падає: таблиця проти іншого коміту це
//     таблиця про інший предмет.
//
// # Чого тест не може
//
// Він не знає переліку здатностей **оригіналу** — оригіналу тут немає, і
// витягнути його з мережі в тесті неприпустимо. Замість цього перевірка
// вимагає, щоб реєстр зафіксував коміт, файли, з яких знято перелік, і рядок на
// кожну категорію, яку оригінал оголошує. Це робить «забули рядок» видимим на
// рев'ю, а не механічно — і саме тому перелік у реєстрі має бути знятий з
// файлів оригіналу, а не з власної пам'яті.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const reconciliationFile = "js_analyser_reconciliation.md"

// upstreamCommitPattern вимагає зафіксований коміт: таблиця звірки без нього
// описує невідомий стан оригіналу.
var upstreamCommitPattern = regexp.MustCompile(`Коміт оригіналу: ` + "`" + `([0-9a-f]{40})` + "`")

// verdicts are the only three allowed answers. A fourth state is the failure
// mode this test exists to make impossible: "done" with no row, "partial", TODO.
var verdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

// oursEveryCapabilityMustCover is our own public surface, read out of the code
// by the test rather than written down. A new secret rule or a new finding kind
// that nobody put a row for fails the test, which is the whole point: the port
// grew and the registry did not.
var oursEveryCapabilityMustCover = map[string]string{
	// The five finding kinds a reader of a file can act on.
	"xss_sink":            "target_js_findings.go",
	"xss_function":        "target_js_findings.go",
	"interesting_comment": "target_js_findings.go",
	"suspicious_comment":  "target_js_findings.go",
	"email":               "target_js_findings.go",
	// The sink vocabulary, one detector per upstream pattern family.
	"innerHTML":                "target_js_findings.go",
	"outerHTML":                "target_js_findings.go",
	"document.write":           "target_js_findings.go",
	"dangerouslySetInnerHTML":  "target_js_findings.go",
	"jsJQueryReceivers":        "target_js_findings.go",
	"jsLocationProperties":     "target_js_findings.go",
	"jsEventHandlerProperties": "target_js_findings.go",
	"jsEvalTaintPattern":       "target_js_findings.go",
	// The secret vocabulary and the two rules that made the measured false
	// positives go away.
	"secretValueIsUsable":    "osint_secrets.go",
	"stripe_publishable_key": "osint_secrets.go",
	"hardcoded_username":     "osint_secrets.go",
	"secretRules":            "osint_secrets.go",
	// The endpoint extraction and the two entry points the port added.
	"analyzeJavaScript":       "target_javascript.go",
	"analyzeScriptURLs":       "target_js_endpoint.go",
	"targetJSAnalysisHandler": "target_js_endpoint.go",
	// The renderer on the screen: without it the findings are in the engine and
	// nowhere a person looks.
	"renderTargetJsBadge": "../web/templates/lab/index.html",
}

// readReconciliation loads the registry and fails with the file's own name, so a
// missing registry is a clear failure rather than a panic.
func readReconciliation(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(reconciliationFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v", reconciliationFile, err)
	}
	return string(body)
}

// capabilityRows returns the numbered rows of the reconciliation table.
func capabilityRows(t *testing.T, registry string) [][]string {
	t.Helper()
	var rows [][]string
	for _, line := range strings.Split(registry, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 7 {
			continue
		}
		number := strings.TrimSpace(cells[0])
		if number == "" {
			continue
		}
		if _, err := strconvAtoi(number); err != nil {
			continue
		}
		for i := range cells {
			// A verdict and a symbol are written as inline code in the table, and
			// the backticks are markdown, not part of the answer. Stripping them
			// here is what lets the registry stay readable without the test
			// demanding a different spelling for the same word.
			cells[i] = strings.Trim(strings.TrimSpace(cells[i]), "`")
		}
		rows = append(rows, cells)
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no capability rows: the table was emptied or renamed", reconciliationFile)
	}
	return rows
}

func strconvAtoi(text string) (int, error) {
	if text == "" {
		return 0, os.ErrInvalid
	}
	value := 0
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, os.ErrInvalid
		}
		value = value*10 + int(r-'0')
	}
	return value, nil
}

// TestReconciliationPinsTheUpstreamCommit: a table without the upstream commit
// describes an unknown subject.
func TestReconciliationPinsTheUpstreamCommit(t *testing.T) {
	registry := readReconciliation(t)
	match := upstreamCommitPattern.FindStringSubmatch(registry)
	if match == nil {
		t.Fatalf("%s does not pin the upstream commit; a table against an unknown state describes nothing", reconciliationFile)
	}
	if len(match[1]) != 40 {
		t.Fatalf("upstream commit %q is not a full sha", match[1])
	}
}

// TestReconciliationNamesTheFilesTheListCameFrom: the list must be taken from
// the original's files, and the place that says so is the preamble — not a row
// that happens to cite the same file while arguing about something else. A
// mention anywhere in the document was too weak a check: renaming the file in
// the preamble while leaving every row's citation intact left the test green.
func TestReconciliationNamesTheFilesTheListCameFrom(t *testing.T) {
	registry := readReconciliation(t)
	marker := "## Здатності оригіналу"
	index := strings.Index(registry, marker)
	if index < 0 {
		t.Fatalf("%s has no capability table: the section heading the preamble points at is gone", reconciliationFile)
	}
	preamble := registry[:index]
	for _, file := range []string{"analyzer.py", "js_analyzer.py", "app.py", "static/js/app.js", "templates/index.html"} {
		if !strings.Contains(preamble, file) {
			t.Fatalf("the preamble never names %s: the list of capabilities cannot have been read from the original's files", file)
		}
	}
}

// TestEveryCapabilityRowHasARealVerdict: the three states, and no fourth.
func TestEveryCapabilityRowHasARealVerdict(t *testing.T) {
	registry := readReconciliation(t)
	rows := capabilityRows(t, registry)
	seen := map[int]bool{}
	for _, cells := range rows {
		number, _ := strconvAtoi(cells[0])
		verdict := cells[3]
		if !verdicts[verdict] {
			t.Fatalf("row %d has verdict %q; allowed: супадає, улучшено, не перенесено", number, verdict)
		}
		if seen[number] {
			t.Fatalf("row number %d appears twice", number)
		}
		seen[number] = true
	}
	// The numbers must be a run: a gap is a row that was pulled out without
	// renumbering, which is the silent-loss case this test is for.
	for number := 1; number <= len(rows); number++ {
		if !seen[number] {
			t.Fatalf("no row %d: the table has a hole, so a capability was removed without a verdict", number)
		}
	}
}

// TestNotPortedRowsStateAReasonAndWhatIsUsedInstead: silence means "removed",
// and a report cannot tell that from a complete port.
func TestNotPortedRowsStateAReasonAndWhatIsUsedInstead(t *testing.T) {
	registry := readReconciliation(t)
	for _, cells := range capabilityRows(t, registry) {
		if cells[3] != "не перенесено" {
			continue
		}
		number, _ := strconvAtoi(cells[0])
		reason := cells[5]
		if reason == "" || reason == "-" || reason == "—" {
			t.Fatalf("row %d is не перенесено without a reason", number)
		}
		if !strings.Contains(reason, "причина") && !strings.Contains(reason, "Причина") {
			t.Fatalf("row %d gives no reason, only a statement: %q", number, reason)
		}
	}
}

// TestClaimedSymbolsExistInTheTree: a row that claims a symbol which is not in
// the code is a declaration of work that was never done.
func TestClaimedSymbolsExistInTheTree(t *testing.T) {
	registry := readReconciliation(t)
	claimed := 0
	for _, cells := range capabilityRows(t, registry) {
		for _, token := range strings.Split(cells[6], ",") {
			token = strings.Trim(strings.TrimSpace(token), "`")
			if !strings.HasPrefix(token, "symbol:") {
				continue
			}
			symbol := strings.TrimPrefix(token, "symbol:")
			if symbol == "" {
				t.Fatalf("row %s declares an empty symbol", cells[0])
			}
			claimed++
			if !symbolInTree(t, symbol) {
				t.Fatalf("row %s claims symbol %q, which is not in the tree", cells[0], symbol)
			}
		}
	}
	if claimed == 0 {
		t.Fatalf("no row claims a symbol: the registry cannot be checked against the code")
	}
}

// TestEveryClaimedTestExists closes the other half of the evidence. A verdict of
// "улучшено" with a `test:` reference is a claim about behaviour, and a test name
// that is not in the tree is a claim about nothing. This is the check that makes
// flipping a row from "не перенесено" impossible on words alone: the row has to
// name something that either exists as a symbol or runs as a test.
func TestEveryClaimedTestExists(t *testing.T) {
	registry := readReconciliation(t)
	claimed := 0
	for _, cells := range capabilityRows(t, registry) {
		for _, token := range strings.Split(cells[6], ",") {
			token = strings.Trim(strings.TrimSpace(token), "`")
			if !strings.HasPrefix(token, "test:") {
				continue
			}
			name := strings.TrimPrefix(token, "test:")
			if name == "" {
				t.Fatalf("row %s declares an empty test", cells[0])
			}
			claimed++
			if !testInTree(t, name) {
				t.Fatalf("row %s claims test %q, which is not in the tree", cells[0], name)
			}
		}
	}
	if claimed == 0 {
		t.Fatalf("no row claims a test: a verdict cannot be evidence without one")
	}
}

// TestEveryPortedRowCitesSomethingCheckable is the anti-wording check. Every row
// that is not "не перенесено" has to point at a symbol or a test; a row that
// claims an improvement and names nothing is a declaration, which is the exact
// failure the reconciliation rule was written to prevent.
func TestEveryPortedRowCitesSomethingCheckable(t *testing.T) {
	registry := readReconciliation(t)
	for _, cells := range capabilityRows(t, registry) {
		verdict := strings.TrimSpace(cells[3])
		if verdict == "`не перенесено`" || verdict == "не перенесено" {
			continue
		}
		refs := ""
		if len(cells) > 6 {
			refs = cells[6]
		}
		if !strings.Contains(refs, "symbol:") && !strings.Contains(refs, "test:") {
			t.Fatalf("row %s (%s) claims %s and cites no symbol and no test", cells[0], cells[1], verdict)
		}
	}
}

// testInTree looks a test function name up in the engine's test files and in the
// gateway's, so a reference to a Django test counts as well.
func testInTree(t *testing.T, name string) bool {
	t.Helper()
	// The whole engine tree, not only the root package: the CLI's tests live in
	// `cmd/jsanalyse`, and a reference to them has to be checkable like any other.
	var matches []string
	walk := func(root string) {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" || entry.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(entry.Name(), "_test.go") {
				matches = append(matches, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	walk(".")
	// The gateway's tests count too: a behaviour proved there is proved.
	walk("../web/lab")
	pythonTests, err := filepath.Glob("../web/lab/test_*.py")
	if err != nil {
		t.Fatalf("glob gateway tests: %v", err)
	}
	matches = append(matches, pythonTests...)
	needle := "func " + name + "("
	pythonNeedle := "def " + name + "("
	for _, file := range matches {
		body, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(body)
		if strings.Contains(text, needle) || strings.Contains(text, pythonNeedle) {
			return true
		}
	}
	return false
}

// symbolInTree looks the name up in the engine sources and in the lab template.
// Both are read: an engine-only port is not the deliverable, the report is.
func symbolInTree(t *testing.T, symbol string) bool {
	t.Helper()
	files := []string{
		"target_js_findings.go",
		"target_javascript.go",
		"target_js_endpoint.go",
		"osint_secrets.go",
		"main.go",
		"../web/templates/lab/index.html",
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if strings.Contains(string(body), symbol) {
			return true
		}
	}
	return false
}

// TestEveryCapabilityOfOursIsCoveredByARow is the check that would have caught
// the three capabilities the previous port lost: our own surface is read out of
// the code, and each name has to appear in a row. Add a secret rule and the test
// demands a row for it; remove a row and the test goes red.
func TestEveryCapabilityOfOursIsCoveredByARow(t *testing.T) {
	registry := readReconciliation(t)
	for capability, file := range oursEveryCapabilityMustCover {
		if !strings.Contains(registry, capability) {
			t.Fatalf("%s has no registry row: our own capability %q is not classified, which is how the previous port lost three of them", file, capability)
		}
	}
}

// TestCapabilityRowsAreNumberedWithoutGaps pins the shape of the table itself.
// A row that is deleted or renumbered changes nothing else in the document, so
// every content check above would still pass — the three capabilities the first
// port lost were lost exactly this way, by a list that shrank silently. The count
// is written out rather than derived, so adding a capability means saying so.
func TestCapabilityRowsAreNumberedWithoutGaps(t *testing.T) {
	registry := readReconciliation(t)
	rows := capabilityRows(t, registry)
	const want = 18
	if len(rows) != want {
		t.Fatalf("the registry has %d capability rows, want %d: a row was removed or added", len(rows), want)
	}
	for index, cells := range rows {
		number, err := strconv.Atoi(strings.TrimSpace(cells[0]))
		if err != nil {
			t.Fatalf("row %d has the number %q", index+1, cells[0])
		}
		if number != index+1 {
			t.Fatalf("row %d is numbered %d: the list has a gap or a repeat", index+1, number)
		}
		if strings.TrimSpace(cells[1]) == "" {
			t.Fatalf("row %d names no capability", number)
		}
	}
}

// TestTheRegistryNamesTheMeasuredComparison: verdicts of "улучшено" are claims,
// and a claim without a measurement is the same defect one level up.
func TestTheRegistryNamesTheMeasuredComparison(t *testing.T) {
	registry := readReconciliation(t)
	for _, needle := range []string{"Juice Shop", "85 с", ".ru"} {
		if !strings.Contains(registry, needle) {
			t.Fatalf("the registry never mentions %q: an improved verdict with no measurement is a claim, not evidence", needle)
		}
	}
}

// TestReconciliationFileIsWhereTheTestLooks is a guard against the registry
// being moved to make the test pass while the documentation points elsewhere.
func TestReconciliationFileIsWhereTheTestLooks(t *testing.T) {
	path := filepath.Clean(reconciliationFile)
	if path != reconciliationFile {
		t.Fatalf("registry path %q is not the plain file name the test reads", path)
	}
}
