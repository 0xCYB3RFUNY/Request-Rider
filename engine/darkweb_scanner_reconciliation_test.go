package main

// Механічна перевірка реєстру звірки з `darkweb_scanner`.
//
// Це Python-сканер із **24 перевірками** у `checks/`, але головне вимірювання
// цього реєстру — скільки з них реально виконується:
//
//   - `vulnscan.py` (`build_checks()`) реєструє **22**;
//   - `vulnscan_lite.py` реєструє **6**.
//
// Різниця — **16 мертвих перевірок**. `AGENTS.md` називає «непрацюючий
// інструмент, який не працював ніколи» окремим класом сміття, тому це
// твердження перевіряється механічно: якщо upstream почне реєструвати всі
// перевірки в lite-вході, реєстр опишує не той предмет.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const darkwebRegistry = "darkweb_scanner_reconciliation.md"

const darkwebCommit = "75efce3"

const darkwebRequiredRows = 11

const (
	darkwebCheckFiles = 25
	darkwebFullChecks = 22
	darkwebLiteChecks = 6
)

var darkwebCloneRoots = []string{
	"../Semple-Интеграции/darkweb_scanner",
	"../darkweb_scanner",
}

var darkwebUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var darkwebVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var darkwebRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readDarkwebRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(darkwebRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", darkwebRegistry, err)
	}
	rows := make([][]string, 0, darkwebRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := darkwebRow.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		cells := strings.Split(match[2], "|")
		if len(cells) < 5 {
			continue
		}
		rows = append(rows, append([]string{match[1]}, cells...))
	}
	return rows
}

func darkwebCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func darkwebDir(t *testing.T) string {
	t.Helper()
	for _, root := range darkwebCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("darkweb_scanner clone not found in %v: the registry's counts "+
		"cannot be verified against the original", darkwebCloneRoots)
	return ""
}

func darkwebOurSources(t *testing.T) string {
	t.Helper()
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == darkwebRegistry ||
			name == "reconciliation_summary_test.go"
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner", "pkg/intruder"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				skipped(entry.Name()) {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
			if readErr != nil {
				continue
			}
			parts = append(parts, string(raw))
		}
	}
	if len(parts) == 0 {
		t.Fatalf("no sources were read: the check would pass on an empty tree")
	}
	return strings.Join(parts, "\n")
}

// darkwebCountChecks рахує екземпляри перевірок у списку `checks = [...]`
// або `build_checks()`.
//
// Регулярка вимагає **`()` після імені**: у `from checks import (` рядку є
// ім'я без дужок, і рахувати його — це рахувати імпорт, а не реєстрацію.
// Перша версія цієї перевірки брала просто слова й звірила б 22 з 40.
func darkwebCountChecks(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)

	start := strings.Index(text, "checks = [")
	if start < 0 {
		start = strings.Index(text, "return [")
		if start < 0 {
			t.Fatalf("%s holds no check list at all: the registry counts "+
				"registered checks, and there is nothing to count", path)
		}
		start += len("return [")
	} else {
		start += len("checks = [")
	}
	end := strings.Index(text[start:], "]")
	if end < 0 {
		t.Fatalf("%s has an unterminated check list", path)
	}
	body := text[start : start+end]

	instantiated := regexp.MustCompile(`\b[A-Z][A-Za-z0-9]*\(`)
	count := 0
	for _, match := range instantiated.FindAllString(body, -1) {
		if strings.HasPrefix(match, "Keyword") || strings.HasPrefix(match, "wordlist") {
			continue
		}
		count++
	}
	return count
}

// TestTheDarkwebRegistryFixesTheUpstreamCommit.
func TestTheDarkwebRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(darkwebRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", darkwebRegistry, err)
	}
	match := darkwebUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", darkwebRegistry)
	}
	if got := string(match[1]); got != darkwebCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, darkwebCommit)
	}
}

// TestTheDarkwebRegistryHasEveryRowItPromises.
func TestTheDarkwebRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readDarkwebRegistry(t)); got < darkwebRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			darkwebRegistry, got, darkwebRequiredRows)
	}
}

// TestEveryDarkwebRowHasAVerdictFromTheThree.
func TestEveryDarkwebRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readDarkwebRegistry(t) {
		verdict := darkwebCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !darkwebVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedDarkwebRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedDarkwebRowSaysWhy(t *testing.T) {
	for _, row := range readDarkwebRegistry(t) {
		if darkwebCell(row, 3) != "не перенесено" {
			continue
		}
		tail := strings.Join(row[min(len(row), 5):], " | ")
		if strings.Trim(tail, " |") == "" {
			t.Errorf("row %s is не перенесено with no reason", row[0])
			continue
		}
		if !strings.Contains(strings.ToLower(tail), "причина") {
			t.Errorf("row %s is не перенесено but the reason never says why: %s", row[0], tail)
		}
	}
}

// TestEveryDarkwebRowNamesASymbolThatExists.
func TestEveryDarkwebRowNamesASymbolThatExists(t *testing.T) {
	sources := darkwebOurSources(t)
	for _, row := range readDarkwebRegistry(t) {
		symbol := darkwebCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in our tree", row[0], symbol)
		}
	}
}

// TestTheCheckCatalogIsMeasured.
//
// 25 файлів у `checks/` (24 перевірки + `__init__.py`) — це «скільки написано»,
// а не «скільки працює».
// Обидва числа реєстр називає, тому обидва перевіряються.
func TestTheCheckCatalogIsMeasured(t *testing.T) {
	dir := darkwebDir(t)
	entries, err := os.ReadDir(filepath.Join(dir, "checks"))
	if err != nil {
		t.Fatalf("read checks/: %v", err)
	}
	files := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".py") {
			files++
		}
	}
	if files != darkwebCheckFiles {
		t.Errorf("the original ships %d check files, the registry claims %d",
			files, darkwebCheckFiles)
	}
}

// TestTheDeadChecksInLiteAreStillMeasured — головне вимірювання цього реєстру.
//
// `AGENTS.md`, «Гарбейж-колектор», називає «непрацюючий інструмент, який не
// працював ніколи» окремим класом сміття. Реєстр називає **16 перевірок, які
// лежать у каталозі мертвими** у lite-вході.
//
// Число виходить із різниці двох замірів, і обидва мусять лишатися правдивими:
//
//	vulnscan.py       → 22 зареєстровані
//	vulnscan_lite.py  →  6 зареєстрованих
//	різниця           → 16 мертвих у lite
//
// `AGENTS.md` забороняє «зайвий шлях», тому реєстр має право назвати саме цю
// різницю — але вона мусить бути виміряна, а не порахована на око.
func TestTheDeadChecksInLiteAreStillMeasured(t *testing.T) {
	dir := darkwebDir(t)
	full := darkwebCountChecks(t, filepath.Join(dir, "vulnscan.py"))
	lite := darkwebCountChecks(t, filepath.Join(dir, "vulnscan_lite.py"))

	if full != darkwebFullChecks {
		t.Errorf("the full entry registers %d checks, the registry claims %d",
			full, darkwebFullChecks)
	}
	if lite != darkwebLiteChecks {
		t.Errorf("the lite entry registers %d checks, the registry claims %d",
			lite, darkwebLiteChecks)
	}
	if lite >= full {
		t.Errorf("the lite entry registers %d checks against the full entry's %d: "+
			"the registry's whole finding is that lite runs fewer, and that is "+
			"no longer true", lite, full)
	}
}

// TestTheRegistryNamesTheDeadCodeAsGarbage.
//
// Реєстр мусить прямо сказати, що 16 перевірок — це сміття за `AGENTS.md`, а
// не «обмежена профільна збірка». Без цього наступна сесія скопіює lite-вхід
// разом із мертвим кодом.
func TestTheRegistryNamesTheDeadCodeAsGarbage(t *testing.T) {
	raw, err := os.ReadFile(darkwebRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", darkwebRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "смітт") {
		t.Error("the registry never calls the 16 unregistered checks garbage: " +
			"they read as a profile choice, and a later session would copy them")
	}
	if !strings.Contains(text, "мертв") {
		t.Error("the registry does not describe the 16 checks as dead code: the " +
			"word is what keeps the finding from reading as a design decision")
	}
}

// TestTheTorRowNamesOurOwnMeasuredSymbol — рядок 5.
//
// Вердикт `улучшено` тримається на нашому коді, а не на оцінці: `routing.go`
// формує SOCKS5-адресу з будь-якої заданої змінної. Тому твердження
// перевіряється пошуком рядка в нашому коді.
func TestTheTorRowNamesOurOwnMeasuredSymbol(t *testing.T) {
	sources := darkwebOurSources(t)
	if !strings.Contains(sources, "socks5://") {
		t.Error("our code no longer builds a socks5:// route: row 5 claims our " +
			"Tor path is broader than the original's single SOCKS5 form, and " +
			"there is nothing broader left")
	}
}
