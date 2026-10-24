package main

// Механічна перевірка реєстру звірки з `R-s0n/Custom_Vuln_Scan_Templates`.
//
// Репозиторій **не містить коду** — це корпус файлів для чужих рушіїв:
// 16 профілів сканера Burp (`.bb`) і 10 шаблонів nuclei (`.yaml`).
//
// Тому перевірка має три шари, і кожен ловить своє:
//
//  1. **предмет звірки** — коміт оригіналу зафіксовано;
//  2. **числа з оригіналу** — перелік каталогів і підрахунок файлів
//     знімаються з клону, а не з реєстру: інакше здатність, яку ніхто
//     не переносив, просто не потрапила б у перелік;
//  3. **наші твердження** — `headless` і `requests` мають лишатися в
//     списку блоків, бо три `супадає` у реєстрі стоять на цьому;
//     якщо блок зникне, вердикти стануть брехнею.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const customVulnRegistry = "custom_vuln_scan_templates_reconciliation.md"

const customVulnCommit = "2e98272"

// Кількість файлів, яких реєстр вимагає в кожному з двох каталогів.
const (
	customVulnBurpFiles     = 16
	customVulnNucleiFiles   = 10
	customVulnHeadlessFiles = 8
	customVulnRequiredRows  = 12
)

var customVulnCloneRoots = []string{
	"../Semple-Интеграции/Custom_Vuln_Scan_Templates",
	"../Custom_Vuln_Scan_Templates",
}

var customVulnUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var customVulnVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var customVulnRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readCustomVulnRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(customVulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", customVulnRegistry, err)
	}
	rows := make([][]string, 0, customVulnRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := customVulnRow.FindStringSubmatch(strings.TrimSpace(line))
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

func customVulnCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// customVulnDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються.
func customVulnDir(t *testing.T) string {
	t.Helper()
	for _, root := range customVulnCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("Custom_Vuln_Scan_Templates clone not found in %v: the registry's "+
		"counts cannot be verified against the original", customVulnCloneRoots)
	return ""
}

func customVulnOurSources(t *testing.T) string {
	t.Helper()
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == customVulnRegistry ||
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

// countFiles рахує файли з розширенням у каталозі.
func countFiles(t *testing.T, dir string, suffix string) int {
	t.Helper()
	found, err := filepath.Glob(filepath.Join(dir, "*"+suffix))
	if err != nil {
		t.Fatalf("glob %s: %v", suffix, err)
	}
	return len(found)
}

// TestTheCustomVulnRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestTheCustomVulnRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(customVulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", customVulnRegistry, err)
	}
	match := customVulnUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", customVulnRegistry)
	}
	if got := string(match[1]); got != customVulnCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, customVulnCommit)
	}
}

// TestTheCustomVulnRegistryHasEveryRowItPromises.
func TestTheCustomVulnRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readCustomVulnRegistry(t)); got < customVulnRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			customVulnRegistry, got, customVulnRequiredRows)
	}
}

// TestEveryCustomVulnRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryCustomVulnRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readCustomVulnRegistry(t) {
		verdict := customVulnCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !customVulnVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedCustomVulnRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedCustomVulnRowSaysWhy(t *testing.T) {
	for _, row := range readCustomVulnRegistry(t) {
		if customVulnCell(row, 3) != "не перенесено" {
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

// TestEveryCustomVulnRowNamesASymbolThatExists — символ має бути в дереві.
func TestEveryCustomVulnRowNamesASymbolThatExists(t *testing.T) {
	sources := customVulnOurSources(t)
	for _, row := range readCustomVulnRegistry(t) {
		symbol := customVulnCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheBurpProfileCountIsMeasured — перша половина корпусу.
//
// 16 `.bb` — не «багато профілів», а конкретне число, яким реєстр
// виміряно і на якому тримається рядок 5. Перелік знімається з клону.
func TestTheBurpProfileCountIsMeasured(t *testing.T) {
	dir := customVulnDir(t)
	got := countFiles(t, filepath.Join(dir, "BurpBounty"), ".bb")
	if got != customVulnBurpFiles {
		t.Errorf("the original holds %d .bb profiles, the registry claims %d",
			got, customVulnBurpFiles)
	}
}

// TestTheNucleiTemplateCountIsMeasured — друга половина корпусу.
func TestTheNucleiTemplateCountIsMeasured(t *testing.T) {
	dir := customVulnDir(t)
	got := countFiles(t, filepath.Join(dir, "Nuclei"), ".yaml") +
		countFiles(t, filepath.Join(dir, "Nuclei", "headless"), ".yaml")
	if got != customVulnNucleiFiles {
		t.Errorf("the original holds %d nuclei templates, the registry claims %d",
			got, customVulnNucleiFiles)
	}
}

// TestTheHeadlessShareIsMeasured — головне вимірювання цього реєстру.
//
// 8 із 10 шаблонів мають блок `headless:`. Саме це число дає рядку 2 його
// зміст: якщо в оригіналі headless-шаблонів немає, рядок «у нас є
// CapabilityHeadless» перетворюється на виправдання без предмета.
func TestTheHeadlessShareIsMeasured(t *testing.T) {
	dir := customVulnDir(t)
	found, err := filepath.Glob(filepath.Join(dir, "Nuclei", "headless", "*.yaml"))
	if err != nil {
		t.Fatalf("glob headless: %v", err)
	}
	withHeadless := 0
	for _, path := range found {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if strings.Contains(string(raw), "headless:") {
			withHeadless++
		}
	}
	if withHeadless != customVulnHeadlessFiles {
		t.Errorf("the original has %d templates with a headless block, the "+
			"registry claims %d", withHeadless, customVulnHeadlessFiles)
	}
}

// TestBothHalvesOfTheCorpusAreNamed — головна прогалина цього реєстру.
//
// Корпус має **два** формати для **двох чужих рушіїв`. Реєстр, який назвав
// б лише один, зробив би з `10 шаблонів ми виконаємо` твердження без
// підстави: не названий другий ракурс виглядає як повне покриття.
func TestBothHalvesOfTheCorpusAreNamed(t *testing.T) {
	customVulnDir(t)
	raw, err := os.ReadFile(customVulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", customVulnRegistry, err)
	}
	text := string(raw)
	for _, name := range []string{"BurpBounty", "Nuclei"} {
		if !strings.Contains(text, "`"+name+"/`") {
			t.Errorf("the original ships a %q directory and the registry never "+
				"names it", name)
		}
	}
	if !strings.Contains(text, "80 445") {
		t.Errorf("the registry does not state the payload total measured from " +
			"the original (80445)")
	}
}

// TestWeStillRunBothNucleiBlockKinds — наші `супадає` мають підставу.
//
// Рядки 1 і 2 кажуть `супадає` на підставі того, що ми розпізнаємо блоки
// `requests:` і `headless:`. Якщо будь-який зникне з нашого списку блоків,
// ці вердикти стануть брехнею — і корпус, який ми завантажимо, просто не
// відпрацює.
func TestWeStillRunBothNucleiBlockKinds(t *testing.T) {
	sources := customVulnOurSources(t)
	if !strings.Contains(sources, `"requests"`) {
		t.Error("our document parser no longer knows the `requests` block: " +
			"row 1 claims we run the two request-style templates of this corpus")
	}
	if !strings.Contains(sources, `"headless"`) {
		t.Error("our document parser no longer knows the `headless` block: " +
			"row 2 claims we run the eight headless templates of this corpus")
	}
	if !strings.Contains(sources, "CapabilityHeadless") {
		t.Error("CapabilityHeadless is gone from our code: row 2 names it as the " +
			"symbol that classifies those templates")
	}
}

// TestTheHeadlessClaimIsNotBorrowedFromOurBrowserWorker.
//
// Реєстр має одну найважливішу різницю: ми **вміємо** виконати headless-шаблон
// nuclei, але **наш** browser-worker ніколи не виконує nuclei-шаблонів.
// Тому «у нас є headless» без цього уточнення виглядало б як покриття, якого
// немає.
//
// Перевірка ловить саме випадок, коли хтось видалить уточнення і залишить
// голу перехвальне твердження: тоді з'явиться рядок про наш browser-worker
// у контексті headless-шаблонів nuclei, якого в реєстрі бути не повинно.
func TestTheHeadlessClaimIsNotBorrowedFromOurBrowserWorker(t *testing.T) {
	raw, err := os.ReadFile(customVulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", customVulnRegistry, err)
	}
	text := strings.ToLower(string(raw))
	// Реєстр зобов'язаний сказати, що browser-worker НЕ виконує nuclei-шаблони.
	if !strings.Contains(text, "не виконує nuclei-шаблон") &&
		!strings.Contains(text, "не виконує nuclei-шаблони") {
		t.Error("the registry claims headless support without stating that our " +
			"browser-worker does not run nuclei templates: that is the exact " +
			"reading the owner rejected")
	}
}
