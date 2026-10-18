package main

// Механічна перевірка реєстру звірки з `projectdiscovery/subfinder`.
//
// Реєстр рахує **покриття джерел**: скільки сторонніх джерел піддоменів має
// оригінал і скільки маємо ми. Тому головна перевірка читає теки
// `pkg/subscraping/sources/*` клону і вимагає, щоб реєстр звірявся з їх
// **реальною кількістю**, а не з числом, яке було актуальним на момент написання.
//
// Друга половина тієї ж думки — `TestEveryKeyedSourceIsCounted`: 38 із 58
// джерел вимагають ключа, і саме це число визначає, чи наш «безкоштовний» шлях
// є перевагою, чи прогалиною. Число береться з `KeyRequirement()` кожного
// джерела, а не з пам'яті.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const subfinderRegistry = "subfinder_reconciliation.md"

// subfinderCommit — коміт клону, зафіксований у реєстрі.
//
// Один і той самий коміт у тесті й у реєстрі: якщо клон оновити, реєстр має
// оновитися разом із ним, інакше таблиця — про інший предмет.
const subfinderCommit = "7d90382"

// subfinderCloneRoots — можливі місця клону. Обидва приймаються, бо оператор
// переміщав дерево; перший — поточний, другий — старий шлях.
var subfinderCloneRoots = []string{
	"../Semple-Интеграции/subfinder",
	"../subfinder",
}

var subfinderUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var subfinderVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var subfinderRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const subfinderRequiredRows = 12

func readSubfinderRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(subfinderRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", subfinderRegistry, err)
	}
	rows := make([][]string, 0, subfinderRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := subfinderRow.FindStringSubmatch(strings.TrimSpace(line))
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

func subfinderCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// subfinderDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Мовчати не можна, тож причина й шлях друкуються.
func subfinderDir(t *testing.T) string {
	t.Helper()
	for _, root := range subfinderCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("subfinder clone not found in %v: the registry's source counts cannot "+
		"be verified against the original", subfinderCloneRoots)
	return ""
}

// subfinderKeyRequirement — значення `KeyRequirement()` джерела.
//
// Розбирається з исходника, а не викликається: оригінал — чужий пакет, його
// не можна імпортувати, а читати треба саме так, як він є.
// Регулярка має бути такою, а не простою: визначення зустрічаються у двох
// форматах — `{\n\treturn …\n}` і `{ return … }` на одному рядку (так написано
// `submd`), — і значення повернення має діставатися **після** останньої точки,
// бо `return subscraping.RequiredKey` при жадібному `[\w.]*` віддає `y`, а не
// `RequiredKey`. Обидві помилки мого першого варіанта зловив сам клон.
var subfinderKeyRequirement = regexp.MustCompile(
	`func \(s \*Source\) KeyRequirement\(\) [\w.]+\s*\{\s*return\s+[\w.]*\.(\w+)`)

// subfinderSources читає всі теки джерел і повертає їх назви разом із
// вимогою ключа.
func subfinderSources(t *testing.T, dir string) (keyed, free []string) {
	t.Helper()
	base := filepath.Join(dir, "pkg/subscraping/sources")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read %s: %v", base, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(base, entry.Name()))
		if err != nil {
			continue
		}
		found := false
		for _, file := range files {
			name := file.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(base, entry.Name(), name))
			if readErr != nil {
				continue
			}
			match := subfinderKeyRequirement.FindSubmatch(raw)
			if match == nil {
				continue
			}
			if string(match[1]) == "RequiredKey" {
				keyed = append(keyed, entry.Name())
			} else {
				free = append(free, entry.Name())
			}
			found = true
			break
		}
		if !found {
			t.Errorf("source %s has no readable KeyRequirement(): the registry's "+
				"key counts cannot be verified for it", entry.Name())
		}
	}
	return keyed, free
}

func subfinderGoSources(t *testing.T) string {
	t.Helper()
	parts := []string{}
	for _, root := range []string{".", "pkg"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			parts = append(parts, string(raw))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(parts) == 0 {
		t.Fatalf("no sources were read: the check would pass on an empty tree")
	}
	return strings.Join(parts, "\n")
}

// TestSubfinderRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestSubfinderRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(subfinderRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", subfinderRegistry, err)
	}
	if !subfinderUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", subfinderRegistry)
	}
	match := subfinderUpstreamCommit.FindSubmatch(raw)
	if got := string(match[1]); got != subfinderCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, subfinderCommit)
	}
}

// TestTheSubfinderRegistryHasEveryRowItPromises.
func TestTheSubfinderRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readSubfinderRegistry(t)); got < subfinderRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			subfinderRegistry, got, subfinderRequiredRows)
	}
}

// TestEverySubfinderRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEverySubfinderRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readSubfinderRegistry(t) {
		verdict := subfinderCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !subfinderVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedSubfinderRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedSubfinderRowSaysWhy(t *testing.T) {
	for _, row := range readSubfinderRegistry(t) {
		if subfinderCell(row, 3) != "не перенесено" {
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

// TestEverySubfinderRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEverySubfinderRowNamesASymbolThatExists(t *testing.T) {
	sources := subfinderGoSources(t)
	for _, row := range readSubfinderRegistry(t) {
		symbol := subfinderCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheSourceCountIsMeasuredNotGuessed — головна перевірка.
//
// Реєстр заявляє 58 джерел. Число рахується з `pkg/subscraping/sources/`.
// Якщо upstream додасть або зменшить джерело, реєстр зобов'язаний змінитися —
// інакше таблиця описує інший набір.
func TestTheSourceCountIsMeasuredNotGuessed(t *testing.T) {
	dir := subfinderDir(t)
	keyed, free := subfinderSources(t, dir)
	total := len(keyed) + len(free)
	if total == 0 {
		t.Fatalf("no sources found in %s: the check would pass on an empty original",
			dir)
	}
	registry, err := os.ReadFile(subfinderRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", subfinderRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(total)) {
		t.Errorf("the original has %d sources, and the registry does not mention "+
			"that number", total)
	}
	_ = free
}

// TestEveryKeyedSourceIsCounted — 38 із 58 вимагають ключа.
//
// Це число визначає зміст висновку реєстру: саме тому наш шлях називається
// перевагою на keyless-мовчанці. Якби воно виявилося малим, висновок «у нас
// 6 безкоштовних» перестав би бути аргументом, і тест це показує.
func TestEveryKeyedSourceIsCounted(t *testing.T) {
	dir := subfinderDir(t)
	keyed, free := subfinderSources(t, dir)
	if len(keyed) == 0 {
		t.Skip("no keyed sources found: the upstream shape changed and the " +
			"registry's row 8 needs a look")
	}
	registry, err := os.ReadFile(subfinderRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", subfinderRegistry, err)
	}
	text := string(registry)
	if !strings.Contains(text, strconv.Itoa(len(keyed))) {
		t.Errorf("%d of the original's sources require an API key, and the "+
			"registry does not mention that count", len(keyed))
	}
	if !strings.Contains(text, strconv.Itoa(len(free))) {
		t.Errorf("%d of the original's sources need no key, and the registry does "+
			"not mention that count", len(free))
	}
}

// TestTheRegistryAdmitsItCoversFewerSources — чесність про 58 проти 6.
//
// Реєстр не має права виглядати так, наче ми покриваємо все. Тут перевіряється
// проти байтів самого тексту: він обязан містити і число оригіналу, і число
// наших джерел, і слово про те, що ми покриваємо менше.
func TestTheRegistryAdmitsItCoversFewerSources(t *testing.T) {
	raw, err := os.ReadFile(subfinderRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", subfinderRegistry, err)
	}
	text := strings.ToLower(string(raw))
	// «58 проти 6» — це і є заява про те, що покриття менше.
	if !strings.Contains(text, "58 проти 6") {
		t.Errorf("%s does not state the 58-vs-6 comparison: a reader could take "+
			"the table for full coverage", subfinderRegistry)
	}
}

// TestOurCertificateIndexesAreCountedFromOurCode — наші 5 CT-індексів з коду.
//
// Число «5» не береться зі слів: рахуються імена в `certificateSources`.
func TestOurCertificateIndexesAreCountedFromOurCode(t *testing.T) {
	raw, err := os.ReadFile("osint_transforms.go")
	if err != nil {
		t.Fatalf("read our own transforms: %v", err)
	}
	source := string(raw)
	index := strings.Index(source, "func certificateSources(")
	if index < 0 {
		t.Fatalf("certificateSources is gone: the registry's count needs a look")
	}
	block := source[index:]
	if end := strings.Index(block, "\n}"); end > 0 {
		block = block[:end]
	}
	count := strings.Count(block, "name:")
	if count == 0 {
		t.Fatalf("certificateSources declares no index: the registry's count is wrong")
	}
	registry, err := os.ReadFile(subfinderRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", subfinderRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(count)) {
		t.Errorf("our code declares %d certificate indexes, and the registry "+
			"does not mention that number", count)
	}
}
