package main

// Механічна перевірка реєстру звірки з `savoirfairelinux/vulnscout`.
//
// Дві особливості, які роблять цей реєстр не схожим на інші.
//
// Перша: **інший клас інструмента.** Vulnscout — SBOM-платформа, ми —
// живі сканери. Тому більшість рядків `не перенесено`, і перевірка має
// фіксувати саме цю причину, а не просто наявність вердикту: якщо хтось
// змінить причину на «часу не було», реєстр стане брехнею.
//
// Друга: **дві помилки попереднього виміру виправлені в самому реєстрі** —
// ліцензія `LICENSE.GPL-3.0-only` є, а код дорівнює 35 033 рядки, а не
// 93 034. Перевірка звіряє обидва числа з клоном, щоб виправлення не
// відкотилося назад.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const vulnscoutRegistry = "vulnscout_reconciliation.md"

const vulnscoutCommit = "df874ef"

// vulnscoutRegistrySource — сам реєстр: він згадує предметні терміни оригіналу
// і не має рахуватися як наш код.
const vulnscoutRegistrySource = "vulnscout_reconciliation.md"

var vulnscoutCloneRoots = []string{
	"../Semple-Интеграции/vulnscout",
	"../vulnscout",
}

var vulnscoutUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var vulnscoutVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var vulnscoutRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const vulnscoutRequiredRows = 12

func readVulnscoutRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(vulnscoutRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnscoutRegistry, err)
	}
	rows := make([][]string, 0, vulnscoutRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := vulnscoutRow.FindStringSubmatch(strings.TrimSpace(line))
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

func vulnscoutCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// vulnscoutDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються, щоб прогалина була видима.
func vulnscoutDir(t *testing.T) string {
	t.Helper()
	for _, root := range vulnscoutCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("vulnscout clone not found in %v: the registry's counts cannot be "+
		"verified against the original", vulnscoutCloneRoots)
	return ""
}

func vulnscoutOurSources(t *testing.T) string {
	t.Helper()
	// Реєстр і **цей тест** згадують `grype`/`CycloneDX` за визначенням, тому
	// обидва виключаються. Перша версія не виключала нічого й падала на
	// власному імені — тобто перевірка «у нас немає SBOM» не могла пройти
	// ніколи, тобто не була перевіркою.
	skipped := map[string]bool{
		vulnscoutRegistrySource:            true,
		"vulnscout_reconciliation_test.go": true,
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			if skipped[entry.Name()] {
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

// TestVulnscoutRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestVulnscoutRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(vulnscoutRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnscoutRegistry, err)
	}
	match := vulnscoutUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", vulnscoutRegistry)
	}
	if got := string(match[1]); got != vulnscoutCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, vulnscoutCommit)
	}
}

// TestTheVulnscoutRegistryHasEveryRowItPromises.
func TestTheVulnscoutRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readVulnscoutRegistry(t)); got < vulnscoutRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			vulnscoutRegistry, got, vulnscoutRequiredRows)
	}
}

// TestEveryVulnscoutRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryVulnscoutRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readVulnscoutRegistry(t) {
		verdict := vulnscoutCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !vulnscoutVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedVulnscoutRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedVulnscoutRowSaysWhy(t *testing.T) {
	for _, row := range readVulnscoutRegistry(t) {
		if vulnscoutCell(row, 3) != "не перенесено" {
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

// TestEveryVulnscoutRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEveryVulnscoutRowNamesASymbolThatExists(t *testing.T) {
	sources := vulnscoutOurSources(t)
	for _, row := range readVulnscoutRegistry(t) {
		symbol := vulnscoutCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheNotPortedReasonsNameTheClassDifference — головна перевірка цього
// реєстру.
//
// Десять `не перенесено` тут означають «**інший клас інструмента**», а не
// «не встигли». Це різниця, яку треба тримати: якщо хтось перепише причину на
// «час», реєстр перестане відповідати на те, що в ньому написано, і на
// `vulnscout` дивинуться так, наче це прогалина у нашому продукті.
func TestTheNotPortedReasonsNameTheClassDifference(t *testing.T) {
	registry, err := os.ReadFile(vulnscoutRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnscoutRegistry, err)
	}
	if !strings.Contains(string(registry), "інший клас") {
		t.Errorf("%s never says that this is a different class of tool: the "+
			"ten не перенесено rows read as unfinished work otherwise",
			vulnscoutRegistry)
	}
	notPorted := 0
	for _, row := range readVulnscoutRegistry(t) {
		if vulnscoutCell(row, 3) == "не перенесено" {
			notPorted++
		}
	}
	if notPorted == 0 {
		t.Fatal("no не перенесено rows at all: the upstream shape changed and " +
			"the registry needs a look")
	}
}

// TestTheCorrectedNumbersAreMeasured — дві виправлені помилки не відкочуються.
//
// Ліцензія **є** (`LICENSE.GPL-3.0-only`), і код дорівнює 35 033 рядки в
// `src/`. Обидва числа звіряються з клоном: якщо попередня хибна таблиця
// повернеться, тест це побачить.
func TestTheCorrectedNumbersAreMeasured(t *testing.T) {
	dir := vulnscoutDir(t)

	// 1) ліцензія є, і реєстр зобов'язаний її назвати.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read clone: %v", err)
	}
	licenseNamed := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "LICENSE") {
			licenseNamed = entry.Name()
			break
		}
	}
	if licenseNamed == "" {
		t.Fatal("the clone has no LICENSE file at all: the registry's license " +
			"claim needs a look")
	}
	registry, err := os.ReadFile(vulnscoutRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnscoutRegistry, err)
	}
	if !strings.Contains(string(registry), licenseNamed) {
		t.Errorf("the clone ships %q, and %s does not name it", licenseNamed, vulnscoutRegistry)
	}

	// 2) рядки коду саме в src/, а не разом із тестами й frontend.
	files, lines := vulnscoutSourceSize(t, dir)
	if lines == 0 {
		t.Fatalf("no source read from %s: the count cannot stand either way", dir)
	}
	text := string(registry)
	if !strings.Contains(text, strconv.Itoa(files)) {
		t.Errorf("the original has %d source files in src/, and the registry "+
			"does not mention that number", files)
	}
	if wanted := vulnscoutThousandsSeparator(lines); !strings.Contains(text, wanted) {
		t.Errorf("the original has %d source lines in src/, and the registry "+
			"does not mention %s", lines, wanted)
	}
}

// vulnscoutSourceSize рахує файли й рядки саме в `src/`, без тестів.
//
// Тут була б помилка наївно рахувати все: попередня таблиця брала 93 034
// рядки, бо включила `tests/`, `frontend/` і `doc/`, а це не код застосунку.
func vulnscoutSourceSize(t *testing.T, dir string) (files, lines int) {
	t.Helper()
	err := filepath.Walk(filepath.Join(dir, "src"), func(path string,
		info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".py") {
			return nil
		}
		if strings.HasSuffix(path, "_test.py") {
			return nil
		}
		files++
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines += strings.Count(string(raw), "\n")
		return nil
	})
	if err != nil {
		t.Fatalf("walk upstream src: %v", err)
	}
	return files, lines
}

// vulnscoutThousandsSeparator форматує число як у реєстрі: «35 033».
func vulnscoutThousandsSeparator(value int) string {
	digits := strconv.Itoa(value)
	if len(digits) <= 3 {
		return digits
	}
	var out []byte
	for index, digit := range []byte(digits) {
		if index > 0 && (len(digits)-index)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, digit)
	}
	return string(out)
}

// TestTheSbomTermsAreTheOnesTheOriginalUses — звірка предметних слів.
//
// `SPDX`, `CycloneDX`, `grype` — це не мої слова про оригінал, а літерали з
// його коду. Якщо upstream перейменує формат або замінить рушій, реєстр має
// вимагати перегляду.
func TestTheSbomTermsAreTheOnesTheOriginalUses(t *testing.T) {
	dir := vulnscoutDir(t)
	parts := []string{}
	err := filepath.Walk(filepath.Join(dir, "src"), func(path string,
		info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".py") {
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
		t.Fatalf("walk upstream src: %v", err)
	}
	corpus := strings.Join(parts, "\n")
	for _, term := range []string{"SPDX", "CycloneDX", "grype", "OpenVEX"} {
		if !strings.Contains(corpus, term) {
			t.Errorf("the original no longer mentions %q anywhere in src/: the "+
				"registry's rows about it need a look", term)
		}
	}
	registry, err := os.ReadFile(vulnscoutRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnscoutRegistry, err)
	}
	for _, term := range []string{"SPDX", "CycloneDX", "grype", "OpenVEX"} {
		if !strings.Contains(string(registry), term) {
			t.Errorf("%s does not name %q, which the original uses", vulnscoutRegistry, term)
		}
	}
}

// TestWeHaveNoSbomParser — твердження «нашого парсера SBOM: 0» перевірюється.
//
// Реєстр каже, що ми не приймаємо артефакти. Це твердження про наш код, а не
// про оригінал, тому воно перевірюється пошуком: якщо `CycloneDX` з'явиться
// в нашому дереві, рядок 1 «не перенесено» стане брехнею.
func TestWeHaveNoSbomParser(t *testing.T) {
	sources := vulnscoutOurSources(t)
	for _, term := range []string{"CycloneDX", "cyclonedx", "grype"} {
		if strings.Contains(sources, term) {
			t.Errorf("our tree now mentions %q, and the registry says row 1 is "+
				"не перенесено: the registry needs a look", term)
		}
	}
}
