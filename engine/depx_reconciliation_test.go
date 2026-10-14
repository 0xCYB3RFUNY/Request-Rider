package main

// Механічна перевірка реєстру звірки з `projectdiscovery/depx`.
//
// Дві речі, які роблять цей тест не схожим на решту.
//
// Перша: **символи шукаються по всьому проєкту**, а не лише в `engine/*.go`.
// Реєстр звіряє і Go-символ (`retirejsLibraries`), і Django-модель
// (`ProjectEndpoint`), і константу з шаблону (`EXPORT_REPORT_CSS`). Пошук
// лише в Go зробив би перевірку символів декоративною для половини рядків —
// вона «проходила б» ніколи.
//
// Друга: головна перевірка стежить за **відсутністю** розбору lockfile.
// Реєстр каже, що ми не читаємо репозиторій ціли. Це твердження про наш код,
// тож воно перевірюється пошуком: якщо з'явиться `package-lock.json` або
// `lockfile`, десять рядків `не перенесено` прочитаються як недоречені.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const depxRegistry = "depx_reconciliation.md"

const depxCommit = "4d5e392"

var depxCloneRoots = []string{
	"../Semple-Интеграции/depx",
	"../depx",
}

var depxUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var depxVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var depxRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const depxRequiredRows = 12

func readDexpRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(depxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", depxRegistry, err)
	}
	rows := make([][]string, 0, depxRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := depxRow.FindStringSubmatch(strings.TrimSpace(line))
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

func depxCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func depxDir(t *testing.T) string {
	t.Helper()
	for _, root := range depxCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("depx clone not found in %v: the registry's counts cannot be "+
		"verified against the original", depxCloneRoots)
	return ""
}

// depxProjectSources читає **весь** наш проєкт: Go движка, Python Django і
// шаблон. Реєстр звіряє здатності на трьох шарах, і перевірка символів має
// бачити всі три — інакше вона не перевіряє нічого.
func depxProjectSources(t *testing.T) string {
	t.Helper()
	// Усі реєстрові файли виключаються: вони згадують `lockfile`,
	// `sbom` та інші слова оригіналу за визначенням. Перевірка, що читає
	// сама себе, не може ніколи стати зеленою.
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == depxRegistry ||
			name == "reconciliation_summary_test.go"
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner", "pkg/enrich",
		"../web/lab", "../web/core", "../web/templates/lab"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if skipped(name) {
				continue
			}
			switch {
			case strings.HasSuffix(name, ".go"),
				strings.HasSuffix(name, ".py"),
				strings.HasSuffix(name, ".html"):
			default:
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(root, name))
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

// TestDexpRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestDexpRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(depxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", depxRegistry, err)
	}
	match := depxUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", depxRegistry)
	}
	if got := string(match[1]); got != depxCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, depxCommit)
	}
}

// TestTheDexpRegistryHasEveryRowItPromises.
func TestTheDexpRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readDexpRegistry(t)); got < depxRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			depxRegistry, got, depxRequiredRows)
	}
}

// TestEveryDexpRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryDexpRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readDexpRegistry(t) {
		verdict := depxCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !depxVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedDexpRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedDexpRowSaysWhy(t *testing.T) {
	for _, row := range readDexpRegistry(t) {
		if depxCell(row, 3) != "не перенесено" {
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

// TestEveryDexpRowNamesASymbolThatExists — символ має бути в проєкті.
//
// Пошук іде по Go, Python і шаблону разом: реєстр звіряє здатності на всіх
// трьох шарах, і перевірка символів має бачити всі три.
func TestEveryDexpRowNamesASymbolThatExists(t *testing.T) {
	sources := depxProjectSources(t)
	for _, row := range readDexpRegistry(t) {
		symbol := depxCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the project", row[0], symbol)
		}
	}
}

// TestTheMaliciousIndexSizeIsMeasured — головна здатність depx.
//
// `internal/malindex/` — 2 140 рядків, тобто більше за наш увесь розбір
// залежностей разом. Число звіряється з клоном, бо саме воно робить рядок 2
// окремим, а не частиною загального «ми не читаємо репозиторій».
func TestTheMaliciousIndexSizeIsMeasured(t *testing.T) {
	dir := depxDir(t)
	lines := 0
	err := filepath.Walk(filepath.Join(dir, "internal/malindex"), func(path string,
		info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines += strings.Count(string(raw), "\n")
		return nil
	})
	if err != nil {
		t.Fatalf("walk upstream malindex: %v", err)
	}
	if lines == 0 {
		t.Fatalf("no malindex source read: the registry's headline claim " +
			"cannot stand either way")
	}
	registry, err := os.ReadFile(depxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", depxRegistry, err)
	}
	if wanted := depxThousandsSeparator(lines); !strings.Contains(string(registry), wanted) {
		t.Errorf("the original's malicious-package index holds %d lines, and the "+
			"registry does not mention %s", lines, wanted)
	}
}

func depxThousandsSeparator(value int) string {
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

// TestThePackageCountIsMeasured — 18 пакетів у `internal/`.
func TestThePackageCountIsMeasured(t *testing.T) {
	dir := depxDir(t)
	entries, err := os.ReadDir(filepath.Join(dir, "internal"))
	if err != nil {
		t.Fatalf("read upstream internal: %v", err)
	}
	packages := 0
	for _, entry := range entries {
		if entry.IsDir() {
			packages++
		}
	}
	if packages == 0 {
		t.Fatalf("no packages found: the registry's count cannot stand either way")
	}
	registry, err := os.ReadFile(depxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", depxRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(packages)) {
		t.Errorf("the original has %d packages in internal/, and the registry "+
			"does not mention that number", packages)
	}
}

// TestWeParseNoLockfile — головна перевірка цього реєстру.
//
// Дев'ять `не перенесено` спираються на те, що ми не читаємо lockfile. Якщо
// з'явиться будь-який з цих маркерів, ця підстава перестає бути правдою, і
// реєстр треба переглядати — а не тихо залишати старим.
func TestWeParseNoLockfile(t *testing.T) {
	sources := depxProjectSources(t)
	for _, marker := range []string{
		"package-lock.json", "yarn.lock", "pnpm-lock", "go.sum",
		"requirements.txt", "Cargo.lock", "composer.lock", "Gemfile.lock",
	} {
		if strings.Contains(sources, marker) {
			t.Errorf("our project now mentions %q: the registry's nine "+
				"не перенесено rows rest on the absence of lockfile parsing",
				marker)
		}
	}
}

// TestTheRetireOverlapIsReal — рядок 4 стверджує, що перетин є.
//
// Це єдиний рядок `супадає`, тож він несе найбільшу вагу: якщо
// `retirejsLibraries` зникне або перейменується, реєстр перестане мати
// жодного справжнього перетину з depx, і це треба побачити одразу.
func TestTheRetireOverlapIsReal(t *testing.T) {
	sources := depxProjectSources(t)
	if !strings.Contains(sources, "retirejsLibraries") {
		t.Error("retirejsLibraries is gone from the project: row 4 is супадає, " +
			"and that verdict now has nothing behind it")
	}
	registry, err := os.ReadFile(depxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", depxRegistry, err)
	}
	if !strings.Contains(string(registry), "retirejsLibraries") {
		t.Errorf("%s does not name retirejsLibraries, which is its only "+
			"genuine overlap with the original", depxRegistry)
	}
}

// TestTheUndeterminedProgressClaimIsMeasured — рядок 10 стверджує, що в нас
// є індикатор невизначеної довжини.
//
// Твердження про наш код, тому перевірюється пошуком: `percent == -1` має
// бути в шаблоні. Якщо його приберуть, `улушшено` перестане бути
// виміряним.
func TestTheUndeterminedProgressClaimIsMeasured(t *testing.T) {
	raw, err := os.ReadFile("../web/templates/lab/index.html")
	if err != nil {
		t.Fatalf("read our template: %v", err)
	}
	// Літерал у нашому шаблоні — `percent: -1` і `percent < 0`, а **не**
	// `percent == -1`, як я спершу написав у реєстрі: вираз з подвійним
	// знаком рівності у нашому коді відсутній, і перевірка за ним ніколи не
	// могла б пройти.
	if !strings.Contains(string(raw), "percent: -1") &&
		!strings.Contains(string(raw), "percent < 0") {
		t.Error("our template no longer carries an indeterminate percent marker: " +
			"row 10 claims an indicator we do not have")
	}
}
