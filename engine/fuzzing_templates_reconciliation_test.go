package main

// Механічна перевірка реєстру звірки з `projectdiscovery/fuzzing-templates`.
//
// Репозиторій **не містить коду** — це корпус YAML-шаблонів. Тому перевірка
// міряє не функції, а **покриття**: здатність оригіналу тут дорівнює самому
// корпусу, і реєстр зобов'язаний назвати кожну категорію.
//
// Друга половина — перевірка **нашого** рушія: якщо здатність «виконувати
// fuzzing-шаблон» перестане бути в коді, три `супадає`/`улучшено` миттю
// стають брехнею, і це треба побачити одразу.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const fuzzingTemplatesRegistry = "fuzzing_templates_reconciliation.md"

const fuzzingTemplatesCommit = "5585787"

var fuzzingTemplatesCloneRoots = []string{
	"../Semple-Интеграции/fuzzing-templates",
	"../fuzzing-templates",
}

var fuzzingTemplatesUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var fuzzingTemplatesVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var fuzzingTemplatesRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const fuzzingTemplatesRequiredRows = 10

func readFuzzingTemplatesRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(fuzzingTemplatesRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", fuzzingTemplatesRegistry, err)
	}
	rows := make([][]string, 0, fuzzingTemplatesRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := fuzzingTemplatesRow.FindStringSubmatch(strings.TrimSpace(line))
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

func fuzzingTemplatesCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// fuzzingTemplatesDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються.
func fuzzingTemplatesDir(t *testing.T) string {
	t.Helper()
	for _, root := range fuzzingTemplatesCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("fuzzing-templates clone not found in %v: the registry's counts "+
		"cannot be verified against the original", fuzzingTemplatesCloneRoots)
	return ""
}

func fuzzingTemplatesOurSources(t *testing.T) string {
	t.Helper()
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == fuzzingTemplatesRegistry ||
			name == "reconciliation_summary_test.go"
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner"} {
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

// TestFuzzingTemplatesRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestFuzzingTemplatesRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(fuzzingTemplatesRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", fuzzingTemplatesRegistry, err)
	}
	match := fuzzingTemplatesUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", fuzzingTemplatesRegistry)
	}
	if got := string(match[1]); got != fuzzingTemplatesCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, fuzzingTemplatesCommit)
	}
}

// TestTheFuzzingTemplatesRegistryHasEveryRowItPromises.
func TestTheFuzzingTemplatesRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readFuzzingTemplatesRegistry(t)); got < fuzzingTemplatesRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			fuzzingTemplatesRegistry, got, fuzzingTemplatesRequiredRows)
	}
}

// TestEveryFuzzingTemplatesRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryFuzzingTemplatesRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readFuzzingTemplatesRegistry(t) {
		verdict := fuzzingTemplatesCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !fuzzingTemplatesVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedFuzzingTemplatesRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedFuzzingTemplatesRowSaysWhy(t *testing.T) {
	for _, row := range readFuzzingTemplatesRegistry(t) {
		if fuzzingTemplatesCell(row, 3) != "не перенесено" {
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

// TestEveryFuzzingTemplatesRowNamesASymbolThatExists — символ має бути в дереві.
func TestEveryFuzzingTemplatesRowNamesASymbolThatExists(t *testing.T) {
	sources := fuzzingTemplatesOurSources(t)
	for _, row := range readFuzzingTemplatesRegistry(t) {
		symbol := fuzzingTemplatesCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestEveryCategoryIsAccountedFor — головна перевірка цього реєстру.
//
// Перелік категорій знімається з **оригіналу**, а не з того, що вже є в
// реєстрі: інакше здатність, яку ніхто не переносив, просто не потрапила б
// у перелік і виглядала б так, наче її немає.
//
// Тому: нова категорія в upstream зобов'язана з'явитися в реєстрі.
func TestEveryCategoryIsAccountedFor(t *testing.T) {
	dir := fuzzingTemplatesDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read clone: %v", err)
	}
	total := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		found, walkErr := filepath.Glob(filepath.Join(dir, entry.Name(), "*.yaml"))
		if walkErr != nil {
			t.Errorf("glob %s: %v", entry.Name(), walkErr)
			continue
		}
		if len(found) == 0 {
			continue
		}
		total += len(found)
		registry, readErr := os.ReadFile(fuzzingTemplatesRegistry)
		if readErr != nil {
			t.Fatalf("read %s: %v", fuzzingTemplatesRegistry, readErr)
		}
		if !strings.Contains(string(registry), "`"+entry.Name()+"`") {
			t.Errorf("the original has a %q category, and %s has no row "+
				"naming it", entry.Name(), fuzzingTemplatesRegistry)
		}
	}
	if total == 0 {
		t.Fatalf("no templates found in %s: the registry's count cannot stand "+
			"either way", dir)
	}
	registry, err := os.ReadFile(fuzzingTemplatesRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", fuzzingTemplatesRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(total)) {
		t.Errorf("the original holds %d templates, and the registry does not "+
			"mention that number", total)
	}
}

// TestWeStillRunFuzzingTemplates — наш рушій має працювати.
//
// Три рядки реєстру кажуть `супадає`/`улучшено` на підставі того, що ми
// вміємо виконати fuzzing-шаблон. Якщо `CapabilityDAST` зникне, ці вердикти
// стануть брехнею — і корпус, який ми завантажимо, просто не відпрацює.
func TestWeStillRunFuzzingTemplates(t *testing.T) {
	sources := fuzzingTemplatesOurSources(t)
	if !strings.Contains(sources, "CapabilityDAST") {
		t.Error("CapabilityDAST is gone from our code: rows 1 and 9 claim we " +
			"run fuzzing templates, and that is no longer true")
	}
	if !strings.Contains(sources, `"fuzzing"`) {
		t.Error("our document parser no longer knows the fuzzing block: the " +
			"fuzzing capability cannot be classified without it")
	}
}

// TestTheDastIsolationClaimIsMeasured — ізольований виклик `-dast`.
//
// Реєстр посилається на виміряний дефект: `-dast` у папці без fuzzing
// шаблонів друкує `no templates provided for scan` і виходить з кодом 1.
// Якщо ми перестанемо ізолювати `-dast`, весь виклик загине на 54 файлах —
// тому твердження перевірюється пошуком нашого коментаря про це.
func TestTheDastIsolationClaimIsMeasured(t *testing.T) {
	sources := fuzzingTemplatesOurSources(t)
	if !strings.Contains(sources, "no templates provided for scan") {
		t.Error("our code no longer records the measured `-dast` failure: row 2 " +
			"cites it as the reason the invocation must stay isolated")
	}
}
