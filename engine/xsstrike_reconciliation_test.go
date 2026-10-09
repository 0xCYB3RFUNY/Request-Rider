package main

// Механічна перевірка реєстру звірки з `XSStrike`.
//
// Реєстр має одну особливість, якої немає в інших: **ліцензію**. XSStrike —
// GPL-3.0, тому код у MIT-проєкт не переноситься, і реєстр фіксує не «що ми
// зробили», а «що ми зробили власними силами». Тому тут перевіряється ще
// одне: ліцензія має бути названа, бо читач реєстру інакше вирішить, що
// `не перенесено` — це недолік, а не наслідок ліцензії.
//
// Друга особливість: цифра **66 WAF-підписів**. Вона приходить з клону, тому
// перевіряється читанням оригіналу — реєстр не має права вигадувати розмір
// чужої бази.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const xsstrikeRegistry = "xsstrike_reconciliation.md"

var xsstrikeCloneRoots = []string{
	"../Semple-Интеграции/xsstrike",
	"../xsstrike",
}

var xsstrikeUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var xsstrikeVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var xsstrikeRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const xsstrikeRequiredRows = 12

func readXsstrikeRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(xsstrikeRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xsstrikeRegistry, err)
	}
	rows := make([][]string, 0, xsstrikeRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := xsstrikeRow.FindStringSubmatch(strings.TrimSpace(line))
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

func xsstrikeCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func xsstrikeDir(t *testing.T) string {
	t.Helper()
	for _, root := range xsstrikeCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Fatalf("xsstrike clone not found in %v: the registry's counts cannot be "+
		"verified against the original", xsstrikeCloneRoots)
	return ""
}

func xsstrikeSources(t *testing.T) string {
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

// TestXsstrikeRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestXsstrikeRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(xsstrikeRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xsstrikeRegistry, err)
	}
	if !xsstrikeUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", xsstrikeRegistry)
	}
}

// TestTheXsstrikeRegistryNamesTheLicenseItCannotUse — ліцензія названа.
//
// Без цього рядка читач бачить `не перенесено` на половині таблиці й думає, що
// це недолік роботи. Причина тут інша: GPL-3.0 не вливається в MIT. Реєстр
// має це сказати явно, і перевірка падає, якщо зняти.
func TestTheXsstrikeRegistryNamesTheLicenseItCannotUse(t *testing.T) {
	raw, err := os.ReadFile(xsstrikeRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xsstrikeRegistry, err)
	}
	if !strings.Contains(strings.ToLower(string(raw)), "gpl-3.0") {
		t.Errorf("%s does not name the license: every не перенесено row in it is "+
			"read as a gap in our work, while the actual reason is the license", xsstrikeRegistry)
	}
}

// TestTheXsstrikeRegistryHasEveryRowItPromises.
func TestTheXsstrikeRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readXsstrikeRegistry(t)); got < xsstrikeRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d", xsstrikeRegistry, got, xsstrikeRequiredRows)
	}
}

// TestEveryXsstrikeRowHasAVerdictFromTheThree.
func TestEveryXsstrikeRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readXsstrikeRegistry(t) {
		verdict := xsstrikeCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !xsstrikeVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улушшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedXsstrikeRowSaysWhy.
func TestEveryNotPortedXsstrikeRowSaysWhy(t *testing.T) {
	for _, row := range readXsstrikeRegistry(t) {
		if xsstrikeCell(row, 3) != "не перенесено" {
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

// TestEveryXsstrikeRowNamesASymbolThatExists.
func TestEveryXsstrikeRowNamesASymbolThatExists(t *testing.T) {
	sources := xsstrikeSources(t)
	for _, row := range readXsstrikeRegistry(t) {
		symbol := xsstrikeCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheWafDatabaseCountIsMeasuredNotGuessed — 66 підписів з оригіналу.
//
// Реєстр заявляє конкретне число, і число береться з `db/wafSignatures.json`
// клону. Якщо upstream змінить базу, реєстр зобов'язаний змінитися разом із
// ним: мовчати тут означало б писати «66» у документі, який перестане відповідати
// джерелу.
func TestTheWafDatabaseCountIsMeasuredNotGuessed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(xsstrikeDir(t), "db/wafSignatures.json"))
	if err != nil {
		t.Fatalf("read upstream waf signatures: %v", err)
	}
	var signatures map[string]any
	if err := json.Unmarshal(raw, &signatures); err != nil {
		t.Fatalf("wafSignatures.json is not a JSON object: %v", err)
	}
	count := len(signatures)
	if count == 0 {
		t.Fatalf("the upstream WAF database is empty: the registry's claim about it " +
			"cannot stand either way")
	}

	registry, err := os.ReadFile(xsstrikeRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xsstrikeRegistry, err)
	}
	if !strings.Contains(string(registry), xsStrikeItoa(count)) {
		t.Errorf("the upstream WAF database holds %d signatures, and the registry "+
			"does not mention %d: it claims a number it did not measure", count, count)
	}
}

// TestTheLibraryDatabaseCountIsMeasuredNotGuessed — те саме для 34 бібліотек.
func TestTheLibraryDatabaseCountIsMeasuredNotGuessed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(xsstrikeDir(t), "db/definitions.json"))
	if err != nil {
		t.Fatalf("read upstream definitions: %v", err)
	}
	var definitions map[string]any
	if err := json.Unmarshal(raw, &definitions); err != nil {
		t.Fatalf("definitions.json is not a JSON object: %v", err)
	}
	count := len(definitions)

	registry, err := os.ReadFile(xsstrikeRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xsstrikeRegistry, err)
	}
	if !strings.Contains(string(registry), xsStrikeItoa(count)) {
		t.Errorf("the upstream library database holds %d entries, and the registry "+
			"does not mention %d", count, count)
	}
}

// TestEveryScanModeOfTheOriginalIsAccountedFor — кожен режим `modes/` має рядок
// або згадку.
//
// XSStrike має чотири режими, і `bruteforcer` та `singleFuzz` — це різні
// способи почати перевірку. Реєстр має назвати кожен: інакше режим зникає
// мовчки, а читач реєстру не дізнається, що він існує.
func TestEveryScanModeOfTheOriginalIsAccountedFor(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(xsstrikeDir(t), "modes"))
	if err != nil {
		t.Fatalf("read modes dir: %v", err)
	}
	registry, err := os.ReadFile(xsstrikeRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xsstrikeRegistry, err)
	}
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".py") || strings.HasPrefix(name, "__") {
			continue
		}
		seen++
		mode := strings.TrimSuffix(name, ".py")
		if !strings.Contains(string(registry), mode) {
			t.Errorf("mode %s has no registry row", mode)
		}
	}
	if seen != 4 {
		t.Logf("the original has %d modes now; the registry's summary needs a look", seen)
	}
}

// xsStrikeItoa — локальний Itoa. Ім'я унікальне з тієї ж причини, що й
// `gfPatternsItoa`: `itoa` вже зайнятий у цьому пакеті чужим файлом.
func xsStrikeItoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}
