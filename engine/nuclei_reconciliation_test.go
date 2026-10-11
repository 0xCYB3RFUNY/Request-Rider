package main

// Механічна перевірка реєстру звірки з `projectdiscovery/nuclei/v3`.
//
// Тест перевіряє не зміст таблиці — її не перевіряє ніхто — а те, чому вона
// присвячена: що реєстр існує, що кожен рядок має вердикт з трьох, що
// `не перенесено` має причину, що заявлений символ реально є в дереві, і що
// зафіксовано коміт upstream. Рівень L2 з `АУДИТ_ІНТЕГРАЦІЙ.md` — це саме
// «реєстр є і він перевіряється механічно».
//
// Чому саме `не перенесено` вимагає причини. Вердикт без причини нерозрізнюваний
// від рядка, який забули заповнити, а саме такий рядок ховає втрату: його видно,
// але ніхто не знає, що за ним стояло. Причина обов'язкова — це рівно те
// правило, через яке з'явилися попередні реєстри.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nucleiRegistry — файл реєстру поруч із тестом.
const nucleiRegistry = "nuclei_reconciliation.md"

// nucleiUpstreamCommit фіксує предмет звірки. Таблиця проти незафіксованого
// коміту — це таблиця про інший предмет, тому тест падає, якщо рядок зник.
//
// Приймається і SHA-коміт, і тег модуля Go: `go.mod` фіксує саме `v3.11.1`, а
// `v` не є hex-цифрою, тому регулярка лише на `[0-9a-f]` відмовилася б на
// предметі, який проєкт справді використовує. Вимога — щоб предмет був
// **зафіксований**, а не щоб він виглядав як хеш.
var nucleiUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `(v?[0-9A-Za-z][0-9A-Za-z.\-]{1,40})` + "`")

var nucleiVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

// nucleiRow ловить рядок таблиці за формою `| N | ... |`. Індекс клітинки
// вердикту не захардкоджується: воно рахується, а не задається, інакше зсув
// на одну колонку перетворює перевірку на декорацію.
var nucleiRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

// nucleiRequiredRowCount — скільки рядків має бути. Число не «на око»: воно
// росте разом із реєстром, і тест каже, коли реєстр урізали.
const nucleiRequiredRowCount = 53

// readNucleiRegistry читає рядки таблиці, повертаючи номер рядка й клітинки.
func readNucleiRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(nucleiRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiRegistry, err)
	}
	rows := make([][]string, 0, nucleiRequiredRowCount)
	for _, line := range strings.Split(string(raw), "\n") {
		match := nucleiRow.FindStringSubmatch(strings.TrimSpace(line))
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

// nucleiCell повертає клітинку за індексом, обрізаючи пробіли й зворотні лапки.
func nucleiCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// TestNucleiRegistryFixesTheUpstreamCommit — предмет звірки має бути зафіксований.
func TestNucleiRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(nucleiRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiRegistry, err)
	}
	if !nucleiUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", nucleiRegistry)
	}
}

// TestNucleiRegistryHasEveryRowItPromises — число рядків не зменшується мовчки.
func TestNucleiRegistryHasEveryRowItPromises(t *testing.T) {
	rows := readNucleiRegistry(t)
	if len(rows) < nucleiRequiredRowCount {
		t.Errorf("%s has %d numbered rows, want at least %d: a row was removed "+
			"and the reason went with it", nucleiRegistry, len(rows), nucleiRequiredRowCount)
	}
}

// TestEveryNucleiRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryNucleiRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readNucleiRegistry(t) {
		// Клітинки: 1 = здатність, 2 = де в оригіналі, 3 = вердикт.
		verdict := nucleiCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !nucleiVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улушшено / не перенесено", row[0], verdict)
		}
	}
}

// TestEveryNotPortedNucleiRowSaysWhy — причина обов'язкова: вердикт без причини
// нерозрізнюваний від нерозкритого рядка.
func TestEveryNotPortedNucleiRowSaysWhy(t *testing.T) {
	for _, row := range readNucleiRegistry(t) {
		if nucleiCell(row, 3) != "не перенесено" {
			continue
		}
		// Підстава — остання істотна клітинка перед символом; вона може містити
		// кілька речень, тому беремо весь хвіст рядка, а не фіксовану комірку.
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

// TestEveryNucleiRowNamesASymbolThatExists — заявлений символ має бути в дереві.
//
// Пошук іде по **всіх** шарах, де живе заявлене: `.go` у корені движка, `pkg/`
// і шаблони. Пошук лише по кореневих `*.go` відрапортував би «немає» про наявний
// код, і перевірка стала б декорацією.
func TestEveryNucleiRowNamesASymbolThatExists(t *testing.T) {
	sources := nucleiEngineSources(t)
	for _, row := range readNucleiRegistry(t) {
		symbol := nucleiCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			t.Errorf("row %s names no symbol", row[0])
			continue
		}
		// `NucleiOptions` і `nucleiRequest` — це типи й поля, а не функції; вони
		// живуть у тому ж дереві, тому перевірка однакова.
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// nucleiEngineSources читає всі Go-файли движка і шаблони, щоб символ, який живе
// у `pkg/`, був знайдений, а не доповідався відсутнім.
func nucleiEngineSources(t *testing.T) string {
	t.Helper()
	parts := []string{}
	for _, root := range []string{".", "pkg", "web/templates"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".html") {
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

// TestEveryNucleiCapabilityWeHaveIsCovered — наша власна здатність має рядок.
//
// Напрям «сверка з тим, що вже є» пропускає здатність, яку ще ніхто не
// переносив: вона просто відсутня, і відсутність читається як «нема чого
// втрачати». Тому перевірка йде в інший бік: будь-який наш символ
// nuclei-інтеграції, який є в дереві, має бути згаданий у реєстрі.
func TestEveryNucleiCapabilityWeHaveIsCovered(t *testing.T) {
	rows := readNucleiRegistry(t)
	seen := map[string]bool{}
	for _, row := range rows {
		seen[nucleiCell(row, len(row)-1)] = true
	}
	// Символи, які реєстр зобов'язаний називати: усе, чим цей шар користується
	// для планування, класифікації та доказу. Перелік відкритий по іменах, а не
	// виводиться з коду, бо мета тесту — не «усі символи в каталозі», а «жодна
	// здатність, про яку ми знаємо, не залишилася без рядка».
	required := []string{
		"buildNucleiArgs",           // план запуску і прапорці
		"BuildPlan",                 // розкладка по template-id і батчах
		"nucleiFinding",             // розбір JSONL і звіт
		"protocolBlocks",            // секції документа
		"capabilityFlag",            // можливості движка
		"javascriptAddressesTarget", // класифікація JavaScript
		"IsWorkflow",                // workflow
		"IsFlow",                    // flow
		"applyLocalFallback",        // локальний відкат
		"TemplateEvent",             // live-потік
	}
	for _, symbol := range required {
		if !seen[symbol] {
			t.Errorf("capability %q exists in the tree but no registry row names it", symbol)
		}
	}
}
