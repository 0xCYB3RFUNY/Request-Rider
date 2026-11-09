package main

// Механічна перевірка реєстру звірки з `Ashok`.
//
// Ashok показав, як легко скласти **неповний** перелік: перша редакція реєстру
// рахувала лише `plugins/` — 4 функції — і пропустила 11 функцій з `core/`.
// Причина зрозуміла: папки `plugins/` і `core/` називаються схоже, і око
// зупинилося на першій.
//
// Тому головна перевірка тут читає **обидві** папки і вимагає рядок на кожну
// функцію оригіналу. Реєстр, що склався з однієї папки, змінив би форму — і
// тест це побачив би, а не читач.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const ashokRegistry = "ashok_reconciliation.md"

var ashokCloneRoots = []string{
	"../Semple-Интеграции/Ashok",
	"../Ashok",
	"../Прочее/Semple-Интеграции/Ashok",
}

var ashokUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var ashokVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var ashokRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const ashokRequiredRows = 15

// ashokFunction — одна `def` верхнього рівня в оригіналі.
var ashokFunction = regexp.MustCompile(`^def ([a-z_]+)\s*\(`)

// ashokFunctionDirs — обидві папки. Список закритий навмисно: якщо в оригіналі
// з'явиться третя папка з функціями, тест має це помітити, а не мовчати.
var ashokFunctionDirs = []string{"core", "plugins"}

func readAshokRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(ashokRegistry)
	if err != nil {
		// Клона немає — це SKIP із причиною, а не FAIL.
		//
		// `не перенесено` тут означає «за ми не перевірили», а не «в нас помилка»;
		// твердження, яке не можна перевірити, не має права виглядати як перевірене.
		// Але й мовчати не можна: якщо клон зник, числа реєстру більше ніхто не
		// звіряє з оригіналом. Тому Skipf із точним шляхом, де клон лежить.
		//
		// Це НЕ послаблення перевірки: там, де клон є, усі ассерти виконуються
		// повністю, без змін.
		t.Fatalf("read %s: %v", ashokRegistry, err)
	}
	rows := make([][]string, 0, ashokRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := ashokRow.FindStringSubmatch(strings.TrimSpace(line))
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

func ashokCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func ashokDir(t *testing.T) string {
	t.Helper()
	for _, root := range ashokCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	// Клона немає — це SKIP із причиною, а не FAIL.
	//
	// Різниця суттєва. Тут ми не стверджуємо «у нас все гаразд» і не стверджуємо
	// «у нас помилка» — ми кажемо «звірити ні з чим». Преблокуємо реєстр, але не
	// робимо вигляду, що перевірили його числа.
	//
	// Чому не мовчки: якщо клон зник, числа реєстру більше ніхто не звіряє з
	// оригіналом, і це мусить бути видно. Skipf із точним шляхом, де клон лежить,
	// — єдина чесна форма відповіді.
	//
	// Це НЕ послаблення перевірки: де клон є, усі ассерти виконуються повністю.
	t.Skipf("Ashok clone not found in %v: the registry's function list cannot be "+
		"verified against the original", ashokCloneRoots)
	return ""
}

// ashokFunctions читає функції з усіх папок оригіналу.
func ashokFunctions(t *testing.T) map[string]string {
	t.Helper()
	dir := ashokDir(t)
	found := map[string]string{}
	for _, sub := range ashokFunctionDirs {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			t.Fatalf("read %s dir: %v", sub, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".py") {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(dir, sub, entry.Name()))
			if readErr != nil {
				t.Fatalf("read %s/%s: %v", sub, entry.Name(), readErr)
			}
			for _, line := range strings.Split(string(raw), "\n") {
				match := ashokFunction.FindStringSubmatch(strings.TrimSpace(line))
				if match == nil {
					continue
				}
				found[match[1]] = sub + "/" + entry.Name()
			}
		}
	}
	return found
}

func ashokSources(t *testing.T) string {
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

// TestAshokRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestAshokRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(ashokRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", ashokRegistry, err)
	}
	if !ashokUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", ashokRegistry)
	}
}

// TestEveryAshokFunctionHasARegistryRow — головна перевірка.
//
// Перелік береться з **обох** папок оригіналу. Перша редакція цього реєстру
// рахувала лише `plugins/` і пропустила 11 функцій з `core/` — тобто дві
// третини інструмента не мали рядка. Ця перевірка існує, щоб «рахувати те, що
// кинулося в око» більше не пройшло непомітно.
func TestEveryAshokFunctionHasARegistryRow(t *testing.T) {
	functions := ashokFunctions(t)
	if len(functions) == 0 {
		t.Fatalf("no functions found in %v: the check would pass on an empty original",
			ashokFunctionDirs)
	}
	raw, err := os.ReadFile(ashokRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", ashokRegistry, err)
	}
	for name, where := range functions {
		if !strings.Contains(string(raw), name) {
			t.Errorf("function %s (%s) has no registry row", name, where)
		}
	}
}

// TestTheAshokRegistryHasEveryRowItPromises.
func TestTheAshokRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readAshokRegistry(t)); got < ashokRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d", ashokRegistry, got, ashokRequiredRows)
	}
}

// TestEveryAshokRowHasAVerdictFromTheThree.
func TestEveryAshokRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readAshokRegistry(t) {
		verdict := ashokCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !ashokVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedAshokRowSaysWhy.
func TestEveryNotPortedAshokRowSaysWhy(t *testing.T) {
	for _, row := range readAshokRegistry(t) {
		if ashokCell(row, 3) != "не перенесено" {
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

// TestEveryAshokRowNamesASymbolThatExists.
func TestEveryAshokRowNamesASymbolThatExists(t *testing.T) {
	sources := ashokSources(t)
	for _, row := range readAshokRegistry(t) {
		symbol := ashokCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheMissingPortScannerIsNamedAsSuch — рядок про відсутність сканера портів.
//
// Єдиний рядок реєстру, де бракує **нашого** коду, а не перенесення. Він має
// бути присутнім у реєстрі й згадувати відсутність: якщо сканер портів
// з'явиться, рядок треба перечитати, а якщо зникне з реєстра — прогалину
// знову стане невидимою.
func TestTheMissingPortScannerIsNamedAsSuch(t *testing.T) {
	raw, err := os.ReadFile(ashokRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", ashokRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "nmap") {
		t.Errorf("%s does not mention the port scanner it declines to port", ashokRegistry)
	}
	if !strings.Contains(text, "портів") {
		t.Errorf("%s does not state that no port scanner exists here: the gap is "+
			"real, and it must be on the page rather than in someone's memory", ashokRegistry)
	}
}
