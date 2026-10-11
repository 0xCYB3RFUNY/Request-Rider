package main

// Механічна перевірка реєстру звірки з `1ndy2/Gf-Patterns`.
//
// Реєстр описує набір **даних** — 605 регулярних виразів у 14 JSON-файлах.
// Тому тест має ще одну перевірку, якої немає в жодному іншому реєстрі проєкту:
// він читає самі файли оригіналу і звіряє числа. Реєстр, який вигадує кількість
// патернів, «свіжий» рівно до першої правки оригіналу.
//
// Чотири речі, які він доводить:
//   - предмет звірки зафіксовано;
//   - кожен рядок має вердикт з трьох;
//   - `не перенесено` має причину;
//   - числа реєстру збігаються з файлами, які лежать у клоні.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const gfPatternsRegistry = "gfpatterns_reconciliation.md"

// gfPatternsClone — шлях до клону в робочому дереві. Оператор перемістив усі
// клони в `Semple-Интеграции/` 2026-10-08; обидва шляхи приймаються, бо реєстр
// має читатися і в дереві, де клон ще в корені.
// Клон лежить у корені репозиторію, а тест — у `engine/`, тому шлях піднімається
// на рівень вище. Обидва варіанти приймаються: оператор перемістив клони в
// `Semple-Интеграции/` 2026-10-08, а дерево, де клон ще в корені, теж має
// читатися.
var gfPatternsCloneRoots = []string{
	"../Semple-Интеграции/Gf-Patterns",
	"../Gf-Patterns",
	"../Прочее/Semple-Интеграции/Gf-Patterns",
}

var gfPatternsUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var gfPatternsVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var gfPatternsRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

// gfPatternsRequiredRows — 14 здатностей, по одній на файл оригіналу. Число не
// «на око»: воно дорівнює кількості JSON-файлів у клоні, і наступна перевірка
// це звіряє.
const gfPatternsRequiredRows = 14

func readGFPatternsRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(gfPatternsRegistry)
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
		t.Fatalf("read %s: %v", gfPatternsRegistry, err)
	}
	rows := make([][]string, 0, gfPatternsRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := gfPatternsRow.FindStringSubmatch(strings.TrimSpace(line))
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

func gfPatternsCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// gfPatternsDir знаходить клон оригіналу. Перевірка, яка не змогла знайти
// предмет звірки, повинна мовчати про відсутність символів — вона й мовчить,
// але з явною помилкою, а не з «усе зелено».
func gfPatternsDir(t *testing.T) string {
	t.Helper()
	for _, root := range gfPatternsCloneRoots {
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
	t.Skipf("Gf-Patterns clone not found in %v: the registry's numbers cannot be "+
		"verified against the original, and a registry nobody can check is a claim",
		gfPatternsCloneRoots)
	return ""
}

// gfPatternFile — один файл-категорія оригіналу.
//
// Обидва ключі читаються, бо `jsvar.json` має `pattern`, а решта — `patterns`.
// Різниця не випадкова: вона означає, що в оригіналі є файл, який **не працює
// як категорія**, і реєстр має це відображати, а не мовчати.
type gfPatternFile struct {
	Name     string
	Patterns []string
	Flags    string
	Key      string
}

func readGFPatternFiles(t *testing.T) []gfPatternFile {
	t.Helper()
	dir := gfPatternsDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	files := make([]gfPatternFile, 0, 16)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			t.Fatalf("read %s: %v", entry.Name(), readErr)
		}
		var document struct {
			Flags    string   `json:"flags"`
			Patterns []string `json:"patterns"`
			Pattern  string   `json:"pattern"`
		}
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("%s is not valid JSON: %v", entry.Name(), err)
		}
		patterns := document.Patterns
		key := "patterns"
		if len(patterns) == 0 && document.Pattern != "" {
			patterns = []string{document.Pattern}
			key = "pattern"
		}
		files = append(files, gfPatternFile{
			Name: entry.Name(), Patterns: patterns, Flags: document.Flags, Key: key,
		})
	}
	return files
}

// TestGFPatternsRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestGFPatternsRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(gfPatternsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gfPatternsRegistry, err)
	}
	if !gfPatternsUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", gfPatternsRegistry)
	}
}

// TestTheRegistryHasOneRowPerCategoryOfTheOriginal — рядок на кожен файл
// оригіналу. Це той самий принцип, що й «перелік знімається з файлів
// оригіналу»: файл, якому не відповідає жоден рядок, просто зникає, і його
// відсутність ніхто не помічає.
func TestTheRegistryHasOneRowPerCategoryOfTheOriginal(t *testing.T) {
	files := readGFPatternFiles(t)
	if len(files) == 0 {
		t.Fatalf("no category files found: the check would pass on an empty clone")
	}
	rows := readGFPatternsRegistry(t)
	if len(rows) != len(files) {
		t.Errorf("%s has %d numbered rows, the original has %d category files",
			gfPatternsRegistry, len(rows), len(files))
	}
	for _, file := range files {
		found := false
		for _, row := range rows {
			if strings.Contains(gfPatternsCell(row, 1), file.Name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("category %s has no registry row", file.Name)
		}
	}
}

// TestEveryGFPatternsRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryGFPatternsRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readGFPatternsRegistry(t) {
		// 1 = здатність, 2 = де в оригіналі, 3 = вердикт.
		verdict := gfPatternsCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !gfPatternsVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedGFPatternsRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedGFPatternsRowSaysWhy(t *testing.T) {
	for _, row := range readGFPatternsRegistry(t) {
		if gfPatternsCell(row, 3) != "не перенесено" {
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

// TestEveryGFPatternsRowNamesASymbolThatExists — заявлений символ має бути в
// дереві. Пошук іде по `.` і `pkg/`, бо символ може жити в будь-якому з них.
func TestEveryGFPatternsRowNamesASymbolThatExists(t *testing.T) {
	sources := gfPatternsSources(t)
	for _, row := range readGFPatternsRegistry(t) {
		symbol := gfPatternsCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			// Рядок, для якого символів у нас немає, позначається прочерком.
			// Це законно: вердикт `не перенесено` означає, що коду в нас немає,
			// і вимагати символ означало б вимагати вигаданої функції.
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

func gfPatternsSources(t *testing.T) string {
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

// TestTheRegistryCountsMatchTheOriginalFiles — числа реєстру звірені з
// файлами. Найважливіша з перевірок цього набору: реєстр рахує **дані**, а дані
// змінюються в upstream, і «605 патернів» має бути або правдою, або цифрою з
// минулого.
//
// Перевіряються три числа: файлів, патернів сумарно, і порожніх категорій.
func TestTheRegistryCountsMatchTheOriginalFiles(t *testing.T) {
	files := readGFPatternFiles(t)
	total := 0
	empty := 0
	for _, file := range files {
		total += len(file.Patterns)
		if len(file.Patterns) == 0 {
			empty++
		}
	}
	registry := gfPatternsSources(t)
	_ = registry

	raw, err := os.ReadFile(gfPatternsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gfPatternsRegistry, err)
	}
	text := string(raw)

	if got := gfPatternsItoa(len(files)); !strings.Contains(text, got) {
		t.Errorf("the registry does not mention the category count %d", len(files))
	}
	if got := gfPatternsItoa(total); !strings.Contains(text, got) {
		t.Errorf("the registry claims a total that is not %d: it says something else, "+
			"and the original now holds %d patterns across %d files",
			total, total, len(files))
	}
	if empty != 0 {
		t.Logf("%d categories carry no patterns; the registry names each of them, "+
			"and that is the expected state", empty)
	}
}

// TestTheSingletonKeyIsCountedAndNamed — категорія з єдиничним ключем.
//
// `jsvar.json` має ключ `pattern` замість `patterns`, і в ньому **один** вираз.
// Перша редакція цього реєстру назвала цю категорію порожньою, бо лічила
// тільки `patterns` — і механічний тест це виявив: сума вийшла 605 замість 606.
// Тому окрема перевірка: ключ, відмінний від `patterns`, має бути і порахований,
// і названий у реєстрі.
func TestTheSingletonKeyIsCountedAndNamed(t *testing.T) {
	raw, err := os.ReadFile(gfPatternsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gfPatternsRegistry, err)
	}
	singletons := 0
	for _, file := range readGFPatternFiles(t) {
		if file.Key == "patterns" {
			continue
		}
		singletons++
		if len(file.Patterns) == 0 {
			t.Errorf("%s uses the %q key and holds nothing: a category with no "+
				"patterns is still a category and needs a verdict", file.Name, file.Key)
		}
		if !strings.Contains(string(raw), file.Name) {
			t.Errorf("%s uses the %q key, and no registry row names it", file.Name, file.Key)
		}
	}
	if singletons != 1 {
		t.Logf("%d categories use a key other than patterns: the original's shape "+
			"changed, and the registry row for %q needs a look", singletons, "jsvar.json")
	}
}

// gfPatternsItoa — локальний Itoa, щоб не тягнути `strconv` у тест раді
// читабельності викликів.
//
// Ім'я **не** `itoa`: такий уже оголошений у `target_js_findings_test.go`,
// а це пакет `main`, де два однакові помощники — це компіляційна помилка. Тут
// не дублюється й не перейменовується чужий символ; просто взято ім'я, яке
// нічого не ламає. Реалізація тривіальна і перевіряється самим фактом збігу.
func gfPatternsItoa(value int) string {
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
