package main

// Звірка підсумку реєстру з його ж рядками.
//
// Цей файл існує через конкретну помилку, а не «для повноти». Підсумок
// реєстру — це таблиця чисел у прозі («`не перенесено` | **4**»), а таблиця
// здатностей — це рядки з вердиктами. Обидві написані вручну, і **ніщо не
// звіряло їх між собою**.
//
// Наслідок виміряний: `subfinder_reconciliation.md` заявляв **7** рядків
// `не перенесено`, а містив **4**. Число було з правильної таблиці, взятої
// з іншої редакції, і виглядало переконливо.
//
// Тому правило просте і механічне: якщо реєстр **містить** рядок підсумку про
// кількість вердиктів, це число має збігатися з тим, що реально стоїть у
// рядках. Реєстр без такого рядка перевірка не зачіпає — вона не має права
// вимагати формату, якого сам не навчила.
//
// Реєстри, які перевіряються: `engine/*_reconciliation.md` і
// `engine/reconciliation/*_reconciliation.md`. Ті, що не мають рядка
// підсумку, просто пропускаються — це не збіг, а відсутність вимоги.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// reconciliationVerdicts — вердикт-стан для рядка здатностей.
var reconciliationVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

// reconciliationRowRe ловить рядок таблиці здатностей: `| 7 | … |`.
// Число обов'язкове, бо без нього це будь-яка таблиця у файлі.
var reconciliationRowRe = regexp.MustCompile(`^\|\s*(\d+)\s*\|`)

// reconciliationVerdictRe дістає вердикт із рядка: перший із трьох, обгорнутий
// зворотними лапками. Пошук по рядку, а не по фіксованій колонці, бо різні
// реєстри мають різну кількість колонок, і колонка — деталь формату, а не
// зміст.
var reconciliationVerdictRe = regexp.MustCompile(
	"`(" + "супадає|улучшено|не перенесено" + ")`")

// reconciliationSummaryRe ловить рядок підсумку виду:
//
//	| `не перенесено` | **4** |
//
// Назва вердикту в зворотних лапках, потім число в подвійному зірці.
var reconciliationSummaryRe = regexp.MustCompile(
	`^\|\s*` + "`" + `([^` + "`" + `]+)` + "`" + `\s*\|\s*\*\*(\d+)\*\*\s*\|`)

// reconciliationCountRows рахує вердикти по рядках таблиці здатностей.
func reconciliationCountRows(t *testing.T, path string) (map[string]int, int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	counts := map[string]int{}
	total := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if !reconciliationRowRe.MatchString(line) {
			continue
		}
		match := reconciliationVerdictRe.FindStringSubmatch(line)
		if match == nil || !reconciliationVerdicts[match[1]] {
			continue
		}
		counts[match[1]]++
		total++
	}
	return counts, total
}

// reconciliationSummary читає числа з рядків підсумку.
func reconciliationSummary(t *testing.T, path string) map[string]int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	summary := map[string]int{}
	for _, line := range strings.Split(string(raw), "\n") {
		match := reconciliationSummaryRe.FindStringSubmatch(line)
		if match == nil || !reconciliationVerdicts[match[1]] {
			continue
		}
		// Дубль у підсумку означає, що число в ньому не визначене.
		if _, seen := summary[match[1]]; seen {
			t.Errorf("%s states %q twice in its summary: the count is not a "+
				"single claim, so neither occurrence can be checked", path, match[1])
			continue
		}
		summary[match[1]], _ = strconv.Atoi(match[2])
	}
	return summary
}

// reconciliationRegistryFiles збирає всі реєстри звірки в дереві engine.
func reconciliationRegistryFiles(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, dir := range []string{".", "reconciliation"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Каталогу може не бути — це не помилка, а відсутність даних.
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_reconciliation.md") {
				continue
			}
			found = append(found, filepath.Join(dir, entry.Name()))
		}
	}
	if len(found) == 0 {
		t.Fatalf("no reconciliation registry found: this check would pass on an " +
			"empty tree and prove nothing")
	}
	return found
}

// TestEveryRegistrySummaryMatchesItsOwnRows — головна перевірка цього файлу.
//
// Кожен реєстр, який **заявляє** число вердиктів, звіряється з тим, що його
// рядки реально кажуть. Реєстр без заявленого числа пропускається: вимагати
// його тут означало б додавати вимогу, якої сам файл не встановлює.
func TestEveryRegistrySummaryMatchesItsOwnRows(t *testing.T) {
	checked := 0
	for _, path := range reconciliationRegistryFiles(t) {
		summary := reconciliationSummary(t, path)
		if len(summary) == 0 {
			t.Logf("%s states no verdict counts in a summary: nothing to check", path)
			continue
		}
		counts, total := reconciliationCountRows(t, path)
		if total == 0 {
			t.Errorf("%s states %d verdict counts but has no capability rows "+
				"to check them against", path, len(summary))
			continue
		}
		for verdict, claimed := range summary {
			actual, ok := counts[verdict]
			if !ok {
				t.Errorf("%s claims %d rows of %q, and has none at all",
					path, claimed, verdict)
				continue
			}
			if claimed != actual {
				t.Errorf("%s claims %d rows of %q in its summary, and its "+
					"capability table holds %d", path, claimed, verdict, actual)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Log("no registry states verdict counts yet: this check has not run " +
			"against anything")
	}
}

// TestNoRegistryMisspellsAVerdict — глобальна перевірка канону вердиктів.
//
// Тайп `улушшено` замість `улучшено` повторився **вісім разів за одну
// сесію** у восьми різних реєстрах.
//
// Перша версія цієї перевірки була **марною**: вона шукала, чи немає
// відмінності в довжині у слів, які **вже збігаються** з каноном, — тобто
// вона фізично не могла побачити `улушшено`, бо це слово не є канонічним
// і просто ігнорувалося. Перевірка, яка не бачить власної мети, гірша за
// відсутньої.
//
// Правильна форма: будь-який токен у зворотних лапках, який **починається**
// як вердикт, але **не є** вердиктом, — це помилка. Порівняння довжини
// тут зайве: канон перевіряється повним збігом.
func TestNoRegistryMisspellsAVerdict(t *testing.T) {
	prefixes := []string{"улу", "суп", "не п", "непере"}
	for _, path := range reconciliationRegistryFiles(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Рядок, де **поруч** є й канонічний вердикт, — це рядок, який
		// документує виправлення: «було `улушшено`, стало `улучшено`». Такі
		// рядки пропускаються, інакше guard вів би сам на себе.
		lines := strings.Split(string(raw), "\n")
		for _, line := range lines {
			if strings.Contains(line, "`улучшено`") ||
				strings.Contains(line, "`супадає`") ||
				strings.Contains(line, "`не перенесено`") {
				continue
			}
			candidates := reconciliationVerdictLike.FindAllString(line, -1)
			for _, candidate := range candidates {
				token := strings.Trim(candidate, "`")
				looksLike := false
				for _, prefix := range prefixes {
					if strings.HasPrefix(token, prefix) {
						looksLike = true
						break
					}
				}
				if !looksLike {
					continue
				}
				if !reconciliationVerdicts[token] {
					t.Errorf("%s line %d contains %q, which starts like a verdict "+
						"but is not one of супадає / улучшено / не перенесено",
						path, indexOfLine(lines, line)+1, token)
				}
			}
		}
	}
}

func indexOfLine(lines []string, line string) int {
	for index, candidate := range lines {
		if candidate == line {
			return index
		}
	}
	return 0
}

// reconciliationVerdictLike ловить фрагменти в зворотних лапках довжиною
// 6-20 символів — це діапазон, у якому живуть усі три вердикти й їхні
// помилкові варіанти.
var reconciliationVerdictLike = regexp.MustCompile("`[^`\n]{6,20}`")
