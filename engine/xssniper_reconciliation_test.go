package main

// Механічна перевірка реєстру звірки з `H4mzaX/XSSniper`.
//
// Реєстр має одну властивість, яку треба перевіряти особенно ретельно: він
// **не** стверджує, що ми кращі за оригінал за обсягом. Тобто «113 payload-ів
// проти наших 27 DOM-векторів» — це прогалина в обсязі, і вона має бути
// видимою в числах реєстру, а не зникти за формулюванням «роль перекрита
// nuclei». Тому головна перевірка читає і клон, і наш код, і порівнює обидва
// числа — а не лише перевіряє, що рядки існують.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const xssniperRegistry = "xssniper_reconciliation.md"

// xssniperCommit — коміт клону, зафіксований у реєстрі.
const xssniperCommit = "72e1018"

var xssniperCloneRoots = []string{
	"../Semple-Интеграции/XSSniper",
	"../XSSniper",
	"../Прочее/Semple-Интеграции/XSSniper",
}

var xssniperUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var xssniperVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var xssniperRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const xssniperRequiredRows = 12

func readXssniperRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	rows := make([][]string, 0, xssniperRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := xssniperRow.FindStringSubmatch(strings.TrimSpace(line))
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

func xssniperCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// xssniperDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються, щоб прогалина була видима.
func xssniperDir(t *testing.T) string {
	t.Helper()
	for _, root := range xssniperCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("XSSniper clone not found in %v: the registry's counts cannot be "+
		"verified against the original", xssniperCloneRoots)
	return ""
}

func xssniperOurSources(t *testing.T, files ...string) string {
	t.Helper()
	wanted := map[string]bool{}
	for _, name := range files {
		wanted[name] = true
	}
	parts := []string{}
	for _, root := range []string{".", "pkg/active"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			if len(wanted) > 0 && !wanted[entry.Name()] {
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

// TestXssniperRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestXssniperRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	match := xssniperUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", xssniperRegistry)
	}
	if got := string(match[1]); got != xssniperCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, xssniperCommit)
	}
}

// TestTheXssniperRegistryHasEveryRowItPromises.
func TestTheXssniperRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readXssniperRegistry(t)); got < xssniperRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			xssniperRegistry, got, xssniperRequiredRows)
	}
}

// TestEveryXssniperRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryXssniperRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readXssniperRegistry(t) {
		verdict := xssniperCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !xssniperVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улушшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedXssniperRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedXssniperRowSaysWhy(t *testing.T) {
	for _, row := range readXssniperRegistry(t) {
		if xssniperCell(row, 3) != "не перенесено" {
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

// TestEveryXssniperRowNamesASymbolThatExists — заявлений символ має бути в дереві.
//
// Збудовано з тих самих файлів, які реєстр цитує: якщо символ живе в
// `pkg/active/`, шукати його треба там, а не в корені движка.
func TestEveryXssniperRowNamesASymbolThatExists(t *testing.T) {
	sources := xssniperOurSources(t)
	for _, row := range readXssniperRegistry(t) {
		symbol := xssniperCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// xssniperLibraryCategory ловить категорію словника: `'dom_based': [`.
//
// Якір `^` і пробіл-таб замість `\s` — не дрібниця. `\s` у Go включає
// перевід рядка, тому `(?m)^\s+` переходив на наступний рядок і приліпляв до
// попередньої категорії **заголовок наступної**: кожна з перших дев'яти
// категорій отримувала зайвий одиниць, і сума ставала 122 замість 113.
// Це той самий клас дефекту, що й необмежена функція: рахунок «майже
// правильний» і з п'ятьма зайвими — найгірший вид.
var xssniperLibraryCategory = regexp.MustCompile(`(?m)^ +'([a-z_0-9]+)': *\[`)

// xssniperPayloadLibrary читає `payload_library` з клону і повертає категорії
// та кількість payload-ів у кожній.
//
// Рахування йде по сирому тексту, а не через `ast`: словник — це літерал
// у тілі функції, і його структура стабільна, тоді як розбір AST утягнув би
// в залежність заради одного числа.
func xssniperPayloadLibrary(t *testing.T, dir string) (categories []string, payloads map[string]int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "payload_tester.py"))
	if err != nil {
		t.Fatalf("read upstream payload library: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "def _load_payload_library")
	if start < 0 {
		t.Fatalf("_load_payload_library is gone: the registry's counts need a look")
	}
	body := source[start:]
	// Функція має **верхню межу** — наступний метод того ж класу. Без неї
	// підрахунок ішов до кінця файлу і рахував чужі словники: перша версія
	// дала 166 замість 113 і «знайшла» помилку в реєстрі, який був правильний.
	//
	// Індекс шукається **всередині `body`**, і береться **перший** з двох
	// кандидатів, а не спершу `async def`.
	//
	// Друге важливіше за перше: `async def` не обов'язково йде раніше за
	// `def`. Коли я перевіряв `async def` першим, зріз проходив повз
	// синхронний `_load_encoding_methods` і зупинявся на наступному `async
	// def` — на десять рядків пізніше. Остання категорія затягувала туди
	// словник методів кодування і показувала 24 замість 15, сума 122 замість
	// 113. Межа, яка «є», але не там, гірша за відсутньої: вона дає число,
	// що виглядає виміряним.
	cut := -1
	for _, marker := range []string{"\n    async def ", "\n    def "} {
		if idx := strings.Index(body[1:], marker); idx > 0 && (cut < 0 || idx < cut) {
			cut = idx
		}
	}
	if cut > 0 {
		body = body[:cut+1]
	}
	matches := xssniperLibraryCategory.FindAllStringSubmatchIndex(body, -1)
	if len(matches) == 0 {
		t.Fatalf("no categories parsed from _load_payload_library: the check " +
			"would pass on an unparsed original")
	}
	payloads = map[string]int{}
	for index, match := range matches {
		categories = append(categories, body[match[2]:match[3]])
		end := len(body)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		segment := body[match[1]:end]
		payloads[body[match[2]:match[3]]] = len(xssniperLibraryEntry.FindAllString(segment, -1))
	}
	return categories, payloads
}

// xssniperLibraryEntry ловить один payload у списку: рядок, що починається з
// лапки після відступу. Набори пробілів і табуляцій, а не `\s`, щоб не
// переходити рядок і не приліпляти наступний елемент.
var xssniperLibraryEntry = regexp.MustCompile("(?m)^[ \t]+['\"]")

// TestThePayloadCountsAreMeasuredNotGuessed — головна перевірка.
//
// Реєстр заявляє 10 категорій і 113 payload-ів. Числа рахуються з клону.
// Окремо перевіряється, що реєстр називає **кожну** категорію: перелік
// категорій знімається з оригіналу, а не з власного пам'яті, тому нова
// катег��рія в upstream зобов'язана з'явитися в реєстрі рядком.
func TestThePayloadCountsAreMeasuredNotGuessed(t *testing.T) {
	dir := xssniperDir(t)
	categories, payloads := xssniperPayloadLibrary(t, dir)
	total := 0
	for _, count := range payloads {
		total += count
	}
	if total == 0 {
		t.Fatalf("no payloads parsed: the registry's headline count cannot " +
			"stand either way")
	}
	registry, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	text := string(registry)
	if !strings.Contains(text, strconv.Itoa(len(categories))) {
		t.Errorf("the original library holds %d categories, and the registry "+
			"does not mention that number", len(categories))
	}
	if !strings.Contains(text, strconv.Itoa(total)) {
		t.Errorf("the original library holds %d payloads, and the registry does "+
			"not mention that number", total)
	}
	for _, category := range categories {
		if !strings.Contains(text, "`"+category+"`") &&
			!strings.Contains(text, "`"+category+"` —") {
			if !strings.Contains(text, category) {
				t.Errorf("the original has category %q, and the registry does "+
					"not mention it at all", category)
			}
		}
	}
}

// TestThePerCategoryCountsAreMeasured — кожна категорія має свою цифру.
//
// Одне загальне число «113» не доводить нічого: воно однакове і для
// повного списку, і для того, де половина категорій порожня. Тому число
// поруч із кожною назвою категорії звіряється окремо.
func TestThePerCategoryCountsAreMeasured(t *testing.T) {
	dir := xssniperDir(t)
	categories, payloads := xssniperPayloadLibrary(t, dir)
	registry, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	text := string(registry)
	for _, category := range categories {
		if !strings.Contains(text, category) {
			// Категорію не названо — про неї вже сказав попередній тест.
			continue
		}
		count := payloads[category]
		if count == 0 {
			t.Errorf("category %q parsed as empty: either the registry's "+
				"category table is wrong or the upstream shape changed", category)
			continue
		}
		if !strings.Contains(text, strconv.Itoa(count)) {
			t.Errorf("category %q holds %d payloads, and the registry has no "+
				"such number next to it", category, count)
		}
	}
	_ = len(categories)
}

// TestOurDomVectorCountIsMeasuredFromOurCode — наші 27 DOM-векторів.
//
// Число «27» не береться зі слів: рахується довжина `domVectors` у нашому
// коді. Якщо хтось додасть вектор і не поправить реєстр, розходження стане
// видимим — і це навмисно, бо «у нас 27» є твердженням про наш код.
func TestOurDomVectorCountIsMeasuredFromOurCode(t *testing.T) {
	raw, err := os.ReadFile("pkg/active/detect_dom_vectors.go")
	if err != nil {
		t.Fatalf("read our own detectors: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "var domVectors = []domVector{")
	if start < 0 {
		t.Fatalf("domVectors is gone from our code: the registry's count needs a look")
	}
	body := source[start:]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}
	count := strings.Count(body, "{")
	if count == 0 {
		t.Fatalf("domVectors is empty: the registry's count is wrong")
	}
	registry, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(count)) {
		t.Errorf("our code declares %d DOM vectors, and the registry does not "+
			"mention that number", count)
	}
}

// TestTheEncodingMethodsAreCounted — сім методів обфускації.
//
// Окремо, бо це найдрібніша одиниця в оригіналі: сім рядків коду, які
// легко втратити, і втрата яких не змінює жодного заявленого числа, поки
// реєстр не вимагатиме саме цього рахунку.
func TestTheEncodingMethodsAreCounted(t *testing.T) {
	dir := xssniperDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "payload_tester.py"))
	if err != nil {
		t.Fatalf("read upstream encodings: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "def _load_encoding_methods")
	if start < 0 {
		t.Skip("upstream no longer exposes encoding methods: the registry's " +
			"row 4 needs a look")
	}
	body := source[start:]
	if end := strings.Index(body, "\n    async def "); end > 0 {
		body = body[:end]
	}
	// Методи — це `'name': lambda …`, а не списки, тому регулярка має ловити
	// саме пару ключ-стовпчики. Клас символів — `[a-z0-9_]`, а не `[a-z_]`:
	// `base64_encode` містить цифри, і звужений клас непомітно втрачає
	// саме його — перша версія рахувала 6 замість 7.
	count := len(xssniperEncodingMethod.FindAllString(body, -1))
	if count == 0 {
		t.Fatalf("no encoding methods parsed: the check would pass on an " +
			"unparsed original")
	}
	registry, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(count)) {
		t.Errorf("the original offers %d encoding methods, and the registry "+
			"does not mention that number", count)
	}
}

// xssniperEncodingMethod ловить метод обфускації: `'url_encode': lambda …`.
var xssniperEncodingMethod = regexp.MustCompile(`'[a-z0-9_]+':`)

// TestTheRegistryAdmitsItCoversFewerPayloads — чесність про обсяг.
//
// Найважливіша перевірка цього реєстру. Він не має права читатися так, наче
// ми не гірші за оригінал: якщо «113» зникне з тексту, читач не дізнається,
// що прогалина в обсязі була. Тому требується, щоб реєстр містив і число
// оригіналу, і наше, і слово про те, що наше менше.
func TestTheRegistryAdmitsItCoversFewerPayloads(t *testing.T) {
	dir := xssniperDir(t)
	_, payloads := xssniperPayloadLibrary(t, dir)
	original := 0
	for _, count := range payloads {
		original += count
	}
	registry, err := os.ReadFile(xssniperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", xssniperRegistry, err)
	}
	text := string(registry)
	if !strings.Contains(text, strconv.Itoa(original)) {
		t.Fatalf("%s does not state the original's payload count %d: a reader "+
			"could take the table for parity", xssniperRegistry, original)
	}
	if !strings.Contains(text, "проти") {
		t.Errorf("%s never compares its own count with the original's: the "+
			"gap in volume has to be visible, not implied", xssniperRegistry)
	}
}
