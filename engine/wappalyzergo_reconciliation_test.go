package main

// Механічна перевірка реєстру звірки з `projectdiscovery/wappalyzergo`.
//
// Реєстр рахує **покриття відбитків**: скільки технологій оригінал уміє
// назвати і скільки ми називаємо. Тому головна тут перевірка читає
// `fingerprints_data.json` з модульного кешу Go і вимагає, щоб реєстр називав
// **кожен вид доказу** оригіналу.
//
// Чому саме види доказу, а не окремі відбитки. Перелік 7 624 відбитків у
// реєстрі не вмістити й не потрібно: це дані, а не рішення. Але видів
// доказу всього шість (`html`, `js`, `headers`, `cookies`, `icon`,
// `website`), і кожен із них ламається по-різному — іконка в нас відсутня
// повністю, заголовки частково. Тому перевірка тримає саме їх: втрата виду
// доказу в upstream змінить числа реєстру, а втрата одного відбитка — ні.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const wappalyzerRegistry = "wappalyzergo_reconciliation.md"

// wappalyzerVersion — версія з `engine/go.mod:153`. Не вигадується: тест
// звіряє її з модульним кешем, тому заміна версії в `go.mod` робить реєстр
// простроченим, а не мовчки неправильним.
const wappalyzerVersion = "v0.3.0"

var wappalyzerUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40}|v[0-9]+\.[0-9]+\.[0-9]+)` + "`")

var wappalyzerVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var wappalyzerRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const wappalyzerRequiredRows = 19

func readWappalyzerRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(wappalyzerRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", wappalyzerRegistry, err)
	}
	rows := make([][]string, 0, wappalyzerRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := wappalyzerRow.FindStringSubmatch(strings.TrimSpace(line))
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

func wappalyzerCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// wappalyzerDir знаходить вихідники оригіналу в модульному кеші.
//
// Тут SKIP, а не FAIL: відсутність кешу — це відсутність джерела для звірки,
// а не помилка нашого коду. Мовчати не можна, бо тоді числа реєстру перестають
// бути перевіреними нібито, і це має бути видно.
func wappalyzerDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE failed (%v): the registry's counts cannot be "+
			"verified against the original", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)),
		"github.com/projectdiscovery/wappalyzergo@"+wappalyzerVersion)
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		t.Skipf("wappalyzergo %s not found at %s: the registry's counts cannot be "+
			"verified against the original", wappalyzerVersion, dir)
	}
	return dir
}

// wappalyzerFingerprints — розібраний `fingerprints_data.json`.
type wappalyzerFingerprints struct {
	apps map[string]wappalyzerApp
}

// wappalyzerApp — один відбиток. `JS` приходить масивом або об'єктом, тому
// обидва варіанти приймаються, а лічильник змінних рахується через
// `interface{}` — інакше половина відбитків не розбереться.
type wappalyzerApp struct {
	Cats     []int    `json:"cats"`
	HTML     []string `json:"html"`
	Headers  map[string]string
	Cookies  map[string]string
	Icon     string
	Website  string
	JSONKeys []string
}

func wappalyzerParseApps(t *testing.T, dir string) map[string]wappalyzerApp {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "fingerprints_data.json"))
	if err != nil {
		t.Fatalf("read upstream fingerprints: %v", err)
	}
	var document struct {
		Apps map[string]wappalyzerApp `json:"apps"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("fingerprints_data.json is not the expected shape: %v", err)
	}
	if len(document.Apps) == 0 {
		t.Fatalf("the upstream fingerprint set is empty: the registry's headline " +
			"count cannot stand either way")
	}
	return document.Apps
}

// wappalyzerKinds рахує, скільки відбитків мають кожен вид доказу.
//
// Рахування йде по сирому JSON, а не по розібраній структурі: типи полів у
// оригіналі різні (`icon` — рядок, `js` — об'єкт або масив, `headers` —
// об'єкт), і спроба звести їх до одного типу в Go означала б або відкинути
// половину відбитків, або порахувати не ті ключі.
func wappalyzerKinds(t *testing.T, dir string) (kinds map[string]int, jsVars int, total int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "fingerprints_data.json"))
	if err != nil {
		t.Fatalf("read upstream fingerprints: %v", err)
	}
	var document struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("fingerprints_data.json is not the expected shape: %v", err)
	}
	kinds = map[string]int{}
	for _, app := range document.Apps {
		total++
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(app, &fields); err != nil {
			continue
		}
		for key, value := range fields {
			switch key {
			case "cats", "website":
				kinds[key]++
			case "js":
				kinds[key]++
				jsVars += wappalyzerCountKeys(value)
			default:
				kinds[key]++
			}
		}
	}
	return kinds, jsVars, total
}

// wappalyzerCountKeys рахує ключі масиву або об'єкта.
func wappalyzerCountKeys(raw json.RawMessage) int {
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asMap); err == nil {
		return len(asMap)
	}
	var asSlice []json.RawMessage
	if err := json.Unmarshal(raw, &asSlice); err == nil {
		return len(asSlice)
	}
	return 0
}

func wappalyzerSources(t *testing.T) string {
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

// TestWappalyzerRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestWappalyzerRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(wappalyzerRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", wappalyzerRegistry, err)
	}
	if !wappalyzerUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", wappalyzerRegistry)
	}
	if !strings.Contains(string(raw), wappalyzerVersion) {
		t.Errorf("%s does not mention the version %s that go.mod pins",
			wappalyzerRegistry, wappalyzerVersion)
	}
}

// TestTheWappalyzerRegistryHasEveryRowItPromises.
func TestTheWappalyzerRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readWappalyzerRegistry(t)); got < wappalyzerRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			wappalyzerRegistry, got, wappalyzerRequiredRows)
	}
}

// TestEveryWappalyzerRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryWappalyzerRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readWappalyzerRegistry(t) {
		verdict := wappalyzerCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !wappalyzerVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedWappalyzerRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedWappalyzerRowSaysWhy(t *testing.T) {
	for _, row := range readWappalyzerRegistry(t) {
		if wappalyzerCell(row, 3) != "не перенесено" {
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

// TestEveryWappalyzerRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEveryWappalyzerRowNamesASymbolThatExists(t *testing.T) {
	sources := wappalyzerSources(t)
	for _, row := range readWappalyzerRegistry(t) {
		symbol := wappalyzerCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheFingerprintTotalIsMeasuredNotGuessed — головна перевірка.
//
// Реєстр заявляє 7 624 відбитки. Число береться з `fingerprints_data.json`
// модульного кешу, і якщо upstream змінить набір, реєстр зобов'язаний
// змінитися разом із ним.
func TestTheFingerprintTotalIsMeasuredNotGuessed(t *testing.T) {
	dir := wappalyzerDir(t)
	apps := wappalyzerParseApps(t, dir)
	registry, err := os.ReadFile(wappalyzerRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", wappalyzerRegistry, err)
	}
	// Число збирається з розрядною прогалиною, бо реєстр пише «7 624».
	wanted := wappalyzerThousandsSeparator(len(apps))
	if !strings.Contains(string(registry), wanted) {
		t.Errorf("the upstream set holds %d fingerprints, and the registry does "+
			"not mention %s", len(apps), wanted)
	}
}

// TestEveryKindOfEvidenceIsAccountedFor — види доказу не можуть зникнути мовчки.
//
// Це друга половина тієї ж думки. Перелік відбитків — це дані, а види доказу —
// це рішення про те, що саме ми вміємо бачити. Якщо upstream додасть вид
// доказу, реєстр зобов'язаний отримати рядок: інакше з'явиться технологія,
// яку можна визначити, а рядка про неї не буде.
func TestEveryKindOfEvidenceIsAccountedFor(t *testing.T) {
	dir := wappalyzerDir(t)
	kinds, _, _ := wappalyzerKinds(t, dir)
	registry, err := os.ReadFile(wappalyzerRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", wappalyzerRegistry, err)
	}
	text := string(registry)
	for kind := range kinds {
		if !strings.Contains(text, "`"+kind+"`") {
			t.Errorf("upstream fingerprints use evidence kind %q, and the "+
				"registry has no row naming it", kind)
		}
	}
}

// TestTheCategoryCountIsMeasured — категорії теж є даними оригіналу.
func TestTheCategoryCountIsMeasured(t *testing.T) {
	dir := wappalyzerDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "categories_data.json"))
	if err != nil {
		t.Fatalf("read upstream categories: %v", err)
	}
	var categories map[string]json.RawMessage
	if err := json.Unmarshal(raw, &categories); err != nil {
		t.Fatalf("categories_data.json is not a JSON object: %v", err)
	}
	if len(categories) == 0 {
		t.Fatalf("the upstream category set is empty: the registry's claim " +
			"about it cannot stand either way")
	}
	registry, err := os.ReadFile(wappalyzerRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", wappalyzerRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(len(categories))) {
		t.Errorf("the upstream set holds %d categories, and the registry does "+
			"not mention that number", len(categories))
	}
}

// TestTheJsVariableCountIsMeasured — 5 480 JS-змінних є найбільшою прогалиною.
//
// Окремою перевіркою, бо це найбільший вид доказу за обсягом і найдорожчий за
// втратою: якщо ми перенесемо `wappalyzergo`, цей рядок зобов'язаний змінити
// вердикт на `улучшено` разом із рештою JS-рядків.
func TestTheJsVariableCountIsMeasured(t *testing.T) {
	dir := wappalyzerDir(t)
	_, jsVars, _ := wappalyzerKinds(t, dir)
	if jsVars == 0 {
		t.Skipf("upstream exposes no js keys now: the registry's js row needs a look")
	}
	registry, err := os.ReadFile(wappalyzerRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", wappalyzerRegistry, err)
	}
	wanted := wappalyzerThousandsSeparator(jsVars)
	if !strings.Contains(string(registry), wanted) {
		t.Errorf("upstream exposes %d js variables, and the registry does not "+
			"mention %s", jsVars, wanted)
	}
}

// TestOurSignatureCountIsMeasuredFromOurCode — число «22» перевірюється з коду.
//
// Реєстр каже, що ми називаємо 22 технології з 7 624. Число 22 рахується
// тут з `osint_transform_entities.go`, а не береться зі слів: якщо хтось додасть
// підпис у коді й не поправить реєстр, розходження стане видимим.
func TestOurSignatureCountIsMeasuredFromOurCode(t *testing.T) {
	raw, err := os.ReadFile("osint_transform_entities.go")
	if err != nil {
		t.Fatalf("read our own probe: %v", err)
	}
	source := string(raw)
	for _, table := range []string{"technologyHeaderSignatures", "technologyCookieSignatures"} {
		index := strings.Index(source, "var "+table+" = []technologySignature{")
		if index < 0 {
			t.Errorf("%s is gone from our code: the registry's count needs a look", table)
			continue
		}
		block := source[index:]
		if end := strings.Index(block, "\n}"); end > 0 {
			block = block[:end]
		}
		count := strings.Count(block, "name:")
		if count == 0 {
			t.Errorf("%s declares no signatures: the registry's count needs a look", table)
		}
	}
}

// wappalyzerThousandsSeparator форматує число як у реєстрі: «7 624».
// Розрядка звичайним пробілом, а не неразривним, бо реєстр пише саме так і
// пошук має бути тим самим.
func wappalyzerThousandsSeparator(value int) string {
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
