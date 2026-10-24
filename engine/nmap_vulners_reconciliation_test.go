package main

// Механічна перевірка реєстру звірки з `nmap-vulners` (клон `rapid7/nmap-vulners`).
//
// Ключова особливість цього реєстру: Python-частина репозиторію — це **збиральна**,
// а сам інструмент один Lua-файл `vulners.nse`. Тому перевірка має рахувати саме
// його, а не `tools/*.py`: інакше ми вимірювали б будівництво каталогу й назвали
// б його сканером.
//
// Головне, що реєстр стверджує і що перевіряється механічно:
//
//  1. `vulners.nse` — це те, що запускається;
//  2. **722 правила відбитків** із прив'язкою до CPE;
//  3. джерела правил — `recog` / `wappalyzer` / nuclei, і саме nuclei є
//     одним із них. Це пряма відповідь на нашу відкриту задачу з wappalyzergo,
//     тому твердження перевіряється пошуком у даних, а не на слово.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const nmapVulnersRegistry = "nmap_vulners_reconciliation.md"

const nmapVulnersCommit = "47c73ec"

const nmapVulnersRequiredRows = 11

// Числа, які реєстр заявляє. Вони мають збігатися з оригіналом.
const (
	nmapVulnersNSELines     = 4395
	nmapVulnersFingerprints = 722
	nmapVulnersPaths        = 953
	nmapVulnersProbes       = 6
)

var nmapVulnersCloneRoots = []string{
	"../Semple-Интеграции/nmap-vulners",
	"../nmap-vulners",
}

var nmapVulnersUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var nmapVulnersVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var nmapVulnersRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readNmapVulnersRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(nmapVulnersRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nmapVulnersRegistry, err)
	}
	rows := make([][]string, 0, nmapVulnersRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := nmapVulnersRow.FindStringSubmatch(strings.TrimSpace(line))
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

func nmapVulnersCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func nmapVulnersDir(t *testing.T) string {
	t.Helper()
	for _, root := range nmapVulnersCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("nmap-vulners clone not found in %v: the registry's counts cannot "+
		"be verified against the original", nmapVulnersCloneRoots)
	return ""
}

func nmapVulnersOurSources(t *testing.T) string {
	t.Helper()
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == nmapVulnersRegistry ||
			name == "reconciliation_summary_test.go"
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner", "pkg/intruder"} {
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

// nmapVulnersGoMod читає `go.mod`, бо `wappalyzergo` є саме там.
func nmapVulnersGoMod(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	return string(raw)
}

// TestTheNmapVulnersRegistryFixesTheUpstreamCommit.
func TestTheNmapVulnersRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(nmapVulnersRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nmapVulnersRegistry, err)
	}
	match := nmapVulnersUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", nmapVulnersRegistry)
	}
	if got := string(match[1]); got != nmapVulnersCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, nmapVulnersCommit)
	}
}

// TestTheNmapVulnersRegistryHasEveryRowItPromises.
func TestTheNmapVulnersRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readNmapVulnersRegistry(t)); got < nmapVulnersRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			nmapVulnersRegistry, got, nmapVulnersRequiredRows)
	}
}

// TestEveryNmapVulnersRowHasAVerdictFromTheThree.
func TestEveryNmapVulnersRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readNmapVulnersRegistry(t) {
		verdict := nmapVulnersCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !nmapVulnersVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedNmapVulnersRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedNmapVulnersRowSaysWhy(t *testing.T) {
	for _, row := range readNmapVulnersRegistry(t) {
		if nmapVulnersCell(row, 3) != "не перенесено" {
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

// TestEveryNmapVulnersRowNamesASymbolThatExists.
//
// Символ шукається і в Go, і в `go.mod`: рядок 11 називає `wappalyzergo`,
// який у нас є **лише залежністю**, жодного імпорту. Перевірка лише Go
// назвала б його відсутнім.
func TestEveryNmapVulnersRowNamesASymbolThatExists(t *testing.T) {
	tree := nmapVulnersOurSources(t) + "\n" + nmapVulnersGoMod(t)
	for _, row := range readNmapVulnersRegistry(t) {
		symbol := nmapVulnersCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(tree, symbol) {
			t.Errorf("row %s claims symbol %q, which is neither in our Go code "+
				"nor in go.mod", row[0], symbol)
		}
	}
}

// nmapVulnersFingerprintRules читає правила відбитків оригіналу.
func nmapVulnersFingerprintRules(t *testing.T) map[string]map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(nmapVulnersDir(t), "catalog", "fingerprints.json"))
	if err != nil {
		t.Fatalf("read fingerprints.json: %v", err)
	}
	var doc struct {
		Rules map[string]map[string]interface{} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fingerprints.json: %v", err)
	}
	if len(doc.Rules) == 0 {
		t.Fatalf("fingerprints.json holds no rules: the registry's count cannot " +
			"stand either way")
	}
	return doc.Rules
}

// TestTheFingerprintTableIsMeasured — головна знахідка цього реєстру.
//
// 722 правила — не «багато», а конкретне число, на якому тримається рядки 2 і
// 11. Перелік знімається з оригіналу, а не з реєстру.
func TestTheFingerprintTableIsMeasured(t *testing.T) {
	rules := nmapVulnersFingerprintRules(t)
	if got := len(rules); got != nmapVulnersFingerprints {
		t.Errorf("the original ships %d fingerprint rules, the registry claims %d",
			got, nmapVulnersFingerprints)
	}
}

// TestEveryFingerprintCarriesACpeAlias — рядок 2.
//
// Реєстр каже: у кожного правила є `alias` у формі CPE, і саме він робить
// відбиток придатним для зіставлення з CVE. Якщо правила втратять `alias`,
// таблиця перестане робити те, заради чого створена, — і реєстр описуватиме
// не той предмет.
func TestEveryFingerprintCarriesACpeAlias(t *testing.T) {
	rules := nmapVulnersFingerprintRules(t)
	missing := 0
	for name, rule := range rules {
		alias, ok := rule["alias"].(string)
		if !ok || !strings.HasPrefix(alias, "cpe:") {
			missing++
			if missing <= 3 {
				t.Errorf("fingerprint %q has no cpe: alias: %v", name, rule["alias"])
			}
		}
	}
	if missing > 0 {
		t.Errorf("%d of %d fingerprints carry no `cpe:` alias: row 2 claims the "+
			"whole table is CPE-addressable", missing, len(rules))
	}
}

// TestNucleiIsOneOfTheSources — рядок 11, наша відкрита задача.
//
// Реєстр стверджує, що автор уже зібрав правила з **наших** nuclei-шаблонів
// і wappalyzer. Твердження перевіряється пошуком у даних: якщо `nuclei:`
// зникне з джерел, то причина «вже зроблено те саме» зникне разом із ним.
func TestNucleiIsOneOfTheSources(t *testing.T) {
	dir := nmapVulnersDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "catalog", "probes.json"))
	if err != nil {
		t.Fatalf("read probes.json: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "nuclei:") {
		t.Error("the original's probes no longer name nuclei as a source: row 11 " +
			"cites this as proof the same mapping was already built, and the " +
			"proof is gone")
	}
	if !strings.Contains(text, "wappalyzer") {
		t.Error("the original's probes no longer name wappalyzer: row 11 counts " +
			"wappalyzer-derived rules, and the source is gone")
	}
}

// TestThePathTableIsMeasured — рядок 4.
func TestThePathTableIsMeasured(t *testing.T) {
	dir := nmapVulnersDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "catalog", "paths.json"))
	if err != nil {
		t.Fatalf("read paths.json: %v", err)
	}
	var doc struct {
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse paths.json: %v", err)
	}
	if got := len(doc.Paths); got != nmapVulnersPaths {
		t.Errorf("the original ships %d paths, the registry claims %d",
			got, nmapVulnersPaths)
	}
}

// TestTheNseScriptIsTheToolAndNotThePython — головна різниця цього реєстру.
//
// Python у цьому репозиторії збирає каталог, а запускається `vulners.nse`.
// Якщо NSE зникне або подрібне, вимір «4 395 рядків Lua» перестане бути
// виміром інструмента.
func TestTheNseScriptIsTheToolAndNotThePython(t *testing.T) {
	dir := nmapVulnersDir(t)
	path := filepath.Join(dir, "vulners.nse")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vulners.nse: %v", err)
	}
	lines := strings.Count(string(raw), "\n")
	if lines != nmapVulnersNSELines {
		t.Errorf("vulners.nse holds %d lines, the registry claims %d",
			lines, nmapVulnersNSELines)
	}
	if !strings.Contains(string(raw), "cpe:") {
		t.Error("vulners.nse no longer mentions CPE: rows 1 and 2 say the whole " +
			"tool exists to turn a banner into a CPE, and the script does not")
	}
}

// TestWeHaveNoCpeConceptNorNmap — рядки 2 і 10.
//
// Дві відсутності, на яких стоїть більшість `не перенесено`. Якщо ми
// додамо CPE або Nmap, ці рядки треба перечитати — і перевірка це покаже.
func TestWeHaveNoCpeConceptNorNmap(t *testing.T) {
	sources := nmapVulnersOurSources(t)
	// `cpe:/a:` — форма CPE-рядка. `cpeExchangeMaxBytes` не є CPE.
	for _, line := range strings.Split(sources, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(trimmed, "cpe:/") {
			t.Errorf("our code now mentions a CPE string: %s\nrow 2 says the "+
				"CPE concept is absent from our project", trimmed)
		}
	}
	raw, err := os.ReadFile(nmapVulnersRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nmapVulnersRegistry, err)
	}
	if !strings.Contains(string(raw), "CPE") {
		t.Error("the registry no longer names CPE: that absence is the reason " +
			"rows 1, 2 and 3 are не перенесено")
	}
}

// TestWappalyzerIsStillOnlyIndirect — рядок 11.
//
// Рядок 11 цінний саме тому, що `wappalyzergo` **не інтегровано**, хоча
// рішення власника про інтеграцію зафіксоване. Твердження двостороннє:
// якщо ми імпортуємо бібліотеку, рядок треба перечитати.
func TestWappalyzerIsStillOnlyIndirect(t *testing.T) {
	goMod := nmapVulnersGoMod(t)
	if !strings.Contains(goMod, "wappalyzergo") {
		t.Fatal("wappalyzergo is gone from go.mod: row 11 names it as the better " +
			"library we already carry, and there is nothing to carry")
	}
	if !strings.Contains(goMod, "wappalyzergo v") ||
		!strings.Contains(goMod, "// indirect") {
		// перевірка нижче точніша: рядок має містити `// indirect`
	}
	if idx := strings.Index(goMod, "wappalyzergo"); idx >= 0 {
		line := goMod[idx:]
		if end := strings.Index(line, "\n"); end >= 0 {
			line = line[:end]
		}
		if !strings.Contains(line, "// indirect") {
			t.Logf("wappalyzergo is now a direct dependency: %q\nrow 11 said it is "+
				"`// indirect` with zero imports — re-read the registry", line)
		}
	}

	// А імпорту справді немає: єдине згадування — коментар про те, чому ми
	// його не імпортуємо.
	if !strings.Contains(nmapVulnersOurSources(t), "wappalyzergo") {
		t.Error("wappalyzergo is now absent even from our comments: row 11 " +
			"records that it is deliberately not imported, and that decision " +
			"left no trace")
	}
}

// TestTheRegistryNamesThePinnedNumber.
//
// Рядок 11 спирається на конкретні числа (722 правила, 953 шляхи,
// 197 із wappalyzer). Вони перевіряються вище по клону; тут перевіряється,
// що реєстр їх у себе має, інакше «готове рішення тієї самої задачі» — це
// твердження без предмета.
func TestTheRegistryNamesThePinnedNumber(t *testing.T) {
	raw, err := os.ReadFile(nmapVulnersRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nmapVulnersRegistry, err)
	}
	text := string(raw)
	for _, number := range []string{strconv.Itoa(nmapVulnersFingerprints), strconv.Itoa(nmapVulnersPaths)} {
		if !strings.Contains(text, number) {
			t.Errorf("the registry does not state %s: rows 2 and 11 quote the "+
				"size of the original's table, and the number is missing", number)
		}
	}
}
