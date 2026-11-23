package main

// Механічна перевірка реєстру звірки з `000pp/Pinkerton`.
//
// Те саме, що `jsfscan_reconciliation_test.go` і `js_analyser_reconciliation_test.go`,
// і з тієї ж причини: попередній порт активного сканера виглядав готовим, зелений
// набір був зеленим, а звірка написана — і три здатності оригіналу виявилися
// відсутніми без жодного рядка «не перенесено».

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const pinkertonRegistry = "pinkerton_reconciliation.md"

// pinkertonUpstreamCommit вимагає зафіксований коміт: таблиця без нього описує
// невідомий стан оригіналу.
var pinkertonUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

// pinkertonVerdicts are the only three allowed answers.
var pinkertonVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var pinkertonRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

// pinkertonRuleLine рахує правила у згенерованому файлі. Вирівнювання полів
// структури робить gofmt, тому пробіли між `id:` і значенням не сталі: пошук
// за фіксованим рядком перестав би працювати після `gofmt -w` — це
// зафіксована пастка в самому реєстрі, і тест не має на неї наступати.
var pinkertonRuleLine = regexp.MustCompile(`id:\s+"pinkerton_`)

func readPinkertonRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(pinkertonRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", pinkertonRegistry, err)
	}
	rows := make([][]string, 0, 8)
	for _, line := range strings.Split(string(raw), "\n") {
		match := pinkertonRow.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		cells := strings.Split(match[2], "|")
		// Основна таблиця має сім колонок: номер, здатність, джерело, вердикт,
		// у нас, підстава, символ. Таблиця прогалин має п'ять, і без цієї
		// перевірки її рядки проходили б як рядки реєстру — з вердиктом у
		// стовпці «причина втрати», яка не є вердиктом.
		if len(cells) < 6 {
			continue
		}
		rows = append(rows, append([]string{match[1]}, cells...))
	}
	return rows
}

func TestPinkertonRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(pinkertonRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", pinkertonRegistry, err)
	}
	if !pinkertonUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit; a table against an unknown commit is a declaration",
			pinkertonRegistry)
	}
}

func TestEveryPinkertonRowHasAVerdictFromTheThree(t *testing.T) {
	rows := readPinkertonRegistry(t)
	if len(rows) == 0 {
		t.Fatalf("%s has no numbered rows at all", pinkertonRegistry)
	}
	for _, row := range rows {
		if len(row) < 4 {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		verdict := strings.Trim(strings.TrimSpace(row[3]), "`")
		if !pinkertonVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено", row[0], verdict)
		}
	}
}

func TestEveryNotPortedPinkertonRowHasAReason(t *testing.T) {
	for _, row := range readPinkertonRegistry(t) {
		if len(row) < 6 {
			t.Errorf("row %s has no reason cell", row[0])
			continue
		}
		if strings.Trim(strings.TrimSpace(row[3]), "`") != "не перенесено" {
			continue
		}
		reason := strings.TrimSpace(row[5])
		if reason == "" || reason == "—" || reason == "-" {
			t.Errorf("row %s is не перенесено with no reason", row[0])
		}
	}
}

// TestTheGeneratedRegistryCarriesEveryUpstreamRule: the registry claims 64, and
// the generated file must carry 64. A number in prose is not a fact.
func TestTheGeneratedRegistryCarriesEveryUpstreamRule(t *testing.T) {
	raw, err := os.ReadFile("pinkerton_rules.go")
	if err != nil {
		t.Fatalf("read the generated registry: %v", err)
	}
	count := len(pinkertonRuleLine.FindAll(raw, -1))
	if count != 64 {
		t.Errorf("the generated registry carries %d rules, the registry claims 64", count)
	}
}

// TestEveryGeneratedPatternIsUsableByGo: `regexp.MustCompile` panics at process
// start on a pattern Go cannot compile, which is how the `(?<=mailto:)` lookbehind
// took the engine down before this test existed.
func TestEveryGeneratedPatternIsUsableByGo(t *testing.T) {
	for _, rule := range pinkertonRules {
		if rule.pattern == nil {
			t.Errorf("rule %s has no pattern", rule.id)
			continue
		}
		if rule.pattern.String() == "" {
			t.Errorf("rule %s compiles to an empty pattern", rule.id)
		}
	}
	if len(pinkertonRules) != 64 {
		t.Errorf("pinkertonRules has %d entries, want 64", len(pinkertonRules))
	}
}

// TestTheLookbehindWasReplacedNotDropped: the Mailto rule originally carried a
// lookbehind RE2 cannot express. The replacement must keep the same reach.
func TestTheLookbehindWasReplacedNotDropped(t *testing.T) {
	for _, rule := range pinkertonRules {
		if rule.id != "pinkerton_mailto" {
			continue
		}
		if strings.Contains(rule.pattern.String(), "(?<") {
			t.Fatalf("the Mailto rule still carries a lookbehind: %s", rule.pattern.String())
		}
		match := rule.pattern.FindStringSubmatch("mailto:security@pravda.ru")
		if match == nil {
			t.Fatalf("the Mailto rule no longer matches its own form: %s", rule.pattern.String())
		}
		// Значення — сам `mailto:`-URL, а не голо адреси: префікс став частиною
		// збігу, бо RE2 не вміє lookbehind, і окремої групи для адреси не
		// введено. Для правила, названого «Mailto», URL є саме тим, що треба
		// відкрити, тому це рішення, а не втрата.
		if !strings.Contains(match[secretValueGroup(rule)], "security@pravda.ru") {
			t.Fatalf("the Mailto value is %q, want it to carry the address",
				match[secretValueGroup(rule)])
		}
		return
	}
	t.Fatal("pinkerton_mailto is missing from the generated registry")
}

// TestEveryUpstreamRuleIsClassifiedByTheRegistry: некласифіковане вважається
// втратою. Кожне правило згенерованого реєстру має бути назване в таблиці
// реєстру, інакше воно є «відсутнім без рядка» — саме той стан, який звірка
// має робити неможливим.
func TestEveryUpstreamRuleIsClassifiedByTheRegistry(t *testing.T) {
	raw, err := os.ReadFile("pinkerton_reconciliation.md")
	if err != nil {
		t.Fatalf("read %s: %v", pinkertonRegistry, err)
	}
	text := string(raw)
	missing := []string{}
	for _, rule := range pinkertonRules {
		name := strings.TrimPrefix(rule.id, "pinkerton_")
		if !strings.Contains(text, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d rules are absent from the registry and count as not ported: %v",
			len(missing), missing[:minInt(len(missing), 8)])
	}
}

// TestTheRegistryStatesTheMeasuredCoverage: реєстр має називати виміряне число.
// Після кампанії з вимірами «48 із 64» і «62 із 64» число в тексті було трьох
// різним, і кожне виглядало виміром, бо жодне не було пов'язане з тестом.
func TestTheRegistryStatesTheMeasuredCoverage(t *testing.T) {
	raw, err := os.ReadFile("pinkerton_reconciliation.md")
	if err != nil {
		t.Fatalf("read %s: %v", pinkertonRegistry, err)
	}
	text := string(raw)
	if !strings.Contains(text, "**64 із 64**") {
		t.Error("the registry does not state the measured 64-of-64 figure")
	}
	// Розподіл «48 під власним id + 16 злиті з нашими» є частиною виміру: без
	// нього 48 у відповіді читаються як втрата, хоста злиття пояснено в тексті
	// і ніким не перевірено.
	if !strings.Contains(text, "| з них злиті з нашими правилами (без дубльованого рядка) | 16 |") {
		t.Error("the registry does not state how many vendor rules are folded into this project's own")
	}
	if !strings.Contains(text, "дублікатів значень у відповіді | **0**") {
		t.Error("the registry does not state that the report carries no duplicate values")
	}
	if strings.Contains(text, "48 із 64") || strings.Contains(text, "46 із 64") {
		t.Error("the registry still states a superseded measurement as current")
	}
}

// TestTheStaleProcessLessonIsRecorded: вимірювання, що дало 48 замість 64, було
// наслідком зупинки рушія за рядком у cmdline, який не збігається з відносним
// шляхом запуску. Якщо цей урок зникне з реєстру, ті самі 48 повернуться і
// знову будуть виглядати як втрата здатностей.
func TestTheStaleProcessLessonIsRecorded(t *testing.T) {
	raw, err := os.ReadFile("pinkerton_reconciliation.md")
	if err != nil {
		t.Fatalf("read %s: %v", pinkertonRegistry, err)
	}
	text := string(raw)
	for _, needle := range []string{"ss -tlnp", "pid=[0-9]+", "старого"} {
		if !strings.Contains(text, needle) {
			t.Errorf("the registry does not record the stale-process lesson (%q is missing)", needle)
		}
	}
}

// TestTheUpstreamRuleCountIsReadFromTheGeneratedFile: 64 є фактом про згенерований
// файл, і реєстр на нього посилається.
func TestTheUpstreamRuleCountIsReadFromTheGeneratedFile(t *testing.T) {
	raw, err := os.ReadFile("pinkerton_rules.go")
	if err != nil {
		t.Fatalf("read the generated registry: %v", err)
	}
	count := len(pinkertonRuleLine.FindAll(raw, -1))
	claimed, err := strconv.Atoi("64")
	if err != nil {
		t.Fatalf("the expected count is unparsable: %v", err)
	}
	if count != claimed {
		t.Errorf("the generated file has %d rules, this test expects %d", count, claimed)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
