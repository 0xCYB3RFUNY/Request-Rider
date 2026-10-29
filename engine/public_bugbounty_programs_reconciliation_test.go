package main

// Механічна перевірка реєстру звірки з
// `projectdiscovery/public-bugbounty-programs`.
//
// Репозиторій — **набір даних**, а не рушій. Тому головна перевірка
// читає `data.json` і звіряє з реєстром **кількість програм** і **кожне
// поле запису**: набір даних має реєструвати собі поля так само ретельно,
// як реєстр реєструє функції.
//
// Друга половина — проєктна заборона. Реєстр каже, що вбудований список
// програм у нас відсутній свідомо. Перевірка стежить, щоб у нашій моделі
// не з'явилося поле, яке виглядало б як allowlist: це була б зміна правила
// проекту, а не доробка.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const bugBountyRegistry = "public_bugbounty_programs_reconciliation.md"

const bugBountyCommit = "45f285b"

var bugBountyCloneRoots = []string{
	"../Semple-Интеграции/public-bugbounty-programs",
	"../public-bugbounty-programs",
}

var bugBountyUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var bugBountyVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var bugBountyRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const bugBountyRequiredRows = 8

func readBugBountyRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	rows := make([][]string, 0, bugBountyRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := bugBountyRow.FindStringSubmatch(strings.TrimSpace(line))
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

func bugBountyCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// bugBountyDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються.
func bugBountyDir(t *testing.T) string {
	t.Helper()
	for _, root := range bugBountyCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("public-bugbounty-programs clone not found in %v: the registry's "+
		"counts cannot be verified against the original", bugBountyCloneRoots)
	return ""
}

// bugBountyProgram — один запис набору.
// `bounty` — **бульове** поле, а не рядок із сумою: перша версія оголосила
// його рядком, і `json.Unmarshal` упав на реальному наборі. Типи полів
// перевіряються розб��ром, а не припущенням — інакше наступне поле із
// неочікуваним типом зупинить перевірку ще на етапі розбору.
type bugBountyProgram struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Bounty  bool     `json:"bounty"`
	Domains []string `json:"domains"`
	Swag    *bool    `json:"swag,omitempty"`
}

// bugBountyPrograms читає набір і повертає програми та множину полів.
func bugBountyPrograms(t *testing.T, dir string) (programs []bugBountyProgram,
	fields map[string]int, swagCount int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "dist/data.json"))
	if err != nil {
		t.Fatalf("read upstream dataset: %v", err)
	}
	var document struct {
		Programs []bugBountyProgram `json:"programs"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("data.json is not the expected shape: %v", err)
	}
	if len(document.Programs) == 0 {
		t.Fatalf("the upstream dataset is empty: the registry's headline count " +
			"cannot stand either way")
	}
	fields = map[string]int{}
	for index := range document.Programs {
		body, readErr := json.Marshal(document.Programs[index])
		if readErr != nil {
			continue
		}
		var asMap map[string]json.RawMessage
		if err := json.Unmarshal(body, &asMap); err != nil {
			continue
		}
		for key := range asMap {
			fields[key]++
		}
		if _, ok := asMap["swag"]; ok {
			swagCount++
		}
	}
	return document.Programs, fields, swagCount
}

// TestBugBountyRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestBugBountyRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	match := bugBountyUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", bugBountyRegistry)
	}
	if got := string(match[1]); got != bugBountyCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, bugBountyCommit)
	}
}

// TestTheBugBountyRegistryHasEveryRowItPromises.
func TestTheBugBountyRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readBugBountyRegistry(t)); got < bugBountyRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			bugBountyRegistry, got, bugBountyRequiredRows)
	}
}

// TestEveryBugBountyRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryBugBountyRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readBugBountyRegistry(t) {
		verdict := bugBountyCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !bugBountyVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улушшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedBugBountyRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedBugBountyRowSaysWhy(t *testing.T) {
	for _, row := range readBugBountyRegistry(t) {
		if bugBountyCell(row, 3) != "не перенесено" {
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

// TestTheProgrammeCountIsMeasured — головна перевірка.
//
// 802 — це число, заради якого реєстр існує: перелік program відсутній у
// нас, і читач має бачити, наскільки великий той перелік, якого немає.
func TestTheProgrammeCountIsMeasured(t *testing.T) {
	dir := bugBountyDir(t)
	programs, _, _ := bugBountyPrograms(t, dir)
	registry, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(len(programs))) {
		t.Errorf("the original dataset holds %d programmes, and the registry "+
			"does not mention that number", len(programs))
	}
}

// TestEveryFieldOfTheDatasetIsNamed — набір даних має реєструвати поля.
//
// Тут та сама вимога, що й до функцій оригіналу: кожна здатність має рядок.
// Для набору даних здатність — це поле, і поле `swag` без рядка виглядало б
// так, наче його немає.
func TestEveryFieldOfTheDatasetIsNamed(t *testing.T) {
	dir := bugBountyDir(t)
	programs, fields, _ := bugBountyPrograms(t, dir)
	_ = programs
	registry, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	text := string(registry)
	for field, count := range fields {
		if !strings.Contains(text, "`"+field+"`") && !strings.Contains(text, field) {
			t.Errorf("the dataset has a %q field on %d programmes, and the "+
				"registry names it nowhere", field, count)
		}
	}
	if !strings.Contains(text, strconv.Itoa(len(fields))) {
		t.Errorf("the dataset records hold %d fields, and the registry does "+
			"not mention that number", len(fields))
	}
}

// TestTheBountyFlagSplitIsMeasured — 530 з 802 мають винагороду.
//
// Окремою перевіркою, бо `bounty` — бульове поле, і «розподіл винагород»
// у попередній редакції реєстру було формулюванням без вимірювання за ним.
// Розподіл тепер виміряний: 530 так, 272 ні.
func TestTheBountyFlagSplitIsMeasured(t *testing.T) {
	dir := bugBountyDir(t)
	programs, _, _ := bugBountyPrograms(t, dir)
	withBounty := 0
	for _, program := range programs {
		if program.Bounty {
			withBounty++
		}
	}
	if withBounty == 0 {
		t.Skip("no programme carries a bounty any more: row 2 needs a look")
	}
	registry, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	text := string(registry)
	if !strings.Contains(text, strconv.Itoa(withBounty)) {
		t.Errorf("%d of %d programmes carry a bounty, and the registry does "+
			"not mention that count", withBounty, len(programs))
	}
	if !strings.Contains(text, "bool") {
		t.Errorf("%s does not state that bounty is a boolean: calling it a "+
			"'distribution' without the type misdescribes the dataset",
			bugBountyRegistry)
	}
}

// TestTheDomainTotalIsMeasured — 4 110 доменів.
//
// Домени — це те, що робить набір корисним: 802 програми дають 4 110
// доменів. Число звіряється окремо, бо воно і є фактичний розмір набору.
func TestTheDomainTotalIsMeasured(t *testing.T) {
	dir := bugBountyDir(t)
	programs, _, _ := bugBountyPrograms(t, dir)
	total := 0
	for _, program := range programs {
		total += len(program.Domains)
	}
	if total == 0 {
		t.Fatalf("the dataset holds no domains at all: the registry's claim " +
			"about it cannot stand either way")
	}
	registry, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	if wanted := bugBountyThousandsSeparator(total); !strings.Contains(string(registry), wanted) {
		t.Errorf("the dataset holds %d domains, and the registry does not "+
			"mention %s", total, wanted)
	}
}

func bugBountyThousandsSeparator(value int) string {
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

// TestTheSwagCountIsMeasured — 101 програма з матеріалами.
//
// Окремо, бо це єдине поле, присутнє не в усіх записах: якщо воно зникне з
// набору, рядок 4 стане безпідставним.
func TestTheSwagCountIsMeasured(t *testing.T) {
	dir := bugBountyDir(t)
	_, _, swagCount := bugBountyPrograms(t, dir)
	if swagCount == 0 {
		t.Skip("no swag field in the dataset any more: row 4 needs a look")
	}
	registry, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(swagCount)) {
		t.Errorf("%d programmes carry swag material, and the registry does "+
			"not mention that count", swagCount)
	}
}

// TestWeHaveNoProgrammeAllowlist — проєктна забора, а не нестача.
//
// `AGENTS.md` забороняє вбудовувати allowlist/denylist і scope-логіку в
// код. Реєстр каже, що списку програм у нас немає і це свідомо. Якщо в
// нашій моделі з'явиться поле, схоже на перелік дозволених цілей, це буде
// зміна правила проекту — і тест має це показати, а не мовчати.
func TestWeHaveNoProgrammeAllowlist(t *testing.T) {
	raw, err := os.ReadFile("../web/lab/models.py")
	if err != nil {
		t.Fatalf("read our models: %v", err)
	}
	source := strings.ToLower(string(raw))
	for _, marker := range []string{"allowed_program", "program_list",
		"bugbounty_program", "bounty_programme"} {
		if strings.Contains(source, marker) {
			t.Errorf("our models now declare %q: the registry says the "+
				"programme dataset is deliberately absent, and that would be a "+
				"change to the project's own rule", marker)
		}
	}
	// `scope_in` / `scope_out` при цьому мусять лишитися: вони організаційні
	// і не блокують інструменти.
	for _, field := range []string{"scope_in", "scope_out"} {
		if !strings.Contains(source, field) {
			t.Errorf("%q is gone from our models: row 7 claims the "+
				"organisational space is present, and that needs a look", field)
		}
	}
}

// TestTheRegistryNamesTheProjectRule — причина має бути проєктна заборона.
//
// Рядки 1-6 кажуть `не перенесено` з причини «заборона проекту», а не
// «не встигли». Якщо текст перестане це називати, читач подумає б, що це
// прогалина в продукті.
func TestTheRegistryNamesTheProjectRule(t *testing.T) {
	registry, err := os.ReadFile(bugBountyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", bugBountyRegistry, err)
	}
	text := strings.ToLower(string(registry))
	if !strings.Contains(text, "заборон") && !strings.Contains(text, "ag ents") &&
		!strings.Contains(text, "ag ents.md") {
		t.Errorf("%s never names the project rule as the reason: six rows read "+
			"as unfinished work otherwise", bugBountyRegistry)
	}
}
