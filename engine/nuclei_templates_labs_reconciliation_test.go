package main

// Механічна перевірка реєстру звірки з `projectdiscovery/nuclei-templates-labs`.
//
// Це **не шаблони і не сканер** — це лабораторні стенди: 23 `docker-compose.yml`,
// 3 `Dockerfile`, вразливі застосунки й 26 `README` з ручними кроками
// експлуатації. Уся здатність репозиторію тут — «дати живу ціль, на якій
// шаблон має спрацювати».
//
// Тому перевірка мірить саме це:
//
//  1. предмет звірки — коміт зафіксовано;
//  2. **наявність застосунків** — `docker-compose.yml` рахується в клону.
//     Якщо upstream зникне з лабораторії, реєстр описуватиме не той предмет;
//  3. **наявність CVE-стендів** — каталоги `CVE-*`;
//  4. наші символи;
//  5. рядок 10: реєстр мусить сказати, що ми **не проходимо** кроки
//     експлуатації. Якщо це зникне з тексту, «у нас є стенди» почне
//     читатися як повне покриття — а це те саме неправдиве прочитання,
//     яке власник вже відкидав для headless-шаблонів.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const nucleiLabsRegistry = "nuclei_templates_labs_reconciliation.md"

const nucleiLabsCommit = "144ee9f"

const nucleiLabsRequiredRows = 10

var nucleiLabsCloneRoots = []string{
	"../Semple-Интеграции/nuclei-templates-labs",
	"../nuclei-templates-labs",
}

var nucleiLabsUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var nucleiLabsVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var nucleiLabsRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readNucleiLabsRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(nucleiLabsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiLabsRegistry, err)
	}
	rows := make([][]string, 0, nucleiLabsRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := nucleiLabsRow.FindStringSubmatch(strings.TrimSpace(line))
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

func nucleiLabsCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func nucleiLabsDir(t *testing.T) string {
	t.Helper()
	for _, root := range nucleiLabsCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("nuclei-templates-labs clone not found in %v: the registry's "+
		"counts cannot be verified against the original", nucleiLabsCloneRoots)
	return ""
}

func nucleiLabsOurSources(t *testing.T) string {
	t.Helper()
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == nucleiLabsRegistry ||
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

// TestTheNucleiLabsRegistryFixesTheUpstreamCommit.
func TestTheNucleiLabsRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(nucleiLabsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiLabsRegistry, err)
	}
	match := nucleiLabsUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", nucleiLabsRegistry)
	}
	if got := string(match[1]); got != nucleiLabsCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, nucleiLabsCommit)
	}
}

// TestTheNucleiLabsRegistryHasEveryRowItPromises.
func TestTheNucleiLabsRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readNucleiLabsRegistry(t)); got < nucleiLabsRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			nucleiLabsRegistry, got, nucleiLabsRequiredRows)
	}
}

// TestEveryNucleiLabsRowHasAVerdictFromTheThree.
func TestEveryNucleiLabsRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readNucleiLabsRegistry(t) {
		verdict := nucleiLabsCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !nucleiLabsVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedNucleiLabsRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedNucleiLabsRowSaysWhy(t *testing.T) {
	for _, row := range readNucleiLabsRegistry(t) {
		if nucleiLabsCell(row, 3) != "не перенесено" {
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

// TestEveryNucleiLabsRowNamesASymbolThatExists.
func TestEveryNucleiLabsRowNamesASymbolThatExists(t *testing.T) {
	sources := nucleiLabsOurSources(t)
	for _, row := range readNucleiLabsRegistry(t) {
		symbol := nucleiLabsCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in our tree", row[0], symbol)
		}
	}
}

// nucleiLabsCountCompose рахує `docker-compose.yml` / `.yaml` у вкладених
// каталогах.
//
// Через `filepath.Walk`, а не `filepath.Glob`: glob у Go **не підтримує
// `**`**, і шаблон `**/docker-compose.y*ml` просто не знайшов би нічого.
// Перша версія цієї перевірки через glob падала на повністю коректному клоні.
func nucleiLabsCountCompose(t *testing.T, dir string) int {
	t.Helper()
	count := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.HasPrefix(name, "docker-compose.") &&
			(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return count
}

// TestTheLabsStillShipVulnerableApps — головна перевірка цього реєстру.
//
// Реєстр каже: це **не** корпус шаблонів, а лабораторія з вразливими
// застосунками. Твердження вимірюється: якщо compose-файлів немає, то перед
// нами вже не лабораторія, і весь реєстр описує інший предмет.
func TestTheLabsStillShipVulnerableApps(t *testing.T) {
	dir := nucleiLabsDir(t)
	composes := nucleiLabsCountCompose(t, dir)
	if composes == 0 {
		t.Fatalf("no docker-compose files under %s: the registry calls this a "+
			"lab of vulnerable applications, and there is nothing to launch", dir)
	}
	if composes < 20 {
		t.Errorf("the original ships %d compose files, while the registry calls "+
			"it a lab with %d: the lab shrank", composes, 23)
	}
}

// TestTheCveStandsStillExist.
//
// 10 каталогів `CVE-*` — це і є цінність репозиторію: готовий список того,
// що варто перевірити. Перелік звіряється з клоном, а не з реєстру.
func TestTheCveStandsStillExist(t *testing.T) {
	dir := nucleiLabsDir(t)
	var names []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && strings.HasPrefix(info.Name(), "CVE-") {
			names = append(names, info.Name())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if len(names) != 10 {
		t.Errorf("the original ships %d CVE stands (%v), the registry claims 10",
			len(names), names)
	}
}

// TestTheRegistrySaysItIsALabAndNotACorpus.
//
// Найважливіше прочитання цього реєстру: файл лежить у каталозі
// `nuclei-templates-*`, і без прямої фрази читач візьме його за ще один
// корпус шаблонів.
func TestTheRegistrySaysItIsALabAndNotACorpus(t *testing.T) {
	raw, err := os.ReadFile(nucleiLabsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiLabsRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "лаборатор") {
		t.Error("the registry never calls this a lab: a reader would take it " +
			"for one more template corpus")
	}
	if !strings.Contains(text, "не шаблони") && !strings.Contains(text, "не корпус") {
		t.Error("the registry does not say it is NOT a template corpus: that " +
			"is the whole difference from every other nuclei repository here")
	}
}

// TestTheMissingExploitationStepsIsStillNamed — рядок 10.
//
// Реєстр мусить визнати, що ми **не проходимо** кроки експлуатації з
// `README`. У нас є виміряна відповідь на «чи виконався шаблон», і немає
// автоматизованої відповіді на «чи зрізало він саме ту вразливість».
//
// Якщо ця різниця зникне з тексту, «у нас є стенди» почне читатися як
// повне покриття.
func TestTheMissingExploitationStepsIsStillNamed(t *testing.T) {
	raw, err := os.ReadFile(nucleiLabsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiLabsRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "exploitation steps") {
		t.Error("the registry never mentions the `Exploitation Steps` section " +
			"of the original's READMEs: that manual gap is the one honest " +
			"limit of this repository, and it must stay named")
	}
	if !strings.Contains(text, "не проходить") && !strings.Contains(text, "не проходять") {
		t.Error("the registry does not say we do NOT walk the exploitation " +
			"steps: without it, row 1's `улучшено` reads as full coverage")
	}
}

// TestOurStandIsStillTheFastOneAndNotTheApp.
//
// Рядок 1 тримається на тому, що наш стенд — `httptest`, а не піднятий
// застосунок. Якщо `httptest.NewServer` зникне з наших тестів, вердикт
// «у нас є жива ціль» треба перечитати.
func TestOurStandIsStillTheFastOneAndNotTheApp(t *testing.T) {
	if !strings.Contains(nucleiLabsOurSources(t), "httptest.NewServer") {
		t.Error("httptest.NewServer is gone from our tests: row 1 claims our " +
			"stand is a controlled server rather than a deployed app, and " +
			"there is no such stand any more")
	}
}
