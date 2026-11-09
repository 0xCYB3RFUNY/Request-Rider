package main

// Механічна перевірка реєстру звірки з `vulncov`.
//
// vulncov — **вимірювач того, чи виконують тести вразливий код**, а не сканер.
// Це найвідмінніша категорія з усіх 27 клонів, і перевірка має три шари:
//
//  1. предмет звірки — коміт зафіксовано;
//  2. **наш код теж читається з `web/`**, бо `POSTGRES_TEST_TEMPLATE` і
//     `ai_agent` живуть у Django, а не в Go;
//  3. головне твердження реєстру: у нас **немає** Semgrep, coverage-збору й
//     `venv` для чужого коду. Якщо будь-що з цього з'явиться — сім
//     `не перенесено` стануть частково хибними, і це треба побачити.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const vulncovRegistry = "vulncov_reconciliation.md"

const vulncovCommit = "2989b67"

const vulncovRequiredRows = 10

var vulncovCloneRoots = []string{
	"../Semple-Интеграции/vulncov",
	"../vulncov",
}

var vulncovUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var vulncovVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var vulncovRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readVulncovRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(vulncovRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulncovRegistry, err)
	}
	rows := make([][]string, 0, vulncovRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := vulncovRow.FindStringSubmatch(strings.TrimSpace(line))
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

func vulncovCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func vulncovDir(t *testing.T) string {
	t.Helper()
	for _, root := range vulncovCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("vulncov clone not found in %v: the registry's counts cannot be "+
		"verified against the original", vulncovCloneRoots)
	return ""
}

func vulncovOurTree(t *testing.T) string {
	t.Helper()
	parts := []string{}
	skip := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == vulncovRegistry ||
			name == "reconciliation_summary_test.go"
	}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner",
		"pkg/intruder", "pkg/enrich"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				skip(entry.Name()) {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
			if readErr != nil {
				continue
			}
			parts = append(parts, string(raw))
		}
	}
	for _, dir := range []string{"../web/lab", "../web/core"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".py") {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
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

// TestTheVulncovRegistryFixesTheUpstreamCommit.
func TestTheVulncovRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(vulncovRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulncovRegistry, err)
	}
	match := vulncovUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", vulncovRegistry)
	}
	if got := string(match[1]); got != vulncovCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, vulncovCommit)
	}
}

// TestTheVulncovRegistryHasEveryRowItPromises.
func TestTheVulncovRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readVulncovRegistry(t)); got < vulncovRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			vulncovRegistry, got, vulncovRequiredRows)
	}
}

// TestEveryVulncovRowHasAVerdictFromTheThree.
func TestEveryVulncovRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readVulncovRegistry(t) {
		verdict := vulncovCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !vulncovVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedVulncovRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedVulncovRowSaysWhy(t *testing.T) {
	for _, row := range readVulncovRegistry(t) {
		if vulncovCell(row, 3) != "не перенесено" {
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

// TestEveryVulncovRowNamesASymbolThatExists.
func TestEveryVulncovRowNamesASymbolThatExists(t *testing.T) {
	tree := vulncovOurTree(t)
	for _, row := range readVulncovRegistry(t) {
		symbol := vulncovCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(tree, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in our Go code or "+
				"in web/", row[0], symbol)
		}
	}
}

// TestTheOriginalStillJoinsSemgrepWithCoverage — головна механіка.
//
// Три кроки оригіналу читаються з коду без нуток: Semgrep-файл, coverage-файл,
// `_calculate_match_percentage`. Якщо upstream перестане це робити, реєстр
// описує не той предмет.
func TestTheOriginalStillJoinsSemgrepWithCoverage(t *testing.T) {
	dir := vulncovDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "vulncov", "domain",
		"vuln_coverage_matcher.py"))
	if err != nil {
		t.Fatalf("read vuln_coverage_matcher.py: %v", err)
	}
	text := string(raw)
	for _, token := range []string{"semgrep", "_calculate_match_percentage", "coverage"} {
		if !strings.Contains(text, token) {
			t.Errorf("the original no longer mentions %q in its matcher: the "+
				"registry's whole premise is that it joins semgrep findings "+
				"with coverage, and that join is gone", token)
		}
	}
}

// TestWeHaveNoSemgrepAndNoCoverage — рядки 1, 2 і 8.
//
// Три вердикти стоять на цій відсутності. Якщо ми додамо Semgrep або
// coverage-збір, ці рядки треба перечитати.
func TestWeHaveNoSemgrepAndNoCoverage(t *testing.T) {
	lower := strings.ToLower(vulncovOurTree(t))
	for _, token := range []string{"semgrep", "pytest-cov", "go tool cover"} {
		for _, line := range strings.Split(lower, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, token) {
				t.Errorf("our code now mentions %q: %s\nrows 1, 2 and 8 say the "+
					"coverage layer is absent from our project", token, trimmed)
			}
		}
	}
}

// TestWeDoNotCreateAVenvForSomeoneElsesCode — рядок 3.
//
// `AGENTS.md` забороняє нам тягнути залежності чужого коду: ми виконуємо
// HTTP-запити. Якщо з'явиться `venv` під застосунок цілі, це змінило б
// модель безпеки продукту — і реєстр мусить помітити.
func TestWeDoNotCreateAVenvForSomeoneElsesCode(t *testing.T) {
	tree := vulncovOurTree(t)
	if strings.Contains(tree, "venv_handler") || strings.Contains(tree, "create_virtualenv") {
		t.Error("our code now creates a virtualenv for a target application: " +
			"row 3 says we do not install another project's dependencies, and " +
			"that boundary no longer holds")
	}
}

// TestOurIsolationAnswerIsRealAndMeasured — рядок 10.
//
// `улучшено` тримається на тому, що наша ізоляція **виміряна**: шаблон
// тестової БД з `template0` і кодуванням. Тому перевіряється і символ, і
// те, що реєстр пояснює, чому це не «те саме, що venv».
func TestOurIsolationAnswerIsRealAndMeasured(t *testing.T) {
	tree := vulncovOurTree(t)
	if !strings.Contains(tree, "POSTGRES_TEST_TEMPLATE") {
		t.Error("POSTGRES_TEST_TEMPLATE is gone from our settings: row 10 names " +
			"it as the measured answer to the isolation question this " +
			"repository asks")
	}

	raw, err := os.ReadFile(vulncovRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulncovRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "різні речі") && !strings.Contains(text, "на іншому шарі") {
		t.Error("the registry does not explain that our isolation and the " +
			"original's venv are different things: without that, row 10 reads " +
			"as `супадає`, and the comparison stops being honest")
	}
}

// TestTheRegistryNamesTheDifferentQuestion.
//
// Головне прочитання реєстру: vulncov відповідає «чи знаходять тести дефекти»,
// а ми — «чи є дефекти». Якщо це зникне з тексту, вісім `не перенесено`
// прочитаються як перелік наших невмінь.
func TestTheRegistryNamesTheDifferentQuestion(t *testing.T) {
	raw, err := os.ReadFile(vulncovRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulncovRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "різні питання") {
		t.Error("the registry does not say the two tools answer different " +
			"questions: that sentence is what keeps eight `не перенесено` " +
			"from reading as a list of what we cannot do")
	}
}
