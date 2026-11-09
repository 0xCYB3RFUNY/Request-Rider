package main

// Механічна перевірка реєстру звірки з `VulnHeist`.
//
// Це **автоматизатор Metasploit Framework поверх RPC** — 1 388 рядків, з яких
// Metasploit обслуговує майже все, а сканування займає 223 рядки.
//
// Тому перевірка мірить дві речі, які разом визначають вердикт:
//
//  1. **в оригіналі є `shell=True` з інтерполяцією цілі** в
//     `Nmap_scan.py`. `AGENTS.md` (частина VII) вимагає `shell=False` або
//     масив аргументів. Якщо upstream це виправить — реєстр має помітити;
//  2. **у нас немає Metasploit і немає Nmap**. Це сім `не перенесено`, тому
//     що «сесії до чужого рушія» не мають адресата.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const vulnheistRegistry = "vulnheist_reconciliation.md"

const vulnheistCommit = "f5f96e3"

const vulnheistRequiredRows = 10

var vulnheistCloneRoots = []string{
	"../Semple-Интеграции/VulnHeist",
	"../VulnHeist",
}

var vulnheistUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var vulnheistVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var vulnheistRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readVulnheistRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(vulnheistRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnheistRegistry, err)
	}
	rows := make([][]string, 0, vulnheistRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := vulnheistRow.FindStringSubmatch(strings.TrimSpace(line))
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

func vulnheistCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func vulnheistDir(t *testing.T) string {
	t.Helper()
	for _, root := range vulnheistCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("VulnHeist clone not found in %v: the registry's counts cannot be "+
		"verified against the original", vulnheistCloneRoots)
	return ""
}

func vulnheistOurTree(t *testing.T) string {
	t.Helper()
	parts := []string{}
	skip := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == vulnheistRegistry ||
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

// TestTheVulnheistRegistryFixesTheUpstreamCommit.
func TestTheVulnheistRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(vulnheistRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnheistRegistry, err)
	}
	match := vulnheistUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", vulnheistRegistry)
	}
	if got := string(match[1]); got != vulnheistCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, vulnheistCommit)
	}
}

// TestTheVulnheistRegistryHasEveryRowItPromises.
func TestTheVulnheistRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readVulnheistRegistry(t)); got < vulnheistRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			vulnheistRegistry, got, vulnheistRequiredRows)
	}
}

// TestEveryVulnheistRowHasAVerdictFromTheThree.
func TestEveryVulnheistRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readVulnheistRegistry(t) {
		verdict := vulnheistCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !vulnheistVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedVulnheistRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedVulnheistRowSaysWhy(t *testing.T) {
	for _, row := range readVulnheistRegistry(t) {
		if vulnheistCell(row, 3) != "не перенесено" {
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

// TestEveryVulnheistRowNamesASymbolThatExists.
func TestEveryVulnheistRowNamesASymbolThatExists(t *testing.T) {
	tree := vulnheistOurTree(t)
	for _, row := range readVulnheistRegistry(t) {
		symbol := vulnheistCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(tree, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in our Go code or "+
				"in web/lab", row[0], symbol)
		}
	}
}

// TestTheOriginalStillInterpolatesTheTargetIntoAShell — дефект оригіналу.
//
// `Nmap_scan.py:18-20` збирає команду f-рядком і запускає її через
// `subprocess.run(..., shell=True)`. Будь-який рядок у `target` стає командою.
//
// `AGENTS.md` (частина VII) вимагає для викликів ОС «вимкніть оболонку
// (`shell=False` у Python, масиви аргументів у Go)». Реєстр зобов'язаний
// назвати цей дефект — і якщо upstream його виправить, реєстр опишує не той
// предмет.
func TestTheOriginalStillInterpolatesTheTargetIntoAShell(t *testing.T) {
	dir := vulnheistDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "Nmap_scan.py"))
	if err != nil {
		t.Fatalf("read Nmap_scan.py: %v", err)
	}
	text := string(raw)

	if !strings.Contains(text, "shell=True") {
		t.Error("the original no longer uses shell=True: the registry records a " +
			"defect in it, and the defect is gone")
		return
	}
	// Перевіряємо саме інтерполяцію: f-рядок або конкатенація з `target`
	// у тій самій команді.
	interpolates := strings.Contains(text, "{target}") ||
		strings.Contains(text, "\" + target") ||
		strings.Contains(text, "' + target")
	if !interpolates {
		t.Error("the original still uses shell=True but no longer interpolates " +
			"the target: the recorded defect was specifically the interpolated " +
			"target, and that part is gone")
	}
}

// TestTheRegistryKeepsNamingThatDefect.
func TestTheRegistryKeepsNamingThatDefect(t *testing.T) {
	raw, err := os.ReadFile(vulnheistRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnheistRegistry, err)
	}
	text := string(raw)
	if !strings.Contains(text, "shell=True") {
		t.Error("the registry no longer records the shell=True interpolation: " +
			"it is the most useful thing this repository has to say, and it " +
			"explains why our engine never shells out")
	}
}

// TestWeHaveNoMetasploitAndNoShell — рядки 3, 4 і 6, 7.
//
// Сесії до Metasploit, керування `msfrpcd` і зовнішній Nmap — усе це потребує
// чужого рушія, якого в нас немає. Перевірка перевіряє обидві сторони: і
// відсутність у нас, і наявність назв у реєстрі.
func TestWeHaveNoMetasploitAndNoShell(t *testing.T) {
	lower := strings.ToLower(vulnheistOurTree(t))
	for _, token := range []string{"metasploit", "msfrpcd", "msfpc"} {
		for _, line := range strings.Split(lower, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, token) {
				t.Errorf("our code now mentions %q: %s\nrows 3 and 4 say Metasploit "+
					"is absent from our project", token, trimmed)
			}
		}
	}
}

// TestOurChainsAreTheCounterpart — рядки 1 і 9.
//
// `не перенесено` у цьому реєстрі майже скрізь, і легко прочитати його як
// «ми нічого не вміємо доводити». Протилежне виміряне: у нас 7 ланцюгів із
// контрактом `Name()` + `Apply`, і UNION-доказ ми будуємо самі.
func TestOurChainsAreTheCounterpart(t *testing.T) {
	tree := vulnheistOurTree(t)
	if !strings.Contains(tree, "func (c *Chain") {
		t.Error("our exploit chains are gone: row 1 claims we prove findings " +
			"ourselves, and the chains are the proof")
	}
	if !strings.Contains(tree, "UNION SELECT") {
		t.Error("our own UNION proof is gone: row 2 says we prove SQL injection " +
			"without Metasploit, and the proof query no longer exists")
	}
}
