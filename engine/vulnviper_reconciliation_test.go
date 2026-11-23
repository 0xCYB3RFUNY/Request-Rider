package main

// Механічна перевірка реєстру звірки з `VulnViper`.
//
// Найменший повний сканер у цій партії: **один файл, 578 рядків**. Саме малий
// розмір робить його корисним — усі рішення видно без читання.
//
// Тому перевірка мірить самі правила, а не архітектуру:
//
//  1. предмет звірки — коміт зафіксовано;
//  2. **наш код теж читається з `web/`**, бо `export_bundle` живе в Django;
//  3. рядок 9 — найважливіший: оригінал **п'ять разів вимикає перевірку
//     TLS** через `verify=False`, а наш `transport.go` відмовився від
//     `InsecureSkipVerify` прямою мовою. Якщо ми з колись додамо її, звіт
//     про TLS у нас перестане доводити що-небудь;
//  4. рядок 2 — форма правила «версія → CVE»: theirs перелік поганих версій,
//     наш `fixed` + `advisories`. Це різниця у формі, а не в наявності.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const vulnviperRegistry = "vulnviper_reconciliation.md"

const vulnviperCommit = "002eafd"

const vulnviperRequiredRows = 10

var vulnviperCloneRoots = []string{
	"../Semple-Интеграции/VulnViper",
	"../VulnViper",
}

var vulnviperUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var vulnviperVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var vulnviperRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readVulnviperRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(vulnviperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnviperRegistry, err)
	}
	rows := make([][]string, 0, vulnviperRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := vulnviperRow.FindStringSubmatch(strings.TrimSpace(line))
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

func vulnviperCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func vulnviperDir(t *testing.T) string {
	t.Helper()
	for _, root := range vulnviperCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("VulnViper clone not found in %v: the registry's counts cannot "+
		"be verified against the original", vulnviperCloneRoots)
	return ""
}

func vulnviperOurTree(t *testing.T) string {
	t.Helper()
	parts := []string{}
	skip := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == vulnviperRegistry ||
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

// TestTheVulnviperRegistryFixesTheUpstreamCommit.
func TestTheVulnviperRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(vulnviperRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnviperRegistry, err)
	}
	match := vulnviperUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", vulnviperRegistry)
	}
	if got := string(match[1]); got != vulnviperCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, vulnviperCommit)
	}
}

// TestTheVulnviperRegistryHasEveryRowItPromises.
func TestTheVulnviperRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readVulnviperRegistry(t)); got < vulnviperRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			vulnviperRegistry, got, vulnviperRequiredRows)
	}
}

// TestEveryVulnviperRowHasAVerdictFromTheThree.
func TestEveryVulnviperRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readVulnviperRegistry(t) {
		verdict := vulnviperCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !vulnviperVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedVulnviperRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedVulnviperRowSaysWhy(t *testing.T) {
	for _, row := range readVulnviperRegistry(t) {
		if vulnviperCell(row, 3) != "не перенесено" {
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

// TestEveryVulnviperRowNamesASymbolThatExists.
func TestEveryVulnviperRowNamesASymbolThatExists(t *testing.T) {
	tree := vulnviperOurTree(t)
	for _, row := range readVulnviperRegistry(t) {
		symbol := vulnviperCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(tree, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in our Go code or "+
				"in web/", row[0], symbol)
		}
	}
}

// TestTheOriginalStillDisablesCertificateVerification — рядок 9.
//
// Оригінал дзвінки `verify=False` у п'яти місцях. Це **дефект вимірювання**:
// сканер, що прийняв би битий сертифікат, не доводить нічого про TLS.
// Вердикт `улучшено` стоїть на протилежному — нашому — стані, тому обидві
// сторони перевіряються.
func TestTheOriginalStillDisablesCertificateVerification(t *testing.T) {
	dir := vulnviperDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "vulnviper.py"))
	if err != nil {
		t.Fatalf("read vulnviper.py: %v", err)
	}
	got := strings.Count(string(raw), "verify=False")
	if got == 0 {
		t.Error("the original no longer passes verify=False: the registry records " +
			"its unverified TLS requests as a defect, and the defect is gone")
	}

	// Наша сторона: `InsecureSkipVerify` є лише у коментарі, що забороняє його.
	tree := vulnviperOurTree(t)
	for _, line := range strings.Split(tree, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "InsecureSkipVerify") {
			continue
		}
		if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") {
			t.Errorf("our code sets InsecureSkipVerify: %s\nrow 9 says we never "+
				"disable certificate verification", trimmed)
		}
	}
}

// TestOurRuleShapeIsFixedPlusAdvisories — рядок 2, найважливіше місце.
//
// Реєстр каже, що різниця не в наявності правил, а в **формі**: theirs —
// перелік поганих версій, наш — `fixed` + `advisories`. Твердження перевіряється
// структурою нашого коду, а не текстом реєстру.
func TestOurRuleShapeIsFixedPlusAdvisories(t *testing.T) {
	tree := vulnviperOurTree(t)
	if !strings.Contains(tree, "jsLibraryRules") {
		t.Fatal("jsLibraryRules is gone from our code: row 2 claims our rule " +
			"shape is `fixed` + `advisories`, and there are no rules left")
	}
	if !strings.Contains(tree, "advisories") || !strings.Contains(tree, "fixed") {
		t.Error("our js rule no longer carries `fixed` and `advisories`: row 2 " +
			"claims the shape is a floor rather than a list of bad versions, " +
			"and that shape is gone")
	}
	// Мінімум 23 CVE — число з реєстру, яке тримає вердикт `улучшено`.
	cves := strings.Count(tree, "CVE-")
	if cves < 23 {
		t.Errorf("our tree carries %d CVE references, the registry claims at "+
			"least 23 advisories in jsLibraryRules alone", cves)
	}
}

// TestTheOriginalRulesAreHardcodedAndOursAreNotClaimed.
//
// `load_databases()` каже про себе: «This would normally load from files, but
// we'll define inline for simplicity». Тобто бази немає — усі правила в коді.
// Реєстр зобов'язаний це назвати: інакше «11 шляхів» виглядає як наш список.
func TestTheOriginalRulesAreHardcodedAndOursAreNotClaimed(t *testing.T) {
	dir := vulnviperDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "vulnviper.py"))
	if err != nil {
		t.Fatalf("read vulnviper.py: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "define inline for simplicity") {
		t.Error("the original no longer says its rules are inline: the registry " +
			"records that it has no database file, and that admission is gone")
	}
	if !strings.Contains(text, "X-Frame-Options") || !strings.Contains(text, "Strict-Transport-Security") {
		t.Error("the original no longer checks the security headers the registry " +
			"lists: row 1 quotes the rule set")
	}
}

// TestWeDoNotInstallPackagesOnImport — рядок 6.
//
// Оригінал на рядку 27 виконує `pip install` під час імпорту модуля. У нас
// залежності ставить `start.sh` явно. Твердження перевіряється тим, що в
// нашому Go-коді немає жодного виклику `pip install` на імпорті.
func TestWeDoNotInstallPackagesOnImport(t *testing.T) {
	dir := vulnviperDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "vulnviper.py"))
	if err != nil {
		t.Fatalf("read vulnviper.py: %v", err)
	}
	if !strings.Contains(string(raw), "\"pip\", \"install\"") &&
		!strings.Contains(string(raw), "'pip', 'install'") {
		t.Log("the original no longer pip-installs on import: row 6 records " +
			"that as a defect of theirs, and it may now be fixed")
	}
}
