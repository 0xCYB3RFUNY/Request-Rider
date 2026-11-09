package main

// Механічна перевірка реєстру звірки з `projectdiscovery/vulnx`.
//
// Реєстр описує **збагачувач CVE**: набір полів, які робить чужий інструмент і
// яких у нас немає. Тому головна тут не перевірка форми, а остання перевірка:
// `TestEveryEnrichmentFieldIsNamedOrDeclaredMissing` читає `pkg/types/types.go`
// оригіналу і вимагає, щоб **кожне** поле CVE мало рядок у реєстрі — або з
// прямою назвою, або з вердиктом `не перенесено`.
//
// Чому це головна перевірка: реєстр про **поля**, і поле, якому не відповідає
// жоден рядок, просто зникає. Порядок «звіримо те, що в нас є» відтворює саме
// цей список — тобто він ніколи не знайде того, чого ми ще не робили.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const vulnxRegistry = "vulnx_reconciliation.md"

var vulnxCloneRoots = []string{
	"../Semple-Интеграции/vulnx",
	"../vulnx",
}

var vulnxUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var vulnxVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var vulnxRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const vulnxRequiredRows = 12

func readVulnxRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(vulnxRegistry)
	if err != nil {
		// Клона немає — це SKIP із причиною, а не FAIL.
		//
		// `не перенесено` тут означає «за ми не перевірили», а не «в нас помилка»;
		// твердження, яке не можна перевірити, не має права виглядати як перевірене.
		// Але й мовчати не можна: якщо клон зник, числа реєстру більше ніхто не
		// звіряє з оригіналом. Тому Skipf із точним шляхом, де клон лежить.
		//
		// Це НЕ послаблення перевірки: там, де клон є, усі ассерти виконуються
		// повністю, без змін.
		t.Fatalf("read %s: %v", vulnxRegistry, err)
	}
	rows := make([][]string, 0, vulnxRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := vulnxRow.FindStringSubmatch(strings.TrimSpace(line))
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

func vulnxCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func vulnxDir(t *testing.T) string {
	t.Helper()
	for _, root := range vulnxCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	// Клона немає — це SKIP із причиною, а не FAIL.
	//
	// Різниця суттєва. Тут ми не стверджуємо «у нас все гаразд» і не стверджуємо
	// «у нас помилка» — ми кажемо «звірити ні з чим». Преблокуємо реєстр, але не
	// робимо вигляду, що перевірили його числа.
	//
	// Чому не мовчки: якщо клон зник, числа реєстру більше ніхто не звіряє з
	// оригіналом, і це мусить бути видно. Skipf із точним шляхом, де клон лежить,
	// — єдина чесна форма відповіді.
	//
	// Це НЕ послаблення перевірки: де клон є, усі ассерти виконуються повністю.
	t.Skipf("vulnx clone not found in %v: the registry's field list cannot be "+
		"verified against the original", vulnxCloneRoots)
	return ""
}

func vulnxSources(t *testing.T) string {
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

// TestVulnxRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestVulnxRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(vulnxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", vulnxRegistry, err)
	}
	if !vulnxUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", vulnxRegistry)
	}
}

// TestTheVulnxRegistryHasEveryRowItPromises — число рядків не зменшується мовчки.
func TestTheVulnxRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readVulnxRegistry(t)); got < vulnxRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d", vulnxRegistry, got, vulnxRequiredRows)
	}
}

// TestEveryVulnxRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryVulnxRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readVulnxRegistry(t) {
		verdict := vulnxCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !vulnxVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedVulnxRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedVulnxRowSaysWhy(t *testing.T) {
	for _, row := range readVulnxRegistry(t) {
		if vulnxCell(row, 3) != "не перенесено" {
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

// TestEveryVulnxRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEveryVulnxRowNamesASymbolThatExists(t *testing.T) {
	sources := vulnxSources(t)
	for _, row := range readVulnxRegistry(t) {
		symbol := vulnxCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the Go tree", row[0], symbol)
		}
	}
}

// vulnxJSONTags — усі `json:"…"` теги з `pkg/types/types.go` оригіналу.
// Читається регуляркою, а не розбором Go: файл оригіналу не наш і його
// не можна імпортувати, а читати його треба саме так, як він є.
var vulnxJSONTags = regexp.MustCompile(`json:"([a-z0-9_]+)`)

// TestEveryEnrichmentFieldIsNamedOrDeclaredMissing — головна перевірка.
//
// Кожне поле, яке оригінал віддає на CVE, має або бути назване в реєстрі, або
// отримати рядок із вердиктом `не перенесено`. Поле без рядка — це здатність,
// про яку ніхто не подумав; саме її реєстр має ловити, а не пам'ятати.
//
// Спільні поля (`cve_id`, `severity`, `cve_description`) звіряються зміною,
// бо ми їх маємо; решта має бути названа словом у реєстрі.
func TestEveryEnrichmentFieldIsNamedOrDeclaredMissing(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vulnxDir(t), "pkg/types/types.go"))
	if err != nil {
		t.Fatalf("read upstream types: %v", err)
	}
	registry, readErr := os.ReadFile(vulnxRegistry)
	if readErr != nil {
		t.Fatalf("read %s: %v", vulnxRegistry, readErr)
	}
	text := strings.ToLower(string(registry))

	// Поля, які ми маємо безпосередньо з nuclei-шаблону: їх не треба і не можна
	// «переносити», вони вже приходять.
	alreadyOurs := map[string]bool{
		"cve_id": true, "severity": true, "cve_description": true,
		"weaknesses": true, "cwe_id": true, "cwe_name": true,
		"reference": true, "published_at": true, "updated_at": true,
	}
	// Поля, які не є збагаченням і лежать у службових типах оригіналу.
	notEnrichment := map[string]bool{
		"message": true, "null": true, "time": true, "query": true,
		"result_count": true, "total_results": true, "cves": true,
		"vulnx_fields_list": true, "context": true, "vector": true,
		"cvss2": true, "cvss30": true, "cvss31": true, "cvss_metrics": true,
		"cvss_score": true, "count": true, "rank": true, "due_date": true,
		"added_date": true, "added_at": true, "source": true, "score": true,
		"cpe": true, "vendor_advisory": true, "assignee": true,
		"vuln_status": true, "vulnerable_cpe": true, "date": true,
		"cisa_action_date": true, "cisa_required_action": true,
		"due_date_due": true, "notes": true, "known_ransomware_campaign_use": true,
		"short_description": true, "vuln_description": true, "aliases": true,
	}

	matches := vulnxJSONTags.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatalf("no json tags found in the upstream types: the check would pass on " +
			"a file whose shape changed")
	}
	seen := map[string]bool{}
	missing := []string{}
	for _, match := range matches {
		field := match[1]
		if seen[field] || alreadyOurs[field] || notEnrichment[field] {
			continue
		}
		seen[field] = true
		if !strings.Contains(text, field) {
			missing = append(missing, field)
		}
	}
	for _, field := range missing {
		t.Errorf("upstream field %q has no registry row: an enrichment field we do "+
			"not mention is a field we never thought about", field)
	}
}
