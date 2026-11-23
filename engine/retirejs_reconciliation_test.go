package main

// Механічна перевірка реєстру звірки з `RetireJS/retire.js`.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const retirejsRegistry = "retirejs_reconciliation.md"

var retirejsUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var retirejsVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var retirejsRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readRetirejsRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(retirejsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", retirejsRegistry, err)
	}
	rows := make([][]string, 0, 12)
	for _, line := range strings.Split(string(raw), "\n") {
		match := retirejsRow.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		cells := strings.Split(match[2], "|")
		if len(cells) < 6 {
			continue
		}
		rows = append(rows, append([]string{match[1]}, cells...))
	}
	return rows
}

func TestRetirejsRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(retirejsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", retirejsRegistry, err)
	}
	if !retirejsUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", retirejsRegistry)
	}
}

func TestEveryRetirejsRowHasAVerdictFromTheThree(t *testing.T) {
	rows := readRetirejsRegistry(t)
	if len(rows) == 0 {
		t.Fatalf("%s has no numbered rows", retirejsRegistry)
	}
	for _, row := range rows {
		if len(row) < 4 {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		verdict := strings.Trim(strings.TrimSpace(row[3]), "`")
		if !retirejsVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of the three", row[0], verdict)
		}
	}
}

func TestEveryNotPortedRetirejsRowHasAReason(t *testing.T) {
	for _, row := range readRetirejsRegistry(t) {
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

// TestEveryExtractorKindIsAccountedFor: некласифіковане вважається втратою.
// Кожен із шести видів extractor-ів має рядок у реєстрі — або як перенесений,
// або як «не перенесено» з причиною.
func TestEveryExtractorKindIsAccountedFor(t *testing.T) {
	raw, err := os.ReadFile(retirejsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", retirejsRegistry, err)
	}
	text := string(raw)
	for _, kind := range []string{"func", "filename", "filecontent", "hashes", "uri", "filecontentreplace"} {
		if !strings.Contains(text, kind) {
			t.Errorf("extractor kind %q has no row in the registry", kind)
		}
	}
}

// TestTheRegistryStatesTheThreeDifferentCounts: 6, 249 і 385 — різні одиниці.
// Якщо реєстр називає тільки одне з них, читач не зможе відрізнити «види» від
// «виразів», а це рівно та плутанина, що коштувала три рядки під час перенесення
// активного сканера.
func TestTheRegistryStatesTheThreeDifferentCounts(t *testing.T) {
	raw, err := os.ReadFile(retirejsRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", retirejsRegistry, err)
	}
	text := string(raw)
	for _, needle := range []string{"| **76** |", "| **750** |", "| 6 |", "| 249 |", "| **385** |"} {
		if !strings.Contains(text, needle) {
			t.Errorf("the registry does not state the count %s", needle)
		}
	}
}
