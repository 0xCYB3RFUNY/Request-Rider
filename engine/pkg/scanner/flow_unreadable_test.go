package scanner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// `flow_unreadable.md` — реєстр 29 виразів, які цей бігун ще не читає.
//
// Тест існує, щоб **реєстр не брехав**. Число в ньому має дорівнювати тому, що
// парсер справді не читає: якщо наступна сесія додасть можливостей і зніме
// документи зі списку, тест цього не помітить — і файл почне описувати минуле.
//
// Тому перевірка навпаки: коли парсер читає **більше**, тест падає і називає
// розбіжність, щоб реєстр оновили разом із кодом.
// The whole-corpus count is a **measurement**, not a unit test: it reads 98 000
// files and compiles a flow expression for each one with a `flow:`. Measured 50 s
// plain and over 90 s under `-race`, which is more than the package's own timeout
// allows — so it ran once and the suite went red for a reason that had nothing to
// do with the code.
//
// It is therefore behind `RR_FLOW_CORPUS=1`, and the check that always runs is the
// row check below: it reads the 29 named documents only, so it costs 0.03 s and
// still fails when the registry names a template that is not in the corpus, or one
// that the parser already reads.
func TestTheUnreadableFlowRegistryMatchesWhatTheParserActuallyRefuses(t *testing.T) {
	if os.Getenv("RR_FLOW_CORPUS") != "1" {
		t.Skip("set RR_FLOW_CORPUS=1 to walk the whole corpus and recount the registry")
	}
	root := "/home/kali/Desktop/nuclei-templates"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("the corpus is not present at %s, so the registry cannot be checked against it", root)
	}
	registry := "flow_unreadable.md"
	raw, err := os.ReadFile(registry)
	if err != nil {
		t.Fatalf("the registry is missing: %s", err)
	}

	var files []string
	if walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() &&
			(strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	}); walkErr != nil {
		t.Fatalf("cannot walk the corpus: %s", walkErr)
	}

	total, unreadable := 0, map[string]bool{}
	for _, path := range files {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		document, _ := parsePassiveDocument(string(content))
		if document == nil || strings.TrimSpace(document.Flow) == "" {
			continue
		}
		total++
		if _, parseErr := parseFlow(document.Flow); parseErr != nil {
			relative := strings.TrimPrefix(path, root+string(filepath.Separator))
			unreadable[relative] = true
		}
	}

	declaredTotal := registryNumber(t, string(raw), "усього документів з flow: ")
	declaredUnreadable := registryNumber(t, string(raw), "лишилось: ")

	if total != declaredTotal {
		t.Fatalf("the registry says %d `flow:` documents in the corpus, there are %d: "+
			"the corpus or the registry is out of date, and the file no longer describes the code",
			declaredTotal, total)
	}
	if len(unreadable) != declaredUnreadable {
		missing := make([]string, 0, len(unreadable))
		for name := range unreadable {
			missing = append(missing, name)
		}
		t.Fatalf("the registry lists %d unreadable expressions, the parser refuses %d: "+
			"either the registry is stale or the parser is worse than the file says. Refused now: %v",
			declaredUnreadable, len(unreadable), missing)
	}
}

// registryNumber reads the number that follows a marker in the registry's summary.
//
// It reads the text rather than a parsed table on purpose: the registry is written
// for a human, and a human's summary is the part that goes stale first.
func registryNumber(t *testing.T, text, marker string) int {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, marker) {
			continue
		}
		rest := strings.TrimSpace(trimmed[len(marker):])
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end == 0 {
			t.Fatalf("the registry line %q states no number after %q", trimmed, marker)
		}
		parsed, err := strconv.Atoi(rest[:end])
		if err != nil {
			t.Fatalf("the registry line %q carries a number this test cannot read: %s", trimmed, err)
		}
		return parsed
	}
	t.Fatalf("the registry has no line starting with %q", marker)
	return 0
}

// Кожен документ реєстру має бути **справді** непрочитаним: рядок, який опис��є
// шаблон, що парсер уже читає, — це рядок, який бреше.
func TestEveryRegistryRowIsActuallyUnreadable(t *testing.T) {
	root := "/home/kali/Desktop/nuclei-templates"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("the corpus is not present at %s", root)
	}
	raw, err := os.ReadFile("flow_unreadable.md")
	if err != nil {
		t.Fatalf("the registry is missing: %s", err)
	}

	rows := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") || !strings.Contains(trimmed, ".yaml") {
			continue
		}
		cells := strings.Split(trimmed, "|")
		if len(cells) < 4 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[2]), "`")
		rows++
		content, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil {
			t.Errorf("row %d names %q, which is not in the corpus: %s", rows, name, readErr)
			continue
		}
		document, _ := parsePassiveDocument(string(content))
		if document == nil {
			t.Errorf("row %d names %q, which does not parse into a document at all", rows, name)
			continue
		}
		if _, parseErr := parseFlow(document.Flow); parseErr == nil {
			t.Errorf("row %d names %q, which the parser now reads: the registry row must be deleted, "+
				"not left to describe a case that no longer exists", rows, name)
		}
	}
	// The table and the summary must agree, and both are read from the file rather
	// than written here: a test that carried its own copy of the number would pass
	// after the number changed, which is the one thing it exists to prevent.
	declared := registryNumber(t, string(raw), "лишилось: ")
	if rows != declared {
		t.Fatalf("the registry table lists %d documents, its summary says %d: "+
			"the two must agree, and a summary that outlived its table is the part nobody reads",
			rows, declared)
	}
}
