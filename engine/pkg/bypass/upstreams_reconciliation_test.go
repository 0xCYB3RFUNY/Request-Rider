package bypass

// The registry's guard.
//
// The registry is the difference between a port and a drop of code, and a
// registry nothing checks is a document. Every check below exists because of a
// way this table can quietly stop describing the code:
//
//   - a verdict outside the three, or empty — because "in progress" and
//     "partially" are the words a loss hides behind;
//   - a `not-ported` row with no `instead:` — because an unexplained absence
//     reads as an oversight nobody decided on;
//   - a symbol that is not in the tree — because the row claims a mechanism that
//     was renamed or removed;
//   - a number gap — because a row that was pulled leaves the count wrong and
//     nothing else notices;
//   - a form in the ladder with no row — because that is exactly the hole the
//     procedure was written to close, and the table is written from the
//     originals rather than from the code, so it does not grow by itself.
//
// Every literal here is ASCII. The table is written by hand, and two spellings
// of one Cyrillic word drift apart silently; a guard that failed on that would
// train its reader to ignore it, and one that accepted both without naming them
// would let a fourth verdict through. The verdicts in the table are therefore
// ASCII tokens, and this file needs none of the prose.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// registryFile is the table, next to this test.
const registryFile = "upstreams_reconciliation.md"

// verdictTokens is the whole vocabulary. There is no fourth state.
var verdictTokens = map[string]bool{"matches": true, "improved": true, "not-ported": true}

// notPorted is the one verdict that demands a reason and a replacement.
const notPorted = "not-ported"

// insteadMarker is what a `not-ported` row must carry. It is ASCII because the
// check is mechanical and the marker must not be a variant of a word someone
// can type two ways.
const insteadMarker = "instead:"

var mainRow = regexp.MustCompile(`^\d+$`)
var ownRow = regexp.MustCompile(`^[A-Z]$`)
var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)

type registryRow struct {
	number  string
	verdict string
	symbol  string
	reason  string
	isOurs  bool
	lineNo  int
}

func loadRegistry(t *testing.T) []registryRow {
	t.Helper()
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("read %s: %v", registryFile, err)
	}
	var rows []registryRow
	for index, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		cells := splitCells(line)
		switch {
		case len(cells) == 7 && mainRow.MatchString(cells[0]):
			rows = append(rows, registryRow{
				number: cells[0], verdict: cells[3], reason: cells[5],
				symbol: unquote(cells[6]), lineNo: index + 1,
			})
		case len(cells) == 5 && ownRow.MatchString(cells[0]):
			rows = append(rows, registryRow{
				number: cells[0], verdict: cells[2], reason: cells[3],
				symbol: unquote(cells[4]), isOurs: true, lineNo: index + 1,
			})
		}
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no capability rows; a table with none describes nothing", registryFile)
	}
	return rows
}

// splitCells splits one markdown row, dropping the empty cells the leading and
// trailing pipes produce.
func splitCells(line string) []string {
	parts := strings.Split(line, "|")
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cells = append(cells, strings.TrimSpace(part))
	}
	for len(cells) > 0 && cells[0] == "" {
		cells = cells[1:]
	}
	for len(cells) > 0 && cells[len(cells)-1] == "" {
		cells = cells[:len(cells)-1]
	}
	return cells
}

// unquote strips the backticks the table writes a symbol in. The search is over
// Go source, and a symbol in Go is not written in backticks.
func unquote(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "**")
	trimmed = strings.TrimSuffix(trimmed, "**")
	return strings.Trim(trimmed, "`")
}

// engineTree is every Go file under the engine module: its path and its contents.
//
// The path is included because a row is allowed to name a *file* as its symbol —
// a detector this package deliberately reuses is named by its file — and a tree
// of contents alone would report every file claim as missing.
func engineTree(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	err := filepath.Walk(filepath.Join("..", ".."), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		out.WriteString(filepath.ToSlash(path))
		out.WriteByte('\n')
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		out.Write(data)
		out.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("read the engine tree: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("the engine tree is empty, so every symbol check would pass vacuously")
	}
	return out.String()
}

func TestEveryRegistryRowCarriesAVerdictFromTheThree(t *testing.T) {
	for _, row := range loadRegistry(t) {
		if !verdictTokens[row.verdict] {
			t.Errorf("%s:%d row %s carries verdict %q; the vocabulary is matches / improved / not-ported",
				registryFile, row.lineNo, row.number, row.verdict)
		}
	}
}

func TestARowThatWasNotPortedNamesWhyAndWhatIsUsedInstead(t *testing.T) {
	for _, row := range loadRegistry(t) {
		if row.verdict != notPorted {
			continue
		}
		if len(row.reason) < 30 {
			t.Errorf("%s:%d row %s is %s with no usable reason: %q",
				registryFile, row.lineNo, row.number, notPorted, row.reason)
		}
		if !strings.Contains(row.reason, insteadMarker) {
			t.Errorf("%s:%d row %s is %s but does not say what is used instead; "+
				"an absence with no replacement leaves the reader with a gap",
				registryFile, row.lineNo, row.number, notPorted)
		}
	}
}

func TestEverySymbolTheRegistryClaimsExistsInTheTree(t *testing.T) {
	tree := engineTree(t)
	for _, row := range loadRegistry(t) {
		if row.symbol == "" || row.symbol == "-" || row.symbol == "—" {
			// An em dash is only honest where nothing was ported. A row that
			// claims `matches` and names no symbol is a row asserting a mechanism
			// nothing can check.
			if row.verdict != notPorted {
				t.Errorf("%s:%d row %s claims %q but names no symbol, so nothing can be checked",
					registryFile, row.lineNo, row.number, row.verdict)
			}
			continue
		}
		// A row may name several symbols; each has to be there.
		for _, symbol := range strings.Split(row.symbol, ",") {
			symbol = unquote(symbol)
			if symbol == "" {
				continue
			}
			if !strings.Contains(tree, symbol) {
				t.Errorf("%s:%d row %s claims symbol %q, which is nowhere in the engine tree",
					registryFile, row.lineNo, row.number, symbol)
			}
		}
	}
}

func TestTheRegistryIsNumberedWithoutGaps(t *testing.T) {
	seen := map[int]bool{}
	last := 0
	for _, row := range loadRegistry(t) {
		if row.isOurs {
			continue
		}
		number, err := strconv.Atoi(row.number)
		if err != nil {
			t.Errorf("%s:%d row number %q is not a number", registryFile, row.lineNo, row.number)
			continue
		}
		if seen[number] {
			t.Errorf("%s:%d duplicates capability number %d", registryFile, row.lineNo, number)
		}
		seen[number] = true
		if number != last+1 {
			t.Errorf("%s:%d capability %d follows %d; the table is numbered without gaps",
				registryFile, row.lineNo, number, last)
		}
		last = number
	}
	if last == 0 {
		t.Fatal("no numbered capability rows")
	}
}

func TestEveryFormInTheLadderHasARow(t *testing.T) {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("read %s: %v", registryFile, err)
	}
	text := string(data)
	for _, name := range Forms() {
		if !strings.Contains(text, "`"+name+"`") {
			t.Errorf("form %q is in the ladder and has no row in %s; a capability the table "+
				"does not know about is one that was added without deciding anything",
				name, registryFile)
		}
	}
}

func TestEveryUpstreamSourcePinsACommitOrSaysWhyItCannot(t *testing.T) {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("read %s: %v", registryFile, err)
	}
	// The source table is the three-column one: source, commit, licence.
	sources := 0
	for index, line := range strings.Split(string(data), "\n") {
		cells := splitCells(line)
		if len(cells) != 3 || !strings.HasPrefix(cells[0], "`") {
			continue
		}
		sources++
		cell := unquote(cells[1])
		pinned := commit.MatchString(cell)
		explained := strings.Contains(cell, "404") || strings.Contains(cell, "unpinned")
		if !pinned && !explained {
			t.Errorf("%s:%d source %s pins neither a commit nor a reason: %q",
				registryFile, index+1, cells[0], cell)
		}
	}
	if sources < 9 {
		t.Errorf("the source table lists %d rows, want 8 given plus the one that turned out "+
			"not to exist", sources)
	}
}

func TestTheDeadUpstreamURLIsNamedRatherThanDropped(t *testing.T) {
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("read %s: %v", registryFile, err)
	}
	text := string(data)
	if !strings.Contains(text, "portswigger/403-bypass`") {
		t.Error("the registry does not mention the URL that was given; a source that turned out " +
			"not to exist has to stay in the table, or the reader cannot tell it from never having been offered")
	}
	if !strings.Contains(text, "404") {
		t.Error("the registry does not record that the given URL answered 404")
	}
}

func TestOurOwnCapabilitiesAreListed(t *testing.T) {
	ours := 0
	for _, row := range loadRegistry(t) {
		if row.isOurs {
			ours++
		}
	}
	if ours < 6 {
		t.Errorf("the registry lists %d capabilities of ours, want at least 6: the table has to "+
			"cover what we have as well as what they had, or the guard has nothing to close over", ours)
	}
}
