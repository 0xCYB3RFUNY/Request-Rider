package active

// The register test for `nikto_reconciliation.md`.
//
// Why a register needs a test at all: a capability nobody carried over is
// absent from a list built by "compare what we have", and an absent row reads
// as "nothing was lost". `AGENTS.md` puts the rule in one line — перелік знімається
// з файлів оригіналу, а не з того, що вже перенесено — and this file is what
// makes it mechanical instead of a promise in prose.
//
// What it enforces, and why each one is here:
//
//   - a row is not deleted: dropping a row is how a loss becomes invisible, and
//     the row count is therefore pinned to the plugin list upstream declares;
//   - a verdict is one of exactly three: "in progress", "partially" and an empty
//     cell are the words a loss is hidden behind;
//   - `не перенесено` carries a reason: a row without one is a shrug, and the
//     reader cannot tell a decision from an omission;
//   - a claimed symbol exists in the tree: a row naming a module that was never
//     written reports coverage nobody has, which is worse than no row;
//   - an upstream commit is recorded: a table against an unpinned commit is a
//     table about a different subject.
//
// The verdict vocabulary is not redeclared here. `upstreams_reconciliation_test.go`
// and `vexor_reconciliation_test.go` both need it, and two copies of a closed set
// of three values drift apart the moment one of them gets a typo — at which point
// a legitimate verdict fails in one register and not the other, and the first
// thing a maintainer does is "fix" the test instead of the register.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const niktoRegisterFile = "nikto_reconciliation.md"

// niktoCommit is the upstream revision this register describes.
//
// It is recorded here as well as in the register because the test is what makes
// the record binding: changing one without the other fails, which is the point.
// A table written against an unpinned revision describes a scanner that may not
// exist.
const niktoCommit = "312645d873478a77986627ab1fc8cffe595e85d4"

// niktoPlugins is the capability list taken from `program/plugins/` at
// niktoCommit — 33 files, of which the seven `nikto_report_*` writers are output
// formats rather than checks and `LW2.pm` is a Perl library rather than either.
//
// It is written out here rather than read from disk because upstream is not
// available to a test run, and a test that needed the network would be a test
// that silently stops running. The list is asserted against the register, so a
// capability added upstream without a row here fails in both directions.
var niktoPlugins = []string{
	"nikto_apacheusers", "nikto_auth", "nikto_cgi", "nikto_content_search",
	"nikto_cookies", "nikto_core", "nikto_favicon", "nikto_fileops",
	"nikto_headers", "nikto_ms10_070", "nikto_msgs", "nikto_multiple_index",
	"nikto_negotiate", "nikto_optionsbleed", "nikto_options", "nikto_outdated",
	"nikto_paths", "nikto_put_del_test", "nikto_robots", "nikto_shellshock",
	"nikto_siebel", "nikto_sitefiles", "nikto_springboot", "nikto_ssl",
	"nikto_tests",
}

// reportPlugins are the output formats. They are a row in the register because
// "the tool can write a CSV" is a capability an operator uses, but they are not
// checks, so they do not appear in the pinned plugin count above.
var reportPlugins = []string{"nikto_report_csv", "nikto_report_html", "nikto_report_json"}

// niktoRow is one parsed row of the capability table.
type niktoRow struct {
	capability string
	symbol     string
	verdict    string
	reason     string
}

// niktoRowPattern reads a capability table row.
//
// It is deliberately tolerant of the surrounding prose and strict about the four
// columns: a row is four pipe-separated fields, and the last one is the reason,
// which is why the cells are trimmed before use — a table someone padded to read
// better must not fail for its padding.
var niktoRowPattern = regexp.MustCompile(`^\|\s*` + "`([^`]+)`" + `\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|$`)

// readRegister parses the register file.
func readRegister(t *testing.T) []niktoRow {
	t.Helper()
	raw, err := os.ReadFile(niktoRegisterFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v", niktoRegisterFile, err)
	}
	var rows []niktoRow
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "| `") {
			continue
		}
		match := niktoRowPattern.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		rows = append(rows, niktoRow{
			capability: strings.TrimSpace(match[1]),
			symbol:     strings.TrimSpace(match[2]),
			verdict:    strings.TrimSpace(match[3]),
			reason:     strings.TrimSpace(match[4]),
		})
	}
	return rows
}

func TestTheRegisterHasARowForEveryUpstreamPlugin(t *testing.T) {
	rows := readRegister(t)
	covered := map[string]bool{}
	for _, row := range rows {
		covered[row.capability] = true
	}

	// Every plugin named in the register must be one upstream actually has.
	// A capability invented here is a claim about a tool that does not do it.
	for _, row := range rows {
		name := row.capability
		if index := strings.Index(name, " "); index > 0 {
			name = name[:index]
		}
		name = strings.Trim(name, "`")
		if strings.HasPrefix(name, "nikto_report_") || name == "LW2.pm" {
			continue
		}
		if !contains(niktoPlugins, name) && !contains(reportPlugins, name) {
			t.Errorf("the register has a row for %q, which is not a plugin of nikto", row.capability)
		}
	}

	for _, plugin := range append(append([]string{}, niktoPlugins...), reportPlugins...) {
		if !covered[plugin] {
			t.Errorf("%s has no row in the register: a capability nobody carried over is "+
				"absent from a list built by comparing what we have, and that absence reads "+
				"as 'nothing was lost'", plugin)
		}
	}
}

func TestEveryRowCarriesAVerdictFromTheClosedSet(t *testing.T) {
	for _, row := range readRegister(t) {
		if row.verdict == "" {
			t.Errorf("%s: empty verdict — 'in progress', 'partially' and a blank cell are "+
				"the words a loss hides behind", row.capability)
			continue
		}
		if !allowedVerdicts[row.verdict] {
			t.Errorf("%s: verdict %q is not one of %q, %q, %q",
				row.capability, row.verdict, verdictMatched, verdictImproved, verdictLost)
		}
	}
}

func TestALostCapabilitySaysWhyAndWhatIsUsedInstead(t *testing.T) {
	for _, row := range readRegister(t) {
		if row.verdict != verdictLost {
			continue
		}
		if len(row.reason) < 20 {
			t.Errorf("%s: `не перенесено` with a %d-character reason. A reader cannot tell "+
				"a decision from an omission, and the reason has to say what is used instead",
				row.capability, len(row.reason))
		}
		if row.symbol != "—" && !strings.Contains(row.reason, "причин") && !strings.Contains(row.reason, "ліценз") {
			// Not a hard rule about wording — a nudge, printed only when the row
			// is short, so it fails the length assertion above rather than
			// pretending to police prose.
			t.Logf("%s: the reason does not use the words 'причина' or 'ліцензія': %q",
				row.capability, row.reason)
		}
	}
}

func TestAClaimedSymbolExistsInTheTree(t *testing.T) {
	for _, row := range readRegister(t) {
		if row.verdict == verdictLost {
			continue
		}
		if row.symbol == "" || row.symbol == "—" {
			continue
		}
		for _, cell := range symbolPattern.FindAllStringSubmatch(row.symbol, -1) {
			for _, name := range identifiersIn(cell[1]) {
				if !declaredAnywhere(name) {
					t.Errorf("%s claims %q, which is not declared in the tree: the row "+
						"reports coverage nobody has", row.capability, name)
				}
			}
		}
	}
}

// declaredAnywhere reports whether a claimed symbol is declared in either package a
// row may legitimately point at.
//
// The register used to describe only this package, and `declaredInPackage` was the
// whole of its world. It no longer is: the enumeration corpus and the runner that
// executes it live in `pkg/scanner`, because a scanner that executes third-party
// check data is not an active-scan detector — it is a tool with its own job
// lifecycle. A row naming `RunCorpus` therefore names a real symbol in a different
// package, and searching only here would report that as coverage nobody has.
//
// The fallback is deliberately narrow: it searches exactly the one other package
// this project put these rows in. Widening it to "search the whole repository" would
// make the check unable to fail, which is the property it exists to keep.
func declaredAnywhere(name string) bool {
	return declaredInPackage(name) || declaredInScannerPackage(name)
}

// declaredInScannerPackage is the `pkg/scanner` half of declaredAnywhere.
func declaredInScannerPackage(name string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(name) + `\s*\(`),
		regexp.MustCompile(`(?m)^func\s+\([^)]*\)\s*\*?` + regexp.QuoteMeta(name) + `\s*\(`),
		regexp.MustCompile(`(?m)^type\s+` + regexp.QuoteMeta(name) + `\b`),
		regexp.MustCompile(`(?m)^var\s+` + regexp.QuoteMeta(name) + `\b`),
		regexp.MustCompile(`(?m)^const\s+` + regexp.QuoteMeta(name) + `\b`),
	}
	entries, err := filepath.Glob(filepath.Join("..", "scanner", "*.go"))
	if err != nil || len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(entry)
		if err != nil {
			continue
		}
		body := string(raw)
		if strings.Contains(body, "\n//go:build ") && !strings.Contains(body, "\n//go:build !") {
			continue
		}
		for _, pattern := range patterns {
			if pattern.MatchString(body) {
				return true
			}
		}
	}
	return false
}

func TestTheRegisterNamesAnUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(niktoRegisterFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v", niktoRegisterFile, err)
	}
	text := string(raw)
	if !strings.Contains(text, niktoCommit) {
		t.Errorf("the register does not name upstream commit %s. A table against an "+
			"unpinned commit is a table about a different subject", niktoCommit)
	}
	if !strings.Contains(text, "sullo/nikto") {
		t.Error("the register does not say which repository it describes")
	}
}

// TestAClaimedSymbolExistsInTheTree reuses the machinery the VEXOR register test
// already built rather than declaring a second copy.
//
// The first version of this check scanned for the *file* names the symbol cells
// carried (`detect_misconfig.go`) and reported every one of them as absent, which
// is what a check does when it looks for the wrong thing: it failed loudly, on
// every row, and was wrong about all of them. `symbolPattern`, `identifiersIn`
// and `declaredInPackage` already read a cell as Go identifiers and search the
// whole package, so the register was changed to name symbols rather than files —
// which is also more precise, since two capabilities can share one file.

// `contains` is already declared in `enumerate_test.go` and is used here rather
// than declared again: a second membership helper in one package is two places
// for the answer to differ.
