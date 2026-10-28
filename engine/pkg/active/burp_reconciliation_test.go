package active

// The register test for `burp_reconciliation.md`.
//
// It enforces the same rules as `nikto_reconciliation_test.go` and
// `hunner_reconciliation_test.go`, and for the same reason. A register built by
// "compare what we have" cannot see a capability nobody carried: the row is
// absent, and an absent row reads as "nothing was lost". `AGENTS.md` puts the
// remedy in one line — the list is taken from the original's own files — and
// this file is what makes that mechanical instead of a promise.
//
//   - the row count is pinned to the original's own check list, so a row cannot
//     be deleted quietly;
//   - a verdict is one of exactly three, so "in progress" cannot stand in for a
//     loss;
//   - `не перенесено` carries a reason, so a decision cannot read as an omission;
//   - a claimed symbol exists in the tree, so a row cannot report coverage nobody
//     has;
//   - the original's revision is recorded here as well as in the register, so a
//     table written against a version that was never measured cannot pass;
//   - every check carries the type index it claims, and no index is used twice,
//     so a row cannot silently describe a different check;
//   - the register's summary line is reconciled against its own rows.
//
// The last one exists because a summary is prose written by hand next to a table
// written by hand, and the failure mode is measured elsewhere in this repository:
// `engine/reconciliation_summary_test.go` was added after a register claimed 7
// untransferred rows and held 4 — a number carried over from an older revision of
// the table, which read as perfectly plausible.

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const burpRegisterFile = "burp_reconciliation.md"

// burpOriginalVersion is the Burp Suite revision this register describes.
//
// Burp Suite is not a git repository, so the pin is the distribution version the
// operator supplied — `burpsuite_desktop_v2026.9.1` — rather than a commit hash.
// It is recorded in two places on purpose: changing one without the other fails
// the test, which is exactly the moment a reader should be told the table is
// stale.
const burpOriginalVersion = "burpsuite_desktop_v2026.9.1"

// burpUpstreamChecks is the number of scan checks the original's list holds.
//
// The list is the operator's extraction of the Scan checks tab — 165 distinct
// `type_index` values across the eight categories. Pinned as a count so that
// deleting a row fails here rather than quietly succeeding in the file.
//
// Provenance, because a count without one is hearsay: the distribution's own
// `resources/BuiltInConfigs/*.json` carry the same identifiers (15 distinct ones
// across the 29 files), and 13 of them are in this list; the remaining two
// (`0x08000000`, `0x09000000`) are the extension sources rather than scanner
// checks. The distribution ships no complete machine-readable check list —
// `issue-definitions.html` is a 2.6 KB stub — which is why the operator's
// extraction is the list this register is built against.
const burpUpstreamChecks = 165

// burpRowPattern splits a register row. The Hunner layout has seven columns, and
// the two that matter beyond the verdict are the reason and the symbol, so all
// seven are captured rather than the four the shared pattern takes.
var burpRowPattern = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|`)

// burpIndexPattern reads the type index out of the check-name column.
var burpIndexPattern = regexp.MustCompile(`0[xX][0-9A-Fa-f]{8}`)

// burpSymbolPattern reads the Go symbol out of a symbol cell. The cell names
// both the type and the module the tree registers — `ResponseHeaders (модуль
// \`response-headers\`)` — so the type is the leading identifier and the rest is
// context. Reading the whole cell as a symbol would fail on every row, because
// no such identifier exists.
var burpSymbolPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// TheBurpSummaryMatchesTheRows is not the only summary in the file. The header
// carries a table of "walls" — the four reasons an untransferred capability is
// untransferred — each with a row count. That table is prose written next to the
// capability table, which is exactly the shape `engine/reconciliation_summary_test.go`
// was created for after a register claimed 7 untransferred rows and held 4.
//
// What is verified here is the sum, not each wall's split. The split is a
// judgement about which wall a reason belongs to, and pinning it would make the
// test fail on a rewording rather than on a defect; a sum that disagrees with
// the row count is the defect, because it means the table describes a register
// that no longer exists.
func TestTheBurpWallsTableSumsToTheLostCount(t *testing.T) {
	raw, err := os.ReadFile(burpRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	lost := 0
	for _, row := range burpRows(t) {
		if row.verdict == verdictLost {
			lost++
		}
	}
	sum := 0
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		// A wall row is a reason, a plain count, and what would remove the wall.
		match := wallRowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value, convErr := strconv.Atoi(match[1])
		if convErr != nil {
			continue
		}
		sum += value
		found = true
	}
	if !found {
		t.Fatal("the register states no wall counts at all: the table describing " +
			"why capabilities are untransferred is absent")
	}
	if sum != lost {
		t.Errorf("the wall table accounts for %d rows, but %d rows are %q: a wall "+
			"table that does not add up describes a register that is not there",
			sum, lost, verdictLost)
	}
}

// wallRowPattern matches one wall row: a reason, a plain count, a remedy.
var wallRowPattern = regexp.MustCompile(`^\|\s*[^|]+\|\s*(\d+)\s*\|\s*[^|]+\|`)

// burpSummaryPattern reads a summary line of the shape
//
//	| `не перенесено` | **78** |
var burpSummaryPattern = regexp.MustCompile(
	"^\\|\\s*`([^`]+)`\\s*\\|\\s*\\*\\*(\\d+)\\*\\*\\s*\\|")

// burpRow is one parsed register row.
type burpRow struct {
	id         string
	capability string
	verdict    string
	reason     string
	symbol     string
	index      string
}

// burpRows parses the register into its rows, ignoring the header and the
// separator, and ignoring the summary table, whose names are not numbers.
func burpRows(t *testing.T) []burpRow {
	t.Helper()
	raw, err := os.ReadFile(burpRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	var rows []burpRow
	for _, line := range strings.Split(string(raw), "\n") {
		match := burpRowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		id := strings.TrimSpace(match[1])
		if _, err := strconv.Atoi(id); err != nil {
			continue // header row
		}
		rows = append(rows, burpRow{
			id:         id,
			capability: strings.TrimSpace(match[2]),
			verdict:    strings.TrimSpace(match[4]),
			reason:     strings.TrimSpace(match[6]),
			symbol:     strings.TrimSpace(match[7]),
			index:      strings.TrimSpace(burpIndexPattern.FindString(match[2])),
		})
	}
	return rows
}

func TestBurpRowCountIsPinnedToTheOriginalsCheckList(t *testing.T) {
	rows := burpRows(t)
	if len(rows) != burpUpstreamChecks {
		t.Fatalf("the register holds %d rows, the original's list has %d checks: %v",
			len(rows), burpUpstreamChecks, rowIDs(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.id] {
			t.Errorf("row %s appears twice", row.id)
		}
		seen[row.id] = true
	}
}

// A check whose type index is missing, or whose index names a different check,
// is a row about something else. This is the mechanical form of "the list is
// taken from the original": the register cannot describe 165 checks with one
// identifier repeated 164 times.
func TestEveryBurpRowNamesItsOwnTypeIndex(t *testing.T) {
	rows := burpRows(t)
	indexes := map[string]string{}
	for _, row := range rows {
		if row.index == "" {
			t.Errorf("row %s (%s) carries no type index", row.id, row.verdict)
			continue
		}
		if other, held := indexes[row.index]; held {
			t.Errorf("type index %s is claimed by row %s and row %s — one of them describes a different check",
				row.index, other, row.id)
			continue
		}
		indexes[row.index] = row.id
	}
	if len(indexes) != burpUpstreamChecks {
		t.Errorf("the register names %d distinct type indices for %d checks",
			len(indexes), burpUpstreamChecks)
	}
}

func TestEveryBurpRowHasAVerdictFromTheAllowedThree(t *testing.T) {
	for _, row := range burpRows(t) {
		if row.verdict == "" {
			t.Errorf("row %s carries no verdict", row.id)
			continue
		}
		if !allowedVerdicts[row.verdict] {
			t.Errorf("row %s carries verdict %q, which is not one of the three allowed",
				row.id, row.verdict)
		}
	}
}

func TestAnUntransferredBurpCapabilitySaysWhy(t *testing.T) {
	for _, row := range burpRows(t) {
		if row.verdict != verdictLost {
			continue
		}
		// A dash in the reason column is the shrug this rule exists to reject:
		// the reader cannot tell a decision from an omission.
		if row.reason == "" || row.reason == "—" {
			t.Errorf("row %s is %q with no reason", row.id, verdictLost)
		}
	}
}

// A row that claims coverage has to claim it in the tree. A symbol that exists
// nowhere is a row reporting something nobody built.
func TestBurpClaimedSymbolsExistInTheTree(t *testing.T) {
	for _, row := range burpRows(t) {
		if row.symbol == "" || row.symbol == "—" {
			continue
		}
		if !declaredAnywhere(burpSymbolOf(row.symbol)) {
			t.Errorf("row %s claims symbol %q (read as %q), which is not declared in the tree",
				row.id, row.symbol, burpSymbolOf(row.symbol))
		}
	}
}

// burpSymbolOf reads the Go type out of a symbol cell.
func burpSymbolOf(cell string) string {
	return burpSymbolPattern.FindString(strings.TrimSpace(cell))
}

// loadBurpRegister feeds this register into the package's coverage guard.
//
// `TestEveryDetectorAndChainIsCoveredDynamically` in
// `vexor_reconciliation_test.go` asks every module in `AllModules()` whether any
// register row names it, and it reads three registers by name. A fourth register
// is invisible to it, so the eleven detectors this register classifies — the
// twelve Burp checks carried in two batches — would be reported as
// unclassified despite their rows being present here. The guard is right that a
// module arriving without a row is a capability nobody decided on; the answer is
// for it to see the register, not for the row to stop existing.
func loadBurpRegister(t *testing.T) []registerRow {
	t.Helper()
	raw, err := os.ReadFile(burpRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	var out []registerRow
	for _, line := range strings.Split(string(raw), "\n") {
		match := burpRowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSpace(match[1])); err != nil {
			continue // header row
		}
		out = append(out, registerRow{
			capability: strings.TrimSpace(match[2]),
			symbol:     strings.TrimSpace(match[7]),
			verdict:    strings.TrimSpace(match[4]),
			reason:     strings.TrimSpace(match[6]),
			line:       strings.TrimSpace(line),
		})
	}
	return out
}

// burpRegisterRowsForNarrowGuard is the same register in the upstream guard's
// row type.
//
// There are two guards that ask whether a detector is classified, and they live
// in two other files: `TestEveryDetectorAndChainIsCoveredDynamically` in
// `vexor_reconciliation_test.go` and `TestEveryDetectorOfThisPortIsClassified`
// in `upstreams_reconciliation_test.go`. Both already learned that a guard
// reading one register produces false alarms about detectors another register
// covers — the second one was widened with `xssRegisterRowsForNarrowGuard` for
// exactly this reason. Twelve Burp checks arrived in two batches and belong to
// neither the VEXOR nor the upstream register, so both guards need this third
// conversion or they report a capability nobody decided on for a capability that
// is decided in writing here.
func burpRegisterRowsForNarrowGuard(t *testing.T) []upstreamRegisterRow {
	t.Helper()
	var out []upstreamRegisterRow
	for _, row := range burpRows(t) {
		out = append(out, upstreamRegisterRow{
			tool:       "Burp Suite scan checks",
			capability: row.capability,
			symbol:     row.symbol,
			verdict:    row.verdict,
			reason:     row.reason,
			line:       row.id,
		})
	}
	return out
}

func TestTheBurpRegisterPinsTheOriginalVersion(t *testing.T) {
	raw, err := os.ReadFile(burpRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, burpOriginalVersion) {
		t.Errorf("the register does not name the original version %s; a table against an unpinned "+
			"revision describes a different subject", burpOriginalVersion)
	}
	// The version and the row count have to agree with what the register says
	// about its own source, or the two statements can drift apart.
	if !strings.Contains(text, "**165 типів перевірок**") {
		t.Errorf("the register does not state the size of the list it is built against")
	}
}

// The summary is reconciled against the rows.
//
// A register whose prose says one thing and whose table says another is worse
// than a register with no summary: the number looks measured. The counts are
// computed here from the rows and compared with the register's own line.
func TestTheBurpSummaryMatchesTheRows(t *testing.T) {
	raw, err := os.ReadFile(burpRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	rows := burpRows(t)
	counted := map[string]int{}
	for _, row := range rows {
		counted[row.verdict]++
	}

	claimed := map[string]int{}
	for _, line := range strings.Split(string(raw), "\n") {
		match := burpSummaryPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if !allowedVerdicts[match[1]] {
			continue
		}
		value, err := strconv.Atoi(match[2])
		if err != nil {
			t.Errorf("summary line for %q holds %q, which is not a number", match[1], match[2])
			continue
		}
		claimed[match[1]] = value
	}
	for _, verdict := range sortedKeys(counted) {
		if claimed[verdict] != counted[verdict] {
			t.Errorf("the register's summary says %d rows are %q, but %d of them are",
				claimed[verdict], verdict, counted[verdict])
		}
	}
	// A verdict the rows hold that the summary never mentions is the same defect
	// in the other direction: a loss the reader is not told about.
	for _, verdict := range sortedKeys(claimed) {
		if counted[verdict] == 0 {
			t.Errorf("the summary reports %d rows as %q, but no row carries that verdict",
				claimed[verdict], verdict)
		}
	}
}

// rowIDs lists the row identifiers for a failure message, so a count mismatch
// names which row vanished rather than only how many.
func rowIDs(rows []burpRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.id)
	}
	sort.Strings(out)
	return out
}

// sortedKeys returns a map's keys in a stable order, so a failure reports the
// same verdict twice rather than a different one each run.
func sortedKeys(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for key := range counts {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
