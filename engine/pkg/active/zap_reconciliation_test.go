package active

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const zapRegisterFile = "zap_reconciliation.md"

// zapOriginalCommit is the commit in zap-extensions where the 74 scan rules were audited.
const zapOriginalCommit = "a55ab8eb9e4a317226f5d020a403fc3c55ae3f24"

// zapUpstreamChecks is the total count of active scan rules across addOns/ascanrules*.
const zapUpstreamChecks = 74

var zapRowPattern = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|`)
var zapIndexPattern = regexp.MustCompile(`0[xX][0-9A-Fa-f]{8}`)
var zapSymbolPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

type zapRow struct {
	id         string
	capability string
	verdict    string
	reason     string
	symbol     string
	index      string
}

func zapRows(t *testing.T) []zapRow {
	t.Helper()
	raw, err := os.ReadFile(zapRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	var rows []zapRow
	for _, line := range strings.Split(string(raw), "\n") {
		match := zapRowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		id := strings.TrimSpace(match[1])
		if _, err := strconv.Atoi(id); err != nil {
			continue // header row
		}
		rows = append(rows, zapRow{
			id:         id,
			capability: strings.TrimSpace(match[2]),
			verdict:    strings.TrimSpace(match[4]),
			reason:     strings.TrimSpace(match[6]),
			symbol:     strings.TrimSpace(match[7]),
			index:      strings.TrimSpace(zapIndexPattern.FindString(match[2])),
		})
	}
	return rows
}

func TestZAPRowCountIsPinnedToTheOriginalsCheckList(t *testing.T) {
	rows := zapRows(t)
	if len(rows) != zapUpstreamChecks {
		t.Fatalf("the register holds %d rows, the original list has %d checks",
			len(rows), zapUpstreamChecks)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.id] {
			t.Errorf("row %s appears twice", row.id)
		}
		seen[row.id] = true
	}
}

func TestTheZAPWallsTableSumsToTheLostCount(t *testing.T) {
	raw, err := os.ReadFile(zapRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	lost := 0
	for _, row := range zapRows(t) {
		if row.verdict == verdictLost {
			lost++
		}
	}
	sum := 0
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
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
		t.Fatal("the register states no wall counts at all")
	}
	if sum != lost {
		t.Errorf("the wall table accounts for %d rows, but %d rows are %q",
			sum, lost, verdictLost)
	}
}

func TestZAPVerdictsAreOneOfThree(t *testing.T) {
	for _, row := range zapRows(t) {
		switch row.verdict {
		case verdictMatched, verdictImproved, verdictLost:
		default:
			t.Errorf("row %s has unknown verdict %q", row.id, row.verdict)
		}
	}
}

func TestZAPLostRowsCarryReasons(t *testing.T) {
	for _, row := range zapRows(t) {
		if row.verdict == verdictLost && row.reason == "" {
			t.Errorf("row %s is lost without a reason", row.id)
		}
	}
}

func TestZAPSymbolsExistInTree(t *testing.T) {
	for _, row := range zapRows(t) {
		if row.verdict == verdictLost {
			continue
		}
		name := zapSymbolPattern.FindString(row.symbol)
		if name == "" {
			t.Errorf("row %s names no Go symbol: %q", row.id, row.symbol)
			continue
		}
		if !declaredAnywhere(name) {
			t.Errorf("row %s claims symbol %q, which is not declared in the tree",
				row.id, name)
		}
	}
}

func TestZAPOriginalCommitIsRecorded(t *testing.T) {
	raw, err := os.ReadFile(zapRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	if !strings.Contains(string(raw), zapOriginalCommit) {
		t.Errorf("the register does not name upstream commit %s", zapOriginalCommit)
	}
}

func TestZAPIndexesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, row := range zapRows(t) {
		if row.index == "" {
			t.Errorf("row %s has no hex plugin index", row.id)
			continue
		}
		if previous, duplicate := seen[row.index]; duplicate {
			t.Errorf("index %s is used on row %s and row %s", row.index, previous, row.id)
		}
		seen[row.index] = row.id
	}
}
