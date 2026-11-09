package active

// The register test for `hunner_reconciliation.md`.
//
// It enforces the same five rules as `nikto_reconciliation_test.go`, and for the
// same reason. A register built by "compare what we have" cannot see a capability
// nobody carried over: the row is absent, and an absent row reads as "nothing was
// lost". `AGENTS.md` puts the remedy in one line — перелік знімається з файлів
// оригіналу — and this file is what makes that mechanical instead of a promise.
//
//   - the row count is pinned to the function list upstream declares, so a row
//     cannot be deleted quietly;
//   - a verdict is one of exactly three, so "in progress" cannot stand in for a
//     loss;
//   - `не перенесено` carries a reason, so a decision cannot read as an omission;
//   - a claimed symbol exists in the tree, so a row cannot report coverage nobody
//     has;
//   - the upstream commit is recorded here as well as in the register, so a table
//     written against a revision that never existed cannot pass.
//
// The verdict vocabulary is not redeclared: `allowedVerdicts` and `verdictLost`
// come from `vexor_reconciliation_test.go`, because two copies of a closed set of
// three values drift apart the moment one of them gets a typo.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const hunnerRegisterFile = "hunner_reconciliation.md"

// hunnerCommit is the upstream revision this register describes.
//
// Hunner has had exactly one merge commit since 2019, so this is also upstream HEAD
// as measured on 2026-10-03: `git rev-parse HEAD` in a fresh clone of
// https://github.com/b3-v3r/Hunner.git. Recording it in two places is the point —
// changing one without the other fails the test, which is exactly the moment a
// reader should be told the table is stale.
const hunnerCommit = "5e46a4532469df816e0a4329671cb76fb1300d74"

// hunnerUpstreamFunctions is the list of capabilities taken from the original's
// files, not from what this project happens to have. Twenty-four functions are
// declared by upstream:
//
//	hunner.py                 info heads banner XXS desc SQL Dos SSH_Brut FTP_Brut mail Main_Menu
//	modules/banner.py         (module, no function)
//	modules/dos.py            dos dos2
//	modules/ftp.py            connect
//	modules/hun_listener.py   clear banner connect_ssh main
//	modules/mail.py           banner clear check_mail brut
//	modules/ssh.py            brut
//
// Pinned as a count so that deleting a row fails here rather than quietly
// succeeding in the file.
const hunnerUpstreamFunctions = 24

// hunnerRowPattern splits a register row. The upstream layout has seven columns and
// the two that matter beyond the verdict are the reason and the symbol, so all seven
// are captured rather than the four the shared pattern takes.
var hunnerRowPattern = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|`)

// hunnerRows parses the register into its rows, ignoring the header and the
// separator.
func hunnerRows(t *testing.T) []struct {
	id, verdict, reason, symbol string
} {
	t.Helper()
	raw, err := os.ReadFile(hunnerRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	var rows []struct {
		id, verdict, reason, symbol string
	}
	for _, line := range strings.Split(string(raw), "\n") {
		match := hunnerRowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		id := strings.TrimSpace(match[1])
		if _, err := strconv.Atoi(id); err != nil {
			continue // header row
		}
		rows = append(rows, struct{ id, verdict, reason, symbol string }{
			id:      id,
			verdict: strings.TrimSpace(match[4]),
			reason:  strings.TrimSpace(match[6]),
			symbol:  strings.TrimSpace(match[7]),
		})
	}
	return rows
}

func TestHunnerRowCountIsPinnedToTheOriginalsFunctionList(t *testing.T) {
	rows := hunnerRows(t)
	if len(rows) != hunnerUpstreamFunctions {
		t.Fatalf("the register holds %d rows, upstream declares %d functions: %v",
			len(rows), hunnerUpstreamFunctions, func() []string {
				var ids []string
				for _, row := range rows {
					ids = append(ids, row.id)
				}
				return ids
			}())
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.id] {
			t.Errorf("row %s appears twice", row.id)
		}
		seen[row.id] = true
	}
}

func TestEveryHunnerRowHasAVerdictFromTheAllowedThree(t *testing.T) {
	for _, row := range hunnerRows(t) {
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

func TestAnUntransferredHunnerCapabilitySaysWhy(t *testing.T) {
	for _, row := range hunnerRows(t) {
		if row.verdict != verdictLost {
			continue
		}
		// A dash in the reason column is the shrug this rule exists to reject: the
		// reader cannot tell a decision from an omission.
		if row.reason == "" || row.reason == "—" {
			t.Errorf("row %s is %q with no reason", row.id, verdictLost)
		}
	}
}

func TestHunnerClaimedSymbolsExistInTheTree(t *testing.T) {
	for _, row := range hunnerRows(t) {
		if row.symbol == "" || row.symbol == "—" {
			continue
		}
		if !declaredAnywhere(row.symbol) {
			t.Errorf("row %s claims symbol %q, which is not declared in the tree", row.id, row.symbol)
		}
	}
}

func TestTheHunnerRegisterPinsTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(hunnerRegisterFile)
	if err != nil {
		t.Fatalf("reading the register: %v", err)
	}
	if !strings.Contains(string(raw), hunnerCommit) {
		t.Errorf("the register does not record upstream commit %s; a table against an unpinned revision describes a different subject", hunnerCommit)
	}
}
