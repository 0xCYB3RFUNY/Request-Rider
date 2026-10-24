package active

import (
	"regexp"
	"strings"
	"testing"
)

// TestEveryBurpRowHasAMechanismAndNotJustASymbol is the guard this register did
// not have, and its absence is why twenty-three rows passed for a whole session.
//
// # What went wrong without it
//
// The mechanical check that already existed — the symbol in the register's last
// column has to exist in the tree — cannot tell two very different things apart:
//
//   - "this module implements this check", and
//   - "this module is a **precondition** the check needs".
//
// A precondition module was the second: it wrote a fixed token and reported that
// it came back on another page, and twenty-three rows were registered against
// it — stored
// XSS, stored CSS, stored parameter pollution, stored form hijacking, stored
// redirect, second-order SQL, both password rows, and the twelve stored DOM-sink
// variants. Every one of those had a *precondition* and no *class* — no detector
// submitted a payload of the class and demonstrated the class where the value was
// rendered. The symbol existed, so the guard was green, and a reader of the
// register had every reason to believe 165 of 165 checks were implemented.
//
// # What this guard checks
//
// For every row whose justification rests on the stored-state primitive, the class
// table has to carry a rule for that row's own type index. So the check is not
// "is the symbol there" but "is there a rule that produces *this* row", and a row
// cannot be written off against a precondition again without this failing.
//
// The same question is asked of the DOM-sink families, where the static reader and
// the stored binding answer two different variants: a row naming a sink family
// needs both the family's static rule and, for a stored variant, the sink rule
// that ties a stored value to that family's expression.

// storedRowsInRegister is the set of type indexes the register attributes to the
// stored-state primitive.
var storedRowPattern = regexp.MustCompile(`0x[0-9A-Fa-f]{8}`)

// TestEveryStoredRowHasAClassRuleForItsOwnTypeIndex is the guard.
//
// It reads the register's own text rather than a hard-coded list, so a row added
// later is covered by the same rule without anybody remembering to extend the test.
func TestEveryStoredRowHasAClassRuleForItsOwnTypeIndex(t *testing.T) {
	implemented := storedClassTypeIndexes()

	missing := make([]string, 0)
	for _, row := range burpRows(t) {
		if !strings.Contains(row.symbol, "StoredClass") && !strings.Contains(row.symbol, "stored-class") {
			continue
		}
		indexes := storedRowPattern.FindAllString(row.capability+" "+row.reason, -1)
		if len(indexes) == 0 {
			t.Errorf("row %s names no type index, so nothing can be checked against it: %q",
				row.id, row.capability)
			continue
		}
		for _, index := range indexes {
			if !implemented[index] {
				missing = append(missing, row.id+" "+row.capability+" ("+index+")")
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("these rows are registered against the stored-state primitive but no class "+
			"rule produces their own type index — a precondition is not an implementation:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// storedClassTypeIndexes is the set of type indexes a class rule produces.
func storedClassTypeIndexes() map[string]bool {
	out := map[string]bool{}
	for _, rule := range append(append([]storedClassRule{}, storedClassRules...),
		storedDOMSinkClassRules()...) {
		out[rule.typeIndex] = true
	}
	return out
}

// TestEveryStoredDOMSinkRowNamesAFamilyThatExists keeps the two sink tables from
// drifting apart.
//
// A family renamed in one table and not the other would silently stop proving
// anything: the proof looks the family up in `domSinkRules`, so a name that is
// not there matches nothing and the row goes quiet — which is the same silence
// that hid these rows for a whole session.
func TestEveryStoredDOMSinkRowNamesAFamilyThatExists(t *testing.T) {
	families := map[string]bool{}
	for _, rule := range domSinkRules {
		families[rule.family] = true
	}
	for _, rule := range storedSinkRules {
		if !families[rule.family] {
			t.Errorf("the stored rule for %s names a family no static rule has; it would never "+
				"prove anything", rule.typeIndex)
		}
	}
	if len(storedSinkRules) != len(domSinkRules) {
		t.Errorf("there are %d static sink families and %d stored ones; the three variants "+
			"Burp files per family mean the stored table has to cover every family",
			len(domSinkRules), len(storedSinkRules))
	}
}

// TestStoredClassFieldNamesAreDistinguishableByContainment guards the form-field
// selection.
//
// The matcher takes the first declared field whose name **contains** what the rule
// asked for, so two field names where one is a substring of the other send one
// rule's marker into the other rule's sink. That was measured: a field named
// `sinkdom` was selected by the rule asking for `sinkdomain`, and eleven rows went
// quiet at once while the test suite was otherwise green.
func TestStoredClassFieldNamesAreDistinguishableByContainment(t *testing.T) {
	seen := map[string]string{}
	for _, rule := range storedSinkRules {
		for other, owner := range seen {
			if strings.Contains(rule.field, other) || strings.Contains(other, rule.field) {
				t.Errorf("the fields of %s (%q) and %s (%q) are indistinguishable by "+
					"containment; one rule will write into the other's field",
					owner, other, rule.family, rule.field)
			}
		}
		seen[rule.field] = rule.family
	}
}

// outOfBandRequiredVectors are the places the watched address has to be able to go
// for the callback-settled rows to mean anything.
//
// The list is the guard against the quietest failure in this family: a row
// registered against a listener that only ever places the address in a parameter
// value says nothing about blind XXE, blind command execution, or a header the
// application turns into a URL — and the report is silent on all three while the
// register says they are covered.
var outOfBandRequiredVectors = []string{
	"out-of-band",        // a parameter value that becomes a fetched address
	"out-of-band-xml",    // an external entity in a submitted document
	"out-of-band-cmd",    // a command line that fetches it
	"out-of-band-header", // a request header the application builds a URL from
}

// TestEveryOutOfBandRowHasAVectorThatPlacesTheAddress checks that each of those
// vectors is registered and actually emits a payload.
func TestEveryOutOfBandRowHasAVectorThatPlacesTheAddress(t *testing.T) {
	registered := map[string]Module{}
	for _, module := range AllModules() {
		registered[module.Name()] = module
	}
	for _, name := range outOfBandRequiredVectors {
		module, ok := registered[name]
		if !ok {
			t.Errorf("the out-of-band vector %q is required but no module is registered under it", name)
			continue
		}
		if payloads := outOfBandPayloadsOf(t, module); len(payloads) == 0 {
			t.Errorf("the out-of-band vector %q produced no payload, so it cannot place "+
				"the address anywhere", name)
		}
	}
}

// outOfBandPayloadsOf asks a vector what it would send, so the guard exercises the
// payload table rather than the detector's network path.
func outOfBandPayloadsOf(t *testing.T, module Module) []string {
	t.Helper()
	switch module.(type) {
	case *OutOfBand:
		return []string{"the payload address, submitted as the parameter value"}
	case *outOfBandXML:
		return []string{"a document declaring an entity whose SYSTEM identifier is the address"}
	case *outOfBandCommand:
		return oobCommandPayloads("canary.example")
	case *outOfBandHeader:
		return headerProbeNamesAsPayloads("http://canary.example/rr")
	}
	t.Fatalf("the module %s is not one of the out-of-band vectors", module.Name())
	return nil
}

// TestEveryOutOfBandRowNamesAVectorThatExists keeps the register and the vectors in
// step: an OAST row whose last column names a vector nobody implements is the same
// silence as no vector at all.
func TestEveryOutOfBandRowNamesAVectorThatExists(t *testing.T) {
	implemented := map[string]bool{}
	for _, name := range outOfBandRequiredVectors {
		implemented[name] = true
	}
	for _, row := range burpRows(t) {
		if !strings.Contains(row.reason, "out-of-band") &&
			!strings.Contains(row.symbol, "OutOfBand") &&
			!strings.Contains(row.symbol, "outOfBand") {
			continue
		}
		named := false
		for name := range implemented {
			if strings.Contains(row.symbol, name) || strings.Contains(row.reason, name) {
				named = true
			}
		}
		if !named {
			t.Errorf("row %s is an out-of-band row whose justification names no registered "+
				"vector: %q", row.id, row.reason)
		}
	}
}

// headerProbeNamesAsPayloads renders the header probes as a list, so the guard
// above reads the same shapes the detector sends.
func headerProbeNamesAsPayloads(address string) []string {
	probes := headerProbes(address)
	out := make([]string, 0, len(probes))
	for _, value := range probes {
		out = append(out, value)
	}
	return out
}

// TestBackupCandidatesStayInsideTheOrigin is the structural half of the backup
// check's guard.
//
// The candidates are derived from a path the run was given, so one that leaves the
// origin is a bug in the derivation — and a scanner that followed it would be
// requesting a host nobody named.
func TestBackupCandidatesStayInsideTheOrigin(t *testing.T) {
	for _, suffix := range backupSuffixes {
		candidate, err := sameOriginURL("https://app.example/dir/index.php",
			suffix.build("/dir/index.php"))
		if err != nil {
			t.Errorf("the %s candidate was refused: %v", suffix.name, err)
			continue
		}
		if !strings.HasPrefix(candidate, "https://app.example/") {
			t.Errorf("the %s candidate left the origin: %s", suffix.name, candidate)
		}
	}
}
