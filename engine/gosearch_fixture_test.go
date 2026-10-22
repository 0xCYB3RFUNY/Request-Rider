package main

// The fixture is part of the proof, so it has to be checked like one.
//
// `gosearch_fixture.json` is the single input both sides of the reconciliation are
// measured against. Without these checks a fixture can rot in three ways that all
// look like a green run: a capability drops out of it, it stops being exhaustive
// over the original's capabilities, or it starts carrying placeholders — and a
// fixture made of `example.com` measures **our own filtering** rather than our
// coverage, which is the exact failure the porting rule names.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const gosearchFixture = "gosearch_fixture.json"

type gosearchFixtureFile struct {
	UpstreamCommit string                     `json:"upstream_commit"`
	QueryUsername  string                     `json:"query_username"`
	QueryEmail     string                     `json:"query_email"`
	Capabilities   map[string]json.RawMessage `json:"capabilities"`
	Measured       json.RawMessage            `json:"measured_2026_10_07"`
}

func readGosearchFixture(t *testing.T) gosearchFixtureFile {
	t.Helper()
	raw, err := os.ReadFile(gosearchFixture)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchFixture, err)
	}
	var fixture gosearchFixtureFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("%s is not valid JSON: %v", gosearchFixture, err)
	}
	return fixture
}

// TestTheFixtureIsPresentAndPinned: the fixture is the evidence. Without it the
// registry's numbers are unreproducible, and a change upstream tomorrow would not
// check them.
func TestTheFixtureIsPresentAndPinned(t *testing.T) {
	fixture := readGosearchFixture(t)
	if len(fixture.UpstreamCommit) != 40 {
		t.Errorf("upstream_commit = %q, want the full 40-character commit", fixture.UpstreamCommit)
	}
	raw, err := os.ReadFile(gosearchRegistry)
	if err != nil {
		t.Fatalf("read the registry: %v", err)
	}
	if !strings.Contains(string(raw), fixture.UpstreamCommit[:7]) {
		t.Errorf("the registry does not pin the same commit the fixture was built against")
	}
}

// TestTheFixtureCoversEveryCapabilityTheRegistryPorted is the exhaustiveness
// check. A capability present in the registry and absent from the fixture means
// the reconciliation's claim about it was never measured.
func TestTheFixtureCoversEveryCapabilityTheRegistryPorted(t *testing.T) {
	fixture := readGosearchFixture(t)
	// One fixture entry per upstream module. `search_domains` covers
	// `utils.BuildDomains`, `github_keys` covers the four GitHub files.
	for _, capability := range []string{
		"proxynova", "breachdirectory", "weakpass", "gravatar",
		"keybase", "hudsonrock", "github_keys", "search_domains",
	} {
		if _, ok := fixture.Capabilities[capability]; !ok {
			t.Errorf("the fixture has no entry for %q", capability)
		}
	}
}

// TestTheFixtureCarriesNoPlaceholders: this is the check that would have caught
// the measured mistake the rule is named after.
//
// `example.com`, `EXAMPLE`, `AKIA…EXAMPLE` and friends are rejected by this
// project's own filters **by design**. A fixture built from them would measure the
// filters rather than the port, and every number in the registry would be a
// statement about the wrong thing.
func TestTheFixtureCarriesNoPlaceholders(t *testing.T) {
	raw, err := os.ReadFile(gosearchFixture)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchFixture, err)
	}
	text := string(raw)
	// The comment fields are documentation and are allowed to *name* a
	// placeholder; only the data may not contain one.
	for _, placeholder := range []string{
		`"example.com"`, `"EXAMPLE"`, `"AKIA`, `"your-`, `"TODO"`, `"FIXME"`,
		`"changeme"`, `"password123"`, `"test@example"`,
	} {
		if strings.Contains(text, placeholder) {
			t.Errorf("the fixture contains %s; a fixture of placeholders measures our filtering, not our coverage", placeholder)
		}
	}
}

// TestTheFixtureCarriesTheShapesThatBrokeTheOriginal is the reason the fixture has
// the values it has. Each entry below is a body that defeats the original's
// implementation, and a fixture without it would let a regression in our fix pass.
func TestTheFixtureCarriesTheShapesThatBrokeTheOriginal(t *testing.T) {
	raw, err := os.ReadFile(gosearchFixture)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchFixture, err)
	}
	text := string(raw)
	for name, needle := range map[string]string{
		"a password containing colons":                `p:a:ss:word`,
		"a line with no separator":                    `"no-separator-here"`,
		"a count that disagrees":                      `"count": 4`,
		"an entry carrying its own password":          `"password": "Winter2019"`,
		"an entry with no password":                   `"password": ""`,
		"a non-zero service status":                   `"code": 205`,
		"an empty stealers list":                      `"stealers": []`,
		"a message the original's literal would miss": "Nothing on file for this identifier.",
		"two keys of one type":                        "ExampleKeyMaterialTwo",
		"a GitHub privacy placeholder":                "users.noreply.github.com",
		"only a 204 is evidence":                      `"follower-alpha": 204`,
		"a 404 is not a mutual":                       `"follower-beta": 404`,
		"a redirect is answered":                      `"ibnaleem.io": 301`,
	} {
		if !strings.Contains(text, needle) {
			t.Errorf("the fixture no longer carries %s (%s); the fix it guards has no evidence", name, needle)
		}
	}
}

// TestTheFixtureRecordsBothSidesOfTheMeasurement: the rule requires the original to
// be run separately on the same bytes and both numbers kept. A registry whose
// fixture records only our side has not done the comparison it claims.
func TestTheFixtureRecordsBothSidesOfTheMeasurement(t *testing.T) {
	fixture := readGosearchFixture(t)
	if len(fixture.Measured) == 0 {
		t.Fatal("the fixture records no measurement")
	}
	raw, err := os.ReadFile(gosearchFixture)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchFixture, err)
	}
	text := string(raw)
	for _, needle := range []string{
		`"upstream_`, `"ours_`,
	} {
		if !strings.Contains(text, needle) {
			t.Errorf("the fixture records no %s figure", strings.Trim(needle, `"`))
		}
	}
}

// TestTheRegistryAndTheFixtureAgreeOnTheDomains: both sides measured the same
// three names on the same day. A drift here means one of the two numbers was
// written from memory rather than from a run.
func TestTheRegistryAndTheFixtureAgreeOnTheDomains(t *testing.T) {
	fixture := readGosearchFixture(t)
	var measured struct {
		UpstreamDomains int      `json:"upstream_domains_found"`
		OursDomains     int      `json:"ours_domains_found"`
		OursNames       []string `json:"ours_domains"`
		UpstreamMode    string   `json:"upstream_report_file_mode"`
		OursMode        string   `json:"ours_report_file_mode"`
	}
	if err := json.Unmarshal(fixture.Measured, &measured); err != nil {
		t.Fatalf("the measured block is not an object: %v", err)
	}
	if measured.UpstreamDomains == 0 || measured.OursDomains == 0 {
		t.Fatalf("the domain measurement is missing: %+v", measured)
	}
	if measured.UpstreamDomains != measured.OursDomains {
		t.Errorf("the two sides found %d and %d domains; one of those numbers was not measured",
			measured.UpstreamDomains, measured.OursDomains)
	}
	if len(measured.OursNames) != measured.OursDomains {
		t.Errorf("the fixture names %d domains but reports %d found", len(measured.OursNames), measured.OursDomains)
	}
	// The one deliberate behavioural departure, recorded as a fact: the original's
	// file was world-writable and ours is not.
	if measured.UpstreamMode == measured.OursMode {
		t.Errorf("both sides recorded report mode %s; the fixture must record the difference it claims",
			measured.UpstreamMode)
	}
}
