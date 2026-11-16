package active

// Tests for the product fingerprint detector.
//
// The detector's whole claim is that it reads what the target published and
// says nothing else, so the tests are written against two things a mocked
// transport cannot check: that the module reports the version the *server*
// wrote rather than one the test handed it, and that reading it costs the
// target no requests at all.
//
// The version comparison is tested separately and as a table, because it is the
// one place in this module a wrong answer produces a confident false claim: a
// floor compared wrongly turns a supported release into an "end of life" row,
// and that sends someone to patch a host that does not need it.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// bannerFixture serves a response whose headers and body are the test's to
// write, and counts the requests it answered.
type bannerFixture struct {
	header http.Header
	body   string
	calls  atomic.Int64
}

func newBannerFixture(t *testing.T, header http.Header, body string) (*bannerFixture, *Transport, Point) {
	t.Helper()
	fixture := &bannerFixture{header: header, body: body}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.calls.Add(1)
		for name, values := range fixture.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, fixture.body)
	}))
	t.Cleanup(server.Close)

	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return fixture, transport, Point{URL: server.URL, Method: "GET", Values: map[string][]string{}}
}

func TestAnOutdatedBannerIsReportedWithItsVersionAndSource(t *testing.T) {
	header := http.Header{}
	header.Set("X-Powered-By", "PHP/7.4.33")
	fixture, transport, point := newBannerFixture(t, header, "")

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := fingerprint{}
	findings := module.Scan(context.Background(), transport, point, baseline)
	if len(findings) == 0 {
		t.Fatal("no finding for a PHP that published 7.4.33, a branch that stopped receiving fixes on 2022-11-28")
	}

	var eol *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "End-of-life") {
			eol = &findings[i]
		}
	}
	if eol == nil {
		t.Fatalf("no end-of-life row among %v", fingerprintTitles(findings))
	}
	if eol.Version != "7.4.33" {
		t.Errorf("Version = %q, want the version the server published", eol.Version)
	}
	if eol.VersionSource != "header:X-Powered-By" {
		t.Errorf("VersionSource = %q, want header:X-Powered-By — a number with no origin is not checkable", eol.VersionSource)
	}
	if eol.PatchState == "" {
		t.Error("PatchState is empty on a version-gated row; NewFinding sets UnverifiedPatch for exactly these")
	}
	if eol.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity %q exceeds the ceiling for tier %q", eol.Severity, eol.Tier)
	}
	if !strings.Contains(eol.Evidence, "PHP/7.4.33") {
		t.Errorf("evidence does not quote what the server wrote: %q", eol.Evidence)
	}

	// The detector is allowed to spend nothing: it reads the baseline the scan
	// already took. A probe here would be a request the operator did not ask
	// for, against a property this module claims in its own documentation.
	if got := fixture.calls.Load(); got != 1 {
		t.Errorf("the detector issued %d requests, want 1 (the baseline only)", got)
	}
}

func TestACurrentVersionProducesNoEndOfLifeRow(t *testing.T) {
	// 8.3.1 is on a maintained PHP branch, so the same header that produced a
	// row above must produce none here. A floor compared wrongly in one
	// direction is exactly as wrong as in the other.
	header := http.Header{}
	header.Set("X-Powered-By", "PHP/8.3.1")
	_, transport, point := newBannerFixture(t, header, "")

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := fingerprint{}
	for _, finding := range module.Scan(context.Background(), transport, point, baseline) {
		if strings.Contains(finding.Title, "End-of-life") {
			t.Errorf("reported a supported PHP as end of life: %q", finding.Title)
		}
	}
}

// TestASupportedProductWithNoKnownFloorIsNotClaimed guards the rule the module's
// documentation makes: a product this module has no defensible end-of-life
// claim about produces no such row.
//
// Apache httpd 2.4 is the case that matters. The first version of this table
// carried a row saying "Apache below 2.4.49 is end of life", which is false —
// the ASF still supports 2.4 — and every test agreed with it because the test
// asserted the table rather than the world. nginx is the standing example of a
// product that is deliberately absent: it has no dated end of support.
func TestASupportedProductWithNoKnownFloorIsNotClaimed(t *testing.T) {
	for _, banner := range []string{
		"Apache/2.4.49 (Ubuntu)",
		"Apache/2.4.62",
		"nginx/1.18.0",
		"nginx/1.27.0",
	} {
		header := http.Header{}
		header.Set("Server", banner)
		_, transport, point := newBannerFixture(t, header, "")

		baseline, err := transport.Baseline(context.Background(), point, false)
		if err != nil {
			t.Fatalf("Baseline: %v", err)
		}
		module := fingerprint{}
		for _, finding := range module.Scan(context.Background(), transport, point, baseline) {
			if strings.Contains(finding.Title, "End-of-life") {
				t.Errorf("%q reported as end of life: %q", banner, finding.Title)
			}
		}
	}
}

func TestTheVersionFloorIsComparedNotTheVersionLength(t *testing.T) {
	cases := []struct {
		version string
		floor   string
		below   bool
		why     string
	}{
		{"2.4.48", "2.4.49", true, "one patch below the fix"},
		{"2.4.49", "2.4.49", false, "exactly the floor"},
		{"2.4.50", "2.4.49", false, "one past the floor"},
		{"1.1.1g", "1.1.1k", true, "a patch letter orders alphabetically, and g < k"},
		{"1.1.1k", "1.1.1k", false, "the floor's own patch letter"},
		{"1.1.1t", "1.1.1k", false, "past the floor by letter"},
		{"1.1.1", "1.1.1k", true, "a bare release precedes its lettered patches"},
		{"1.1.1k", "1.1.1", false, "and a lettered patch follows the bare one"},
		{"2.4", "2.4.49", true, "a short banner is not newer than a full one"},
		{"2.4.0", "2.4", false, "a missing component is zero, so these are equal"},
		{"7.4.33", "8.0", true, "PHP 7.4 is below the maintained 8.0"},
		{"8.0.0", "8.0", false, "8.0 is the floor"},
		{"8.3.1", "8.0", false, "a minor release above the floor is supported"},
		{"9.1", "8.0", false, "a major jump is not below"},
		{"unknown", "2.4.49", false, "an unreadable version produces silence, not a claim"},
		{"2.4.49", "unknown", false, "an unreadable floor produces silence, not a claim"},
		{"", "2.4.49", false, "an empty version produces silence"},
	}
	for _, c := range cases {
		if got := below(c.version, c.floor); got != c.below {
			t.Errorf("below(%q, %q) = %v, want %v (%s)", c.version, c.floor, got, c.below, c.why)
		}
	}
}

func TestEveryEolFloorCarriesItsDateAndAFloor(t *testing.T) {
	// A half-filled row is a claim nobody can check. This is the test the
	// module's own documentation promises exists.
	for _, row := range eolTable {
		if row.floor == "" {
			t.Errorf("%s has a row with no floor: there is nothing to compare a version against", row.product)
		}
		if row.date == "" {
			t.Errorf("%s has a row with no end-of-life date", row.product)
		}
		if row.advisory == "" {
			t.Errorf("%s has a row with no advisory saying what stops being fixed", row.product)
		}
		if _, ok := parseVersion(row.floor); !ok {
			t.Errorf("%s floor %q is not a version this module can compare against", row.product, row.floor)
		}
		if len(row.date) != len("2006-01-02") {
			t.Errorf("%s date %q is not an ISO date, so a reader cannot place it", row.product, row.date)
		}
	}
}

func TestAnUnreadableBannerProducesSilence(t *testing.T) {
	header := http.Header{}
	header.Set("Server", "not a banner at all")
	_, transport, point := newBannerFixture(t, header, "")

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := fingerprint{}
	if findings := module.Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("reported %v from a banner with no version in it", fingerprintTitles(findings))
	}
}

func TestANilBaselineProducesNothing(t *testing.T) {
	// "I could not read the page" is not "this server runs nothing". Every other
	// detector in this package refuses for the same reason.
	module := fingerprint{}
	if findings := module.Scan(context.Background(), nil, Point{URL: "http://x/"}, nil); len(findings) != 0 {
		t.Errorf("reported %v with no baseline at all", fingerprintTitles(findings))
	}
}

func TestAVersionInTheBodyIsNotAHeaderDisclosure(t *testing.T) {
	// A page publishes its generator in HTML on purpose and every visitor sees
	// it, so the disclosure row is for headers only. The end-of-life row is a
	// separate claim and does still apply.
	_, transport, point := newBannerFixture(t, http.Header{},
		`<meta name="generator" content="WordPress 4.9">`)

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	module := fingerprint{}
	for _, finding := range module.Scan(context.Background(), transport, point, baseline) {
		if strings.Contains(finding.Title, "disclosed in") {
			t.Errorf("called a meta generator a header disclosure: %q", finding.Title)
		}
	}
}

func TestOneProductIsNotReportedTwiceForTheSameSource(t *testing.T) {
	header := http.Header{}
	// The same banner names Apache twice: once as the server and once inside
	// the parenthesised module list.
	header.Set("Server", "Apache/2.4.49 (Ubuntu) PHP/7.4.33")
	fixture, transport, point := newBannerFixture(t, header, "")

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	findings := fingerprint{}.Scan(context.Background(), transport, point, baseline)

	seen := map[string]int{}
	for _, finding := range findings {
		seen[finding.Module+"|"+finding.VersionSource+"|"+finding.Version]++
	}
	for key, count := range seen {
		if count > 1 {
			t.Errorf("%s reported %d times: %v", key, count, fingerprintTitles(findings))
		}
	}
	if fixture.calls.Load() != 1 {
		t.Errorf("the detector issued %d requests, want 1", fixture.calls.Load())
	}
}

// fingerprintTitles renders findings for a failure message.
func fingerprintTitles(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Title)
	}
	return out
}
