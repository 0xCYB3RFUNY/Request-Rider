package active

// Tests for the misconfiguration detector.
//
// The behaviour worth pinning here is mostly about restraint. A hardening module
// that reports too much is a module whose one real finding gets read alongside
// three hundred rows about robots.txt, so the exemptions and the aggregation are
// tested as carefully as the detection.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type misconfigFixture struct {
	status  int
	header  http.Header
	body    string
	origins []string
}

func newMisconfigFixture(t *testing.T, f *misconfigFixture) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			f.origins = append(f.origins, origin)
		}
		for name, values := range f.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.body)
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL + "/account", Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"1"}},
	}
}

func (Misconfig) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return Misconfig{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

func fullHeaderSet() http.Header {
	header := http.Header{}
	for _, h := range hardeningHeaders {
		header.Set(h.name, "1")
	}
	return header
}

// A CORS check cannot be made without offering an origin, so the detector
// presents one and the server echoes it: that decision is now observable.
func TestMisconfigReportsReflectedOrigin(t *testing.T) {
	fixture := &misconfigFixture{status: 200, body: "<html><body>ok</body></html>"}
	transport, point := newMisconfigFixture(t, fixture)
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false,
		http.Header{"Origin": {"https://cors-probe.invalid"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Header.Set("Access-Control-Allow-Origin", "https://cors-probe.invalid")
	finding := corsFinding(point, resp, "https://cors-probe.invalid")
	if finding == nil {
		t.Fatal("a reflected origin was not reported")
	}
	if finding.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium without credentials", finding.Severity)
	}
	if !strings.Contains(finding.Evidence, "Access-Control-Allow-Origin") {
		t.Errorf("evidence = %q, want the header quoted", finding.Evidence)
	}
	if len(fixture.origins) == 0 {
		t.Error("no Origin was offered; a CORS check cannot be made without one")
	}
}

// Credentials turn a reflection into a full cross-origin read of an authenticated
// endpoint, which is a different severity.
func TestMisconfigRaisesSeverityWithCredentials(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200})
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Header.Set("Access-Control-Allow-Origin", "https://cors-probe.invalid")
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	finding := corsFinding(point, resp, "https://cors-probe.invalid")
	if finding == nil {
		t.Fatal("a credentialed reflection was not reported")
	}
	if finding.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high with credentials", finding.Severity)
	}
}

// `*` with credentials is rejected by every browser, so a server that sends it
// exposes nothing and reporting it would be a finding about a configuration no
// browser honours.
func TestMisconfigIgnoresWildcardWithCredentials(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200})
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Header.Set("Access-Control-Allow-Origin", "*")
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	if corsFinding(point, resp, "https://cors-probe.invalid") != nil {
		t.Error("reported a wildcard-with-credentials configuration no browser honours")
	}
}

// An origin the server names explicitly is an allow-list, not a defect.
func TestMisconfigIgnoresAnExplicitAllowList(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200})
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Header.Set("Access-Control-Allow-Origin", "https://partner.example")
	if corsFinding(point, resp, "https://cors-probe.invalid") != nil {
		t.Error("reported an explicitly allowed origin as a reflection")
	}
}

func TestMisconfigReportsMissingHeaders(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200, body: "ok"})
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Header.Set("Content-Security-Policy", "default-src 'self'")
	finding := headerFinding(point, resp)
	if finding == nil {
		t.Fatal("a missing header set was not reported")
	}
	if !strings.Contains(finding.Title, "X-Frame-Options") {
		t.Errorf("title = %q, want the missing headers named", finding.Title)
	}
	if !strings.Contains(finding.Evidence, "clickjacking") {
		t.Errorf("evidence = %q, want the reason each header is wanted", finding.Evidence)
	}
}

func TestMisconfigReportsNothingWhenHeadersAreComplete(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200, header: fullHeaderSet()})
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if headerFinding(point, resp) != nil {
		t.Error("reported missing headers on a response that carries them all")
	}
}

func TestMisconfigReportsDirectoryListing(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{
		status: 200, body: "<html><body><h1>Index of /uploads</h1></body></html>",
	})
	resp, err := transport.Do(context.Background(), http.MethodGet, point.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if listingFinding(point, resp) == nil {
		t.Error("a directory index was not reported")
	}
}

// The exemptions are exact, never by prefix — a prefix rule would exempt
// `/admin/login`, which is precisely a URL that should be reported.
func TestPublicResourceExemptionIsExactNotByPrefix(t *testing.T) {
	exempt := []string{
		"https://target.test/robots.txt", "https://target.test/sitemap.xml",
		"https://target.test/assets/app.css", "https://target.test/img/logo.SVG",
		"https://target.test/favicon.ico", "https://target.test/.well-known/security.txt",
	}
	for _, raw := range exempt {
		if !isPublicResource(raw) {
			t.Errorf("isPublicResource(%q) = false, want true", raw)
		}
	}
	notExempt := []string{
		"https://target.test/admin/login", "https://target.test/account",
		"https://target.test/robots.txt.bak", "https://target.test/api/users",
		"https://target.test/login.php", "https://target.test/",
	}
	for _, raw := range notExempt {
		if isPublicResource(raw) {
			t.Errorf("isPublicResource(%q) = true; a prefix rule would exempt it", raw)
		}
	}
}

func TestMisconfigSkipsPublicResourcesEntirely(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200, body: "ok"})
	point.URL = strings.TrimSuffix(point.URL, "/account") + "/robots.txt"
	if findings := (Misconfig{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none for a public resource", len(findings))
	}
}

// A site-wide gap is one row, not one per page. A report with four hundred
// identical rows is a report nobody reads to the end.
func TestAggregateHeaderFindingsCollapsesToOneRow(t *testing.T) {
	var findings []Finding
	for i := 0; i < 40; i++ {
		row, _ := NewFinding(Spec{
			Module: "misconfig", Title: "Missing Security Headers (X-Frame-Options)",
			Claimed: SeverityLow, Tier: TierVerified,
			Point: Point{URL: "https://target.test/page/" + string(rune('a'+i%26)) + itoaTest(i), Method: "GET"},
		})
		findings = append(findings, row)
	}
	crow, _ := NewFinding(Spec{
		Module: "misconfig", Title: "CORS Misconfiguration (origin reflected)",
		Claimed: SeverityMedium, Tier: TierVerified, Point: Point{URL: "https://target.test/api", Method: "GET"},
	})
	findings = append(findings, crow)

	aggregated := AggregateHeaderFindings(findings)
	if len(aggregated) != 2 {
		t.Fatalf("aggregated to %d rows, want 2 (one site-wide + the CORS row)", len(aggregated))
	}
	var site *Finding
	for i := range aggregated {
		if strings.Contains(aggregated[i].Title, "site-wide") {
			site = &aggregated[i]
		}
	}
	if site == nil {
		t.Fatal("no site-wide row")
	}
	if !strings.Contains(site.Title, "40 endpoints") {
		t.Errorf("title = %q, want the count", site.Title)
	}
	// The list is capped and the remainder counted, because a report that listed
	// eight of forty reads as if eight were affected.
	if !strings.Contains(site.Evidence, "and 32 more") {
		t.Errorf("evidence = %q, want the remainder counted rather than dropped", site.Evidence)
	}
}

// One affected endpoint is a per-endpoint problem and stays a single row.
func TestAggregateHeaderFindingsLeavesASingleEndpointAlone(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "misconfig", Title: "Missing Security Headers (X-Frame-Options)",
		Claimed: SeverityLow, Tier: TierVerified,
		Point: Point{URL: "https://target.test/one", Method: "GET"},
	})
	out := AggregateHeaderFindings([]Finding{row})
	if len(out) != 1 {
		t.Fatalf("rows = %d, want 1", len(out))
	}
	if strings.Contains(out[0].Title, "site-wide") {
		t.Error("a single affected endpoint was described as a site-wide gap")
	}
}

// Two rows for the same endpoint is one problem, not two. Without this the
// second guard in the aggregator looks redundant — the first one already refuses
// a single row — and a redundant guard is code nobody maintains.
func TestAggregateHeaderFindingsDoesNotAggregateOneEndpointTwice(t *testing.T) {
	var findings []Finding
	for i := 0; i < 2; i++ {
		row, _ := NewFinding(Spec{
			Module: "misconfig", Title: "Missing Security Headers (X-Frame-Options)",
			Claimed: SeverityLow, Tier: TierVerified,
			Point: Point{URL: "https://target.test/same", Method: "GET"},
		})
		findings = append(findings, row)
	}
	out := AggregateHeaderFindings(findings)
	for _, row := range out {
		if strings.Contains(row.Title, "site-wide") {
			t.Fatalf("aggregated two rows for one endpoint into %q", row.Title)
		}
	}
}

func itoaTest(v int) string {
	if v == 0 {
		return "0"
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte('0' + v%10)}, out...)
		v /= 10
	}
	return string(out)
}

func TestMisconfigReportsNothingOnCancellation(t *testing.T) {
	transport, point := newMisconfigFixture(t, &misconfigFixture{status: 200, body: "ok"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (Misconfig{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}
