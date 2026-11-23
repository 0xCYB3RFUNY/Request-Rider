package active

// The level contract, and the chain built on it.
//
// `Module.Level` is a declaration every detector makes and every dispatcher used
// to ignore. That is not a cosmetic gap: the two detectors that declare
// `LevelEndpoint` — the credential reader and the header reader — were only ever
// handed surfaces that happened to have a form, so on any application whose
// pages carry no forms they reported nothing at all. The first test here is
// written to fail on that behaviour rather than on a missing return value.
//
// The chain tests are written the same way: each one names the ingredient or the
// tier it needs, because a correlation rule that fires on "both findings
// exist" instead of "both findings are proven and on the same host" is a rule
// that reports a coincidence.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A page with no form at all, printing a credential. Nothing here is an
// injectable surface, so with the level contract ignored the credential reader
// is never given this page and the finding does not exist.
func TestAnEndpointLevelDetectorRunsOnAPageWithNoForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			// No form, no input, no link: a page whose only content is a
			// configuration dump that leaked into the template.
			fmt.Fprint(w, "<html><body><pre>STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz</pre></body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>nothing</body></html>")
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		// The probe is off so this test measures the level contract alone: every
		// request below comes from the crawl and the detectors.
		InterestingPaths: []string{},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range report.Findings {
		if strings.Contains(f.Title, "Stripe") {
			return
		}
	}
	t.Fatalf("a credential printed by a page with no form produced no finding; findings were %q",
		titlesOf(report.Findings))
}

// The counterpart: a detector that fires payloads is never handed a bare URL. An
// injection finding has to name a parameter, and a row without one is a row
// nobody can reproduce.
func TestAParameterLevelDetectorIsNeverGivenABareUrl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>plain, no form, no parameters</body></html>")
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		InterestingPaths: []string{},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range report.Findings {
		switch f.Module {
		case "sqli", "xss", "lfi", "cmdi", "ssti", "ssrf", "redirect":
			if f.Param == "" {
				t.Fatalf("the %s detector reported %q with no parameter, so there is nothing to "+
					"reproduce: a parameter-level detector was handed a bare URL", f.Module, f.Title)
			}
		}
	}
}

// --- ssrf + exposed configuration ------------------------------------------

func ssrfFinding(host string) Finding {
	return Finding{
		ID: "f-ssrf", Module: "ssrf", Title: "SSRF: the parameter fetches an attacker-chosen URL",
		Severity: SeverityHigh, Tier: TierVerified, Endpoint: host + "/api/fetch", Method: "GET",
		Param: "url", Evidence: "the request returned a body the target does not hold itself",
	}
}

func configFinding(host, title, evidence string) Finding {
	return Finding{
		ID: "f-cfg", Module: "exposure", Title: title, Severity: SeverityCritical,
		Tier: TierVerified, Endpoint: host + "/actuator/env", Method: "GET", Evidence: evidence,
	}
}

// Both halves proven, the exposed file carries a credential, same host: critical.
func TestSSRFAndAConfigurationWithCredentialsCompose(t *testing.T) {
	rule := &ChainSSRFToConfigExposure{}
	in := ChainInput{Findings: []Finding{
		ssrfFinding("https://shop.example"),
		configFinding("https://shop.example", "Connection String with Credentials",
			"mongodb://app:s3cr3tpassword@10.0.0.9:27017/orders"),
	}}
	finding := rule.Apply(context.Background(), in)
	if finding == nil {
		t.Fatal("a proven SSRF and a proven configuration carrying a password did not compose")
	}
	if finding.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical: the exposure finding already demonstrated a credential",
			finding.Severity)
	}
	if finding.Tier != TierVerified {
		t.Fatalf("tier = %s, want verified", finding.Tier)
	}
	if len(finding.ChainOf) != 2 {
		t.Fatalf("chain_of = %v, want both ingredient ids", finding.ChainOf)
	}
}

// The exposed file is readable but holds nothing that authenticates. The pair is
// still reported — a reachable service and a readable file is worth an
// operator's time — but not as a proven credential theft.
func TestSSRFAndAConfigurationWithoutCredentialsStayPotential(t *testing.T) {
	rule := &ChainSSRFToConfigExposure{}
	in := ChainInput{Findings: []Finding{
		ssrfFinding("https://shop.example"),
		configFinding("https://shop.example", "Exposed configuration file",
			"APP_ENV=production\nAPP_DEBUG=false"),
	}}
	finding := rule.Apply(context.Background(), in)
	if finding == nil {
		t.Fatal("the pair was dropped: an operator should still see a reachable service beside a " +
			"readable configuration file")
	}
	if finding.Tier != TierPotential {
		t.Fatalf("tier = %s, want potential: nothing in the file was shown to authenticate", finding.Tier)
	}
	if !finding.Capped {
		t.Fatal("an unproven chain row must be reported as capped, so the downgrade is visible")
	}
	if !strings.Contains(finding.Evidence, "not established") {
		t.Fatalf("the row does not name what is missing: %q", finding.Evidence)
	}
}

// Two hosts are two problems. An SSRF on one deployment and a leaked `.env` on
// another do not compose, and correlating them because one scan found both is
// how a chain report becomes a coincidence list.
func TestSSRFAndAConfigurationOnDifferentHostsDoNotCompose(t *testing.T) {
	rule := &ChainSSRFToConfigExposure{}
	in := ChainInput{Findings: []Finding{
		ssrfFinding("https://shop.example"),
		configFinding("https://cdn.example", "Connection String with Credentials",
			"postgres://app:s3cr3t@10.0.0.9:5432/orders"),
	}}
	if finding := rule.Apply(context.Background(), in); finding != nil {
		t.Fatalf("composed across hosts: %q", finding.Title)
	}
}

// An unproven ingredient is not an ingredient.
func TestAnUnprovenIngredientDoesNotCompose(t *testing.T) {
	rule := &ChainSSRFToConfigExposure{}
	weak := configFinding("https://shop.example", "Connection String with Credentials",
		"postgres://app:s3cr3t@10.0.0.9:5432/orders")
	weak.Tier = TierPotential
	weak.Severity = SeverityMedium
	in := ChainInput{Findings: []Finding{ssrfFinding("https://shop.example"), weak}}
	if finding := rule.Apply(context.Background(), in); finding != nil {
		t.Fatalf("composed from a potential ingredient: %q", finding.Title)
	}
}

// An exposure finding that is not about configuration is a real finding and not
// this chain's ingredient.
func TestSSRFAndAnIncidentalExposureDoNotCompose(t *testing.T) {
	rule := &ChainSSRFToConfigExposure{}
	incidental := configFinding("https://shop.example", "GitHub Token", "ghp_...")
	incidental.Endpoint = "https://shop.example/assets/app.js"
	in := ChainInput{Findings: []Finding{ssrfFinding("https://shop.example"), incidental}}
	if finding := rule.Apply(context.Background(), in); finding != nil {
		t.Fatalf("composed from a token in a script file: %q", finding.Title)
	}
}

// The rule issues no request. It correlates two exchanges that already happened,
// and a chain rule that sends traffic to turn a correlation into a proof is a
// second scanner wearing a chain's name.
func TestTheSSRFChainIssuesNoRequest(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>plain</body></html>")
	}))
	defer server.Close()

	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	in := ChainInput{
		Transport: transport,
		Findings: []Finding{
			ssrfFinding(server.URL),
			configFinding(server.URL, "Connection String with Credentials",
				"redis://app:s3cr3t@10.0.0.9:6379/0"),
		},
	}
	rule := &ChainSSRFToConfigExposure{}
	if rule.Apply(context.Background(), in) == nil {
		t.Fatal("the rule did not compose its ingredients")
	}
	if requests != 0 {
		t.Fatalf("the rule made %d request(s) against the target", requests)
	}
	if transport.Requests() != 0 {
		t.Fatalf("the transport counted %d request(s) for a rule that sends none", transport.Requests())
	}
}
