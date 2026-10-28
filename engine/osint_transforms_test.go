package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `username_enum` is the local one and stays that way. `email_recon` is not, and
// this test used to assert that it was — it called `email_recon` with no
// confirmation and required two entities and no network use, which is the exact
// contract that kept the social-profile probe unreachable: the registry said
// `network: false`, the page sent no confirmation, and the run answered with the
// local normalization while reporting that verification was disabled.
//
// So the local half is pinned here on the transform that still is local, and
// `email_recon`'s own contract — a network transform that refuses an unconfirmed
// run and probes when confirmed — is pinned in `osint_email_recon_test.go`. The
// normalization `email_recon` used to be checked for is still checked there: it
// runs before the probe and both entities survive it.
func TestLocalUsernameTransformsAreNetworkFree(t *testing.T) {
	server := &server{}
	for _, transform := range []string{"username_enum", "username_normalize"} {
		result, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: transform, Value: "analyst_01",
		})
		if err != nil {
			t.Fatalf("%s: %v", transform, err)
		}
		if !result.LocalOnly || result.NetworkUsed || len(result.Entities) != 1 {
			t.Fatalf("%s result = %#v", transform, result)
		}
	}
}

// The local email normalization is still reachable, on the transform that is
// registered as local. Without this, marking `email_recon` as a network transform
// would have quietly taken away a capability the operator had before.
func TestEmailDomainIsStillTheLocalTransformForAnAddress(t *testing.T) {
	if transformIsNetwork("email_domain") {
		t.Fatal("email_domain performs no requests and must stay registered local")
	}
	result, err := (&server{}).runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "email_domain", Value: "Analyst@Example.com",
	})
	if err != nil {
		t.Fatalf("email_domain: %v", err)
	}
	if !result.LocalOnly || result.NetworkUsed {
		t.Fatalf("email_domain reported local_only=%v network_used=%v", result.LocalOnly, result.NetworkUsed)
	}
	if len(result.Entities) != 1 || result.Entities[0].Type != "domain" ||
		result.Entities[0].Identity != "example.com" {
		t.Fatalf("email_domain result = %#v", result)
	}
}

func TestIPTransformUsesOptionalLocalGeoIPJSON(t *testing.T) {
	database := filepath.Join(t.TempDir(), "geoip.json")
	if err := os.WriteFile(database, []byte(`{"192.0.2.0/24":{"country":"Testland","city":"Fixture"}}`), 0o600); err != nil {
		t.Fatalf("write geoip fixture: %v", err)
	}
	t.Setenv("OSINT_GEOIP_JSON", database)
	result, err := (&server{}).runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "ip_geo", Value: "192.0.2.5",
	})
	if err != nil {
		t.Fatalf("ip transform: %v", err)
	}
	if len(result.Entities) != 1 || result.Entities[0].Properties["geo_source"] != "local_json" {
		t.Fatalf("geo result = %#v", result)
	}
}

func TestNetworkTransformsRequireExplicitConfirmation(t *testing.T) {
	server := &server{}
	// Each transform gets a value of the kind it accepts. One blanket value for all
	// six used to work because the engine only looked at the shape of the string;
	// now that applicability is a stated contract `github_recon("example.com")` is
	// refused for being inapplicable, and this test would pass for the wrong reason
	// if it kept asking about the wrong thing.
	for transform, value := range map[string]string{
		"subdomains":   "example.com",
		"github_recon": "example_user",
		"reverse_dns":  "example.com",
		"dns_records":  "example.com",
		"wayback_urls": "example.com",
		"s3_buckets":   "example.com",
	} {
		_, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: transform, Value: value,
		})
		if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
			t.Fatalf("%s without confirmation error = %v", transform, err)
		}
	}
}

// A value no reading makes valid is refused before the transform body runs, so the
// refusal cannot be a confirmation prompt in disguise and cannot cost a request.
func TestInapplicableValuesAreRefusedBeforeTheConfirmationCheck(t *testing.T) {
	for _, pair := range [][2]string{{"subdomains", "443"}, {"wayback_urls", "cloudflare"}} {
		_, err := (&server{}).runOSINTTransform(context.Background(), osintTransformInput{
			Transform: pair[0], Value: pair[1],
		})
		if err == nil || !strings.Contains(err.Error(), "TRANSFORM_NOT_APPLICABLE") {
			t.Fatalf("%s(%q) = %v, want TRANSFORM_NOT_APPLICABLE before any confirmation", pair[0], pair[1], err)
		}
		code, message, ok := validateTransformInput(&osintTransformInput{
			Transform: pair[0], Value: pair[1],
		})
		if ok || code != "TRANSFORM_NOT_APPLICABLE" || message == "" {
			t.Fatalf("validateTransformInput(%s, %q) = %q %q %v", pair[0], pair[1], code, message, ok)
		}
	}
}

func TestTransformRegistryDeclaresNetworkBoundaries(t *testing.T) {
	// 22 since 2026-10-07, when `identity_graph` was added: Gravatar, Keybase and
	// HudsonRock, ported from `ibnaleem/gosearch` at commit `687f9ed`. Gravatar and
	// Keybase were previously read as bare HTML and judged by status code, which
	// could not see a profile's linked accounts or Keybase's verified proofs;
	// HudsonRock was absent, `subdomains` reading a different endpoint of it that
	// yields hostnames rather than a person's infostealer log.
	//
	// 21 since 2026-10-07, when `breach_exposure` was added: the three breach
	// corpora gosearch asked (ProxyNova, BreachDirectory, weakpass), ported from
	// `ibnaleem/gosearch` at commit `687f9ed`. It is the one transform that
	// returns the credential value rather than a fingerprint, and the registry
	// description says so before the operator confirms the run.
	//
	// 20 since 2026-10-03, when `http_probe` was added: an httpx run over a
	// host, recorded into the graph as the URLs that answered, the addresses the
	// host resolves to and the technologies it announces.
	//
	// 19 since 2026-10-01, when `cidr_range`, `asn_lookup` and `technology_probe`
	// were added — the three entity kinds that had no transform at all. Before
	// 2026-09-30 it was 16, `username_search` being the network counterpart of
	// `username_enum` with the merged Sherlock + Maigret platform catalogue.
	//
	// The size is a contract on purpose — a registry that silently gained or
	// lost a transform is exactly the change the UI would not show, because the
	// page builds its menu from this list and has no second copy to disagree
	// with it. So adding a transform means coming here and saying so.
	//
	// 23 since `s3_buckets` was added. That addition shipped in the same commit
	// as this assertion and left it at 22, so the test has been red since the
	// moment it was written: the contract it states was not the contract the
	// code held. The transform itself is fully wired — registry entry, dispatch
	// case, and a UI label present in both dictionaries — so the number was the
	// stale half, not the registry.
	if len(transformRegistry) != 23 {
		t.Fatalf("registry size = %d", len(transformRegistry))
	}
	for _, item := range transformRegistry {
		if item["id"] == "" || item["network"] == nil {
			t.Fatalf("invalid registry item: %#v", item)
		}
	}
}

// TestSecretScanTransformsAreNetworkConfirmed: a scan that reaches a network must
// not be reachable without the explicit confirmation, and it must be reachable
// from the entity kinds it says it accepts. The two halves are one test because
// the failure that matters is a transform that is offered for the wrong input —
// that is the shape an operator clicks on by mistake.
func TestSecretScanTransformsAreNetworkConfirmed(t *testing.T) {
	// The value has to be a real example of the kind the transform accepts: a
	// made-up string is refused by the classifier before the confirmation is
	// ever consulted, so the test would be measuring the wrong gate.
	cases := map[string]string{
		"git_secrets": "torvalds",
		"secret_scan": "example.test",
	}
	for _, id := range []string{"git_secrets", "secret_scan"} {
		value, ok := cases[id]
		if !ok {
			t.Fatalf("no sample value for %s", id)
		}
		var found bool
		for _, item := range transformRegistry {
			if item["id"] != id {
				continue
			}
			found = true
			if item["network"] != true {
				t.Fatalf("%s is registered as a local transform but performs network requests", id)
			}
			accepts, _ := item["accepts"].([]string)
			if len(accepts) == 0 {
				t.Fatalf("%s accepts nothing, so the menu can never offer it", id)
			}
			// The confirmation is enforced by `validateTransformInput`, which is the
			// single entry point every run passes through — including the ones the
			// gateway builds. Asking `transformApplicabilityError` about it instead
			// would test a function that has no opinion on confirmation, and the
			// test would be asserting nothing.
			// `validateTransformInput` returns (code, message, ok) and `ok` is the
			// third value, so the rejection is `ok == false` with a non-empty code.
			if code, message, ok := validateTransformInput(&osintTransformInput{
				Transform: id, Value: value,
			}); ok || code != "NETWORK_CONFIRMATION_REQUIRED" || message == "" {
				t.Fatalf("%s without confirmation = ok:%v code:%q %q, want NETWORK_CONFIRMATION_REQUIRED",
					id, ok, code, message)
			}
			if _, message, ok := validateTransformInput(&osintTransformInput{
				Transform: id, Value: value, ConfirmNetwork: true,
			}); !ok {
				t.Fatalf("%s refused its own accepted value %q even with confirmation: %s",
					id, value, message)
			}
		}
		if !found {
			t.Fatalf("%s is not registered, so the UI will never offer it", id)
		}
	}
}

// A local username normalizer must not report a network capability as missing.
//
// This is a regression test for a warning that was still being printed after the
// thing it complained about had existed for a month. `runUsernameEnum` appended
// "External platform enumeration is intentionally disabled; use a separately
// reviewed provider adapter." — while `username_search`, the network counterpart
// that queries the merged Sherlock and Maigret catalogue, had been in the
// registry since 2026-09-30. An operator reading that message was told the
// project could not do the one thing it does, and pointed at a provider adapter
// that was never written and never needed.
//
// Two halves, because the claim was made in two places and either one alone
// leaves the operator misinformed:
//
//   - the run itself must be warning-free, because a warning in this project
//     means "this run could not answer part of the question" and this run
//     answered all of it;
//   - the registry description — the text the operator reads *before* picking a
//     transform — has to name the transform that actually performs the
//     enumeration, rather than declare it unavailable.
//
// Mutation check, both directions: re-adding the warning line fails the first
// half; restoring "intentionally disabled" to the description fails the second.
func TestLocalUsernameTransformsDoNotClaimEnumerationIsUnavailable(t *testing.T) {
	server := &server{}
	for _, transform := range []string{"username_enum", "username_normalize"} {
		result, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: transform, Value: "analyst_01",
		})
		if err != nil {
			t.Fatalf("%s: %v", transform, err)
		}
		if len(result.Entities) != 1 || result.Entities[0].Type != "username" {
			t.Fatalf("%s entities = %#v, want one normalized username", transform, result.Entities)
		}
		if len(result.Warnings) != 0 {
			t.Fatalf("%s warned on a run that answered everything it was asked: %#v",
				transform, result.Warnings)
		}
	}

	var description string
	for _, item := range transformRegistry {
		if item["id"] == "username_enum" {
			description, _ = item["description"].(string)
		}
		if text, _ := item["description"].(string); strings.Contains(text, "intentionally disabled") {
			t.Fatalf("registry description for %v claims a capability is disabled: %q",
				item["id"], text)
		}
	}
	if description == "" {
		t.Fatal("username_enum is not in the registry, so the menu can never offer it")
	}
	if !strings.Contains(description, "username_search") {
		t.Fatalf("username_enum description does not name the transform that enumerates platforms: %q",
			description)
	}
}

func TestDNSRecordsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	engine := &server{}
	result := &osintTransformResult{}
	err := engine.runDNSRecords(ctx, result, osintTransformInput{
		Value: "example.com", ConfirmNetwork: true,
	})
	if err == nil {
		t.Fatal("runDNSRecords must fail on a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runDNSRecords error = %v, want context.Canceled", err)
	}
}

func TestGHDBLinksGeneratesCategorizedDorksWithRiskAndMultiEngines(t *testing.T) {
	server := &server{}
	result, err := server.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "ghdb_links",
		Value:     "www.nchti.ru",
	})
	if err != nil {
		t.Fatalf("ghdb_links failed: %v", err)
	}
	if !result.LocalOnly || result.NetworkUsed {
		t.Fatalf("ghdb_links should be local without network: got local_only=%v, network_used=%v", result.LocalOnly, result.NetworkUsed)
	}
	if len(result.Entities) < 10 {
		t.Fatalf("ghdb_links returned too few entities: %d", len(result.Entities))
	}
	if len(result.Relations) < 10 {
		t.Fatalf("ghdb_links returned too few relations: %d", len(result.Relations))
	}

	foundSubdomains := false
	foundSecrets := false
	for _, entity := range result.Entities {
		if entity.Type != "url" {
			continue
		}
		if entity.RiskScore <= 0 {
			t.Errorf("entity %s has non-positive risk score: %d", entity.Identity, entity.RiskScore)
		}
		if entity.DisplayValue == "" {
			t.Errorf("entity %s is missing display_value", entity.Identity)
		}
		category, _ := entity.Properties["category"].(string)
		if category == "subdomains_discovery" {
			foundSubdomains = true
			dork, _ := entity.Properties["dork"].(string)
			// Must dork apex domain nchti.ru instead of *.www.nchti.ru
			if !strings.Contains(dork, "site:*.nchti.ru") {
				t.Errorf("subdomain dork does not target apex domain properly: %q", dork)
			}
		}
		if category == "public_secrets" {
			foundSecrets = true
		}
		if entity.Properties["google_url"] == nil || entity.Properties["ddg_url"] == nil || entity.Properties["bing_url"] == nil {
			t.Errorf("entity %s is missing multi-engine search URLs", entity.Identity)
		}
	}
	if !foundSubdomains {
		t.Errorf("subdomains_discovery category not found in entities")
	}
	if !foundSecrets {
		t.Errorf("public_secrets category not found in entities")
	}

	for _, rel := range result.Relations {
		if rel.Type == "recon_query" {
			if rel.SourceType != "domain" || rel.TargetType != "url" {
				t.Errorf("recon_query relation has bad endpoints: %#v", rel)
			}
		}
	}
}

func TestGHDBSearchNetworkConfirmationAndCMSDorks(t *testing.T) {
	server := &server{}

	// 1. Unconfirmed network must fail with NETWORK_CONFIRMATION_REQUIRED
	_, err := server.runOSINTTransform(context.Background(), osintTransformInput{
		Transform:      "ghdb_search",
		Value:          "www.target.test",
		ConfirmNetwork: false,
	})
	if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Fatalf("expected NETWORK_CONFIRMATION_REQUIRED error, got: %v", err)
	}

	// 2. Confirmed network run with mocked transport
	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		host := req.URL.Host
		if strings.Contains(host, "duckduckgo.com") {
			// Mock DDG search results
			htmlBody := `
<!DOCTYPE html>
<html>
<body>
  <div class="result results_links results_links_deep web-result">
    <h2 class="result__title">
      <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fmoodle.target.test%2Fmod%2F&amp;rut=123">Moodle Learning Portal</a>
    </h2>
    <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fmoodle.target.test%2Fmod%2F&amp;rut=123">Distance education platform...</a>
  </div>
  <div class="result results_links results_links_deep web-result">
    <h2 class="result__title">
      <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.target.test%2Fwp-login.php&amp;rut=456">Target Admin Login</a>
    </h2>
    <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.target.test%2Fwp-login.php&amp;rut=456">Log in to WordPress dashboard...</a>
  </div>
</body>
</html>`
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(strings.NewReader(htmlBody)),
			}, nil
		}

		// Mock target host response (WordPress signatures)
		wpHTML := `<html><head><link rel="stylesheet" href="/wp-content/plugins/test-plugin/style.css"></head><body><h1>WordPress Site</h1></body></html>`
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"text/html"}},
			Body:       io.NopCloser(strings.NewReader(wpHTML)),
		}, nil
	})

	ctx := withToolTransport(context.Background(), mockTransport)
	result, err := server.runOSINTTransform(ctx, osintTransformInput{
		Transform:      "ghdb_search",
		Value:          "www.target.test",
		ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("ghdb_search failed: %v", err)
	}

	if result.LocalOnly || !result.NetworkUsed {
		t.Fatalf("ghdb_search must mark network_used=true, local_only=false: got local_only=%v, network_used=%v", result.LocalOnly, result.NetworkUsed)
	}

	// Verify CMS entity and relation
	foundCMS := false
	for _, entity := range result.Entities {
		if entity.Type == "technology" && entity.Identity == "wordpress" {
			foundCMS = true
			if entity.DisplayValue != "CMS: Wordpress" {
				t.Errorf("unexpected CMS display value: %q", entity.DisplayValue)
			}
		}
	}
	if !foundCMS {
		t.Errorf("wordpress CMS technology entity was not found in result")
	}

	foundUses := false
	for _, rel := range result.Relations {
		if rel.Type == "uses" && rel.Source == "www.target.test" && rel.Target == "wordpress" {
			foundUses = true
		}
	}
	if !foundUses {
		t.Errorf("uses relation between www.target.test and wordpress was not found")
	}

	// Verify Exploit-DB WordPress GHDB dorks
	foundWPDork := false
	for _, entity := range result.Entities {
		if entity.Type == "url" {
			category, _ := entity.Properties["category"].(string)
			if category == "cms_wordpress" {
				foundWPDork = true
			}
		}
	}
	if !foundWPDork {
		t.Errorf("cms_wordpress dork category not found in generated dorks")
	}

	// Verify discovered subdomain from search scraper
	foundMoodleSubdomain := false
	for _, entity := range result.Entities {
		if entity.Type == "subdomain" && entity.Identity == "moodle.target.test" {
			foundMoodleSubdomain = true
		}
	}
	if !foundMoodleSubdomain {
		t.Errorf("discovered subdomain moodle.target.test was not added to entities")
	}

	foundSubdomainOf := false
	for _, rel := range result.Relations {
		if rel.Type == "subdomain_of" && rel.Source == "moodle.target.test" && rel.Target == "target.test" {
			foundSubdomainOf = true
		}
	}
	if !foundSubdomainOf {
		t.Errorf("subdomain_of relation for moodle.target.test -> target.test not found")
	}

	// Verify discovered URLs from search scraper
	foundMoodleURL := false
	foundLoginURL := false
	for _, entity := range result.Entities {
		if entity.Type == "url" {
			if entity.Identity == "https://moodle.target.test/mod/" {
				foundMoodleURL = true
				if entity.DisplayValue != "Moodle Learning Portal" {
					t.Errorf("unexpected display value for moodle URL: %q", entity.DisplayValue)
				}
			}
			if entity.Identity == "https://www.target.test/wp-login.php" {
				foundLoginURL = true
				if entity.RiskScore < 50 {
					t.Errorf("login URL should have elevated risk score (>=50), got: %d", entity.RiskScore)
				}
			}
		}
	}
	if !foundMoodleURL {
		t.Errorf("discovered URL https://moodle.target.test/mod/ not found in entities")
	}
	if !foundLoginURL {
		t.Errorf("discovered URL https://www.target.test/wp-login.php not found in entities")
	}

	// Verify exposes relations
	foundExposesMoodle := false
	foundExposesLogin := false
	for _, rel := range result.Relations {
		if rel.Type == "exposes" {
			if rel.Source == "moodle.target.test" && rel.Target == "https://moodle.target.test/mod/" {
				foundExposesMoodle = true
			}
			if rel.Source == "www.target.test" && rel.Target == "https://www.target.test/wp-login.php" {
				foundExposesLogin = true
			}
		}
	}
	if !foundExposesMoodle {
		t.Errorf("exposes relation for moodle.target.test not found")
	}
	if !foundExposesLogin {
		t.Errorf("exposes relation for www.target.test not found")
	}
}
