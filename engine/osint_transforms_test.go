package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalEmailAndUsernameTransformsAreNetworkFree(t *testing.T) {
	server := &server{}
	email, err := server.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "email_recon", Value: "Analyst@Example.com",
	})
	if err != nil {
		t.Fatalf("email transform: %v", err)
	}
	if !email.LocalOnly || email.NetworkUsed || len(email.Entities) != 2 || len(email.Relations) != 1 {
		t.Fatalf("email result = %#v", email)
	}
	username, err := server.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "username_enum", Value: "analyst_01",
	})
	if err != nil {
		t.Fatalf("username transform: %v", err)
	}
	if !username.LocalOnly || username.NetworkUsed || len(username.Entities) != 1 {
		t.Fatalf("username result = %#v", username)
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
	if len(transformRegistry) != 22 {
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
