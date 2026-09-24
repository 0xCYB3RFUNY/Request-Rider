package main

import (
	"context"
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
	for _, transform := range []string{"subdomains", "github_recon", "reverse_dns", "dns_records", "wayback_urls", "s3_buckets"} {
		_, err := server.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: transform, Value: "example.com",
		})
		if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
			t.Fatalf("%s without confirmation error = %v", transform, err)
		}
	}
}

func TestTransformRegistryDeclaresNetworkBoundaries(t *testing.T) {
	if len(transformRegistry) != 13 {
		t.Fatalf("registry size = %d", len(transformRegistry))
	}
	for _, item := range transformRegistry {
		if item["id"] == "" || item["network"] == nil {
			t.Fatalf("invalid registry item: %#v", item)
		}
	}
}
