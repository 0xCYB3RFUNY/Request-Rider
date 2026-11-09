package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// The recorded URL names the host that served it. Attaching the observation to
// the apex instead throws that host away, and it is the only host the record
// names: an analyst reading `https://api.example.com/login` needs to see that
// it was api.example.com, not that it was "somewhere under example.com".
func TestRunWaybackURLsAttachesTheURLToTheHostThatServedIt(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/cdx/search/cdx"] = http.StatusTooManyRequests
	fixture.bodies["/web/timemap/json"] = `[["urlkey","timestamp","original"],
		["ru,example.com)/","20240101","https://api.example.com/login"],
		["ru,example.com)/","20240202","https://example.com/root"]]`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}

	subdomainEntity, domainEntity := false, false
	for _, row := range result.Entities {
		if row.Type == "subdomain" && row.Identity == "api.example.com" {
			subdomainEntity = true
		}
		if row.Type == "domain" && row.Identity == "example.com" {
			domainEntity = true
		}
	}
	if !subdomainEntity {
		t.Fatalf("api.example.com was not stored as the subdomain it is: %#v", result.Entities)
	}
	if !domainEntity {
		t.Fatalf("the queried domain is missing: %#v", result.Entities)
	}

	// The URL is linked to the host that answered it, not to the apex. A link to
	// the apex would make every URL on every host in the zone look like it
	// belonged to the zone itself.
	linkedToHost, linkedToApex, apexOwnSubdomain := false, false, false
	for _, relation := range result.Relations {
		if relation.Type == "observed_at" && relation.Source == "https://api.example.com/login" {
			if relation.Target == "api.example.com" {
				linkedToHost = true
			}
			if relation.Target == "example.com" {
				linkedToApex = true
			}
		}
		// The apex must not be declared a subdomain of itself. The host type is
		// decided against the queried domain precisely so that this cannot
		// happen, and a self-referential relation is a cycle in the graph.
		if relation.Type == "subdomain_of" && relation.Source == relation.Target {
			apexOwnSubdomain = true
		}
	}
	if !linkedToHost {
		t.Fatal("the URL was not linked to the host that served it")
	}
	if linkedToApex {
		t.Fatal("the URL was still linked to the apex it was looked up under")
	}
	if apexOwnSubdomain {
		t.Fatal("the apex was declared a subdomain of itself")
	}
}

// Coordinates are what make an archived response fetchable rather than guessed
// at, so they are kept — but only as a complete set. A partial address reads as
// an archive record and fails to resolve, which is worse than no address at all,
// because it looks like evidence that is there.
func TestRunWaybackURLsKeepsArchiveCoordinatesOnlyWhenTheyAreComplete(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()

	// One URL with a complete WARC address, one with the length missing.
	fixture.bodies["/web/timemap.json"] = ""
	fixture.bodies["/cdx/search/cdx"] = ""
	engine.archiveIndexList = func(ctx context.Context, prefix string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{{
			name:   "crawl CC-MAIN-0001",
			query:  engine.archiveIndexBase + "/crawl",
			layout: archiveLayoutObjects, field: "url", continueOnEmpty: true,
		}}, nil
	}
	fixture.bodies["/crawl"] = `{"url":"https://example.com/whole","timestamp":"20240101","filename":"crawl-data/x.warc.gz","offset":"1234","length":"5678"}` + "\n" +
		`{"url":"https://example.com/partial","timestamp":"20240102","filename":"crawl-data/y.warc.gz","offset":"9"}`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}

	properties := map[string]map[string]interface{}{}
	for _, row := range result.Entities {
		if row.Type == "url" {
			properties[row.Identity] = row.Properties
		}
	}
	whole, ok := properties["https://example.com/whole"]
	if !ok {
		t.Fatalf("the complete record is missing: %#v", properties)
	}
	if whole["archive_file"] != "crawl-data/x.warc.gz" || whole["archive_offset"] != "1234" || whole["archive_length"] != "5678" {
		t.Fatalf("a complete archive address was not kept whole: %#v", whole)
	}
	if whole["captured_at"] != "20240101" {
		t.Fatalf("the capture time was dropped: %#v", whole)
	}
	partial, ok := properties["https://example.com/partial"]
	if !ok {
		t.Fatalf("the partial record is missing: %#v", properties)
	}
	// The URL is still stored — it was read perfectly — but an address that
	// cannot be fetched must not be written as if it could.
	for _, field := range []string{"archive_file", "archive_offset", "archive_length"} {
		if _, present := partial[field]; present {
			t.Fatalf("an incomplete archive address was written anyway: %#v", partial)
		}
	}
	if partial["captured_at"] != "20240102" {
		t.Fatalf("the capture time of a partial record was dropped: %#v", partial)
	}
}

// The newest published crawl answers 504 until its query path is serving, while
// older ones answer normally. That is a gap in coverage, and reporting it as a
// failure would make a healthy 128-collection run look broken.
func TestRunWaybackURLsReportsAnUnservedCollectionAsSkippedNotFailed(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	engine.archiveIndexList = func(ctx context.Context, prefix string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{
			{name: "crawl CC-MAIN-2026-39", query: engine.archiveIndexBase + "/newest", layout: archiveLayoutObjects, field: "url", continueOnEmpty: true},
			{name: "crawl CC-MAIN-2025-30", query: engine.archiveIndexBase + "/older", layout: archiveLayoutObjects, field: "url", continueOnEmpty: true},
		}, nil
	}
	fixture.statuses["/newest"] = http.StatusGatewayTimeout
	fixture.bodies["/older"] = `{"url":"https://example.com/a","timestamp":"20250101"}`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	// The chain keeps walking: an unserved collection must not end the search.
	found := false
	for _, row := range result.Entities {
		if row.Type == "url" && row.Identity == "https://example.com/a" {
			found = true
		}
	}
	if !found {
		t.Fatalf("one unserved collection ended the chain: %#v", result.Entities)
	}
	if result.Metadata["archive_failures"] != nil && result.Metadata["archive_failures"].(int) != 0 {
		t.Fatalf("an unserved collection was counted as a failure: %#v", result.Metadata)
	}
	named := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "not being served yet") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the unserved collection was not named: %#v", result.Warnings)
	}
}

// The Internet Archive publishes the archive address in its own row layout, but
// only if it is asked for: the default field list is the URL alone. A coordinate
// feature that works only for one of the two index families is half a feature.
func TestRunWaybackURLsReadsCoordinatesFromTheRowLayout(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/web/timemap/json"] = http.StatusTooManyRequests
	// The header is what the reader resolves columns by, so a reordered or
	// extended row has to keep working: the position of "original" is not fixed.
	fixture.bodies["/cdx/search/cdx"] = `[["urlkey","timestamp","original","filename","offset","length"],
		["ru,example.com)/","20240101120000","https://example.com/a","crawl-data/a.warc.gz","100","2048"]]`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	for _, row := range result.Entities {
		if row.Type != "url" {
			continue
		}
		if row.Properties["archive_file"] != "crawl-data/a.warc.gz" ||
			row.Properties["archive_offset"] != "100" || row.Properties["archive_length"] != "2048" {
			t.Fatalf("the row layout's archive address was not read: %#v", row.Properties)
		}
		if row.Properties["captured_at"] != "20240101120000" {
			t.Fatalf("the row layout's timestamp was not read: %#v", row.Properties)
		}
		return
	}
	t.Fatalf("no url entity: %#v", result.Entities)
}
