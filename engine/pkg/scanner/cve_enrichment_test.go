package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCVEEnricherLookupAndApplyToFinding(t *testing.T) {
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") != "CVE-2024-1234" {
			t.Fatalf("unexpected cve query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2024-1234","epss":"0.9712","percentile":"0.9985"}]}`))
	}))
	defer epssSrv.Close()

	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-1234","knownRansomwareCampaignUse":"Known","dateAdded":"2024-02-01"}]}`))
	}))
	defer kevSrv.Close()

	enricher := NewCVEEnricher(epssSrv.Client())
	enricher.epssURL = epssSrv.URL
	enricher.kevURL = kevSrv.URL

	finding := map[string]interface{}{
		"template_id":    "cve-2024-1234",
		"severity":       "CRITICAL",
		"recommendation": "",
		"cve":            []string{"CVE-2024-1234"},
	}

	enricher.ApplyToFinding(context.Background(), finding)

	if got, ok := finding["epss_score"].(float64); !ok || got < 0.97 {
		t.Fatalf("epss_score = %#v, want >= 0.97", finding["epss_score"])
	}
	if got, ok := finding["epss_percentile"].(float64); !ok || got < 0.99 {
		t.Fatalf("epss_percentile = %#v, want >= 0.99", finding["epss_percentile"])
	}
	if got, ok := finding["is_kev"].(bool); !ok || !got {
		t.Fatalf("is_kev = %#v, want true", finding["is_kev"])
	}
	if got := finding["known_ransomware_campaign_use"]; got != "Known" {
		t.Fatalf("known_ransomware_campaign_use = %#v, want Known", got)
	}
}

func TestCVEEnricherRegisteredMetadataPopulatesPoCPatchAndAge(t *testing.T) {
	enricher := NewCVEEnricher(nil)
	enricher.epssURL = ""
	enricher.kevURL = ""
	enricher.nowFunc = func() time.Time {
		return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	}
	enricher.Register(CVEEnrichment{
		CVEID:          "CVE-2025-9999",
		EPSSScore:      0.55,
		IsPoC:          true,
		IsRemote:       true,
		IsOSS:          true,
		PatchURL:       "https://vendor.example.test/advisory/patch",
		VendorAdvisory: "https://vendor.example.test/advisory",
		PublishedAt:    "2026-11-08T00:00:00Z",
		PoCs: []PoCRecord{
			{URL: "https://github.com/example/poc", Source: "github", AddedAt: "2026-11-10"},
		},
		HackerOneRank:  3,
		HackerOneCount: 12,
		ShodanCount:    420,
		ShodanQuery:    "http.title:Example",
	})

	finding := map[string]interface{}{
		"cve":            []string{"CVE-2025-9999"},
		"recommendation": "",
	}
	enricher.ApplyToFinding(context.Background(), finding)

	if finding["is_poc"] != true || finding["is_remote"] != true || finding["is_oss"] != true {
		t.Fatalf("boolean flags not populated: %#v", finding)
	}
	if finding["age_in_days"] != 10 {
		t.Fatalf("age_in_days = %#v, want 10", finding["age_in_days"])
	}
	if finding["patch_url"] != "https://vendor.example.test/advisory/patch" {
		t.Fatalf("patch_url = %#v", finding["patch_url"])
	}
	if finding["recommendation"] == "" {
		t.Fatalf("recommendation should be populated from patch_url")
	}
	if _, ok := finding["poc"].([]PoCRecord); !ok {
		t.Fatalf("poc field missing: %#v", finding["poc"])
	}
	if _, ok := finding["hackerone"].(map[string]int); !ok {
		t.Fatalf("hackerone field missing: %#v", finding["hackerone"])
	}
	if _, ok := finding["shodan"].(map[string]interface{}); !ok {
		t.Fatalf("shodan field missing: %#v", finding["shodan"])
	}
}

func TestCVEEnricherAutoDetectsPoCFromReferences(t *testing.T) {
	enricher := NewCVEEnricher(nil)
	enricher.epssURL = ""
	enricher.kevURL = ""

	finding := map[string]interface{}{
		"cve": []string{"CVE-2017-5638"},
		"references": []string{
			"https://cwiki.apache.org/confluence/display/WW/S2-045",
			"https://github.com/vulhub/vulhub/tree/master/struts2/s2-045",
			"https://www.exploit-db.com/exploits/41570",
			"https://sploitus.com/exploit?id=1337-POC",
		},
	}

	enricher.ApplyToFinding(context.Background(), finding)

	if finding["is_poc"] != true {
		t.Fatalf("expected is_poc=true, got %#v", finding["is_poc"])
	}
	pocs, ok := finding["poc"].([]PoCRecord)
	if !ok || len(pocs) < 3 {
		t.Fatalf("expected at least 3 PoCs extracted, got %#v", finding["poc"])
	}
	if pocs[0].URL != "https://github.com/vulhub/vulhub/tree/master/struts2/s2-045" {
		t.Fatalf("unexpected first poc URL: %s", pocs[0].URL)
	}
	if pocs[1].URL != "https://www.exploit-db.com/exploits/41570" {
		t.Fatalf("unexpected second poc URL: %s", pocs[1].URL)
	}
	if pocs[2].URL != "https://sploitus.com/exploit?id=1337-POC" {
		t.Fatalf("unexpected third poc URL: %s", pocs[2].URL)
	}
}
