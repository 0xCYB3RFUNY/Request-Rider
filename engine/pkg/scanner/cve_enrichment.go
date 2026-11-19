package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PoCRecord captures a public proof-of-concept reference attached to a CVE.
type PoCRecord struct {
	URL     string `json:"url"`
	Source  string `json:"source,omitempty"`
	AddedAt string `json:"added_at,omitempty"`
}

// CVEEnrichment holds vulnx-compatible vulnerability priority metadata for a CVE.
type CVEEnrichment struct {
	CVEID                      string      `json:"cve_id"`
	EPSSScore                  float64     `json:"epss_score,omitempty"`
	EPSSPercentile             float64     `json:"epss_percentile,omitempty"`
	IsKEV                      bool        `json:"is_kev,omitempty"`
	IsExploited                bool        `json:"is_exploited,omitempty"`
	IsPoC                      bool        `json:"is_poc,omitempty"`
	IsRemote                   bool        `json:"is_remote,omitempty"`
	IsOSS                      bool        `json:"is_oss,omitempty"`
	KnownRansomwareCampaignUse string      `json:"known_ransomware_campaign_use,omitempty"`
	AgeInDays                  int         `json:"age_in_days,omitempty"`
	PatchURL                   string      `json:"patch_url,omitempty"`
	VendorAdvisory             string      `json:"vendor_advisory,omitempty"`
	PoCs                       []PoCRecord `json:"poc,omitempty"`
	HackerOneRank              int         `json:"hackerone_rank,omitempty"`
	HackerOneCount             int         `json:"hackerone_count,omitempty"`
	ShodanCount                int         `json:"shodan_count,omitempty"`
	ShodanQuery                string      `json:"shodan_query,omitempty"`
	PublishedAt                string      `json:"published_at,omitempty"`
}

// CVEEnricher resolves and caches EPSS, CISA KEV, and PoC metadata for CVEs.
type CVEEnricher struct {
	client  *http.Client
	epssURL string
	kevURL  string
	mu      sync.RWMutex
	cache   map[string]CVEEnrichment
	kevSet  map[string]kevEntry
	kevLoad bool
	nowFunc func() time.Time
}

type kevEntry struct {
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	DateAdded                  string `json:"dateAdded"`
}

// NewCVEEnricher constructs a CVEEnricher with safe timeouts and optional overrides.
func NewCVEEnricher(client *http.Client) *CVEEnricher {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &CVEEnricher{
		client:  client,
		epssURL: "https://api.first.org/data/v1/epss",
		kevURL:  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		cache:   make(map[string]CVEEnrichment),
		kevSet:  make(map[string]kevEntry),
		nowFunc: time.Now,
	}
}

var (
	defaultEnricherOnce sync.Once
	defaultEnricherInst *CVEEnricher
)

// DefaultCVEEnricher returns a process-wide cached CVEEnricher with a 2s HTTP timeout.
func DefaultCVEEnricher() *CVEEnricher {
	defaultEnricherOnce.Do(func() {
		defaultEnricherInst = NewCVEEnricher(&http.Client{Timeout: 2 * time.Second})
	})
	return defaultEnricherInst
}

// Register pre-populates enrichment metadata in the local cache (useful for offline catalogs and tests).
func (e *CVEEnricher) Register(item CVEEnrichment) {
	id := strings.ToUpper(strings.TrimSpace(item.CVEID))
	if id == "" {
		return
	}
	item.CVEID = id
	if item.AgeInDays == 0 && item.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, item.PublishedAt); err == nil {
			days := int(e.nowFunc().UTC().Sub(t.UTC()).Hours() / 24)
			if days >= 0 {
				item.AgeInDays = days
			}
		}
	}
	e.mu.Lock()
	e.cache[id] = item
	e.mu.Unlock()
}

// Lookup returns enrichment data for one CVE from cache or upstream EPSS/KEV feeds.
func (e *CVEEnricher) Lookup(ctx context.Context, cveID string) (CVEEnrichment, bool) {
	id := strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(id, "CVE-") {
		return CVEEnrichment{}, false
	}

	e.mu.RLock()
	cached, ok := e.cache[id]
	e.mu.RUnlock()
	if ok {
		return cached, true
	}

	result := CVEEnrichment{CVEID: id}
	foundAny := false

	if score, pct, ok := e.fetchEPSS(ctx, id); ok {
		result.EPSSScore = score
		result.EPSSPercentile = pct
		foundAny = true
	}
	if entry, ok := e.lookupKEV(ctx, id); ok {
		result.IsKEV = true
		result.IsExploited = true
		if entry.KnownRansomwareCampaignUse != "" {
			result.KnownRansomwareCampaignUse = entry.KnownRansomwareCampaignUse
		}
		foundAny = true
	}

	if !foundAny {
		return CVEEnrichment{}, false
	}
	e.Register(result)
	return result, true
}

func (e *CVEEnricher) fetchEPSS(ctx context.Context, cveID string) (float64, float64, bool) {
	if e.epssURL == "" || e.client == nil {
		return 0, 0, false
	}
	reqURL := fmt.Sprintf("%s?cve=%s", strings.TrimRight(e.epssURL, "?"), url.QueryEscape(cveID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, 0, false
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, false
	}
	var payload struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || len(payload.Data) == 0 {
		return 0, 0, false
	}
	var score, pct float64
	_, _ = fmt.Sscanf(payload.Data[0].EPSS, "%f", &score)
	_, _ = fmt.Sscanf(payload.Data[0].Percentile, "%f", &pct)
	return score, pct, true
}

func (e *CVEEnricher) lookupKEV(ctx context.Context, cveID string) (kevEntry, bool) {
	e.mu.RLock()
	loaded := e.kevLoad
	entry, ok := e.kevSet[cveID]
	e.mu.RUnlock()
	if loaded {
		return entry, ok
	}
	if e.kevURL == "" || e.client == nil {
		return kevEntry{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.kevURL, nil)
	if err != nil {
		return kevEntry{}, false
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return kevEntry{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return kevEntry{}, false
	}
	var feed struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
			DateAdded                  string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return kevEntry{}, false
	}
	e.mu.Lock()
	for _, v := range feed.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if id != "" {
			e.kevSet[id] = kevEntry{
				KnownRansomwareCampaignUse: v.KnownRansomwareCampaignUse,
				DateAdded:                  v.DateAdded,
			}
		}
	}
	e.kevLoad = true
	entry, ok = e.kevSet[cveID]
	e.mu.Unlock()
	return entry, ok
}

// ApplyToFinding enriches a shared finding map with vulnx priority metadata when CVEs are present.
func (e *CVEEnricher) ApplyToFinding(ctx context.Context, finding map[string]interface{}) {
	if e == nil || finding == nil {
		return
	}
	cves := extractFindingCVEs(finding)
	if len(cves) == 0 {
		return
	}

	var best *CVEEnrichment
	for _, cve := range cves {
		info, ok := e.Lookup(ctx, cve)
		if !ok {
			continue
		}
		if best == nil || info.EPSSScore > best.EPSSScore || (info.IsKEV && !best.IsKEV) {
			copyInfo := info
			best = &copyInfo
		}
	}
	if best == nil {
		if autoPoCs := extractPoCsFromFinding(finding); len(autoPoCs) > 0 {
			finding["is_poc"] = true
			finding["poc"] = autoPoCs
		}
		return
	}

	finding["epss_score"] = best.EPSSScore
	finding["epss_percentile"] = best.EPSSPercentile
	finding["is_kev"] = best.IsKEV
	finding["is_exploited"] = best.IsExploited
	finding["is_poc"] = best.IsPoC
	finding["is_remote"] = best.IsRemote
	finding["is_oss"] = best.IsOSS
	if best.KnownRansomwareCampaignUse != "" {
		finding["known_ransomware_campaign_use"] = best.KnownRansomwareCampaignUse
	}
	if best.AgeInDays > 0 {
		finding["age_in_days"] = best.AgeInDays
	}
	if best.PatchURL != "" {
		finding["patch_url"] = best.PatchURL
		if rec, _ := finding["recommendation"].(string); strings.TrimSpace(rec) == "" {
			finding["recommendation"] = "Apply vendor patch: " + best.PatchURL
		}
	}
	if best.VendorAdvisory != "" {
		finding["vendor_advisory"] = best.VendorAdvisory
	}
	if len(best.PoCs) > 0 {
		finding["poc"] = best.PoCs
	}
	if autoPoCs := extractPoCsFromFinding(finding); len(autoPoCs) > 0 {
		finding["is_poc"] = true
		existingPoCs, _ := finding["poc"].([]PoCRecord)
		finding["poc"] = append(existingPoCs, autoPoCs...)
	}
	if best.HackerOneRank > 0 || best.HackerOneCount > 0 {
		finding["hackerone"] = map[string]int{
			"rank":  best.HackerOneRank,
			"count": best.HackerOneCount,
		}
	}
	if best.ShodanCount > 0 || best.ShodanQuery != "" {
		finding["shodan"] = map[string]interface{}{
			"count": best.ShodanCount,
			"query": best.ShodanQuery,
		}
	}
}

var pocLinkKeywords = []string{
	"github.com",
	"exploit-db.com",
	"packetstormsecurity.com",
	"packetstorm.news",
	"0day.today",
	"cxsecurity.com",
	"seclists.org",
	"sploitus.com",
	"edb-id",
}

func extractPoCsFromFinding(finding map[string]interface{}) []PoCRecord {
	var records []PoCRecord
	seen := make(map[string]bool)

	addURL := func(u, src string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		records = append(records, PoCRecord{
			URL:    u,
			Source: src,
		})
	}

	checkLink := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		lower := strings.ToLower(trimmed)
		for _, kw := range pocLinkKeywords {
			if strings.Contains(lower, kw) {
				addURL(trimmed, "reference")
				break
			}
		}
	}

	for _, key := range []string{"references", "reference"} {
		switch v := finding[key].(type) {
		case []string:
			for _, r := range v {
				checkLink(r)
			}
		case []interface{}:
			for _, r := range v {
				if s, ok := r.(string); ok {
					checkLink(s)
				}
			}
		case string:
			checkLink(v)
		}
	}

	return records
}

func extractFindingCVEs(finding map[string]interface{}) []string {
	switch v := finding["cve"].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) != "" {
			return []string{v}
		}
	}
	return nil
}
