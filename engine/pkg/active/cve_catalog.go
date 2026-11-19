package active

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// CVECatalogEntry describes one known CVE in the local intelligence catalog.
type CVECatalogEntry struct {
	ID          string `json:"id"`
	Year        int    `json:"year"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	CVSSScore   string `json:"cvss_score,omitempty"`
	Description string `json:"description,omitempty"`
	Template    string `json:"template,omitempty"`
	Source      string `json:"source"`
}

// CVECatalogStats summarizes the loaded CVE coverage across years and severities.
type CVECatalogStats struct {
	Total      int            `json:"total"`
	MinYear    int            `json:"min_year"`
	MaxYear    int            `json:"max_year"`
	ByYear     map[int]int    `json:"by_year"`
	BySeverity map[string]int `json:"by_severity"`
	CatalogDir string         `json:"catalog_path,omitempty"`
}

// CVECatalog indexes known CVEs from local nuclei-templates (cves.json) and
// built-in active/corpus signatures spanning 1999–2026.
type CVECatalog struct {
	mu      sync.RWMutex
	byID    map[string]CVECatalogEntry
	ordered []CVECatalogEntry
	source  string
}

type nucleiCVEJSONLine struct {
	ID       string `json:"ID"`
	FilePath string `json:"file_path"`
	Info     struct {
		Name           string `json:"Name"`
		Severity       string `json:"Severity"`
		Description    string `json:"Description"`
		Classification struct {
			CVSSScore string `json:"CVSSScore"`
		} `json:"Classification"`
	} `json:"Info"`
}

var builtinCatalogSeeds = []CVECatalogEntry{
	{ID: "CVE-1999-0738", Year: 1999, Name: "Microsoft IIS Winmsdp.exe Information Disclosure", Severity: "medium", Source: "corpus"},
	{ID: "CVE-2012-1823", Year: 2012, Name: "PHP-CGI Query-String Argument Injection", Severity: "high", Source: "active"},
	{ID: "CVE-2014-6271", Year: 2014, Name: "GNU Bash Shellshock Remote Code Execution", Severity: "critical", Source: "active"},
	{ID: "CVE-2017-5638", Year: 2017, Name: "Apache Struts2 Jakarta Multipart Parser OGNL Injection", Severity: "critical", Source: "active"},
	{ID: "CVE-2019-11510", Year: 2019, Name: "Pulse Secure SSL VPN Arbitrary File Read", Severity: "critical", Source: "active"},
	{ID: "CVE-2020-11022", Year: 2020, Name: "jQuery htmlPrefilter Cross-Site Scripting", Severity: "medium", Source: "active"},
	{ID: "CVE-2021-41773", Year: 2021, Name: "Apache HTTP Server 2.4.49 Path Traversal", Severity: "critical", Source: "active"},
	{ID: "CVE-2021-42013", Year: 2021, Name: "Apache HTTP Server 2.4.50 Path Traversal & RCE", Severity: "critical", Source: "active"},
	{ID: "CVE-2021-44228", Year: 2021, Name: "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)", Severity: "critical", Source: "active"},
	{ID: "CVE-2023-22515", Year: 2023, Name: "Atlassian Confluence Broken Access Control", Severity: "critical", Source: "active"},
	{ID: "CVE-2025-29927", Year: 2025, Name: "Next.js Middleware Authorization Bypass", Severity: "critical", Source: "active"},
	{ID: "CVE-2025-30208", Year: 2025, Name: "Vite Dev Server /@fs/ Arbitrary File Read", Severity: "high", Source: "active"},
	{ID: "CVE-2025-55182", Year: 2025, Name: "React Server Components Flight Deserialization", Severity: "critical", Source: "active"},
	{ID: "CVE-2026-0545", Year: 2026, Name: "MLflow Job API Unauthenticated Access", Severity: "critical", Source: "active"},
}

// DefaultCVECatalogPath locates cves.json on disk if present.
func DefaultCVECatalogPath() string {
	if env := strings.TrimSpace(os.Getenv("RR_CVE_CATALOG_PATH")); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		"/home/kali/nuclei-templates/cves.json",
		filepath.Join(home, "nuclei-templates", "cves.json"),
		filepath.Join(home, "Desktop", "nuclei-templates", "cves.json"),
		filepath.Join(home, ".local", "nuclei-templates", "cves.json"),
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// LoadCVECatalog builds a CVE catalog from built-in seeds and an optional
// nuclei-templates cves.json NDJSON file. Missing file on disk is not an error:
// the built-in 1999–2026 seeds remain available.
func LoadCVECatalog(path string) (*CVECatalog, error) {
	cat := &CVECatalog{
		byID: make(map[string]CVECatalogEntry, 5000),
	}
	for _, seed := range builtinCatalogSeeds {
		cat.byID[seed.ID] = seed
	}
	if path == "" {
		path = DefaultCVECatalogPath()
	}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		cat.source = path

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec nucleiCVEJSONLine
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			id := strings.ToUpper(strings.TrimSpace(rec.ID))
			if !reCVEPattern.MatchString(id) {
				continue
			}
			year := parseCVEYear(id)
			entry := CVECatalogEntry{
				ID:          id,
				Year:        year,
				Name:        strings.TrimSpace(rec.Info.Name),
				Severity:    strings.ToLower(strings.TrimSpace(rec.Info.Severity)),
				CVSSScore:   strings.TrimSpace(rec.Info.Classification.CVSSScore),
				Description: strings.TrimSpace(rec.Info.Description),
				Template:    strings.TrimSpace(rec.FilePath),
				Source:      "nuclei-templates",
			}
			if existing, exists := cat.byID[id]; exists && existing.Source == "active" {
				// Preserve active-verified flag while enriching metadata from cves.json.
				entry.Source = "active+nuclei"
			}
			cat.byID[id] = entry
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	cat.ordered = make([]CVECatalogEntry, 0, len(cat.byID))
	for _, e := range cat.byID {
		cat.ordered = append(cat.ordered, e)
	}
	sort.Slice(cat.ordered, func(i, j int) bool {
		return cat.ordered[i].ID < cat.ordered[j].ID
	})
	return cat, nil
}

func parseCVEYear(id string) int {
	parts := strings.Split(id, "-")
	if len(parts) < 3 {
		return 0
	}
	y, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return y
}

// Lookup returns a single CVE entry by ID (case-insensitive).
func (c *CVECatalog) Lookup(id string) (CVECatalogEntry, bool) {
	if c == nil {
		return CVECatalogEntry{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.byID[strings.ToUpper(strings.TrimSpace(id))]
	return e, ok
}

// Search filters catalog entries by substring across ID, Name, Description, or Template.
func (c *CVECatalog) Search(query string, limit int) []CVECatalogEntry {
	if c == nil {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if limit <= 0 {
		limit = 50
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	var out []CVECatalogEntry
	for _, e := range c.ordered {
		if q == "" ||
			strings.Contains(strings.ToLower(e.ID), q) ||
			strings.Contains(strings.ToLower(e.Name), q) ||
			strings.Contains(strings.ToLower(e.Description), q) ||
			strings.Contains(strings.ToLower(e.Template), q) {
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

// Stats returns counts by year and severity across the loaded catalog.
func (c *CVECatalog) Stats() CVECatalogStats {
	stats := CVECatalogStats{
		ByYear:     map[int]int{},
		BySeverity: map[string]int{},
	}
	if c == nil {
		return stats
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats.Total = len(c.ordered)
	stats.CatalogDir = c.source
	for _, e := range c.ordered {
		if e.Year > 0 {
			stats.ByYear[e.Year]++
			if stats.MinYear == 0 || e.Year < stats.MinYear {
				stats.MinYear = e.Year
			}
			if e.Year > stats.MaxYear {
				stats.MaxYear = e.Year
			}
		}
		sev := e.Severity
		if sev == "" {
			sev = "unknown"
		}
		stats.BySeverity[sev]++
	}
	return stats
}
