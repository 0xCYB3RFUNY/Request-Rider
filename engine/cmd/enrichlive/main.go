// Command enrichlive measures the Target enrichment analysers against a real
// site.
//
// It exists because of the rule that a fixture proves the code reads our bytes
// and a live target proves the code reads anyone else's. Every other number this
// project reports about a port came from a fixture; this is the one that says
// whether the analysers find anything in the wild, and what they find that a
// fixture would never have contained.
//
// It is a measurement tool, not a scanner: it fetches, it never sends anything
// else, it writes nothing outside its own stdout, and it holds no state.
//
// Usage:
//
//	go run ./cmd/enrichlive https://ria.ru/
//	go run ./cmd/enrichlive -depth 1 -pages 5 https://example.ru/
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"intruder/engine/pkg/enrich"
)

func main() {
	var depth, pages, timeoutMS int
	flag.IntVar(&depth, "depth", 1, "how many link levels to follow")
	flag.IntVar(&pages, "pages", 5, "maximum pages to fetch")
	flag.IntVar(&timeoutMS, "timeout", 15000, "per-request timeout in ms")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: enrichlive [flags] <url>")
		os.Exit(2)
	}
	target, err := url.Parse(flag.Arg(0))
	if err != nil || target.Scheme == "" || target.Host == "" {
		fmt.Fprintf(os.Stderr, "not an absolute http(s) URL: %q\n", flag.Arg(0))
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Printf("# enrichlive %s  depth=%d pages=%d\n", target, depth, pages)

	type frontierItem struct {
		rawURL string
		d      int
	}
	queue := []frontierItem{{target.String(), 0}}
	seen := map[string]bool{target.String(): true}

	totals := map[string]int{}
	fetched := 0
	patternHits := map[string]int{}
	var notable []enrich.NotableFile
	infoKinds := map[string]int{}
	csrfKinds := map[string]int{}
	rejectedKinds := map[string]int{}
	hosts := map[string]bool{}
	var sampleFindings []string

	for len(queue) > 0 && fetched < pages {
		item := queue[0]
		queue = queue[1:]

		req, err := http.NewRequest(http.MethodGet, item.rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("- %s\n  transport: %v\n", item.rawURL, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			fmt.Printf("- %s\n  body: %v\n", item.rawURL, readErr)
			continue
		}
		fetched++

		contentType := resp.Header.Get("Content-Type")
		analysis := enrich.Analyse(item.rawURL, body, resp.Header, contentType, enrich.Options{
			OriginHost: target.Host,
		})
		counts := analysis.Counts()
		totals["pages"]++
		totals["notable_files"] += counts.NotableFiles
		totals["patterns"] += counts.Patterns
		totals["info"] += counts.Info
		totals["csrf_issues"] += counts.CSRFIssues
		totals["reused_tokens"] += counts.ReusedTokens
		totals["secrets"] += counts.Secrets
		totals["rejected_secrets"] += counts.RejectedSecrets
		for id, n := range analysis.PatternCounts {
			patternHits[id] += n
		}
		for _, i := range analysis.Info {
			infoKinds[string(i.Kind)]++
		}
		if analysis.Secrets != nil {
			for _, f := range analysis.Secrets.Findings {
				if len(sampleFindings) < 60 {
					sampleFindings = append(sampleFindings,
						fmt.Sprintf("SECRET %s score=%d L%d %s", f.Rule, f.Score, f.Line, truncate(f.Value, 60)))
				}
			}
			for _, r := range analysis.Secrets.Rejected {
				rejectedKinds[r.Reason]++
			}
		}
		if analysis.CSRF != nil {
			for _, issue := range analysis.CSRF.Issues {
				csrfKinds[string(issue.Kind)]++
			}
			for _, reuse := range analysis.CSRF.Reused {
				sampleFindings = append(sampleFindings,
					fmt.Sprintf("csrf-reuse %s on %s", reuse.Value, strings.Join(reuse.Forms, ",")))
			}
		}
		for _, f := range analysis.NotableFiles {
			notable = append(notable, f)
		}
		for _, h := range analysis.ExternalHosts {
			hosts[h] = true
		}
		for _, m := range analysis.Patterns {
			if len(sampleFindings) < 40 {
				sampleFindings = append(sampleFindings,
					fmt.Sprintf("%s L%d %s", m.Pattern, m.Line, truncate(m.Value, 90)))
			}
		}
		for _, i := range analysis.Info {
			if len(sampleFindings) < 40 {
				sampleFindings = append(sampleFindings,
					fmt.Sprintf("info/%s L%d %s", i.Kind, i.Line, truncate(i.Value, 90)))
			}
		}

		fmt.Printf("- %s\n  status=%d type=%s bytes=%d notable=%d patterns=%d info=%d csrf=%d hosts=%d secrets=%d rejected=%d rulesRun=%d\n",
			item.rawURL, resp.StatusCode, contentType, len(body),
			counts.NotableFiles, counts.Patterns, counts.Info, counts.CSRFIssues, counts.Hosts,
			counts.Secrets, counts.RejectedSecrets, counts.SecretRulesRun)

		if item.d >= depth {
			continue
		}
		for _, ref := range enrich.Fetchable(analysis.References) {
			next, err := target.Parse(ref)
			if err != nil {
				continue
			}
			if next.Scheme != "http" && next.Scheme != "https" {
				continue
			}
			next.Fragment = ""
			if seen[next.String()] {
				continue
			}
			seen[next.String()] = true
			queue = append(queue, frontierItem{next.String(), item.d + 1})
		}
	}

	fmt.Printf("\n## totals (real numbers, not estimates)\n")
	keys := make([]string, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-16s %d\n", k, totals[k])
	}

	fmt.Printf("\n## pattern hits\n")
	pk := make([]string, 0, len(patternHits))
	for k := range patternHits {
		pk = append(pk, k)
	}
	sort.Strings(pk)
	for _, k := range pk {
		fmt.Printf("  %-16s %d\n", k, patternHits[k])
	}

	fmt.Printf("\n## info classes\n")
	ik := make([]string, 0, len(infoKinds))
	for k := range infoKinds {
		ik = append(ik, k)
	}
	sort.Strings(ik)
	for _, k := range ik {
		fmt.Printf("  %-20s %d\n", k, infoKinds[k])
	}

	fmt.Printf("\n## csrf classes\n")
	ck := make([]string, 0, len(csrfKinds))
	for k := range csrfKinds {
		ck = append(ck, k)
	}
	sort.Strings(ck)
	for _, k := range ck {
		fmt.Printf("  %-20s %d\n", k, csrfKinds[k])
	}

	fmt.Printf("\n## rejected secret matches (why)\n")
	rk := make([]string, 0, len(rejectedKinds))
	for k := range rejectedKinds {
		rk = append(rk, k)
	}
	sort.Strings(rk)
	for _, k := range rk {
		fmt.Printf("  %6d  %s\n", rejectedKinds[k], truncate(k, 90))
	}

	fmt.Printf("\n## notable files (top 20 by severity)\n")
	if len(notable) > 20 {
		sort.Slice(notable, func(i, j int) bool { return notable[i].Severity > notable[j].Severity })
		notable = notable[:20]
	}
	for _, f := range notable {
		fmt.Printf("  sev=%d %-10s %s\n", f.Severity, f.Ext, truncate(f.URL, 120))
	}

	fmt.Printf("\n## external hosts (%d)\n", len(hosts))
	hk := make([]string, 0, len(hosts))
	for k := range hosts {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	for _, k := range hk {
		fmt.Printf("  %s\n", k)
	}

	fmt.Printf("\n## sample findings (first 40)\n")
	for _, s := range sampleFindings {
		fmt.Printf("  %s\n", s)
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
