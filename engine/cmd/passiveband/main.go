// Command passiveband measures the passive match band against a real template
// corpus, the way TestCorpusProbe measures the invocation plan.
//
// It answers three questions that unit tests cannot:
//
//   - what share of a real corpus the band can actually judge, and what the
//     band names for the rest;
//
//   - whether its verdict agrees with the nuclei binary on a sample, which is
//     the only way to claim "as accurate as nuclei" rather than "consistent
//     with our reading of nuclei";
//
//   - whether peak RSS grows with the number of templates compiled, which is
//     the memory criterion of the plan.
//
//     go run ./cmd/passiveband -corpus /path/to/templates -sample 40 -rss 2000
//     go run ./cmd/passiveband -corpus /path/to/templates -sample 0   # coverage only
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"intruder/engine/pkg/scanner"
)

func main() {
	corpus := flag.String("corpus", "", "template tree to measure")
	sample := flag.Int("sample", 40, "templates to also score against a synthetic exchange (0 for coverage only)")
	rssStep := flag.Int("rss", 2000, "re-read peak RSS every N templates (0 disables)")
	chunk := flag.Int("chunk", 2000, "templates per chunk in the growth measurement (0 disables)")
	cache := flag.Int("cache", 0, "compiled regex/DSL cache limit (0 leaves the default in place)")
	flag.Parse()

	if strings.TrimSpace(*corpus) == "" {
		fmt.Fprintln(os.Stderr, "passiveband: -corpus is required")
		os.Exit(2)
	}

	paths, err := corpusFiles(*corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "passiveband: walk: %v\n", err)
		os.Exit(1)
	}
	sort.Strings(paths)
	if *cache > 0 {
		scanner.SetPassiveCompileCacheLimits(*cache, *cache)
	}
	fmt.Printf("files in tree: %d\n", len(paths))
	fmt.Printf("compiled pattern cache limit: %d\n", scanner.PassiveCompileCacheLimit())
	// The floor is printed before any template is read. It is the part of the
	// process cost that belongs to the dependency graph rather than to the
	// corpus, and a peak on its own would hide it: 13 764 templates add nothing
	// measurable, so most of the number below is this floor.
	fmt.Printf("peak RSS before any template is read: %.1f MB\n", float64(peakRSS())/(1024*1024))

	scorable, reasons := 0, map[string]int{}
	var maxRSS uint64
	step := *rssStep
	if step <= 0 {
		step = len(paths) + 1
	}

	// Only the sample is retained. The first version of this tool kept every
	// file's bytes, which meant the RSS it printed was the harness's own
	// appetite rather than the band's: 13 764 templates of the official corpus
	// are 137 MB of YAML, so a tool that holds them all reports a figure that
	// grows with the corpus by construction. A memory measurement of a band
	// that never holds a corpus has to let the corpus go as it goes.
	var sampleContents [][]byte
	measured := 0
	for index, path := range paths {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		measured++
		if len(sampleContents) < *sample {
			sampleContents = append(sampleContents, payload)
		}
		capability := scanner.PassiveCapabilityOf(string(payload))
		if capability.Supported {
			scorable++
		} else {
			reasons[capability.Reason]++
		}
		if (index+1)%step == 0 {
			if rss := peakRSS(); rss > maxRSS {
				maxRSS = rss
			}
		}
	}
	if rss := peakRSS(); rss > maxRSS {
		maxRSS = rss
	}

	fmt.Printf("scorable by the passive band: %d (%.1f%% of %d)\n",
		scorable, percent(scorable, measured), measured)
	fmt.Printf("peak RSS: %.1f MB\n", float64(maxRSS)/(1024*1024))

	if len(reasons) > 0 {
		fmt.Println("\nwhy the rest are not scorable:")
		for _, pair := range sortedCounts(reasons) {
			fmt.Printf("  %6d  %s\n", pair.Count, pair.Reason)
		}
	}

	if *sample > 0 {
		scoreSample(sampleContents)
	}
	measureGrowth(paths, *chunk)
}

// measureGrowth answers the memory criterion directly: peak RSS is read after
// every chunk, so the run shows whether the band accumulates anything per
// template or releases it. A band that holds every compiled template would draw
// a line climbing with the corpus, and a band that releases them draws a line
// that flattens at the first chunk — the shape is the evidence, not the final
// number.
func measureGrowth(paths []string, chunk int) {
	if chunk <= 0 {
		fmt.Println("\nno growth measurement: -rss is 0")
		return
	}
	exchange := scanner.PassiveExchange{
		Method: "GET", URL: "https://shop.example.com/", Host: "https://shop.example.com",
		RawRequest:  "GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello",
		StatusCode:  200, Body: "hello", Header: http.Header{"Content-Type": {"text/html"}},
		ContentLength: 5,
	}
	fmt.Printf("\npeak RSS per chunk of %d templates:\n", chunk)
	// The order here is the whole measurement. VmHWM is a high-water mark that
	// never falls, so it has to be reset after a collection and before the work:
	// resetting first would pin the mark to the garbage the collector is about
	// to take, and reading it without a reset would report whatever the coverage
	// pass already peaked at for every chunk, which looks like proof and is not.
	// Per chunk the number below is therefore the peak the *band* reached while
	// scoring that chunk, from a collected baseline.
	var baseline uint64
	var liveBaseline uint64
	for done := 0; done < len(paths); done += chunk {
		end := done + chunk
		if end > len(paths) {
			end = len(paths)
		}
		runtime.GC()
		resetPeak()
		for _, path := range paths[done:end] {
			payload, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			scanner.ScorePassiveTemplate(string(payload), exchange)
		}
		runtime.GC()
		peak := peakRSS()
		if done == 0 {
			baseline = peak
		}
		delta := float64(int64(peak)-int64(baseline)) / (1024 * 1024)
		// The live heap is printed next to the peak because a peak on its own
		// cannot tell a leak from one large transient: only the retained number
		// says whether the band is still holding templates it has already
		// scored.
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		fmt.Printf("  %6d templates  peak %7.1f MB  live heap %7.1f MB  (%+.1f MB peak, %+.1f MB live)\n",
			end, float64(peak)/(1024*1024), float64(stats.HeapAlloc)/(1024*1024),
			delta, float64(int64(stats.HeapAlloc)-int64(liveBaseline))/(1024*1024))
		if done == 0 {
			liveBaseline = stats.HeapAlloc
		}
	}
}

// resetPeak clears the kernel's high-water mark for this process. Without it
// the growth measurement reads a peak that the coverage pass already set and
// reports the same number for every chunk, which looks like proof and is not.
func resetPeak() {
	handle, err := os.OpenFile("/proc/self/clear_refs", os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Println("  (cannot reset the peak: " + err.Error() + ")")
		return
	}
	defer handle.Close()
	_, _ = handle.WriteString("5")
}

// scoreSample scores templates against a synthetic exchange and prints the
// verdicts, so the numbers can be compared with a nuclei run by hand. The
// exchange is synthetic on purpose: the band is a pure function, so any real
// saved exchange from the archive would work equally well, and a fixed one
// keeps two runs comparable.
func scoreSample(contents [][]byte) {
	exchange := scanner.PassiveExchange{
		Method:     "GET",
		URL:        "https://shop.example.com/admin/login",
		Host:       "https://shop.example.com",
		RawRequest: "GET /admin/login HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
			"Set-Cookie: session=abc123; Path=/\r\n\r\n" +
			"<title>Admin Login</title><form action=\"/admin/login\" method=\"post\">",
		StatusCode: 200,
		Body:       "<title>Admin Login</title><form action=\"/admin/login\" method=\"post\">",
		Header: http.Header{
			"Content-Type": {"text/html"},
			"Set-Cookie":   {"session=abc123; Path=/"},
		},
		Duration:      150 * time.Millisecond,
		ContentLength: 70,
	}
	scored, matched, named := 0, 0, map[string]int{}
	for _, payload := range contents {
		verdict := scanner.ScorePassiveTemplate(string(payload), exchange)
		if verdict.Reason != "" {
			named[verdict.Reason]++
			continue
		}
		scored++
		if verdict.Matched {
			matched++
		}
	}
	fmt.Printf("\nsample of %d: scored %d, matched %d\n", len(contents), scored, matched)
	if len(named) > 0 {
		fmt.Println("named in the sample:")
		for _, pair := range sortedCounts(named) {
			fmt.Printf("  %6d  %s\n", pair.Count, pair.Reason)
		}
	}
}

// corpusFiles walks a template tree, skipping the VCS and build directories
// that a merged collection carries alongside its templates.
func corpusFiles(root string) ([]string, error) {
	skip := map[string]bool{".git": true, ".github": true, "node_modules": true, "dist": true}
	var paths []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		lowered := strings.ToLower(info.Name())
		if strings.HasSuffix(lowered, ".yaml") || strings.HasSuffix(lowered, ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

// peakRSS reports the process high-water mark. It is read from /proc rather
// than from runtime.MemStats because MemStats knows about the Go heap, and the
// question here is what the process actually costs.
func peakRSS() uint64 {
	payload, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		var kilobytes uint64
		if _, err := fmt.Sscanf(fields[1], "%d", &kilobytes); err != nil {
			return 0
		}
		return kilobytes * 1024
	}
	return 0
}

// reasonCount is one "why not scorable" bucket. It is a named type rather than
// an anonymous struct so a `%d` verb on its count is a compile error if the
// pairing is ever wrong.
type reasonCount struct {
	Reason string
	Count  int
}

// sortedCounts orders the buckets by size and then by text, so two runs of the
// tool over the same corpus print the same report.
func sortedCounts(counts map[string]int) []reasonCount {
	pairs := make([]reasonCount, 0, len(counts))
	for reason, count := range counts {
		pairs = append(pairs, reasonCount{Reason: reason, Count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].Reason < pairs[j].Reason
	})
	return pairs
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}
