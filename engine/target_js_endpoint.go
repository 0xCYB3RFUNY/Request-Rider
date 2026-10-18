package main

// JavaScript analysis on request, for the crawler that cannot fetch a body itself.
//
// # Why this exists
//
// The Target crawler has two modes and only one of them could report what a
// JavaScript file says.
//
// The static crawler fetches the bytes itself, so `analyzeJavaScript` runs on
// them inside the crawl and the page record carries `page["js"]`. Measured on a
// live target: 19 endpoints and 21 findings out of one 150 KB bundle.
//
// The browser-driven mode never fetches a body. `browser-worker` drives a real
// browser and reports the pages it navigated plus the requests the page made, so
// every `.js` the site loaded is *seen as a URL* and *read as a program* by
// nobody. The analyst sees the script in the network list and gets no endpoints,
// no sinks and no secrets from it — the same file, a different answer, and
// nothing on the screen to say why.
//
// So this is the missing half as its own endpoint rather than as a hidden second
// path inside the crawl: the gateway hands the engine the script URLs a
// browser-driven job reported, and gets back the same page record the static
// crawler would have produced. One analyser, one transport, one record shape —
// which is what makes the two modes comparable at all.
//
// # Why the fetch is not a shortcut
//
// The request goes through `newCrawlerClient(s.requestTransport(), …)` and
// `crawlOnce`, which is the same client, the same route transport, the same
// retry and rate-limit handling and the same `source_ip` lookup the crawl uses.
// A separate `http.Get` here would be a second way out of the process for the
// same target: no route generation, no per-exchange source IP, no anti-detect
// shape. That is precisely the duplication the file header of
// `target_javascript.go` refuses, and it is why this is a handler rather than a
// helper the gateway calls into through some other channel.
//
// # What it deliberately does not do
//
// It does not crawl. There is no queue, no depth, no page budget: it reads the
// URLs it is given, in the order it is given them, and answers about each one.
// Whatever discovered those URLs stays that crawler's business — the static
// crawl discovers them by parsing documents, the browser mode by watching the
// network, and neither learns anything new from the other here.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// targetJSAnalysisRequest is what the gateway sends: the script URLs a job saw.
//
// A URL may be given as a bare string or as an object carrying the page it was
// loaded from. The object form exists because a browser-driven crawl knows the
// referrer of every script, and some CDNs answer differently to a bundle request
// that claims to come from nowhere — a bare string would then make the same site
// look different from the two modes depending on which crawler asked.
type targetJSAnalysisRequest struct {
	URLs []json.RawMessage `json:"urls"`
	// Referer is the fallback for entries given as bare strings, so the common
	// case stays one field and the per-script case stays exact.
	Referer string `json:"referer"`
	// Concurrency is how many bundles the operator wants read at once. Zero means
	// "no preference", not "one": a page with one script and a page with sixty
	// should not cost the same setup, and a caller that did not ask must not be
	// silently given a serial loop either. A negative value is refused.
	Concurrency int `json:"concurrency"`
}

// targetScriptRef is one script to read, with the page it was loaded from.
type targetScriptRef struct {
	URL     string
	Referer string
}

// normalizeScriptRefs reads both accepted forms into one list, and refuses an
// entry that names no URL rather than dropping it silently: a list that quietly
// loses entries is a list whose length the analyst cannot trust.
func normalizeScriptRefs(raw []json.RawMessage, fallbackReferer string) ([]targetScriptRef, string) {
	refs := make([]targetScriptRef, 0, len(raw))
	rejected := ""
	for _, entry := range raw {
		var asString string
		if err := json.Unmarshal(entry, &asString); err == nil {
			refs = append(refs, targetScriptRef{URL: asString, Referer: fallbackReferer})
			continue
		}
		var asObject struct {
			URL     string `json:"url"`
			Referer string `json:"referer"`
		}
		if err := json.Unmarshal(entry, &asObject); err == nil && strings.TrimSpace(asObject.URL) != "" {
			referer := strings.TrimSpace(asObject.Referer)
			if referer == "" {
				referer = fallbackReferer
			}
			refs = append(refs, targetScriptRef{URL: asObject.URL, Referer: referer})
			continue
		}
		if rejected == "" {
			rejected = "an entry named no url"
		}
	}
	return refs, rejected
}

// targetJSAnalysisEntry is one answer: a URL, what the server said, and the
// analysis when the bytes turned out to be a program.
//
// The record is the crawler's own page shape — `kind`, `content_type`, `status`,
// `js` — rather than a new one, so the gateway can put it in front of the same
// renderer and the same exporters that already draw a statically crawled
// bundle. A second record shape would mean a second renderer, and the report
// would have to explain which crawler produced which row.
type targetJSAnalysisEntry struct {
	URL         string                 `json:"url"`
	Kind        string                 `json:"kind"`
	Status      int                    `json:"status"`
	ContentType string                 `json:"content_type"`
	Bytes       int                    `json:"bytes"`
	Time        int64                  `json:"time"`
	Millis      int64                  `json:"ms"`
	JS          map[string]interface{} `json:"js,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// targetJSAnalysisHandler answers "what does this JavaScript file say" for a list
// of URLs.
func (s *server) targetJSAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input targetJSAnalysisRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	refs, rejected := normalizeScriptRefs(input.URLs, input.Referer)
	if input.Concurrency < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_CONCURRENCY",
			fmt.Errorf("concurrency %d is not a worker count", input.Concurrency))
		return
	}
	entries, peak := s.analyzeScriptURLs(r.Context(), refs, input.Concurrency)
	answer := map[string]interface{}{"results": entries, "peak_parallel": peak}
	if rejected != "" {
		answer["warning"] = rejected
	}
	writeJSON(w, http.StatusOK, answer)
}

// analyzeScriptURLs reads and analyses every distinct script URL.
//
// Three things are decided here rather than by the caller, because the caller
// is a JSON gateway and would have to answer them differently:
//
//   - **Duplicates are analysed once.** A page loads the same bundle from several
//     component bundles, and parsing it once per occurrence would pay the most
//     expensive operation in the process for a file already read.
//   - **The crawler decides what a program is, not this handler.** It reuses
//     `isJavaScriptResource` verbatim, so a resource queued as `javascript` is
//     analysed whatever it turned out to contain, and a document that is neither
//     queued as a script nor served as one is reported as itself. A stricter rule
//     here would mean the same bytes are read in one mode and skipped in the
//     other, with nothing on the screen to explain the difference.
//   - **One failure does not lose the others.** A bundle on a host that has gone
//     away must not blank the analysis of the eleven that loaded.
//
// The reads run concurrently. That is the capability the source listing calls
// "concurrent processing", and the reason it is worth having is measurable: a
// page's bundle set spends its wall clock waiting for bytes, not parsing them, so
// a sequential loop costs the operator the sum of every bundle's latency instead
// of the slowest one.
//
// The *order* of the answer is still the order of the request, because that order
// is a contract: the export writes it and the browser tests read it. Completion
// order is not stable, so the result is rebuilt from the index each job was
// dispatched at rather than from the order the workers happened to finish in.
//
// The concurrency is bounded, and the bound is visible twice: it is settable per
// request (`concurrency`) and from the environment (`RR_SCRIPT_ANALYSIS_WORKERS`),
// and the peak that was actually reached comes back in `peak_parallel`. A cap
// nobody can see or raise is precisely what this project forbids, so the
// response says what it did instead of quietly doing less than asked.
func (s *server) analyzeScriptURLs(ctx context.Context, refs []targetScriptRef, concurrency int) ([]targetJSAnalysisEntry, int) {
	// The dispatch list is built exactly as the sequential version built it: same
	// duplicate rule, same order, same refusal of a non-http URL. Turning
	// concurrency on must change the wall clock and nothing else, so this part is
	// still a straight loop.
	seen := make(map[string]bool, len(refs))
	jobs := make([]scriptAnalysisJob, 0, len(refs))
	for _, ref := range refs {
		reference := strings.TrimSpace(ref.URL)
		if reference == "" || seen[reference] {
			continue
		}
		seen[reference] = true
		current := scriptAnalysisJob{index: len(jobs), entry: targetJSAnalysisEntry{URL: reference}}
		parsed, err := url.Parse(reference)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			current.entry.Error = "not an http(s) url"
		} else {
			current.target = parsed
			current.readable = true
			current.referer = ref.Referer
		}
		jobs = append(jobs, current)
	}

	results := make([]targetJSAnalysisEntry, len(jobs))
	for i := range jobs {
		results[jobs[i].index] = jobs[i].entry
	}

	workers := scriptAnalysisConcurrency(len(jobs), concurrency)
	return results, s.scriptAnalysisWorkers(ctx, workers, jobs, results)
}

// scriptAnalysisConcurrency decides how many reads may be in flight at once.
//
// Three rules, in order: what the caller asked for wins, because an explicit
// request field is the project's rule for limits; then the environment, which is
// the deployment's own ceiling; then the default, which is only reached when
// nobody said anything. A non-positive answer from either source is refused
// rather than clamped, because silently turning "unlimited" into eight would be
// the hidden cap this project bans.
func scriptAnalysisConcurrency(total, requested int) int {
	workers := 0
	if requested > 0 {
		workers = requested
	} else if raw := strings.TrimSpace(os.Getenv("RR_SCRIPT_ANALYSIS_WORKERS")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			// A value nobody can read is worse than no value: it would look like
			// the default was chosen. Say so where the operator can see it.
			log.Printf("RR_SCRIPT_ANALYSIS_WORKERS=%q is not a worker count; using the default", raw)
		} else {
			workers = parsed
		}
	}
	if workers == 0 {
		workers = defaultScriptAnalysisWorkers
	}
	if total > 0 && workers > total {
		workers = total
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// defaultScriptAnalysisWorkers is the value used when nobody asked for one.
//
// It is a *transport* ceiling, not a scope limit: it says how many bundles are
// read at once, never how many may be read. A page with sixty bundles still gets
// all sixty analysed, sixty at a time at worst. The number is small because the
// cost of being wrong is asymmetric — a server that answers thirty simultaneous
// requests slower than it answers six serves both cases worse, while the operator
// simply sees `peak_parallel` and can raise it.
const defaultScriptAnalysisWorkers = 8

// scriptAnalysisJob is one dispatched read: the index it must answer into, the
// URL to read, and the entry already holding what is known before the read.
//
// The entry exists at dispatch time so that a job whose URL was refused arrives
// at the pool with its verdict already written, and the worker only has to know
// whether there is something left to read.
type scriptAnalysisJob struct {
	index    int
	target   *url.URL
	entry    targetJSAnalysisEntry
	readable bool
	// referer is the page the script was loaded from, and it is carried
	// separately from `entry.URL` on purpose: passing the script's own address as
	// its referrer is the mistake this field exists to prevent. Some CDNs answer a
	// bundle request that claims to come from nowhere differently from one that
	// names its page, and the answer then says the file is missing when it is
	// served. The field was lost once during the rewrite to a pool and its own test
	// caught it.
	referer string
}

// scriptAnalysisWorkers runs the readable jobs through a bounded pool and writes
// each answer back into the slot its index names.
//
// Two workers therefore never touch the same element: `results` is pre-sized and
// indexed by the dispatch position, and a job either writes its own slot or
// leaves the one the dispatch loop already put there. The only shared mutable
// state is the running count used to report the peak, which is why that one is
// guarded and the slots are not.
//
// The bound is a semaphore, and the direction of the token is the whole
// mechanism: a worker **puts** a token in before starting and **takes** it out
// when it finishes. The first version took one out when it finished without
// putting one back, so the channel drained to empty and the next worker blocked
// on `<-slots` forever — a deadlock that the test with six staggered reads
// found on its first run.
//
// A job that cannot take a token is run on the dispatching goroutine instead of
// waiting for one to appear. That keeps the pool bounded and never blocks the
// caller, and the answer still lands in its own slot.
func (s *server) scriptAnalysisWorkers(ctx context.Context, workers int, jobs []scriptAnalysisJob, results []targetJSAnalysisEntry) int {
	if workers < 1 {
		workers = 1
	}
	var (
		mu    sync.Mutex
		inUse int
		peak  int
		wg    sync.WaitGroup
	)
	// One semaphore, one owner: it is created here and closed over by both
	// helpers, so nothing outside can hand out or reclaim a token.
	slots := make(chan struct{}, workers)
	acquire := func() bool {
		select {
		case slots <- struct{}{}:
			mu.Lock()
			inUse++
			if inUse > peak {
				peak = inUse
			}
			mu.Unlock()
			return true
		default:
			return false
		}
	}
	release := func() {
		<-slots
		mu.Lock()
		inUse--
		mu.Unlock()
	}

	for i := range jobs {
		if !jobs[i].readable {
			continue
		}
		if !acquire() {
			results[jobs[i].index] = s.analyzeScriptURL(ctx, jobs[i].target, jobs[i].referer)
			continue
		}
		wg.Add(1)
		go func(current scriptAnalysisJob) {
			defer wg.Done()
			defer release()
			results[current.index] = s.analyzeScriptURL(ctx, current.target, current.referer)
		}(jobs[i])
	}
	wg.Wait()
	return peak
}

// analyzeScriptURL fetches one URL the way the crawler fetches, and analyses it
// when what came back is a program.
func (s *server) analyzeScriptURL(ctx context.Context, target *url.URL, referer string) targetJSAnalysisEntry {
	entry := targetJSAnalysisEntry{URL: target.String()}
	kind := classifyScriptURL(target)
	shape := crawlerRequestShape{}
	client, err := newCrawlerClient(s.requestTransport(), shape)
	if err != nil {
		entry.Error = "cookie jar: " + err.Error()
		return entry
	}
	request, err := javascriptRequest(ctx, target, referer)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	// Fetch time and analysis time are two numbers, not one. The crawler's page
	// record reports how long the read took, and the analysis reports how long the
	// parse took; folding them together would make a slow site and a heavy bundle
	// indistinguishable on the same row.
	fetchStarted := time.Now()
	outcome, err := crawlOnce(ctx, client, request, shape)
	if err != nil {
		entry.Time = time.Since(fetchStarted).Milliseconds()
		entry.Error = err.Error()
		return entry
	}
	response := outcome.resp
	if response == nil {
		entry.Time = time.Since(fetchStarted).Milliseconds()
		entry.Error = "no response"
		return entry
	}
	defer response.Body.Close()
	entry.Status = response.StatusCode
	entry.ContentType = response.Header.Get("Content-Type")
	// The read is the crawler's own and it is unbounded in both paths. A
	// half-read bundle would be a statement about our read rather than about the
	// site, so nothing here is analysed short: `readAnalysisBody` reports whether
	// it stopped early, and today it never does. Inventing a ceiling the crawl
	// does not have would make this path answer about fewer bytes than the crawl
	// does for the same file, which is the divergence this handler exists to
	// remove.
	body, _, readErr := readAnalysisBody(response.Body)
	entry.Kind = kind
	entry.Bytes = len(body)
	entry.Time = time.Since(fetchStarted).Milliseconds()
	if readErr != nil {
		entry.Error = readErr.Error()
		return entry
	}
	if !isJavaScriptResource(kind, entry.ContentType) {
		return entry
	}
	started := time.Now()
	analysis := analyzeJavaScript(target.String(), body)
	analysis.Millis = time.Since(started).Milliseconds()
	encoded, err := json.Marshal(analysis)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	decoded := map[string]interface{}{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		entry.Error = err.Error()
		return entry
	}
	entry.JS = decoded
	return entry
}

// javascriptRequest builds the request for a script read.
//
// The Accept header names the script media types and nothing else, so a server
// that varies on Accept answers with the program rather than with a fallback
// document — which is the same thing a browser asks for and the reason the
// static crawler and this handler see the same bytes for the same URL.
func javascriptRequest(ctx context.Context, target *url.URL, referer string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/javascript, text/javascript, application/ecmascript, text/ecmascript, */*;q=0.8")
	if referer != "" {
		request.Header.Set("Referer", referer)
	}
	return request, nil
}

// classifyScriptURL names what a URL looked like before anything was fetched.
//
// The suffix is read because it is what the crawler queued it as, and a network
// log has no other classification: the browser worker's `resource_type` says
// "script", and the extension is what survives into the URL the gateway forwards.
// A URL that does not look like a script is still fetched — a server may serve a
// program from a path with no extension — and the content type decides afterwards.
func classifyScriptURL(target *url.URL) string {
	path := strings.ToLower(target.Path)
	switch {
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"):
		return "javascript"
	case strings.HasSuffix(path, ".json"), strings.HasSuffix(path, ".map"):
		return "json"
	default:
		return "page"
	}
}
