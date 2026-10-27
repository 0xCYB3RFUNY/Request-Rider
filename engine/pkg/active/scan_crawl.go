package active

// The crawl, and the small pieces of run bookkeeping the orchestrator uses.
//
// The upstream crawler is a loop over twenty hard-coded paths — `/login`,
// `/admin`, `/api/v1/users` and the rest — on one host, with no link following
// and no content check. That finds the paths a developer already thought about
// and none of the ones they did not, and on any application whose interesting
// surface is under a different path it reports an empty site.
//
// This one reads the links the application itself publishes, harvests the
// injectable surfaces out of the pages it fetched, and records every request it
// made so a report can be checked against the target's own logs.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"intruder/engine/pkg/runstate"
)

// page is one fetched page, with the body kept because the body is where the
// injectable surfaces are.
type page struct {
	URL         string
	Body        string
	ContentType string
	StatusCode  int
	Depth       int
}

// linkPattern finds href and src destinations in a body. It is a link extractor
// and nothing more: a link is a URL, and deciding whether the URL is worth
// fetching is the frontier's job, not the pattern's.
var linkPattern = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*(?:["']([^"'>]+)["']|([^\s"'<>]+))`)

// crawl walks the target and returns the pages it fetched.
//
// The walk is breadth-first because a breadth-first walk is what shows the
// operator the shallow surface first, and the shallow surface is where a
// researcher's next click is. It stops on `MaxPages`, on `MaxDepth`, when the
// frontier empties, or when the context is cancelled — and it reports which of
// those it was, because a run that stopped at its page budget and a run that ran
// out of links are different results.
func (s *Scan) crawl(ctx context.Context, transport *Transport, start *url.URL) ([]page, []string, int, error) {
	origin := start.Scheme + "://" + start.Host
	visited := map[string]bool{start.String(): true}
	queue := []page{{URL: start.String(), Depth: 0}}
	var out []page
	var warnings []string
	requests := 0
	var lastErr error

	for len(queue) > 0 {
		if ctx.Err() != nil {
			return out, append(warnings, "crawl cancelled"), requests, ctx.Err()
		}
		// The run's own page budget, checked here rather than after the fetch,
		// so the run stops at the number the operator gave.
		if s.request.MaxPages > 0 && len(out) >= s.request.MaxPages {
			return out, append(warnings, fmt.Sprintf(
				"stopped at the requested %d page(s); %d link(s) were still queued", s.request.MaxPages, len(queue))), requests, nil
		}
		current := queue[0]
		queue = queue[1:]

		resp, err := transport.Do(ctx, "GET", current.URL, nil, s.request.FollowRedirects, nil)
		if errors.Is(err, runstate.ErrPaused) {
			// The pause dropped this page mid-flight. It goes back to the front of
			// the queue rather than being dropped: the operator paused the run, they
			// did not abandon the page, and a frontier that loses the page a pause
			// interrupted is a frontier that quietly loses work.
			queue = append([]page{current}, queue...)
			if waitErr := s.awaitResume(ctx); waitErr != nil {
				return out, append(warnings, "crawl cancelled"), requests, waitErr
			}
			continue
		}
		requests++
		if err != nil {
			lastErr = err
			warnings = append(warnings, fmt.Sprintf("%s: %v", current.URL, err))
			continue
		}
		current.Body = resp.Body
		current.ContentType = resp.Header.Get("Content-Type")
		current.StatusCode = resp.StatusCode
		out = append(out, current)
		s.trace("fetched", current.URL, fmt.Sprintf("%d, %d bytes, depth %d",
			resp.StatusCode, len(resp.Body), current.Depth))
		s.emit(Progress{
			Phase: "crawling", PagesFetched: len(out), PagesTotal: -1, PointsTotal: -1,
			Detail: fmt.Sprintf("%d page(s) fetched, %d link(s) queued", len(out), len(queue)),
		})

		if current.Depth == 0 && resp.FinalURL != "" {
			if finalParsed, err := url.Parse(resp.FinalURL); err == nil && finalParsed.Host != "" {
				origin = finalParsed.Scheme + "://" + finalParsed.Host
			}
		}
		// A body is only followed for links when it is a body. Following links
		// out of a stylesheet or a script turns a crawl into a download of
		// everything the page names, which is not what was asked for.
		if !isFollowableDocument(current.ContentType, current.Body) {
			continue
		}
		if s.request.MaxDepth >= 0 && current.Depth >= s.request.MaxDepth {
			continue
		}
		baseURL := current.URL
		if resp.FinalURL != "" {
			baseURL = resp.FinalURL
		}
		for _, link := range linksFrom(current.Body, baseURL) {
			if s.request.sameOrigin() && !sameHost(link, origin) {
				continue
			}
			if visited[link] {
				continue
			}
			visited[link] = true
			queue = append(queue, page{URL: link, Depth: current.Depth + 1})
		}
	}
	return out, warnings, requests, lastErr
}

// awaitResume blocks while the run is paused and returns the run's error when the
// run was cancelled instead.
//
// It is the one place the loops ask for permission to continue, so a run with a
// gate and a run without one behave identically apart from the pause: a nil gate
// means there is nothing to wait for and the call returns immediately.
func (s *Scan) awaitResume(ctx context.Context) error {
	if s.request.Gate == nil {
		return ctx.Err()
	}
	return s.request.Gate.Wait(ctx)
}

// isFollowableDocument reports whether a response is a document whose links are
// worth following.
//
// It is a separate function from `isHTML` because the question is different: a
// detector asks "is this body HTML", and the crawler asks "is this body a
// document I should read links out of". A page served as `text/plain` is still
// HTML to a detector, and is not a document to a crawler.
// A declared content type is not the last word, and trusting it alone is a real
// gap: a server that serves its own HTML as `text/plain` is common enough
// (misconfigured static handlers, framework error pages, a proxy that rewrites
// the type) that refusing to follow its links loses the whole site. So the body
// is read when the type does not claim HTML, and a body that *is* a document is
// followed. What the body check requires — a doctype or an opening `<html>` at
// the very start — is what a JSON or a script body never has, so the check stays
// a content check and not a "does it contain angle brackets" test.
func isFollowableDocument(contentType, body string) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 1024 {
		head = head[:1024]
	}
	return strings.Contains(head, "<!doctype html") || strings.Contains(head, "<html")
}

// linksFrom extracts absolute, followable links from a body, resolved against
// the page they were found on.
//
// A link that is a fragment, a `javascript:` or `mailto:` URL, or a `data:` URL is
// not a page. Fetching it is a request that cannot return a document, and the
// frontier would fill with them.
func linksFrom(body, pageURL string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, match := range linkPattern.FindAllStringSubmatch(body, -1) {
		raw := match[1]
		if raw == "" && len(match) > 2 {
			raw = match[2]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") ||
			strings.HasPrefix(lower, "tel:") || strings.HasPrefix(lower, "data:") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(parsed)
		resolved.Fragment = ""
		resolved.RawFragment = ""
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		// A link into the site's own assets is not a page to probe, and
		// including them is how a crawl spends its whole budget on stylesheets.
		if isAssetPath(resolved.Path) {
			continue
		}
		absolute := resolved.String()
		if seen[absolute] {
			continue
		}
		seen[absolute] = true
		out = append(out, absolute)
	}
	sort.Strings(out)
	return out
}

var assetExtensions = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true,
	".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true,
	".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".otf": true, ".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".zip": true, ".gz": true, ".tar": true, ".pdf": true, ".doc": true,
	".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".csv": true, ".rss": true, ".atom": true,
}

// isAssetPath reports whether a path names a static file rather than a page.
func isAssetPath(path string) bool {
	if index := strings.IndexAny(path, "?#"); index >= 0 {
		path = path[:index]
	}
	dot := strings.LastIndex(path, ".")
	if dot < 0 {
		return false
	}
	return assetExtensions[strings.ToLower(path[dot:])]
}

// harvestAll collects the injectable surfaces of every page, in page order, with
// no duplicates across pages.
//
// The order is the crawl order, so a surface found on the first page is tested
// first, and a run that is cancelled halfway has tested the shallow surface —
// which is the one a researcher would have clicked.
func harvestAll(pages []page) []Point {
	seen := map[string]bool{}
	var out []Point
	for _, p := range pages {
		for _, point := range Harvest(p.URL, p.Body, p.ContentType) {
			key := point.Key()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, point)
		}
	}
	return out
}

// --- run bookkeeping -------------------------------------------------------

// emit publishes progress to the run's reporter, if it has one.
func (s *Scan) emit(progress Progress) {
	s.mu.Lock()
	s.progress = progress
	notify := s.notify
	s.mu.Unlock()
	if notify != nil {
		notify(progress)
	}
}

// announce hands finished rows to the run's finding sink, if it has one.
//
// One call per row, never one per surface: a caller that renders what it
// receives has to be able to show a single new row, and a surface that produced
// forty rows is forty rows arriving rather than one batch that has to be split
// by the caller. A nil sink is the ordinary case for a caller that only wants
// the report, so the check is the first thing that happens.
func (s *Scan) announce(rows []Finding) {
	if s.sink == nil || len(rows) == 0 {
		return
	}
	for _, row := range rows {
		s.sink(row)
	}
}

// Progress returns the last progress the run published.
func (s *Scan) Progress() Progress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.progress
}

// fail records why a run that produced no result is not "completed". A run that
// found four things and then hit a dead host has still found four things, so the
// error is recorded and the partial report is kept rather than discarded.
func (s *Scan) fail(err error) {
	s.emit(Progress{Phase: "failed", Error: err.Error(), Detail: err.Error()})
}

// trace appends one line to the run's own record.
func (s *Scan) trace(phase, subject, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The trace is a record, not a log: it is bounded, because a run over a large
	// site would otherwise carry a line per request into the report.
	if len(s.events) >= maxTraceEvents {
		return
	}
	s.events = append(s.events, ScanEvent{
		At: s.request.clock()(), Phase: phase, Subject: subject, Detail: detail,
	})
}

// warn appends one line to the run's own record. It is the trace's own
// vocabulary: a line an operator reads inside the report rather than a log line
// that disappears with the terminal.
func (s *Scan) warn(detail string) {
	s.trace("warning", "", detail)
}

// maxPausedRetries is how many times one surface is re-offered after a pause
// dropped it.
//
// It is a bound on a pathological loop, not on the run: an operator who pauses and
// resumes repeatedly gets the surface back each time, and a surface that is
// dropped that many times is written into the report's warnings rather than
// vanishing. Nothing else about the run is limited by it — the pages a crawl may
// fetch and the surfaces a run may probe stay exactly what the operator asked for.
const maxPausedRetries = 8

// maxTraceEvents bounds the run's trace. A run that produced more lines than this
// has said everything it is going to say, and the report keeps its findings.
const maxTraceEvents = 400

func (s *Scan) traceSnapshot() []ScanEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ScanEvent{}, s.events...)
}

// sameHost reports whether a URL is on a given origin.
func sameHost(raw, origin string) bool {
	if hostOf(raw) != hostOf(origin) {
		return false
	}
	sRaw, sOrig := schemeOf(raw), schemeOf(origin)
	if strings.EqualFold(sRaw, sOrig) {
		return true
	}
	return (sRaw == "http" || sRaw == "https") && (sOrig == "http" || sOrig == "https")
}

// schemeOf returns the scheme of an absolute URL, or "" when it has none.
func schemeOf(raw string) string {
	if index := strings.Index(raw, "://"); index >= 0 {
		return strings.ToLower(raw[:index])
	}
	return ""
}
