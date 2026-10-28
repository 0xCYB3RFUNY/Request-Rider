package active

// Endpoints no page links to.
//
// The crawl reads the links an application publishes, which is how it finds the
// surfaces the developer already thought about. It cannot find the ones they did
// not: a `/swagger.json` on a server whose HTML never links an API, a `/.env`
// nobody mentions, an `/actuator/env` the build leaves switched on. Those are the
// endpoints that carry the worst findings, and they are invisible to a link
// follower by construction.
//
// So a run also checks a short list of well-known paths on the start origin, and
// treats each answer exactly like a crawled page: the same harvest, the same
// detectors, the same evidence. The upstream implementation does this too — after
// its crawl, with a list of twenty-one paths — and this file is that capability
// kept, with the parts that were wrong corrected rather than copied.
//
// What was corrected, and why:
//
//   - Upstream keeps a bare `interestingPaths` var and probes it unconditionally,
//     so an operator cannot say "check these three paths" and cannot turn it
//     off. Here the list is a request field: nil uses the default, a supplied
//     list replaces it, and there is no ceiling on either.
//   - Upstream's worker pool is a fixed 8 with no bound on what the operator
//     asked for. Here the run's own `Concurrency` is the width, so the pool is
//     the number the operator can see and change elsewhere in the same request.
//
// What is kept unchanged, because it was right: the probe never follows
// redirects, an answer that is not 200 is not interesting, the final URL is
// re-checked against the origin before anything is recorded, and a path the crawl
// already reached is not recorded twice.

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// DefaultInterestingPaths is what a run checks when the request does not say.
//
// It is a starting point and not a catalogue: the paths are the ones a web
// application most often leaves reachable and least often links. A run that
// wanted more says so in `ScanRequest.InterestingPaths`, and a run that wanted
// none passes an empty list, which is honoured as "none" rather than replaced by
// the default.
var DefaultInterestingPaths = []string{
	"/robots.txt",
	"/sitemap.xml",
	"/.env",
	"/.git/HEAD",
	"/.git/config",
	"/admin",
	"/login",
	"/api",
	"/api/v1",
	"/graphql",
	"/swagger.json",
	"/openapi.json",
	"/actuator",
	"/actuator/env",
	"/actuator/health",
	"/server-status",
	"/phpinfo.php",
	"/wp-login.php",
	"/debug",
	"/console",
	"/backup.zip",
}

// interestingPaths resolves the request field to the list a run will use.
//
// The three cases are distinguished because collapsing them is how a "turn it
// off" turns into "you cannot turn it off": nil means the caller did not choose,
// an empty non-nil list means the caller chose none, and a populated list means
// the caller chose exactly those.
func interestingPaths(request []string) []string {
	if request == nil {
		return DefaultInterestingPaths
	}
	out := make([]string, 0, len(request))
	for _, path := range request {
		if path == "" {
			continue
		}
		if path[0] != '/' {
			path = "/" + path
		}
		out = append(out, path)
	}
	return out
}

// probeInterestingPaths checks the list on the start origin and returns the
// answers as pages, so the caller harvests them exactly as it harvests the crawl.
//
// Four conditions decide whether an answer counts, and each of them exists because
// its absence produces a finding that is not one:
//
//   - the request does not follow redirects, so a 3xx cannot walk the probe to
//     another host;
//   - the status is 200, because a 403 and a 404 are both "not there" and a 200
//     on `/.env` is the finding;
//   - the final URL is on the origin, re-verified after the request rather than
//     assumed from the path, which is the check that makes the no-follow client
//     a defence rather than a courtesy;
//   - the crawl did not already reach it, so one endpoint is one surface and the
//     detectors do not report the same answer twice.
func (s *Scan) probeInterestingPaths(ctx context.Context, transport *Transport, origin string, alreadyVisited map[string]bool) ([]page, []string) {
	paths := interestingPaths(s.request.InterestingPaths)
	if len(paths) == 0 {
		return nil, nil
	}
	probed, warnings := s.probePathWave(ctx, transport, origin, paths, alreadyVisited)
	// Second wave: the paths `robots.txt` names.
	//
	// A `Disallow` line is the operator of the site writing down a URL that
	// exists and is not linked from anywhere. It is the cheapest enumeration
	// source a site publishes about itself, and before this the file was fetched,
	// answered, and then read as if it were an ordinary text page: the paths in
	// it never reached the frontier, so a run reported an application as smaller
	// than its own robots.txt admits.
	//
	// This is Nikto's `nikto_robots`, and it is the difference between the two
	// tools here that matters: Nikto prints the disallow list, we *scan* what it
	// names, so a path the site tried to hide is probed by every detector rather
	// than merely displayed.
	if ctx.Err() == nil {
		if hidden := s.disallowedPaths(probed, alreadyVisited); len(hidden) > 0 {
			s.emit(Progress{
				Phase:       "probing",
				PagesTotal:  -1,
				PointsTotal: -1,
				Detail:      fmt.Sprintf("robots.txt named %d hidden path(s) on %s", len(hidden), origin),
			})
			second, secondWarnings := s.probePathWave(ctx, transport, origin, hidden, alreadyVisited)
			probed = append(probed, second...)
			warnings = append(warnings, secondWarnings...)
		}
	}
	return probed, warnings
}

// robotsPath is the file the second wave is read from.
const robotsPath = "/robots.txt"

// disallowedPaths reads the paths `robots.txt` names and are worth probing.
//
// The rules it follows are the ones the standard states, not the ones a parser
// would guess:
//
//   - `Disallow:` lines only. `Allow:` narrows a prefix rather than opening a
//     door, and a site listing `/admin` under `Allow` is not inviting a probe of
//     `/admin`.
//   - A bare `Disallow:` with no value allows everything and hides nothing, so it
//     is skipped; parsing it as "/" would point every run at the site root and
//     report the start page as a hidden find.
//   - A value containing `*` or `$` is a pattern, not a path, and is skipped
//     rather than guessed at. `*` is the whole reason a site-wide rule like
//     `Disallow: /*.php$` would otherwise send every probe at a URL that does not
//     exist.
//   - Only same-origin paths survive. A `Disallow: /x` plus a `Sitemap` on
//     another host is not a reason to probe that host — that is the same
//     authorisation decision `SameOrigin` already governs, and it is not this
//     function's to override.
//   - A named path must look like a path: a leading `/`, a depth the operator can
//     read, and no scheme.
func (s *Scan) disallowedPaths(probed []page, alreadyVisited map[string]bool) []string {
	var robots string
	for _, p := range probed {
		if strings.HasSuffix(p.URL, robotsPath) {
			robots = p.Body
		}
	}
	if robots == "" {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(robots, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if field != "disallow" || value == "" {
			continue
		}
		if strings.ContainsAny(value, "*$") || strings.Contains(value, "://") {
			continue
		}
		if !strings.HasPrefix(value, "/") {
			continue
		}
		if seen[value] {
			continue
		}
		// A rule with no extension is ambiguous, and both readings are real: a
		// site writes `Disallow: /staging` meaning the directory and everything
		// under it, and writes `Disallow: /health` meaning that one endpoint.
		// Probing only the slash form misses the file; probing only the bare form
		// misses a site that serves `/staging/index` and 404s on `/staging`. So
		// both are probed, and `withoutVisited` and the server decide which of the
		// two answers.
		seen[value] = true
		out = append(out, value)
		if !strings.HasSuffix(value, "/") && !strings.Contains(value, ".") {
			withSlash := value + "/"
			if !seen[withSlash] {
				seen[withSlash] = true
				out = append(out, withSlash)
			}
		}
	}
	sort.Strings(out)
	return out
}

// hostOriginOf returns the scheme://host of a URL, or "" when it does not parse.
//
// Named `hostOriginOf` rather than `origin` because the probe functions take a
// parameter called `origin`, and a package function with the same name as its
// callers' parameter is a name that silently means two things in one file. The
// `host` prefix is here for a second reason: a test file in this package already
// declares its own `originOf`, and a package-level name is package-level however
// ordinary it looked.
func hostOriginOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// withoutVisited drops the paths the crawl already reached.
//
// A path already in the frontier is not probed again: one endpoint is one
// surface, and probing it twice makes the detectors report the same answer twice
// with different evidence.
func withoutVisited(paths []string, origin string, alreadyVisited map[string]bool) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		if alreadyVisited[origin+path] {
			continue
		}
		out = append(out, path)
	}
	return out
}

// probePathWave fetches one batch of paths and returns the ones that answered.
//
// The wave is factored out because there are now two of them: the well-known
// list the operator typed, and the list `robots.txt` publishes. Both make the
// same checks in the same way, and a second copy of the checks is how the two
// would start disagreeing about what counts as "there".
func (s *Scan) probePathWave(ctx context.Context, transport *Transport, origin string, paths []string, alreadyVisited map[string]bool) ([]page, []string) {
	paths = withoutVisited(paths, origin, alreadyVisited)
	if len(paths) == 0 {
		return nil, nil
	}
	// The phase is announced before the first probe rather than after the last
	// one, so a run that spends a minute on twenty-one paths shows what it is
	// doing instead of looking stalled at "crawling".
	s.emit(Progress{
		Phase:       "probing",
		PagesTotal:  -1,
		PointsTotal: -1,
		Detail:      fmt.Sprintf("checking %d well-known path(s) on %s", len(paths), origin),
	})

	// A response is bounded the same way a page is: the harvest wants a body it
	// can parse, and an endpoint that streams without end is a target problem,
	// not a reason to read it forever.
	type answer struct {
		page page
		ok   bool
	}
	var (
		warnings []string
		answers  = make([]answer, len(paths))
	)
	width := s.request.workers()
	if width > len(paths) {
		width = len(paths)
	}
	// width is at least 1 because workers() never returns less, but the guard is
	// kept explicit: a semaphore of zero would deadlock the run rather than
	// slow it, and a deadlock here would be invisible.
	if width < 1 {
		width = 1
	}

	slots := make(chan struct{}, width)
	var wg sync.WaitGroup
	for index, path := range paths {
		wg.Add(1)
		go func(index int, path string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if ctx.Err() != nil {
				return
			}
			full, err := url.Parse(origin + path)
			if err != nil {
				return
			}
			resp, err := transport.Do(ctx, "GET", full.String(), nil, false, nil)
			if err != nil || resp.StatusCode != 200 {
				return
			}
			// The final URL, not the requested one: a server that answers a path
			// with a redirect onto another host is answered here without following
			// it, and only the origin's own URL is ever recorded.
			if resp.FinalURL != "" && !sameHost(resp.FinalURL, origin) {
				return
			}
			answers[index] = answer{
				page: page{
					URL:         full.String(),
					Body:        resp.Body,
					ContentType: resp.Header.Get("Content-Type"),
					StatusCode:  resp.StatusCode,
					Depth:       0,
				},
				ok: true,
			}
		}(index, path)
	}
	wg.Wait()
	if ctx.Err() != nil {
		warnings = append(warnings, "well-known path probe cancelled")
	}

	var out []page
	for index := range paths {
		if !answers[index].ok {
			continue
		}
		found := answers[index].page
		if alreadyVisited[found.URL] {
			continue
		}
		alreadyVisited[found.URL] = true
		out = append(out, found)
	}
	return out, warnings
}
