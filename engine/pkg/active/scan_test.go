package active

// Tests for the run: the crawl, the surface harvest, the worker pool, the
// progress a caller sees, and what a cancelled run keeps.
//
// The fixtures are live `httptest` servers with real injectable surfaces and
// real injections, because the thing being tested is the run and a mocked
// detector would only prove that the run calls what it was told to call.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// vulnerableSite is a small application with a real injection, a real redirect
// and links to two more pages.
type vulnerableSite struct {
	mu    sync.Mutex
	paths []string
	// probes counts the query parameters the run sent, so a test can assert the
	// run actually probed rather than merely reported.
	probes int
}

func newVulnerableSite(t *testing.T) (*httptest.Server, *vulnerableSite) {
	t.Helper()
	site := &vulnerableSite{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site.mu.Lock()
		site.paths = append(site.paths, r.URL.Path)
		value := r.URL.Query().Get("q")
		if value != "" {
			site.probes++
		}
		site.mu.Unlock()

		switch r.URL.Path {
		case "/", "/index.html":
			_, _ = w.Write([]byte(`<html><body>
				<h1>search</h1>
				<form action="/search" method="get"><input name="q"><input type="submit"></form>
				<a href="/product?id=7">a product</a>
				<a href="/about">about</a>
				<link rel="stylesheet" href="/site.css">
				<script src="/app.js"></script>
			</body></html>`))
		case "/search":
			if strings.Contains(value, "'") {
				// An error-based injection: the diagnostic is the proof.
				_, _ = w.Write([]byte(`<html><body>You have an error in your SQL syntax near '` + value + `'`))
				return
			}
			_, _ = w.Write([]byte(`<html><body><p>no results for ` + value + `</p></body></html>`))
		case "/product":
			_, _ = w.Write([]byte(`<html><body><p>product 7</p><a href="/">home</a></body></html>`))
		case "/about":
			_, _ = w.Write([]byte(`<html><body><p>about us</p></body></html>`))
		case "/site.css":
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("body{color:#000}"))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("console.log(1)"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	t.Cleanup(server.Close)
	return server, site
}

// A run over a site with an injection finds it, and the finding points at the
// surface that was actually probed.
func TestScanFindsADemonstratedInjection(t *testing.T) {
	server, site := newVulnerableSite(t)
	run := NewScan(ScanRequest{URL: server.URL, MaxDepth: 2, Concurrency: 2, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("no findings on a site with an error-based injection: pages=%d points=%d trace=%v",
			report.Pages, len(report.Points), report.Trace)
	}
	var injected *Finding
	for i := range report.Findings {
		if report.Findings[i].Module == "sqli" {
			injected = &report.Findings[i]
		}
	}
	if injected == nil {
		t.Fatalf("the SQL injection was not reported: %s", chainTitles(report.Findings))
	}
	if injected.Tier != TierVerified {
		t.Errorf("tier = %q, want verified for a database diagnostic", injected.Tier)
	}
	if injected.Endpoint == "" || injected.Param == "" {
		t.Errorf("finding = %+v, want an endpoint and a parameter", injected)
	}
	// The run has to have actually sent probes, not just harvested the surface.
	site.mu.Lock()
	probes := site.probes
	site.mu.Unlock()
	if probes == 0 {
		t.Error("no query parameter was ever sent; the run reported without probing")
	}
}

// The crawl follows the links the application publishes. Upstream crawls twenty
// hard-coded paths, which finds nothing on a site whose pages are at other
// paths.
func TestScanFollowsPublishedLinksRatherThanAHardCodedList(t *testing.T) {
	server, _ := newVulnerableSite(t)
	run := NewScan(ScanRequest{URL: server.URL, MaxDepth: 3, Concurrency: 2, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	fetched := map[string]bool{}
	for _, url := range report.Visited {
		fetched[url] = true
	}
	for _, want := range []string{"/product", "/about", "/search"} {
		found := false
		for got := range fetched {
			if strings.Contains(got, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("page %q was never fetched; pages = %v", want, scanKeys(fetched))
		}
	}
	// A stylesheet is not a page to probe. Following it is how a crawl spends its
	// whole budget on assets.
	for got := range fetched {
		if strings.HasSuffix(got, ".css") || strings.HasSuffix(got, ".js") {
			t.Errorf("the crawl fetched the asset %q", got)
		}
	}
}

func scanKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A body that is not a document is not read for links, so a page served as JSON
// or as a script does not turn the crawl into a download of everything it names.
//
// The check is on the crawl, not on the helper: a test of the helper alone
// survives removing the guard that calls it, which is what mutation S3 did.
func TestCrawlDoesNotReadLinksOutOfANonDocument(t *testing.T) {
	var mu sync.Mutex
	fetched := 0
	// requested records the path of every request, so the assertion can name the
	// route that must not be asked for rather than a total that can balance out.
	requested := map[string]bool{}
	jsonRoutes := []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j", "/k",
		"/l", "/m", "/n", "/o", "/p", "/q", "/r", "/s", "/t", "/u", "/v", "/q2"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetched++
		requested[r.URL.Path] = true
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			// A JSON document naming twenty routes, which is what an API index or
			// a single-page app's manifest looks like.
			_, _ = w.Write([]byte(`{"routes":["/a","/b","/c","/d","/e","/f","/g","/h",` +
				`"/i","/j","/k","/l","/m","/n","/o","/p","/q","/r","/s","/t","/u","/v"]}`))
			return
		}
		_, _ = w.Write([]byte("<html><body><form action='/q' method='get'><input name='q'></form></body></html>"))
	}))
	t.Cleanup(server.Close)

	run := NewScan(ScanRequest{
		URL: server.URL, MaxDepth: 3, RoundTripper: http.DefaultTransport,
		// The well-known path probe is a separate capability with its own tests.
		// It is switched off here explicitly so this test measures one thing —
		// whether a non-document is read for links — and so that switching it off
		// is itself covered: an empty list is honoured as "none" rather than
		// replaced by the default, which is the distinction the probe's own tests
		// would otherwise have no way to observe.
		InterestingPaths: []string{},
	}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Pages != 1 {
		t.Errorf("pages = %d (%v), want only the JSON document: a non-document is not read for links",
			report.Pages, report.Visited)
	}
	mu.Lock()
	defer mu.Unlock()
	// Which routes were requested is the property, and it is stronger than a
	// total: a total can be satisfied by accident — one extra request elsewhere
	// would balance one request too many on a named route. The twenty-two routes
	// the JSON body lists are the ones a link-following crawl would chase, and
	// none of them may be asked for.
	for _, path := range jsonRoutes {
		if requested[path] {
			t.Errorf("the run requested %s, which only the JSON body names: a non-document "+
				"must not be read for links", path)
		}
	}
	if fetched < 1 {
		t.Errorf("the run made %d requests, want at least the start page", fetched)
	}
}

// A non-HTML body is not read for links, so a page that names a hundred URLs in
// a script does not turn the crawl into a download.
func TestCrawlDoesNotFollowLinksOutOfANonDocument(t *testing.T) {
	body := strings.Repeat(`<a href="/x">x</a>`, 50)
	// A JSON body that *names* links is still not a document. This is the case
	// that makes the check a content check: a manifest full of routes must not
	// become a crawl frontier.
	if isFollowableDocument("application/json", body) {
		t.Error("a JSON body was treated as a document")
	}
	if isFollowableDocument("text/css", `body{background:url(/img.png)}`) {
		t.Error("a stylesheet was treated as a document")
	}
	if !isFollowableDocument("text/html; charset=utf-8", "<p>x</p>") {
		t.Error("an HTML body was refused")
	}
	// A declared type is not the last word. A server that serves its own HTML as
	// text/plain is common enough that refusing to follow its links loses the
	// whole site, so the body is read when the type does not claim HTML.
	if !isFollowableDocument("text/plain", "<!DOCTYPE html><html><body>x</body></html>") {
		t.Error("an HTML document declared as text/plain was refused")
	}
	// No declared type: the first tag is what decides.
	if !isFollowableDocument("", "<!DOCTYPE html><html><body>x</body></html>") {
		t.Error("an undeclared HTML document was refused")
	}
	if isFollowableDocument("", `{"a":1}`) {
		t.Error("an undeclared JSON body was treated as a document")
	}
	// A body that merely mentions an opening tag mid-string is not a document
	// either; only the very start counts.
	if isFollowableDocument("application/json", `{"page":"<html><body>x"}`) {
		t.Error("a JSON string containing markup was treated as a document")
	}
}

func TestLinksFromSkipsWhatIsNotAPage(t *testing.T) {
	page := "https://target.test/dir/page"
	body := strings.Join([]string{
		`<a href="/a">a</a>`,
		`<a href="b">relative</a>`,
		`<a href="#top">anchor</a>`,
		`<a href="javascript:alert(1)">js</a>`,
		`<a href="mailto:x@y.z">mail</a>`,
		`<a href="tel:+123">tel</a>`,
		`<a href="data:text/html,x">data</a>`,
		`<a href="/style.css">css</a>`,
		`<img src="/img/a.png">`,
		`<form action="/submit">`,
		`<a href="https://other.test/x">offsite</a>`,
	}, "\n")
	got := linksFrom(body, page)
	joined := strings.Join(got, " ")
	for _, want := range []string{"https://target.test/a", "https://target.test/dir/b", "https://target.test/submit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("links = %v, want %q", got, want)
		}
	}
	// An off-host link is extracted and the frontier decides whether to follow
	// it, so the filter is asserted on the crawl rather than here.
	for _, unwanted := range []string{"#top", "javascript:", "mailto:", "tel:", "data:", ".css", ".png"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("links = %v, want no %q", got, unwanted)
		}
	}
}

// The page budget is the operator's number, and a run that stops at it says so
// rather than reporting a complete site.
func TestScanStopsAtThePageBudgetAndSaysSo(t *testing.T) {
	server, _ := newVulnerableSite(t)
	run := NewScan(ScanRequest{URL: server.URL, MaxDepth: 5, MaxPages: 2, Concurrency: 1, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Pages > 2 {
		t.Errorf("pages = %d, want at most the requested 2", report.Pages)
	}
	if len(report.Warnings) == 0 {
		t.Error("stopping at the budget was not reported; a truncated run reads as a small site")
	}
}

// A cancelled run keeps what it found and says it was cancelled. A run that
// discards its partial report makes a timeout look like an empty site.
func TestScanKeepsPartialResultsWhenCancelled(t *testing.T) {
	server, _ := newVulnerableSite(t)
	ctx, cancel := context.WithCancel(context.Background())
	run := NewScan(ScanRequest{URL: server.URL, MaxDepth: 3, Concurrency: 2, RoundTripper: http.DefaultTransport},
		func(Progress) {})
	// Cancel from the first progress the run publishes, which is before any
	// finding exists.
	var once sync.Once
	run.notify = func(p Progress) { once.Do(cancel) }
	report, _ := run.Run(ctx)
	if report == nil {
		t.Fatal("a cancelled run returned no report at all")
	}
	if run.Progress().Phase != "cancelled" && run.Progress().Phase != "failed" {
		t.Errorf("phase = %q, want the run to say it stopped", run.Progress().Phase)
	}
}

// Progress is published as the run works, and the crawl's totals are -1 while
// the frontier is still growing. A panel must be able to show an indeterminate
// bar rather than a false percentage.
func TestScanPublishesProgressWithHonestTotals(t *testing.T) {
	server, _ := newVulnerableSite(t)
	var mu sync.Mutex
	var seen []Progress
	run := NewScan(ScanRequest{URL: server.URL, MaxDepth: 2, Concurrency: 2, RoundTripper: http.DefaultTransport},
		func(p Progress) {
			mu.Lock()
			seen = append(seen, p)
			mu.Unlock()
		})
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the run published no progress at all")
	}
	phases := map[string]bool{}
	for _, p := range seen {
		phases[p.Phase] = true
	}
	for _, want := range []string{"crawling", "probing"} {
		if !phases[want] {
			t.Errorf("phases = %v, want %q", scanKeys(phases), want)
		}
	}
	for i, p := range seen {
		if p.Phase == "crawling" && p.PagesTotal != -1 {
			t.Errorf("progress %d: PagesTotal = %d during the crawl, want -1 while the frontier grows", i, p.PagesTotal)
		}
	}
	last := seen[len(seen)-1]
	if last.Phase != "completed" {
		t.Errorf("last phase = %q, want completed", last.Phase)
	}
	if last.PointsTotal != last.PointsTested {
		t.Errorf("points %d/%d at the end, want them equal", last.PointsTested, last.PointsTotal)
	}
}

// Two runs of the same target produce the same order, so a diff between two
// reports shows a change and not a reshuffle.
func TestScanReportIsDeterministic(t *testing.T) {
	server, _ := newVulnerableSite(t)
	var previous []string
	for attempt := 0; attempt < 2; attempt++ {
		run := NewScan(ScanRequest{URL: server.URL, MaxDepth: 2, Concurrency: 4, RoundTripper: http.DefaultTransport}, nil)
		report, err := run.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		var ids []string
		for _, f := range report.Findings {
			ids = append(ids, f.ID)
		}
		if attempt == 0 {
			previous = ids
			continue
		}
		if strings.Join(ids, "|") != strings.Join(previous, "|") {
			t.Errorf("run 2 = %v\nrun 1 = %v", ids, previous)
		}
	}
}

// A run against a target that answers nothing is a named failure, not an empty
// report that reads as "nothing to find".
func TestScanNamesAFailureRatherThanReportingAnEmptySite(t *testing.T) {
	run := NewScan(ScanRequest{URL: "http://127.0.0.1:1", MaxDepth: 1, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if run.Progress().Phase != "failed" {
		t.Errorf("phase = %q, want failed", run.Progress().Phase)
	}
	if run.Progress().Error == "" {
		t.Error("a failed run published no error; an empty report reads as a clean site")
	}
	if err == nil {
		t.Error("Run returned no error for an unreachable target")
	}
	if report == nil {
		t.Error("a failed run returned no report to inspect")
	}
}

func TestScanRefusesARelativeTarget(t *testing.T) {
	for _, target := range []string{"", "not a url", "/relative", "ftp://target.test/x", "://"} {
		run := NewScan(ScanRequest{URL: target}, nil)
		if _, err := run.Run(context.Background()); err == nil {
			t.Errorf("target %q was accepted; it must be an absolute http or https URL", target)
		}
	}
}

// The detector set is a fixed order, and every detector is present exactly once.
func TestAllModulesIsCompleteAndOrdered(t *testing.T) {
	modules := AllModules()
	if len(modules) == 0 {
		t.Fatal("no modules registered")
	}
	seen := map[string]bool{}
	for _, module := range modules {
		if module.Name() == "" {
			t.Error("a module has no name")
		}
		if seen[module.Name()] {
			t.Errorf("module %q is registered twice", module.Name())
		}
		seen[module.Name()] = true
	}
	for _, want := range []string{"exposure", "misconfig", "redirect", "ssrf",
		"sqli", "xss", "lfi", "cmdi", "ssti"} {
		if !seen[want] {
			t.Errorf("module %q is missing from the run", want)
		}
	}
	// Two runs must ask for the same modules in the same order, or a diff between
	// two reports shows reordering.
	second := AllModules()
	for i := range modules {
		if modules[i].Name() != second[i].Name() {
			t.Fatalf("module order is not fixed: %q then %q", modules[i].Name(), second[i].Name())
		}
	}
}

// The blind delay has to reach the detectors that make a target wait, because
// that is the only number the operator has over how long their database is held
// open.
//
// It is worth a test of its own for what it caught: both detectors carried a
// `BlindDelay` field, and both were constructed as the empty literal, so the
// field was read on every probe and was always zero. The number existed in the
// report of nobody's run, and the scanner held a stranger's connection for its
// own default with nothing on screen saying so.
func TestTheBlindDelayReachesBothDetectorsThatMakeATargetWait(t *testing.T) {
	wanted := 7 * time.Second
	modules := modulesFor("", wanted)

	sqli, cmdi := 0, 0
	for _, module := range modules {
		switch m := module.(type) {
		case SQLi:
			if m.BlindDelay != wanted {
				t.Errorf("SQLi was given %s, want %s", m.BlindDelay, wanted)
			}
			sqli++
		case CMDi:
			if m.BlindDelay != wanted {
				t.Errorf("CMDi was given %s, want %s", m.BlindDelay, wanted)
			}
			cmdi++
		}
	}
	if sqli != 1 || cmdi != 1 {
		t.Fatalf("found %d SQLi and %d CMDi in the set, want one of each", sqli, cmdi)
	}
}

// A run that was given no blind delay must hand on the zero it was given, not a
// default invented here: the defaults live in the detectors, where they are
// documented, and a value substituted in this function would be a second place
// to look and a second thing to change.
func TestNoBlindDelayHandsOnZeroRatherThanAGuess(t *testing.T) {
	for _, module := range AllModulesWithMarker("") {
		switch m := module.(type) {
		case SQLi:
			if m.BlindDelay != 0 {
				t.Errorf("SQLi was given %s with no delay asked for", m.BlindDelay)
			}
		case CMDi:
			if m.BlindDelay != 0 {
				t.Errorf("CMDi was given %s with no delay asked for", m.BlindDelay)
			}
		}
	}
}

// The number has to survive the whole way in, not merely the assembly step: a
// test that only calls `modulesFor` passes while `NewScan` drops the field on
// the floor, and that is exactly the shape the previous test had. This one goes
// through the constructor the engine actually calls.
func TestTheBlindDelaySurvivesTheConstructor(t *testing.T) {
	wanted := 3 * time.Second
	run := NewScan(ScanRequest{URL: "http://example.test/", BlindDelay: wanted}, nil)
	for _, module := range run.modules {
		switch m := module.(type) {
		case SQLi:
			if m.BlindDelay != wanted {
				t.Fatalf("the run's SQLi carries %s, want %s", m.BlindDelay, wanted)
			}
			return
		}
	}
	t.Fatal("the run has no SQLi detector")
}

// The whole set is assembled by one function now, so a detector added anywhere
// but there would not be in the run at all — and a detector missing from the run
// reports as "this target has no findings", which is the loss this register was
// built to prevent.
func TestTheDetectorSetIsAssembledInExactlyOnePlace(t *testing.T) {
	fromModules := AllModules()
	fromRun := modulesFor("", 0)
	if len(fromModules) != len(fromRun) {
		t.Fatalf("AllModules returns %d detectors, the run builds %d", len(fromModules), len(fromRun))
	}
	for i := range fromModules {
		if fromModules[i].Name() != fromRun[i].Name() {
			t.Errorf("detector %d is %q in AllModules and %q in the run", i,
				fromModules[i].Name(), fromRun[i].Name())
		}
	}
}

// A run records the plan it was given, so a report says how it was produced and
// not only what it found. This is also where a hidden ceiling would show up.
func TestScanReportCarriesItsPlanAndPoolWidth(t *testing.T) {
	server, _ := newVulnerableSite(t)
	delay := 5 * time.Millisecond
	run := NewScan(ScanRequest{
		URL: server.URL, MaxDepth: 1, MaxPages: 3, Concurrency: 3, Delay: delay,
		RoundTripper: http.DefaultTransport,
	}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Plan.MaxPages != 3 || report.Plan.MaxDepth != 1 || report.Plan.Concurrency != 3 {
		t.Errorf("plan = %+v, want the request echoed back", report.Plan)
	}
	if report.Plan.Delay != delay {
		t.Errorf("plan delay = %v, want %v", report.Plan.Delay, delay)
	}
	if report.Workers != 3 {
		t.Errorf("workers = %d, want the requested 3", report.Workers)
	}
	if report.Stats.Requests <= 0 {
		t.Error("the run reported no requests; the request count is the audit trail")
	}
	if report.Stats.Modules != len(AllModules()) {
		t.Errorf("modules = %d, want %d", report.Stats.Modules, len(AllModules()))
	}
	if report.Duration == "" {
		t.Error("no duration on the report")
	}
	if report.Started.IsZero() {
		t.Error("no start time on the report")
	}
}

// The same-origin switch is a field, not a policy: it defaults to on and turns
// off when the operator says so.
func TestSameOriginIsAFieldAndNotAPolicy(t *testing.T) {
	var off bool
	if (ScanRequest{}).sameOrigin() != true {
		t.Error("same-origin should default to on")
	}
	if (ScanRequest{SameOrigin: &off}).sameOrigin() != false {
		t.Error("the operator could not turn same-origin off")
	}
}

// One surface's failure does not take the run down: a worker that panics would,
// so this asserts the ordinary case where one endpoint is dead.
func TestScanSurvivesADeadPage(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><form action="/q" method="get"><input name="q"></form></body></html>`))
	}))
	t.Cleanup(live.Close)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // the port is now closed: a link to it fails

	page := fmt.Sprintf(`<html><body><a href="%s/gone">dead</a>
		<form action="/q" method="get"><input name="q"></form></body></html>`, deadURL)
	root := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	t.Cleanup(root.Close)

	run := NewScan(ScanRequest{URL: root.URL, MaxDepth: 2, Concurrency: 2, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Pages < 2 {
		t.Errorf("pages = %d, want the live pages kept despite the dead link", report.Pages)
	}
	if len(report.Warnings) == 0 {
		t.Error("a dead page was not recorded as a warning")
	}
}

// An asset is not a page even when it contains links. An SVG is the case that
// matters, because SVG may carry real `<a href>` elements — the guard is only
// observable there, and a fixture made of JSON bodies cannot see it at all,
// because a JSON body has no `href` to find.
func TestCrawlDoesNotFollowLinksInsideAnAsset(t *testing.T) {
	var mu sync.Mutex
	followed := false
	asset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		followed = true
		mu.Unlock()
		_, _ = w.Write([]byte("<html><body>followed</body></html>"))
	}))
	t.Cleanup(asset.Close)

	root := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<html><body><img src="/logo.svg">` +
				`<a href="/feed">feed</a><a href="/real">real</a></body></html>`))
			return
		}
		// A feed at a path with no file extension, so the extension filter cannot
		// catch it and the document check is the only thing standing between the
		// crawl and a frontier full of entries. An Atom feed carries real `href`
		// attributes, so the link pattern matches them.
		if r.URL.Path == "/feed" {
			w.Header().Set("Content-Type", "application/atom+xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><feed><title>t</title>` +
				`<link href="` + asset.URL + `/from-feed"/>` +
				`<entry><link href="` + asset.URL + `/from-entry"/></entry></feed>`))
			return
		}
		if r.URL.Path == "/logo.svg" {
			w.Header().Set("Content-Type", "image/svg+xml")
			// A real link inside the image.
			_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><a href="` +
				asset.URL + `/from-svg"><rect width="1" height="1"/></a></svg>`))
			return
		}
		_, _ = w.Write([]byte("<html><body>a real page</body></html>"))
	}))
	t.Cleanup(root.Close)

	run := NewScan(ScanRequest{URL: root.URL, MaxDepth: 3, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The real page is followed; the link inside the image is not.
	foundReal := false
	for _, visited := range report.Visited {
		if strings.HasSuffix(visited, "/real") {
			foundReal = true
		}
		if strings.Contains(visited, "from-svg") {
			t.Errorf("followed a link inside an image asset: %q", visited)
		}
		if strings.Contains(visited, "from-feed") || strings.Contains(visited, "from-entry") {
			t.Errorf("followed a link out of a feed: %q", visited)
		}
	}
	if !foundReal {
		t.Errorf("the real page was not followed: %v", report.Visited)
	}
	mu.Lock()
	defer mu.Unlock()
	if followed {
		t.Error("the asset's link was fetched")
	}
}

// The crawl stays on the host the operator named, and the switch is a field.
//
// The check is on the crawl and not on `sameOrigin`, because a test of the helper
// survives removing the filter that calls it — which is what mutation S12 did.
func TestCrawlStaysOnTheNamedHostUnlessTheOperatorSaysOtherwise(t *testing.T) {
	offsite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>another site</body></html>"))
	}))
	t.Cleanup(offsite.Close)

	// A different *host*, not a different port. Both servers listen on
	// 127.0.0.1, and a crawler that compares hostnames without the port would see
	// one host here and the test would pass for the wrong reason.
	offsiteURL := strings.Replace(offsite.URL, "127.0.0.1", "localhost", 1)
	root := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><a href="` + offsiteURL + `/x">offsite</a></body></html>`))
	}))
	t.Cleanup(root.Close)

	on := NewScan(ScanRequest{URL: root.URL, MaxDepth: 2, RoundTripper: http.DefaultTransport}, nil)
	report, err := on.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, visited := range report.Visited {
		if strings.Contains(visited, "localhost") {
			t.Errorf("visited %q with same-origin on", visited)
		}
	}
	var off bool
	allow := NewScan(ScanRequest{
		URL: root.URL, MaxDepth: 2, SameOrigin: &off, RoundTripper: http.DefaultTransport,
	}, nil)
	report, err = allow.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, visited := range report.Visited {
		if strings.Contains(visited, "localhost") {
			found = true
		}
	}
	if !found {
		t.Errorf("the operator turned same-origin off and the crawl still stayed put: %v", report.Visited)
	}
}

// The run's trace is bounded, because a run over a large site would otherwise
// carry a line per request into the report and the report would stop being
// readable. The bound is a stated number, not a silent one.
func TestScanTraceIsBounded(t *testing.T) {
	// Enough pages to overflow the bound by a wide margin.
	const pages = maxTraceEvents + 60
	root := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			var links strings.Builder
			for i := 0; i < pages; i++ {
				fmt.Fprintf(&links, `<a href="/p%d">p</a>`, i)
			}
			_, _ = w.Write([]byte("<html><body>" + links.String() + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>a page</body></html>"))
	}))
	t.Cleanup(root.Close)

	run := NewScan(ScanRequest{URL: root.URL, MaxDepth: 2, RoundTripper: http.DefaultTransport}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Pages <= maxTraceEvents {
		t.Skipf("the fixture produced %d pages, fewer than the bound of %d", report.Pages, maxTraceEvents)
	}
	if len(report.Trace) > maxTraceEvents {
		t.Errorf("trace = %d lines, want at most %d", len(report.Trace), maxTraceEvents)
	}
	if len(report.Trace) != maxTraceEvents {
		t.Errorf("trace = %d lines, want it filled to the bound of %d", len(report.Trace), maxTraceEvents)
	}
	// The report is still usable: the bound applies to the trace, not to the
	// findings or the page list.
	if report.Pages <= maxTraceEvents {
		t.Error("the trace bound was applied to the page list as well")
	}
	if len(report.Visited) != report.Pages {
		t.Errorf("visited = %d, pages = %d: the trace bound leaked into the report", len(report.Visited), report.Pages)
	}
}

func TestCrawlFollowsLinksWithUnquotedAndSchemeMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			fmt.Fprintf(w, `<html><body>
				<a href=/unquoted-page>Unquoted</a>
				<a href="/quoted-page">Quoted</a>
			</body></html>`)
			return
		}
		fmt.Fprintf(w, "<html><body>Page %s</body></html>", r.URL.Path)
	}))
	defer server.Close()

	run := NewScan(ScanRequest{
		URL: server.URL + "/", MaxDepth: 2, RoundTripper: http.DefaultTransport,
	}, nil)
	report, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	foundUnquoted := false
	foundQuoted := false
	for _, visited := range report.Visited {
		if strings.Contains(visited, "/unquoted-page") {
			foundUnquoted = true
		}
		if strings.Contains(visited, "/quoted-page") {
			foundQuoted = true
		}
	}
	if !foundUnquoted {
		t.Errorf("unquoted link was not crawled: %v", report.Visited)
	}
	if !foundQuoted {
		t.Errorf("quoted link was not crawled: %v", report.Visited)
	}
}
