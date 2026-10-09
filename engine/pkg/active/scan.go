package active

// Scan orchestration: crawl a target, harvest its injectable surfaces, run the
// detectors over them, correlate the results into chains, and attach proofs.
//
// This is the shape of a whole run rather than of one probe, and it is separate
// from the detectors on purpose. A detector answers "what does this one request
// show", and it must stay answerable without knowing about crawling, about
// progress reporting, or about how many other detectors are running against the
// same surface. Everything that needs to know all three lives here.
//
// The upstream scanner is a single pass: `crawler.go` visits a fixed list of
// twenty hard-coded paths on one host, every detector then re-fetches every page
// it needs, and the run has no progress, no cancellation, and no notion of what
// it has already covered.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AllModules is the detector set, in a fixed order.
//
// The order is the run order, and it is fixed rather than map-ordered so that two
// runs against the same target spend their requests in the same sequence — which
// is what makes a diff between two runs readable. Cheap and host-level modules
// come first because one request answers them for every surface, and the
// parameter-level injection modules come last because they are the expensive ones
// and the ones whose findings the chain rules need.
func AllModules() []Module {
	return AllModulesWithMarker("")
}

// AllModulesWithMarker is the detector set with the redirect destination filled
// in.
//
// It goes through `modulesWith` rather than `modulesFor`, so the set a caller
// gets by asking for "the modules" is the same set a run carries. When it did
// not, the four modules added later were absent from `AllModules` and present in
// every run, and `AllModules` is what the documentation and the reconciliation
// tests read — a set that disagrees with the product is a second answer to a
// question that has one.
func AllModulesWithMarker(marker string) []Module {
	return modulesFor(marker, 0)
}

// moduleOptions are the inputs a run supplies to the detectors that cannot work
// without them.
//
// It is a struct rather than more positional arguments because `modulesFor` is
// already called from four places, two of them in tests, and adding a fourth
// positional parameter to a function that reads `modulesFor(marker, delay)` would
// make every call site a guess about which of the two zero durations was meant.
type moduleOptions struct {
	// params is the hidden-parameter wordlist, from the JavaScript analyser.
	params []string
	// paths is the operator's dictionary, for the hidden-path module.
	paths []string
}

// modulesFor is the detector set with no run-specific inputs.
//
// `TestTheDetectorSetIsAssembledInExactlyOnePlace` compares this function's result
// with `AllModules` and requires the two to be identical, which is the invariant
// that keeps a detector from being present in a run and absent from the set the
// documentation and the registers read. So `modulesFor` delegates to the real
// assembly rather than being a second, shorter list: the four modules that take
// run inputs are in both, and this one hands them the zero value, which means
// they run and report nothing — the documented behaviour of an absent wordlist,
// not a missing detector.
func modulesFor(marker string, blindDelay time.Duration) []Module {
	return modulesWith(marker, blindDelay, moduleOptions{})
}

// modulesWith is the one place the detector set is assembled, and it carries the
// run's own inputs into the four modules that cannot invent their own. `modulesFor`
// is that same list with the zero value for those inputs, which is why there is one
// list and not two: a second, shorter list is a set that disagrees with the product.
//
// It is a function rather than a literal because two detectors have to be told
// something the caller knows and the literal could not: the open-redirect
// destination, and how long a blind technique may hold a target's connection.
// Both were separate arrangements once — `AllModulesWithMarker` for the first,
// and a `SQLi{BlindDelay: …}` written at the call site for the second — which is
// how `CMDi.BlindDelay` ended up a field that nothing ever set: the module was
// constructed as `CMDi{}` and the field was read on every scan of a value that
// was always zero, so the detector could never use a delay the operator chose.
// One list means a field on a detector is either fed here or is dead, and there
// is no third arrangement to forget.
// The endpoint-level block comes first and is ordered cheapest-first: the passive
// readers (published data, cookies, session shape) cost nothing beyond the
// baseline every surface already fetched, and the path-reading pair (methods,
// source disclosure) costs a handful of requests each but answers questions no
// payload can. `Escaping` is last of all and the reason is in its own file: it
// costs twenty requests per surface and only tells the operator which payloads are
// worth trying, which is worth twenty requests once the cheaper detectors found
// nothing and not worth them otherwise.
func modulesWith(marker string, blindDelay time.Duration, options moduleOptions) []Module {
	return []Module{
		// Endpoint level: passive readers, then method and path checks.
		Exposure{}, Misconfig{}, PII{}, Cookies{}, SessionFixation{},
		CSRF{}, Methods{}, &SourceDisclosure{},
		// `JSLibrary` reads the baseline and spends no request, so it goes first
		// among the readers: the version a page ships is known before the run has
		// spent anything. `SSI` and `WebCacheDeception` each cost requests, so
		// they sit after the readers that cost none.
		JSLibrary{}, SSI{}, WebCacheDeception{},
		// `Shellshock` probes two headers per endpoint, so it sits after the
		// readers that cost nothing and before the path probe. The order is
		// cheapest-first and this is the first thing here that spends a request
		// for a bug that affects a CGI setup rather than an application one —
		// which is also the order an operator would want it answered in.
		Shellshock{},
		// `ReDoS` is a parameter-level detector that spends four requests on a clean
		// surface (one control plus the first family), so it sits after the readers
		// and after the parameter families that answer from one response. It goes
		// before the rest because its answer is a measurement: the longer the scan
		// runs, the more another family can add on top of an already-slow endpoint.
		ReDoS{},
		// Parameter level: the injection families, then the redirect probe that
		// needs the marker this function receives.
		Redirect{MarkerHost: marker}, SSRF{},
		SQLi{BlindDelay: blindDelay}, XSS{}, XSSEscape{}, ClientTemplate{}, LFI{},
		// The 27-shape table is the most expensive module in the set, so it goes
		// last among the parameter families: it is gated on a surface that filters,
		// and by then the cheaper modules have already said whether the surface
		// reflects anything at all.
		DOMVectors{},
		CMDi{BlindDelay: blindDelay}, SSTI{},
		NoSQL{}, XPath{}, LDAP{}, XXE{}, CodeInjection{}, CRLF{},
		// Fourteen probes, so it goes after the one-request families and before the
		// host-level ones: a run that finds a merge pays for the table once.
		ProtoPollution{},
		// Host level, and last of all for the reason `Escaping` is: the same
		// server answers every URL on it, so a product it names is one answer,
		// and reading it costs no request at all — the baseline the surface
		// already fetched carries the banner. Placing it before `Escaping`
		// would spend twenty requests per surface before the operator learns
		// what software they are looking at.
		fingerprint{},
		// The transformation analysis, which is the last detector a surface sees.
		Escaping{},
		// Endpoint level: the question is about a path or a URL, so firing a
		// wordlist per injectable parameter would fire it once per parameter for
		// the same URL and report the same rows N times.
		HiddenParams{Params: options.params},
		AuthBypassExt{},
		// Host level: a dictionary is fired at the origin once, and the dev
		// server's file bridge belongs to the origin rather than to a page.
		HiddenPaths{Paths: options.paths},
		ViteFSRead{},
	}
}

// ScanRequest is one run's input.
type ScanRequest struct {
	// URL is the absolute http or https URL to start from.
	URL string
	// MaxPages bounds the crawl. Zero means the run follows links until the
	// frontier is empty; a positive value is the number of pages.
	MaxPages int
	// MaxDepth bounds link-following. Negative means unbounded, zero means the
	// start page only. There is no hidden ceiling on either: the operator's
	// number is the number, and the run is stopped by `Cancel` or by the context
	// otherwise.
	MaxDepth int
	// SameOrigin keeps the crawl on the start URL's host. It defaults to true
	// because a scanner that follows a link off-host is scanning a different
	// authorisation decision than the one the operator asked about; it is a
	// field, not a policy, and setting it false turns it off.
	SameOrigin *bool
	// Concurrency is how many surfaces are probed at once. Zero picks a value
	// from the machine; it is a worker-pool width, not a rate limit, and it does
	// not reduce what the run can look at.
	Concurrency int
	// FollowRedirects lets probes follow redirects, so a detector sees what a
	// browser would see.
	FollowRedirects bool
	// Delay is a pause between probes on one surface. It exists so a run against
	// a fragile target can be slowed by the operator; zero means no pause.
	Delay time.Duration
	// BlindDelay is how long a blind technique may ask the target to wait.
	//
	// Two detectors make a target wait — the SQL injection delay and the command
	// injection one — and both cost the target a held connection per probe. That
	// cost belongs where the operator can see it, so it is a field here and is
	// handed to both detectors by `modulesFor`. Zero means each detector's own
	// documented default; there is no ceiling on the value, because a delay the
	// operator typed is a delay they asked for.
	BlindDelay time.Duration
	// InterestingPaths are the paths a run checks after the crawl, on the start
	// origin, for endpoints that no page links to.
	//
	// Nil means DefaultInterestingPaths. A non-nil list *replaces* the default
	// rather than adding to it, so an operator who supplies one path gets exactly
	// that path. There is no ceiling on either: this is a field the operator
	// writes, not a limit the scanner imposes.
	//
	// The default list is a convenience, not a boundary. A run that probes only
	// this list and no links reports an empty site on any application whose
	// surface lives elsewhere, which is why the crawl reads the application's own
	// links and this list is added on top rather than instead.
	InterestingPaths []string
	// Now is the clock, injectable so the run's own timings are testable.
	//
	// It is excluded from the report's JSON. A `Report` is what leaves the
	// engine, and a function is not data: leaving the field exported without the
	// tag made every `json.Marshal` of a report fail with "unsupported type:
	// func() time.Time", so a finished run could not be sent to the browser or
	// written to a project at all. The clock is a property of the run, not of its
	// result, so nothing is lost by omitting it.
	Now func() time.Time `json:"-"`
	// RoundTripper is how the run's requests leave the process.
	//
	// It is required, and that is the same rule the transport itself follows: a
	// scan that quietly fell back to http.DefaultTransport would lose the shared
	// cookie jar, the recording proxy and the per-request timeout, and the
	// operator's Traffic view would show nothing while the run reported pages
	// fetched. The engine passes the recording transport; a test passes its own.
	//
	// It is excluded from the report's JSON for the same reason `Now` is: a
	// RoundTripper holds connections and function fields, so marshalling one
	// fails. Naming it in the report would also be misleading — the operator needs
	// to know what the run did, and the recording itself is visible in Traffic.
	RoundTripper http.RoundTripper `json:"-"`
	// Timeout bounds one request. Zero means the transport's default.
	Timeout time.Duration
	// MarkerHost is the destination the open-redirect detector offers to the
	// target: the host it asks the application to redirect a browser to, so a
	// `Location` naming it is proof the application will send the visitor
	// somewhere the operator chose.
	//
	// Empty means the run mints its own per-run host under the reserved `.invalid`
	// TLD, which by RFC 2606 can never resolve, and which the redirect probe does
	// not follow — so the destination is safe to name without being real, and the
	// run is still able to tell an off-site redirect from ordinary navigation.
	// Whatever is used ends up in `Report.Plan.MarkerHost`, so the report names the
	// destination the run actually offered rather than leaving it to be guessed.
	//
	// Supplying your own host — the OAST listener you control, for instance — is
	// what turns a blind open redirect into a callback you receive; the run does
	// not need it, and nothing else about the run changes.
	MarkerHost string
	// Params is the hidden-parameter wordlist, one name per entry.
	//
	// It is fed to `HiddenParams` and nowhere else. The names come from the
	// JavaScript analyser, which reports `js.ParamCandidates` per file: the query
	// and body parameters its call sites carry, plus the names the program binds.
	// A run without one probes nothing, and that is visible — the detector is
	// still in the run's module count and still reports nothing, which is the same
	// arrangement `Redirect` had before its marker was filled in and the reason
	// this field is documented where the marker is.
	//
	// There is no ceiling. A five-figure wordlist costs ten requests per name per
	// unique URL, and the operator decides whether to spend that.
	Params []string
	// PathWordlist is the operator's dictionary for `HiddenPaths`, one path per
	// entry.
	//
	// No default, and the reason is `DefaultInterestingPaths`: this project
	// already probes a short fixed list after the crawl, and a second default
	// dictionary would fire the same requests twice. Nil means the module does not
	// run.
	PathWordlist []string
	// Bypass turns the 403 ladder on for this run.
	//
	// It is off by default and it is a field rather than behaviour because every
	// form is a real request against the operator's target: a run that sent the
	// ladder at every refused endpoint without being asked would spend requests
	// the operator never agreed to. What it spends is in `Stats.BypassWalks`,
	// `Stats.BypassHits` and `Stats.BypassRequests`, so the cost is visible in
	// the same report as the findings.
	Bypass bool
	// BypassForms narrows the ladder. Nil means every form, and it is read only
	// when `Bypass` is set.
	//
	// There is no ceiling on the selection and no default: an operator who wants
	// only the header forms gets exactly those, and an operator who wants the
	// whole ladder gets the whole ladder.
	BypassForms []string
	// BrowserCandidates bounds how many expressions one row may be executed in.
	// Zero means every expression the module offers, which is the documented default.
	BrowserCandidates int
	// Renderer is the browser a run may settle its escaping rows in.
	//
	// It is a field, not behaviour: nil means no browser was offered, no browser
	// proof is attempted, and the report says so in its warnings rather than
	// leaving a run that proved less than another to look like a run that proved
	// the same. It is excluded from the report's JSON for the reason `Now` and
	// `RoundTripper` are — a renderer holds connections and a base URL, and the
	// report is data.
	Renderer Renderer `json:"-"`
	// FindingSink receives every finding the moment a surface produces it.
	//
	// It exists because a run that only reports its rows at the end makes the
	// operator watch a counter instead of a result: `Progress.Findings` says
	// "282" while nothing on the screen says what those 282 are. A caller that
	// wants the table to fill while the run works has to be told per row, and the
	// per-row boundary is the only place where "what did we find" is known.
	//
	// Three properties matter to a caller and are guaranteed here:
	//
	//   - It is called from the probing workers, so an implementation has to be
	//     safe for concurrent use. The engine's job publisher takes its own lock.
	//   - It is called for detector rows and for chain rows, which is everything
	//     that ever enters `Report.Findings`. It is *not* called for proofs:
	//     a proof upgrades a row that already exists rather than adding one, so
	//     there is no new row to announce and the terminal report carries the
	//     upgrade.
	//   - Order is completion order — a surface's rows when that surface
	//     finishes, the chains once correlation finishes — not the report's
	//     surface order. A reader comparing a live row order with a finished
	//     report order sees two orders of the same rows, and both are correct.
	//
	// A row announced here still carries the tier its detector gave it. A proof
	// may raise it before the run ends, so the terminal report is what a reader
	// must treat as authoritative, and it replaces whatever this sink fed.
	//
	// A nil sink means "nobody is watching", exactly as a nil reporter does.
	FindingSink func(Finding) `json:"-"`
}

// countUnexecutedEscapes counts the rows a browser could have settled and did not.
//
// It walks the browser-proof registry rather than a module name, so a module that
// becomes provable is counted the day it is registered and not the day somebody
// remembers to add it here.
//
// It is deliberately a count and not a judgement: the warnings it feeds say what
// was not done, and the number is the whole of what they can honestly say.
//
// It counts every provable row without a browser proof, whatever tier the row
// carries. An earlier version of this counted only the unverified ones, and it
// counted nothing at all on the context that fires most often: a payload that
// escapes a JavaScript string is *already* verified from the response, so the
// filter that looked for `Tier != TierVerified` excluded exactly the rows a
// browser exists to corroborate.
func countUnexecutedEscapes(findings []Finding, proofs []Proof) int {
	settled := make(map[string]bool, len(proofs))
	for _, proof := range proofs {
		if proof.Kind == "browser-execution" {
			settled[proof.FindingID] = true
		}
	}
	total := 0
	for _, finding := range findings {
		if _, provable := browserProofPayloads[finding.Module]; provable && !settled[finding.ID] {
			total++
		}
	}
	return total
}

func (r ScanRequest) sameOrigin() bool {
	if r.SameOrigin == nil {
		return true
	}
	return *r.SameOrigin
}

// clock returns the request's clock, or the wall clock. It is a function so a
// test can pin a run's timings and read them instead of measuring them.
func (r ScanRequest) clock() func() time.Time {
	if r.Now == nil {
		return time.Now
	}
	return r.Now
}

func (r ScanRequest) workers() int {
	if r.Concurrency > 0 {
		return r.Concurrency
	}
	// A width, not a rate. It is derived from the machine so a run on a
	// four-core box does not open a hundred sockets, and it is reported in the
	// run's plan so the operator can see what it got.
	return 8
}

// Progress is what a caller learns while a run is in flight.
type Progress struct {
	// Phase names what the run is doing: "crawling", "probing", "correlating",
	// "proving", "completed", "cancelled", "failed".
	Phase string `json:"phase"`
	// PagesFetched and PagesTotal are the crawl's own counters. PagesTotal is -1
	// while the frontier is still growing and the run does not know a final
	// count, so a panel can show an indeterminate bar instead of a false 0%.
	PagesFetched int `json:"pages_fetched"`
	PagesTotal   int `json:"pages_total"`
	// PointsTested and PointsTotal are the injectable surfaces. Same -1 rule.
	PointsTested int `json:"points_tested"`
	PointsTotal  int `json:"points_total"`
	// Findings is the running count, so a panel can fill while the run works.
	Findings int `json:"findings"`
	// Detail is a human sentence naming what just happened.
	Detail string `json:"detail"`
	// Error is why a run that never produced a result is not "completed".
	Error string `json:"error,omitempty"`
}

// Report is the finished run.
type Report struct {
	Target string  `json:"target"`
	Points []Point `json:"points"`
	// Pages is how many pages the crawl fetched and Visited is which ones.
	//
	// Both are reported because the count alone cannot answer the question an
	// operator actually has after a scan that found one thing: was that the only
	// page, or did the run only look at one. `Visited` is the answer.
	Pages   int      `json:"pages"`
	Visited []string `json:"visited"`
	// Plan is what the run was told to do, so a report says how it was produced
	// rather than only what it found.
	Plan ScanRequest `json:"plan"`
	// Workers is the pool width the run actually used.
	Workers int `json:"workers"`
	// Findings are the detector findings, chains and proofs together, sorted so
	// two runs of the same target produce the same order.
	Findings []Finding   `json:"findings"`
	Proofs   []Proof     `json:"proofs"`
	Stats    ScanStats   `json:"stats"`
	Started  time.Time   `json:"started"`
	Duration string      `json:"duration"`
	Warnings []string    `json:"warnings,omitempty"`
	Trace    []ScanEvent `json:"trace,omitempty"`
}

// ScanStats counts what the run did, by the two units that are easy to confuse.
type ScanStats struct {
	Requests  int `json:"requests"`
	Points    int `json:"points"`
	Modules   int `json:"modules"`
	Chains    int `json:"chains"`
	Verified  int `json:"verified"`
	Potential int `json:"potential"`
	Capped    int `json:"capped"`
	// Hosts counts distinct hosts probed, so a run that wandered off-host is
	// visible in the report rather than only in the endpoints.
	Hosts int `json:"hosts"`
	// BypassWalks, BypassHits and BypassRequests are the 403 ladder's own
	// numbers, kept apart from `Requests` on purpose.
	//
	// `Requests` already contains the ladder's spending, because every form is a
	// request and counting it anywhere else would let a run report a smaller
	// footprint than it had. These three say *why*: how many times a refusal
	// sent the run down the ladder, how many of those reached the resource, and
	// how many requests the whole thing cost. They are all zero when the
	// operator did not turn the ladder on, which is a real answer.
	BypassWalks    int `json:"bypass_walks"`
	BypassHits     int `json:"bypass_hits"`
	BypassRequests int `json:"bypass_requests"`
	// BrowserAttempts and BrowserExecuted are the browser proof stage's own
	// numbers.
	//
	// They are separate from `Requests` because the worker issues them, not the
	// transport, and a run that hid them inside the request count would report a
	// footprint it cannot itemise. A run without a browser has both at zero,
	// which is a real answer rather than an absence.
	BrowserAttempts int `json:"browser_attempts"`
	BrowserExecuted int `json:"browser_executed"`
	// BrowserSkipped is how many expressions the run's own bound kept it from trying.
	// It is reported because a run that stopped early and a run that found nothing are
	// different facts, and a report that shows both as zero reads as the second.
	BrowserSkipped int `json:"browser_skipped"`
	// BrowserErrors counts the loads the browser could not perform at all. It is its
	// own field because it is the tool's failure and not the target's, and a run that
	// reports it as "nothing executed" is blaming a page for a browser that was not
	// looking.
	BrowserErrors int `json:"browser_errors"`
}

// ScanEvent is one line of the run's own trace, so a report can be read as a
// sequence of requests rather than as a wall of findings.
type ScanEvent struct {
	At      time.Time `json:"at"`
	Phase   string    `json:"phase"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail"`
}

// Reporter receives progress. It is called from the run's goroutines, so an
// implementation that touches shared state has to do its own locking — the
// engine's SSE writer already serialises.
type Reporter func(Progress)

// Scan is a run in progress. It is a value, not a package global, so a test can
// run two against two servers without either seeing the other.
type Scan struct {
	request ScanRequest
	modules []Module
	chains  []Chain
	// notify receives progress as it happens. It is the run's only outward
	// edge, so a caller can watch a run without the run knowing whether it is
	// being watched by an SSE writer, a test, or nothing at all.
	notify Reporter
	// sink receives each finding as the surface that produced it finishes. It is
	// read once by `Run` and never written, so it needs no lock of its own; the
	// implementation has to be concurrency-safe because the probing workers are
	// the callers.
	sink   func(Finding)
	mu     sync.Mutex
	progress Progress
	events   []ScanEvent
}

// NewScan builds a run. Nothing is fetched until Run is called.
//
// A nil reporter is allowed and means "nobody is watching": the run still counts
// and still traces, and `Progress()` still answers, so a caller that only wants
// the report at the end does not have to supply a sink.
func NewScan(request ScanRequest, report Reporter) *Scan {
	request.MarkerHost = redirectMarker(request.MarkerHost)
	return &Scan{
		request: request,
		modules: modulesWith(request.MarkerHost, request.BlindDelay, moduleOptions{
			params: request.Params,
			paths:  request.PathWordlist,
		}),
		chains: AllChains(),
		notify: report,
		sink:   request.FindingSink,
		progress: Progress{
			Phase: "queued", PagesTotal: -1, PointsTotal: -1,
		},
	}
}

// redirectMarker is the destination the open-redirect detector will offer, and it
// always returns something.
//
// The "always" is the point. An empty destination makes `Redirect.Scan` return
// nothing at all, so a run that left it empty reported "no open redirect" for
// every target on the internet while carrying the module in its module count —
// the detector was counted, never run. So a run with no destination of its own
// mints one per run, and the refusal to continue is not an option: a scan tool
// that skips a detector without saying so is the failure this project already paid
// for once.
//
// The minted host is a canary under `.invalid`. RFC 2606 reserves that TLD so it
// can never resolve, the redirect probe does not follow the `Location` it reads,
// and a host that cannot resolve cannot be anybody's target by accident.
func redirectMarker(marker string) string {
	if trimmed := strings.TrimSpace(marker); trimmed != "" {
		return trimmed
	}
	canary := newCanary("rrredir")
	if canary == "" {
		// crypto/rand is unavailable. The alternative to a random host is a fixed
		// one, and a fixed host is one a target can recognise and refuse to
		// redirect to, which would make the detector report nothing for a reason
		// that has nothing to do with the target. There is no third option that
		// keeps the check sound, so the run proceeds without the destination and
		// the report says so.
		return ""
	}
	return canary + ".invalid"
}

// Run executes the scan and returns its report.
//
// The report is returned even when the run failed, with the error named in
// `Stats`-adjacent `Progress.Error` and the partial work kept. A run that found
// four things and then hit a dead host has still found four things, and dropping
// them because the fifth page timed out is how a partial run becomes an empty
// one.
func (s *Scan) Run(ctx context.Context) (*Report, error) {
	clock := s.request.clock()
	started := clock()
	target, err := url.Parse(strings.TrimSpace(s.request.URL))
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("url must be an absolute http or https URL")
	}
	// The transport is built with the caller's RoundTripper and nothing else: it
	// refuses to be constructed rather than quietly falling back to
	// http.DefaultTransport and losing the recording proxy and the cookie jar.
	transport, err := NewTransport(s.request.RoundTripper, Options{
		Timeout:     s.request.Timeout,
		Bypass:      s.request.Bypass,
		BypassForms: s.request.BypassForms,
	})
	if err != nil {
		return nil, err
	}
	report := &Report{
		Target:  target.String(),
		Plan:    s.request,
		Workers: s.request.workers(),
		Started: started,
	}
	s.emit(Progress{Phase: "crawling", PagesTotal: -1, PointsTotal: -1, Detail: "following links from " + target.Host})

	pages, crawlWarnings, _, err := s.crawl(ctx, transport, target)
	report.Pages = len(pages)
	for _, p := range pages {
		report.Visited = append(report.Visited, p.URL)
	}
	report.Warnings = append(report.Warnings, crawlWarnings...)
	if len(pages) == 0 {
		// The requests this run already spent are reported even when it produced
		// nothing. A run that failed after fetching a start page reports "requests:
		// 0", which reads as "nothing was sent" while the warnings above name the
		// URL it spent them on — and the count is the one number that describes what
		// the scan did to the target.
		report.Stats.Requests = transport.Requests()
		report.Stats.BypassWalks, report.Stats.BypassHits, report.Stats.BypassRequests = transport.BypassStats()
		if err != nil {
			s.fail(fmt.Errorf("no page could be fetched: %w", err))
			report.Duration = clock().Sub(started).String()
			report.Trace = s.traceSnapshot()
			return report, err
		}
		s.fail(fmt.Errorf("the start page returned no injectable surface and no link to follow"))
		report.Duration = clock().Sub(started).String()
		report.Trace = s.traceSnapshot()
		return report, nil
	}

	// Endpoints no page links to. The crawl can only find what the application
	// publishes, so a run also checks a short list of well-known paths on the
	// start origin and feeds the answers through the same harvest. The answers
	// are added to the page list rather than replacing it: the crawl found the
	// surfaces the developer published, this finds the ones they did not, and a
	// run that reported only the second would be worse than one that reported
	// neither.
	origin := target.Scheme + "://" + target.Host
	visited := map[string]bool{}
	for _, p := range pages {
		visited[p.URL] = true
	}
	probed, probeWarnings := s.probeInterestingPaths(ctx, transport, origin, visited)
	report.Warnings = append(report.Warnings, probeWarnings...)
	if len(probed) > 0 {
		pages = append(pages, probed...)
		report.Pages = len(pages)
		for _, p := range probed {
			report.Visited = append(report.Visited, p.URL)
		}
		s.trace("probing", target.Host,
			fmt.Sprintf("%d well-known path(s) answered 200 and were added to the surface", len(probed)))
	}

	points := harvestAll(pages)
	report.Points = points
	hosts := map[string]bool{}
	for _, point := range points {
		hosts[hostOf(point.URL)] = true
	}
	report.Stats = ScanStats{
		Points:  len(points),
		Modules: len(s.modules),
		Hosts:   len(hosts),
	}
	// A run that could not mint a redirect destination reports it rather than
	// counting the module and staying silent: the module count says nine
	// detectors ran, and without this line nothing in the report would say that
	// one of them could not.
	if s.request.MarkerHost == "" {
		report.Warnings = append(report.Warnings,
			"the open-redirect detector ran without a destination because the system has no entropy "+
				"source, so it could not prove an off-site redirect; every other detector ran normally")
	}
	s.trace("crawling", target.Host,
		fmt.Sprintf("%d page(s), %d injectable surface(s), %d host(s)", len(pages), len(points), len(hosts)))

	// The detectors. One baseline per surface, fetched once and shared, because
	// every detector needs the same unmodified response and re-fetching it per
	// detector is both slower and the reason two detectors can disagree about
	// what the original page looked like.
	findings := s.probe(ctx, transport, s.surfacesFor(points, pages), report)
	report.Findings = append(report.Findings, findings...)

	// The chains. They run after every detector rather than inside one, because
	// a chain correlates two findings and neither detector knows the other
	// exists.
	s.emit(Progress{Phase: "correlating", PointsTested: len(points), PointsTotal: len(points),
		Findings: len(report.Findings), Detail: "correlating findings into chains"})
	chains := Chains(ctx, ChainInput{Transport: transport, Findings: report.Findings, Points: points})
	report.Findings = append(report.Findings, chains...)
	// A chain is a row an operator has not seen yet and it is not in the report
	// until correlation finishes, so it is announced here for the same reason the
	// detector rows are announced in `probe`: the run's rows exist before the run
	// ends, and a watcher that is only told at the end is watching a counter.
	s.announce(chains)
	report.Stats.Chains = len(chains)

	// The proofs. They run last, over the verified rows only, so a run does not
	// spend requests proving something it has not established.
	s.emit(Progress{Phase: "proving", PointsTested: len(points), PointsTotal: len(points),
		Findings: len(report.Findings), Detail: "generating proofs for confirmed findings"})
	suite := &Suite{Transport: transport, Renderer: s.request.Renderer,
		MarkerHost: s.request.MarkerHost, Candidates: s.request.BrowserCandidates}
	report.Proofs = suite.Run(ctx, report.Findings)
	applyProofUpgrades(report.Findings, report.Proofs)
	report.Stats.BrowserAttempts, report.Stats.BrowserExecuted = suite.browserAttempts, 0
	report.Stats.BrowserSkipped = suite.browserSkipped
	report.Stats.BrowserErrors = suite.browserErrors
	for _, proof := range report.Proofs {
		if proof.Kind == "browser-execution" {
			report.Stats.BrowserExecuted++
		}
	}
	// A run that had a browser and settled nothing with it is reported, because
	// the alternative is a report where a missing capability and a target that
	// resisted look identical.
	if s.request.Renderer != nil && suite.browserAttempts > 0 && report.Stats.BrowserExecuted == 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"a browser was available and %d escaping row(s) were checked in it, and none of them "+
				"executed: the payloads are reported at the tier the response proved, not as failures",
			suite.browserAttempts))
	}
	// And the same in the other direction: a run with no browser that found an
	// escape has rows nobody settled in one, and a reader comparing two reports
	// has to be able to see that this one could not have.
	if suite.browserErrors > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"the browser failed to load %d page(s) during the confirmation stage: those rows were "+
				"left at the tier the response proved, and the failure is the browser's, not the target's",
			suite.browserErrors))
	}
	if suite.browserSkipped > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%d expression(s) were not tried because the run was bounded to %d per row "+
				"(browser_candidates); the rows they belong to keep the tier the response proved",
			suite.browserSkipped, s.request.BrowserCandidates))
	}
	if s.request.Renderer == nil {
		if structural := countUnexecutedEscapes(report.Findings, report.Proofs); structural > 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf(
				"%d escaping row(s) were proved structurally only: no browser was offered to this "+
					"run, so nothing here was executed", structural))
		}
	}

	SortFindings(report.Findings)
	// Every request of the run, counted by the transport they all went through.
	report.Stats.Requests = transport.Requests()
	// The ladder's own numbers, so a report says what the bypass cost as well as
	// what the run found. They are zero when the operator did not turn it on.
	report.Stats.BypassWalks, report.Stats.BypassHits, report.Stats.BypassRequests = transport.BypassStats()
	for _, finding := range report.Findings {
		switch finding.Tier {
		case TierVerified:
			report.Stats.Verified++
		default:
			report.Stats.Potential++
		}
		if finding.Capped {
			report.Stats.Capped++
		}
	}
	report.Duration = clock().Sub(started).String()
	s.emit(Progress{Phase: "completed", PointsTested: len(points), PointsTotal: len(points),
		Findings: len(report.Findings), Detail: report.Duration})
	s.trace("completed", target.Host, fmt.Sprintf("%d finding(s), %d proof(s)", len(report.Findings), len(report.Proofs)))
	report.Trace = s.traceSnapshot()
	return report, nil
}

// probe runs every module over every surface through a worker pool.
// surfacesFor lays out the work: every injectable surface for the detectors that
// work on parameters, and every unique URL for the detectors that work on an
// endpoint.
//
// The endpoint pass is not an optimisation and not an extra: without it the two
// detectors that declare `LevelEndpoint` are handed only surfaces that happen to
// have a form, so a credential printed on a page the application never built a
// form for, and a missing security header on a page with no parameters, are
// both invisible. Those are exactly the findings an endpoint-level detector
// exists to produce.
func (s *Scan) surfacesFor(points []Point, pages []page) []probeSurface {
	// One loop, three buckets. There were two loops here for a while and the second
	// one was *added* rather than substituted, so every module that is neither
	// host- nor endpoint-level was appended to `param` twice. Every parameter-level
	// detector therefore ran twice per surface and reported every finding twice:
	// two rows with the same content-addressed ID, which is precisely the state the
	// ID scheme exists to make impossible.
	//
	// It surfaced as an unrelated failure. `applyProofUpgrades` raises the *last*
	// row carrying a proof's ID, so with duplicates the other copy stayed at
	// `potential` and `TestTheReportShowsTheRowAProofRaised` reported a proof that
	// had verified something the row still denied — a correct assertion about a
	// report that was wrong. Nothing about that test points at a duplicated module
	// list, which is why this is written down here rather than left to be found a
	// third time.
	var param, endpoint, host []Module
	for _, module := range s.modules {
		switch module.Level() {
		case LevelHost:
			host = append(host, module)
		case LevelEndpoint:
			endpoint = append(endpoint, module)
		default:
			param = append(param, module)
		}
	}

	var out []probeSurface
	// Host-level detectors get exactly one surface: the run's start URL. The
	// question they answer is about the server rather than about a page — what
	// software it is, what its banner says — and a server answers the same thing
	// on every URL, so a second surface would produce a second copy of the same
	// row. That is not a small duplication: the fixture scan reported 24 identical
	// fingerprint rows from one host before this branch existed, which is the
	// "four hundred identical rows" failure `Misconfig` documents for hardening
	// headers, reproduced by a level nobody had implemented.
	//
	// `LevelHost` was declared in the enum and had no case anywhere, so it fell
	// into the `default` below and ran on every injectable parameter — the same
	// dead-field shape as `CMDi.BlindDelay` being constructed as `CMDi{}`: a
	// contract the caller reads and the wiring never fulfils. Nothing else
	// declares `LevelHost`, so this branch changes no existing module's
	// behaviour; it makes the enum mean what it says.
	if len(host) > 0 {
		out = append(out, probeSurface{
			point:   Point{URL: s.request.URL, Method: http.MethodGet},
			modules: host,
		})
	}

	// Injectable surfaces. A surface with no module that applies to it is not
	// queued: fetching a baseline for it would spend a request to run nothing.
	if len(param) > 0 {
		for _, point := range points {
			out = append(out, probeSurface{point: point, modules: param})
		}
	}

	// Unique endpoints, in the order the run reached them, so the report reads in
	// the order the crawl discovered rather than in map order. A URL that is both
	// a crawled page and a probed path appears once.
	if len(endpoint) > 0 {
		seen := make(map[string]bool, len(pages))
		for _, p := range pages {
			key := p.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, probeSurface{
				point:   Point{URL: p.URL, Method: http.MethodGet},
				modules: endpoint,
			})
		}
	}
	return out
}

// moduleCount is how many detectors a run carries, for the progress line.
func (s *Scan) moduleCount() int { return len(s.modules) }

// probeSurface is one unit of work: a point, the detectors that apply to it at
// their level, and the single baseline they share.
//
// The module list is here rather than read per point because the level decides
// which points a detector is ever given, and that decision is made once, where
// the work is laid out. A detector declared LevelEndpoint is never handed a
// parameter and one declared LevelParam is never handed a bare URL — that
// separation is the contract `Module.Level` states, and it is what makes the
// numbers in the report mean something: a credential leak is counted per
// endpoint, an injection per injectable surface.
type probeSurface struct {
	point   Point
	modules []Module
}

func (s *Scan) probe(ctx context.Context, transport *Transport, surfaces []probeSurface, report *Report) []Finding {
	points := make([]Point, 0, len(surfaces))
	for _, surface := range surfaces {
		points = append(points, surface.point)
	}
	workers := s.request.workers()
	if workers > len(surfaces) {
		workers = len(surfaces)
	}
	if workers < 1 {
		return nil
	}
	// Per-surface results, written by exactly one worker each, so the mutex
	// guards the shared slices and not the work.
	perPoint := make([][]Finding, len(surfaces))
	baseline := make([]*Response, len(surfaces))
	var done int64
	var mu sync.Mutex

	s.emit(Progress{Phase: "probing", PointsTotal: len(points), PagesFetched: report.Pages,
		Detail: fmt.Sprintf("probing %d surface(s) with %d detector(s) across %d worker(s)",
			len(surfaces), s.moduleCount(), workers)})

	queue := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range queue {
				if ctx.Err() != nil {
					return
				}
				surface := surfaces[index]
				point := surface.point
				// One baseline, fetched once. A nil baseline is passed through to
				// the detectors, and Fresh refuses it, so a surface that cannot
				// be read produces nothing rather than a guess.
				base, err := transport.Baseline(ctx, point, s.request.FollowRedirects)
				if err == nil {
					baseline[index] = base
				}
				var local []Finding
				for _, module := range surface.modules {
					if ctx.Err() != nil {
						break
					}
					if s.request.Delay > 0 {
						select {
						case <-time.After(s.request.Delay):
						case <-ctx.Done():
							return
						}
					}
					local = append(local, module.Scan(ctx, transport, point, baseline[index])...)
				}
				// The write and the count are one critical section. Writing the
				// slice element outside the lock races with the progress loop
				// below, which reads every element to total the findings — and
				// `go test -race` found it on the first run of a concurrent
				// surface, which is exactly where it would be found.
				mu.Lock()
				perPoint[index] = local
				done++
				progress := Progress{
					Phase: "probing", PagesFetched: report.Pages,
					PointsTested: int(done), PointsTotal: len(surfaces),
					Detail: fmt.Sprintf("%d/%d surface(s)", done, len(surfaces)),
				}
				for _, list := range perPoint {
					progress.Findings += len(list)
				}
				mu.Unlock()
				// The rows leave the run here, outside the lock, so a caller that
				// takes its own lock — the engine publishes each one on the job's
				// stream — cannot deadlock against the progress bookkeeping, and
				// so a slow sink does not serialise the workers.
				s.announce(local)
				s.emit(progress)
			}
		}()
	}
	for index := range surfaces {
		select {
		case queue <- index:
		case <-ctx.Done():
			close(queue)
			wg.Wait()
			return s.collect(perPoint)
		}
	}
	close(queue)
	wg.Wait()
	return s.collect(perPoint)
}

// collect flattens the per-surface results in surface order.
//
// Order is the crawl order, not the completion order, so a cancelled run's
// partial report reads the same way a complete one does.
func (s *Scan) collect(perPoint [][]Finding) []Finding {
	var out []Finding
	for _, list := range perPoint {
		out = append(out, list...)
	}
	return out
}

// applyProofUpgrades raises the rows a proof demonstrated the impact for.
//
// A proof that arrives for a row the detector left at `TierPotential` is not
// decoration: it re-requested the endpoint and accepted the answer only when a
// value this run chose came back and the request was not echoed. That is the same
// bar every other verified row had to clear, so the row is raised to `TierVerified`
// and its evidence becomes the proof's own sentence.
//
// The proof is left alone. It carries `Upgrades`, so the report can say which came
// first — a proof beside a row that was already verified corroborates it, and a
// proof that arrived first is what raised the row. Silently showing both as
// "verified, with a proof" would not say that.
//
// A proof whose `finding_id` names no row is dropped rather than attached to
// whatever row happens to be first: that would put the evidence for one claim next
// to a different claim.
func applyProofUpgrades(findings []Finding, proofs []Proof) {
	if len(proofs) == 0 {
		return
	}
	rows := make(map[string]*Finding, len(findings))
	for i := range findings {
		rows[findings[i].ID] = &findings[i]
	}
	for _, proof := range proofs {
		if !proof.Upgrades {
			continue
		}
		if row, ok := rows[proof.FindingID]; ok && row.Tier != TierVerified {
			row.Tier = TierVerified
			row.Evidence = proof.Proof
		}
	}
}
