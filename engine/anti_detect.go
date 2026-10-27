package main

// Request shaping and challenge evidence for the static site-map crawler.
//
// The rule this file follows is the same one the browser worker follows:
// **automation artefacts are removed, identity is never invented.** The
// User-Agent the crawler sends is randomized from the anti-detect pool (RandomUserAgent())
// using UserAgent.txt so that the security tool never leaks recognisable signatures
// to the target while preserving consistent browser navigation headers (Sec-Fetch-*,
// Referer, Upgrade-Insecure-Requests).
//
// What is fixed here is the *request*, not the client:
//
//   - cookies persist across the crawl. A crawler with no jar is stateless, and
//     a stateless client is both trivially detectable and unable to replay a
//     clearance cookie the analyst obtained elsewhere.
//   - the navigation metadata a real browser sends — Sec-Fetch-*, Referer,
//     Upgrade-Insecure-Requests — is present and consistent with what the
//     crawler is actually doing, so the headers describe the request truthfully.
//   - a 429 or 503 that carries Retry-After is honoured, because backing off is
//     what a real client does and not backing off is what gets a client banned.
//
// What is deliberately NOT fixed, and is named in DEVELOPMENT_LOG.md rather
// than hidden: the TLS ClientHello, the order in which Go writes headers, and
// Accept-Encoding, which Go keeps at "gzip". Those identify the Go standard
// library to any fingerprint database, and closing them means either
// impersonating a browser's TLS stack — the same category of lie as a
// rewritten User-Agent — or adding a dependency this project decided against.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"intruder/engine/pkg/bypass"
)

// crawlerRequestShape carries what one crawl needs to know about how it is
// allowed to look. Every field is either an explicit analyst setting or a
// derived fact, and nothing here is a hidden cap: the values that cost time
// are read from configuration and reported back per page.
type crawlerRequestShape struct {
	// acceptLanguage is the analyst's language preference. It is identity, so
	// it is never invented: empty means the header is not sent at all, which
	// is what the crawler did before this field existed.
	acceptLanguage string
	// retryAttempts is how many extra tries a 429 or 503 earns. 0 means the
	// first response is recorded as it is, exactly as before.
	retryAttempts int
	// retryDelayMs is added to a server-requested pause, so a Retry-After is
	// never shortened by the crawler.
	retryDelayMs int
	// timeout bounds one crawl request. Zero means `defaultCrawlTimeout`.
	//
	// It is a field rather than a constant because the alternative was measured:
	// with no per-request bound, a host that accepted the connection and then said
	// nothing kept the crawl waiting on the transport's own 60-second response
	// header deadline, twenty consecutive times over, before the run could call
	// that a broken host. A crawl that cannot fail cannot be paused.
	timeout time.Duration
}

// defaultCrawlTimeout is how long one crawl request may wait when the analyst did
// not say. It matches the active scanner's documented default so the two tools
// behave alike against the same target, and it is a default rather than a ceiling:
// `timeout_ms` overrides it in either direction and nothing clamps the operator's
// number.
const defaultCrawlTimeout = 15 * time.Second

// navigatorHeaders returns the metadata a browser attaches to a top-level
// navigation. They describe the request's relationship to the page, not the
// client, so they carry no identity and are always safe to state truthfully.
func navigatorHeaders(target *url.URL, referer string) map[string]string {
	header := map[string]string{
		"Sec-Fetch-Site": fetchSite(target, referer),
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
	}
	if target != nil && target.Scheme == "https" {
		// Sent by every browser on an https navigation, and it is the one
		// header whose absence is louder than its presence.
		header["Upgrade-Insecure-Requests"] = "1"
	}
	if referer != "" {
		header["Referer"] = referer
	}
	return header
}

// fetchSite reports where a navigation came from, which is the one of the four
// Sec-Fetch values that is a fact about this request rather than a claim about
// the client. The origin comparison is real: claiming "same-origin" for a
// cross-site hop would make the value a lie, which is worse than omitting it.
func fetchSite(target *url.URL, referer string) string {
	if referer == "" {
		return "none"
	}
	source, err := url.Parse(referer)
	if err != nil || target == nil {
		return "cross-site"
	}
	if source.Scheme == target.Scheme && source.Host == target.Host {
		return "same-origin"
	}
	return "cross-site"
}

// documentAccept returns the Accept value a browser sends for one crawled
// resource. A crawler that sent the same list for a stylesheet and for a
// document is as conspicuous as one that sent no Accept at all.
func documentAccept(kind, lowerPath string) string {
	switch {
	case kind == "robots.txt":
		return "text/plain,*/*;q=0.5"
	case kind == "sitemap" || strings.HasSuffix(lowerPath, ".xml"):
		return "application/xml,text/xml;q=0.9,*/*;q=0.8"
	case strings.HasSuffix(lowerPath, ".json"):
		return "application/json,text/plain;q=0.9,*/*;q=0.8"
	default:
		return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	}
}

// crawlerKindKey carries "what kind of resource is being fetched" from the
// crawl loop to the transport. It travels in the context rather than in a
// header on purpose: a header invented to be deleted on the way out is one
// refactor away from being sent to the target, and the request this code sends
// is the evidence the analyst reads.
type crawlerKindKey struct{}

func withCrawlerKind(ctx context.Context, kind string) context.Context {
	return context.WithValue(ctx, crawlerKindKey{}, kind)
}

func crawlerKind(ctx context.Context) string {
	if kind, ok := ctx.Value(crawlerKindKey{}).(string); ok && kind != "" {
		return kind
	}
	return "page"
}

// crawlerTransport shapes the outgoing request and then delegates to the
// route-aware transport, so Tor, the dial bounds and the generation check keep
// working exactly as they did. It never replaces the transport, only decorates
// the request, because replacing it would take the crawl off the active route.
type crawlerTransport struct {
	base  http.RoundTripper
	shape crawlerRequestShape

	// ladder is the 403 walk, or nil when the operator did not ask for one.
	//
	// It is nil by default and that is a decision, not an omission: a walk sends
	// one request per form, so a crawl of a thousand pages that hit an edge
	// refusing by shape would cost thousands more. The operator turns it on.
	ladder *bypass.Driver

	// walk is the client the ladder uses, and it is deliberately *not* this
	// transport.
	//
	// It carries the same cookie jar so a form is sent with the session the crawl
	// has built, and the same base so it leaves by the same route — but its
	// transport is the bare `base`, because a form that went back through this
	// decorator would re-apply the navigator headers to an already-rewritten
	// request and, worse, would re-enter the walk it is being sent from.
	walk *http.Client

	// onBypass is called once per page that was reached only because a form
	// reached it.
	//
	// It exists because a map that silently got wider is a map that lies: the
	// page is in the report and nothing says the plain request was refused. The
	// crawl's own log is where an analyst reads it.
	onBypass func(method, rawURL, form string, status int)
}

func (t crawlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	shaped := req.Clone(req.Context())
	kind := crawlerKind(shaped.Context())
	for name, value := range navigatorHeaders(shaped.URL, shaped.Header.Get("Referer")) {
		shaped.Header.Set(name, value)
	}
	if shaped.Header.Get("User-Agent") == "" {
		shaped.Header.Set("User-Agent", RandomUserAgent())
	}
	// Accept-Encoding is deliberately not set: Go adds "gzip" and decodes it
	// transparently, and claiming a longer list would mean handing back a body
	// this crawler cannot read.
	shaped.Header.Set("Accept", documentAccept(kind, strings.ToLower(shaped.URL.Path)))
	if t.shape.acceptLanguage != "" {
		shaped.Header.Set("Accept-Language", t.shape.acceptLanguage)
	}

	resp, err := t.base.RoundTrip(shaped)
	if err != nil || t.ladder == nil || !bypass.Refused(resp.StatusCode) {
		// No ladder, or the plain request was answered: nothing to walk. The
		// navigator-shaped request is the whole job of this method in that case.
		return resp, err
	}

	// The refusal is kept, body and all. If no form reaches the page the caller
	// gets the 403 it would have got anyway, and closing it here would replace a
	// real answer with an empty one.
	refused := resp
	walked, attempt, walkErr := t.ladder.Walk(shaped.Context(), t.walk, shaped, resp.StatusCode)
	if walkErr != nil {
		if errors.Is(walkErr, bypass.ErrNoFormReached) {
			// Every form refused, and this caller's own 403 is the truthful answer
			// — so the walk failing is not a failure of the crawl. The refusal is
			// kept, body and all.
			if t.onBypass != nil {
				t.onBypass(shaped.Method, shaped.URL.String(), attempt.TriedSummary(), refused.StatusCode)
			}
			return refused, nil
		}
		return nil, walkErr
	}
	refused.Body.Close()
	if t.onBypass != nil {
		t.onBypass(shaped.Method, shaped.URL.String(), attempt.SucceededBy, walked.StatusCode)
	}
	return walked, nil
}

func (t crawlerTransport) CloseIdleConnections() {
	if ci, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
	if t.walk != nil {
		t.walk.CloseIdleConnections()
	}
}

// newCrawlerClient builds the client the site-map crawl uses.
//
// The jar is the part that matters most and the part that was missing: without
// it every page is a first contact, a session cookie is discarded the moment
// it is set, and a clearance cookie the analyst obtained in the browser can
// never be replayed here. The jar is created with a public-suffix-less store
// on purpose — net/http has no PSL, and the crawl is already free to follow
// links across hosts, so pretending otherwise would only lose cookies.
//
// Redirects are followed, and the chain is recorded rather than thrown away.
// Measured on a live target 2026-10-03: the crawl answered `ErrUseLastResponse`
// to every 3xx, so a site whose homepage redirects — `https://yandex.ru/` answers
// `302` with no body — was published as a page with no body, therefore with no
// link, therefore with no script, and the map came back empty with nothing in it
// to explain why. A redirect is the normal way a site says "the page you asked
// for is over there", and refusing to read it is refusing the site, not the
// analyst's request. `crawlRedirectChain` puts the hops back into the page
// record, so following them costs no evidence.
func newCrawlerClient(base http.RoundTripper, shape crawlerRequestShape) (*http.Client, error) {
	return newCrawlerClientWithBypass(base, shape, nil, nil)
}

// newCrawlerClientWithBypass is the crawler client with the 403 walk attached.
//
// `forms` is the operator's selection, as a list of form names. An empty list —
// and `nil`, which is the same thing here — means no walk at all; a populated one
// means walk exactly those forms.
//
// # This deliberately does NOT follow `bypass.New`'s convention, and the
// difference is the whole point
//
// `bypass.New(nil)` means "every form", because inside the package the caller is
// asking which techniques to try and has no reason to enumerate them. This caller
// is the operator's button, and the button has two positions: not pressed, and
// pressed. So here the empty selection means **off**, and turning the walk on
// requires the caller to name the forms it wants.
//
// An earlier version of this comment documented the opposite rule — nil meaning
// "every form" — while the code below did `if len(forms) > 0` and therefore meant
// "off". The comment and the code disagreed inside one file, and `main.go` and the
// Django gateway both send a populated list or an empty one, so the implementation
// was right and the comment was wrong. Fixing the comment is what keeps the next
// reader from "correcting" the code to match it and breaking the button.
//
// Neither caller invents the default list, so the engine never has to change when
// a form is added: whoever offers the operator the choice owns the list.
//
// The walk's own client shares the jar. That is the part that makes it worth
// having: a form that reaches a page behind a login must arrive with the session
// the crawl built, or the 403 it answers is the login page and the walk teaches
// us nothing about the edge.
//
// The walk's client does **not** share this transport, so the navigator headers
// are applied once — to the plain request — and a form is not re-decorated on top
// of an already rewritten request.
func newCrawlerClientWithBypass(
	base http.RoundTripper, shape crawlerRequestShape, forms []string,
	onBypass func(method, rawURL, form string, status int),
) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := crawlerTransport{base: base, shape: shape, onBypass: onBypass}
	// A length check, not a nil check, because "the operator chose nothing" and
	// "there is a ladder and it has no forms" are different states: the second
	// would attach a walk that rejects every form and then re-sends the plain
	// request, spending one request to learn nothing.
	if len(forms) > 0 {
		transport.ladder = bypass.New(forms)
		transport.walk = &http.Client{Transport: base, Jar: jar}
	}
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   shape.timeout,
	}
	if client.Timeout <= 0 {
		client.Timeout = defaultCrawlTimeout
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Go's own bound is 10 hops; the crawl keeps it rather than inventing a
		// second number, because a loop that outlives the standard bound is a
		// site problem and the client's answer to it is already written down.
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return client, nil
}

// crawlRedirectChain reads the hops a request made out of the responses the
// server sent back, so a page can say where it actually came from. It is empty
// for every response that was not a redirect.
//
// Each hop is written the way the site wrote it: the URL that was asked for, the
// `Location` it answered with, and the status that said so. Walking backwards
// from the final response and then reversing gives the order the analyst reads.
func crawlRedirectChain(resp *http.Response) []map[string]interface{} {
	if resp == nil || resp.Request == nil || resp.Request.Response == nil {
		return nil
	}
	chain := []map[string]interface{}{}
	for hop := resp.Request.Response; hop != nil && hop.Request != nil; hop = hop.Request.Response {
		if hop.Request.URL == nil {
			break
		}
		entry := map[string]interface{}{
			"from":   hop.Request.URL.String(),
			"status": hop.StatusCode,
		}
		if location := strings.TrimSpace(hop.Header.Get("Location")); location != "" {
			entry["to"] = resolveCrawlLocation(hop.Request.URL, location)
		}
		chain = append(chain, entry)
	}
	if len(chain) == 0 {
		return nil
	}
	// The chain was walked from the last hop backwards; the analyst reads it
	// forwards, in the order the site asked for it.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// resolveCrawlLocation turns a `Location` header into the absolute URL it means,
// because the site is allowed to answer with a path and the record is read by a
// person who cannot tell `/home` from `https://other.host/home`.
func resolveCrawlLocation(base *url.URL, location string) string {
	parsed, err := url.Parse(location)
	if err != nil {
		return location
	}
	return base.ResolveReference(parsed).String()
}

// challengeFinding is one piece of evidence that the response a crawl received
// is a gate rather than the site.
// challengeFinding is what one marker proved.
//
// Gate is the part that decides whether a page is a wall or a page that happens
// to carry a captcha widget, and it is the part that was missing. Measured on a
// live target 2026-10-03: the homepage of a large news site carries
// `g-recaptcha` on a comment form and 279 KB of real content around it. Read as
// a gate, it was — the crawler stopped following links, so no script was ever
// discovered, and Target reported neither endpoints, nor sinks, nor secrets.
// The markers split in two by what the vendor writes them into:
//
//   - a gate: an interstitial the edge serves *instead of* the page, so the
//     string appears only there — Cloudflare's `Just a moment`,
//     `/cdn-cgi/challenge-platform`, `cf-challenge-running`, an image challenge,
//     a `px-captcha` slider;
//   - a widget: a script or a div every ordinary site with that captcha
//     embeds — `g-recaptcha`, `recaptcha/api.js`, `grecaptcha.execute`,
//     `h-captcha`, Turnstile, `challenges.cloudflare.com`.
//
// A widget is reported as context and the crawl continues; a gate is reported
// and the crawl stops, because its links would report coverage it never had.
type challengeFinding struct {
	Vendor   string `json:"vendor"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
	Gate     bool   `json:"gate"`
}

// challengeVendors maps the markers the vendors actually ship to what they
// mean. Each is matched against a response header, a cookie name or the body
// text — never against a status code, because a 403 is a 403 and a 503 is a
// 503, and reading a vendor out of one is a guess dressed as a finding.
var challengeVendors = []struct {
	Vendor  string
	Kind    string
	Source  string
	Marker  string
	Headers bool
	// Gate says the marker belongs to a page the edge serves *instead of* the
	// requested one. Everything left false below is a widget the site embeds on
	// its own pages; see challengeFinding.Gate for the measurement.
	Gate bool
}{
	{Vendor: "cloudflare", Kind: "interstitial", Source: "header", Marker: "cf-mitigated", Headers: true, Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "header", Marker: "cf-chl-bypass", Headers: true, Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "header", Marker: "cf-chl-b2", Headers: true, Gate: true},
	{Vendor: "datadome", Kind: "interstitial", Source: "header", Marker: "x-datadome", Headers: true, Gate: true},
	{Vendor: "akamai", Kind: "interstitial", Source: "header", Marker: "x-akamai-transformed", Headers: true, Gate: true},
	{Vendor: "perimeterx", Kind: "interstitial", Source: "header", Marker: "x-px-", Headers: true, Gate: true},
	{Vendor: "imperva", Kind: "interstitial", Source: "header", Marker: "incap_ses", Headers: true, Gate: true},
	{Vendor: "kasada", Kind: "interstitial", Source: "header", Marker: "x-kpsdk-ct", Headers: true, Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "cookie", Marker: "cf_clearance", Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "cookie", Marker: "__cf_bm", Gate: true},
	{Vendor: "datadome", Kind: "interstitial", Source: "cookie", Marker: "datadome", Gate: true},
	{Vendor: "perimeterx", Kind: "interstitial", Source: "cookie", Marker: "_px", Gate: true},
	{Vendor: "akamai", Kind: "interstitial", Source: "cookie", Marker: "bm_sz", Gate: true},
	{Vendor: "akamai", Kind: "interstitial", Source: "cookie", Marker: "ak_bmsc", Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "body", Marker: "Just a moment", Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "body", Marker: "/cdn-cgi/challenge-platform", Gate: true},
	{Vendor: "cloudflare", Kind: "interstitial", Source: "body", Marker: "cf-challenge-running", Gate: true},
	{Vendor: "cloudflare", Kind: "checkbox", Source: "body", Marker: "cf-turnstile"},
	{Vendor: "cloudflare", Kind: "checkbox", Source: "body", Marker: "challenges.cloudflare.com"},
	{Vendor: "recaptcha", Kind: "checkbox", Source: "body", Marker: "g-recaptcha"},
	{Vendor: "recaptcha", Kind: "checkbox", Source: "body", Marker: "recaptcha/api.js"},
	{Vendor: "recaptcha", Kind: "token", Source: "body", Marker: "grecaptcha.execute"},
	{Vendor: "hcaptcha", Kind: "checkbox", Source: "body", Marker: "h-captcha"},
	{Vendor: "hcaptcha", Kind: "checkbox", Source: "body", Marker: "hcaptcha.com/1/api.js"},
	{Vendor: "perimeterx", Kind: "slider", Source: "body", Marker: "px-captcha", Gate: true},
	{Vendor: "captcha", Kind: "grid", Source: "body", Marker: "recaptcha-image", Gate: true},
	{Vendor: "captcha", Kind: "text", Source: "body", Marker: "id=\"captcha\"", Gate: true},
}

// detectChallenge reports what the response is, with the evidence that decided
// it. The static crawler cannot execute JavaScript, so it never claims to have
// passed anything: what it can do is say that the page it received was a gate,
// which is the difference between an empty map and an explained one.
func detectChallenge(status int, header http.Header, cookies []*http.Cookie, body []byte, bodyTruncated bool) []challengeFinding {
	names := make(map[string]bool, len(cookies))
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name != "" {
			names[strings.ToLower(cookie.Name)] = true
		}
	}
	// A truncated body is a prefix of the document, not the document. Reading
	// it as if it were complete is how a gate at the end of a large page gets
	// reported as absent, so the fact travels with the finding.
	scope := "complete"
	if bodyTruncated {
		scope = "body prefix (truncated)"
	}
	text := ""
	if len(body) > 0 {
		text = strings.ToLower(string(body))
	}
	findings := make([]challengeFinding, 0, 4)
	seen := make(map[string]bool, 4)
	for _, vendor := range challengeVendors {
		var evidence string
		switch vendor.Source {
		case "header":
			for name, values := range header {
				for _, value := range values {
					if strings.Contains(strings.ToLower(name), vendor.Marker) &&
						strings.Contains(strings.ToLower(value), vendor.Marker) {
						evidence = fmt.Sprintf("%s: %s", name, vendor.Marker)
						break
					}
				}
				if evidence != "" {
					break
				}
			}
		case "cookie":
			if names[vendor.Marker] {
				evidence = "cookie " + vendor.Marker
			}
		case "body":
			if text != "" && strings.Contains(text, strings.ToLower(vendor.Marker)) {
				evidence = fmt.Sprintf("%s contains %q", scope, vendor.Marker)
			}
		}
		if evidence == "" {
			continue
		}
		key := vendor.Vendor + "|" + vendor.Kind + "|" + evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, challengeFinding{
			Vendor: vendor.Vendor, Kind: vendor.Kind,
			Source: vendor.Source, Evidence: evidence,
			Gate: vendor.Gate,
		})
	}
	// A status is reported as context, never as a finding: a bare 403 says
	// nothing about who refused, and attaching a vendor to it would be the
	// kind of guess this function exists to avoid.
	_ = status
	return findings
}

// challengeIsGate answers the only question the crawl has to ask about a page it
// received: is this a wall, or is it the site with a captcha widget on it?
//
// It reads the flag the vendor table carries, and not the count of findings,
// because the count says nothing: a page with three widget markers is still a
// page with scripts, and treating it as a wall is what emptied the map of every
// JavaScript file on a live site before this distinction existed.
func challengeIsGate(record interface{}) bool {
	findings, ok := record.([]challengeFinding)
	if !ok {
		return false
	}
	for _, finding := range findings {
		if finding.Gate {
			return true
		}
	}
	return false
}

// retryDelayFor returns how long a server asked the crawler to wait, and
// whether it asked at all. Retry-After is either a delay in seconds or an
// HTTP date; a date the crawler cannot parse is a server that did not really
// answer, and guessing a delay for it would be inventing a limit.
func retryDelayFor(header http.Header, now time.Time) (time.Duration, bool) {
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	if when, err := http.ParseTime(raw); err == nil {
		if delay := when.Sub(now); delay > 0 {
			return delay, true
		}
		return 0, true
	}
	return 0, false
}

// refererFor returns the Referer a browser would send when following a link
// from one page to another. It is omitted for the crawl's first request,
// because a browser sends no Referer on a typed or bookmarked navigation, and
// for non-document resources, because a browser does not navigate to a
// stylesheet or a robots file and so sends no navigation metadata for it.
func refererFor(referer string, kind string) string {
	if referer == "" || kind != "page" {
		return ""
	}
	return referer
}

// crawlOutcome is what one crawl step actually cost and produced. The retry
// fields are reported on the page rather than kept here, because a retry the
// analyst cannot see is a delay with no explanation attached to it.
type crawlOutcome struct {
	resp     *http.Response
	attempts int
	// retried is the count of extra tries, so 0 means the first answer was
	// taken as it came.
	retried int
	// waitedMS is how long the crawler spent honouring Retry-After. It is the
	// crawl's own time, not the server's answer, and the two are reported
	// separately so a wait is never mistaken for a slow site.
	waitedMS int64
	// retryAfter is the delay the server asked for, in seconds, or "" when it
	// asked for nothing.
	retryAfter string
}

// rateLimited reports whether a status is the one a rate limiter answers with.
// A 429 and a 503 are the two a Retry-After accompanies; anything else is a
// real answer and repeating the request would be noise.
func rateLimited(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// crawlOnce performs one crawl step, retrying a rate-limited answer as often as
// the analyst allowed.
//
// The wait is never shorter than the server asked for, and the crawler's own
// delay is added on top of it rather than replacing it — shortening a
// Retry-After is how a client earns a ban, and the delay is visible in the
// page record either way.
func crawlOnce(ctx context.Context, client *http.Client, req *http.Request, shape crawlerRequestShape) (*crawlOutcome, error) {
	outcome := &crawlOutcome{}
	for {
		outcome.attempts++
		resp, err := client.Do(req)
		if err != nil {
			return outcome, err
		}
		if !rateLimited(resp.StatusCode) || outcome.attempts > shape.retryAttempts {
			outcome.resp = resp
			return outcome, nil
		}
		wait, asked := retryDelayFor(resp.Header, time.Now())
		outcome.retryAfter = strconv.FormatInt(int64(wait/time.Second), 10)
		if !asked {
			// Nothing was asked for, so nothing is invented. A second try
			// happens immediately and the record says the server gave no
			// instruction, which is the truth about this response.
			outcome.retryAfter = ""
		}
		total := wait + time.Duration(shape.retryDelayMs)*time.Millisecond
		// Drain and close before waiting: an unread body holds the connection
		// out of the pool for the whole pause.
		_, _, _ = readAnalysisBody(resp.Body)
		resp.Body.Close()
		if !waitForDelay(ctx, total) {
			return outcome, ctx.Err()
		}
		outcome.waitedMS += total.Milliseconds()
		outcome.retried++
	}
}
