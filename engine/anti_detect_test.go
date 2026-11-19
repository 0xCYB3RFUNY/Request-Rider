package main

// Tests for the static crawler's request shaping and challenge evidence.
//
// The header tests measure what actually went on the wire against a real
// server, because the alternative — asserting that a helper returns the string
// it was given — would pass just as happily if the helper were never called.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu     sync.Mutex
	paths  []string
	header []http.Header
	cookie []string
}

func (c *capture) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths = append(c.paths, r.URL.Path)
	c.header = append(c.header, r.Header.Clone())
	c.cookie = append(c.cookie, r.Header.Get("Cookie"))
}

func (c *capture) at(i int) http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.header[i]
}

func (c *capture) cookiesAt(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cookie[i]
}

func TestCrawlerSendsTheNavigationMetadataABrowserSends(t *testing.T) {
	seen := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/second">second</a></body></html>`))
	}))
	defer server.Close()

	client, err := newCrawlerClient(server.Client().Transport, crawlerRequestShape{})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	for _, step := range []struct{ path, referer, kind string }{
		{"/", "", "page"},
		{"/second", server.URL + "/", "page"},
	} {
		req, err := http.NewRequestWithContext(
			withCrawlerKind(context.Background(), step.kind),
			http.MethodGet, server.URL+step.path, nil,
		)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if referer := refererFor(step.referer, step.kind); referer != "" {
			req.Header.Set("Referer", referer)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_, _, _ = readAnalysisBody(resp.Body)
		resp.Body.Close()
	}

	first := seen.at(0)
	// A browser sends no Referer on a typed or bookmarked navigation, so the
	// crawl's first request must not either.
	if got := first.Get("Referer"); got != "" {
		t.Fatalf("first request Referer = %q, want empty", got)
	}
	if got := first.Get("Sec-Fetch-Site"); got != "none" {
		t.Fatalf("first Sec-Fetch-Site = %q, want none", got)
	}
	for _, name := range []string{"Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept"} {
		if first.Get(name) == "" {
			t.Fatalf("first request is missing %s", name)
		}
	}
	if got := first.Get("Sec-Fetch-Mode"); got != "navigate" {
		t.Fatalf("Sec-Fetch-Mode = %q, want navigate", got)
	}

	second := seen.at(1)
	if got := second.Get("Referer"); got != server.URL+"/" {
		t.Fatalf("second Referer = %q, want %q", got, server.URL+"/")
	}
	if got := second.Get("Sec-Fetch-Site"); got != "same-origin" {
		t.Fatalf("second Sec-Fetch-Site = %q, want same-origin", got)
	}
}

func TestSecFetchSiteTellsCrossSiteFromSameOrigin(t *testing.T) {
	target, _ := url.Parse("https://target.example/page")
	cases := map[string]string{
		"":                             "none",
		"https://target.example/other": "same-origin",
		"https://other.example/page":   "cross-site",
		// Same host, different scheme: a different origin, so claiming
		// same-origin would be a lie about this request.
		"http://target.example/other": "cross-site",
	}
	for referer, want := range cases {
		if got := fetchSite(target, referer); got != want {
			t.Fatalf("fetchSite(%q) = %q, want %q", referer, got, want)
		}
	}
}

func TestCookiesSurviveAcrossTheCrawl(t *testing.T) {
	// The gap this closes: with no jar, every request is a first contact, so a
	// session cookie is discarded the moment it is set and a clearance cookie
	// can never be replayed.
	seen := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/second">second</a></body></html>`))
	}))
	defer server.Close()

	client, err := newCrawlerClient(server.Client().Transport, crawlerRequestShape{})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	for _, path := range []string{"/", "/second"} {
		req, err := http.NewRequestWithContext(
			withCrawlerKind(context.Background(), "page"),
			http.MethodGet, server.URL+path, nil,
		)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_, _, _ = readAnalysisBody(resp.Body)
		resp.Body.Close()
	}
	if got := seen.cookiesAt(0); strings.Contains(got, "session=") {
		t.Fatalf("first request already carried a cookie: %q", got)
	}
	if got := seen.cookiesAt(1); !strings.Contains(got, "session=abc123") {
		t.Fatalf("second request Cookie = %q, want the session cookie", got)
	}
}

func TestAcceptLanguageIsOnlySentWhenAskedFor(t *testing.T) {
	// Identity is never invented: without the field the header is absent,
	// which is exactly what the crawler sent before the field existed.
	seen := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	for _, shape := range []crawlerRequestShape{{}, {acceptLanguage: "uk-UA,uk;q=0.9"}} {
		client, err := newCrawlerClient(server.Client().Transport, shape)
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		req, err := http.NewRequestWithContext(
			withCrawlerKind(context.Background(), "page"),
			http.MethodGet, server.URL+"/", nil,
		)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_, _, _ = readAnalysisBody(resp.Body)
		resp.Body.Close()
	}
	if got := seen.at(0).Get("Accept-Language"); got != "" {
		t.Fatalf("Accept-Language = %q with no setting, want absent", got)
	}
	if got := seen.at(1).Get("Accept-Language"); got != "uk-UA,uk;q=0.9" {
		t.Fatalf("Accept-Language = %q, want the requested value", got)
	}
}

func TestAcceptReflectsTheResourceKind(t *testing.T) {
	// One Accept list for a stylesheet and for a document is as conspicuous as
	// no Accept at all, so the list follows the resource.
	if got := documentAccept("page", "/"); !strings.Contains(got, "text/html") {
		t.Fatalf("page Accept = %q", got)
	}
	if got := documentAccept("robots.txt", "/robots.txt"); !strings.Contains(got, "text/plain") {
		t.Fatalf("robots Accept = %q", got)
	}
	if got := documentAccept("sitemap", "/sitemap.xml"); !strings.Contains(got, "application/xml") {
		t.Fatalf("sitemap Accept = %q", got)
	}
}

func TestRefererIsOmittedForTheFirstRequestAndForNonDocuments(t *testing.T) {
	if got := refererFor("", "page"); got != "" {
		t.Fatalf("first request referer = %q, want empty", got)
	}
	if got := refererFor("https://x.example/a", "page"); got != "https://x.example/a" {
		t.Fatalf("page referer = %q", got)
	}
	if got := refererFor("https://x.example/a", "javascript"); got != "" {
		t.Fatalf("non-document referer = %q, want empty", got)
	}
}

func TestARateLimitedAnswerIsRetriedAndTheWaitIsReported(t *testing.T) {
	var served int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		attempt := served
		mu.Unlock()
		if attempt == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	client, err := newCrawlerClient(server.Client().Transport, crawlerRequestShape{retryAttempts: 1})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, err := http.NewRequestWithContext(
		withCrawlerKind(context.Background(), "page"), http.MethodGet, server.URL+"/", nil,
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	outcome, err := crawlOnce(context.Background(), client, req, crawlerRequestShape{retryAttempts: 1})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	_, _, _ = readAnalysisBody(outcome.resp.Body)
	outcome.resp.Body.Close()
	if outcome.resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after the retry", outcome.resp.StatusCode)
	}
	if outcome.retried != 1 {
		t.Fatalf("retried = %d, want 1", outcome.retried)
	}
	if outcome.attempts != 2 {
		t.Fatalf("attempts = %d, want 2", outcome.attempts)
	}
	// The server asked for a second, and the crawler must not have shortened
	// it: honouring the pause is the whole point.
	if outcome.waitedMS < 1000 {
		t.Fatalf("waitedMS = %d, want at least the 1000ms the server asked for", outcome.waitedMS)
	}
	if outcome.retryAfter != "1" {
		t.Fatalf("retryAfter = %q, want 1", outcome.retryAfter)
	}
}

func TestARateLimitedAnswerIsNotRetriedWhenTheAnalystAllowedNoRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client, err := newCrawlerClient(server.Client().Transport, crawlerRequestShape{})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, err := http.NewRequestWithContext(
		withCrawlerKind(context.Background(), "page"), http.MethodGet, server.URL+"/", nil,
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	outcome, err := crawlOnce(context.Background(), client, req, crawlerRequestShape{})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	_, _, _ = readAnalysisBody(outcome.resp.Body)
	outcome.resp.Body.Close()
	if outcome.retried != 0 {
		t.Fatalf("retried = %d, want 0 when retry_attempts is 0", outcome.retried)
	}
	if outcome.resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want the server's own 429", outcome.resp.StatusCode)
	}
}

func TestRetryAfterIsReadFromSecondsAndFromADate(t *testing.T) {
	if _, ok := retryDelayFor(http.Header{"Retry-After": {"7"}}, time.Now()); !ok {
		t.Fatal("a delay in seconds was not read")
	}
	if got, _ := retryDelayFor(http.Header{"Retry-After": {"7"}}, time.Now()); got != 7*time.Second {
		t.Fatalf("seconds delay = %v, want 7s", got)
	}
	when := time.Now().Add(4 * time.Second).UTC().Format(http.TimeFormat)
	got, ok := retryDelayFor(http.Header{"Retry-After": {when}}, time.Now())
	if !ok || got <= 0 {
		t.Fatalf("an HTTP date was not read: %v ok=%v", got, ok)
	}
	// A date in the past is an instruction that has already passed, not a
	// reason to wait.
	if got, ok := retryDelayFor(
		http.Header{"Retry-After": {time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)}},
		time.Now(),
	); !ok || got != 0 {
		t.Fatalf("past date = %v ok=%v, want 0 and true", got, ok)
	}
	// Nonsense is a server that did not answer, and a guessed delay for it
	// would be an invented limit.
	if _, ok := retryDelayFor(http.Header{"Retry-After": {"soon"}}, time.Now()); ok {
		t.Fatal("an unparsable Retry-After was treated as an instruction")
	}
	if _, ok := retryDelayFor(http.Header{}, time.Now()); ok {
		t.Fatal("a missing Retry-After was treated as an instruction")
	}
}

func TestChallengeDetectionNamesTheVendorAndTheMarker(t *testing.T) {
	header := http.Header{}
	header.Set("Server", "cloudflare")
	header.Set("cf-mitigated", "challenge")
	body := []byte(`<html><head><title>Just a moment...</title></head><body>
		<div class="cf-turnstile" data-sitekey="0x"></div></body></html>`)
	findings := detectChallenge(403, header, nil, body, false)
	if len(findings) == 0 {
		t.Fatal("a Cloudflare challenge was not detected")
	}
	vendors := map[string]bool{}
	for _, finding := range findings {
		if finding.Vendor != "cloudflare" {
			continue
		}
		vendors[finding.Kind] = true
		if finding.Evidence == "" {
			t.Fatalf("finding without evidence: %+v", finding)
		}
	}
	if !vendors["interstitial"] {
		t.Fatalf("the interstitial was not named: %+v", findings)
	}
	if !vendors["checkbox"] {
		t.Fatalf("the widget was not named: %+v", findings)
	}
}

// TestChallengeDetectionTellsAGateFromAWidget is the distinction the crawl needs
// and did not have. Every marker used to mean the same thing: a wall. Measured
// on a live site 2026-10-03, a homepage carrying `g-recaptcha` on a comment
// form was read as a wall, the walk stopped there, and Target reported neither
// endpoints, nor sinks, nor secrets for a site that has all three.
//
// A gate is an interstitial the edge serves instead of the page; a widget is
// what an ordinary site with that captcha embeds on its own pages. Both are
// reported — hiding one would trade a wrong claim for another — and only the
// gate carries Gate.
func TestChallengeDetectionTellsAGateFromAWidget(t *testing.T) {
	t.Run("a widget on a real page is context, not a wall", func(t *testing.T) {
		header := http.Header{}
		header.Set("Content-Type", "text/html")
		body := []byte(`<html><body><article>news</article>
<form action="/comment"><div class="g-recaptcha" data-sitekey="x"></div>
<div class="h-captcha" data-sitekey="y"></div></form>
<script src="https://www.google.com/recaptcha/api.js"></script>
<script src="https://js.hcaptcha.com/1/api.js"></script>
</body></html>`)
		findings := detectChallenge(200, header, nil, body, false)
		if len(findings) == 0 {
			t.Fatal("the captcha widget was not reported at all")
		}
		for _, finding := range findings {
			if finding.Gate {
				t.Fatalf("a widget was reported as a gate: %+v", finding)
			}
		}
		if challengeIsGate(findings) {
			t.Fatal("a page that merely embeds a captcha was treated as a gate")
		}
	})

	t.Run("an interstitial is a wall", func(t *testing.T) {
		header := http.Header{}
		body := []byte(`<html><head><title>Just a moment...</title></head>
<body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script></body></html>`)
		findings := detectChallenge(503, header, nil, body, false)
		if len(findings) == 0 {
			t.Fatal("the interstitial was not reported")
		}
		if !challengeIsGate(findings) {
			t.Fatalf("an interstitial was not treated as a gate: %+v", findings)
		}
	})

	t.Run("an edge decision is a wall", func(t *testing.T) {
		// The reason a widget cannot be a wall is that it lives in the body of a
		// page the site owns. A cookie the edge sets is written when it decided
		// to challenge, so it carries that decision and nothing else.
		cookies := []*http.Cookie{{Name: "datadome", Value: "protected"}}
		findings := detectChallenge(200, http.Header{}, cookies, []byte("<html><body>no widget here</body></html>"), false)
		if !challengeIsGate(findings) {
			t.Fatalf("an edge cookie was not treated as a gate: %+v", findings)
		}
	})

	t.Run("a plain page is not a wall", func(t *testing.T) {
		if challengeIsGate(detectChallenge(200, http.Header{}, nil, []byte("<html><body>ok</body></html>"), false)) {
			t.Fatal("a plain page was treated as a gate")
		}
	})
}

func TestChallengeDetectionIsSilentOnAPlainPage(t *testing.T) {
	// A negative here is what makes a positive mean something: a detector that
	// fired on ordinary HTML would name a vendor on every site.
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	body := []byte(`<html><head><title>Shop</title></head><body><h1>Catalogue</h1></body></html>`)
	if findings := detectChallenge(200, header, nil, body, false); len(findings) != 0 {
		t.Fatalf("a plain page produced findings: %+v", findings)
	}
}

func TestChallengeDetectionNeverNamesAVendorFromAStatusAlone(t *testing.T) {
	// A bare 403 says nothing about who refused. Attaching a vendor to it
	// would be exactly the guess this function exists to avoid.
	header := http.Header{}
	body := []byte(`<html><body><h1>Forbidden</h1></body></html>`)
	if findings := detectChallenge(403, header, nil, body, false); len(findings) != 0 {
		t.Fatalf("a 403 alone produced findings: %+v", findings)
	}
}

func TestChallengeDetectionReadsCookies(t *testing.T) {
	header := http.Header{}
	cookies := []*http.Cookie{{Name: "datadome", Value: "x"}}
	if findings := detectChallenge(200, header, cookies, nil, false); len(findings) == 0 {
		t.Fatal("a DataDome cookie was not detected")
	}
}

func TestChallengeDetectionSaysWhenTheBodyWasOnlyAPrefix(t *testing.T) {
	// A truncated body is a prefix of the document. Reading it as if it were
	// the whole thing is how a gate at the end of a large page is reported as
	// absent, so the fact travels with the finding.
	header := http.Header{}
	body := []byte("<html><body>...Just a moment...")
	findings := detectChallenge(503, header, nil, body, true)
	if len(findings) == 0 {
		t.Fatal("a marker in a truncated body was not detected")
	}
	if !strings.Contains(findings[0].Evidence, "truncated") {
		t.Fatalf("the truncation was not reported: %+v", findings[0])
	}
}

func TestUpgradeInsecureRequestsIsSentOnHTTPSOnly(t *testing.T) {
	secure, _ := url.Parse("https://target.example/")
	if got := navigatorHeaders(secure, "")["Upgrade-Insecure-Requests"]; got != "1" {
		t.Fatalf("https Upgrade-Insecure-Requests = %q, want 1", got)
	}
	plain, _ := url.Parse("http://target.example/")
	if _, ok := navigatorHeaders(plain, "")["Upgrade-Insecure-Requests"]; ok {
		t.Fatal("an http navigation sent Upgrade-Insecure-Requests")
	}
}
