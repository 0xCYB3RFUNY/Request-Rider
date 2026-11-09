package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A difference that does not reproduce is not a result set.
//
// This file exists because of a live run against a real news site. The NoSQL, LDAP
// and XPath detectors reported rows on endpoints that answer 165 bytes to every
// request — measured by firing the same payload eight times and getting one
// distinct body — so every one of those rows was the target's own variance under a
// burst of probes, not an evaluation. A differential detector that fires payload A
// once and payload B once cannot tell the two apart: a rate limiter, a captcha
// interstitial or a rotating banner all produce a pair that differs for reasons
// that have nothing to do with the payload.
//
// The fixture below is that target made deterministic: it answers the *same* way
// every time, except on one request in four, when it renders a banner. A detector
// that fires once per arm will find the difference roughly half the time and report
// an injection on a server running no database at all.
func TestAWobblingTargetIsNotAnInjection(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		n := served.Add(1)
		w.Header().Set("Content-Type", "text/html")
		if n%4 == 0 {
			// The wobble: a rotating banner, present on a quarter of the answers.
			_, _ = w.Write([]byte(`<html><body><div class="promo">today's offer</div>` +
				`<a href="/news?id=` + url.QueryEscape(value) + `">next</a>` +
				`<p>news</p></body></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><body>` +
			`<a href="/news?id=` + url.QueryEscape(value) + `">next</a>` +
			// A form, because the crawl harvests a parameter to probe from a form or
			// a link and there is nothing to probe without one.
			`<form action="/news" method="get"><input name="id" type="text"></form>` +
			`<p>news</p></body></html>`))
	}))
	defer server.Close()

	start, _ := url.Parse(server.URL)
	start.Path = "/news"

	report, err := NewScan(ScanRequest{
		URL: start.String(), MaxPages: 2, MaxDepth: 1, Concurrency: 1,
		Timeout: 20 * time.Second, RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, f := range report.Findings {
		switch f.Module {
		case "nosql", "ldap", "xpath":
			t.Errorf("false positive on a target that only wobbles: %s tier=%s %s",
				f.Module, f.Tier, f.Title)
		}
	}
	t.Logf("requests served=%d findings=%d", served.Load(), len(report.Findings))
}

// TestConfirmationKeepsARealResultSet is the other half: the confirmation must not
// swallow a genuine evaluation. A server that really answers differently for the
// two arms still has to be reported, or the fix is just a quieter bug.
func TestConfirmationKeepsARealResultSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		switch {
		case strings.Contains(value, "return true"), strings.Contains(value, "||this'"):
			// The genuine result set, and it never wobbles.
			_, _ = w.Write([]byte(`<html><body><ul><li>alpha</li><li>bravo</li>` +
				`<li>charlie</li><li>delta</li></ul>` +
				`<form action="/news" method="get"><input name="id" type="text"></form>` +
				`</body></html>`))
		case strings.Contains(value, "return false"), strings.Contains(value, "||!this'"):
			_, _ = w.Write([]byte(`<html><body><p>No documents matched.</p></body></html>`))
		default:
			// The form is what the crawl turns into a point to probe; a page without
			// one yields no parameter and the differential detectors never run.
			_, _ = w.Write([]byte(`<html><body>` +
				`<form action="/news" method="get"><input name="id" type="text"></form>` +
				`<p>news</p></body></html>`))
		}
	}))
	defer server.Close()

	start, _ := url.Parse(server.URL)
	start.Path = "/news"

	report, err := NewScan(ScanRequest{
		URL: start.String(), MaxPages: 2, MaxDepth: 1, Concurrency: 1,
		Timeout: 20 * time.Second, RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	mods := map[string]int{}
	for _, f := range report.Findings {
		mods[f.Module]++
	}
	found := false
	for _, f := range report.Findings {
		if f.Module == "nosql" {
			found = true
			t.Logf("kept: %s tier=%s %s", f.Module, f.Tier, f.Title)
		}
	}
	if !found {
		t.Errorf("a target that really answers differently for the two arms produced no nosql row: "+
			"the confirmation pass swallowed a genuine result set (%d findings overall)", len(report.Findings))
	}
}
