package active

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestActiveScanExtractMapForms(t *testing.T) {
	pageHTML := `<html><body>
<form action="/search" method="get">
  <input type="text" name="q" />
  <input type="hidden" name="token" value="abc123csrf" />
  <select name="category"><option value="news">News</option><option value="blog" selected>Blog</option></select>
  <input type="submit" name="btn" value="Search" />
</form>
<form action="/post_comment" method="post">
  <input type="text" name="author" />
  <textarea name="comment"></textarea>
  <input type="checkbox" name="subscribe" value="yes" />
  <input type="submit" value="Send" />
</form>
</body></html>`

	base, _ := url.Parse("http://test.local/index.html")
	forms := extractMapForms([]byte(pageHTML), "text/html", base)
	if len(forms) != 2 {
		t.Fatalf("extractMapForms returned %d forms, want 2", len(forms))
	}

	// 1. GET form
	getForm := forms[0]
	if getForm.Method != http.MethodGet {
		t.Errorf("expected GET method, got %s", getForm.Method)
	}
	parsedGET, err := url.Parse(getForm.URL)
	if err != nil {
		t.Fatalf("failed to parse GET form url: %v", err)
	}
	qVals := parsedGET.Query()
	if qVals.Get("q") != crawlFormMarker {
		t.Errorf("expected q=%s, got %s", crawlFormMarker, qVals.Get("q"))
	}
	if qVals.Get("token") != "abc123csrf" {
		t.Errorf("expected token=abc123csrf, got %s", qVals.Get("token"))
	}
	if qVals.Get("category") != "blog" {
		t.Errorf("expected category=blog, got %s", qVals.Get("category"))
	}

	// 2. POST form
	postForm := forms[1]
	if postForm.Method != http.MethodPost {
		t.Errorf("expected POST method, got %s", postForm.Method)
	}
	if !strings.HasSuffix(postForm.URL, "/post_comment") {
		t.Errorf("expected url ending with /post_comment, got %s", postForm.URL)
	}
	postVals, err := url.ParseQuery(postForm.Body)
	if err != nil {
		t.Fatalf("failed to parse POST body: %v", err)
	}
	if postVals.Get("author") != crawlFormMarker {
		t.Errorf("expected author=%s, got %s", crawlFormMarker, postVals.Get("author"))
	}
	if postVals.Get("comment") != crawlFormMarker {
		t.Errorf("expected comment=%s, got %s", crawlFormMarker, postVals.Get("comment"))
	}
	if postVals.Get("subscribe") != "yes" {
		t.Errorf("expected subscribe=yes, got %s", postVals.Get("subscribe"))
	}
}

func TestActiveScanCrawlSubmitsFormsAndHonorsCookies(t *testing.T) {
	var mu sync.Mutex
	var requestsReceived []string
	var tokenCounter int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		requestsReceived = append(requestsReceived, fmt.Sprintf("%s %s cookie=%s body=%s", r.Method, r.URL.RequestURI(), cookie, string(b)))
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tok := atomic.AddInt64(&tokenCounter, 1)

		switch r.URL.Path {
		case "/":
			if !strings.Contains(cookie, "session=secret123") {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			fmt.Fprintf(w, `<html><body>
<h1>Admin Area</h1>
<a href="/vuln1">Vuln 1</a>
<form action="/search" method="get">
  <input name="query" />
  <input type="hidden" name="user_token" value="%d" />
  <input type="submit" value="Search" />
</form>
<form action="/action" method="post">
  <input name="data" />
  <input type="hidden" name="user_token" value="%d" />
  <input type="submit" value="Go" />
</form>
</body></html>`, tok, tok)
		case "/login":
			fmt.Fprint(w, `<html><body>Login Page</body></html>`)
		case "/vuln1":
			fmt.Fprint(w, `<html><body>Vuln 1 Page</body></html>`)
		case "/search":
			fmt.Fprint(w, `<html><body>Search Result</body></html>`)
		case "/action":
			fmt.Fprint(w, `<html><body>Action Result</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	scanReq := ScanRequest{
		URL:          ts.URL + "/",
		MaxPages:     20,
		MaxDepth:     3,
		Cookies:      "session=secret123",
		RoundTripper: http.DefaultTransport,
	}

	transport, err := NewTransport(scanReq.RoundTripper, Options{
		Cookies: scanReq.Cookies,
	})
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	scan := NewScan(scanReq, nil)
	startURL, _ := url.Parse(scanReq.URL)
	pages, warnings, reqCount, crawlErr := scan.crawl(context.Background(), transport, startURL)

	if crawlErr != nil {
		t.Fatalf("crawl returned error: %v, warnings: %v", crawlErr, warnings)
	}
	if reqCount < 4 {
		t.Errorf("expected at least 4 requests (/, /vuln1, GET /search, POST /action), got %d", reqCount)
	}

	var foundVuln1, foundSearch, foundAction bool
	for _, p := range pages {
		if strings.Contains(p.URL, "/vuln1") {
			foundVuln1 = true
		}
		if strings.Contains(p.URL, "/search?") && strings.Contains(p.URL, "query="+crawlFormMarker) {
			foundSearch = true
		}
		if strings.Contains(p.URL, "/action") && p.Method == http.MethodPost {
			foundAction = true
		}
	}

	if !foundVuln1 {
		t.Errorf("crawl did not reach /vuln1: pages=%v", pages)
	}
	if !foundSearch {
		t.Errorf("crawl did not submit GET search form: pages=%v", pages)
	}
	if !foundAction {
		t.Errorf("crawl did not submit POST action form: pages=%v", pages)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, reqLog := range requestsReceived {
		if !strings.Contains(reqLog, "session=secret123") {
			t.Errorf("request was sent without authentication cookie: %s", reqLog)
		}
	}
}
