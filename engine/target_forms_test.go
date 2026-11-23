package main

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

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestExtractMapFormsGETUsesMarkersAndFormValues(t *testing.T) {
	page := `<html><body><form action="/sqli/" method="GET">
<input type="text" name="id"><input type="hidden" name="token" value="abc">
<select name="kind"><option value="a">A</option><option value="b" selected>B</option></select>
<input type="checkbox" name="remember" value="yes">
<input type="file" name="upload">
<input type="submit" name="Submit" value="Go"></form></body></html>`
	forms := extractMapForms([]byte(page), "text/html", mustURL(t, "http://t.test/start"))
	if len(forms) != 1 {
		t.Fatalf("forms = %#v, want 1", forms)
	}
	got := forms[0]
	if got.Method != http.MethodGet || got.Body != "" {
		t.Fatalf("form = %#v, want GET without body", got)
	}
	parsed := mustURL(t, got.URL)
	if parsed.Path != "/sqli/" {
		t.Fatalf("path = %q", parsed.Path)
	}
	want := map[string]string{"id": crawlFormMarker, "token": "abc", "kind": "b", "remember": "yes", "Submit": "Go"}
	for key, value := range want {
		if parsed.Query().Get(key) != value {
			t.Errorf("query %s = %q, want %q (url %s)", key, parsed.Query().Get(key), value, got.URL)
		}
	}
	if parsed.Query().Has("upload") {
		t.Errorf("file input must not be submitted: %s", got.URL)
	}
}

func TestExtractMapFormsPOSTBodyAndDefaults(t *testing.T) {
	page := `<form method="post"><input name="user"><input type="password" name="pw">
<textarea name="note"></textarea><input type="submit" name="Login"></form>`
	forms := extractMapForms([]byte(page), "text/html; charset=utf-8", mustURL(t, "http://t.test/login.php"))
	if len(forms) != 1 || forms[0].Method != http.MethodPost {
		t.Fatalf("forms = %#v", forms)
	}
	if forms[0].URL != "http://t.test/login.php" {
		t.Errorf("an empty action must resolve to the page itself, got %q", forms[0].URL)
	}
	values, err := url.ParseQuery(forms[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"user", "pw", "note"} {
		if values.Get(name) != crawlFormMarker {
			t.Errorf("%s = %q, want marker", name, values.Get(name))
		}
	}
	if values.Get("Login") != "Submit" {
		t.Errorf("submit default = %q", values.Get("Login"))
	}
}

func TestExtractMapFormsKeyIgnoresValues(t *testing.T) {
	first := extractMapForms([]byte(`<form action="/a"><input type="hidden" name="t" value="1"></form>`), "text/html", mustURL(t, "http://t.test/"))
	second := extractMapForms([]byte(`<form action="/a"><input type="hidden" name="t" value="2"></form>`), "text/html", mustURL(t, "http://t.test/"))
	if len(first) != 1 || len(second) != 1 || first[0].Key != second[0].Key {
		t.Fatalf("a rotating token must not change the form shape: %#v %#v", first, second)
	}
}

func TestExtractMapFormsIgnoresNonHTMLAndBadAction(t *testing.T) {
	if forms := extractMapForms([]byte(`<form></form>`), "application/json", mustURL(t, "http://t.test/")); forms != nil {
		t.Errorf("non-HTML produced forms: %#v", forms)
	}
	if forms := extractMapForms([]byte(`<form action="javascript:void(0)"></form>`), "text/html", mustURL(t, "http://t.test/")); len(forms) != 0 {
		t.Errorf("javascript: action produced forms: %#v", forms)
	}
}

func TestTargetMapSubmitsFormsAndTerminatesWithRotatingToken(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var tokens int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s %s %s", r.Method, r.URL.RequestURI(), string(body)))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		// Every answer carries a form with a brand new token, like DVWA.
		token := atomic.AddInt64(&tokens, 1)
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><body><form action="/search" method="get"><input name="q"><input type="hidden" name="user_token" value="%d"><input type="submit" name="Submit" value="Search"></form>`+
				`<form action="/post" method="post"><input name="msg"><input type="hidden" name="user_token" value="%d"></form></body></html>`, token, token)
		default:
			fmt.Fprintf(w, `<html><body>ok<form action="/search" method="get"><input name="q"><input type="hidden" name="user_token" value="%d"><input type="submit" name="Submit" value="Search"></form></body></html>`, token)
		}
	}))
	defer target.Close()

	job := &targetMap{status: "running", startURL: target.URL}
	s := &server{}
	s.runTargetMap(7, job, context.Background(), targetMapInput{URL: target.URL, MaxDepth: -1, SameOrigin: true})

	mu.Lock()
	defer mu.Unlock()
	var gotSearch, gotPost bool
	searchCount, postCount := 0, 0
	for _, line := range seen {
		if strings.HasPrefix(line, "GET /search?") && strings.Contains(line, "q="+crawlFormMarker) && strings.Contains(line, "Submit=Search") {
			gotSearch = true
			searchCount++
		}
		if strings.HasPrefix(line, "POST /post ") {
			postCount++
			if strings.Contains(line, "msg="+crawlFormMarker) {
				gotPost = true
			}
		}
	}
	if !gotSearch || !gotPost {
		t.Fatalf("form requests missing (search=%v post=%v): %#v", gotSearch, gotPost, seen)
	}
	if searchCount != 1 || postCount != 1 {
		t.Fatalf("each form shape must be sent once, got search=%d post=%d: %#v", searchCount, postCount, seen)
	}
	job.mu.RLock()
	defer job.mu.RUnlock()
	sawMethod := false
	for _, page := range job.pages {
		if page["method"] == http.MethodPost {
			sawMethod = true
		}
	}
	if !sawMethod {
		t.Errorf("a submitted POST form must be recorded with its method: %#v", job.pages)
	}
}

func TestTargetMapDoesNotSubmitFormsOffOrigin(t *testing.T) {
	var offOriginHits int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&offOriginHits, 1)
	}))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<form action="%s/x" method="post"><input name="a"></form>`, other.URL)
	}))
	defer target.Close()

	job := &targetMap{status: "running", startURL: target.URL}
	s := &server{}
	s.runTargetMap(8, job, context.Background(), targetMapInput{URL: target.URL, MaxDepth: 3, SameOrigin: true})
	if atomic.LoadInt64(&offOriginHits) != 0 {
		t.Fatalf("a same-origin crawl submitted a form to another origin")
	}
}
