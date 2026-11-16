package active

// Tests for the `robots.txt` wave of the well-known path probe.
//
// The capability is Nikto's `nikto_robots`, and the difference between the two
// tools is the point: Nikto prints the disallow list for the operator to read,
// we probe what it names, so a path the site tried to hide reaches every
// detector instead of only appearing on a screen.
//
// The fixture is a live server, not a parsed string, because the behaviour that
// matters is the second request actually happening — a parser that reads the
// file perfectly and never probes what it found would pass every test written
// against a string.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// robotsFixture answers `/robots.txt` with the given body, and records every path
// it was asked for.
type robotsFixture struct {
	url    string
	body   string
	mu     sync.Mutex
	asked  []string
	hidden map[string]string
}

func newRobotsFixture(t *testing.T, robots string, hidden map[string]string) *robotsFixture {
	t.Helper()
	fixture := &robotsFixture{body: robots, hidden: hidden}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.asked = append(fixture.asked, r.URL.Path)
		_, isHidden := fixture.hidden[r.URL.Path]
		fixture.mu.Unlock()

		if isHidden {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><body><form action="/hidden" method="get">`+
				`<input name="token" type="text"></form></body></html>`)
			return
		}
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, fixture.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	fixture.url = server.URL
	return fixture
}

func (f *robotsFixture) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string{}, f.asked...)
	sort.Strings(out)
	return out
}

func (f *robotsFixture) askedFor(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.asked {
		if got == path {
			return true
		}
	}
	return false
}

// runFixture probes the interesting paths against a fixture and returns what the
// run added to its surface.
func runFixture(t *testing.T, fixture *robotsFixture, interesting []string) []page {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	scan := NewScan(ScanRequest{
		URL:              fixture.url,
		InterestingPaths: interesting,
		RoundTripper:     http.DefaultTransport,
	}, nil)
	visited := map[string]bool{}
	probed, _ := scan.probeInterestingPaths(context.Background(), transport, fixture.url, visited)
	return probed
}

func TestThePathsRobotsNamesAreProbed(t *testing.T) {
	fixture := newRobotsFixture(t, "User-agent: *\nDisallow: /private/\nDisallow: /staging\n",
		map[string]string{"/private/": "login page", "/staging/": "staging index"})

	probed := runFixture(t, fixture, []string{"/robots.txt"})

	urls := make([]string, 0, len(probed))
	for _, p := range probed {
		urls = append(urls, p.URL)
	}
	sort.Strings(urls)
	want := []string{fixture.url + "/private/", fixture.url + "/robots.txt", fixture.url + "/staging/"}
	if strings.Join(urls, " ") != strings.Join(want, " ") {
		t.Fatalf("probed %v, want %v", urls, want)
	}

	// The point of the capability: the hidden page is not merely listed, it is
	// fetched, so its forms are harvested and every detector sees it.
	if !strings.Contains(strings.Join(urls, " "), "/private/") {
		t.Error("the path robots.txt named did not reach the surface")
	}
}

func TestAPathRobotsNamesWithoutATrailingSlashIsProbedAsADirectory(t *testing.T) {
	// `Disallow: /staging` is how a site writes "and everything under it".
	// Probing `/staging` alone would 404 on a site that serves `/staging/index`.
	fixture := newRobotsFixture(t, "Disallow: /staging\n", map[string]string{"/staging/": "staging"})

	probed := runFixture(t, fixture, []string{"/robots.txt"})
	found := false
	for _, p := range probed {
		if strings.HasSuffix(p.URL, "/staging/") {
			found = true
		}
	}
	if !found {
		t.Errorf("`Disallow: /staging` did not produce a probe of /staging/; asked for %v", fixture.paths())
	}
}

func TestARobotsPatternIsNotProbedAsAPath(t *testing.T) {
	// `*` and `$` make the line a pattern. Turning `Disallow: /*.php$` into a
	// request for a URL containing a literal asterisk would report a path that
	// does not exist, and the report would say the site named it.
	fixture := newRobotsFixture(t, "Disallow: /*.php$\nDisallow: /admin/*/config\n", nil)

	probed := runFixture(t, fixture, []string{"/robots.txt"})
	for _, p := range probed {
		if strings.Contains(p.URL, "*") || strings.Contains(p.URL, "$") {
			t.Errorf("probed a pattern as a path: %s", p.URL)
		}
	}
}

func TestAnEmptyDisallowIsNotTheSiteRoot(t *testing.T) {
	// `Disallow:` with no value means "allow everything". Read as `/` it would
	// point every run at the site root and call the start page a hidden find.
	fixture := newRobotsFixture(t, "User-agent: *\nDisallow:\n", map[string]string{"/": "home"})

	probed := runFixture(t, fixture, []string{"/robots.txt"})
	for _, p := range probed {
		if strings.HasSuffix(p.URL, "/") && !strings.HasSuffix(p.URL, "/robots.txt") {
			t.Errorf("an empty Disallow produced a probe of the site root: %s", p.URL)
		}
	}
}

func TestAllowLinesAreNotReadAsHiddenPaths(t *testing.T) {
	// `Allow:` narrows a prefix; it does not invite a probe.
	fixture := newRobotsFixture(t, "Disallow: /app/\nAllow: /app/public\n", nil)

	probed := runFixture(t, fixture, []string{"/robots.txt"})
	for _, p := range probed {
		if strings.Contains(p.URL, "/app/public") {
			t.Errorf("an Allow line produced a probe: %s", p.URL)
		}
	}
}

func TestAnAbsentRobotsFileChangesNothing(t *testing.T) {
	fixture := newRobotsFixture(t, "", nil)
	probed := runFixture(t, fixture, []string{"/private/"})
	if len(probed) != 0 {
		t.Errorf("a 404 on robots.txt still produced %d page(s): %v", len(probed), probed)
	}
}

func TestRobotsCommentsAndMalformedLinesAreIgnored(t *testing.T) {
	fixture := newRobotsFixture(t, "# a comment\n\nDisallow: /x\nnot a directive\n:::\nDisallow: y\n",
		map[string]string{"/x": "found"})

	probed := runFixture(t, fixture, []string{"/robots.txt"})
	for _, p := range probed {
		if strings.Contains(p.URL, "not-a-directive") || strings.Contains(p.URL, "y") && !strings.HasSuffix(p.URL, "/robots.txt") {
			t.Errorf("a malformed robots line produced a probe: %s", p.URL)
		}
	}
	// And the valid one still worked, so the test above is not passing because
	// nothing was parsed at all.
	found := false
	for _, p := range probed {
		if strings.HasSuffix(p.URL, "/x") {
			found = true
		}
	}
	if !found {
		t.Errorf("the valid Disallow in a file with malformed lines was dropped; asked for %v", fixture.paths())
	}
}

func TestAProbedPathIsNotProbedTwice(t *testing.T) {
	fixture := newRobotsFixture(t, "Disallow: /private/\n", map[string]string{"/private/": "page"})

	runFixture(t, fixture, []string{"/robots.txt", "/private/"})

	count := 0
	for _, path := range fixture.paths() {
		if path == "/private/" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("/private/ was requested %d time(s), want 1: %v", count, fixture.paths())
	}
}

// TestTheRunReportsWhatRobotsContributed is the number the operator reads: a
// hidden path that reached the surface is visible in the report, not only in the
// requests.
func TestTheRunReportsWhatRobotsContributed(t *testing.T) {
	fixture := newRobotsFixture(t, fmt.Sprintf("Disallow: /private/\n"),
		map[string]string{"/private/": "page"})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.asked = append(fixture.asked, r.URL.Path)
		body, isHidden := fixture.hidden[r.URL.Path]
		fixture.mu.Unlock()
		if isHidden {
			_, _ = io.WriteString(w, body)
			return
		}
		if r.URL.Path == "/robots.txt" {
			_, _ = io.WriteString(w, fixture.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	scan := NewScan(ScanRequest{
		URL:              server.URL,
		MaxPages:         1,
		MaxDepth:         0,
		InterestingPaths: []string{"/robots.txt"},
		RoundTripper:     http.DefaultTransport,
	}, nil)
	report, err := scan.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	found := false
	for _, url := range report.Visited {
		if strings.HasSuffix(url, "/private/") {
			found = true
		}
	}
	if !found {
		t.Errorf("the run's visited list does not contain the path robots.txt named: %v", report.Visited)
	}
}
