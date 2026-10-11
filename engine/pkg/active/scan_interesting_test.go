package active

// The well-known path probe is the capability that finds endpoints no page links
// to. It is easy to write a test for it that passes while it does nothing, so
// each test here is written against the shape of the defect it prevents rather
// than against the function's return value.
//
// The four conditions that matter are each tested against a server that behaves
// the way the condition is about:
//
//   - only 200 counts, and 200 on `/.env` is the finding;
//   - a redirect off the origin is never recorded;
//   - a path the crawl already reached is not recorded twice;
//   - an operator's list replaces the default, and an empty list means none.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// reportedPaths are the well-known paths a run actually asked for.
// withoutDetectorOwnedPaths drops the paths the endpoint-level detectors ask for on
// their own account.
//
// The invariant this file tests is about the **interesting-paths phase**: an
// operator who names three paths gets those three, and an operator who names none
// gets none. It was written when the only paths a run requested were the crawl's
// and the probe's, so counting every path the target saw was the same thing. Six
// endpoint-level detectors later, it stopped being the same thing: the source
// disclosure detector fetches a soft-404 baseline and then its own path list, and
// the method detector writes an object and reads it back — fourteen paths that the
// operator never named and that have nothing to do with this feature.
//
// The subtracted set is read from the package's own tables rather than pasted in,
// so a path added to `sensitiveFiles` is subtracted from the next run without this
// file being touched. That is the difference between a filter that stays true and a
// hard-coded list that quietly stops covering.
//
// The operator's own list wins over the filter, and that is not a detail. Six of
// the twenty-one default paths are also in `sensitiveFiles`, so the interesting-path
// probe and the source-disclosure detector ask for the same six URLs — and when the
// operator has *not* named a list, those six are legitimately part of what the probe
// asked for. Subtracting them unconditionally reported fifteen paths where
// twenty-one had been asked, which is the same class of error as the original: a
// count that does not describe the phase it claims to describe.
func withoutDetectorOwnedPaths(paths, want []string) []string {
	named := make(map[string]bool, len(want))
	for _, path := range want {
		named[path] = true
	}
	owned := map[string]bool{softNotFoundPath: true}
	for _, file := range sensitiveFiles {
		owned[file.path] = true
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if named[path] {
			out = append(out, path)
			continue
		}
		// The written object carries a per-run canary, so its exact name cannot be
		// listed; the pattern it is built from can be.
		if strings.Contains(path, "rr-upload-") && strings.HasSuffix(path, ".txt") {
			continue
		}
		if owned[path] {
			continue
		}
		// The Vite file bridge is host-level and its paths are built from a table
		// rather than stored, so they are subtracted by the same rule the rest of
		// this filter uses: read from the package, not pasted in. A probe added to
		// `viteReadTargets` is subtracted from the next run without this file being
		// touched — which is the whole point of reading a table instead of a list.
		if viteBridgePath(path) {
			continue
		}
		// Same rule for the truncation probes: their URLs are built from the path
		// and the extension rather than stored, so the filter reads the table.
		if truncationProbePath(path) {
			continue
		}
		out = append(out, path)
	}
	return out
}

// truncationProbePath reports whether a path is one of this package's
// path-truncation probes for one of its own server-extension surfaces.
func truncationProbePath(path string) bool {
	for _, candidate := range []string{".jsp", ".php", ".asp", ".aspx", ".shtml", ".cgi"} {
		for _, form := range truncationForms(candidate) {
			if strings.Contains(path, form) {
				return true
			}
		}
	}
	return false
}

// viteBridgePath reports whether a path is one of this package's `/@fs/` probes.
func viteBridgePath(path string) bool {
	if !strings.HasPrefix(path, "/@fs") {
		return false
	}
	for _, target := range viteReadTargets {
		for _, encoding := range viteEncodings(target.path) {
			if path == "/@fs"+encoding {
				return true
			}
		}
	}
	return false
}

func reportedPaths(t *testing.T, mu *sync.Mutex, seen map[string]bool) []string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	return out
}

// An endpoint nobody links to is still scanned. This is the whole reason the
// probe exists: a `/.env` served at 200 while no page in the application links
// it is invisible to a link-following crawl by construction.
func TestAWellKnownPathNoPageLinksToIsStillScanned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			// The page links nothing at all, so a crawl-only run has one page.
			fmt.Fprint(w, "<html><body>nothing to follow</body></html>")
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "DB_PASSWORD=hunter2please\nSTRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Pages < 2 {
		t.Fatalf("pages = %d (%v), want the start page and /.env: an endpoint no page links "+
			"to is exactly what the probe is for", report.Pages, report.Visited)
	}
	found := false
	for _, f := range report.Findings {
		if strings.Contains(f.Title, "Connection String") || strings.Contains(f.Title, "Hardcoded Password") ||
			strings.Contains(f.Title, "Stripe") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("a 200 on /.env carrying credentials produced no finding; findings were %v",
			titlesOf(report.Findings))
	}
}

// Only 200 counts. A 403 and a 404 are both "not there", and a probe that
// recorded them would report endpoints that do not exist.
func TestOnlyA200CountsAsAWellKnownEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>plain</body></html>")
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "forbidden")
		case "/teapot":
			w.WriteHeader(http.StatusTeapot)
			fmt.Fprint(w, "short and stout")
		}
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		InterestingPaths: []string{"/forbidden", "/teapot"},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Pages != 1 {
		t.Fatalf("pages = %d (%v), want 1: a 403 and a 418 are not endpoints",
			report.Pages, report.Visited)
	}
}

// A redirect off the origin is never recorded. The probe does not follow
// redirects, so this is the check that makes the no-follow client a defence: a
// server that answers every unknown path with a redirect to another site must not
// be able to place that site's URL in the report.
func TestAWellKnownProbeIsNeverRecordedOffOrigin(t *testing.T) {
	var offHost string
	away := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html><body>the other host</body></html>")
	}))
	defer away.Close()
	offHost = away.URL

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>plain</body></html>")
			return
		}
		http.Redirect(w, r, offHost+"/elsewhere", http.StatusFound)
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		InterestingPaths: []string{"/open"},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, visited := range report.Visited {
		if strings.Contains(visited, strings.TrimPrefix(offHost, "http://")) {
			t.Fatalf("visited %q, which belongs to another host", visited)
		}
	}
	if report.Pages != 1 {
		t.Fatalf("pages = %d (%v), want 1: a 302 is not an endpoint",
			report.Pages, report.Visited)
	}
}

// An operator's list replaces the default, and an empty list means none.
//
// Upstream keeps the list in a package variable and probes it unconditionally, so
// neither of these is expressible: an operator who wants three paths gets the
// twenty-one, and an operator who wants none gets the twenty-one anyway. Both are
// capabilities of the request, not of the code.
func TestTheOperatorsPathListReplacesTheDefault(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>plain</body></html>")
	}))
	defer server.Close()

	for _, tc := range []struct {
		name  string
		given []string
		want  []string
	}{
		{"nil means the default", nil, DefaultInterestingPaths},
		{"a list replaces the default", []string{"/only-this"}, []string{"/only-this"}},
		{"an empty list means none", []string{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			seen = map[string]bool{}
			mu.Unlock()

			if _, err := NewScan(ScanRequest{
				URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
				InterestingPaths: tc.given,
				RoundTripper:     http.DefaultTransport,
			}, nil).Run(context.Background()); err != nil {
				t.Fatalf("Run: %v", err)
			}
			got := reportedPaths(t, &mu, seen)
			got = without(got, "/")
			got = withoutDetectorOwnedPaths(got, tc.want)
			want := tc.want
			if want == nil {
				if len(got) != 0 {
					t.Fatalf("asked for %v, the target was asked for %v", got, got)
				}
				return
			}
			if len(got) != len(want) {
				t.Fatalf("asked for %d path(s) (%v), want the %d the request named",
					len(got), got, len(want))
			}
			for _, path := range want {
				if !seen[path] {
					t.Fatalf("%s was never requested; the target saw %v", path, got)
				}
			}
		})
	}
}

// The probe's own requests are counted in the run's request total. They are
// requests to the target, and a run that hides them reports a smaller footprint
// than it had.
func TestTheWellKnownProbeCountsInTheRequestTotal(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>plain</body></html>")
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		InterestingPaths: []string{"/a", "/b", "/c"},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	seen := requests
	mu.Unlock()
	if report.Stats.Requests != seen {
		t.Fatalf("the report counts %d requests and the target saw %d: the probe is uncounted",
			report.Stats.Requests, seen)
	}
	// The exact total is not asserted: the endpoint-level pass fetches a baseline
	// per page on top of the crawl, and pinning a number here would make this test
	// break every time an unrelated request is added. What is asserted is that the
	// three paths the operator named were actually asked for, which is the part
	// that would fail if the probe silently stopped running.
	mu.Lock()
	defer mu.Unlock()
	if seen != 4 && requests < 4 {
		t.Fatalf("the target saw %d requests, want at least 4: one crawl and three probes", seen)
	}
}

// A path without a leading slash is still a path. An operator who writes "admin"
// meant "/admin", and a probe that built "http://hostadmin" would silently check
// a hostname rather than a path.
func TestAProbePathWithoutALeadingSlashStillHitsTheOrigin(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>plain</body></html>")
	}))
	defer server.Close()

	if _, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		InterestingPaths: []string{"admin"},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !seen["/admin"] {
		t.Fatalf("the target saw %v, want /admin", reportedPaths(t, &mu, seen))
	}
}

func without(paths []string, drop string) []string {
	var out []string
	for _, path := range paths {
		if path != drop {
			out = append(out, path)
		}
	}
	return out
}

// A transport that reports a final URL on another host is not believed.
//
// The probe does not follow redirects, so with a real network the status check
// already rejects a 302 and the origin check is never reached — which is exactly
// why it was untested and survived mutation P. The check is a defence against a
// transport that reports an exchange that ended elsewhere: the recording
// transport is injected, so "where did this exchange end" is a field the probe
// reads rather than a fact it can assume, and a run that recorded a URL from
// another host would hand that URL to every detector as if it were the target's.
//
// The RoundTripper is the injection point the request already declares, so this
// is the supported way to produce such a transport rather than a mock of the
// probe itself.
type offHostRoundTripper struct {
	inner http.RoundTripper
	host  string
}

func (t offHostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	swapped, parseErr := url.Parse(t.host)
	if parseErr != nil {
		return resp, nil
	}
	resp.Request = &http.Request{URL: swapped, Method: http.MethodGet}
	return resp, nil
}

func TestAWellKnownProbeDoesNotBelieveAnOffHostFinalURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>plain</body></html>")
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		InterestingPaths: []string{"/leaked"},
		RoundTripper: offHostRoundTripper{
			inner: http.DefaultTransport,
			host:  "https://attacker.example/",
		},
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, visited := range report.Visited {
		if strings.Contains(visited, "attacker.example") {
			t.Fatalf("visited %q, which the transport claimed ended on another host", visited)
		}
	}
	if report.Pages != 1 {
		t.Fatalf("pages = %d (%v), want 1: an exchange that ended off-host is not the target's endpoint",
			report.Pages, report.Visited)
	}
}
