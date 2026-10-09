package active

// Tests for the three detectors that fire requests the crawl did not ask for:
// the hidden-parameter wordlist, the path-truncation bypass and the Vite file
// bridge, plus the operator's path dictionary.
//
// Every test runs against a live `httptest` server rather than a stub of the
// transport, because the whole question each of these detectors asks is about
// what a real HTTP server answers — a mocked transport would agree with whatever
// the detector does, including the wrong thing.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recordingServer is a target that answers from a handler and records the paths
// it was asked for, so a test can assert what was *not* fired as well as what was.
type recordingServer struct {
	*httptest.Server
	asked []string
}

// newRecordingServer starts a server whose handler decides the answer.
func newRecordingServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *recordingServer {
	t.Helper()
	rec := &recordingServer{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.asked = append(rec.asked, r.URL.RequestURI())
		handler(w, r)
	}))
	t.Cleanup(rec.Close)
	return rec
}

// transportFor builds a transport pointed at a server, using the package's own
// defaults so a test measures the same request the run would make.
//
// The redirect policy is the server's own client with redirects refused, because
// the truncation detector's whole signal is a baseline that redirects and a probe
// that does not: a test transport that followed them would compare two copies of
// the login page.
func transportFor(t *testing.T, server *httptest.Server) *Transport {
	t.Helper()
	roundTripper := &redirectRefusingTransport{next: server.Client().Transport}
	if roundTripper.next == nil {
		roundTripper.next = http.DefaultTransport
	}
	transport, err := NewTransport(roundTripper, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return transport
}

// redirectRefusingTransport refuses every redirect, the way `Transport.Do` does
// when a probe asks it not to follow.
type redirectRefusingTransport struct{ next http.RoundTripper }

func (t *redirectRefusingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.next.RoundTrip(r)
}

// # Hidden parameters

// TestAWordlistedParameterTheServerReadsIsReported is the technique: a name from
// the application's own JavaScript, fired at a page, and the server reacting to
// its presence.
//
// The fixture reacts the way a server reads an unknown parameter: it renders the
// same document for every value and a different document when the parameter is
// present. That is the signature the two-value design reads, and a single-value
// echo check would miss it entirely.
func TestAWordlistedParameterTheServerReadsIsReported(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("report_token") != "" {
			w.Write([]byte(`<html><body>hidden branch: ok</body></html>`))
			return
		}
		w.Write([]byte(`<html><body>public page</body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/search", Method: http.MethodGet}

	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := HiddenParams{Params: []string{"report_token", "ab", "a b"}}.Scan(
		context.Background(), transport, point, baseline)
	if len(findings) != 1 {
		t.Fatalf("want exactly one finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.Param != "report_token" {
		t.Errorf("the finding is about %q, not the parameter that answered", finding.Param)
	}
	if finding.ClaimedTooHigh() {
		t.Errorf("a hidden parameter is potential at most: %+v", finding)
	}
	if finding.Tier != TierPotential {
		t.Errorf("tier %q: %+v", finding.Tier, finding)
	}
	// The wordlist entries that are not names are not fired: two requests per
	// candidate, one candidate.
	if len(server.asked) != 3 {
		t.Errorf("want baseline + 2 probes, the server saw %v", server.asked)
	}
}

// TestAParameterTheServerIgnoresIsNotReported is the control, and it is what
// makes the detector usable: five thousand dictionary entries on a server that
// ignores every unknown parameter must produce no rows at all.
func TestAParameterTheServerIgnoresIsNotReported(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>public page</body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/search", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := HiddenParams{Params: []string{"alpha", "beta", "gamma"}}.Scan(
		context.Background(), transport, point, baseline)
	if len(findings) != 0 {
		t.Errorf("a parameter the server ignores produced rows: %+v", findings)
	}
}

// TestAPageThatChangesOnItsOwnIsNotAParameterDiscovery is the false positive that
// decides whether a wordlist scan is usable at all: a banner that rotates between
// two answers changes the page without any parameter being read.
func TestAPageThatChangesOnItsOwnIsNotAParameterDiscovery(t *testing.T) {
	counter := 0
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Two values, two different documents, neither of them mentioning the
		// parameter: exactly what a rotating banner looks like to a differ.
		counter++
		if counter%2 == 0 {
			w.Write([]byte(`<html><body>banner A</body></html>`))
			return
		}
		w.Write([]byte(`<html><body>banner B</body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	baseline := &Response{StatusCode: 200, Body: `<html><body>banner B</body></html>`}

	findings := HiddenParams{Params: []string{"tracker"}}.Scan(
		context.Background(), transport, point, baseline)
	if len(findings) != 0 {
		t.Errorf("a page that rotates on its own produced a discovery: %+v", findings)
	}
}

// TestAReflectedUndeclaredParameterIsItsOwnRow is the second arm of the
// two-value decision: a value that reaches the response is reported as reflected,
// and it is a different title from the consumed case, because a reader acts on
// the two differently.
func TestAReflectedUndeclaredParameterIsItsOwnRow(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if value := r.URL.Query().Get("utm_source"); value != "" {
			w.Write([]byte(`<html><body>you came from ` + value + `</body></html>`))
			return
		}
		w.Write([]byte(`<html><body>public page</body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := HiddenParams{Params: []string{"utm_source"}}.Scan(
		context.Background(), transport, point, baseline)
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "reflected") {
		t.Errorf("a reflected parameter is not titled as one: %q", findings[0].Title)
	}
}

// TestAnEmptyWordlistSpendsNothing is the contract the field documents: nil means
// the module is not asked to run, and a run must not pay a baseline request for a
// wordlist it does not have.
func TestAnEmptyWordlistSpendsNothing(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	if findings := (HiddenParams{}).Scan(context.Background(), transport, point, nil); len(findings) != 0 {
		t.Errorf("an empty wordlist produced rows: %+v", findings)
	}
	if len(server.asked) != 0 {
		t.Errorf("an empty wordlist sent requests: %v", server.asked)
	}
}

// # Path truncation

// TestTheTruncationFormReachesAGatedPage is the reported pair, exactly:
// `memory_info.jsp` answers 301 to the login page, `memory_info.jsp;.jsp` answers
// 200 with the page.
func TestTheTruncationFormReachesAGatedPage(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ";") {
			w.Write([]byte(`<html><body><h1>Memory</h1><p>JVM heap usage</p></body></html>`))
			return
		}
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/server-admin/memory_info.jsp", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := AuthBypassExt{}.Scan(context.Background(), transport, point, baseline)
	if len(findings) != 1 {
		t.Fatalf("want one bypass, got %d: %+v", len(findings), findings)
	}
	if findings[0].Tier != TierVerified {
		t.Errorf("a 301 baseline and a 200 probe is the verified case: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Title, "truncation") {
		t.Errorf("the row does not name the technique: %q", findings[0].Title)
	}
}

// TestALoginPageRenderedTwiceIsNotABypass is the false positive this detector
// exists to avoid: the same login page with a different nonce answers with
// different bytes, and a byte comparison would call that an access grant.
func TestALoginPageRenderedTwiceIsNotABypass(t *testing.T) {
	nonce := 0
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		nonce++
		w.Write([]byte(`<html><body><form action="/login"><input type="password" name="password">` +
			`<input type="hidden" name="csrf" value="` + string(rune('a'+nonce)) + `"></form>` +
			`<p>Sign in</p></body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/admin/panel.jsp", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := AuthBypassExt{}.Scan(context.Background(), transport, point, baseline)
	if len(findings) != 0 {
		t.Errorf("a rotating login page was reported as a bypass: %+v", findings)
	}
}

// TestAStaticPathIsNotProbed is the noise control: a detector that fired five
// truncation forms at every crawled URL would spend five requests on the
// overwhelming majority of pages that have no server-side extension at all.
func TestAStaticPathIsNotProbed(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/about.html", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := (AuthBypassExt{}).Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("a static path produced a row: %+v", findings)
	}
	if len(server.asked) != 1 {
		t.Errorf("a static path was probed anyway: %v", server.asked)
	}
}

// TestAnUnchangedAnswerIsNotABypass is the second control: a `.php` page that
// answers the same thing however it is addressed is not a bypass.
func TestAnUnchangedAnswerIsNotABypass(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>same</body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/index.php", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := (AuthBypassExt{}).Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("an unchanged answer produced a row: %+v", findings)
	}
}

// # Vite file bridge

// TestTheFileBridgeReturningAPasswdFileIsARead is the advisory's payload: the
// `/@fs/` endpoint answers with a line only `/etc/passwd` contains.
func TestTheFileBridgeReturningAPasswdFileIsARead(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/@fs/etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := ViteFSRead{}.Scan(context.Background(), transport, point, baseline)
	if len(findings) != 1 {
		t.Fatalf("want one read, got %d: %+v", len(findings), findings)
	}
	if findings[0].Tier != TierVerified {
		t.Errorf("a returned file is the verified case: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "root:x:0:0:") {
		t.Errorf("the evidence does not show the file: %q", findings[0].Evidence)
	}
}

// TestAForbiddenFileBridgeIsNotARead is the control that makes the detector
// quiet: every current Vite answers `/@fs/etc/passwd` with 403, and reporting a
// refusal as a read would put a critical row on every dev server on the internet.
func TestAForbiddenFileBridgeIsNotARead(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("The request url \"…\" is outside of Vite serving allow list."))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := (ViteFSRead{}).Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("a 403 file bridge produced a read: %+v", findings)
	}
}

// TestAServerThatAnswersEverythingIsNotARead is the second control: a server that
// answers 200 to every path would answer the probe too, and only the signature
// tells the two apart.
func TestAServerThatAnswersEverythingIsNotARead(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>hello</body></html>"))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := (ViteFSRead{}).Scan(context.Background(), transport, point, baseline); len(findings) != 0 {
		t.Errorf("a server that answers 200 to everything produced a read: %+v", findings)
	}
}

// # Path dictionary

// TestAPathTheServerDistinguishesIsFound is what the dictionary is for, and the
// discriminator is the measured not-found answer rather than a status list.
func TestAPathTheServerDistinguishesIsFound(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin-panel/":
			w.Write([]byte("<html><body>the forgotten admin</body></html>"))
		case "/nothing-here/":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<html><body>not found</body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<html><body>not found</body></html>"))
		}
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	findings := HiddenPaths{Paths: []string{"/admin-panel/", "/not-there/"}}.Scan(
		context.Background(), transport, point, nil)
	if len(findings) != 1 {
		t.Fatalf("want one found path, got %d: %+v", len(findings), findings)
	}
	if findings[0].Title == "" || !strings.Contains(findings[0].Title, "admin-panel") {
		t.Errorf("the row does not name the path: %q", findings[0].Title)
	}
	if findings[0].Tier != TierVerified {
		t.Errorf("a different status is the verified case: %+v", findings[0])
	}
}

// TestASoftNotFoundPageIsNotAReport is the false positive that makes a dictionary
// scan useless, and it is the reason this module measures its own 404: a server
// that answers 200 with a rendered not-found page would report every entry.
func TestASoftNotFoundPageIsNotAReport(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>page ` + r.URL.Path + ` does not exist</body></html>`))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/", Method: http.MethodGet}
	findings := HiddenPaths{Paths: []string{"/a/", "/b/", "/c/"}}.Scan(
		context.Background(), transport, point, nil)
	if len(findings) != 0 {
		t.Errorf("a soft-404 server produced %d rows: %+v", len(findings), findings)
	}
}

// TestAnEmptyDictionarySpendsNothing is the same contract as the wordlist's, and
// for the same reason: there is no default dictionary, so an absent one has to
// cost nothing rather than fall back to a list the operator did not ask for.
func TestAnEmptyDictionarySpendsNothing(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	transport := transportFor(t, server.Server)
	if findings := (HiddenPaths{}).Scan(
		context.Background(), transport, Point{URL: server.URL + "/", Method: http.MethodGet}, nil,
	); len(findings) != 0 {
		t.Errorf("an empty dictionary produced rows: %+v", findings)
	}
	if len(server.asked) != 0 {
		t.Errorf("an empty dictionary sent requests: %v", server.asked)
	}
}

// # Wiring

// TestTheRunCarriesTheWordlistIntoTheModule is the test the `Redirect` incident
// asked for: a detector that is in the run but can never be fed its input reports
// "no finding" for every target on the internet while appearing in the module
// count. This one asserts the field reaches the module.
func TestTheRunCarriesTheWordlistIntoTheModule(t *testing.T) {
	request := ScanRequest{
		URL:           "https://example.invalid/",
		Params:        []string{"report_token"},
		PathWordlist:  []string{"/admin/"},
		BlindDelay:    0,
		RoundTripper:  http.DefaultTransport,
	}
	scan := NewScan(request, nil)
	var sawParams, sawPaths bool
	for _, module := range scan.modules {
		switch typed := module.(type) {
		case HiddenParams:
			sawParams = len(typed.Params) == 1 && typed.Params[0] == "report_token"
		case HiddenPaths:
			sawPaths = len(typed.Paths) == 1 && typed.Paths[0] == "/admin/"
		}
	}
	if !sawParams {
		t.Error("the run did not carry the parameter wordlist into the module")
	}
	if !sawPaths {
		t.Error("the run did not carry the dictionary into the module")
	}
}

// TestTheNewDetectorsAreInThePlainModuleSet is the other half: a module assembled
// only by `NewScan` with fields set would be absent from `AllModules`, and a
// report that lists the detector count would then disagree with the run.
func TestTheNewDetectorsAreInThePlainModuleSet(t *testing.T) {
	names := map[string]bool{}
	for _, module := range AllModules() {
		names[module.Name()] = true
	}
	for _, wanted := range []string{"hidden_params", "auth_bypass_ext", "hidden_paths", "vite_fs_read"} {
		if !names[wanted] {
			t.Errorf("module %q is not in the set a plain run carries", wanted)
		}
	}
}

// # Shape checks that are pure functions
//
// These need no server, and they are here because the URL rewriting is where a
// truncation probe goes wrong silently: a probe that rewrites the query instead
// of the path still sends a request, and only the shape test notices.

func TestTruncationURLRewritesThePathAndKeepsTheQuery(t *testing.T) {
	got := truncationURL("https://host.example/a/b.jsp?x=1", ".jsp", ";.jsp")
	if got != "https://host.example/a/b;.jsp?x=1" {
		t.Errorf("want the path rewritten and the query kept, got %q", got)
	}
}

func TestServerExtensionOfReadsOnlyMappedExtensions(t *testing.T) {
	cases := map[string]string{
		"https://h/a/b.jsp":       ".jsp",
		"https://h/a/b.PHP":       ".php",
		"https://h/a/b.html":      "",
		"https://h/a/b":           "",
		"https://h/a.b.css?x=.jsp": "",
	}
	for rawURL, want := range cases {
		if got := serverExtensionOf(rawURL); got != want {
			t.Errorf("serverExtensionOf(%q) = %q, want %q", rawURL, got, want)
		}
	}
}

func TestTheHiddenPathDictionaryRefusesAnythingThatIsNotAPath(t *testing.T) {
	got := (HiddenPaths{Paths: []string{
		"admin", "https://other.example/x", "/a b", "//evil.example/", "/ok",
	}}).usablePaths()
	if len(got) != 2 || got[0] != "/admin" || got[1] != "/ok" {
		t.Errorf("the dictionary was not cleaned: %v", got)
	}
}

// TestTheWordlistDoesNotContainAQuery confirms the module-level rule that a
// dictionary entry carrying a query separator is a query, not a name, and that a
// duplicate is one entry rather than two requests' worth of rows.
func TestTheWordlistDoesNotContainAQuery(t *testing.T) {
	got := (HiddenParams{Params: []string{
		"token", "x=1&y=2", "has space", "no", "dupe", "dupe",
	}}).usableNames()
	if len(got) != 2 || got[0] != "dupe" || got[1] != "token" {
		t.Errorf("the wordlist was not cleaned: %v", got)
	}
}
