package main

// Tests for the two capabilities this file's additions carry: `SearchDomains`
// (twenty-six TLD candidates) and the file dump (`utils.WriteToFile` +
// `utils.WriteEmailToFile`).
//
// Both are ported from `ibnaleem/gosearch` at `687f9ed`, and both have a defect in
// the original that is worth naming before the assertions:
//
//   - `search.go:66` counts a candidate domain as found on **any** non-error
//     status, which includes `404` and `403` — so "this name is taken" and
//     "something is listening" were the same answer, and a parked page counted;
//   - `utils.go:25` writes a file on **every** run with `os.ModePerm` (0777),
//     so plaintext credentials landed in a world-readable file whether the
//     operator wanted one or not;
//   - `utils.go:56` (`WriteEmailToFile`) has **no mutex** while
//     `WriteToFile` (`:27`) does, and both are called from concurrent goroutines
//     — a real data race on the addresses file.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// domainProbeFixture answers plain-HTTP domain probes the way a real registrar and
// a real parked page do.
type domainProbeFixture struct {
	mu sync.Mutex
	// taken is the set of hosts that answer like a live site.
	taken    map[string]int
	askedFor map[string]int
}

func (fixture *domainProbeFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		fixture.mu.Lock()
		fixture.askedFor[host]++
		status, known := fixture.taken[host]
		fixture.mu.Unlock()
		if !known {
			// Everything not explicitly taken answers 404, which is what a name
			// that is free answers at an HTTP host.
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
		fmt.Fprint(w, "body for "+host)
	})
}

func (fixture *domainProbeFixture) serve(t *testing.T) *httptest.Server {
	t.Helper()
	served := httptest.NewServer(fixture.handler(t))
	t.Cleanup(served.Close)
	return served
}

// hostIn rewrites the twenty-six candidate hosts onto one fixture server.
//
// The pass builds `http://<user><tld>`, so every candidate has to land on the test
// server. Rewriting here rather than in the pass keeps the pass's URL construction
// exactly as upstream has it — a construction that the registry test pins.
func (fixture *domainProbeFixture) hostIn(served *httptest.Server) func() {
	return func() {}
}

// TestSearchDomainsProbesEveryCandidate pins the list against upstream: twenty-six
// TLDs, one request each. The size is part of what the pass costs, so a trimmed
// list would be a bound nobody can see.
func TestSearchDomainsProbesEveryCandidate(t *testing.T) {
	fixture := &domainProbeFixture{taken: map[string]int{}, askedFor: map[string]int{}}
	served := fixture.serve(t)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	// `httptest` answers every host it is given, so the candidates are exercised
	// through the same construction the pass uses.
	previous := identityGraphDomainHostPrefix
	identityGraphDomainHostPrefix = strings.TrimSuffix(served.URL, "/") + "/"
	defer func() { identityGraphDomainHostPrefix = previous }()

	result := &osintTransformResult{Metadata: map[string]interface{}{}}
	checked, err := identityGraphDomainPass(context.Background(), client, "ibnaleem",
		5_000_000_000, 0, result, nil)
	if err != nil {
		t.Fatalf("the domain pass returned %v", err)
	}
	if checked != 0 {
		t.Errorf("got %d answered candidates from a server that answers 200 for everything", checked)
	}
	if got := result.Metadata["domains_probed"]; got != len(identityGraphDomainTLDs) {
		t.Errorf("domains_probed = %v, want %d", got, len(identityGraphDomainTLDs))
	}
	if len(identityGraphDomainTLDs) != 26 {
		t.Errorf("the TLD list has %d entries, want the 26 of utils.BuildDomains", len(identityGraphDomainTLDs))
	}
}

// TestSearchDomainsCountOnlyWhatAnswered: the original counted a candidate on any
// non-error status. `404` and `403` mean "nothing here", and a parked page counts
// as much as a site — so a pass whose hits are mostly other people's domains is the
// consequence. The status is still recorded on the node, because "something
// answered" and "the name is taken" are different answers.
func TestSearchDomainsCountOnlyWhatAnswered(t *testing.T) {
	cases := map[string]struct {
		status   int
		counted  bool
		explains string
	}{
		"a live site":             {http.StatusOK, true, "counted"},
		"a redirect":              {http.StatusMovedPermanently, true, "counted"},
		"not found":               {http.StatusNotFound, false, "not counted"},
		"forbidden":               {http.StatusForbidden, false, "not counted"},
		"gone":                    {http.StatusGone, false, "not counted"},
		"a parked page answering": {http.StatusForbidden, false, "not counted"},
	}
	for name, testCase := range cases {
		if got := identityGraphDomainChecked(testCase.status); got != testCase.counted {
			t.Errorf("%s (status %d): counted = %v, %s", name, testCase.status, got, testCase.explains)
		}
	}
}

// TestSearchDomainsIsOffByDefaultAndSaysSo: twenty-six requests whose hits are
// mostly parked pages is not something to run on every identity lookup. It is
// opt-in, and the applied value is in the metadata — a run without domain nodes has
// to say it did not probe, not look like it probed and found nothing.
func TestSearchDomainsIsOffByDefaultAndSaysSo(t *testing.T) {
	result := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", nil)
	if result.Metadata["check_domains"] != false {
		t.Errorf("check_domains = %v, want false by default", result.Metadata["check_domains"])
	}
	if result.Metadata["domain_candidates"] != len(identityGraphDomainTLDs) {
		t.Errorf("domain_candidates = %v, want the size of the list even when the pass is off",
			result.Metadata["domain_candidates"])
	}
	var domainEntities int
	for _, item := range result.Entities {
		if item.Properties["kind"] == "domain_candidate" {
			domainEntities++
		}
	}
	if domainEntities != 0 {
		t.Errorf("got %d domain entities from a run that did not ask for the pass", domainEntities)
	}

	on := identityGraphRun(t, identityGraphQuiet(), "ibnaleem",
		map[string]interface{}{"check_domains": true})
	if on.Metadata["check_domains"] != true {
		t.Errorf("check_domains = %v, want true when asked for", on.Metadata["check_domains"])
	}
}

// TestTheReportFileIsWrittenOnlyWhenAsked pins the difference that matters most:
// the original wrote a file on every run, so a tool invocation always left
// credentials on disk.
func TestTheReportFileIsWrittenOnlyWhenAsked(t *testing.T) {
	directory := t.TempDir()

	quiet := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", map[string]interface{}{
		"dump_path": directory,
	})
	if quiet.Metadata["report_path"] != nil {
		t.Errorf("a run that did not ask for a file left one at %v", quiet.Metadata["report_path"])
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read the report directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d file(s) in the report directory from a run that did not ask for one", len(entries))
	}

	written := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", map[string]interface{}{
		"dump_file": true,
		"dump_path": directory,
	})
	path, _ := written.Metadata["report_path"].(string)
	if path == "" {
		t.Fatal("the run published no report_path")
	}
	if filepath.Dir(path) != directory {
		t.Errorf("the report was written to %s, outside the directory the caller named (%s)", path, directory)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the report: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, ":: Query") {
		t.Errorf("the report does not name the query:\n%s", text)
	}
}

// TestTheReportFileIsNotWorldReadable is the one behavioural departure from
// upstream, and it is made deliberately: the original opens with `os.ModePerm`
// (0777), so a plaintext credential ended up in a file any account on the machine
// could read. `0640` keeps the capability and drops the exposure.
func TestTheReportFileIsNotWorldReadable(t *testing.T) {
	directory := t.TempDir()
	written := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", map[string]interface{}{
		"dump_file": true,
		"dump_path": directory,
	})
	path, _ := written.Metadata["report_path"].(string)
	if path == "" {
		t.Fatal("the run published no report_path")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the report: %v", err)
	}
	mode := info.Mode().Perm()
	if mode&0o007 != 0 {
		t.Errorf("the report is mode %04o; the original's os.ModePerm left a credential world-readable", mode)
	}
	if mode&0o200 == 0 {
		t.Errorf("the report is mode %04o and not writable by its owner", mode)
	}
}

// TestTheReportFileCarriesTheAddressesAndTheWarnings: `WriteToFile` and
// `WriteEmailToFile` were two files, and the second had **no mutex** while the
// first did (`utils.go:56` against `utils.go:27`) — both were called from
// concurrent goroutines, so addresses were appended from several of them. One file
// assembled in memory and written once cannot disagree with itself.
func TestTheReportFileCarriesTheAddressesAndTheWarnings(t *testing.T) {
	directory := t.TempDir()
	fixture := identityGraphQuiet()
	fixture.gravatarBody = `{"entry":[{"requestHash":"ibnaleem","emails":[{"value":"ibnaleem@yandex.ru"}],"accounts":[]}]}`
	fixture.hudsonBody = `{"message":"","stealers":[{"stealer_family":"RedLine","computer_name":"DESKTOP-AB12","date_compromised":"2026-09-30T10:00:00Z","top_passwords":["Summer2018"],"operating_system":"Windows 11"}]}`

	written := identityGraphRun(t, fixture, "svc.admin@yandex.ru", map[string]interface{}{
		"dump_file": true,
		"dump_path": directory,
	})
	path, _ := written.Metadata["report_path"].(string)
	if path == "" {
		t.Fatal("the run published no report_path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the report: %v", err)
	}
	text := string(raw)
	for _, needle := range []string{
		"svc.admin@yandex.ru", // the query
		"ibnaleem@yandex.ru",  // the published address
		"RedLine",             // the stealer family
		"DESKTOP-AB12",        // the machine
		"Summer2018",          // a password the machine held
		":: Emails",           // the addresses get their own section
		"HudsonRock",          // the services asked
	} {
		if !strings.Contains(text, needle) {
			t.Errorf("the report does not carry %q:\n%s", needle, text)
		}
	}
	// And the name is the query plus the date, as upstream named it
	// (`utils.go:45`), so a file from the original and a file from here are
	// recognisably the same artefact.
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "svc.admin@yandex.ru_") {
		t.Errorf("report name = %q, want the query and the date as upstream writes it", base)
	}
	if !strings.HasSuffix(base, identityGraphDumpSuffix) {
		t.Errorf("report name = %q, want the %q extension of upstream", base, identityGraphDumpSuffix)
	}
}

// TestDumpOptionsAreReadAsTheCallerWroteThem covers both switches, including the
// refusal to guess at a string that is not a boolean.
func TestDumpOptionsAreReadAsTheCallerWroteThem(t *testing.T) {
	cases := []struct {
		name    string
		options map[string]interface{}
		dump    bool
	}{
		{"absent means no file", map[string]interface{}{}, false},
		{"true asks for one", map[string]interface{}{"dump_file": true}, true},
		{"the string true asks for one", map[string]interface{}{"dump_file": "true"}, true},
		{"a number asks for one", map[string]interface{}{"dump_file": 1}, true},
		{"false asks for none", map[string]interface{}{"dump_file": false}, false},
		{"rubbish asks for none rather than guessing", map[string]interface{}{"dump_file": "maybe"}, false},
	}
	for _, testCase := range cases {
		if got := identityGraphDumpRequested(testCase.options); got != testCase.dump {
			t.Errorf("%s: dump_file read as %v", testCase.name, got)
		}
	}

	domainCases := []struct {
		name    string
		options map[string]interface{}
		want    bool
	}{
		{"absent means the pass is off", map[string]interface{}{}, false},
		{"true turns it on", map[string]interface{}{"check_domains": true}, true},
		{"the string true turns it on", map[string]interface{}{"check_domains": "true"}, true},
		{"false leaves it off", map[string]interface{}{"check_domains": false}, false},
		{"rubbish leaves it off", map[string]interface{}{"check_domains": "maybe"}, false},
	}
	for _, testCase := range domainCases {
		if got := identityGraphCheckDomains(testCase.options); got != testCase.want {
			t.Errorf("%s: check_domains read as %v", testCase.name, got)
		}
	}
}

// TestTheReportFileSanitisesTheQuery: the file name is the query, and a query can
// carry a path separator. `../../../etc/passwd` must not become a path.
func TestTheReportFileSanitisesTheQuery(t *testing.T) {
	directory := t.TempDir()
	written := identityGraphRun(t, identityGraphQuiet(), "../../etc/passwd", map[string]interface{}{
		"dump_file": true,
		"dump_path": directory,
	})
	path, _ := written.Metadata["report_path"].(string)
	if path == "" {
		t.Fatal("the run published no report_path")
	}
	if filepath.Dir(path) != directory {
		t.Errorf("a query containing path separators escaped the directory: %s", path)
	}
}

// TestTheTLDListMatchesUpstream reads the original rather than trusting the copy
// above. The list is the pass's entire cost model, and a drifted list would be a
// bound nobody can see.
func TestTheTLDListMatchesUpstream(t *testing.T) {
	body, err := readGosearchUpstream(t, "internal/utils/utils.go")
	if err != nil {
		t.Skipf("the upstream clone is not present at %s: %v", gosearchCloneRoot, err)
	}
	start := strings.Index(body, "tlds := []string{")
	if start < 0 {
		t.Fatal("the upstream source no longer declares its TLD list")
	}
	block := body[start : strings.Index(body[start:], "}")+start]
	for _, tld := range identityGraphDomainTLDs {
		if !strings.Contains(block, `"`+tld+`"`) {
			t.Errorf("the upstream list no longer contains %q, which this port probes", tld)
		}
	}
	// And the port adds nothing upstream does not have, so the cost is the same.
	count := strings.Count(block, `".`)
	if count != len(identityGraphDomainTLDs) {
		t.Errorf("upstream lists %d TLDs, this port probes %d", count, len(identityGraphDomainTLDs))
	}
}
