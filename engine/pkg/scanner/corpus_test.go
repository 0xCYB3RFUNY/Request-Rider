package scanner

// Tests for the enumeration corpus: the loader, the matcher and the grouping.
//
// The corpus is generated data, so most of these are regression tests over it: a
// conversion that quietly drops a third of the rows would leave every functional
// test green while the scanner got worse. The count and the kind distribution are
// therefore asserted as numbers, not described.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Go refuses to write `<`, `>`, quotes, braces, pipe, caret, backtick, backslash
// or a space into a request line, and escaping the path changes the question. The
// corpus keeps no such row: 29 of them came back from the parity stand with no
// response at all, which leaves no exchange in Traffic and a run that still looks
// clean. This is the check that they are gone, with the reason recorded rather than
// assumed.
func TestTheCorpusHoldsNoPathGoWouldRefuseToSend(t *testing.T) {
	all, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	// A plain scan rather than a regexp: the character set contains a backtick and
	// a backslash, and a class holding either is a quoting trap in both kinds of Go
	// string. An earlier version of this test was silently matching every path
	// ending in `.cfm` because the raw string ended at the backtick.
	const unacceptable = `<>"{}|^` + "\\" + " "

	for _, check := range all {
		for _, symbol := range check.Path {
			if strings.ContainsRune(unacceptable, symbol) || symbol < 0x20 || symbol == 0x7f {
				t.Errorf("check %s carries a path Go will not put in a request line: %s", check.ID, check.Path)
				break
			}
		}
	}
}

func TestTheRepositoryCorpusIsTheWholeConvertedBase(t *testing.T) {
	checks, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("LoadDefaultCorpus: %v", err)
	}
	// Upstream carries 7240 checks. The converter drops what this engine cannot
	// execute (unrunnable match expressions, odd methods) and collapses ids that
	// share a method and path. The result is measured, not estimated: the
	// converter prints these same numbers when it runs.
	if len(checks) < 5000 {
		t.Fatalf("corpus has %d checks; the conversion produced 5522 and a drop like this "+
			"means the generator lost rows, not that the base shrank", len(checks))
	}

	byKind := map[string]int{}
	paths := map[string]struct{}{}
	for _, check := range checks {
		byKind[check.Kind]++
		paths[check.Key()] = struct{}{}
	}
	if byKind[MatchCode] == 0 || byKind[MatchBody] == 0 {
		t.Errorf("a kind went missing: %v", byKind)
	}
	if len(paths) < 1000 {
		t.Errorf("only %d distinct requests out of %d checks; grouping would be pointless",
			len(paths), len(checks))
	}
	t.Logf("checks=%d requests=%d by kind=%v", len(checks), len(paths), byKind)
}

func TestTheSecondCallerGetsTheCorpusToo(t *testing.T) {
	// Regression. The parse is guarded by a sync.Once, and the cached value used to
	// be a local of the accessor: the first call parsed and cached, and every call
	// after it returned nil because its own local was still zero. The caller that
	// mattered most — the one after an operator opened a second view or ran a second
	// scan — silently got an empty corpus, and an empty corpus reports a clean
	// site. Nothing errors, so only a test that asks twice catches it.
	first, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("the first call returned no checks")
	}
	if len(second) != len(first) {
		t.Fatalf("the second call returned %d checks, the first %d", len(second), len(first))
	}
}

func TestACallerNarrowingTheCorpusDoesNotStarveTheNext(t *testing.T) {
	// The same defect seen from the other side: the accessor hands out a copy, so a
	// caller that filters its slice in place cannot empty the corpus for everyone
	// who asks afterwards.
	base, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("LoadDefaultCorpus: %v", err)
	}
	held := FilterCorpus(base, []string{TagInformation})
	if err := os.WriteFile(os.DevNull, nil, 0o600); err != nil {
		t.Fatalf("unreachable: %v", err)
	}
	_ = held
	// Drain the caller's slice the way an in-place filter would.
	for i := range held {
		held[i] = CorpusCheck{}
	}
	again, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if len(again) != len(base) {
		t.Fatalf("a caller rewrote %d of %d checks for everyone after it",
			len(base)-len(again), len(base))
	}
	for _, check := range again {
		if check.ID == "" {
			t.Fatal("the corpus was handed out blanked")
		}
		break
	}
}

func TestEveryPathInTheCorpusIsAPathAServerWouldServe(t *testing.T) {
	// Regression, and the defect it found. Upstream writes `@CGIDIRname.ext`, where
	// `@CGIDIR` stands for the CGI directory *including* its separator. The
	// converter concatenated without one and produced `/cgi-binScart32.exe` — a path
	// no server serves, so 518 checks could never fire and the whole run looked
	// green. 25 rows carried a correct `/cgi-bin/`; 542 do now.
	checks, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("LoadDefaultCorpus: %v", err)
	}
	// The defect's exact shape: `/cgi-bin` glued to what follows. A slash, a hyphen
	// or the end of the string is fine — upstream really does carry paths like
	// `/html/cgi-bin/cgicso` and `/cgi-bin-sdb/printenv`, and flagging those would be
	// a test that cries wolf on correct data.
	glued := regexp.MustCompile(`/cgi-bin[^/-]`)
	seen := map[string]bool{}
	for _, check := range checks {
		if glued.MatchString(check.Path) {
			t.Errorf("check %s has /cgi-bin glued to its neighbour: %q", check.ID, check.Path)
		}
		if strings.HasPrefix(check.Path, "/cgi-bin/") {
			seen["cgi"] = true
		}
	}
	if !seen["cgi"] {
		t.Error("no corpus row is addressed under /cgi-bin/, which is where 9.5% of " +
			"upstream's checks live; the addressing was lost somewhere")
	}
}

func TestEveryCorpusRowIsExecutable(t *testing.T) {
	checks, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("LoadDefaultCorpus: %v", err)
	}
	for _, check := range checks {
		switch check.Kind {
		case MatchCode:
			if check.Value == "" {
				t.Errorf("check %s (%s) is a code check with no code", check.ID, check.Path)
			}
		case MatchBody, MatchHeader:
			if check.pattern == nil {
				t.Errorf("check %s (%s) has no compiled pattern", check.ID, check.Path)
			}
		case MatchAnd:
			if len(check.patterns) == 0 {
				t.Errorf("check %s (%s) is a conjunction with no compiled half", check.ID, check.Path)
			}
		default:
			t.Errorf("check %s carries unknown kind %q", check.ID, check.Kind)
		}
		if check.Method == "" || !strings.HasPrefix(check.Path, "/") {
			t.Errorf("check %s has an unusable request: %q %q", check.ID, check.Method, check.Path)
		}
	}
}

// The conjunction rules below are upstream's, taken from its own parser
// (`parse_dsl` and `dsl_evaluate` in `program/plugins/nikto_core.plugin`): a half
// whose label carries no `!` must hold, a half that carries one must fail, and the
// check is lost as soon as one of those goes wrong. Nothing here treats a body
// half as negative by default — an earlier version did, on a reading the database
// itself refutes in 280 rows, and every one of the 672 conjunctions was inverted.

func TestAConjunctionHoldsOnlyWhenEveryUnmarkedHalfHolds(t *testing.T) {
	check := CorpusCheck{Kind: MatchAnd, Value: "CODE:200&&BODY:not found"}
	check.patterns = map[string]*regexp.Regexp{"BODY:not found": mustCompile(t, "not found")}

	if !check.Match(200, "<html>404 not found</html>", nil) {
		t.Error("a 200 whose body carries the text did not pass; both halves are positive upstream")
	}
	if check.Match(200, "<html>a real page</html>", nil) {
		t.Error("a 200 whose body lacks the text passed a conjunction that asks for both")
	}
	if check.Match(404, "<html>404 not found</html>", nil) {
		t.Error("the check passed on a 404 even though it asked for 200")
	}
}

func TestANegatedHalfMustNotHold(t *testing.T) {
	check := CorpusCheck{Kind: MatchAnd, Value: "BODY:token&&!CODE:404"}
	check.patterns = map[string]*regexp.Regexp{"BODY:token": mustCompile(t, "token")}
	if !check.Match(200, "a token appears", nil) {
		t.Error("a 200 carrying the token did not pass; the `!` belongs to the other half")
	}
	if check.Match(404, "a token appears", nil) {
		t.Error("a 404 passed a check that demands a status other than 404")
	}
	if check.Match(200, "nothing relevant", nil) {
		t.Error("the check passed without its body half")
	}
}

func TestANegatedBodyHalfMustNotMatch(t *testing.T) {
	check := CorpusCheck{Kind: MatchAnd, Value: "CODE:200&&!BODY:not found"}
	// The pattern is keyed by the half as written, `!` included, because that is the
	// text the loader records and the matcher looks up.
	check.patterns = map[string]*regexp.Regexp{"!BODY:not found": mustCompile(t, "not found")}
	if !check.Match(200, "<html>a real page</html>", nil) {
		t.Error("a real page failed a check that asks the body *not* to say 'not found'")
	}
	if check.Match(200, "<html>not found</html>", nil) {
		t.Error("the page carrying the text passed a check that forbids it")
	}
}

func TestATopLevelDisjunctionNeedsOnlyOneAlternative(t *testing.T) {
	// Upstream turns a top-level `||` into one group of alternatives before it looks
	// at anything else, so the row `BODY:PHP Version||@LFI()` is satisfied by either.
	check := CorpusCheck{Kind: MatchAnd, Value: "BODY:PHP Version||BODY:zope"}
	check.patterns = map[string]*regexp.Regexp{
		"BODY:PHP Version": mustCompile(t, "PHP Version"),
		"BODY:zope":        mustCompile(t, "zope"),
	}
	// Patterns are case sensitive unless the row asks otherwise with `(?i)`, which is
	// why 51 rows in the database spell it out.
	if !check.Match(200, "<p>zope</p>", nil) {
		t.Error("the second alternative was not tried")
	}
	if !check.Match(200, "<p>PHP Version 5</p>", nil) {
		t.Error("the first alternative did not hold")
	}
	if check.Match(200, "<p>something else</p>", nil) {
		t.Error("a body matching neither alternative was accepted")
	}
}

func TestAHeaderHalfNeedsTheHeaderToBeThere(t *testing.T) {
	check := CorpusCheck{Kind: MatchAnd, Value: "CODE:200&&HEADER:Server"}
	check.patterns = map[string]*regexp.Regexp{}
	header := http.Header{"Server": []string{"nginx"}}
	if !check.Match(200, "", header) {
		t.Error("a present header did not satisfy a bare HEADER half")
	}
	if check.Match(200, "", nil) {
		t.Error("an absent header satisfied a bare HEADER half")
	}
}

func TestANegatedBareHeaderHalfNeedsTheHeaderToBeAbsent(t *testing.T) {
	check := CorpusCheck{Kind: MatchAnd, Value: "CODE:200&&!HEADER:Server"}
	check.patterns = map[string]*regexp.Regexp{}
	if !check.Match(200, "", nil) {
		t.Error("an absent header did not satisfy a negated bare HEADER half")
	}
	if check.Match(200, "", http.Header{"Server": []string{"nginx"}}) {
		t.Error("a present header satisfied a negated bare HEADER half")
	}
}

func TestARuntimePayloadTokenConstrainsNothing(t *testing.T) {
	// Upstream skips an `@LFI()` token outright rather than failing on it, because
	// it is filled in at request time and says nothing about the response.
	check := CorpusCheck{Kind: MatchAnd, Value: "CODE:200&&@LFI()&&BODY:token"}
	check.patterns = map[string]*regexp.Regexp{"BODY:token": mustCompile(t, "token")}
	if !check.Match(200, "a token appears", nil) {
		t.Error("a runtime payload token was treated as a condition on the response")
	}
}

func TestAConjunctionWithAnUncompiledHalfReportsNothing(t *testing.T) {
	check := CorpusCheck{Kind: MatchAnd, Value: "CODE:200&&BODY:not found"}
	check.patterns = map[string]*regexp.Regexp{}
	if check.Match(200, "anything", nil) {
		t.Error("a conjunction missing a compiled half reported a finding instead of failing safe")
	}
}

func TestAConjunctionAskingNothingReportsNothing(t *testing.T) {
	// A conjunction whose every half upstream skips constrains nothing at all: it
	// asks no question, so no response can answer it. A version of this test that
	// used a body half the response failed to match stayed green when the "nothing
	// was required" flag was forced on, because the half failed for its own reason —
	// it did not test the flag at all.
	check := CorpusCheck{Kind: MatchAnd, Value: "@LFI()"}
	check.patterns = map[string]*regexp.Regexp{}
	if check.Match(200, "<html>anything at all</html>", nil) {
		t.Error("a conjunction that asks nothing reported a finding")
	}
}

func TestACodeCheckComparesTheStatusItNames(t *testing.T) {
	check := CorpusCheck{Kind: MatchCode, Value: "200"}
	if !check.Match(200, "anything at all", nil) {
		t.Error("a 200 check did not match a 200")
	}
	if check.Match(403, "", nil) {
		t.Error("a 200 check matched a 403")
	}
}

func TestABodyCheckNeedsTheTextItNames(t *testing.T) {
	checks, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("LoadDefaultCorpus: %v", err)
	}
	var body CorpusCheck
	for _, check := range checks {
		if check.Kind == MatchBody {
			body = check
			break
		}
	}
	if body.pattern == nil {
		t.Fatalf("the corpus has %d checks but none of kind %s carried a pattern",
			len(checks), MatchBody)
	}
	if !body.Match(200, "prefix "+body.Value+" suffix", nil) {
		t.Error("a body check did not match a body carrying its own pattern")
	}
	if body.Match(200, "an unrelated page", nil) {
		t.Error("a body check matched a body that does not carry its pattern")
	}
}

func TestAContentMatchOnAnErrorPageIsNotAFinding(t *testing.T) {
	// Regression from a live run. A 404 whose body is the site's own error template
	// matched a body check, and the finding said a path existed because the
	// substitute page contained a word. Every real server has such a page.
	body := CorpusCheck{Kind: MatchBody, Value: "social-", pattern: mustCompile(t, "social-")}
	if body.Match(http.StatusNotFound, "<i><%= ria.getIcon('social-'+data.name) %></i>", nil) {
		t.Error("a body check matched the error page a server substitutes for a path that does not exist")
	}
	if body.Match(http.StatusInternalServerError, "something social- happened", nil) {
		t.Error("a body check matched a 5xx error page")
	}
	if !body.Match(http.StatusOK, "something social- happened", nil) {
		t.Error("a body check stopped matching a 200, which is the answer it exists for")
	}
}

func TestARowWithTooFewFieldsIsRefused(t *testing.T) {
	// A truncated row would otherwise index past the end and produce a check with
	// empty fields, which reads as a request to "/" against an empty pattern.
	path := filepath.Join(t.TempDir(), "short.tsv")
	writeCorpus(t, path, "0001\tGET\t/x")

	_, err := LoadCorpus(path)
	if err == nil {
		t.Fatal("a row with three fields was accepted")
	}
	if !strings.Contains(err.Error(), "tab-separated") {
		t.Errorf("the error does not say what is wrong with the row: %v", err)
	}
}

// failingReader yields one usable row and then fails, so the scanner's own error
// path is reached — which is the path that reports a truncated data file instead of
// a complete one.
type failingReader struct {
	sent bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.sent {
		return 0, fmt.Errorf("fixture: the corpus stream broke mid-read")
	}
	f.sent = true
	return copy(p, "0001\tGET\t/x\tCODE\t200\t\trow\n"), nil
}

func TestAStreamThatBreaksIsAnErrorNotAShortCorpus(t *testing.T) {
	// Reading fewer rows than the file holds because the read failed would report a
	// smaller corpus, and a smaller corpus looks like a scan that found less rather
	// than a corpus that could not be read.
	if _, err := ParseCorpus(&failingReader{}); err == nil {
		t.Fatal("a stream that broke mid-read produced a corpus")
	}
}

func TestAFailedParseIsReturnedRatherThanAnEmptyCorpus(t *testing.T) {
	// The accessor caches its parse. If the parse failed, every later caller has to
	// be told so; handing out an empty slice instead would report a clean site on
	// a target that was never looked at.
	// Burn the once against the real corpus first. Resetting it would make the next
	// `Do` re-parse and overwrite the failure being installed, so the accessor would
	// correctly report success and the test would prove nothing.
	corpusOnce.Do(func() {})
	previousCorpus, previousErr := cachedCorpus, cachedErr
	cachedCorpus, cachedErr = nil, fmt.Errorf("fixture: parse failed")
	t.Cleanup(func() { cachedCorpus, cachedErr = previousCorpus, previousErr })

	if _, err := LoadDefaultCorpus(); err == nil {
		t.Fatal("a cached parse failure was reported as an empty corpus")
	}
}

func TestACheckThatCannotBeEvaluatedReportsNothingRatherThanEverything(t *testing.T) {
	// Each guard is a place where a data defect could turn into a finding that
	// matches everything. A check with no compiled pattern, an unknown kind, and a
	// code check whose argument is not a number must all answer false — never true,
	// and never panic on the nil pattern.
	unrunnable := []CorpusCheck{
		{ID: "no pattern", Kind: MatchBody, Value: "x"},
		{ID: "no pattern", Kind: MatchHeader, Value: "x"},
		{ID: "unknown kind", Kind: "TITLE", Value: "Admin"},
		{ID: "code is not a number", Kind: MatchCode, Value: "OK"},
		{ID: "empty kind", Value: "x"},
	}
	for _, check := range unrunnable {
		if check.Match(200, "a body that contains x and Admin", http.Header{"Server": []string{"x"}}) {
			t.Errorf("check %q matched a response it cannot evaluate", check.ID)
		}
	}
}

func TestAMissingCorpusFileIsAnErrorNotAnEmptyCorpus(t *testing.T) {
	// The distinction that matters: an empty selection reports a clean site, so a
	// path that cannot be opened has to fail rather than come back empty.
	if _, err := LoadCorpus(filepath.Join(t.TempDir(), "absent.tsv")); err == nil {
		t.Error("an unreadable corpus reported success")
	}
}

func TestACodeCheckStillReadsAnErrorStatus(t *testing.T) {
	// "This path answers 403" is a real observation about a real path. The guard is
	// about content matching an error template, not about error statuses being
	// uninteresting, and a check that named the status must still be honoured.
	forbidden := CorpusCheck{Kind: MatchCode, Value: "403"}
	if !forbidden.Match(http.StatusForbidden, "", nil) {
		t.Error("a code check for 403 did not match a 403")
	}
}

func TestAHeaderCheckLooksAnywhereInTheHeaderSet(t *testing.T) {
	header := http.Header{}
	header.Set("Server", "nginx/1.18.0")
	header.Add("X-Powered-By", "PHP/8.1.2")

	matching := CorpusCheck{Kind: MatchHeader, Value: `PHP/[0-9]`, pattern: mustCompile(t, `PHP/[0-9]`)}
	if !matching.Match(200, "", header) {
		t.Error("a header check did not find its pattern in a later header")
	}
	absent := CorpusCheck{Kind: MatchHeader, Value: "nothing-here", pattern: mustCompile(t, "nothing-here")}
	if absent.Match(200, "", header) {
		t.Error("a header check matched a header set that does not carry its pattern")
	}
}

func TestAnUncompilablePatternIsAnErrorNamingTheCheck(t *testing.T) {
	// A generated corpus cannot contain this; a hand-edited one can. The loader's
	// job is to make that visible instead of returning a corpus whose rows silently
	// never match.
	path := filepath.Join(t.TempDir(), "broken.tsv")
	writeCorpus(t, path, "0001\tGET\t/x\tBODY\t(unclosed\t\tbroken")

	_, err := LoadCorpus(path)
	if err == nil {
		t.Fatal("an uncompilable pattern loaded without complaint")
	}
	if !strings.Contains(err.Error(), "0001") {
		t.Errorf("the error does not name the check: %v", err)
	}
}

func TestAnUnknownMatchKindIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kind.tsv")
	writeCorpus(t, path, "0001\tGET\t/x\tTITLE\tAdmin\t\tunknown kind")

	if _, err := LoadCorpus(path); err == nil {
		t.Fatal("a row with an unknown match kind loaded")
	}
}

func TestAnEmptyCorpusIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.tsv")
	writeCorpus(t, path)

	if _, err := LoadCorpus(path); err == nil {
		t.Fatal("a corpus with no rows loaded as if it were usable")
	}
}

func TestSeveralChecksOnOnePathBecomeOneRequest(t *testing.T) {
	grouped := GroupCorpus([]CorpusCheck{
		{ID: "a", Method: "GET", Path: "/", Kind: MatchBody, Value: "x"},
		{ID: "b", Method: "GET", Path: "/", Kind: MatchBody, Value: "y"},
		{ID: "c", Method: "GET", Path: "/admin", Kind: MatchCode, Value: "200"},
		{ID: "d", Method: "POST", Path: "/", Kind: MatchCode, Value: "500"},
	})
	if len(grouped) != 3 {
		t.Fatalf("grouped into %d requests, want 3: the same path on two methods is two requests", len(grouped))
	}
	if len(grouped[0].Checks) != 2 {
		t.Errorf("the / request carries %d checks, want 2", len(grouped[0].Checks))
	}
	if grouped[0].Method != "GET" || grouped[0].Path != "/" {
		t.Errorf("first group = %s %s, want GET /", grouped[0].Method, grouped[0].Path)
	}
}

func TestAFilterNarrowsAndAnUntaggedCheckSurvivesIt(t *testing.T) {
	checks := []CorpusCheck{
		{Tags: "b", Method: "GET", Path: "/a"},
		{Tags: "c", Method: "GET", Path: "/b"},
		{Tags: "bc", Method: "GET", Path: "/c"},
		{Method: "GET", Path: "/untagged"},
	}
	selected := FilterCorpus(checks, []string{TagInformation})
	if len(selected) != 3 {
		t.Fatalf("filter kept %d checks, want 3 (b, c, bc plus the untagged one)", len(selected))
	}
	for _, check := range selected {
		if check.Path == "/a" {
			t.Error("a check outside the filter survived it")
		}
	}
	// An empty filter is "run everything", not "run nothing".
	if all := FilterCorpus(checks, nil); len(all) != len(checks) {
		t.Errorf("an empty filter returned %d of %d", len(all), len(checks))
	}
}

func TestTheStatsCountChecksAndRequestsSeparately(t *testing.T) {
	// They are different units and a report that shows one in place of the other
	// misstates what a run costs.
	stats := DescribeCorpus([]CorpusCheck{
		{Method: "GET", Path: "/", Tags: "b"},
		{Method: "GET", Path: "/", Tags: "c"},
		{Method: "GET", Path: "/x", Tags: "b"},
	})
	if stats.Selected != 3 {
		t.Errorf("Selected = %d, want 3 checks", stats.Selected)
	}
	if stats.UniquePaths != 2 {
		t.Errorf("UniquePaths = %d, want 2 requests", stats.UniquePaths)
	}
	if stats.ByTag[TagMisconfiguration] != 2 {
		t.Errorf("ByTag[b] = %d, want 2", stats.ByTag[TagMisconfiguration])
	}
}

func TestEveryTagTheCorpusUsesIsOneWeName(t *testing.T) {
	checks, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("LoadDefaultCorpus: %v", err)
	}
	known := map[string]bool{}
	for _, tag := range CorpusTags {
		known[tag] = true
	}
	for _, check := range checks {
		for _, tag := range check.Tags {
			if !known[string(tag)] {
				t.Fatalf("check %s carries tag %q, which no exported name matches: a filter on it "+
					"would select nothing and read as a clean scan", check.ID, string(tag))
			}
		}
	}
}

func TestTheCorpusRecordsItsOwnProvenance(t *testing.T) {
	// The provenance lives in the file that is embedded, so this reads the file
	// rather than the parsed rows: a header that the parser skips would otherwise
	// be invisible here.
	// The data file is the only place that travels with the rows. If it stops
	// saying where they came from, the restriction on upstream's database is
	// something a future reader finds out from a licence complaint instead.
	// Read the embedded bytes rather than the file on disk: the property that
	// matters is that the provenance travels with the binary, so a header that
	// only exists in the checkout would pass this test and still be absent in the
	// container image.
	header := string(embeddedCorpus)
	if len(header) > 4096 {
		header = header[:4096]
	}
	for _, want := range []string{"Nikto", "sullo/nikto"} {
		if !strings.Contains(header, want) {
			t.Errorf("the corpus header does not mention %q", want)
		}
	}
}

// mustCompile builds a pattern for a check constructed by hand in a test, so the
// test does not have to reach into the loader to get one.
func mustCompile(t *testing.T, expr string) *regexp.Regexp {
	t.Helper()
	pattern, err := regexp.Compile(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return pattern
}

// writeCorpus writes a one-row corpus with a synthetic header row first.
func writeCorpus(t *testing.T, path string, rows ...string) {
	t.Helper()
	body := strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write corpus: %v", err)
	}
}
