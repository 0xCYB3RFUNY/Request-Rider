package active

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// errTestBrowser stands for a browser that did not produce a page.
var errTestBrowser = errors.New("browser did not start")

// testTransport is the transport every proof suite needs, aimed at a server that
// answers nothing: these tests are about the browser, and a transport that cannot
// be built would fail them for a reason that is not theirs.
func testTransport(t *testing.T, handler http.Handler) *Transport {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return transport
}

// stubRenderer is a browser whose answer a test writes down.
//
// It is a stub in the strict sense and that is the point of these tests: they
// are about the *decision* — does the marker in the page's request list settle
// the row, and does anything else leave it alone — and each of them is paired
// with a live run against the real worker, which is the only thing that can say
// whether a browser executes the payload at all.
type stubRenderer struct {
	page BrowserPage
	err  error
	// got records what the renderer was asked to load, so a test can assert the
	// proof loaded the payload and not merely the endpoint.
	got []string
}

func (s *stubRenderer) Render(_ context.Context, target string) (BrowserPage, error) {
	s.got = append(s.got, target)
	return s.page, s.err
}

// anEscapeRow is the structural row the browser is asked to settle: a payload
// carrying the detector's own proof statement, at the structural tier.
func anEscapeRow() Finding {
	finding, _ := NewFinding(Spec{
		Module: "xss-escape", Title: "value reaches an unquoted attribute and escapes it",
		Claimed: SeverityHigh, Tier: TierPotential,
		Point: Point{
			URL: "http://fixture/x", Method: http.MethodGet, Param: "q",
		},
		Payload:  `<img src=x onerror=` + xsseProof + `>`,
		Evidence: "the page wrote the payload as a tag",
	})
	return finding
}

// TestTheBrowserSettlesAnEscapingRowItWatchedExecute is the whole decision in one
// test: the marker this run chose is in the page's own request list, so the row
// gains a proof and the proof says it was executed rather than reflected.
func TestTheBrowserSettlesAnEscapingRowItWatchedExecute(t *testing.T) {
	row := anEscapeRow()
	marker := xsseMarkerURL("rr.invalid", row.ID)
	if marker == "" {
		t.Fatal("no marker for a row with an id: the proof needs an address to watch for")
	}
	renderer := &stubRenderer{page: BrowserPage{
		URL: "http://fixture/x?q=payload", Status: 200,
		Network: []string{"http://fixture/x?q=payload", marker},
	}}
	suite := &Suite{Renderer: renderer, MarkerHost: "rr.invalid"}
	proof := suite.executeInBrowser(context.Background(), row)
	if proof == nil {
		t.Fatalf("no proof for a page that requested %s", marker)
	}
	if proof.Kind != "browser-execution" {
		t.Errorf("kind = %q, want browser-execution", proof.Kind)
	}
	if proof.FindingID != row.ID {
		t.Errorf("proof is filed against %q, want the row's own id %q", proof.FindingID, row.ID)
	}
	if !strings.Contains(proof.Proof, marker) {
		t.Errorf("proof = %q, want it to name the request that settled the row", proof.Proof)
	}
	// The address must carry the payload. A proof that ran against the bare
	// endpoint would show a clean page and produce nothing, and a test that only
	// checked the marker would pass while the proof could never work.
	if len(renderer.got) != 1 || !strings.Contains(renderer.got[0], "onerror") {
		t.Fatalf("renderer was asked for %v, want the endpoint carrying the payload", renderer.got)
	}
	if !strings.Contains(renderer.got[0], "fetch%28") && !strings.Contains(renderer.got[0], "fetch(") {
		t.Errorf("loaded %q, want the payload's statement replaced by the marker request", renderer.got[0])
	}
	if suite.browserAttempts != 1 {
		t.Errorf("browserAttempts = %d, want 1: the cost of asking a browser is reported", suite.browserAttempts)
	}
}

// TestTheStageTriesEachCandidateUntilOneRuns. A row that does not name its engine
// is offered every expression its module knows, and the stage stops at the first
// the page executes. Both halves matter: stopping at the first would settle a Vue
// 3 row on a 1.x-shaped page that happened to compile it, and trying all of them
// after a success would spend two more browser loads to learn nothing.
func TestTheStageTriesEachCandidateUntilOneRuns(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "csti", Title: "client-side template injection", Claimed: SeverityHigh,
		Tier: TierPotential, Point: Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
		Payload: cstiProbe, Evidence: "the page wrote the probe into an expression",
	})
	marker := xsseMarkerURL("rr.invalid", row.ID)
	candidates := cstiProofPayloads(row, marker)
	if len(candidates) < 2 {
		t.Fatalf("candidates = %v, want more than one to exercise the retry", candidates)
	}
	// A browser that runs only the last expression in the list: what a Vue 3 page
	// does, and the reason the list exists.
	renderer := &pickyRenderer{wants: candidates[len(candidates)-1]}
	suite := &Suite{Renderer: renderer, MarkerHost: "rr.invalid"}
	proof := suite.executeInBrowser(context.Background(), row)
	if proof == nil {
		t.Fatalf("no proof: a page that executed %q settles the row", candidates[len(candidates)-1])
	}
	if renderer.calls != len(candidates) {
		t.Errorf("the browser was asked %d time(s) for %d candidates, want one each: the stage "+
			"must try in order and stop at the first that runs", renderer.calls, len(candidates))
	}
	if !strings.Contains(proof.Proof, "$props") {
		t.Errorf("proof = %q, want it to name the expression that actually ran", proof.Proof)
	}
}

// TestOneBrokenBrowserLoadEndsTheRowRatherThanTheNextCandidate. An error from the
// renderer is the browser failing to load a page, and a browser that cannot load
// one page cannot load the next: retrying spends a full navigation per candidate
// to learn the same thing. So the first error ends the row — unproven, at the
// detector's tier — and the run's attempt count says one, not two.
func TestOneBrokenBrowserLoadEndsTheRowRatherThanTheNextCandidate(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "csti", Title: "client-side template injection", Claimed: SeverityHigh,
		Tier: TierPotential, Point: Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
		Payload: cstiProbe, Evidence: "the page wrote the probe into an expression",
	})
	broken := &countingErrorRenderer{}
	suite := &Suite{Renderer: broken, MarkerHost: "rr.invalid"}
	if proof := suite.executeInBrowser(context.Background(), row); proof != nil {
		t.Fatalf("proof = %+v, want none from a browser that could not load the page", proof)
	}
	candidates := len(cstiProofPayloads(row, xsseMarkerURL("rr.invalid", row.ID)))
	if broken.calls != 1 || candidates < 2 {
		t.Errorf("the browser was asked %d time(s) for %d candidates, want 1: a dead browser "+
			"does not become a working one on the second try", broken.calls, candidates)
	}
}

// countingErrorRenderer always fails, and remembers how often it was asked.
type countingErrorRenderer struct{ calls int }

func (c *countingErrorRenderer) Render(context.Context, string) (BrowserPage, error) {
	c.calls++
	return BrowserPage{}, errTestBrowser
}

// TestTheStageOpensWithTheRowsOwnSpelling is the ordering seen from the stage,
// where the cost is real: the executable table is 25 shapes and each navigation
// costs seconds, so a row settled only after the walk paid two dozen page loads to
// learn something the report already said.
func TestTheStageOpensWithTheRowsOwnSpelling(t *testing.T) {
	late := domVectors[20]
	row, _ := NewFinding(Spec{
		Module: "dom-vectors", Title: "filter bypass: " + late.name, Claimed: SeverityHigh,
		Tier: TierPotential,
		// The row's payload carries the detector's probe marker, not this run's, so
		// the ordering has to match by shape — which is what the stage does.
		Payload: "<svg><animate onbegin=fetch('rrprobe') attributeName=x dur=1s>",
		Point:   Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
	})
	marker := xsseMarkerURL("rr.invalid", row.ID)
	candidates := domVectorProofPayloads(row, marker)
	if len(candidates) == 0 || !strings.Contains(candidates[0], "$") && !strings.Contains(candidates[0], "animate") {
		t.Fatalf("candidates[0] = %q, want the row's own shape (the svg animate spelling) first",
			candidates[:1])
	}
	renderer := &pickyRenderer{wants: candidates[0]}
	suite := &Suite{Transport: testTransport(t, nil), Renderer: renderer, MarkerHost: "rr.invalid"}
	if proofs := suite.Run(context.Background(), []Finding{row}); len(proofs) != 1 {
		t.Fatalf("proofs = %+v, want one", proofs)
	}
	if renderer.calls != 1 {
		t.Errorf("the browser was asked %d time(s), want 1: the row's own spelling is the one that "+
			"reached the page", renderer.calls)
	}
}

// TestTheStageStillWalksTheTableWhenTheRowsOwnShapeDoesNotRun. The ordering is an
// ordering, not a filter: a row whose own spelling reflects but does not execute
// still gets the rest of the list, because the shape that runs may be a different
// one — which is exactly the filter-bypass case this table exists for.
func TestTheStageStillWalksTheTableWhenTheRowsOwnShapeDoesNotRun(t *testing.T) {
	// The row's own shape is in the list and is tried first, and does not run here —
	// so the walk has to continue to the shapes the row did not report.
	row, _ := NewFinding(Spec{
		Module: "dom-vectors", Title: "filter bypass", Claimed: SeverityHigh,
		Tier:    TierPotential,
		Payload: "<svg><animate onbegin=fetch('rrprobe') attributeName=x dur=1s>",
		Point:   Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
	})
	marker := xsseMarkerURL("rr.invalid", row.ID)
	candidates := domVectorProofPayloads(row, marker)
	if len(candidates) < 3 {
		t.Fatalf("candidates = %v, want the whole table after the row's own shape", candidates)
	}
	renderer := &pickyRenderer{wants: candidates[2]}
	suite := &Suite{Transport: testTransport(t, nil), Renderer: renderer, MarkerHost: "rr.invalid"}
	if proofs := suite.Run(context.Background(), []Finding{row}); len(proofs) != 1 {
		t.Fatalf("proofs = %+v, want one: the table is the fallback, not the first choice", proofs)
	}
	if renderer.calls != 3 {
		t.Errorf("the browser was asked %d time(s), want 3", renderer.calls)
	}
}

// pickyRenderer executes only the expression it was told to, and reports the
// requests that expression makes. The address it receives is percent-encoded, so
// it compares the decoded form.
type pickyRenderer struct {
	wants string
	calls int
}

func (p *pickyRenderer) Render(_ context.Context, target string) (BrowserPage, error) {
	p.calls++
	decoded, err := url.QueryUnescape(target)
	if err != nil {
		decoded = target
	}
	marker := markerInTarget(target)
	if !strings.Contains(decoded, p.wants) || marker == "" {
		return BrowserPage{URL: target, Status: 200, Network: []string{target}}, nil
	}
	return BrowserPage{URL: target, Status: 200, Network: []string{target, marker}}, nil
}

// markerInTarget reads the marker URL out of the loaded address.
func markerInTarget(target string) string {
	decoded := target
	if unescaped, err := url.QueryUnescape(target); err == nil {
		decoded = unescaped
	}
	// Three call shapes carry the marker, because upstream's table puts its payload in
	// three positions: `fetch(http://…)` where the slot replaced a call's argument,
	// `fetch('http://…')` where it became a handler body, and the same with double
	// quotes where the shape quoted it itself.
	match := regexp.MustCompile(`fetch\((?:"([^"]*)"|'([^']*)'|([^()]+))\)`).FindStringSubmatch(decoded)
	if len(match) < 2 {
		return ""
	}
	for _, group := range match[1:] {
		if strings.TrimSpace(group) != "" {
			return strings.TrimSpace(group)
		}
	}
	return ""
}

// TestTheBrowserLeavesEveryUnprovenOutcomeAlone is the other half, and it is the
// half that matters most: an unproven execution must leave the row exactly as the
// detector left it. A proof that raises a tier on a failure, on an absent
// renderer, or on a substring match is worse than no proof, because it converts a
// capability's absence into a claim.
func TestTheBrowserLeavesEveryUnprovenOutcomeAlone(t *testing.T) {
	row := anEscapeRow()
	cases := []struct {
		name  string
		suite *Suite
		page  BrowserPage
		err   error
	}{
		{"no renderer at all", &Suite{MarkerHost: "rr.invalid"}, BrowserPage{}, nil},
		{"no marker host", &Suite{Renderer: &stubRenderer{}}, BrowserPage{}, nil},
		{"the browser failed", &Suite{Renderer: &stubRenderer{err: errTestBrowser}, MarkerHost: "rr.invalid"},
			BrowserPage{}, errTestBrowser},
		{"the page asked for something else",
			&Suite{Renderer: &stubRenderer{page: BrowserPage{Network: []string{"http://fixture/x"}}}, MarkerHost: "rr.invalid"},
			BrowserPage{}, nil},
		{"the page reflected the payload but requested nothing",
			&Suite{Renderer: &stubRenderer{page: BrowserPage{Network: []string{"http://fixture/x?q=fetch"}}}, MarkerHost: "rr.invalid"},
			BrowserPage{}, nil},
		{"a longer url carries the marker as a prefix",
			// The strictness has a cost, and this is it: a page that rewrites the
			// marker before requesting it — a cache-buster, a proxy that appends a
			// query — is an execution this proof declines rather than guesses about.
			// The row keeps the structural tier, which understates the finding
			// instead of inventing one.
			&Suite{Renderer: &stubRenderer{page: BrowserPage{Network: []string{
				xsseMarkerURL("rr.invalid", anEscapeRow().ID) + "?cb=1"}}}, MarkerHost: "rr.invalid"},
			BrowserPage{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if proof := tc.suite.executeInBrowser(context.Background(), row); proof != nil {
				t.Fatalf("proof = %+v, want none: nothing here demonstrated execution", proof)
			}
		})
	}
}

// TestTheBrowserDeclinesAPayloadItCannotRewrite. The `javascript:` URI shape needs
// a click, so its payload carries no statement this proof can substitute — and a
// rewriter that guessed would produce a payload the structural confirmations never
// described.
func TestTheBrowserDeclinesAPayloadItCannotRewrite(t *testing.T) {
	row := anEscapeRow()
	row.Payload = xsseLinkPayload("rrc")
	row.ID = "link-row"
	renderer := &stubRenderer{page: BrowserPage{Network: []string{"http://rr.invalid/rrxe/link-row"}}}
	suite := &Suite{Renderer: renderer, MarkerHost: "rr.invalid"}
	if proof := suite.executeInBrowser(context.Background(), row); proof != nil {
		t.Fatalf("proof = %+v, want none: the payload carries no statement to replace", proof)
	}
	if len(renderer.got) != 0 {
		t.Errorf("renderer was asked for %v, want nothing: a declined proof must cost no browser time", renderer.got)
	}
	if suite.browserAttempts != 0 {
		t.Errorf("browserAttempts = %d, want 0 for a proof that declined before asking", suite.browserAttempts)
	}
}

// TestTheMarkerIsSafeInsideTheStatementThatCarriesIt. A marker containing a
// quote would end the JavaScript string it is written in, so the payload would
// stop being the payload — and the proof would then report on a page the
// detector never described.
func TestTheMarkerIsSafeInsideTheStatementThatCarriesIt(t *testing.T) {
	for _, host := range []string{"rr.invalid", "rr-abc123.invalid", "oast.example"} {
		marker := xsseMarkerURL(host, "AbC-123_x")
		if marker == "" {
			t.Fatalf("no marker for host %q", host)
		}
		if strings.ContainsAny(marker, "'\"`\\<>") || strings.Contains(marker, " ") {
			t.Errorf("marker %q carries a character that would break the statement carrying it", marker)
		}
	}
	// A finding id is a hash from the report's own scheme, and the marker is
	// written into a URL path, so the token has to be reduced to path characters.
	if got := xsseMarkerToken("A/B?C#D"); got != "abcd" {
		t.Errorf("token = %q, want %q", got, "abcd")
	}
	if got := xsseMarkerURL("rr.invalid", "///"); got != "" {
		t.Errorf("marker = %q, want none: a token that reduces to nothing must not produce a bare path", got)
	}
}

// TestTheMarkerIsPerRow. One shared address would let one row's execution stand
// in for another's: the suite checks rows in order, and a target with two
// injections would see the first row's marker requested and then settle the
// second row on that answer. The row's own id is what keeps the two apart.
func TestTheMarkerIsPerRow(t *testing.T) {
	first := anEscapeRow()
	second := anEscapeRow()
	second.Payload = `<svg onload=` + xsseProof + `>`
	second.ID = FindingID("xss-escape", Point{URL: "http://fixture/y", Method: http.MethodGet, Param: "q"},
		second.Payload)
	if first.ID == second.ID {
		t.Fatal("the two rows share an id, so the test below would prove nothing")
	}
	one, two := xsseMarkerURL("rr.invalid", first.ID), xsseMarkerURL("rr.invalid", second.ID)
	if one == "" || two == "" {
		t.Fatalf("markers = %q, %q: both rows need an address", one, two)
	}
	if one == two {
		t.Fatalf("both rows watch %q, so one execution settles both", one)
	}
	// And the settlement is checked against the row's own marker: a page that
	// requested the *other* row's marker leaves this one exactly where the
	// detector left it.
	renderer := &stubRenderer{page: BrowserPage{Network: []string{two}}}
	suite := &Suite{Renderer: renderer, MarkerHost: "rr.invalid"}
	if proof := suite.executeInBrowser(context.Background(), first); proof != nil {
		t.Fatalf("proof = %+v, want none: the page requested another row's marker", proof)
	}
}

// TestTheProofURLKeepsTheParameterUnderTest. The proof loads one surface, and a
// URL that dropped the parameter would load a clean page and prove nothing —
// which looks identical to a target that refused to execute.
func TestTheProofURLKeepsTheParameterUnderTest(t *testing.T) {
	row := anEscapeRow()
	url := proofURL(row, "PAYLOAD")
	if !strings.Contains(url, "q=PAYLOAD") {
		t.Errorf("url = %q, want it to carry the parameter under test", url)
	}
	// An endpoint that already carries a query keeps it: a proof that dropped the
	// rest of the request is no longer the request the detector proved.
	row.Endpoint = "http://fixture/x?page=3"
	if url := proofURL(row, "PAYLOAD"); !strings.Contains(url, "page=3") || !strings.Contains(url, "q=PAYLOAD") {
		t.Errorf("url = %q, want both the existing query and the parameter under test", url)
	}
	if proofURL(Finding{Endpoint: "http://fixture/x"}, "P") != "" {
		t.Error("a row with no parameter produced a url: it has nothing to prove")
	}
}

// TestTheSuiteRunsTheBrowserProofAboveTheTierGate. Every other proof is gated on a
// row that already showed an impact; this one is that showing. Gating it on
// `TierVerified` would gate it on the outcome it produces, and the gate test
// below fails if the row comes back unraised.
func TestTheSuiteRunsTheBrowserProofAboveTheTierGate(t *testing.T) {
	row := anEscapeRow()
	marker := xsseMarkerURL("rr.invalid", row.ID)
	suite := &Suite{
		Transport:  testTransport(t, nil),
		Renderer:   &stubRenderer{page: BrowserPage{Network: []string{marker}}},
		MarkerHost: "rr.invalid",
	}
	proofs := suite.Run(context.Background(), []Finding{row})
	if len(proofs) != 1 {
		t.Fatalf("proofs = %d, want 1: a structural escape row is exactly the row a browser settles", len(proofs))
	}
	if !proofs[0].Upgrades {
		t.Error("proof.Upgrades = false: the row this proof came from was not verified")
	}
	// And the upgrade actually lands, which is the part the gate would have
	// silently skipped.
	findings := []Finding{row}
	applyProofUpgrades(findings, proofs)
	if findings[0].Tier != TierVerified {
		t.Errorf("tier = %v, want verified: a page that requested this run's marker executed the script",
			findings[0].Tier)
	}
}

// TestTheSuiteWithoutABrowserProvesNothingAndSaysSo. A run with no renderer has
// to look different from a run whose browser found nothing, or two reports
// compare equal when they are not.
func TestTheSuiteWithoutABrowserProvesNothingAndSaysSo(t *testing.T) {
	row := anEscapeRow()
	suite := &Suite{Transport: testTransport(t, nil), MarkerHost: "rr.invalid"}
	if proofs := suite.Run(context.Background(), []Finding{row}); len(proofs) != 0 {
		t.Fatalf("proofs = %+v, want none without a renderer", proofs)
	}
}
