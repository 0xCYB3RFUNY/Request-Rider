package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheVectorTableIsUpstreamsTable is the transcription check: 27 shapes, in the
// order xsser lists them, with the names that make each row readable.
//
// The count is pinned from the upstream file rather than remembered: `core/fuzzing/DOM.py`
// declares `DOMvectors` with 27 entries and a table that drifts from it silently
// loses a spelling while every test stays green.
func TestTheVectorTableIsUpstreamsTable(t *testing.T) {
	if len(domVectors) != 27 {
		t.Fatalf("vectors = %d, want 27: xsser's core/fuzzing/DOM.py declares 27 DOMvectors, "+
			"and a table that drifts from it loses a spelling while the tests stay green",
			len(domVectors))
	}
	for _, vector := range domVectors {
		if vector.name == "" {
			t.Errorf("a vector has no name: %q", vector.shape)
		}
		if strings.Count(vector.shape, "%s") != 1 {
			t.Errorf("%s: shape %q must carry exactly one slot", vector.name, vector.shape)
		}
		if !strings.HasPrefix(vector.shape, "Y#") {
			t.Errorf("%s: shape %q lost xsser's prefix, and the table has to stay comparable "+
				"with upstream line by line", vector.name, vector.shape)
		}
	}
}

// TestEveryVectorCarriesTheMarkerIntoValidSyntax is the property the three slot
// kinds exist for. A single substitution would produce a payload that is not
// JavaScript for at least one of the three positions, and a non-script payload in
// a browser proof is a payload that reports "the page refused" for a reason that
// was never the page's.
func TestEveryVectorCarriesTheMarkerIntoValidSyntax(t *testing.T) {
	marker := "http://rr.invalid/rrxe/row"
	for _, vector := range domVectors {
		payload, ok := domVectorPayload(vector, marker)
		if !ok {
			t.Errorf("%s: no payload built", vector.name)
			continue
		}
		if strings.Contains(payload, "Y#") {
			t.Errorf("%s: payload %q still carries xsser's own marker", vector.name, payload)
		}
		if !strings.Contains(payload, "rrxe") {
			t.Errorf("%s: payload %q does not carry this run's marker", vector.name, payload)
		}
		if strings.Contains(payload, "alert(") {
			t.Errorf("%s: payload %q still calls alert: the dialog is what makes a scanner "+
				"uninstallable", vector.name, payload)
		}
		// The three positions, checked by what each must look like.
		switch vector.statement {
		case domStatementCall:
			if !strings.Contains(payload, "fetch("+marker+")") {
				t.Errorf("%s: payload %q does not call fetch with the marker as its argument",
					vector.name, payload)
			}
		case domStatementBody:
			if !strings.Contains(payload, "fetch('"+marker+"')") {
				t.Errorf("%s: payload %q does not use the marker as a handler body", vector.name, payload)
			}
		case domStatementSource:
			if !strings.Contains(payload, `\/rrxe\/row`) {
				t.Errorf("%s: payload %q puts the marker in a regex source without escaping "+
					"the slashes, so the evaluated request would not be the marker", vector.name, payload)
			}
		}
		if strings.Contains(payload, "%s") {
			t.Errorf("%s: payload %q still carries its slot", vector.name, payload)
		}
		// The two shapes whose payload travels as evaluated text have no request to
		// watch for, so they are reported and never offered to the browser. This
		// asserts the table agrees with itself about which is which, in both
		// directions: offering a shape with no request, and withholding one that has.
		offered := domVectorProofPayloads(Finding{Module: "dom-vectors"}, marker)
		present := false
		for _, candidate := range offered {
			if candidate == payload {
				present = true
				break
			}
		}
		if vector.executedByRequest && !present {
			t.Errorf("%s: payload %q is marked executable but the browser stage does not offer it",
				vector.name, payload)
		}
		if !vector.executedByRequest && present {
			t.Errorf("%s: payload %q travels as evaluated text, so a request-carrying "+
				"marker cannot prove it, yet the browser stage offers it", vector.name, payload)
		}
	}
}

// TestTheVectorProofsAreTheTableInOrder is what the browser stage is handed, and
// the order is the escalation: the shape upstream puts first is the one a page is
// most likely to run, and a row settled on the first load costs one navigation.
func TestTheVectorProofsAreTheTableInOrder(t *testing.T) {
	marker := "http://rr.invalid/rrxe/row"
	candidates := domVectorProofPayloads(Finding{Module: "dom-vectors"}, marker)
	if len(candidates) == 0 {
		t.Fatal("a dom-vectors row was offered nothing to execute")
	}
	first, _ := domVectorPayload(domVectors[0], marker)
	if candidates[0] != first {
		t.Errorf("first candidate = %q, want the table's first shape %q", candidates[0], first)
	}
	if len(candidates) > len(domVectors) {
		t.Errorf("candidates = %d, more than the table's %d", len(candidates), len(domVectors))
	}
	// A row from another module gets nothing: sending it a spelling its detector
	// never described would prove something nobody wrote down.
	if got := domVectorProofPayloads(Finding{Module: "xss-escape"}, marker); got != nil {
		t.Errorf("a foreign row was offered %d spellings, want none", len(got))
	}
	if got := domVectorProofPayloads(Finding{Module: "dom-vectors"}, ""); got != nil {
		t.Errorf("a row with no marker was offered %d spellings, want none", len(got))
	}
}

// domVectorTarget is a reflecting surface that either filters the two characters
// every shape is built from or does not.
//
// The filtering case is the surface the table exists for: the application escapes
// `<` and `>`, so the shapes built from a literal tag are reflected escaped and
// only the encoded spellings survive. The unfiltered case is the control, and it
// is a different handler rather than the same one with a flag, because a
// "no filter" that still escaped something would be neither.
func domVectorTarget(t *testing.T, filtered bool) (*httptest.Server, *Transport) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		if filtered {
			value = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(value)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div class="result">` + value +
			`</div><form method="get"><input name="q" value=""></form></body></html>`))
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return server, transport
}

func domVectorPoint(target string) Point {
	return Point{URL: target, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}}, Source: "query"}
}

// TestDOMVectorsSpendItsTableOnlyWhereAFilterBlocksThePlainShape. The gate is the
// whole reason the module is affordable, so it is the thing under test: 27 requests
// on every surface of every site is a scan nobody runs.
func TestDOMVectorsSpendItsTableOnlyWhereAFilterBlocksThePlainShape(t *testing.T) {
	// A surface that filters `<` and `>`: the plain shape cannot work and the
	// encoded spellings can.
	server, transport := domVectorTarget(t, true)
	findings := (DOMVectors{}).Scan(context.Background(), transport, domVectorPoint(server.URL),
		&Response{Body: `<html><body><div class="result">hello</div></body></html>`})
	if len(findings) == 0 {
		t.Fatal("no rows on a surface that filters the plain shape: the table is the answer " +
			"there and it stayed silent")
	}
	// Every row is a potential: a spelling that reached the page proves nothing
	// until the browser runs it, and this module has no way to run it.
	for _, row := range findings {
		if row.Tier != TierPotential {
			t.Errorf("%s: tier = %v, want potential", row.Payload, row.Tier)
		}
		if !strings.Contains(row.Title, "filter bypass") {
			t.Errorf("%s: title = %q, want it to say the filter was bypassed", row.Payload, row.Title)
		}
	}
	// A surface with no filter at all is where the structural detector already
	// works, so this module must add nothing there.
	open, openTransport := domVectorTarget(t, false)
	if rows := (DOMVectors{}).Scan(context.Background(), openTransport, domVectorPoint(open.URL),
		&Response{Body: `<html><body><div class="result">hello</div></body></html>`}); len(rows) != 0 {
		t.Errorf("an unfiltered surface produced %d rows: the plain shape works there and the "+
			"escalation has nothing to add", len(rows))
	}
}

// TestDOMVectorsNeedsAValueThatIsReflectedAtAll. A surface that drops the parameter
// cannot be escaped, and a table sent to it measures the scanner's budget rather
// than the target.
func TestDOMVectorsNeedsAValueThatIsReflectedAtAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><p>nothing here</p></body></html>`))
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if rows := (DOMVectors{}).Scan(context.Background(), transport, domVectorPoint(server.URL),
		&Response{Body: `<html><body><p>nothing here</p></body></html>`}); len(rows) != 0 {
		t.Errorf("rows = %d on a surface that reflects nothing, want 0", len(rows))
	}
	// And with no baseline at all: the same rule the package keeps everywhere.
	if rows := (DOMVectors{}).Scan(context.Background(), transport, domVectorPoint(server.URL), nil); len(rows) != 0 {
		t.Errorf("rows = %d without a baseline, want 0: nothing could be told from nothing", len(rows))
	}
}

// TestTheBrowserStageRunsTheSpellingThatReachedThePage. The stub executes only the
// shape whose name the finding carries, which is how a real page behaves: it runs
// the one that got through.
func TestTheBrowserStageRunsTheSpellingThatReachedThePage(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "dom-vectors", Title: "filter bypass: img onerror", Claimed: SeverityHigh,
		Tier:    TierPotential,
		Point:   Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
		Payload: `<img src=x onerror=fetch('rrprobe')>`,
	})
	marker := xsseMarkerURL("rr.invalid", row.ID)
	executed, _ := domVectorPayload(domVectors[15], marker)
	renderer := &pickyRenderer{wants: executed}
	// The number of loads is the position of that shape in the candidate list, read
	// from the list rather than written down: a table that gained or lost a shape
	// would otherwise make this assertion wrong for the wrong reason.
	candidates := domVectorProofPayloads(row, marker)
	position := 0
	for i, candidate := range candidates {
		if candidate == executed {
			position = i + 1
			break
		}
	}
	if position == 0 {
		t.Fatalf("the shape that reached the page is not in the candidate list: %v", candidates)
	}
	suite := &Suite{Transport: testTransport(t, nil), Renderer: renderer, MarkerHost: "rr.invalid"}
	proofs := suite.Run(context.Background(), []Finding{row})
	if len(proofs) != 1 {
		t.Fatalf("proofs = %+v, want one: the page ran the spelling that got through", proofs)
	}
	if renderer.calls != position {
		t.Errorf("the browser was asked %d time(s), want %d: the table's order, up to the shape "+
			"that ran", renderer.calls, position)
	}
	findings := []Finding{row}
	applyProofUpgrades(findings, proofs)
	if findings[0].Tier != TierVerified {
		t.Errorf("tier = %v, want verified: the page requested the expression's marker",
			findings[0].Tier)
	}
}
