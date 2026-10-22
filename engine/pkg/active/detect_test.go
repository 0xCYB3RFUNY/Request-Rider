package active

// Tests for the shared detector primitives.
//
// The primitives are where the false-positive decisions are made, so they are
// tested directly rather than only through one detector. A mutation that makes
// Fresh accept a nil baseline is invisible to every detector-level test in the
// package — each of them supplies a real one — which is why the guard gets its
// own assertions here.

import (
	"net/http"
	"strings"
	"testing"
)

func body(text string) *Response {
	return &Response{StatusCode: 200, Header: http.Header{}, Body: text}
}

// A fingerprint that was already on the page is a property of the page. This is
// the check that separates a detector from a substring search, and it is the one
// a detector that skips it cannot make.
func TestFreshRequiresTheFingerprintToBeNew(t *testing.T) {
	baseline := body(`<p>Last failed query: you have an error in your SQL syntax</p>`)
	injected := body(`<p>Last failed query: you have an error in your SQL syntax</p><div>Item 1</div>`)
	if Fresh(baseline, injected, "you have an error in your SQL syntax") {
		t.Error("Fresh accepted a fingerprint the baseline already carried")
	}
	if Fresh(baseline, body(`<p>you have an error in your SQL syntax</p>`), "you have an error in your SQL syntax") {
		t.Error("Fresh accepted a fingerprint present in the baseline")
	}
	// A baseline that never carried the fingerprint, so the third assertion
	// tests what it claims to: a fingerprint the injection introduced.
	clean := body(`<div>Item 1</div>`)
	if !Fresh(clean, body(`<p>fine</p><p>you have an error in your SQL syntax</p>`), "you have an error in your SQL syntax") {
		t.Error("Fresh rejected a fingerprint the injection introduced")
	}
}

// A case-insensitive fingerprint is the only kind that works against a database,
// which does not promise capitalisation. A case-sensitive test against a
// lowercase pattern misses the most common diagnostic in existence.
func TestFreshFoldIgnoresCase(t *testing.T) {
	baseline := body(`<div>Item 1</div>`)
	for _, injected := range []string{
		`You have an error in your SQL syntax`,
		`you have an error in your SQL syntax`,
		`YOU HAVE AN ERROR IN YOUR SQL SYNTAX`,
	} {
		if !FreshFold(baseline, body(injected), "you have an error in your sql syntax") {
			t.Errorf("FreshFold missed %q", injected)
		}
	}
	if FreshFold(body(`YOU HAVE AN ERROR IN YOUR SQL SYNTAX`), body(`fine`), "you have an error in your sql syntax") {
		t.Error("FreshFold accepted a fingerprint already on the page, in another case")
	}
}

// The mutation-proof case: with no baseline there is no way to tell "already
// there" from "appeared", so a fingerprint proves nothing.
func TestFreshRefusesWithoutABaseline(t *testing.T) {
	injected := body(`you have an error in your SQL syntax`)
	if Fresh(nil, injected, "you have an error in your SQL syntax") {
		t.Error("Fresh accepted a fingerprint with no baseline to compare against")
	}
	if FreshFold(nil, injected, "you have an error in your sql syntax") {
		t.Error("FreshFold accepted a fingerprint with no baseline to compare against")
	}
	// A nil injected response is a failed request, not an empty page.
	if Fresh(body(`x`), nil, "anything") {
		t.Error("Fresh accepted a nil response")
	}
	if Fresh(body(`x`), body(`anything at all`), "") {
		t.Error("Fresh accepted an empty fingerprint, which every body contains")
	}
}

func TestChangedRequiresBothResponses(t *testing.T) {
	if !Changed(body(`a`), body(`b`)) {
		t.Error("Changed rejected two different bodies")
	}
	if Changed(body(`a`), body(`a`)) {
		t.Error("Changed accepted two identical bodies")
	}
	if Changed(nil, body(`b`)) {
		t.Error("Changed accepted a difference with no baseline")
	}
	if Changed(body(`a`), nil) {
		t.Error("Changed accepted a difference with no injected response")
	}
}

// Divergence is the measure a differential detector reads. It has to be
// exactly 0 for identical documents, and it has to be relative to the document
// rather than to a set of shingles — the boilerplate case is the one that
// matters and it is where the obvious implementations go wrong.
func TestDivergenceBounds(t *testing.T) {
	if got := Divergence("same document", "same document"); got != 0 {
		t.Errorf("identical documents scored %v, want 0", got)
	}
	if got := Divergence("", ""); got != 0 {
		t.Errorf("two empty documents scored %v, want 0", got)
	}
	if got := Divergence("abc", ""); got == 0 {
		t.Error("a document against an empty one must score above 0")
	}

	// One word in a thousand characters is a small change, whatever the
	// document is made of.
	long := strings.Repeat("the quick brown fox jumps over the lazy dog ", 20)
	near := strings.Replace(long, "lazy", "eager", 1)
	if got := Divergence(long, near); got > 0.05 {
		t.Errorf("one word in %d bytes scored %v, want a small divergence", len(long), got)
	}

	// The same change in a short line is a large one. A measure that scored
	// both of these alike would be reporting shingles, not content.
	short := "Item 1"
	shortNear := "Item 2"
	if got := Divergence(short, shortNear); got < 0.2 {
		t.Errorf("one character in %q scored %v, want a large divergence", short, got)
	}

	// The case that breaks a 4-gram count of any kind: shared boilerplate at
	// the end must not be charged as change. A set-based score calls this a
	// large difference; a frequency-based one calls it a small one. What the
	// detector needs is that it is the *body* that changed.
	boilerplate := strings.Repeat("<footer>nav link copyright</footer>", 20)
	withBanner := "<main>Account</main><div class=\"ad\">Sale</div>" + boilerplate
	plain := "<main>Account</main>" + boilerplate
	divergence := Divergence(plain, withBanner)
	if divergence > 0.2 {
		t.Errorf("a changed body with %d bytes of shared footer scored %v, want the footer ignored",
			len(boilerplate), divergence)
	}
}

// The UNION test reduces an added region to its readable text. Markup is
// structure, not content, so an empty cell passes and a banner does not.
func TestReadableTextSeparatesMarkupFromContent(t *testing.T) {
	cases := []struct{ name, region, want string }{
		{"empty cell", `<td></td><td></td>`, ""},
		{"nbsp cell", `<td>&nbsp;</td>`, " "},
		{"attribute text", `<a title="promo">x</a>`, "x"},
		{"plain text", `Welcome back`, "Welcome back"},
		{"entity decoded", `&amp;`, "&"},
	}
	for _, tc := range cases {
		if got := readableText(tc.region); got != tc.want {
			t.Errorf("%s: readableText(%q) = %q, want %q", tc.name, tc.region, got, tc.want)
		}
	}
}

func TestAddedIsBlank(t *testing.T) {
	baseline := `<table><tr><td>Item 1</td></tr>`
	if !addedIsBlank(baseline, `<table><tr><td>Item 1</td></tr><tr><td></td></tr>`) {
		t.Error("an extra empty row is what a UNION of NULLs looks like; it must pass")
	}
	if addedIsBlank(baseline, `<table><tr><td>Item 1</td></tr><tr><td>Sale ends soon</td></tr>`) {
		t.Error("an extra row with text is a banner, not a NULL column")
	}
	if addedIsBlank(baseline, baseline+"<p>New arrivals</p>") {
		t.Error("added copy must fail")
	}
	// A response identical to the baseline adds nothing and so is blank, which
	// is why the caller also requires it to be longer.
	if !addedIsBlank(baseline, baseline) {
		t.Error("an unchanged response adds nothing readable")
	}
}

// The session baseline is what a detector is handed. A failed request has to
// surface as nil rather than as an empty response, or every detector would treat
// a connection failure as a page that said nothing interesting.
func TestSessionBaselineReportsFailureAsNil(t *testing.T) {
	transport := mustTransport(t)
	session := &Session{Transport: transport, Target: "http://target.test"}
	point := Point{URL: "http://127.0.0.1:1/closed", Method: "GET", Param: "q", Values: map[string][]string{"q": {"1"}}}
	if got := session.Baseline(t.Context(), point); got != nil {
		t.Fatalf("Baseline = %#v, want nil for an unreachable target", got)
	}
}
