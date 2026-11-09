package active

// Tests for the injection-surface enumeration.
//
// These assertions are all about a transformation of a string, which is the
// reason this file has no network in it: when one of them fails, the failure
// names the transformation and not a socket. The corpus below is real markup
// rather than a hand-drawn minimum, because the cases that break a form
// parser — an unquoted attribute, a `data-` prefixed lookalike, a select whose
// options carry the value, a form with no action at all — are exactly the ones
// a minimal example leaves out.

import (
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// keysOf renders a point list as "METHOD url [source] param" lines, sorted, so
// an assertion reads as a list of surfaces instead of a wall of struct fields.
func keysOf(points []Point) []string {
	out := make([]string, 0, len(points))
	for _, p := range points {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

func hasField(values url.Values, key string) bool {
	_, ok := values[key]
	return ok
}

func TestHarvestReadsQueryStringParameters(t *testing.T) {
	points := Harvest("http://target.test/search?q=shoes&page=2", "", "text/html")
	got := keysOf(points)
	want := []string{
		"GET http://target.test/search [query] page",
		"GET http://target.test/search [query] q",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("query surfaces = %v, want %v", got, want)
	}
}

// The query string is the surface that needs no markup, so it must survive on a
// response type that has no forms at all. Dropping it for a JSON body would
// report an API endpoint as having no injectable parameters.
func TestHarvestReadsQueryOnNonHTMLResponse(t *testing.T) {
	points := Harvest("http://target.test/api/v1/items?limit=10", `{"ok":true}`, "application/json")
	got := keysOf(points)
	want := []string{"GET http://target.test/api/v1/items [query] limit"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("json query surfaces = %v, want %v", got, want)
	}
}

// Every value a page submits is part of the baseline, not just the field under
// attack. A probe that dropped the sibling parameters would be testing a
// different request than the one a user sends.
func TestHarvestKeepsSiblingQueryValues(t *testing.T) {
	points := Harvest("http://target.test/search?q=shoes&page=2", "", "text/html")
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2", len(points))
	}
	for _, p := range points {
		if got := p.Values.Get("q"); got != "shoes" {
			t.Errorf("point %s lost sibling q = %q, want %q", p.Param, got, "shoes")
		}
		if got := p.Values.Get("page"); got != "2" {
			t.Errorf("point %s lost sibling page = %q, want %q", p.Param, got, "2")
		}
	}
}

// A repeated key is one parameter of the application. Splitting it would make
// the report claim coverage of two surfaces when the payload only ever reached
// one position.
func TestHarvestTreatsRepeatedQueryKeyAsOneSurface(t *testing.T) {
	points := Harvest("http://target.test/list?tag=a&tag=b&tag=c", "", "text/html")
	if len(points) != 1 {
		t.Fatalf("points = %d (%v), want 1 surface for a repeated key", len(points), keysOf(points))
	}
	if got := points[0].Values.Get("tag"); got != "a" {
		t.Fatalf("baseline tag = %q, want the first value %q", got, "a")
	}
}

func TestHarvestReadsFormFieldsWithMethodAndAction(t *testing.T) {
	body := `<html><body>
	<form action="/login" method="POST">
		<input type="text" name="user" value="admin">
		<input type="password" name="pass" value="">
		<input type="submit" value="Log in">
	</form>
	</body></html>`
	points := Harvest("http://target.test/account", body, "text/html; charset=utf-8")
	got := keysOf(points)
	want := []string{
		"POST http://target.test/login [form] pass",
		"POST http://target.test/login [form] user",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("form surfaces = %v, want %v", got, want)
	}
}

// A submit control has no name of its own on most pages. Emitting a surface for
// it would report a parameter that exists in no request a browser sends.
func TestHarvestSkipsUnnamedSubmit(t *testing.T) {
	body := `<form method="post" action="/x"><input type="submit" value="Go"></form>`
	points := Harvest("http://target.test/", body, "text/html")
	if len(points) != 0 {
		t.Fatalf("points = %v, want none for a nameless submit", keysOf(points))
	}
}

// The empty and fragment-only action cases are the specification's rule: a form
// with no action submits to the page it sits on. Treating that as an error would
// silently drop every single-page form on the web.
func TestHarvestTreatsEmptyAndFragmentActionAsCurrentPage(t *testing.T) {
	for _, action := range []string{`action=""`, `action="#"`, ""} {
		body := `<form method="POST" ` + action + `><input name="q" value="x"></form>`
		points := Harvest("http://target.test/search", body, "text/html")
		if len(points) != 1 {
			t.Fatalf("action %q: points = %v, want 1", action, keysOf(points))
		}
		got := points[0]
		if got.Method != "POST" || got.Param != "q" {
			t.Fatalf("action %q: got %s, want POST .../search [form] q", action, got)
		}
		if got.URL != "http://target.test/search" {
			t.Fatalf("action %q: url = %q, want the page it sits on", action, got.URL)
		}
	}
}

// A GET form replaces the query string of its action; it does not append to it.
// That is the HTML specification's rule and therefore the browser's, so a probe
// that appended would be comparing its baseline against a request no user ever
// sent. The page's own query is dropped for the same reason, while the form's
// own fields become the new query.
func TestHarvestGetFormReplacesActionQuery(t *testing.T) {
	body := `<form action="/go?a=1&amp;b=2" method="GET"><input name="q" value="x"></form>`
	points := Harvest("http://target.test/page?ref=nav", body, "text/html")
	got := keysOf(points)
	want := []string{
		"GET http://target.test/go [form] q",
		"GET http://target.test/page [query] ref",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("surfaces = %v, want %v (a GET form replaces the query)", got, want)
	}
	if strings.Contains(points[0].URL, "?") {
		t.Fatalf("url = %q, want the action without its query", points[0].URL)
	}
}

// A POST form keeps the action's query: the fields travel in the body, so
// nothing is displaced. Character references are decoded by the parser, so an
// action written `?a=1&amp;b=2` arrives resolved and the probe targets the path
// the browser would really request.
func TestHarvestPostFormKeepsDecodedActionQuery(t *testing.T) {
	body := `<form action="/go?a=1&amp;b=2" method="POST"><input name="q" value="1"></form>`
	points := Harvest("http://target.test/", body, "text/html")
	if len(points) != 1 {
		t.Fatalf("points = %v, want 1", keysOf(points))
	}
	if strings.Contains(points[0].URL, "&amp;") {
		t.Fatalf("url = %q, want the entity already decoded", points[0].URL)
	}
	if points[0].URL != "http://target.test/go?a=1&b=2" {
		t.Fatalf("url = %q, want http://target.test/go?a=1&b=2", points[0].URL)
	}
}

// A browser submits an unsupported method as a GET. Reproducing the form means
// reproducing that, not emitting a PUT surface no user can reach.
func TestHarvestFallsBackToGetForUnsupportedMethod(t *testing.T) {
	for _, method := range []string{"PUT", "DELETE", "PATCH", "trace", "get"} {
		body := `<form action="/x" method="` + method + `"><input name="q" value="1"></form>`
		points := Harvest("http://target.test/", body, "text/html")
		if len(points) != 1 {
			t.Fatalf("method %q: points = %v, want 1", method, keysOf(points))
		}
		if points[0].Method != "GET" {
			t.Fatalf("method %q: got %s, want GET", method, points[0])
		}
	}
}

// A select and a textarea are form fields like any <input>. An extractor that
// reads only <input> loses exactly the surfaces an injection point tends to
// hide in, and loses them silently.
func TestHarvestReadsSelectAndTextarea(t *testing.T) {
	body := `<form action="/f" method="POST">
		<select name="role"><option value="user">User</option><option value="admin">Admin</option></select>
		<textarea name="bio">hello</textarea>
	</form>`
	points := Harvest("http://target.test/", body, "text/html")
	got := keysOf(points)
	want := []string{
		"POST http://target.test/f [form] bio",
		"POST http://target.test/f [form] role",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("control surfaces = %v, want %v", got, want)
	}
	// The baseline must be a request the application has actually seen, so the
	// select contributes its first option rather than an empty value.
	for _, p := range points {
		if p.Param == "role" && p.Values.Get("role") != "user" {
			t.Errorf("select baseline = %q, want the first option %q", p.Values.Get("role"), "user")
		}
	}
}

// An option with no value attribute submits its own text. Reading the attribute
// only would produce an empty baseline, and a boolean-differential probe against
// an empty baseline measures the application's reaction to a malformed request.
func TestHarvestSelectOptionFallsBackToOptionText(t *testing.T) {
	body := `<form action="/f" method="POST"><select name="sort">
		<option>name asc</option><option value="price">Price</option></select></form>`
	points := Harvest("http://target.test/", body, "text/html")
	if len(points) != 1 {
		t.Fatalf("points = %v, want 1", keysOf(points))
	}
	if got := points[0].Values.Get("sort"); got != "name asc" {
		t.Fatalf("sort baseline = %q, want the option text %q", got, "name asc")
	}
}

// `data-href` is not `href`. An attribute prefix match reads the one as the
// other, and a crawler that does so walks to a URL the page never linked to.
func TestHarvestIgnoresPrefixedLookalikeAttributes(t *testing.T) {
	body := `<form action="/real" data-action="/decoy" method="POST">
		<input name="real_field" data-name="decoy_field" value="v"></form>`
	points := Harvest("http://target.test/", body, "text/html")
	got := keysOf(points)
	want := []string{"POST http://target.test/real [form] real_field"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("surfaces = %v, want %v (data-* must not match)", got, want)
	}
}

// HTML allows an unquoted attribute value, and a parser written for the quoted
// form alone reports the page as having no form at all.
func TestHarvestReadsUnquotedAttributes(t *testing.T) {
	body := `<form action=/submit method=post><input name=q value=hello></form>`
	points := Harvest("http://target.test/", body, "text/html")
	got := keysOf(points)
	want := []string{"POST http://target.test/submit [form] q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unquoted surfaces = %v, want %v", got, want)
	}
}

// A fragment does not identify a resource, so keeping it would split one
// surface into two keys and the operator would triage the same field twice.
func TestHarvestDropsFragmentFromOriginAndURL(t *testing.T) {
	points := Harvest("http://target.test/search?q=1#results", "", "text/html")
	if len(points) != 1 {
		t.Fatalf("points = %v, want 1", keysOf(points))
	}
	if strings.Contains(points[0].URL, "#") || strings.Contains(points[0].Origin, "#") {
		t.Fatalf("fragment survived: url=%q origin=%q", points[0].URL, points[0].Origin)
	}
}

// GET and POST against the same path and parameter are different code paths in
// most applications, so they are different surfaces and neither is a duplicate.
func TestHarvestKeepsGetAndPostOnSameParameterApart(t *testing.T) {
	body := `<form action="/dup" method="GET"><input name="q" value="1"></form>
	<form action="/dup" method="POST"><input name="q" value="1"></form>`
	points := Harvest("http://target.test/", body, "text/html")
	got := keysOf(points)
	want := []string{
		"GET http://target.test/dup [form] q",
		"POST http://target.test/dup [form] q",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("surfaces = %v, want %v", got, want)
	}
}

// The same form twice on one page is one surface. Reporting it twice would
// inflate the surface count the operator is about to judge coverage by.
func TestHarvestDeduplicatesRepeatedIdenticalForm(t *testing.T) {
	body := `<form action="/s" method="GET"><input name="q" value="1"></form>
	<form action="/s" method="GET"><input name="q" value="1"></form>`
	points := Harvest("http://target.test/", body, "text/html")
	if len(points) != 1 {
		t.Fatalf("points = %v, want 1 after dedupe", keysOf(points))
	}
}

// Two runs over the same page must produce the same order. A report that
// reorders between runs cannot be diffed against the previous one, and the diff
// is how an analyst tells "the fix worked" from "the scanner behaved
// differently this time".
func TestHarvestOrderIsStableAcrossRuns(t *testing.T) {
	body := `<form action="/f" method="POST">
		<input name="zeta" value="1"><input name="alpha" value="1">
		<input name="mid" value="1"></form>`
	first := keysOf(Harvest("http://target.test/?q=1&a=2&z=3", body, "text/html"))
	for i := 0; i < 20; i++ {
		next := keysOf(Harvest("http://target.test/?q=1&a=2&z=3", body, "text/html"))
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("run %d order = %v, want %v", i, next, first)
		}
	}
	if len(first) != 6 {
		t.Fatalf("surfaces = %d (%v), want 3 query + 3 form", len(first), first)
	}
}

// A truncated body still yields its query surfaces, and a body that is not a
// document at all yields nothing. Either way there is no error to report: a
// page with no injectable parameter is a fact, not a failure.
func TestHarvestOnNonDocumentAndMalformedInput(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		body        string
		contentType string
	}{
		{"stylesheet", "http://target.test/a.css", "body{margin:0}", "text/css"},
		{"binary", "http://target.test/f.bin", "\x00\x01\x02", "application/octet-stream"},
		{"truncated form", "http://target.test/p?keep=1", `<form method="POST" action="/f"><input name="q"`, "text/html"},
		{"relative url without host", "/just/a/path?q=1", "", "text/html"},
		{"empty page", "http://target.test/", "", "text/html"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			points := Harvest(tc.url, tc.body, tc.contentType)
			for _, p := range points {
				if p.Param == "" {
					t.Fatalf("point with empty param: %s", p)
				}
				if !hasField(p.Values, p.Param) {
					t.Fatalf("point %s has no baseline entry for its own param", p)
				}
			}
		})
	}
}

// A partial read of a page must not erase the surfaces already found in its
// URL, and the caller has to be able to tell that the body was incomplete from
// the page's own record.
func TestHarvestKeepsQuerySurfacesFromTruncatedBody(t *testing.T) {
	body := `<form method="POST" action="/f"><input name="q" value="1"`
	points := Harvest("http://target.test/p?keep=1", body, "text/html")
	found := map[string]bool{}
	for _, p := range points {
		found[p.Param] = true
	}
	if !found["keep"] {
		t.Fatalf("surfaces = %v, want the URL query to survive a truncated body", keysOf(points))
	}
}

// The declared type is what lets an operator tell a search box from a CSRF
// token without re-reading the HTML. It is recorded, never used to exclude a
// field: a hidden token is still a parameter the application concatenates.
func TestHarvestRecordsFieldTypeAndKeepsHiddenFields(t *testing.T) {
	body := `<form action="/f" method="POST">
		<input type="text" name="q" value="1">
		<input type="hidden" name="csrfmiddlewaretoken" value="tok">
		<input name="untyped" value="2"></form>`
	points := Harvest("http://target.test/", body, "text/html")
	types := map[string]string{}
	for _, p := range points {
		types[p.Param] = p.FieldType
	}
	if _, ok := types["csrfmiddlewaretoken"]; !ok {
		t.Fatal("hidden field dropped; a token is still a parameter")
	}
	if got := types["q"]; got != "text" {
		t.Errorf("q type = %q, want %q", got, "text")
	}
	if got := types["untyped"]; got != "" {
		t.Errorf("untyped field type = %q, want empty when the page declared none", got)
	}
}

// A client-side action is not a submission target. Firing a payload at it would
// produce a request that never left the browser, reported as a surface.
func TestHarvestRejectsNonHTTPSubmissionTargets(t *testing.T) {
	for _, action := range []string{"javascript:alert(1)", "data:text/html,x", "mailto:a@b.c"} {
		body := `<form action="` + action + `" method="POST"><input name="q" value="1"></form>`
		points := Harvest("http://target.test/current", body, "text/html")
		for _, p := range points {
			if strings.Contains(p.URL, "javascript:") || strings.Contains(p.URL, "data:") {
				t.Fatalf("action %q produced surface %s, want the inherited page URL", action, p)
			}
		}
	}
}

// The log and report line must never carry the parameter's current value. It is
// application data, and a line that carries it is a line that has to be
// redacted before it can be shared.
func TestPointStringCarriesNoValues(t *testing.T) {
	points := Harvest("http://target.test/s?token=super-secret-value", "", "text/html")
	if len(points) != 1 {
		t.Fatalf("points = %v, want 1", keysOf(points))
	}
	if line := points[0].String(); strings.Contains(line, "super-secret-value") {
		t.Fatalf("String() = %q, want it free of parameter values", line)
	}
}
