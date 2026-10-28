package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// storedClassFixture is an application that stores whatever it is given and
// renders it back in the context each stored class needs.
//
// The contexts are the point. A fixture that only echoed values would satisfy the
// precondition and prove no class at all, and a detector that fired on it would be
// reporting that echo — which is exactly the failure the precondition-only rows
// had.
type storedClassFixture struct {
	mu      sync.Mutex
	stored  map[string][]string
	cookies []string
	// sqlError makes the reader of a stored value answer with a database error,
	// which is the only evidence the second-order rule accepts.
	sqlError bool
	// escape renders stored values HTML-escaped, which is what a correct
	// application does and what must produce nothing.
	escape bool
	// inert renders stored values inside a textarea, which is displayed rather
	// than executed and must also produce nothing.
	inert bool
	// noSinkScript leaves the sink expressions out, so a stored value is rendered
	// without ever reaching a sink — the control for the twelve sink rules.
	noSinkScript bool
}

func newStoredClassFixture() *storedClassFixture {
	return &storedClassFixture{stored: map[string][]string{}}
}

func (fixture *storedClassFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/guestbook", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture.mu.Lock()
		for name, values := range r.Form {
			if strings.HasPrefix(name, "rrstored") {
				continue
			}
			// A duplicated parameter is stored **joined**, which is what a server
			// that concatenates them does — and that joining is the whole claim the
			// pollution rule makes. Storing them as separate entries would model a
			// server that picked a winner, which is not the condition under test.
			fixture.stored[name] = append(fixture.stored[name], strings.Join(values, ","))
		}
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form action="/guestbook" method="post">` +
			`<input name="message" type="text">` +
			`<input name="url" type="text">` +
			`<input name="password" type="password">` +
			storedSinkInputs() +
			`</form></body></html>`))
	})
	mux.HandleFunc("/wall", func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		stored := map[string][]string{}
		for name, values := range fixture.stored {
			stored[name] = append([]string(nil), values...)
		}
		sqlError := fixture.sqlError
		escape, inert, noSink := fixture.escape, fixture.inert, fixture.noSinkScript
		fixture.mu.Unlock()

		// A password the application accepted is set back as a cookie, because a
		// credential that rides along on every request is a different finding from
		// one that is merely displayed — and a fixture that only did the first
		// would let the module report the second row on the strength of the first.
		for _, value := range stored["password"] {
			w.Header().Add("Set-Cookie", "session="+value+"; Path=/")
		}

		// The database error appears only once the value it complains about has
		// been stored. A page that errors unconditionally would fail the freshness
		// check for the right reason — the signature was already there — and the
		// second-order row would then never be demonstrable by any fixture.
		if sqlError && strings.Contains(strings.Join(stored["message"], ","), storedMarkerSQL) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><p>You have an error in your SQL syntax near '` +
				storedMarkerSQL + `'</p></body></html>`))
			return
		}

		body := "<html><body><h1>Wall</h1>"
		if !noSink {
			body += storedSinkScript(stored)
		}
		for name, values := range stored {
			for _, value := range values {
				switch {
				case inert:
					body += "<textarea>" + value + "</textarea>"
				case escape:
					body += "<div>" + escapeHTMLValue(value) + "</div>"
				case strings.HasPrefix(name, "sink"):
					// A stored sink field is rendered by the sink script above,
					// not into the body, so that the sink rule's proof is about the
					// expression and not about the word appearing somewhere.
					continue
				case name == "url":
					// A URL field is rendered as a link **and** as a scripted
					// navigation, because the two are the two open-redirect rows
					// and a fixture that renders only one of them would leave the
					// other undemonstrable by any test.
					body += `<a href="` + value + `">go</a>` +
						`<script>var u = "` + value + `"; location.href = u;</script>`
				default:
					body += "<div>" + value + "</div>"
				}
			}
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(body + "</body></html>"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// storedSinkInputs declares the fields the twelve sink rules submit into, so the
// form carries every field they need and the test never has to know which rule
// wanted which one.
func storedSinkInputs() string {
	var out strings.Builder
	for _, name := range storedSinkFieldNames() {
		out.WriteString(`<input name="` + name + `" type="text">`)
	}
	return out.String()
}

// storedSinkScript renders each stored sink value into its own family's sink
// expression.
//
// It is written out by family rather than derived from the rules, on purpose: a
// fixture that built itself from the table would prove that the table matches
// itself. Writing it here means the test asserts against a rendering a reader can
// check by eye.
func storedSinkScript(stored map[string][]string) string {
	pick := func(field string) string {
		if values := stored[field]; len(values) > 0 {
			return values[len(values)-1]
		}
		return ""
	}
	var out strings.Builder
	out.WriteString("<script>\n")
	for _, line := range []struct{ field, expression string }{
		{"sinkcookie", `document.cookie = "` + `"@";`},
		{"sinkheader", `xhr.setRequestHeader("X-Trace", "` + `"@");`},
		{"sinklink", `location.href = "` + `"@";`},
		{"sinkdomain", `document.domain = "` + `"@";`},
		{"sinkxpath", `document.evaluate("` + `@", doc, null);`},
		{"sinkjson", `JSON.parse("` + `@");`},
		{"sinkstorage", `localStorage.setItem("k", "` + `"@");`},
		{"sinkfile", `new FileReader().readAsText("file://` + `@");`},
		{"sinkdos", `new Array(Number("` + `@"));`},
		{"sinkmessage", `iframe.contentWindow.postMessage("` + `@", "*");`},
		{"sinksocket", `new WebSocket("` + `@");`},
		{"sinkmarkup", `box.innerHTML = "` + `"@";`},
	} {
		value := pick(line.field)
		if value == "" {
			continue
		}
		out.WriteString(strings.ReplaceAll(line.expression, "@", value) + "\n")
	}
	out.WriteString("</script>\n")
	return out.String()
}

// escapeHTMLValue escapes the characters that would make a value into markup,
// which is what a correct renderer does.
func escapeHTMLValue(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return replacer.Replace(value)
}

// runStoredClass writes to the fixture and returns what came back.
func runStoredClass(t *testing.T, server *httptest.Server) []Finding {
	t.Helper()
	module := &StoredClass{}
	module.PagesKnown([]string{server.URL + "/guestbook", server.URL + "/wall"})
	return module.Scan(context.Background(), mustTransport(t),
		Point{URL: server.URL + "/", Method: http.MethodGet}, nil)
}

// storedClassTitles lists the type indexes a finding set reports.
func storedClassTitles(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Title)
	}
	return out
}

// The application renders stored values as markup, so the HTML injection class is
// demonstrated. This is the row that had a precondition and no class.
func TestStoredClassProvesHTMLInjectionInALiveContext(t *testing.T) {
	fixture := newStoredClassFixture()
	server := fixture.server(t)

	findings := runStoredClass(t, server)
	row := storedClassRow(t, findings, "0x00200100")
	if row.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: the value was read back from the page that renders it",
			row.Tier, TierVerified)
	}
	if !strings.Contains(row.Payload, storedMarkerHTML) {
		t.Errorf("payload = %q, want the submitted marker in it", row.Payload)
	}
	if !strings.Contains(row.Evidence, "rendered on:") {
		t.Errorf("the evidence does not say which page rendered it: %s", row.Evidence)
	}
}

// A value rendered with markup escaped is not an injection, and the marker being
// present in the body is not enough to say otherwise — that distinction is the
// whole reason the proof requires the payload byte for byte.
func TestStoredClassIsSilentWhenValuesAreEscaped(t *testing.T) {
	fixture := newStoredClassFixture()
	fixture.escape = true
	server := fixture.server(t)

	for _, finding := range runStoredClass(t, server) {
		if strings.Contains(finding.Title, "0x00200100") {
			t.Fatalf("reported an HTML injection against escaped output: %q", finding.Title)
		}
	}
}

// A value echoed inside a `<textarea>` is displayed, not executed. Reporting that
// as stored XSS is the commonest false positive in this family, and the inert
// context check exists because of it.
func TestStoredClassDoesNotTreatATextareaAsAnExecutableContext(t *testing.T) {
	fixture := newStoredClassFixture()
	fixture.inert = true
	server := fixture.server(t)

	for _, finding := range runStoredClass(t, server) {
		if strings.Contains(finding.Title, "0x00200100") {
			t.Fatalf("reported an HTML injection for a value rendered in a textarea: %q", finding.Title)
		}
	}
}

// The two script-context rows are the same observation of the payload in a
// different context, and they are both reported because the original files them
// as two checks.
func TestStoredClassProvesScriptContextSeparatelyFromHTML(t *testing.T) {
	fixture := newStoredClassFixture()
	server := fixture.server(t)
	findings := runStoredClass(t, server)

	if len(findings) == 0 {
		t.Fatal("the fixture renders stored values raw, so at least the HTML class is demonstrable")
	}
	// A `<div>` render is not a script context, so the script rows must stay
	// silent even though the value comes back verbatim.
	for _, finding := range findings {
		if strings.Contains(finding.Title, "0x00200312") || strings.Contains(finding.Title, "0x00200322") {
			t.Fatalf("claimed a script context for a value rendered in a <div>: %q", finding.Title)
		}
	}
}

// A database error that appears only after the write is the evidence the
// second-order row accepts; an application that never answers with one produces
// nothing, and that absence is not a claim either way.
func TestStoredClassProvesSecondOrderSQLOnlyFromAFreshSignature(t *testing.T) {
	fixture := newStoredClassFixture()
	server := fixture.server(t)
	for _, finding := range runStoredClass(t, server) {
		if strings.Contains(finding.Title, "0x00100210") {
			t.Fatalf("claimed second-order SQLi against an application that never errors: %q", finding.Title)
		}
	}

	// A fresh fixture for the positive case: the first run already stored the SQL
	// value, so re-running against the same store would put the error page in the
	// **baseline** and the row would be refused for the right reason — the
	// signature was not fresh.
	positive := newStoredClassFixture()
	positive.sqlError = true
	rows := runStoredClass(t, positive.server(t))
	storedClassRow(t, rows, "0x00100210")
}

// A credential rendered back on another page and a credential set in a cookie are
// two different findings, and a fixture that does only one must produce only one.
func TestStoredClassSeparatesAPasswordInTheBodyFromOneInACookie(t *testing.T) {
	fixture := newStoredClassFixture()
	server := fixture.server(t)
	findings := runStoredClass(t, server)

	// This fixture renders the password into the page body and also lists the
	// cookie it set, so both rows are demonstrable and they are distinct rows.
	storedClassRow(t, findings, "0x00400200")
	storedClassRow(t, findings, "0x00500900")
}

// The duplication is the claim. A form that received one value containing a `&`
// has not been polluted, so the rule submits the same field twice and the proof
// looks for the two values side by side.
func TestStoredClassPollutesTheParameterAndProvesTheConcatenation(t *testing.T) {
	fixture := newStoredClassFixture()

	// One server with two paths, because a form's action is on its own origin:
	// resolving `/store` against a *different* host would have the write leave the
	// application, which is a bug in the fixture rather than a property of the
	// check. A first version used two servers and proved nothing at all.
	var seen []string
	application := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/store" {
			seen = append(seen, r.URL.RawQuery)
			fixture.mu.Lock()
			fixture.stored["message"] = append(fixture.stored["message"],
				strings.Join(r.URL.Query()["message"], ","))
			fixture.mu.Unlock()
			storedClassRender(w, fixture)
			return
		}
		w.Write([]byte(`<html><body><form action="/store" method="get">` +
			`<input name="message" type="text"></form></body></html>`))
	}))
	t.Cleanup(application.Close)

	module := &StoredClass{}
	module.PagesKnown([]string{application.URL + "/", application.URL + "/store"})
	findings := module.Scan(context.Background(), mustTransport(t),
		Point{URL: application.URL + "/", Method: http.MethodGet}, nil)

	duplicated := false
	for _, query := range seen {
		if strings.Count(query, "message=") >= 2 {
			duplicated = true
		}
	}
	if !duplicated {
		t.Fatalf("the parameter was never duplicated; queries were %v", seen)
	}
	storedClassRow(t, findings, "0x00501401")
}

// storedClassRender writes the stored values the way an application that echoes
// them raw does, which is the default the class rules are measured against.
func storedClassRender(w http.ResponseWriter, fixture *storedClassFixture) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	body := "<html><body><h1>Wall</h1>"
	for _, values := range fixture.stored {
		for _, value := range values {
			body += "<div>" + value + "</div>"
		}
	}
	w.Write([]byte(body + "</body></html>"))
}

// A URL field rendered as a link and as a scripted navigation demonstrates both
// redirect rows, and they are different claims: one is a destination a reader can
// see, the other moves the visitor with nothing on the page changing.
func TestStoredClassProvesBothRedirectVariantsSeparately(t *testing.T) {
	fixture := newStoredClassFixture()
	server := fixture.server(t)

	findings := runStoredClass(t, server)
	storedClassRow(t, findings, "0x00500101")
	storedClassRow(t, findings, "0x00500112")
}

// A value rendered as inert text is not a redirect either, and the fixture that
// escapes everything must produce neither row.
func TestStoredClassDoesNotClaimARedirectInPlainText(t *testing.T) {
	fixture := newStoredClassFixture()
	fixture.escape = true
	server := fixture.server(t)

	for _, finding := range runStoredClass(t, server) {
		if strings.Contains(finding.Title, "0x00500101") || strings.Contains(finding.Title, "0x00500112") {
			t.Fatalf("claimed a redirect for a value rendered as text: %q", finding.Title)
		}
	}
}

// The twelve stored DOM-sink rows each need the stored value to land **inside**
// that family's sink expression, and the fixture renders it there.
func TestStoredClassProvesEveryStoredDOMSinkVariant(t *testing.T) {
	fixture := newStoredClassFixture()
	server := fixture.server(t)

	findings := runStoredClass(t, server)
	for _, rule := range storedSinkRules {
		found := false
		for _, finding := range findings {
			if strings.Contains(finding.Title, rule.typeIndex) {
				found = true
			}
		}
		if !found {
			t.Errorf("no row for %s (%s); got %v", rule.typeIndex, rule.family,
				storedClassTitles(findings))
		}
	}
}

// A value that is merely rendered, without landing in a sink, is the stored state
// and not any of the twelve classes — which is the distinction the precondition
// could not make.
func TestStoredClassDoesNotClaimASinkForAValueThatNeverReachedOne(t *testing.T) {
	fixture := newStoredClassFixture()
	fixture.noSinkScript = true
	server := fixture.server(t)

	sinkIndexes := map[string]bool{}
	for _, rule := range storedSinkRules {
		sinkIndexes[rule.typeIndex] = true
	}
	for _, finding := range runStoredClass(t, server) {
		for index := range sinkIndexes {
			if strings.Contains(finding.Title, index) {
				t.Fatalf("claimed a sink for a value rendered as text: %q", finding.Title)
			}
		}
	}
}

// A module with no crawled page list has nothing to re-read, and it has to decline
// rather than report the absence of a defect as a finding.
func TestStoredClassIsSilentWithoutACrawledPageList(t *testing.T) {
	if findings := (StoredClass{}).Scan(context.Background(), mustTransport(t),
		Point{URL: "http://example.invalid/", Method: http.MethodGet}, nil); len(findings) != 0 {
		t.Fatalf("findings = %v without a page list", storedClassTitles(findings))
	}
}

// storedClassRow returns the one finding carrying a type index, or fails with the
// titles it did find.
func storedClassRow(t *testing.T, findings []Finding, index string) Finding {
	t.Helper()
	for _, finding := range findings {
		if strings.Contains(finding.Title, index) {
			return finding
		}
	}
	t.Fatalf("no row for %s; got %v", index, storedClassTitles(findings))
	return Finding{}
}
