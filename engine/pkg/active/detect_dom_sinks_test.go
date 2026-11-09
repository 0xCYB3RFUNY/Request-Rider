package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The vulnerable page carries one sink per family, each fed from a
// browser-provided source. Every family must produce a row.
const domSinkVulnerable = `<html><head><script src="/static/app.js"></script></head><body></body></html>`

const domSinkApp = `
document.cookie = "session=" + location.search;
xhr.setRequestHeader("X-Trace", document.referrer);
location.href = new URLSearchParams(location.search).get("next");
document.domain = location.hostname;
box.innerHTML = history.state;
document.evaluate(location.hash, doc, null);
JSON.parse(localStorage.getItem("profile"));
localStorage.setItem("last", location.hash);
var f = new FileReader(); f.readAsText("file://" + location.hash);
new Array(Number(location.hash));
iframe.contentWindow.postMessage(location.search, "*");
var socket = new WebSocket(location.search);
`

// The control page has the same sinks with literal arguments. A detector that
// reported it would be reporting that assignments exist, which is the claim
// these rows explicitly do not make.
const domSinkLiteral = `<html><body><script>
document.cookie = "session=fixed";
xhr.setRequestHeader("X-Trace", "static");
location.href = "/dashboard";
document.domain = "example.com";
box.innerHTML = "<b>hello</b>";
JSON.parse('{"ok":true}');
localStorage.setItem("theme", "dark");
iframe.contentWindow.postMessage("ready", "https://trusted.example");
var socket = new WebSocket("wss://push.example/socket");
</script></body></html>`

func domSinkFixture(t *testing.T, inline string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(domSinkApp))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if inline != "" {
			w.Write([]byte(inline))
			return
		}
		w.Write([]byte(domSinkVulnerable))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func domSinkRows(t *testing.T, server *httptest.Server, baseline *Response) []Finding {
	t.Helper()
	transport := mustTransport(t)
	point := Point{URL: server.URL + "/", Method: http.MethodGet, Origin: server.URL + "/"}
	return DOMSinks{}.Scan(context.Background(), transport, point, baseline)
}

// Both the inline script and the linked one are read: a page that ships its
// sinks in a bundle is the common case, and a detector that only read the
// document would report nothing for it.
func TestDOMSinksReadsInlineAndLinkedScripts(t *testing.T) {
	server := domSinkFixture(t, `<html><body><script>`+domSinkApp+`</script></body></html>`)
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: `<html><body><script>` + domSinkApp + `</script></body></html>`}

	families := map[string]int{}
	for _, finding := range domSinkRows(t, server, baseline) {
		families[finding.Title]++
	}
	want := []string{
		"Cookie Manipulation",
		"Ajax Request Header Manipulation",
		"Link Manipulation",
		"Document Domain Manipulation",
		"DOM Data Manipulation",
		"Client-Side XPath Injection",
		"Client-Side JSON Injection",
		"HTML5 Storage Manipulation",
		"Denial of Service",
		"WebSocket URL Poisoning",
	}
	for _, family := range want {
		rows := 0
		for title := range families {
			if strings.HasPrefix(title, family+" (") {
				rows++
			}
		}
		if rows == 0 {
			t.Errorf("no row for %s; got %v", family, families)
		}
	}
	// The wildcard postMessage is the one family whose defect is the call and
	// not the value, so it fires without a source.
	rows := 0
	for title := range families {
		if strings.HasPrefix(title, "HTML5 Web Message Manipulation (") {
			rows++
		}
	}
	if rows == 0 {
		t.Errorf("no row for HTML5 Web Message Manipulation; got %v", families)
	}
}

// A URL-source sink is the reflected variant and a page-held source is the
// DOM-based one: the two are Burp's two rows and the detector has to tell them
// apart rather than claim both.
func TestDOMSinksSeparatesTheReflectedVariantFromTheDOMVariant(t *testing.T) {
	server := domSinkFixture(t, `<html><body><script>
	var q = location.search;
	document.cookie = "session=" + q;
	document.cookie = "session=" + localStorage.getItem("x");
	</script></body></html>`)
	body := `<html><body><script>
	var q = location.search;
	document.cookie = "session=" + q;
	document.cookie = "session=" + localStorage.getItem("x");
	</script></body></html>`
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: body}

	rows := 0
	reflected, domBased := 0, 0
	for _, finding := range domSinkRows(t, server, baseline) {
		if !strings.HasPrefix(finding.Title, "Cookie Manipulation (") {
			continue
		}
		rows++
		switch {
		case strings.Contains(finding.Title, "(reflected DOM-based)"):
			reflected++
		case strings.Contains(finding.Title, "(DOM-based)"):
			domBased++
		}
	}
	if rows != 2 || reflected != 1 || domBased != 1 {
		t.Fatalf("rows = %d (reflected %d, dom %d), want 2 (1 and 1)", rows, reflected, domBased)
	}
}

// The control: the same sinks with literal arguments. "This assignment exists"
// is not the claim these rows make, so a detector that reported the control
// would be reporting every `document.cookie =` on the internet.
func TestDOMSinksIgnoresSinksFedWithLiterals(t *testing.T) {
	server := domSinkFixture(t, domSinkLiteral)
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: domSinkLiteral}

	findings := domSinkRows(t, server, baseline)
	for _, finding := range findings {
		// The wildcard postMessage is the documented exception: the defect is
		// the call, not the argument.
		if strings.HasPrefix(finding.Title, "HTML5 Web Message Manipulation (") {
			continue
		}
		t.Fatalf("reported %q against a page whose sinks take literals", finding.Title)
	}
}

// A third-party script is named as a dependency by `script-include` and is not
// fetched from here: this module sending requests to somebody else's CDN is a
// side effect nobody asked for.
func TestDOMSinksDoesNotFetchAThirdPartyScript(t *testing.T) {
	var fetched bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/app.js") {
			fetched = true
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><script src="https://cdn.other-host.example/app.js"></script>` +
			`<script>document.cookie = "s=" + location.search;</script></body></html>`))
	}))
	defer server.Close()

	body := `<html><body><script src="https://cdn.other-host.example/app.js"></script>` +
		`<script>document.cookie = "s=" + location.search;</script></body></html>`
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: body}

	domSinkRows(t, server, baseline)
	if fetched {
		t.Fatal("fetched a third-party script from the operator's scanner")
	}
}

// The taint is followed one assignment deep, which is the depth that separates
// the two common real shapes.
func TestDOMSinkTaintFollowsOneAssignment(t *testing.T) {
	tainted := taintedNames("const q = new URLSearchParams(location.search).get('q'); other = 'literal';")
	if _, ok := tainted["q"]; !ok {
		t.Error("a name assigned from location.search is not tainted")
	}
	if _, ok := tainted["other"]; ok {
		t.Error("a name assigned a literal is tainted")
	}
	if domIdentifiersIn("maxX")["x"] {
		t.Error("a one-letter name matched inside a longer identifier")
	}
}
