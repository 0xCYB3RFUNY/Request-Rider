// Package active is the third scanner: autonomous, evidence-first web
// vulnerability discovery with exploit-chain correlation.
//
// # What this package is for
//
// The project already has two ways to find a weakness. The passive MITM proxy
// records whatever the operator or a browser sends, and the nuclei runner
// executes a corpus of templates against a target. Neither of them answers the
// question an autonomous scanner exists to answer: "given only a URL, which
// parameters can I actually fire a payload at, and what happens if I do?"
//
// That middle step — turning a page into a list of injectable surfaces — did not
// exist anywhere in the project. The Target crawler collects pages (url, depth,
// status, content type, kind); `extractMapLinks` in the engine reads `href`,
// `action` and `src` so the crawl has a frontier. But a page with a search box
// was recorded as "a page with a search box", and the parameter `q` inside it
// was never named, never given its current value, and never carried the other
// parameters of that same page so a probe could reproduce the request faithfully.
//
// This file is that missing step. `Harvest` turns one response body into a list
// of `Point`s — a URL, a method, a parameter name, and every sibling value the
// request needs so a single payload can be substituted without changing the rest
// of the request.
//
// # What this package is not
//
// This file is not a scanner. It opens no socket, sends no request, and has no
// state that outlives the call. The probes live in `detect_*.go`, the transport
// lives on the engine, and the correlation lives in `chain.go`. Keeping the
// enumeration pure is what makes it testable: every assertion in the test file
// is a claim about a transformation of a string, so a failure points at the
// transformation and not at a network.
//
// # Parsing, and why it is a parser and not a regex
//
// The upstream implementation this descends from matched `<a href=...>` and
// `<form ...>...</form>` with regular expressions. That approach has two failure
// modes that matter for security work. A regex sees `data-href="..."` as an
// `href`, and it cannot tell a quoted attribute from an unquoted one without
// enumerating every way HTML allows both. `html.Parse` is already the engine's
// choice for link extraction — it is what `extractMapLinks` uses, and it is
// correct for reasons the regex is not.
//
// The same function walks `input`, `select` and `textarea`. A form field is a
// form field regardless of the element that carries it, and an extractor that
// only reads `<input>` silently loses every parameter a textarea or a select
// offers — which is exactly the class of surface an injection point usually
// hides in.
package active

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// Source names where a Point was discovered. It is reported, not used to filter:
// a point discovered in a form is no more and no less worth probing than one
// discovered in a query string, and the operator is the one who decides what to
// do with that.
const (
	// SourceQuery is a parameter of the page URL's own query string.
	SourceQuery = "query"
	// SourceForm is a field of an HTML <form>, GET or POST.
	SourceForm = "form"
)

// field is the name and declared type read out of one form control element. It
// is an intermediate rather than a Point because the name alone is not enough
// to probe: the default value decides what the baseline request looks like, and
// the type is what the operator reads to judge a surface at a glance.
type field struct {
	Name string
	Type string
}

// Point is one injectable surface: a request the probe stage can reproduce with
// exactly one of its parameters replaced.
//
// Values holds the complete parameter set of the original request, including
// the entry for Param itself. That is deliberate. A probe substitutes one value
// inside a copy of Values and leaves the rest untouched, so a request that
// needed `page=3&lang=en` still carries `lang=en` while `page` is under attack.
// A surface that forced the caller to reconstruct sibling parameters would
// quietly change the request it claims to be testing.
type Point struct {
	// URL is the endpoint with no query string. For GET, the query is built
	// from Values at fire time, so a query that is left in URL would be
	// duplicated into the request and the baseline would stop being the
	// baseline.
	URL string `json:"url"`
	// Method is GET or POST, upper-case. An HTML form whose method attribute
	// is missing, empty or nonsense submits by GET; that is what the spec says
	// and it is what the browser does, so it is what a probe must do to stay
	// faithful to the request a user would actually send.
	Method string `json:"method"`
	// Param is the name of the field under test.
	Param string `json:"param"`
	// Source records whether the field came from a query string or a form.
	Source string `json:"source"`
	// FieldType is the HTML input type as written by the page, lower-cased
	// ("" when the page declared none). It is reported so triage can tell a
	// search box from a CSRF token from a checkbox without re-reading the HTML.
	// It is never used to exclude a field: a hidden field carrying a token is
	// still a parameter the application concatenates into a query.
	FieldType string `json:"field_type,omitempty"`
	// Origin is the page the field was discovered on, fragment-free. It is the
	// Referer the discovery request would have carried and the page an operator
	// has to open to see the surface in context.
	Origin string `json:"origin"`
	// Values is the original parameter set of the request, decoded.
	Values url.Values `json:"-"`
}

// Key is the identity of a surface within one run: a probe must not test the
// same parameter of the same endpoint twice, and two pages that render the same
// search form must not double its parameter into the report. Method is part of
// the key because `GET /x?q=` and `POST /x q=` are different code paths in most
// applications, and a surface that only exists on one of them is a real finding
// rather than a duplicate.
func (p Point) Key() string {
	return p.Method + "|" + p.URL + "|" + p.Param
}

// String renders a point for a report line or a log. It never contains the
// values: a parameter's current value is application data, and a log line that
// carries it is a log line that has to be redacted before it can be shared.
func (p Point) String() string {
	return fmt.Sprintf("%s %s [%s] %s", p.Method, p.URL, p.Source, p.Param)
}

// Harvest returns every injectable surface one response body exposes, in a
// stable order and without duplicates.
//
// The order is stable on purpose. A report that lists the same surfaces in a
// different order on every run cannot be diffed against the previous run, and
// diffing two runs is how an analyst tells "the new version fixed it" from "the
// scanner behaved differently this time".
//
// It is not an error for a body to yield no points. A JSON API, a stylesheet
// and a binary download all legitimately contain nothing to inject into, and
// the crawl moves on.
func Harvest(pageURL, body, contentType string) []Point {
	base, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || base.Host == "" {
		return nil
	}
	// Fragments do not identify a resource. Keeping one would split a single
	// surface into two keys, and the second would be a duplicate the operator
	// triages twice.
	base.Fragment = ""
	base.RawFragment = ""

	seen := map[string]bool{}
	var out []Point
	add := func(p Point) {
		key := p.Key()
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}

	// A query string is the one surface that needs no markup. It is harvested
	// from the URL itself, so it applies to every response type, including the
	// JSON and CSS responses that yield no form fields at all.
	for _, point := range queryPoints(base) {
		add(point)
	}
	if !isHTML(contentType) {
		return out
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		// A truncated or malformed body still yielded a URL query above, and
		// the pages it would have yielded forms from are recorded as crawled
		// with body_truncated set. Dropping the whole page's surfaces would
		// turn a partial read into a silent zero.
		return out
	}
	for _, point := range formPoints(base, doc) {
		add(point)
	}
	return out
}

// isHTML reports whether a Content-Type describes a document with forms. Only
// those are walked: a stylesheet or a JSON payload has no <form>, and parsing it
// as one is wasted work that returns nothing.
func isHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "html")
}

// queryPoints builds one surface per distinct key of the page's own query
// string.
//
// A repeated key is one surface, not two. `?tag=a&tag=b` is a single parameter
// of the application; a list-valued field still gets probed with one payload at
// a time, because a payload that lands in the second position and is then
// mistaken for coverage of the first is a false negative dressed as a result.
// The first value is kept as the baseline because it is the one a user would
// have sent.
func queryPoints(base *url.URL) []Point {
	query := base.Query()
	if len(query) == 0 {
		return nil
	}
	origin := base.String()
	endpoint := *base
	endpoint.RawQuery = ""
	endpoint.ForceQuery = false

	var out []Point
	for _, key := range orderedKeys(query) {
		values := cloneValues(query)
		if values.Get(key) == "" {
			// An empty value is still a value the application reads. Leaving
			// it empty keeps the baseline identical to the request the page
			// actually made; substituting a placeholder here would change the
			// request every probe is compared against.
			values.Set(key, "")
		}
		out = append(out, Point{
			URL: endpoint.String(), Method: http.MethodGet, Param: key,
			Source: SourceQuery, Origin: origin, Values: values,
		})
	}
	return out
}

// formPoints walks a parsed document and returns one surface per named field of
// every form on the page.
func formPoints(base *url.URL, doc *html.Node) []Point {
	var out []Point
	var walk func(*html.Node, string, string)
	walk = func(node *html.Node, action, method string) {
		if node.Type == html.ElementNode && node.Data == "form" {
			// A form establishes an action and a method for everything nested
			// inside it, so both are carried down the walk. HTML forbids nested
			// forms, so an inner <form> can only mean the document is broken —
			// and the inner one is then the one a browser would use.
			action = formAction(base, node, action)
			method = formMethod(node)
		}
		if node.Type == html.ElementNode {
			if field, ok := formField(node); ok && field.Name != "" {
				endpoint, err := url.Parse(action)
				if err == nil {
					// Only a GET form discards its action's query. A GET
					// submission encodes the fields as the query string and
					// therefore replaces whatever the action carried, which is
					// why the stored URL keeps none: Values is rebuilt into
					// the query at fire time. A POST form sends the fields in
					// the body, so its action's query survives the submission
					// and dropping it here would send the probe to a different
					// request than the browser sends.
					target := endpoint.String()
					if method == http.MethodGet {
						target = queryless(endpoint)
					}
					values := cloneValues(formDefaults(node))
					out = append(out, Point{
						URL: target, Method: method, Param: field.Name,
						Source: SourceForm, FieldType: field.Type,
						Origin: base.String(), Values: values,
					})
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, action, method)
		}
	}
	walk(doc, base.String(), http.MethodGet)
	return out
}

// formField reads the submitted name and type out of one form control element.
//
// It returns ok=false for elements that are not controls. A <form> is read by
// formAction/formMethod instead, because a form has no name of its own and
// treating its attributes as a field would submit a parameter that exists in no
// request a browser would ever send.
func formField(node *html.Node) (field, bool) {
	var found field
	switch node.Data {
	case "input":
		found.Name = attr(node, "name")
		found.Type = strings.ToLower(strings.TrimSpace(attr(node, "type")))
	case "select", "textarea":
		found.Name = attr(node, "name")
		// The HTML default for these two is text. Reporting it as text is
		// honest: the page declared no type, and the operator should not have
		// to know that <select> has no type attribute to read the field.
		found.Type = "text"
	default:
		return field{}, false
	}
	return found, true
}

// formDefaults collects the default values the page supplies for one control:
// its own `value` attribute for an <input>, and the options a <select> or
// <textarea> offers.
//
// The option values matter more than they look. A baseline built from an empty
// select sends a field the application has never seen in that state, so a probe
// on it measures the application's reaction to a malformed request rather than
// to an attack — and the difference is exactly what a boolean-differential
// detector reads as signal.
func formDefaults(node *html.Node) url.Values {
	values := url.Values{}
	if value := attr(node, "value"); value != "" {
		values.Set(attr(node, "name"), value)
		return values
	}
	if node.Data != "select" {
		return values
	}
	var options []string
	var collect func(*html.Node)
	collect = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "option" {
			// An option without a value attribute submits its own text, which
			// is the browser's rule and not a shortcut.
			value := attr(n, "value")
			if value == "" {
				value = strings.TrimSpace(textContent(n))
			}
			if value != "" {
				options = append(options, value)
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			collect(child)
		}
	}
	collect(node)
	if len(options) > 0 {
		values.Set(attr(node, "name"), options[0])
	}
	return values
}

// formAction resolves a form's submission target.
//
// An absent, empty or fragment-only action means the current document, which is
// the HTML specification's rule: a form with no action submits to the page it is
// on. Treating the empty string as an error instead would drop every single-page
// form on the web, which is a common enough shape that losing it would look
// like a clean scan rather than a missed surface.
func formAction(base *url.URL, node *html.Node, inherited string) string {
	raw := strings.TrimSpace(attr(node, "action"))
	if raw == "" || strings.HasPrefix(raw, "#") {
		return inherited
	}
	resolved, err := base.Parse(raw)
	if err != nil {
		return inherited
	}
	// Only http(s) is a submission target. A `javascript:` or `data:` action is
	// either inert or a client-side handler, and firing a payload at it would
	// produce a request that never left the browser.
	scheme := strings.ToLower(resolved.Scheme)
	if scheme != "http" && scheme != "https" {
		return inherited
	}
	resolved.Fragment = ""
	resolved.RawFragment = ""
	return resolved.String()
}

// formMethod returns the method a browser would use for this form.
//
// Anything other than an explicit POST is GET. That includes an explicit PUT or
// DELETE, and it is not a simplification: a form declaring an unsupported method
// is submitted by every browser as a GET, so reproducing the form faithfully
// means submitting it as a GET. Emitting a PUT surface instead would report
// coverage of a code path no user can reach.
func formMethod(node *html.Node) string {
	if strings.EqualFold(strings.TrimSpace(attr(node, "method")), "POST") {
		return http.MethodPost
	}
	return http.MethodGet
}

// textContent returns the concatenated text of a node's descendants.
func textContent(node *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return b.String()
}

// attr returns an attribute's value, or "" when the element does not carry it.
// `html.Parse` has already decoded character references, so an action written
// as `?a=1&amp;b=2` arrives here as `?a=1&b=2` and needs no further unescaping.
func attr(node *html.Node, key string) string {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, key) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// queryless returns a URL with its query string removed, which is the form a
// Point stores so a probe can rebuild the query from Values without duplicating
// what the page already had in it.
func queryless(u *url.URL) string {
	clone := *u
	clone.RawQuery = ""
	clone.ForceQuery = false
	return clone.String()
}

// cloneValues deep-copies a parameter set. Points are built concurrently and a
// shared map would let one probe's substitution reach another's baseline.
func cloneValues(in url.Values) url.Values {
	out := url.Values{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

// orderedKeys returns a map's keys in a stable order so two runs over the same
// page produce the same report.
func orderedKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// CandidatePointsForURL provides attack surfaces for common API/SPA paths lacking HTML markup.
func CandidatePointsForURL(rawURL string) []Point {
	base, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || base.Host == "" {
		return nil
	}
	path := strings.ToLower(base.Path)
	if !strings.HasPrefix(path, "/api") && !strings.HasPrefix(path, "/rest") && !strings.HasPrefix(path, "/auth") && !strings.HasPrefix(path, "/v1") && !strings.HasPrefix(path, "/v2") && !strings.Contains(path, "login") && !strings.Contains(path, "search") {
		return nil
	}
	var out []Point
	endpoint := *base
	endpoint.RawQuery = ""
	endpoint.ForceQuery = false
	origin := base.String()

	// Auth / Login endpoint
	if strings.Contains(path, "login") || strings.Contains(path, "auth") || strings.Contains(path, "signin") {
		for _, param := range []string{"email", "password", "username"} {
			v := url.Values{}
			v.Set("email", "admin@juice-sh.op")
			v.Set("password", "admin123")
			v.Set(param, "")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodPost,
				Param:     param,
				Source:    SourceForm,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Search / Query endpoint
	if strings.Contains(path, "search") || strings.Contains(path, "find") || strings.Contains(path, "query") {
		for _, param := range []string{"q", "query", "id"} {
			v := url.Values{}
			v.Set(param, "test")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodGet,
				Param:     param,
				Source:    SourceQuery,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Entity endpoints with potential ID parameters
	if strings.Contains(path, "user") || strings.Contains(path, "product") || strings.Contains(path, "basket") || strings.Contains(path, "feedback") {
		if !strings.Contains(path, "login") && !strings.Contains(path, "search") && !strings.Contains(path, "reset") && !strings.Contains(path, "change") {
			v := url.Values{}
			v.Set("id", "1")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodGet,
				Param:     "id",
				Source:    SourceQuery,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Password reset / security question endpoints
	if strings.Contains(path, "reset-password") || strings.Contains(path, "forgot-password") {
		for _, param := range []string{"email", "answer", "new", "repeat"} {
			v := url.Values{}
			v.Set("email", "admin@juice-sh.op")
			v.Set("answer", "test")
			v.Set("new", "newpassword123")
			v.Set("repeat", "newpassword123")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodPost,
				Param:     param,
				Source:    SourceForm,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Membership / Deluxe endpoints
	if strings.Contains(path, "deluxe") {
		for _, param := range []string{"paymentMode", "UserId"} {
			v := url.Values{}
			v.Set("paymentMode", "free")
			v.Set("UserId", "1")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodPost,
				Param:     param,
				Source:    SourceForm,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Change password endpoints
	if strings.Contains(path, "change-password") {
		for _, param := range []string{"new", "repeat", "current"} {
			v := url.Values{}
			v.Set("new", "slurmCl4ssic")
			v.Set("repeat", "slurmCl4ssic")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodGet,
				Param:     param,
				Source:    SourceQuery,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Redirect endpoints
	if strings.Contains(path, "redirect") {
		v := url.Values{}
		v.Set("to", "https://github.com/juice-shop/juice-shop")
		out = append(out, Point{
			URL:       endpoint.String(),
			Method:    http.MethodGet,
			Param:     "to",
			Source:    SourceQuery,
			FieldType: "text",
			Origin:    origin,
			Values:    v,
		})
	}

	// Chatbot endpoints
	if strings.Contains(path, "chatbot") {
		for _, param := range []string{"action", "query"} {
			v := url.Values{}
			v.Set("action", "query")
			v.Set("query", "can I have a coupon code")
			out = append(out, Point{
				URL:       endpoint.String(),
				Method:    http.MethodPost,
				Param:     param,
				Source:    SourceForm,
				FieldType: "text",
				Origin:    origin,
				Values:    v,
			})
		}
	}

	// Profile update endpoints
	if strings.Contains(path, "profile") && !strings.Contains(path, "image") {
		v := url.Values{}
		v.Set("username", "testuser")
		out = append(out, Point{
			URL:       endpoint.String(),
			Method:    http.MethodPost,
			Param:     "username",
			Source:    SourceForm,
			FieldType: "text",
			Origin:    origin,
			Values:    v,
		})
	}

	// Checkout / Order endpoints
	if strings.Contains(path, "checkout") {
		v := url.Values{}
		out = append(out, Point{
			URL:       endpoint.String(),
			Method:    http.MethodPost,
			Param:     "checkout",
			Source:    SourceForm,
			FieldType: "text",
			Origin:    origin,
			Values:    v,
		})
	}

	return out
}
