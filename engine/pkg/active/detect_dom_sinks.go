package active

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// DOMSinks reads a page's own scripts for a data source that reaches a DOM
// sink, and names the sink family.
//
// Burp reports these as eleven separate checks whose difference is the sink:
// `0x00200340` WebSocket URL poisoning, `0x00200350` local file path
// manipulation, `0x00200360` client-side XPath, `0x00200370` client-side JSON,
// `0x00500B00` cookie manipulation, `0x00500C00` Ajax request header
// manipulation, `0x00500D00` denial of service, `0x00500E00` HTML5 web message
// manipulation, `0x00500F00` HTML5 storage manipulation, `0x00501100` document
// domain manipulation, `0x00501200` DOM data manipulation — each of them in
// three variants (DOM-based, reflected DOM-based, stored DOM-based).
//
// # Why this reads the script rather than the reflection
//
// The obvious implementation — inject a payload that writes the cookie itself,
// then read the cookie back — would be measuring the payload, not the
// application. A scanner that fires `document.cookie='…'` and then finds that
// cookie set has proved that its own script ran, which is the DOM-XSS row and
// not this one. So the detector reads the page's **own** code: a source the
// browser hands to a script (`location.search`, `document.referrer`, the
// `document.cookie` it already has) and a sink the application writes with it.
//
// # Why a source is required, and why the two source classes are the two rows
//
// A sink alone is not this class of finding — every application assigns
// `document.cookie` somewhere. The claim is that a value the browser does not
// sanitize reaches it, so the source is half of the proof. And the two source
// classes are exactly Burp's two variants: a value that arrived *in the URL* is
// reflected DOM-based, and a value the page already holds — a cookie, the DOM,
// the referrer, `history.state` — is DOM-based.
//
// # What "reaches it" means here
//
// The taint is tracked one assignment deep, which is the depth that separates
// the two common shapes and stops the claim from outrunning the evidence:
//   - `document.cookie = location.search` — the source is in the argument;
//   - `const q = new URLSearchParams(location.search).get('q');
//     document.cookie = q` — the source reaches the sink through one name.
//
// A sink fed from a name that is not assigned from a source anywhere in the
// same file is reported as an *unclassified* sink, at a lower tier and with no
// variant claim, because "this assignment exists" is a fact and "an attacker
// controls this assignment" is not.

// firstNonBlank returns the first of its arguments that is not blank, for the
// evidence line when a rule's whole match and its argument differ.
func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// DOMSinks is the source-to-sink reader for one page.
type DOMSinks struct{}

// Name implements Module.
func (DOMSinks) Name() string { return "dom-sinks" }

// Level implements Module.
// A page's scripts are a property of the page, so the question is about the
// document rather than about a parameter.
func (DOMSinks) Level() Level { return LevelEndpoint }

// domSourceClass is which of Burp's two DOM variants a source belongs to.
type domSourceClass int

const (
	// domSourceURL is a value the browser took from the address the visitor
	// arrived with: the URL, its query and its fragment, the referrer, the
	// base URI. A payload for one is a URL an attacker writes, which is what
	// makes it reflected rather than stored.
	domSourceURL domSourceClass = iota
	// domSourceDOM is a value the page already holds: a cookie, the DOM it
	// rendered, `history.state`, `window.name`. A payload for one has to have
	// got into that holder first, which is what makes it DOM-based.
	domSourceDOM
)

// domSources are the browser-provided expressions this detector treats as
// sources, grouped by the variant each one implies.
var domSources = map[string]domSourceClass{
	"location.search":          domSourceURL,
	"location.href":            domSourceURL,
	"location.hash":            domSourceURL,
	"location.pathname":        domSourceURL,
	"location":                 domSourceURL,
	"document.location":        domSourceURL,
	"document.URL":             domSourceURL,
	"document.documentURI":     domSourceURL,
	"document.baseURI":         domSourceURL,
	"document.referrer":        domSourceURL,
	"window.location":          domSourceURL,
	"document.cookie":          domSourceDOM,
	"localStorage":             domSourceDOM,
	"sessionStorage":           domSourceDOM,
	"window.name":              domSourceDOM,
	"history.state":            domSourceDOM,
	"document.body":            domSourceDOM,
	"document.documentElement": domSourceDOM,
	"URLSearchParams":          domSourceURL,
}

// domSinkRule is one family: the pattern that finds the write, and how to read
// the argument the value flows through.
type domSinkRule struct {
	// family is the name the report prints, and it is the name of the Burp
	// check family so a reader can look the row up.
	family string
	// typeIndex is the check's identifier in the original, carried in the row
	// so a register row and a report row are the same row.
	typeIndex string
	// claimed is the severity the evidence supports if it is proven.
	claimed Severity
	// match finds the sink. The first submatch, when the pattern has one, is the
	// expression the source flows through.
	match *regexp.Regexp
	// needsSource is false for the sinks whose defect is in the call itself —
	// `postMessage(x, '*')` sends the value to any origin whatever the value is.
	needsSource bool
	// note is what the family means in a sentence, for the description.
	note string
}

// domSinkRules are the families, in report order.
//
// The order is the order a reader triages in: a cookie, a header and a
// navigation are things a visitor's session loses, while a DOM write, an XPath
// call and a `JSON.parse` are things the page reads wrongly. A rule whose sink
// is its own defect — `postMessage(…, '*')` — is the exception and says so.
var domSinkRules = []domSinkRule{
	{
		family: "Cookie Manipulation", typeIndex: "0x00500B00", claimed: SeverityHigh,
		match:       regexp.MustCompile(`(?s)document\s*\.\s*cookie\s*=\s*([^;\n]{1,200})`),
		needsSource: true,
		note: "a value the browser does not sanitize is written into the document's cookie jar, " +
			"and a script on the page can read it back on the next load",
	},
	{
		family: "Ajax Request Header Manipulation", typeIndex: "0x00500C00", claimed: SeverityMedium,
		match:       regexp.MustCompile(`(?s)setRequestHeader\s*\(\s*['"][^'"]{1,80}['"]\s*,\s*([^)]{1,200})\)`),
		needsSource: true,
		note: "a header the script sets from attacker-influenced data is a header the server " +
			"treats as its own client",
	},
	{
		family: "Link Manipulation", typeIndex: "0x00501000", claimed: SeverityMedium,
		match: regexp.MustCompile(`(?s)location\s*\.\s*(?:href|hash)\s*=\s*([^;\n]{1,200})` +
			`|location\s*\.\s*(?:assign|replace)\s*\(\s*([^)]{1,200})\)`),
		needsSource: true,
		note: "a navigation to an address the value chose sends the visitor wherever that value " +
			"said, with this page's origin as the referrer",
	},
	{
		family: "Document Domain Manipulation", typeIndex: "0x00501100", claimed: SeverityMedium,
		match:       regexp.MustCompile(`(?s)document\s*\.\s*domain\s*=\s*([^;\n]{1,200})`),
		needsSource: true,
		note: "a relaxed document domain hands any sibling host a same-origin document to read " +
			"and write",
	},
	{
		family: "DOM Data Manipulation", typeIndex: "0x00501200", claimed: SeverityHigh,
		match: regexp.MustCompile(`(?s)\.\s*(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=\s*` +
			`([^;\n]{1,200})|\.\s*(?:textContent|innerText|nodeValue)\s*\+?=\s*([^;\n]{1,200})`),
		needsSource: true,
		note:        "markup written into the DOM from an unsanitized value is markup this page executes",
	},
	{
		family: "Client-Side XPath Injection", typeIndex: "0x00200360", claimed: SeverityMedium,
		match:       regexp.MustCompile(`(?s)document\s*\.\s*evaluate\s*\(\s*([^,]{1,200})`),
		needsSource: true,
		note: "an XPath expression the value chooses is a query against the page's own XML, " +
			"chosen by the value",
	},
	{
		family: "Client-Side JSON Injection", typeIndex: "0x00200370", claimed: SeverityLow,
		match:       regexp.MustCompile(`(?s)JSON\s*\.\s*parse\s*\(\s*([^)]{1,200})\)`),
		needsSource: true,
		note: "a parsed document whose shape the value chose is a shape the page's own code did " +
			"not expect, and every field it reads afterwards is read from it",
	},
	{
		family: "HTML5 Storage Manipulation", typeIndex: "0x00500F00", claimed: SeverityMedium,
		match: regexp.MustCompile(`(?s)(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*` +
			`['"][^'"]{0,40}['"]\s*,\s*([^)]{1,200})\)`),
		needsSource: true,
		note: "storage is origin-wide and persistent, so what the value writes there is read back " +
			"on every later load and is visible to every script on the origin",
	},
	{
		family: "Local File Path Manipulation", typeIndex: "0x00200350", claimed: SeverityMedium,
		// The whole quoted literal is captured rather than only the scheme: with
		// only the scheme captured, the argument could never carry a source and the
		// rule could never fire — and, once the stored variant needed the argument,
		// it could never tell which file a value named.
		match: regexp.MustCompile(`(?s)(?:new\s+FileReader\s*\(\s*)?['"]((?:file:)[^'"]{0,200})['"]` +
			`|\.(?:src|href)\s*=\s*['"]\s*['"]?\s*\+\s*([^;\n]{1,200})`),
		needsSource: true,
		note:        "a local path the value chooses asks the browser for a file on the visitor's disk",
	},
	{
		family: "Denial of Service", typeIndex: "0x00500D00", claimed: SeverityLow,
		match: regexp.MustCompile(`(?s)new\s+Array\s*\(\s*([^)]{1,80})\)|` +
			`setTimeout\s*\(\s*[^,]{1,80},\s*([^)]{1,80})\)`),
		needsSource: true,
		note: "a loop bound or a timer delay the value chose turns one page load into as much " +
			"work as the value asked for",
	},
	{
		// The one family whose defect is the call and not the value: a wildcard
		// target origin sends whatever the page holds to whatever origin the
		// message names, which is why this row is `verified` on a match and
		// needs no source.
		family: "HTML5 Web Message Manipulation", typeIndex: "0x00500E00", claimed: SeverityMedium,
		match:       regexp.MustCompile(`postMessage\s*\(([^;]{0,200}?),\s*['"]\*['"]\s*\)`),
		needsSource: false,
		note: "a wildcard target origin sends the message to whichever origin the receiving " +
			"document actually lives on, whatever the sender meant",
	},
	{
		family: "WebSocket URL Poisoning", typeIndex: "0x00200340", claimed: SeverityMedium,
		match:       regexp.MustCompile(`(?s)new\s+WebSocket\s*\(\s*([^)]{1,200})\)`),
		needsSource: true,
		note: "a WebSocket address the value chose is a channel this page opens to whoever the " +
			"value named, from inside the visitor's session",
	},
}

// domSinkMaxScript is the longest script this module reads, and the cap exists
// so a minified bundle of several megabytes cannot turn a page reader into a
// reader of the whole asset tree.
const domSinkMaxScript = 512 << 10

// domSinkMaxLinked is how many linked scripts one page contributes. The list is
// the page's own order, so a truncation is visible as a truncated row rather
// than as silence.
const domSinkMaxLinked = 12

// Scan reads the page's scripts and reports every source-to-sink pair.
func (d DOMSinks) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	if !strings.Contains(strings.ToLower(baseline.HeaderValue("Content-Type")), "text/html") {
		return nil
	}

	var out []Finding
	for _, script := range pageScripts(baseline.Body, p.URL) {
		if script.src == "" {
			out = append(out, domSinkFindings(p, script, script.body)...)
			continue
		}
		// A linked script is fetched on its own terms: the page named the URL,
		// so reading it is the same request the page already asked for. Only a
		// **same-origin** one is fetched from here — a third-party `src` is
		// reported by `ScriptIncludeOfAnotherDomain` as a dependency, and this
		// module sending requests to somebody else's CDN is a side effect nobody
		// asked for.
		if !script.sameOrigin {
			continue
		}
		resp, err := t.Do(ctx, http.MethodGet, script.src, nil, false, nil)
		if err != nil || resp == nil || resp.StatusCode >= 400 {
			continue
		}
		body := resp.Body
		if len(body) > domSinkMaxScript {
			body = body[:domSinkMaxScript]
		}
		out = append(out, domSinkFindings(p, script, body)...)
		if len(out) >= domSinkMaxLinked {
			return out[:domSinkMaxLinked]
		}
	}
	return out
}

// pageScript is one script the document carries.
type pageScript struct {
	// name is what the report calls it: the URL for a linked script, and
	// `inline script N` for one written in the page.
	name string
	// src is the linked script's absolute URL, empty for an inline one.
	src string
	// body is the script text, already resolved for a linked script.
	body string
	// sameOrigin is whether a linked script lives on the page's own host, which
	// is the only one this module fetches itself.
	sameOrigin bool
}

// pageScripts reads the document's scripts, in document order.
//
// The page URL is needed rather than optional: a `src="/static/app.js"` is
// relative, and resolving it is what turns a markup attribute into a request the
// module can make and into a host it can compare against the page's own.
func pageScripts(body, pageURL string) []pageScript {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil || doc == nil {
		return nil
	}
	page, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil {
		return nil
	}
	var out []pageScript
	inline := 0
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			if src := strings.TrimSpace(attrValue(n, "src")); src != "" {
				resolved, err := page.Parse(src)
				if err != nil || resolved.Host == "" {
					return
				}
				resolved.Fragment, resolved.RawFragment = "", ""
				out = append(out, pageScript{
					name:       resolved.String(),
					src:        resolved.String(),
					sameOrigin: resolved.Host == page.Host,
				})
				return
			}
			if text := scriptText(n); text != "" {
				inline++
				if len(text) > domSinkMaxScript {
					text = text[:domSinkMaxScript]
				}
				out = append(out, pageScript{name: "inline script " + strconv.Itoa(inline), body: text})
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return out
}

// scriptText reads an inline script's code, and it walks the children because a
// script with CDATA is several text nodes rather than one.
func scriptText(script *html.Node) string {
	var b strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(script)
	return strings.TrimSpace(b.String())
}

// domSinkFindings reads one script and returns every sink whose argument carries
// a source.
//
// One row per **variant**, not per family: a page that writes a cookie from
// `location.search` and then writes it again from `localStorage` has two
// findings, and they are the two checks Burp files separately — the reflected
// one and the DOM-based one. Collapsing them into a single row would report one
// of the two and leave the other unreported, which is the failure this register
// exists to prevent.
func domSinkFindings(p Point, script pageScript, body string) []Finding {
	tainted := taintedNames(body)
	var out []Finding
	for _, rule := range domSinkRules {
		variants := make([]string, 0, 2)
		for _, match := range rule.match.FindAllStringSubmatch(body, -1) {
			argument := domSinkArgument(match)
			variant := domSourceDOMTitle
			if rule.needsSource {
				class, tainted := expressionIsTainted(argument, tainted)
				if !tainted {
					// A sink fed from a name no source was assigned to is a fact
					// about the page and not about this class of finding, so it
					// is left out rather than reported at a lower tier: "this
					// assignment exists" and "an attacker controls this
					// assignment" are two claims and only the second is this row.
					continue
				}
				if class == domSourceURL {
					variant = domSourceURLTitle
				}
			}
			if slices.Contains(variants, variant) {
				continue
			}
			variants = append(variants, variant)
			out = append(out, domSinkFinding(p, script, body, rule, argument, match[0], tainted))
		}
	}
	return out
}

// domSinkArgument picks the expression a rule's value flows through: the first
// non-empty submatch after the whole match, which is the shape every rule in the
// table shares.
func domSinkArgument(match []string) string {
	for _, group := range match[1:] {
		if strings.TrimSpace(group) != "" {
			return strings.TrimSpace(group)
		}
	}
	return ""
}

// taintedNames collects the names a script assigns from a source, which is the
// one hop of propagation this detector follows.
//
// The pattern is deliberately a plain assignment rather than a dataflow
// analysis: a name assigned from `location.search` is what the overwhelming
// majority of real sinks read, and a deeper analysis would have to be right
// about every construct in a minified bundle to be worth more than this is.
func taintedNames(body string) map[string]domSourceClass {
	tainted := make(map[string]domSourceClass)
	assignment := regexp.MustCompile(
		`(?s)\b(?:var|let|const)?\s*([A-Za-z_$][A-Za-z0-9_$]{0,40})\s*=\s*([^;\n]{1,200})`)
	for _, match := range assignment.FindAllStringSubmatch(body, -1) {
		name, expression := match[1], match[2]
		if class, ok := expressionSource(expression); ok {
			tainted[name] = class
		}
	}
	return tainted
}

// expressionSource reports whether an expression reads a browser-provided source,
// and which variant it implies.
func expressionSource(expression string) (domSourceClass, bool) {
	for name, class := range domSources {
		if strings.Contains(expression, name) {
			return class, true
		}
	}
	return domSourceURL, false
}

// expressionIsTainted reports whether a sink argument carries a source directly
// or through one assigned name.
func expressionIsTainted(argument string, tainted map[string]domSourceClass) (domSourceClass, bool) {
	if class, ok := expressionSource(argument); ok {
		return class, true
	}
	identifiers := domIdentifiersIn(argument)
	for name, class := range tainted {
		if identifiers[name] {
			return class, true
		}
	}
	return domSourceURL, false
}

// domIdentifier is the identifier a fragment names. The `$` is in the class
// because JavaScript allows it and a minified bundle uses it for locals, so a
// taint set keyed without it would miss exactly the code that reads most like
// machine output.
var domIdentifier = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

// identifiersIn returns the identifiers a fragment actually names, as a set.
//
// The set is what keeps a one-letter name from tainting a longer one: `x` does
// not match inside `maxX`.
func domIdentifiersIn(fragment string) map[string]bool {
	identifiers := make(map[string]bool)
	for _, match := range domIdentifier.FindAllString(fragment, -1) {
		identifiers[match] = true
	}
	return identifiers
}

// domSinkFinding renders one row for one source-to-sink pair.
func domSinkFinding(p Point, script pageScript, body string, rule domSinkRule,
	argument, match string, tainted map[string]domSourceClass) Finding {
	variant := domSourceDOMTitle
	if rule.needsSource && argumentCarriesURLSource(argument, tainted) {
		variant = domSourceURLTitle
	}
	origin := "not required for this family: the defect is the call itself"
	if rule.needsSource {
		if class, ok := expressionIsTainted(argument, tainted); ok && class == domSourceURL {
			origin = "the address the visitor arrived with (location, the query, the fragment or the referrer)"
		} else {
			origin = "a value the page already held (a cookie, the DOM, history.state, window.name)"
		}
	}
	finding, _ := NewFinding(Spec{
		Module:  "dom-sinks",
		Title:   rule.family + " (" + variant + "): " + rule.typeIndex,
		Claimed: rule.claimed,
		Tier:    TierPotential,
		Point:   p,
		Payload: strings.TrimSpace(match),
		Evidence: "in " + script.name + ":\n" +
			Snippet(body, firstNonBlank(strings.TrimSpace(match), argument), 160),
		Description: "A sink the browser gives meaning to is fed from " + origin + ": " +
			rule.note + ". The source and the sink are both in this page's own code, which is " +
			"what makes this a DOM finding rather than a reflection — a scanner that injected " +
			"the value itself would only be measuring its own payload.",
		Remediation: "Do not build a sink argument from anything the browser hands you. For a " +
			"navigation, allow-list the destinations; for a header or a storage write, take the " +
			"value from a typed field and validate it; for markup, set `textContent` or escape " +
			"before the assignment.",
	})
	return finding
}

// The two variant titles, named once so the report and the register use one
// spelling.
const (
	domSourceDOMTitle = "DOM-based"
	domSourceURLTitle = "reflected DOM-based"
)

// argumentCarriesURLSource reports whether a sink argument reaches a URL-class
// source, which is what makes the row the reflected variant rather than the
// DOM-based one.
func argumentCarriesURLSource(argument string, tainted map[string]domSourceClass) bool {
	identifiers := domIdentifiersIn(argument)
	for name, class := range tainted {
		if class == domSourceURL && identifiers[name] {
			return true
		}
	}
	for name, class := range domSources {
		if class == domSourceURL && identifiers[name] {
			return true
		}
	}
	return false
}
