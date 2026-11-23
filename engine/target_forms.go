package main

// Form submission for the static Target crawler.
//
// A link is a GET the page offers; a form is a request the page *describes*,
// and the application behind it often answers only to that exact shape:
// `/vulnerabilities/sqli/` is a page, `/vulnerabilities/sqli/?id=x&Submit=Submit`
// is the endpoint. A crawler that only follows `href` never reaches the second.
//
// Two decisions are deliberate:
//
//   - Values are markers, not data. Text-like fields carry `crawlFormMarker`,
//     hidden/select/checkbox/radio fields carry what the form itself offers,
//     and file inputs are left out. The crawler never invents credentials.
//   - A form is submitted once per *shape* (method, action, field names), not
//     once per value set. A hidden anti-CSRF token changes on every response,
//     so keying on values would make every answer carry a "new" form and the
//     crawl would never end.

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// crawlFormMarker is the value placed into free-text fields.
const crawlFormMarker = "RRCRAWL"

// mapForm is one form turned into the request a browser would send.
type mapForm struct {
	// Method is GET or POST.
	Method string
	// URL is the request URL. For GET the field query is already part of it.
	URL string
	// Body is the url-encoded body for POST, empty for GET.
	Body string
	// Key identifies the form shape for de-duplication.
	Key string
}

// extractMapForms reads every <form> of an HTML document.
func extractMapForms(body []byte, contentType string, base *url.URL) []mapForm {
	if base == nil || len(body) == 0 || !strings.Contains(strings.ToLower(contentType), "html") {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	var forms []mapForm
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			if form, ok := buildMapForm(node, base); ok {
				forms = append(forms, form)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return forms
}

func nodeAttr(node *html.Node, key string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
}

func buildMapForm(form *html.Node, base *url.URL) (mapForm, bool) {
	method := http.MethodGet
	if raw, ok := nodeAttr(form, "method"); ok && strings.EqualFold(strings.TrimSpace(raw), http.MethodPost) {
		method = http.MethodPost
	}
	action := base
	if raw, ok := nodeAttr(form, "action"); ok && strings.TrimSpace(raw) != "" {
		resolved, err := base.Parse(strings.TrimSpace(raw))
		if err != nil || (resolved.Scheme != "http" && resolved.Scheme != "https") {
			return mapForm{}, false
		}
		action = resolved
	}
	target := *action
	target.Fragment = ""

	fields := url.Values{}
	var names []string
	seenRadio := map[string]bool{}
	submitTaken := false
	add := func(name, value string) {
		if _, exists := fields[name]; !exists {
			names = append(names, name)
		}
		fields.Add(name, value)
	}

	var collect func(*html.Node)
	collect = func(node *html.Node) {
		if node.Type == html.ElementNode {
			name, _ := nodeAttr(node, "name")
			name = strings.TrimSpace(name)
			switch node.Data {
			case "input":
				kind, _ := nodeAttr(node, "type")
				kind = strings.ToLower(strings.TrimSpace(kind))
				value, hasValue := nodeAttr(node, "value")
				if name == "" {
					break
				}
				switch kind {
				case "file", "reset":
				case "submit", "image", "button":
					if kind != "button" && !submitTaken {
						submitTaken = true
						if !hasValue || value == "" {
							value = "Submit"
						}
						add(name, value)
					}
				case "hidden":
					add(name, value)
				case "checkbox":
					if !hasValue || value == "" {
						value = "on"
					}
					add(name, value)
				case "radio":
					if !seenRadio[name] {
						seenRadio[name] = true
						if !hasValue || value == "" {
							value = "on"
						}
						add(name, value)
					}
				case "number", "range":
					if !hasValue || value == "" {
						value = "1"
					}
					add(name, value)
				default:
					if !hasValue || value == "" {
						value = crawlFormMarker
					}
					add(name, value)
				}
			case "textarea":
				if name != "" {
					text := strings.TrimSpace(textOf(node))
					if text == "" {
						text = crawlFormMarker
					}
					add(name, text)
				}
			case "select":
				if name != "" {
					add(name, selectValue(node))
				}
			case "button":
				kind, _ := nodeAttr(node, "type")
				kind = strings.ToLower(strings.TrimSpace(kind))
				if name != "" && (kind == "" || kind == "submit") && !submitTaken {
					submitTaken = true
					value, hasValue := nodeAttr(node, "value")
					if !hasValue || value == "" {
						value = "Submit"
					}
					add(name, value)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			collect(child)
		}
	}
	collect(form)

	sort.Strings(names)
	shape := target
	shape.RawQuery = ""
	key := method + " " + shape.String() + " " + strings.Join(names, ",")
	if method == http.MethodPost {
		return mapForm{Method: method, URL: target.String(), Body: fields.Encode(), Key: key}, true
	}
	target.RawQuery = fields.Encode()
	return mapForm{Method: method, URL: target.String(), Key: key}, true
}

func textOf(node *html.Node) string {
	var out strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			out.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return out.String()
}

// selectValue is the value a browser would send for an untouched <select>: the
// selected option, otherwise the first one.
func selectValue(sel *html.Node) string {
	first, picked := "", ""
	haveFirst, havePicked := false, false
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "option" {
			value, ok := nodeAttr(node, "value")
			if !ok {
				value = strings.TrimSpace(textOf(node))
			}
			if !haveFirst {
				first, haveFirst = value, true
			}
			if _, selected := nodeAttr(node, "selected"); selected && !havePicked {
				picked, havePicked = value, true
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(sel)
	if havePicked {
		return picked
	}
	if haveFirst {
		return first
	}
	return crawlFormMarker
}
