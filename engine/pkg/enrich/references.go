package enrich

import (
	"net/url"
	"strings"
)

// Reference is one href/src discovered in a document, split the way the analyst
// needs it: an absolute URL is something the crawler can fetch, a path is
// something it can only fetch by resolving against a base, and a fragment-only
// reference points at nothing at all.
type Reference struct {
	// Raw is the attribute value exactly as written in the document.
	Raw string `json:"raw"`
	// Absolute is true when the reference carries its own scheme and host.
	Absolute bool `json:"absolute"`
	// Attribute is the attribute it came from (`href`, `src`, `action`).
	Attribute string `json:"attribute"`
	// Tag is the element name, lower-case.
	Tag string `json:"tag"`
	// ProtocolRelative marks `//host/path`, which is absolute in every way that
	// matters to a crawler but carries no scheme. Treating it as a path is the
	// kind of near-miss that silently drops a whole CDN from a map.
	ProtocolRelative bool `json:"protocol_relative,omitempty"`
	// Inline marks `javascript:`, `data:` and `mailto:` — real references in the
	// markup that are not fetchable. They are reported rather than dropped,
	// because `javascript:` navigation is a finding in its own right.
	Inline bool `json:"inline,omitempty"`
	// Scheme is the inline scheme when Inline is set.
	Scheme string `json:"scheme,omitempty"`
}

// ExtractReferences pulls every reference-bearing attribute out of an HTML
// document and classifies each value.
//
// Port of `trap-bytes/gourlex` (MIT, upstream commit bd2143dd6b7b47f037e6d14ae1dfc79798099791).
// The original walks the html tokenizer and reads exactly two attributes, `href`
// and `src`, and it has a bug worth naming: it reads both attributes from every
// start tag but stores them in one pair of variables, so a tag that carries both
// (which none of them do, but a `<base href>` next to a `<link src>` is enough to
// reach it) can only report one.
//
// Three capabilities are added rather than copied, and each is a separate row in
// `gourlex_reconciliation.md`:
//
//   - `img@src`, `iframe@src`, `area@href`, `form@action`, `link@href` are read
//     by name, so a stylesheet, an image directory and an upload endpoint all
//     reach the map. The original reads `src` from every element, which reaches
//     `img@src` by accident and `iframe@src` by the same accident; reading by
//     name is what makes the set explicit and testable.
//   - Inline and protocol-relative references are classified instead of being
//     appended to the path list, because `/x` and `javascript:alert(1)` in the
//     same column is not a classification.
//   - A bare fragment (`#top`) and an empty value are dropped, matching the
//     original, and the reason is in the test rather than in a comment here.
func ExtractReferences(body string) []Reference {
	var out []Reference
	// A document is scanned for tags by hand rather than through a parser
	// because this function runs on every crawled page, including the ones whose
	// Content-Type lies about being HTML, and a token walk tolerates that where
	// a tree builder would reject the document outright.
	forEachStartTag(body, func(tag string, attrs map[string]string) {
		for _, name := range referenceAttributes {
			raw, ok := attrs[name]
			if !ok {
				continue
			}
			value := strings.TrimSpace(raw)
			// A same-page fragment is not a reference to anything else.
			// The original drops only a bare `#`; `#top` is the same idea
			// written fully, and resolving it would fetch the page a second
			// time and publish it under a URL that has no path of its own.
			if value == "" || strings.HasPrefix(value, "#") {
				continue
			}
			out = append(out, classifyReference(value, tag, name))
		}
	})
	return out
}

// referenceAttributes is the read order. It is a list rather than a map so that
// a tag carrying several of them reports them in a stable order, and so the order
// is visible in one place instead of scattered through a walk.
var referenceAttributes = []string{"href", "src", "action", "data-src", "data-url", "formaction"}

// inlineSchemes are the schemes that are real references but never fetchable.
// `mailto:` and `tel:` are included because an analyst collecting contact points
// wants them and dropping them would be a silent loss; they are marked Inline so
// the caller can decide.
var inlineSchemes = map[string]bool{
	"javascript": true, "data": true, "mailto": true, "tel": true,
	"blob": true, "about": true, "file": true,
}

func classifyReference(value, tag, attribute string) Reference {
	ref := Reference{Raw: value, Attribute: attribute, Tag: strings.ToLower(tag)}
	lower := strings.ToLower(value)

	if strings.HasPrefix(lower, "//") {
		ref.ProtocolRelative = true
		return ref
	}
	if idx := strings.IndexByte(lower, ':'); idx > 0 {
		scheme := lower[:idx]
		// A scheme cannot contain `/`, `?` or `#`; without that test `a/b:c`
		// would read as scheme `a/b` and the reference would vanish.
		if !strings.ContainsAny(scheme, "/?#") {
			switch {
			case scheme == "http" || scheme == "https":
				ref.Absolute = true
			case inlineSchemes[scheme]:
				ref.Inline = true
				ref.Scheme = scheme
			default:
				// An unknown scheme is still a reference; it is not fetchable
				// and reporting it as a path would resolve it against the base
				// and produce a URL that was never in the document.
				ref.Inline = true
				ref.Scheme = scheme
			}
			return ref
		}
	}
	return ref
}

// Fetchable returns the references a crawler can act on: absolute URLs and
// site-relative paths. Inline references are excluded and reported separately by
// the caller, because resolving them would invent a URL.
func Fetchable(refs []Reference) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Inline {
			continue
		}
		out = append(out, ref.Raw)
	}
	return out
}

// SplitURLsAndPaths is the original's own output shape: absolute URLs on one
// side, everything else on the other, order preserved.
//
// It exists because the distinction is not ours to invent: `https://cdn/x.js` is
// a different fetch from `/api/v1`, and a report that mixes them cannot answer
// "which hosts does this site talk to".
func SplitURLsAndPaths(refs []Reference) (urls []string, paths []string) {
	urls = make([]string, 0, len(refs))
	paths = make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Inline {
			continue
		}
		if ref.Absolute || ref.ProtocolRelative {
			urls = append(urls, ref.Raw)
			continue
		}
		paths = append(paths, ref.Raw)
	}
	return urls, paths
}

// Hosts returns the distinct hostnames of the absolute references, in
// first-seen order. A host the analyst has not seen before is a finding on its
// own: it is either an asset they do not manage or a third party holding a
// script with the site's cookies in scope.
func Hosts(refs []Reference) []string {
	seen := map[string]bool{}
	var out []string
	for _, ref := range refs {
		if !ref.Absolute && !ref.ProtocolRelative {
			continue
		}
		candidate := ref.Raw
		if !strings.Contains(candidate, "://") {
			candidate = "https:" + candidate
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Host == "" {
			continue
		}
		host := strings.ToLower(parsed.Host)
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

// forEachStartTag calls fn for every start or self-closing tag in body with its
// lower-cased tag name and its attributes.
//
// This is a tolerant scanner, not an HTML parser: it tracks quoting so a `>` inside
// an attribute value does not end the tag early, and it skips comments and raw
// text so a tag mentioned inside a script is not reported as a tag. That is
// enough for reference discovery and costs one pass with no allocation per tag,
// which matters because this runs on every crawled page.
func forEachStartTag(body string, fn func(tag string, attrs map[string]string)) {
	forEachTag(body, func(tag string, attrs map[string]string, _ bool) { fn(tag, attrs) })
}

// forEachTag walks every tag, opening and closing alike. `forEachStartTag` is the
// form most callers want; the CSRF analyser needs the closing tags too, because a
// form's inputs end at `</form>` and reading past it would attribute another
// form's token field to this one.
func forEachTag(body string, fn func(tag string, attrs map[string]string, closing bool)) {
	i := 0
	n := len(body)
	for i < n {
		lt := strings.IndexByte(body[i:], '<')
		if lt < 0 {
			return
		}
		i += lt
		switch {
		case strings.HasPrefix(body[i:], "<!--"):
			end := strings.Index(body[i+4:], "-->")
			if end < 0 {
				return
			}
			i += 4 + end + 3
			continue
		case strings.HasPrefix(body[i:], "<!"), strings.HasPrefix(body[i:], "<?"):
			end := strings.IndexByte(body[i:], '>')
			if end < 0 {
				return
			}
			i += end + 1
			continue
		case strings.HasPrefix(body[i:], "</"):
			end := strings.IndexByte(body[i:], '>')
			if end < 0 {
				return
			}
			if name := strings.ToLower(strings.TrimSpace(body[i+2 : i+end])); name != "" {
				fn(name, map[string]string{}, true)
			}
			i += end + 1
			continue
		}
		name, attrs, next, ok := readTag(body, i)
		if !ok {
			return
		}
		if name != "" {
			fn(name, attrs, false)
			// `<script>` and `<style>` hold raw text, not markup. A document
			// that builds an anchor inside a template literal is extremely
			// common, and reporting `href='/not-a-link'` from a JavaScript
			// string is a finding about our parser, not about the site.
			if name == "script" || name == "style" {
				if end := indexRawTextEnd(body, next, name); end > next {
					i = end
					continue
				}
			}
		}
		i = next
	}
}

// indexRawTextEnd returns the offset just past `</name`, or -1 when the element
// is never closed. HTML really does contain unclosed `<script>`, and treating
// the rest of the document as script text would swallow every reference after
// it — so an unclosed element returns -1 and scanning continues normally.
func indexRawTextEnd(body string, from int, name string) int {
	lower := strings.ToLower(body)
	needle := "</" + name
	for at := from; at < len(lower); {
		idx := strings.Index(lower[at:], needle)
		if idx < 0 {
			return -1
		}
		pos := at + idx
		after := pos + len(needle)
		if after >= len(body) {
			return -1
		}
		if body[after] == '>' || isSpace(body[after]) || body[after] == '/' {
			return after + 1
		}
		at = pos + 1
	}
	return -1
}

func readTag(body string, start int) (name string, attrs map[string]string, next int, ok bool) {
	i := start + 1
	n := len(body)
	nameStart := i
	for i < n && isNameByte(body[i], i == nameStart) {
		i++
	}
	name = strings.ToLower(body[nameStart:i])
	if name == "" {
		return "", nil, start + 1, true
	}
	attrs = map[string]string{}
	for i < n {
		for i < n && isSpace(body[i]) {
			i++
		}
		if i >= n {
			break
		}
		if body[i] == '>' {
			return name, attrs, i + 1, true
		}
		if body[i] == '/' {
			i++
			continue
		}
		attrStart := i
		for i < n && !isSpace(body[i]) && body[i] != '=' && body[i] != '>' && body[i] != '/' {
			i++
		}
		attrName := strings.ToLower(body[attrStart:i])
		for i < n && isSpace(body[i]) {
			i++
		}
		value := ""
		if i < n && body[i] == '=' {
			i++
			for i < n && isSpace(body[i]) {
				i++
			}
			if i < n && (body[i] == '"' || body[i] == '\'') {
				quote := body[i]
				i++
				valueStart := i
				for i < n && body[i] != quote {
					i++
				}
				value = body[valueStart:i]
				if i < n {
					i++
				}
			} else {
				valueStart := i
				for i < n && !isSpace(body[i]) && body[i] != '>' {
					i++
				}
				value = body[valueStart:i]
			}
		}
		if attrName != "" {
			if _, exists := attrs[attrName]; !exists {
				attrs[attrName] = value
			}
		}
	}
	return name, attrs, n, true
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isNameByte(c byte, first bool) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
		return true
	}
	if c == '_' || c == '-' {
		return true
	}
	return !first && c >= '0' && c <= '9'
}
