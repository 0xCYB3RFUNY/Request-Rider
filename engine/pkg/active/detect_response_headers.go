package active

// ResponseHeaders reads the facts a response states about itself in its own
// headers, and reports the ones that contradict the body.
//
// Every check here costs no request: the surface's baseline is the only input,
// which is why this module belongs at the head of the endpoint-level set. The
// rows it produces are structural facts, not guesses — a duplicate cookie name,
// two Content-Type values, or a body that declares itself as HTML while the
// header claims otherwise — so they are reported at TierVerified even though
// nothing was fired at the target.
//
// The reason these are worth a module rather than a lint step is the third one
// in particular: an application that serves `<html>` under `text/plain` has a
// response whose declared type and actual type disagree, and every downstream
// consumer — a browser's sniffing heuristic, a cache, a proxy — resolves that
// disagreement by a rule of its own. A scanner that only fires payloads never
// sees it, and the operator never learns which of their endpoints disagree with
// themselves.

import (
	"context"
	"strconv"
	"strings"
)

// ResponseHeaders is the self-description reader for one endpoint's response.
type ResponseHeaders struct{}

// Name implements Module.
func (ResponseHeaders) Name() string { return "response-headers" }

// Level implements Module.
func (ResponseHeaders) Level() Level { return LevelEndpoint }

// Scan reads the baseline and reports what its headers say about themselves.
func (ResponseHeaders) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.Header == nil {
		return nil
	}
	var out []Finding
	out = append(out, duplicateCookieFindings(p, baseline)...)
	out = append(out, contentTypeFindings(p, baseline)...)
	return out
}

// duplicateCookieFindings reports one row per cookie name the response sets more
// than once (Burp check 0x00400A00).
//
// The same name twice is a real disagreement rather than a formatting quirk:
// one container keeps the value of one of the two Set-Cookie lines and discards
// the other, and which one it keeps is the container's decision — so the
// application cannot know what value the client ended up with. The row quotes
// both lines, because the difference between them (usually a path or an
// attribute) is the whole of what the operator needs to triage it.
func duplicateCookieFindings(p Point, r *Response) []Finding {
	raw := r.SetCookies()
	if len(raw) < 2 {
		return nil
	}
	names := map[string][]string{}
	var order []string
	for _, line := range raw {
		name := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		name = strings.TrimSpace(strings.SplitN(name, ";", 2)[0])
		if name == "" {
			continue
		}
		if _, seen := names[name]; !seen {
			order = append(order, name)
		}
		names[name] = append(names[name], strings.TrimSpace(line))
	}
	var out []Finding
	for _, name := range order {
		lines := names[name]
		if len(lines) < 2 {
			continue
		}
		evidence := strings.Join(lines, "  |  ")
		if len(evidence) > 200 {
			evidence = evidence[:200] + "…"
		}
		finding, _ := NewFinding(Spec{
			Module:   "response-headers",
			Title:    "Duplicate Cookies Set in Response (" + name + ")",
			Claimed:  SeverityLow,
			Tier:     TierVerified,
			Point:    p,
			Evidence: evidence,
			Description: "The response carries " + strconv.Itoa(len(lines)) + " Set-Cookie headers for the cookie " +
				"name \"" + name + "\". Which value survives is the client's decision, so the application " +
				"cannot predict what the next request will carry — and an attacker who controls one of " +
				"the two paths into this response can steer that choice.",
			Remediation: "Set each cookie name once per response, with the attributes it needs; " +
				"split divergent values across distinct names rather than across duplicate headers.",
		})
		out = append(out, finding)
	}
	return out
}

// contentTypeFindings reports the Content-Type disagreements (Burp checks
// 0x00800100, 0x00800200, 0x00800300, 0x00800400, 0x00800500).
func contentTypeFindings(p Point, r *Response) []Finding {
	values := r.Header.Values("Content-Type")
	htmlBody := looksLikeHTML(r.Body)

	// Two Content-Type values in one response is a disagreement between two
	// statements the server made about the same bytes. Two *identical* values
	// are a duplicate header, which no consumer resolves differently, so only
	// values that differ are reported.
	if len(values) > 1 {
		distinct := map[string]bool{}
		for _, v := range values {
			distinct[strings.ToLower(strings.TrimSpace(v))] = true
		}
		if len(distinct) > 1 {
			evidence := strings.Join(values, "  |  ")
			if len(evidence) > 200 {
				evidence = evidence[:200] + "…"
			}
			finding, _ := NewFinding(Spec{
				Module:   "response-headers",
				Title:    "Multiple Content Types Specified",
				Claimed:  SeverityLow,
				Tier:     TierVerified,
				Point:    p,
				Evidence: evidence,
				Description: "The response names more than one Content-Type. Consumers resolve the " +
					"conflict by different rules — some take the first, some the last — so the same bytes " +
					"can be parsed as an HTML document in one client and as a download in another.",
				Remediation: "Send exactly one Content-Type per response.",
			})
			return append([]Finding{finding}, contentTypeFindingsFor(htmlBody, p, r, values)...)
		}
	}
	declared := ""
	if len(values) > 0 {
		declared = strings.TrimSpace(values[0])
	}
	if declared == "" {
		if htmlBody {
			finding, _ := NewFinding(Spec{
				Module:   "response-headers",
				Title:    "Content Type Not Specified",
				Claimed:  SeverityInfo,
				Tier:     TierVerified,
				Point:    p,
				Evidence: "no Content-Type header; body begins with " + bodyOpening(r.Body),
				Description: "The response is an HTML document but names no Content-Type. A client that " +
					"cannot be told what the bytes are has to guess, and its guess is a sniffing " +
					"heuristic rather than the server's intent.",
				Remediation: "Send Content-Type: text/html; charset=utf-8 with every HTML response.",
			})
			return []Finding{finding}
		}
		return nil
	}

	lower := strings.ToLower(declared)
	if !strings.Contains(lower, "text/html") {
		// A declared type that is not HTML while the body is HTML is the
		// disagreement that matters most: the header tells the client to treat
		// markup as plain text, and every parser on the way decides for itself.
		if htmlBody {
			finding, _ := NewFinding(Spec{
				Module:   "response-headers",
				Title:    "Content Type Incorrectly Stated",
				Claimed:  SeverityLow,
				Tier:     TierVerified,
				Point:    p,
				Evidence: "Content-Type: " + declared + " but the body begins with " + bodyOpening(r.Body),
				Description: "The response declares \"" + declared + "\" and carries an HTML document. " +
					"A client that obeys the header renders markup as text; a client that ignores it runs " +
					"the markup. Which one the operator's users get is not decided by the server.",
				Remediation: "Declare the type the body actually is, and serve non-HTML bodies separately.",
			})
			return []Finding{finding}
		}
		return nil
	}

	return charsetFindings(p, r, lower)
}

// contentTypeFindingsFor continues the check after the duplicate-type row, so a
// response can carry both a duplicate and a charset row without either path
// being a second implementation of the other.
func contentTypeFindingsFor(htmlBody bool, p Point, r *Response, values []string) []Finding {
	declared := strings.TrimSpace(values[0])
	lower := strings.ToLower(declared)
	if strings.Contains(lower, "text/html") {
		return charsetFindings(p, r, lower)
	}
	return nil
}

// charsetFindings reports a missing or unrecognised charset on a declared HTML
// response (Burp checks 0x00800200 and 0x00800300).
//
// Both rows are informational and both are facts: `text/html` without a charset
// makes the decoding guesswork, and a charset name no client knows makes it
// guesswork that looks decided.
func charsetFindings(p Point, r *Response, lower string) []Finding {
	charset := contentTypeParameter(lower, "charset")
	if charset == "" {
		finding, _ := NewFinding(Spec{
			Module:   "response-headers",
			Title:    "HTML Charset Missing",
			Claimed:  SeverityInfo,
			Tier:     TierVerified,
			Point:    p,
			Evidence: "Content-Type: " + lower + " carries no charset parameter",
			Description: "An HTML response with no charset leaves the client to decode the bytes by a " +
				"default it chose. A page that is UTF-8 under a Latin-1 default renders mojibake, and a " +
				"page whose attribute values are non-ASCII renders an attack payload the developer never " +
				"intended to write.",
			Remediation: "Send the charset with the type: text/html; charset=utf-8.",
		})
		return []Finding{finding}
	}
	if !knownCharset[charset] {
		finding, _ := NewFinding(Spec{
			Module:   "response-headers",
			Title:    "HTML Charset Unrecognized",
			Claimed:  SeverityInfo,
			Tier:     TierVerified,
			Point:    p,
			Evidence: "Content-Type names charset " + charset,
			Description: "The charset named by the response is not one a client recognises, so the " +
				"declared encoding is as good as absent — the client falls back to its own default while " +
				"the header claims a decision it cannot act on.",
			Remediation: "Use a charset name from the IANA registry that the target clients implement.",
		})
		return []Finding{finding}
	}
	return nil
}

// knownCharset is the small allow-list of encodings a client actually ships.
// A closed list is deliberate: the row reports "the client cannot use this",
// which is a claim about what clients implement, not about what a registry
// once listed.
var knownCharset = map[string]bool{
	"utf-8": true, "utf8": true, "us-ascii": true, "ascii": true,
	"iso-8859-1": true, "iso-8859-15": true, "windows-1250": true,
	"windows-1251": true, "windows-1252": true, "windows-1253": true,
	"windows-1254": true, "windows-1255": true, "windows-1256": true,
	"windows-1257": true, "windows-1258": true, "koi8-r": true,
	"shift_jis": true, "euc-jp": true, "iso-2022-jp": true, "gb2312": true,
	"gbk": true, "gb18030": true, "big5": true, "euc-kr": true,
}

// contentTypeParameter reads one parameter out of a lower-cased Content-Type
// value (`charset=utf-8`), returning "" when the parameter is absent.
func contentTypeParameter(lower, name string) string {
	for _, part := range strings.Split(lower, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, name+"=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(part, name+"="))
		return strings.Trim(value, `"'`)
	}
	return ""
}

// looksLikeHTML reports whether a body is an HTML document, by the two openings
// every HTML document carries. It is the gate for the content-type rows: an
// endpoint that is genuinely a stylesheet must not be reported for having a
// stylesheet's Content-Type.
func looksLikeHTML(body string) bool {
	const limit = 512
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > limit {
		head = head[:limit]
	}
	if head == "" {
		return false
	}
	if strings.HasPrefix(head, "<!doctype html") {
		return true
	}
	// A comment, an XML declaration or whitespace may precede the root element;
	// the root element itself is what decides it, so the marker is searched for
	// rather than required at byte zero.
	return strings.HasPrefix(head, "<html") ||
		strings.HasPrefix(head, "<?xml") && strings.Contains(head, "<html")
}

// bodyOpening renders the first bytes of a body as evidence, with whitespace
// collapsed so the excerpt stays one readable line.
func bodyOpening(body string) string {
	const limit = 120
	flat := strings.Join(strings.Fields(body), " ")
	if len(flat) > limit {
		return flat[:limit] + "…"
	}
	return flat
}
