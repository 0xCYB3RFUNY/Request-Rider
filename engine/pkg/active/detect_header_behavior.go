package active

// HeaderBehavior probes the three request headers whose *echo* or whose
// *effect* is itself the finding: a client IP the application accepted from a
// header (Burp 0x00400110), a response that changes because the User-Agent
// changed (0x00400112, 0x00400120), and one that changes because the Referer
// did (0x00400100).
//
// # What makes these three one module and not three
//
// They are the same measurement — send the same request twice, change one
// header, read the difference — and the trap in all three is the same: a page
// that renders the time, a per-request token or a rotating banner differs from
// itself on every fetch. A detector that compares the variant against the
// baseline alone calls that a finding, and Burp's own rows for these two checks
// are the ones analysts learn to ignore first.
//
// So the measurement has a control. The module sends the request twice with no
// header changed, and the variant has to differ from the control by more than
// the control and the baseline differ from each other. The number that decides
// the row is printed in the evidence, so an operator reading "the page moved
// 0 bytes and the header moved it 214" can disagree with a threshold without
// disagreeing with the finding.
//
// # Why the module costs four requests and what it reads
//
// One control, one IP echo probe, one User-Agent variant, one Referer variant.
// The IP echo needs no control: its token is minted per run, so it cannot
// already be on the page. The module is gated to HTML responses because a JSON
// API's UA handling is a routing decision rather than a page-shape one, and
// because the gate keeps a run's requests on the surfaces where the answer is
// readable.

import (
	"context"
	"crypto/rand"
	"net/http"
	"strconv"
	"strings"
)

// HeaderBehavior is the request-header differential detector.
type HeaderBehavior struct{}

// Name implements Module.
func (HeaderBehavior) Name() string { return "header-behavior" }

// Level implements Module.
func (HeaderBehavior) Level() Level { return LevelEndpoint }

// movementFloor is the smallest body movement a header is allowed to explain
// before the module reports it.
//
// A threshold is a judgement, so it is a named constant with a reason rather
// than a literal in the comparison: a header-dependent page differs by blocks
// of markup, and a page that differs by a dozen bytes is a page that renders a
// counter. It is deliberately far above zero, because the cost of a missed row
// here is one informational observation, while the cost of a false one is an
// analyst who stops reading this module's rows.
const movementFloor = 64

// Scan sends the control and the three variants, and reports what moved.
func (h HeaderBehavior) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.Header == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(baseline.HeaderValue("Content-Type")), "text/html") {
		return nil
	}
	if strings.TrimSpace(baseline.Body) == "" {
		return nil
	}

	var out []Finding
	if finding := spoofableClientIP(ctx, t, p, baseline); finding != nil {
		out = append(out, *finding)
	}
	if finding := headerDependentResponse(ctx, t, p, baseline, "User-Agent"); finding != nil {
		out = append(out, *finding)
	}
	if finding := headerDependentResponse(ctx, t, p, baseline, "Referer"); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// clientIPHeaders are the names an application reads a client's address from
// when a proxy sits in front of it. The list is every spelling a deployment
// actually uses, because an application that honours one of them is reachable
// whichever name this module happens to have sent.
var clientIPHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Client-IP",
	"True-Client-IP", "CF-Connecting-IP", "Fastly-Client-IP", "Forwarded",
}

// spoofableClientIP reports a response that echoes an address the client
// invented (Burp 0x00400110).
//
// The token is minted per run out of the two documentation ranges, so it cannot
// already be in the page — which is why this probe needs no control while the
// two below it do. Every header spelling is set to the same address in one
// request: an application that honours any of them answers, and the answer is
// the row.
func spoofableClientIP(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	address := documentAddress()
	header := http.Header{}
	for _, name := range clientIPHeaders {
		header.Set(name, address)
	}
	header.Set("Forwarded", "for="+address)
	resp, err := t.Do(ctx, p.Method, p.URL, p.Values, false, header)
	if err != nil || resp == nil {
		return nil
	}
	if !Fresh(baseline, resp, address) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "header-behavior",
		Title:   "Spoofable Client IP Address",
		Claimed: SeverityMedium,
		Tier:    TierVerified,
		Point:   p,
		Payload: address,
		Evidence: "the response names " + address + ", which the scan invented in " +
			strings.Join(clientIPHeaders[:3], ", ") + " and friends: " + snippetAround(resp.Body, address),
		Description: "The endpoint accepted a client address from a request header and wrote it into " +
			"its response. Any control that trusts that address — an access decision, a rate limit, an " +
			"audit log, a blocklist — is then a control a caller can set to any value it likes.",
		Remediation: "Take the client address from the connection, and treat a header-supplied one as " +
			"data a trusted proxy may add and a client may not. Strip the header at the edge.",
	})
	return &finding
}

// headerDependentResponse reports a response that changed because `header`
// changed, measured against a control that changed nothing.
//
// The header's own value is stripped from both bodies before comparing: a page
// that prints the request's User-Agent back at the operator proves the header
// arrived, not that the page depends on it.
func headerDependentResponse(ctx context.Context, t *Transport, p Point, baseline *Response, header string) *Finding {
	control, err := t.Do(ctx, p.Method, p.URL, p.Values, false, nil)
	if err != nil || control == nil {
		return nil
	}
	token := headerToken(header)
	// The client's own default User-Agent is the token the baseline and the
	// control both carry, so it is stripped from those two; the Referer variant
	// sends no Referer originally, so nothing of that kind applies there.
	pageToken := ""
	if header == "Referer" {
		pageToken = t.userAgent()
	}

	noise := bodyMovement(stripTokens(baseline.Body, pageToken), stripTokens(control.Body, pageToken))
	variant, err := t.Do(ctx, p.Method, p.URL, p.Values, false, headerSet(header, token))
	if err != nil || variant == nil {
		return nil
	}
	moved := bodyMovement(stripTokens(control.Body, token), stripTokens(variant.Body, token))

	if moved < movementFloor || moved < noise+movementFloor {
		return nil
	}

	claim := "The endpoint's response changes when " + header + " changes."
	switch header {
	case "User-Agent":
		claim = "The endpoint serves a different response to a different " + header + "."
	case "Referer":
		claim = "The endpoint serves a different response depending on where the request says the " +
			"visitor came from."
	}
	finding, _ := NewFinding(Spec{
		Module:  "header-behavior",
		Title:   header + "-Dependent Response",
		Claimed: SeverityInfo,
		Tier:    TierPotential,
		Point:   p,
		Payload: token,
		Evidence: claim + " The same request unchanged changed the body by " + strconv.Itoa(noise) +
			" bytes; changing " + header + " changed it by " + strconv.Itoa(moved) + " bytes (" +
			strconv.Itoa(len(control.Body)) + " → " + strconv.Itoa(len(variant.Body)) + ").",
		Description: "A response whose shape depends on a request header is a response with a second, " +
			"hidden behaviour: content that one client is served and another is not. That is a cache " +
			"poisoning surface, an access-control bypass surface, and — when the difference is an " +
			"error page — a place where a scanner's own signature changes what the target says.",
		Remediation: "Decide the response by the request's authorisation and its resource, not by the " +
			"client's self-description. If a variant page exists, vary it in a cache key the " +
			"infrastructure knows about.",
	})
	return &finding
}

// headerSet builds the header set for one variant request.
func headerSet(header, value string) http.Header {
	out := http.Header{}
	out.Set(header, value)
	return out
}

// headerToken returns the value this module sends in `header`.
//
// The User-Agent is a full, plain one so a server that parses it parses
// something ordinary rather than an error; the Referer is a `.invalid` host,
// which by RFC 2606 can never resolve, so the variant can only ever be read as
// a value rather than followed as a link.
func headerToken(header string) string {
	switch header {
	case "User-Agent":
		return "Mozilla/5.0 (compatible; RequestRider/1.3; +https://requestrider.invalid/scanner)"
	case "Referer":
		return "https://requestrider.invalid/referer-canary/"
	default:
		return "requestrider-" + header
	}
}

// documentAddress mints one address out of the two documentation ranges.
//
// TEST-NET-2 (198.51.100.0/24) and TEST-NET-3 (203.0.113.0/24) are reserved for
// exactly this: they look routable and are guaranteed to lead nowhere, so an
// application that logs or reflects the address records a token that belongs to
// nobody. The range is chosen per run, so a scan that hits the same endpoint
// twice does not ask it the same question twice.
func documentAddress() string {
	raw := make([]byte, 2)
	if _, err := rand.Read(raw); err != nil {
		// Without entropy there is no token to offer, and a fixed one would risk
		// colliding with a value the page already carries. Returning "" makes
		// the probe's echo test fail closed rather than report a guess.
		return ""
	}
	octet := int(raw[0])%254 + 1
	if raw[1]%2 == 0 {
		return "203.0.113." + strconv.Itoa(octet)
	}
	return "198.51.100." + strconv.Itoa(octet)
}

// bodyMovement measures how far two bodies are apart after their tokens are
// stripped.
//
// Length is the measure, because it is the measure a differential detector can
// defend: "the page moved 214 bytes" is a number an operator can re-read, while
// "the page looks different" is the vague judgement the project forbids. Content
// that changed without changing length still counts as one byte of movement, so
// a same-length rewrite is never reported as no movement at all.
func bodyMovement(a, b string) int {
	left, right := collapseWhitespace(a), collapseWhitespace(b)
	if left == right {
		return 0
	}
	distance := len(left) - len(right)
	if distance < 0 {
		distance = -distance
	}
	if distance == 0 {
		return 1
	}
	return distance
}

// stripTokens removes a token from a body so a page that echoes the request's
// own header back is not counted as depending on it.
func stripTokens(body string, tokens ...string) string {
	out := body
	for _, token := range tokens {
		if token != "" {
			out = strings.ReplaceAll(out, token, "")
		}
	}
	return out
}

// collapseWhitespace flattens a body for comparison, so a difference in
// indentation is not a difference in content.
func collapseWhitespace(body string) string {
	return strings.Join(strings.Fields(body), " ")
}

// snippetAround returns the neighbourhood of a token, as the evidence line for
// a row whose proof is an echo.
func snippetAround(body, token string) string {
	idx := strings.Index(body, token)
	if idx < 0 {
		return ""
	}
	start := idx - 60
	if start < 0 {
		start = 0
	}
	end := idx + len(token) + 60
	if end > len(body) {
		end = len(body)
	}
	snippet := trimEvidence(body[start:end])
	if start > 0 {
		snippet = "…" + snippet
	}
	if end < len(body) {
		snippet += "…"
	}
	return snippet
}
