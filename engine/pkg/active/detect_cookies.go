// Cookie hardening and credential transport.
//
// # What upstream contributes and what is already owned here
//
// Arachni's grep family carries four cookie and form checks: `insecure_cookies`,
// `http_only_cookies`, `cookie_set_for_parent_domain`,
// `unencrypted_password_forms`, plus `password_autocomplete`, `form_upload` and
// `captcha`. The misconfiguration detector in this package owns `HSTS` and
// `X-Frame-Options` already, and the session-fixation detector owns the
// session cookie's own attributes — because an attribute missing from a *session*
// cookie is a fixation precondition and an attribute missing from a preference
// cookie is not.
//
// So this module takes the two that have no other owner:
//
//   - a cookie scoped wider than the host that set it, which is the only one of
//     these that is a *domain* decision rather than a flag, and the one that lets a
//     sibling host read a cookie it should never see;
//   - a password field submitted over cleartext HTTP, which is not a hardening
//     gap at all — the credential is on the wire in the request body and in every
//     proxy log between here and the server.
//
// # Why a missing HttpOnly on a preference cookie is reported at all
//
// It is not a vulnerability on its own and the row says so. It is reported
// because it is the condition that decides whether an XSS finding elsewhere on
// the site can read anything at all, and a report that omitted it would leave the
// analyst to work that out from the XSS row. The tier is `potential` and the
// severity is `low`, which together mean: real, worth a line in the report, not
// worth waking anyone for.
package active

import (
	"context"
	"strings"
)

// cookieScopeLevels are the three ways a cookie can be scoped, from widest to
// narrowest.
//
// They are ordered rather than a set because the comparison is a comparison: a
// cookie scoped to the parent domain is readable by every sibling under it, and
// that is a different row from a cookie that carries no attribute at all.
type cookieScope int

const (
	// scopeParentDomain is an explicit `Domain=` attribute. Readable by the
	// setting host and by every sibling that shares the suffix.
	scopeParentDomain cookieScope = iota
	// scopeHostOnly is no `Domain=` attribute — RFC 6265's default, and the
	// correct one.
	scopeHostOnly
	// scopeUnknown means the attribute was present but unparseable, which is
	// itself worth a row: a cookie the browser cannot scope correctly is a cookie
	// whose scope the server does not control.
	scopeUnknown
)

// Cookies is the cookie and credential-transport detector.
type Cookies struct{}

// Name implements Module.
func (Cookies) Name() string { return "cookies" }

// Level implements Module.
func (Cookies) Level() Level { return LevelEndpoint }

// Scan probes one endpoint and reports what its own response says.
func (m Cookies) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	var out []Finding
	for _, setCookie := range baseline.SetCookies() {
		if ctx.Err() != nil {
			return nil
		}
		if finding := cookieScopeFinding(p, baseline, setCookie); finding != nil {
			out = append(out, *finding)
		}
		if finding := cookieFlagFinding(p, baseline, setCookie); finding != nil {
			out = append(out, *finding)
		}
	}
	if finding := cleartextPasswordFinding(p, baseline); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// parseCookie splits a `Set-Cookie` value into its parts.
//
// It is hand-parsed rather than run through `http.Response.Cookies` for the same
// reason the session detector hand-parses: the standard parser drops the attributes
// that are the entire subject here, and a detector that reports on the attributes
// must be reading the bytes that carry them.
func parseCookie(setCookie string) (name string, attributes map[string]string, order []string) {
	attributes = map[string]string{}
	parts := strings.Split(setCookie, ";")
	if len(parts) == 0 {
		return "", nil, nil
	}
	name, _, _ = strings.Cut(strings.TrimSpace(parts[0]), "=")
	for _, part := range parts[1:] {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if _, seen := attributes[key]; !seen {
			order = append(order, key)
		}
		attributes[key] = strings.TrimSpace(value)
	}
	return strings.TrimSpace(name), attributes, order
}

// cookieScopeOf reads a cookie's domain scope.
func cookieScopeOf(attributes map[string]string, host string) cookieScope {
	domain, declared := attributes["domain"]
	if !declared || domain == "" {
		return scopeHostOnly
	}
	trimmed := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, ".")))
	if trimmed == "" || strings.EqualFold(trimmed, host) {
		return scopeHostOnly
	}
	// The comparison is a suffix test with a dot on the left of it, and the dot is
	// the whole point: `notexample.com` ends with `example.com` as a string but is
	// a different registrable domain, and a suffix test without the dot is how a
	// cookie set by `evil-example.com` gets read by `example.com`'s siblings.
	if strings.HasSuffix(strings.ToLower(host), "."+trimmed) {
		return scopeParentDomain
	}
	return scopeUnknown
}

// cookieScopeFinding reports a cookie scoped wider than the host that set it.
func cookieScopeFinding(p Point, baseline *Response, setCookie string) *Finding {
	name, attributes, _ := parseCookie(setCookie)
	if name == "" {
		return nil
	}
	host := hostOf(p.URL)
	if host == "" {
		return nil
	}
	switch cookieScopeOf(attributes, host) {
	case scopeParentDomain:
		finding, _ := NewFinding(Spec{
			Module:   "cookies",
			Title:    "Cookie Scoped to Parent Domain (" + name + ")",
			Claimed:  SeverityMedium,
			Tier:     TierVerified,
			Point:    p,
			Payload:  "GET " + p.URL,
			Evidence: "Set-Cookie: " + redactCookieValue(setCookie),
			Description: "Cookie " + name + " is issued with an explicit Domain attribute covering " + host +
				" and every sibling beneath it. A cookie scoped host-only is unreadable from any other host; " +
				"one scoped to the parent is sent to every one of them, so a single compromised sibling " +
				"reads it — and so does any subdomain an attacker can get created, which is the ordinary " +
				"way this becomes exploitable.",
			Remediation: "Omit the Domain attribute unless the cookie genuinely has to be shared. When it " +
				"does, use `__Host-` prefixed names, which browsers refuse to accept with a Domain " +
				"attribute at all, and which must be Secure, path `/` and host-only.",
		})
		return &finding
	case scopeUnknown:
		finding, _ := NewFinding(Spec{
			Module:   "cookies",
			Title:    "Cookie Domain Attribute Does Not Cover This Host (" + name + ")",
			Claimed:  SeverityLow,
			Tier:     TierVerified,
			Point:    p,
			Payload:  "GET " + p.URL,
			Evidence: "Set-Cookie: " + redactCookieValue(setCookie),
			Description: "Cookie " + name + " carries a Domain attribute that does not cover the host that " +
				"set it. The browser will scope it somewhere the server does not control, so the cookie's " +
				"effective scope is decided by the browser's public-suffix rules rather than by this " +
				"application.",
			Remediation: "Set the Domain attribute to the host that sets the cookie, or omit it entirely.",
		})
		return &finding
	}
	return nil
}

// cookieFlagFinding reports a cookie missing HttpOnly or Secure.
//
// Both attributes are checked together and reported as one row, because the
// operator's action is the same — set both — and two rows for one cookie makes a
// report of forty preferences cookies eighty rows long.
func cookieFlagFinding(p Point, baseline *Response, setCookie string) *Finding {
	name, attributes, _ := parseCookie(setCookie)
	if name == "" || sessionCookieName(name) {
		// The session cookie's attributes are the session-fixation detector's
		// subject, and reporting them twice would put two rows with different
		// severities on one finding.
		return nil
	}
	var missing []string
	if _, ok := attributes["httponly"]; !ok {
		missing = append(missing, "HttpOnly")
	}
	secure, hasSecure := attributes["secure"]
	if !hasSecure && strings.HasPrefix(p.URL, "https://") {
		// `Secure` is only a requirement on a page already served over TLS. On a
		// cleartext page the attribute would be honoured by the browser and the
		// cookie would simply never come back, which is a different bug.
		missing = append(missing, "Secure")
	}
	if hasSecure && !strings.EqualFold(secure, "true") {
		// `Secure=` with anything other than `true` is how a template emits the
		// attribute name and forgets the value. The browser treats it as absent.
		missing = append(missing, "Secure")
	}
	if len(missing) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "cookies",
		Title:    "Cookie Missing " + strings.Join(missing, " and ") + " (" + name + ")",
		Claimed:  SeverityLow,
		Tier:     TierPotential,
		Point:    p,
		Payload:  "GET " + p.URL,
		Evidence: "Set-Cookie: " + redactCookieValue(setCookie),
		Description: "Cookie " + name + " is issued without " + strings.Join(missing, " and ") + ". Neither " +
			"attribute is a vulnerability by itself: together they decide whether an XSS finding elsewhere " +
			"on this site can read the cookie and whether anyone on the network path can take it. The row " +
			"is reported because that dependency is invisible from the XSS row alone.",
		Remediation: "Set HttpOnly and Secure on every cookie that is not required to be readable by script, " +
			"and use `SameSite` to decide whether it travels with cross-site requests.",
	})
	return &finding
}

// cleartextPasswordFinding reports a password field on a cleartext page.
//
// The check is on the *page*, not on the request, because a password field on an
// `http://` page is submitted over `http://` by definition: the form's action is
// either relative, and therefore inherits the cleartext scheme, or explicitly
// cleartext. Either way the credential crosses the network in the request body, in
// the `Referer` of the next navigation, and in every proxy log on the path.
func cleartextPasswordFinding(p Point, baseline *Response) *Finding {
	if !strings.HasPrefix(p.URL, "http://") {
		return nil
	}
	if !passwordFieldPresent(baseline.Body) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "cookies",
		Title:    "Password Field Served Over Cleartext HTTP",
		Claimed:  SeverityHigh,
		Tier:     TierVerified,
		Point:    p,
		Payload:  "GET " + p.URL,
		Evidence: "the page is served over http:// and contains a field declared as a password",
		Description: "The page collects a password and is served without TLS, so the credential is submitted " +
			"in the clear: readable by anything on the path, written to every proxy and access log between " +
			"the visitor and the server, and replayable by anyone who captures it.",
		Remediation: "Serve every page that collects a credential over HTTPS only, and redirect plain HTTP " +
			"to HTTPS before the form is ever rendered. HSTS is the durable form of that redirect; without " +
			"it a single cleartext request is enough for the credential to leak.",
	})
	return &finding
}

// passwordFieldPresent reports whether a body declares a password control.
//
// The declaration is matched rather than the word "password", because a page that
// *talks about* a password — a login help article, a "forgot your password" link —
// is not a page that collects one, and matching the word reports both.
func passwordFieldPresent(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		`type="password"`, `type='password'`, "type=password",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// redactCookieValue keeps a `Set-Cookie` value out of the report.
//
// The *value* is the secret. A cookie named `session` with its identifier in the
// report is a session identifier in the report, and reports get pasted into
// tickets. The name and every attribute are kept, because those are what the row
// is about.
func redactCookieValue(setCookie string) string {
	parts := strings.Split(setCookie, ";")
	var kept []string
	for i, part := range parts {
		if i == 0 {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			kept = append(kept, name+"=<withheld>")
			continue
		}
		kept = append(kept, strings.TrimSpace(part))
	}
	return strings.Join(kept, "; ")
}
