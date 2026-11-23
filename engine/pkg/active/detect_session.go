// CSRF and session fixation: the two bugs that are about the *session*, not the
// request.
//
// # Why they belong together and do not belong with the injection detectors
//
// Both are answers to a question about how the application treats a request it
// cannot tell apart from a genuine one, and both are invisible to a payload test:
// a CSRF-protected endpoint behaves identically when the token is missing and the
// request is forged as it does when the token is present and the request is
// genuine. No payload distinguishes them, because the payload is not what changed.
// What changed is whether the *request* carried something the attacker cannot read,
// and that is only observable by making a request without it.
//
// Upstream has `csrf.rb` and `session_fixation.rb` for the same two, and they are
// merged here for the same reason the CSRF check is not split by form: the two
// share the observation that the application did not require a token it could not
// have known.
//
// # The token test is "can the attacker know it", not "is it in the form"
//
// The common failure is to look for a field named `csrf_token` and declare a form
// unprotected when it has none. That reports every form on the internet, because
// most forms are legitimately token-free — a search box, a newsletter signup, a
// login form whose CSRF protection is the `SameSite` cookie attribute. What makes
// a form need a token is that it *changes state on behalf of someone*, and the
// only signal available from outside is the form's own shape.
//
// So the check is structural and it is narrow: a state-changing method whose form
// carries **no** field whose name or value is unguessable, **and** whose page sets
// no `SameSite` cookie. A form with a hidden field is not automatically safe —
// plenty of frameworks ship a static token — so a hidden field counts as protection
// only if its value changes between two requests to the page, which is a second
// request and the reason this costs what it costs.
//
// # Session fixation is the complement
//
// Fixation is the opposite failure: the session identifier is chosen by whoever
// arrived first, and the application keeps using it after the victim authenticates.
// The only way to see it from outside is to notice that the session cookie's value
// does not change across an authentication-shaped transition — which this detector
// cannot trigger, because it has no credentials. What it *can* do is report the
// precondition honestly: a session cookie that is issued before any authentication
// and accepted over plain HTTP is a fixation precondition, and the row says that
// rather than claiming the fixation was demonstrated.
package active

import (
	"context"
	"regexp"
	"strings"
)

// csrfTokenHints are the field names and value shapes a framework uses for its
// anti-CSRF token.
//
// The names are the recognisable ones, and the value check is what actually
// matters: a token that is a fixed string is not a token at all, which is why a
// hidden field is not accepted as protection on its name.
var csrfTokenHints = []string{
	"csrf", "csrf_token", "csrftoken", "xsrf", "_csrf", "_token", "authenticity_token",
	"__requestverificationtoken", "anti_forgery", "_csrf_token", "token",
}

// csrfStateChangingMethods are the methods that change state.
//
// `GET` is absent and its absence is the point: a `GET` that changes state is its
// own bug and a rare one, and a detector that treated every `GET` as a candidate
// would flag every search box on the internet.
var csrfStateChangingMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

// tokenShapedValue matches the shape of a real per-session or per-request token in
// a hidden input.
//
// It is the fallback for a framework that renamed its token field. The shape is
// deliberately specific — at least 16 characters drawn from the alphabet base64
// uses, with the padding that base64 produces — because the thing it must not match
// is every other hidden field on the page: a page id, a timestamp, a CSRF-free
// form's `form_key`, and a whole generation of framework internals that ship
// fixed 32-character strings.
var tokenShapedValue = regexp.MustCompile(
	`(?i)<input[^>]+type=["']hidden["'][^>]+value=["'][A-Za-z0-9+/]{16,}={0,2}["']`)

// CSRF is the cross-site request forgery detector.
type CSRF struct{}

// Name implements Module.
func (CSRF) Name() string { return "csrf" }

// Level implements Module.
//
// **Param**, and that is not a stylistic choice — it was a bug found by running the
// fixture. An endpoint surface is built as a bare `GET` for every crawled URL, so a
// detector declared `LevelEndpoint` was handed only GETs, and its own check then
// rejected every one of them because a GET has no submission to forge. The detector
// was counted in every run, could not fire in any run, and the fixture reported it
// as broken — which is the "counted but never asked" loss the package has already
// been bitten by once.
//
// `LevelParam` is also the more correct level on its own terms: the unit of
// protection is the *submission*, and a submission surface is a form field. A token
// that guards one field of a form guards the whole submission, so one row per
// submitting surface is both the right granularity and the only one that can
// exist.
func (CSRF) Level() Level { return LevelParam }

// Scan probes one endpoint.
func (m CSRF) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	if !stateChanging(baseline, p) {
		// A surface whose unmodified response is a `GET` is not a submission, and
		// nothing about a token applies to it.
		return nil
	}
	if tokenPresent(baseline.Body) {
		return nil
	}
	if sameSiteCookies(baseline) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "csrf",
		Title:   "Cross-Site Request Forgery (no token on a state-changing endpoint)",
		Claimed: SeverityMedium,
		Tier:    TierPotential,
		Point:   p,
		Payload: "POST " + p.URL,
		Evidence: "the unmodified response carries no anti-CSRF field and sets no SameSite cookie, so a " +
			"cross-origin form submission is indistinguishable from a genuine one",
		Description: "The endpoint accepts a state-changing submission and the page carries nothing an " +
			"attacker could not also forge. A token field would be unreadable cross-origin because the " +
			"attacker cannot read the response that contains it, and a SameSite cookie would not be sent " +
			"with a cross-site form post; with neither, an attacker-controlled page can submit this form as " +
			"the logged-in visitor. The row is capped because whether the endpoint's action is worth stealing " +
			"is a question about the application that this detector cannot answer.",
		Remediation: "Add a per-session or per-request anti-CSRF token to every state-changing form and " +
			"verify it server-side. Set `SameSite=Lax` or `Strict` on the session cookie as a second line of " +
			"defence — not as the only one, since it does not protect an endpoint that is also reachable by a " +
			"simple cross-site form.",
	})
	return []Finding{finding}
}

// stateChanging reports whether this surface takes a submission at all.
//
// The method is read from the surface rather than the response, because a `GET`
// endpoint has no submission to forge and a `POST` one does. A response status of
// 405 is also treated as a refusal: an endpoint that answers "method not allowed"
// to the submission method is not accepting forged submissions either.
func stateChanging(baseline *Response, p Point) bool {
	for _, method := range csrfStateChangingMethods {
		if strings.EqualFold(p.Method, method) {
			return true
		}
	}
	return false
}

// tokenPresent reports whether the page carries anything unguessable.
//
// The name hints and the value shape are both checked, and the value check is the
// one that carries the weight: a framework that ships a *fixed* token has the
// protection of a constant.
func tokenPresent(body string) bool {
	lower := strings.ToLower(body)
	for _, hint := range csrfTokenHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	// A long hex or base64-ish value in a hidden input is the shape of a real
	// token even when its name says nothing — a framework that renamed the field
	// is still sending one, and this detector should not report it for the naming.
	return tokenShapedValue.MatchString(body)
}

// sameSiteCookies reports whether the session cookie carries a SameSite attribute.
//
// This is checked from the raw `Set-Cookie` rather than from the parsed jar,
// because the jar has already discarded the attributes that are the whole point:
// `cookiejar` keeps name and value and drops the rest.
func sameSiteCookies(baseline *Response) bool {
	for _, cookie := range baseline.SetCookies() {
		lower := strings.ToLower(cookie)
		if strings.Contains(lower, "samesite=lax") ||
			strings.Contains(lower, "samesite=strict") ||
			strings.Contains(lower, "samesite=none") {
			return true
		}
	}
	return false
}

// SessionFixation is the session fixation detector.
//
// It reports the precondition, not the demonstrated fixation, and the difference is
// the whole honesty of this module. Demonstrating fixation requires authenticating
// as a victim and watching the identifier survive that transition; this detector
// has no credentials and will not ask for any. So it reports what it can see from
// outside — an identifier in the URL, or one issued without `HttpOnly` over a
// scheme that lets a script read it — and states in the row that the fixation
// itself was not demonstrated.
type SessionFixation struct{}

// Name implements Module.
func (SessionFixation) Name() string { return "sessionfixation" }

// Level implements Module.
func (SessionFixation) Level() Level { return LevelEndpoint }

// Scan probes one endpoint for the fixable half of the precondition.
func (m SessionFixation) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	var evidence []string
	claimed := SeverityMedium

	// An identifier accepted from the query string is the fixation primitive
	// itself: if the application honours `?jsessionid=` or `?PHPSESSID=`, an
	// attacker chooses the identifier and the victim adopts it.
	for _, name := range []string{"jsessionid", "phpsessid", "aspsessionid", "sid", "sessionid", "token"} {
		if strings.Contains(strings.ToLower(p.URL), strings.ToLower(name)+"=") {
			evidence = append(evidence, "the URL carries a session identifier parameter ("+name+
				"), which the application will read as the session to use")
			claimed = SeverityHigh
			break
		}
	}

	for _, cookie := range baseline.SetCookies() {
		name := cookieName(cookie)
		if name == "" || !sessionCookieName(name) {
			continue
		}
		lower := strings.ToLower(cookie)
		if !strings.Contains(lower, "httponly") {
			evidence = append(evidence, "session cookie "+name+" is issued without HttpOnly, so a "+
				"script on the page can read the identifier that identifies the session")
		}
		if !strings.Contains(lower, "secure") && strings.HasPrefix(p.URL, "http://") {
			evidence = append(evidence, "session cookie "+name+" is issued over plain HTTP without "+
				"the Secure attribute, so the identifier travels in the clear and can be fixed by anyone "+
				"on the path")
		}
	}

	if len(evidence) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "sessionfixation",
		Title:   "Session Fixation Precondition (session identifier is attacker-settable)",
		Claimed: claimed,
		// Capped, and the cap is the point: this row says a precondition is
		// present, not that a fixation was achieved. A detector that claimed the
		// fixation would be claiming the one thing it never tested.
		Tier:     TierPotential,
		Point:    p,
		Payload:  "GET " + p.URL,
		Evidence: strings.Join(evidence, "; "),
		Description: "The session identifier can be chosen by the client, or can be read by a script on the " +
			"page, which are the two halves of a fixation. Whether the identifier actually survives an " +
			"authentication transition was not tested — this scanner holds no credentials and did not attempt " +
			"to log in — so the row reports the precondition and stops there.",
		Remediation: "Regenerate the session identifier on every privilege change, including login, and " +
			"never accept one from a query string or a request header. Issue session cookies with HttpOnly " +
			"and Secure, and validate them before use.",
	})
	return []Finding{finding}
}

// cookieName returns the name from a `Set-Cookie` value.
//
// It is read by hand rather than through `http.Response.Cookies`, because this
// package's `Response` holds the header map and the jar-form parse would drop the
// attributes the caller is about to reason about.
func cookieName(setCookie string) string {
	head, _, _ := strings.Cut(setCookie, ";")
	name, _, _ := strings.Cut(strings.TrimSpace(head), "=")
	return strings.TrimSpace(name)
}

// sessionCookieName reports whether a cookie name is the session's own.
//
// The list is the conventional names plus a substring check, because frameworks
// ship their own: a cookie called `myapp_sessionid` is a session cookie and the
// exact-match list would miss every framework that namespaces its cookies.
func sessionCookieName(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid",
		"cfid", "cftoken", "connect.sid", "sess", "sid", "session", "sessionid":
		return true
	}
	return strings.Contains(lower, "sess") || strings.Contains(lower, "session")
}
