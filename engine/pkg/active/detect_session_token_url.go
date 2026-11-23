package active

// SessionTokenInURL names the parameter whose name says it carries a session
// identifier while the application puts it in the query string.
//
// Burp's check is `0x00500700` (Session token in URL). It is answered by reading
// the parameter's *name*, so it costs no request: the crawl already harvested
// the surface, the name is already in `Point.Param`, and what the name declares
// is the whole finding.
//
// Why a name is evidence. A parameter called `jsessionid`, `phpsessid` or
// `sid` is not a value the scanner injected — it is what the page or the
// operator's own URL already carries, which means the application was built to
// accept it there. The exposure that follows is not a property of the value:
// the URL bar, the browser history, the `Referer` header of the next request
// and the access log all get the identifier whether or not it is valid.
//
// The severity is information rather than high because the finding names a
// transmission decision, not a leaked credential. Nothing here claims the token
// works; it claims the application accepts a session identifier where a session
// identifier does not belong.

import (
	"context"
	"strings"
)

// SessionTokenInURL reports the query parameters that carry a session
// identifier in the URL.
type SessionTokenInURL struct{}

// Name implements Module.
func (SessionTokenInURL) Name() string { return "session-token-url" }

// Level implements Module.
func (SessionTokenInURL) Level() Level { return LevelParam }

// sessionParamNames are the parameter names that carry a session identifier
// wherever they appear. The list is deliberately short and specific: `token`
// on its own is a CSRF token, a reset token and a search parameter depending
// on the day, and a detector that reported every `token` would be a detector
// nobody reads.
var sessionParamNames = []string{
	"jsessionid", "phpsessid", "aspsessionid", "asp.net_sessionid",
	"sessionid", "session_id", "sessionid_n", "sessid", "sid", "sess",
	"sessionkey", "session_key", "sessionsid", "s", "sid_",
	"cfid", "cftoken", "rails_session", "rack.session",
	"tomcat_session", "laravel_session", "auth_token_id",
}

// Scan reports the parameter when its own name declares a session identifier.
func (SessionTokenInURL) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	name := strings.ToLower(strings.TrimSpace(p.Param))
	if name == "" {
		return nil
	}
	normalized := strings.ReplaceAll(name, "-", "_")
	for _, candidate := range sessionParamNames {
		if normalized == candidate {
			return []Finding{sessionTokenFinding(p, name)}
		}
	}
	return nil
}

// sessionTokenFinding names the parameter and what its exposure is.
func sessionTokenFinding(p Point, name string) Finding {
	finding, _ := NewFinding(Spec{
		Module:   "session-token-url",
		Title:    "Session Token in URL",
		Claimed:  SeverityMedium,
		Tier:     TierVerified,
		Point:    p,
		Payload:  name + "=<session>",
		Evidence: "parameter `" + name + "` on " + p.URL,
		Description: "The application accepts a session identifier as a URL parameter named `" + name +
			"`. An identifier that travels in the query string is copied into the browser history, " +
			"the access log, the `Referer` header of the next request and any link the operator " +
			"shares, so the session is available to whoever reads any of those. This row names the " +
			"transmission decision, not a stolen session: nothing here claims the token works.",
		Remediation: "Move the session identifier into a cookie with `HttpOnly`, `Secure` and " +
			"`SameSite`, and reject a session identifier that arrives any other way so an old URL " +
			"cannot be replayed.",
	})
	return finding
}
