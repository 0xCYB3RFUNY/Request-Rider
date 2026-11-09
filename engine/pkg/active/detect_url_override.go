package active

// URLOverride asks whether the application builds its own URLs from a header,
// or serves a resource the request did not ask for.
//
// Burp's check is `0x00400F00` (Request URL override). It is two claims that are
// usually confused, and this module keeps them apart because they are remediated
// differently:
//
//   - the response is built **from** an injected header — `X-Forwarded-Host`,
//     `X-Forwarded-Server`, `Forwarded` — so an absolute URL in the body or in
//     a `Location` points at a host this run chose. That is the primitive behind
//     password-reset poisoning and behind cache poisoning, and the proof is the
//     hostname itself appearing where only the application's host belongs.
//   - the application serves a resource the request **did not** name, because
//     `X-Original-URL` or `X-Rewrite-URL` told it to. The proof there is
//     subtraction rather than reflection: a path that answers 404 when asked for
//     directly answers 200 when named in the header, on a request whose own URL
//     was a page that answers 200.
//
// The second proof is a two-sided measurement on purpose. A header alone cannot
// show an override — `X-Original-URL: /admin` returning 200 proves nothing if
// `/admin` answers 200 to everyone, so the run asks for the canary path twice:
// once as the request's own URL and once inside the header. Both answers have to
// differ, and the canary path has to be one this run invented, or the
// measurement is about a page the site simply has.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// URLOverride is the request-URL-override probe.
type URLOverride struct{}

// Name implements Module.
func (URLOverride) Name() string { return "url-override" }

// Level implements Module.
func (URLOverride) Level() Level { return LevelEndpoint }

// overrideHeaders are the header names an application may build its URLs from.
// The list is the set the well-known frameworks read, in a fixed order so the
// report names the first one that worked rather than a different one per run.
var overrideHeaders = []string{
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Host",
	"Forwarded",
}

// rewritingHeaders are the header names an application may read as the request's
// real path.
var rewritingHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Original-Method",
}

// Scan probes the endpoint for both override shapes.
func (u URLOverride) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	parsed, err := url.Parse(p.URL)
	if err != nil || parsed.Host == "" {
		return nil
	}

	var out []Finding
	for _, header := range overrideHeaders {
		if finding := u.hostOverride(ctx, t, p, parsed, header); finding != nil {
			out = append(out, *finding)
			break
		}
	}
	if finding := u.pathOverride(ctx, t, p, parsed, u.urlOverridePath()); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// hostOverride probes whether an injected hostname reaches the response.
//
// The canary host is invented under `.invalid`, which by RFC 2606 can never
// resolve: a hostname in the response that matches it cannot have come from the
// application's own configuration.
func (u URLOverride) hostOverride(ctx context.Context, t *Transport, p Point, parsed *url.URL, header string) *Finding {
	canary := urlOverrideCanary() + ".invalid"
	value := canary
	if header == "Forwarded" {
		value = "host=" + canary
	}
	resp, err := t.Do(ctx, http.MethodGet, p.URL, nil, false, http.Header{header: {value}})
	if err != nil || resp == nil {
		return nil
	}
	evidence := urlOverrideHostEvidence(resp.Body, canary)
	if evidence == "" {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "url-override",
		Title:    "Absolute URL Built From the Request's " + header + " Header",
		Claimed:  SeverityMedium,
		Tier:     TierVerified,
		Point:    p,
		Payload:  header + ": " + value,
		Evidence: evidence,
		Description: "The response contains an absolute URL naming " + canary + ", a host this run " +
			"invented and which cannot resolve. The application therefore builds its own URLs " +
			"from a request header, so anything it mails, redirects to or puts in a page can " +
			"carry a host of the sender's choosing: a reset link that goes to the attacker's " +
			"server, or a cached page whose absolute URLs point elsewhere.",
		Remediation: "Derive the application's canonical host from configuration rather than " +
			"from the request, and ignore " + header + " when building URLs. A proxy that " +
			"appends it is a signal the header must be trusted from, not data to echo.",
	})
	return &finding
}

// urlOverrideHostEvidence finds the canary host inside a response, preferring a
// place where it is a URL rather than a mention.
func urlOverrideHostEvidence(body, canary string) string {
	for _, marker := range []string{"href=\"http", "href='http", "src=\"http", "src='http",
		"action=\"http", "action='http", "content=\"http"} {
		if idx := strings.Index(body, marker); idx >= 0 {
			end := idx + len(marker)
			for end < len(body) && body[end] != '"' && body[end] != '\'' && body[end] != '\n' && body[end] != '\r' {
				end++
			}
			if candidate := body[idx:end]; strings.Contains(candidate, canary) {
				return Snippet(body, canary, 140)
			}
		}
	}
	if strings.Contains(body, canary) {
		return Snippet(body, canary, 140)
	}
	return ""
}

// pathOverride asks whether the application serves a resource the request did
// not name.
//
// The measurement is subtraction, and it is two-sided: a path that answers
// not-found when asked for directly has to answer otherwise when it is named in
// a header. A header alone cannot show an override — `X-Original-URL: /admin`
// returning 200 proves nothing if `/admin` answers 200 to everyone — so the run
// asks for the canary path twice, once as the request's own URL and once inside
// a header.
//
// The disambiguation is spent only when something was already found: the first
// probe carries **all three** header names together, because a server that reads
// any of them overrides. Naming which one is three more requests per surface on
// every surface the run touches, which is what a run pays to learn nothing when
// the target honours none of them.
func (u URLOverride) pathOverride(ctx context.Context, t *Transport, p Point, parsed *url.URL, canary string) *Finding {
	direct := *parsed
	direct.Path = canary
	direct.RawQuery = ""
	directURL := direct.String()

	directResp, err := t.Do(ctx, http.MethodGet, directURL, nil, false, nil)
	if err != nil || directResp == nil {
		return nil
	}
	if directResp.StatusCode < 400 {
		// The canary path is reachable on its own, so a 200 under the header says
		// nothing about the header.
		return nil
	}

	resp, err := t.Do(ctx, http.MethodGet, p.URL, nil, false, rewritingHeader(canary))
	if err != nil || resp == nil {
		return nil
	}
	if resp.StatusCode >= 400 {
		return nil
	}
	finding := urlOverridePathFinding(p, directURL, directResp, resp,
		"the overriding header was not isolated (one of "+strings.Join(rewritingHeaders, ", ")+")", canary)
	return &finding
}

// rewritingHeader builds one request carrying all three rewriting headers.
//
// It is a helper rather than an inline literal because the disambiguation step
// below and this one must agree on the set: a header added to the table and not
// to this request is a header the first probe cannot see.
func rewritingHeader(canary string) http.Header {
	header := http.Header{}
	for _, name := range rewritingHeaders {
		header.Set(name, canary)
	}
	return header
}

// urlOverridePathFinding renders one row naming the header that carried the
// override and the two answers that decided it.
func urlOverridePathFinding(p Point, directURL string, directResp, resp *Response, header, canary string) Finding {
	finding, _ := NewFinding(Spec{
		Module:  "url-override",
		Title:   "Request URL Override Honoured (" + header + ")",
		Claimed: SeverityHigh,
		Tier:    TierVerified,
		Point:   Point{URL: p.URL, Method: p.Method, Origin: p.Origin},
		Payload: "X-Original-URL: " + canary,
		Evidence: fmt.Sprintf("GET %s → %s\nGET %s with the override header → %d",
			directURL, strings.TrimSpace(directResp.Status), p.URL, resp.StatusCode),
		Description: "The request to " + p.URL + " was answered as if it had been a request for " +
			directURL + ", which answers " + strings.TrimSpace(directResp.Status) + " when asked " +
			"for directly. The application therefore reads the path it should serve out of a " +
			"request header, so any request reaching it can name any resource — including one " +
			"the front-end was configured to refuse, because the access decision is taken on " +
			"the URL the client sent and not on the one the application used.",
		Remediation: "Stop reading the request's path from the request headers. Where a proxy " +
			"genuinely rewrites, make the rewrite explicit and authorised at the proxy, and " +
			"have the application use the rewritten value for authorization as well as for " +
			"routing.",
	})
	return finding
}

// urlOverrideCanary is the token that prefixes every path and host this module
// invents, so a reader of a report can tell a canary from the site's own paths.
//
// It is fixed rather than random, and that is deliberate: a finding's identity
// hashes its payload, so a random canary would make two runs of the same target
// produce two different reports — which is exactly what
// `TestScanReportIsDeterministic` refuses, because a diff between two reports
// has to show a change and not a reshuffle. The uniqueness the canary needs is
// *freshness against the baseline*, which `Fresh` measures, not randomness the
// target has never seen the value of.
func urlOverrideCanary() string {
	return "rr-override-probe"
}

// urlOverridePath is the path the module asks for on its own account, and it is
// a method rather than a repeated literal because two probes need the *same*
// invented path — the one asked for directly and the one named in the header —
// and two canaries would make the comparison meaningless. The `.htaccess`
// suffix is there so the path names something static: an application that
// overrides a document root is exercising the same behaviour a path static
// enough to be cached would hit.
func (u URLOverride) urlOverridePath() string {
	return urlOverrideCanary() + ".htaccess"
}
