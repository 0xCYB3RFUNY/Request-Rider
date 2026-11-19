package active

// Authentication bypass by path truncation.
//
// # The technique
//
// A servlet container maps a request URI onto a file by stripping the *last*
// extension it recognises, and everything after the first `;` is a path
// parameter that container-specific code reads. So `/server-admin/memory_info.jsp`
// and `/server-admin/memory_info.jsp;.jsp` are two different URIs that resolve to
// the same file on disk, and the filter chain — the component that sends an
// unauthenticated request to the login page — commonly matches on the extension
// at the end of the raw URI. The truncated form reaches the servlet with the
// filter no longer recognising it as the protected resource.
//
// The reported case is one request pair: `…/memory_info.jsp` answers 301 to the
// login page, `…/memory_info.jsp;.jsp` answers 200 with the page. Two statuses,
// one parameter.
//
// # Why the endpoint list is not enough on its own and this is not a replacement
//
// The advice in the operator's list is to find the sensitive paths in the
// JavaScript first and fuzz each of them. That is the discovery step and it
// belongs to the analyser, which reads the bundle: `jsPrivilegedPath` in
// `engine/target_js_capabilities.go` names the endpoints whose path says they do
// something privileged. This detector is the other half — it takes whatever path
// the surface carries, and it fires the truncation forms on it.
//
// Both halves matter, and neither substitutes for the other. A path nobody
// published is exactly the path this technique needs, so a scan that only probes
// what it crawled misses it; a path the bundle names is exactly the path this
// technique targets, so a scan that only probes what it crawled spends its probes
// on pages nobody asked about.
//
// # What counts as a bypass
//
// A different status code is not enough on its own. Two shapes of false positive
// dominate here, and both are answered rather than argued about:
//
//   - The baseline is a redirect to the login page and the probe is a redirect to
//     the login page too, with a different status because the application varies
//     it. That is not a bypass; it is the same page. So the probe must answer with
//     a body the baseline did not.
//   - The baseline is a login form and the probe is the same login form rendered
//     with a different token. Comparing bytes would call that a bypass; every
//     login page embeds a nonce. So the login markers are compared rather than the
//     bytes, and a probe that still shows the login form is not a bypass however
//     different its bytes are.
//
// The tier follows from what was shown: `verified` when the baseline was gated
// and the probe was not, `potential` when the probe merely differs, and nothing at
// all when the two answers agree.

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// AuthBypassExt probes the path-truncation forms of a server-side page path.
type AuthBypassExt struct{}

// Name implements Module.
func (AuthBypassExt) Name() string { return "auth_bypass_ext" }

// Level implements Module.
//
// Endpoint level: the question is about a path, and a path is what an endpoint is.
func (AuthBypassExt) Level() Level { return LevelEndpoint }

// serverExtensions are the extensions a container maps a file by, and therefore
// the ones a filter chain can be matching on.
//
// The list is not the set of extensions that exist; it is the set where the
// truncation actually changes which file is served. `.html` and `.txt` are absent
// for that reason: no container strips `.html` to reach a servlet, so a probe on
// them is a request to a different file rather than the same one.
var serverExtensions = map[string]bool{
	".jsp": true, ".jspx": true, ".php": true, ".php3": true, ".php4": true,
	".php5": true, ".phtml": true, ".asp": true, ".aspx": true, ".shtml": true,
	".cgi": true, ".pl": true, ".py": true,
}

// truncationForms are the ways a URI is rewritten to hide its extension from a
// filter that matches the end of the raw path.
//
// `;.ext` is the container's own path-parameter syntax. `%3b` is the same
// character encoded, which defeats a filter that matches before decoding. `..;/`
// is the traversal form, which defeats a filter that normalises `..` before it
// matches. `/./` is the normalisation form, for a server that collapses `/./`.
func truncationForms(extension string) []string {
	return []string{
		";" + extension,
		"%3b" + extension,
		"..;/" + extension,
		";x=1" + extension,
		"/./" + extension,
	}
}

// loginMarkers are the things a login page has and an authenticated page does not.
//
// They are read as "is this page still asking me to log in", which is the question
// the technique asks, and the comparison is over markers rather than bytes
// precisely so a rotating nonce does not read as an access grant.
var loginMarkers = []string{
	`type="password"`, `type='password'`, `type=password`,
	`name="password"`, "name='password'",
	"login", "signin", "sign-in", "log-in",
}

// Scan probes one endpoint's truncation forms.
func (m AuthBypassExt) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	extension := serverExtensionOf(p.URL)
	if extension == "" || baseline == nil {
		return nil
	}
	gated := loginMarkersIn(baseline.Body) > 0 || isRedirectStatus(baseline.StatusCode)
	var findings []Finding
	for _, form := range truncationForms(extension) {
		if ctx.Err() != nil {
			return findings
		}
		probe := truncationURL(p.URL, extension, form)
		if probe == "" || probe == p.URL {
			continue
		}
		answered, err := t.Do(ctx, http.MethodGet, probe, nil, false, nil)
		if err != nil || answered == nil {
			continue
		}
		if finding := classifyBypass(p, baseline, answered, probe, gated); finding != nil {
			findings = append(findings, *finding)
			// One bypass per endpoint is the finding. The other four forms are
			// variants of the same claim, and a report with five rows saying "the
			// same endpoint is reachable" is five rows a reader triages separately
			// and dismisses together.
			break
		}
	}
	return findings
}

// serverExtensionOf returns the extension a container would map the path by.
func serverExtensionOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := parsed.Path
	index := strings.LastIndex(path, ".")
	if index <= 0 || index == len(path)-1 {
		return ""
	}
	extension := strings.ToLower(path[index:])
	if !serverExtensions[extension] {
		return ""
	}
	return extension
}

// truncationURL rewrites the last extension of a path into one of the forms.
func truncationURL(rawURL, extension, form string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := parsed.Path
	index := strings.LastIndex(strings.ToLower(path), extension)
	if index <= 0 {
		return ""
	}
	parsed.Path = path[:index] + form
	parsed.RawPath = ""
	return parsed.String()
}

// isRedirectStatus reports whether a status is a redirection the scan does not
// follow.
//
// The probe never follows redirects on purpose: the whole signal is that the
// baseline redirects and the probe does not, and following both would compare two
// copies of the login page and find them equal.
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// loginMarkersIn counts how many of the login markers a body carries.
func loginMarkersIn(body string) int {
	lowered := strings.ToLower(body)
	count := 0
	for _, marker := range loginMarkers {
		if strings.Contains(lowered, marker) {
			count++
		}
	}
	return count
}

// classifyBypass decides what one pair of answers means.
func classifyBypass(
	p Point, baseline, answered *Response, probe string, gated bool,
) *Finding {
	// The baseline already answered 200 and the probe answers 200 with the same
	// bytes: nothing happened. This is the control that keeps the detector quiet
	// on the overwhelming majority of endpoints.
	if answered.Body == baseline.Body && answered.StatusCode == baseline.StatusCode {
		return nil
	}
	if loginMarkersIn(answered.Body) > 0 {
		// A different rendering of the same login page is not an access grant. A
		// nonce rotates, a locale string differs, and a comparison of bytes would
		// report both.
		return nil
	}
	tier := TierPotential
	claimed := SeverityMedium
	title := "Path truncation reaches a page the direct path does not (" + probe + ")"
	if gated && answered.StatusCode == http.StatusOK {
		// The gated case is the verified one: the baseline asked for credentials
		// and this request did not receive content that asks for credentials.
		tier = TierVerified
		claimed = SeverityHigh
		title = "Authentication bypass by path truncation (" + probe + ")"
	}
	finding, _ := NewFinding(Spec{
		Module:   "auth_bypass_ext",
		Title:    title,
		Claimed:  claimed,
		Tier:     tier,
		Point:    p,
		Payload:  probe,
		Evidence: Snippet(answered.Body, "<", 240),
		Description: "The request carries the server-side extension as a path parameter rather than as the " +
			"extension at the end of the URI, so a filter chain that matches on the raw extension does not " +
			"recognise the request as the protected resource. The baseline answered " +
			statusSentence(baseline.StatusCode) + " and this one answered " + statusSentence(answered.StatusCode) + ".",
		Remediation: "Reject requests whose URI contains a path parameter, or normalise the URI before the " +
			"security filter chain runs. On Tomcat, disallow `;` in the mapped path.",
	})
	return &finding
}

// statusSentence names a status for the evidence sentence.
func statusSentence(status int) string {
	if status == 0 {
		return "no response"
	}
	return strconv.Itoa(status) + " " + http.StatusText(status)
}
