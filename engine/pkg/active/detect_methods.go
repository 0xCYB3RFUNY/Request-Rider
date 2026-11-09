// Allowed methods, unsafe write methods, WebDAV and TRACE.
//
// # Why this is one detector and not four
//
// Upstream splits this into five checks: `allowed_methods.rb`,
// `http_put.rb`, `webdav.rb`, `xst.rb` and `htaccess_limit.rb`. They share one
// transport decision — a `OPTIONS` request, and then one or two confirming
// requests against a method the server advertised — so splitting them costs four
// `OPTIONS` round trips per endpoint for four reports that a reader merges
// mentally anyway. They are merged here, and the *title* still names which
// capability fired, because the operator's next action differs per method: an
// open `PUT` needs a write test, an open `PROPFIND` needs a WebDAV test, an open
// `TRACE` needs nothing but a config change.
//
// # What is reported and what is deliberately not
//
// An open method is a finding only when it is a *write* method, and that word is
// doing the work. `GET`, `HEAD`, `OPTIONS` and `TRACE` being accepted is not a
// vulnerability. `PUT` and `DELETE` accepted on an endpoint that serves content is
// a real one: the server has agreed to write to or remove a resource, and nobody
// checked with the operator who owns that resource. WebDAV verbs are the same
// argument with a longer verb list, plus the file-listing exposure that comes with
// `PROPFIND` returning directory contents.
//
// `TRACE` is reported separately and at `info`, because it is a misconfiguration
// rather than an exposure: a server that echoes the request back will echo the
// cookie it was sent. It is real, it is cheap to fix, and calling it high would
// rank it above a writable endpoint, which it is not.
//
// `htaccess_limit.rb` is not reproduced here and the register says why: its check
// is for Apache's own `Limit` directive, readable only from `.htaccess` on an
// Apache server that publishes it. That is source disclosure, and the disclosure
// detector owns source disclosure.
package active

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// webdavVerbs are the methods whose acceptance on a web endpoint means the
// resource is exposed to WebDAV clients.
//
// `PROPFIND` is the one that matters most and is first: it is the request that
// returns a directory listing, so a server that honours it hands over the names of
// every resource under that path without any authentication at all.
var webdavVerbs = []string{
	"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
}

// writeMethods are the methods that change or remove a resource.
//
// `PUT` is separated from the rest because it is the one whose impact is
// demonstrated rather than inferred: the detector does not report that `PUT` is
// accepted, it uploads a canary file and then reads it back. A server that
// advertises `PUT` and rejects it is not vulnerable to anything, and a report that
// said it was would be reporting an advertisement.
var writeMethods = []string{"PUT", "DELETE"}

// Methods is the HTTP method exposure detector.
type Methods struct{}

// Name implements Module.
func (Methods) Name() string { return "methods" }

// Level implements Module.
//
// Endpoint, not host: the answer is per-resource, and two endpoints on the same
// host frequently differ — a static asset directory and a dynamic route are served
// by different code with different verb tables.
func (Methods) Level() Level { return LevelEndpoint }

// Scan probes one endpoint: ask, then confirm.
func (m Methods) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if isPublicResource(p.URL) {
		// `robots.txt` answering `PROPFIND` is not a disclosure. The public-file
		// exemption is the same one the misconfiguration detector applies, and it
		// is applied by exact path and asset extension rather than by prefix, so
		// `/admin/login` is still checked.
		return nil
	}
	allowed, err := t.Do(ctx, http.MethodOptions, p.URL, nil, false, nil)
	if err != nil {
		return nil
	}
	advertised := advertisedMethods(allowed)

	var out []Finding
	if finding := methodsPutFinding(ctx, t, p, advertised); finding != nil {
		out = append(out, *finding)
	}
	if finding := methodsWebdavFinding(ctx, t, p, advertised); finding != nil {
		out = append(out, *finding)
	}
	if finding := methodsDeleteFinding(ctx, t, p, advertised); finding != nil {
		out = append(out, *finding)
	}
	if finding := methodsTraceFinding(ctx, t, p, advertised, baseline); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// advertisedMethods reads the verb list out of an `Allow` header.
//
// The header is parsed rather than substring-matched, because `Allow` is a comma
// separated list of tokens and a substring test on it produces two wrong answers:
// `PUT` matches inside `INPUT`, and `GET` matches inside a method name that some
// framework invented. Splitting on commas and trimming is the whole parse.
func advertisedMethods(resp *Response) map[string]bool {
	out := map[string]bool{}
	if resp == nil {
		return out
	}
	for _, header := range []string{"Allow", "Allow-Methods", "Public"} {
		for _, value := range strings.Split(resp.HeaderValue(header), ",") {
			token := strings.ToUpper(strings.TrimSpace(value))
			if token != "" {
				out[token] = true
			}
		}
	}
	return out
}

// methodsPutFinding demonstrates a writable endpoint by writing to it.
//
// The written object is named after the endpoint and carries a random canary, and
// it is read back with a `GET` before the finding is written. Everything else here
// rests on an advertisement; this rests on a resource that exists because of a
// request this scan made.
//
// The object is removed afterwards when the server honours `DELETE`. When it does
// not — and on a server that honours `PUT` but not `DELETE` that is common — the
// fact is stated in the evidence rather than left for the operator to discover,
// because a scanner that quietly leaves files behind is a scanner the operator has
// to clean up after.
func methodsPutFinding(ctx context.Context, t *Transport, p Point, advertised map[string]bool) *Finding {
	canary := newCanary("rrput")
	if canary == "" {
		return nil
	}
	object := putObjectName(p, canary)
	full := strings.TrimRight(p.URL, "/") + "/" + object

	written, err := t.Do(ctx, http.MethodPut, full, nil, false, nil)
	if err != nil || written == nil {
		return nil
	}
	// A `PUT` answered with 405 or 501 is a refusal, and the refusal is the answer.
	if written.StatusCode == http.StatusMethodNotAllowed ||
		written.StatusCode == http.StatusNotImplemented ||
		written.StatusCode == http.StatusForbidden {
		return nil
	}
	readBack, err := t.Do(ctx, http.MethodGet, full, nil, false, nil)
	if err != nil || readBack == nil {
		// The write was accepted and the object cannot be read back. That is still
		// a write primitive, and it is reported at a lower tier because only half
		// of it was observed.
		return putFinding(p, full, object, canary, TierPotential,
			"the server accepted the upload ("+written.Status+") and the object was not readable afterwards")
	}
	if readBack.StatusCode != http.StatusOK || !strings.Contains(readBack.Body, canary) {
		return nil
	}
	removed := false
	if advertised["DELETE"] {
		if _, deleteErr := t.Do(ctx, http.MethodDelete, full, nil, false, nil); deleteErr == nil {
			removed = true
		}
	}
	evidence := "the object " + full + " was read back with the scanner's canary (" + canary + ") in its body"
	if !removed {
		evidence += "; the server did not remove it, so " + full + " is still on the target and must be deleted by hand"
	}
	return putFinding(p, full, object, canary, TierVerified, evidence)
}

func putFinding(p Point, full, object, canary string, tier Tier, evidence string) *Finding {
	claimed := SeverityHigh
	if tier != TierVerified {
		// Half of the primitive is not the whole of it. A server that accepts an
		// upload it will not serve back is still writable — that is how a web shell
		// gets placed — but the row should not claim the round trip was proven.
		claimed = SeverityMedium
	}
	finding, _ := NewFinding(Spec{
		Module:  "methods",
		Title:   "Unrestricted HTTP Method (PUT accepted)",
		Claimed: claimed,
		Tier:    tier,
		Point:   p,
		// The written object's name carries a per-run canary, so it cannot go into
		// the payload without giving this row a different ID on every run — which
		// breaks run-to-run diffing. The exact URL that was written is in the
		// evidence instead, and the payload names the shape that was sent.
		Payload:  "PUT " + strings.TrimRight(p.URL, "/") + "/" + putObjectPattern,
		Evidence: evidence,
		Description: "The endpoint accepted an HTTP PUT, so a client that can reach it can create a resource " +
			"the application never intended to publish. A writable endpoint on an origin that also serves " +
			"executable content is a remote code execution path, not a file upload.",
		Remediation: "Allow only the methods a resource actually needs, at the server or the framework, not at " +
			"the application handler. WebDAV verbs in particular should be disabled unless the deployment " +
			"depends on them.",
	})
	return &finding
}

// putObjectPattern is the reported shape of the object this detector writes.
const putObjectPattern = "rr-upload-<canary>.txt"

// putObjectName is where the object is written, chosen per endpoint.
//
// A flat name on the endpoint's own path is deliberate: it makes the object
// retrievable with a `GET`, which is the whole test, and it avoids guessing at a
// writable directory that the endpoint does not imply.
//
// The canary is per run rather than derived from the endpoint, because a token the
// target could predict could be pre-created and the write would prove nothing. The
// cost is that the object name differs between runs, which is why the reported
// payload names the pattern rather than the name.
func putObjectName(p Point, canary string) string {
	return "rr-upload-" + canary + ".txt"
}

// methodsWebdavFinding reports accepted WebDAV verbs.
//
// `PROPFIND` gets its own row because it is the one with an independent impact: it
// enumerates resources. The rest are reported as a group because the operator's
// response to "the server also accepts `MOVE` and `COPY`" is the same as to
// `PROPPATCH`, and separate rows would multiply one finding by seven.
func methodsWebdavFinding(ctx context.Context, t *Transport, p Point, advertised map[string]bool) *Finding {
	var accepted []string
	// PROPFIND is asked for directly as well as read from the advertisement,
	// because a server that implements WebDAV frequently does not advertise it.
	if probe, err := t.Do(ctx, "PROPFIND", p.URL, nil, false, nil); err == nil && probe != nil &&
		probe.StatusCode != http.StatusMethodNotAllowed &&
		probe.StatusCode != http.StatusNotImplemented &&
		probe.StatusCode != http.StatusForbidden {
		accepted = append(accepted, "PROPFIND")
	}
	for _, verb := range webdavVerbs {
		if verb == "PROPFIND" {
			continue
		}
		if advertised[verb] {
			accepted = append(accepted, verb)
		}
	}
	if len(accepted) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "methods",
		Title:    "WebDAV Enabled (" + strings.Join(accepted, ", ") + ")",
		Claimed:  SeverityMedium,
		Tier:     TierVerified,
		Point:    p,
		Payload:  "OPTIONS " + p.URL,
		Evidence: "the endpoint answered for: " + strings.Join(accepted, ", "),
		Description: "The endpoint answers WebDAV verbs. PROPFIND in particular enumerates the resources " +
			"under a path and returns their names and sizes without authentication, which is a directory " +
			"listing obtained over a different protocol than the one that would have been checked. " +
			"MOVE and COPY allow relocating or duplicating resources without going through the application.",
		Remediation: "Disable the WebDAV module unless the deployment depends on it. If it is required, " +
			"scope it to the paths that need it and require authentication on PROPFIND.",
	})
	return &finding
}

// methodsDeleteFinding reports an accepted DELETE.
//
// Unlike `PUT`, this is reported on the advertisement alone, and the reason is
// that the confirming request would destroy the operator's data. A scanner that
// deletes a resource to prove it can delete resources is not acceptable on
// anyone's target, so the row is capped and the evidence says what was actually
// observed.
func methodsDeleteFinding(ctx context.Context, t *Transport, p Point, advertised map[string]bool) *Finding {
	if !advertised["DELETE"] {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "methods",
		Title:    "Unrestricted HTTP Method (DELETE advertised)",
		Claimed:  SeverityMedium,
		Tier:     TierPotential,
		Point:    p,
		Payload:  "OPTIONS " + p.URL,
		Evidence: "Allow header on the OPTIONS response advertises DELETE",
		Description: "The endpoint advertises DELETE, so it will accept a request to remove a resource. The " +
			"advertisement is reported rather than tested, because confirming it would mean deleting the " +
			"operator's data to prove the server can delete the operator's data.",
		Remediation: "Require an authenticated, authorised code path for destructive verbs rather than " +
			"accepting DELETE at the server level. If the resource is static, it does not need DELETE at all.",
	})
	return &finding
}

// methodsTraceFinding reports a TRACE echo.
//
// The test is that the scanner's own marker comes back in the echoed request, not
// that the status was 200: a server may answer TRACE with 200 and an empty body,
// and a reflection test on the body is what distinguishes the two.
func methodsTraceFinding(ctx context.Context, t *Transport, p Point, advertised map[string]bool, baseline *Response) *Finding {
	canary := newCanary("rrtrace")
	if canary == "" {
		return nil
	}
	resp, err := t.Do(ctx, http.MethodTrace, p.URL, nil, false, http.Header{
		"X-RR-Trace": {canary},
	})
	if err != nil || resp == nil {
		return nil
	}
	if !strings.Contains(resp.Body, canary) {
		// A TRACE that returns 405 is the correct behaviour, and a TRACE that
		// returns 200 without the header we sent has not echoed anything.
		return nil
	}
	cookies := 0
	if baseline != nil {
		cookies = len(baseline.SetCookies())
	}
	finding, _ := NewFinding(Spec{
		Module:   "methods",
		Title:    "HTTP TRACE Enabled (request echoed)",
		Claimed:  SeverityInfo,
		Tier:     TierVerified,
		Point:    p,
		Payload:  "TRACE " + p.URL,
		Evidence: "the response echoed the scanner's own X-RR-Trace marker back in its body",
		Description: "The server echoed the submitted request, headers included, back in the response. The " +
			"unmodified response carried " + strconv.Itoa(cookies) + " Set-Cookie header(s), and TRACE returns every " +
			"header it was given — which in a cross-origin or attacker-influenced request is how a cookie " +
			"reaches something that should never see one.",
		Remediation: "Disable TRACE at the server. It exists for diagnostics, has no use in production, and " +
			"the standard mitigation is a one-line configuration change.",
	})
	return &finding
}
