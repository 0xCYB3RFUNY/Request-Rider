package active

// BackupFiles looks for the editor's and the deployment tool's leftovers beside
// the file that is being served.
//
// Burp files this as `0x006000D8`, and the register carried it as `улучшено`
// through `srcdisc` — which was a claim about a table of fixed sensitive paths, not
// about this check. `sensitiveFiles` lists `/.git/HEAD`, `/.env`, `/error_log` and
// the rest: those are paths a scanner *guesses*, and a backup file is not a guess.
// It is a name derived from a file the application has already told us exists,
// which is why the original pairs it with a source-disclosure row and why a
// wordlist cannot stand in for it.
//
// # What is generated, and what is not
//
// The names are the ones editors and deployment tools actually leave, and each
// one's rationale is in the table below. A `.bak` for every possible suffix would
// be a wordlist in disguise: it would spend hundreds of requests per path to find
// the three that occur in practice.
//
// # What the response has to look like
//
// A 200 on `/index.php.bak` is not a finding — half the internet answers 200 on
// anything. Two conditions have to hold together, and both are about what came
// back rather than about the status:
//
//   - the body carries **source**, by a fingerprint a rendered page would not have
//     (`<?php`, `function `, `require(`, a shebang);
//   - and it is **not** what the live path returns, either byte-for-byte or in
//     content type — a server that answers 200 with the same rendered document has
//     told us nothing about a file on disk.
//
// The second condition is what makes this a check rather than a fingerprint match,
// and it is why the module reads the live path's own body instead of guessing.

import (
	"context"
	"errors"
	"strings"
)

// // BackupFiles derives backup names from a path the application serves.
type BackupFiles struct{}

// Name implements Module.
func (BackupFiles) Name() string { return "backup-files" }

// Level implements Module.
//
// Endpoint level, because the names are derived from **this** endpoint's path. A
// host-level module would have to guess the paths first, and guessing is what this
// check exists to avoid.
func (BackupFiles) Level() Level { return LevelEndpoint }

// backupSuffix is one editor's or deployment tool's way of leaving a copy.
type backupSuffix struct {
	// name is what the report calls it, and it is the tool's name rather than a
	// description, because an operator who recognises the tool recognises the row
	// without reading the sentence under it.
	name string
	// build turns a path into the candidate. A relative path yields a relative
	// candidate and an absolute one yields an absolute one, because an editor
	// writing `.index.php.swp` puts it in the same directory as the file and the
	// scanner asking for it has to look in the same directory.
	build func(path string) string
	// why is the tool's habit, in a sentence, for the evidence line.
	why string
}

// backupSuffixes are the leftovers worth one request each.
//
// They are ordered by how often the tool is still in use: the first four cover
// most of what a web root accumulates, and the rest are the ones that survive a
// deployment script rather than an editor session.
var backupSuffixes = []backupSuffix{
	{name: "editor backup (tilde)", build: func(path string) string { return path + "~" },
		why: "Emacs and several IDEs write `name~` beside the file they are editing."},
	{name: "Vim swap", build: func(path string) string {
		return joinPath(path, "."+baseName(path)+".swp")
	}, why: "Vim writes `.name.swp` while a file is open, and leaves it behind when it is not."},
	{name: "dated editor copy", build: func(path string) string { return path + ".bak" },
		why: "The most common backup extension, written by editors, deployment scripts and CMS installers."},
	{name: "pre-deployment copy", build: func(path string) string { return path + ".old" },
		why: "Deployment tooling commonly renames the live file to `.old` before replacing it."},
	{name: "pre-deployment copy (dist)", build: func(path string) string { return path + ".orig" },
		why: "The other spelling deployment tooling uses for the file it is about to replace."},
	{name: "copy (dot suffix)", build: func(path string) string { return path + ".copy" },
		why: "A plain copy kept under a dot suffix, which is what several control-panel backup jobs write."},
	{name: "save (dist)", build: func(path string) string { return path + ".save" },
		why: "The save-step leftover of build systems that copy rather than rename."},
	{name: "temporary file", build: func(path string) string { return joinPath(path, baseName(path)+".tmp") },
		why: "A partially written file from an interrupted upload or deploy."},
}

// backupMaxSuffixes bounds how many leftovers one path contributes.
//
// It defaults to the whole table — eight is every leftover worth a request that a
// scan can derive from a path — and exists as a variable so that a caller who
// needs fewer can say so without editing the table. It is a bound on cost, and the
// run's request count is where it shows.
var backupMaxSuffixes = len(backupSuffixes)

// sourceFingerprints are the shapes a file on disk has and a rendered response
// does not.
//
// They are deliberately few and coarse. A precise language detector would be a
// better fingerprint and a worse check: this row's subject is "a source file is
// being served", and a signature list is what that needs.
var sourceFingerprints = []string{
	"<?php", "<?=", "#!/bin/", "#!/usr/bin/env", "function ", "class ",
	"require(", "require_once(", "include(", "# -*- coding", "/*jshint",
	"var ", "let ", "const ", "import ", "package ", "using ", "#define",
}

// Scan derives the leftover names from the endpoint's own path and reports the one
// that served a file from disk.
func (m BackupFiles) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	path := requestPathOf(p.URL)
	if path == "" || path == "/" {
		// A directory has no editor leftovers of its own; the interesting file is
		// the index, and that is the endpoint a run surfaces anyway.
		return nil
	}

	for index, suffix := range backupSuffixes {
		if index >= backupMaxSuffixes || ctx.Err() != nil {
			return nil
		}
		candidate, err := sameOriginURL(p.URL, suffix.build(path))
		if err != nil {
			continue
		}
		resp, err := t.Do(ctx, p.Method, candidate, p.Values, false, nil)
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if len(resp.Body) < 32 {
			continue
		}
		fingerprint, ok := sourceFingerprint(resp.Body)
		if !ok {
			continue
		}
		if servedTheSameDocument(baseline, resp) {
			// The live path and the leftover answered with the same document, so
			// what came back is the rendered page and not a file on disk.
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "backup-files",
			Title:   "Backup File Served (" + suffix.name + "): 0x006000D8",
			Claimed: SeverityMedium,
			Tier:    TierVerified,
			Point:   Point{URL: candidate, Method: p.Method, Origin: p.URL},
			Payload: candidate,
			Evidence: "live path:   " + p.URL +
				"\nleftover:    " + candidate +
				"\nstatus:      " + resp.Status +
				"\ncontent-type: " + resp.HeaderValue("Content-Type") +
				"\nsource fingerprint: " + fingerprint +
				"\n" + suffix.why +
				"\n" + Snippet(resp.Body, fingerprint, 200),
			Description: "The file this application serves has a copy beside it that the web " +
				"server will also serve. The copy is on disk rather than executed, so it contains " +
				"what the source contains — including whatever the author did not intend to " +
				"publish, and including whatever a later deploy of the same change would have " +
				"published by accident.\n\n" +
				"Proven: a file from disk was served under a name derived from the live path, " +
				"and it is not the rendered document. Not proven: that it is newer, or that it " +
				"differs from the deployed version — a reader can diff the two from the evidence.",
			Remediation: "Keep only the files the application serves. Add the leftover patterns " +
				"to the server's deny rules, and make the deploy step delete them rather than " +
				"leaving them beside what it replaced.",
		})
		return []Finding{finding}
	}
	return nil
}

// sourceFingerprint returns the first shape in the body that a rendered response
// would not carry.
func sourceFingerprint(body string) (string, bool) {
	for _, fingerprint := range sourceFingerprints {
		if strings.Contains(body, fingerprint) {
			return fingerprint, true
		}
	}
	return "", false
}

// servedTheSameDocument reports whether the leftover answered with the live path's
// own document.
//
// Both byte-equality and content-type are checked, and they are checked together
// because either alone is wrong often enough to matter: a server that answers 200
// with the rendered page for every path produces byte-equal bodies, and a server
// that serves the same document under a different type produces equal bodies with
// a different header. Only a body that differs **and** a type that differs is a
// file being read from disk.
func servedTheSameDocument(baseline, resp *Response) bool {
	if baseline.Body == resp.Body {
		return true
	}
	return strings.EqualFold(baseline.HeaderValue("Content-Type"),
		resp.HeaderValue("Content-Type"))
}

// requestPathOf returns the path of a URL, without its query.
func requestPathOf(raw string) string {
	parsed := pageURL(raw)
	if parsed == nil || parsed.Path == "" {
		return ""
	}
	return parsed.Path
}

// baseName is the last segment of a path.
func baseName(path string) string {
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		return path[index+1:]
	}
	return path
}

// joinPath puts a name into the same directory as a path.
func joinPath(path, name string) string {
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		return path[:index+1] + name
	}
	return name
}

// sameOriginURL resolves a candidate against the surface's own URL and refuses a
// result on another origin.
//
// The refusal is not a scope rule: the candidates are derived from a path this run
// was given, so a candidate that left the origin is a bug in the derivation rather
// than a request anybody asked for.
func sameOriginURL(base, candidate string) (string, error) {
	// `originOf` answers with two things: the whole URL and the scheme+host. The
	// comparison is against the second, because a candidate derived from a path
	// differs from its base by exactly that path — comparing the first rejected
	// every candidate, which is how this function was found to be dead.
	_, origin, ok := originOf(base)
	if !ok {
		return "", errSameOrigin
	}
	parsed, err := pageURL(base).Parse(candidate)
	if err != nil {
		return "", err
	}
	_, resolved, ok := originOf(parsed.String())
	if !ok || resolved != origin {
		return "", errSameOrigin
	}
	parsed.Fragment, parsed.RawFragment = "", ""
	return parsed.String(), nil
}

// errSameOrigin is the named failure a candidate that leaves the origin returns.
var errSameOrigin = errors.New("active: the candidate leaves the origin it was derived from")
