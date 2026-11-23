// Tests written for the 2026-10-01 reconciliation against upstream VEXOR.
//
// Each test here exists because a gap was found by reading the upstream README and
// comparing its detection matrix against this implementation, not because a bug was
// reported. The gap was: CMDi carried six shell syntaxes against upstream's eight,
// redirect carried six bypass vectors against upstream's ten, and the chain engine
// had no rule for "SSRF + exposed configuration → cloud credential theft" at all.
//
// These are count-and-shape tests, so the obvious failure mode is a number that
// drifts back down with a later edit and nobody notices. Each one therefore also
// pins *what* has to be present, not only how many: a test that counts `>= 8` passes
// for any eight entries, including a set that dropped a syntax and gained a
// duplicate. The table at the bottom names the edit each test is supposed to catch.

package active

import (
	"strings"
	"testing"
)

// TestCMDiSyntaxesCoverTheReconciledSet pins the shell forms the echo technique
// is wrapped in.
//
// The count is above upstream's eight on purpose, and the assertion is on the
// named set rather than on the length: a detector that dropped `backtick` and
// added another spelling of `pipe` would still pass a length check.
func TestCMDiSyntaxesCoverTheReconciledSet(t *testing.T) {
	names := map[string]bool{}
	for _, syntax := range cmdSyntaxes {
		if syntax.name == "" {
			t.Error("a syntax has no name; the report would carry an unnamed shape")
		}
		if names[syntax.name] {
			t.Errorf("syntax %q appears twice", syntax.name)
		}
		names[syntax.name] = true
	}
	for _, required := range []string{
		"semicolon", "pipe", "newline", "dollar substitution", "backtick",
		"and", "or", "brace grouping", "encoded newline", "IFS substitution",
		"process substitution",
	} {
		if !names[required] {
			t.Errorf("syntax %q is gone; it was added to close the gap with upstream VEXOR", required)
		}
	}
	if len(cmdSyntaxes) < 11 {
		t.Errorf("have %d syntaxes, want at least 11 (upstream documents 8)", len(cmdSyntaxes))
	}
}

// TestCMDiSyntaxesAreDistinct is the property that makes the count meaningful: a
// duplicate is one wasted request per parameter per surface, and a syntax list
// padded with near-duplicates buys a bigger number without finding more.
func TestCMDiSyntaxesAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, syntax := range cmdSyntaxes {
		built := syntax.make("echo MARKER")
		if previous, clash := seen[built]; clash {
			t.Errorf("syntaxes %q and %q build the same payload %q", previous, syntax.name, built)
		}
		seen[built] = syntax.name
	}
}

// TestCMDiEncodedNewlineActuallyCarriesTheEncoding pins the one added syntax whose
// payload is easy to "simplify" back into a duplicate of `newline`.
//
// `newline` sends a raw byte and `encoded newline` sends the percent-encoded pair.
// A filter treats them differently, which is the entire reason the second exists,
// so a payload that decodes to the first one is a bug rather than a style choice.
func TestCMDiEncodedNewlineActuallyCarriesTheEncoding(t *testing.T) {
	var encoded string
	for _, syntax := range cmdSyntaxes {
		if syntax.name == "encoded newline" {
			encoded = syntax.make("echo MARKER")
		}
	}
	if encoded == "" {
		t.Fatal("the encoded-newline syntax is missing")
	}
	if !strings.Contains(encoded, "%0a") {
		t.Errorf("payload %q does not carry the encoded newline", encoded)
	}
	if strings.Contains(encoded, "\n") {
		t.Errorf("payload %q also carries a raw newline, so it is not a separate shape", encoded)
	}
}

// TestRedirectVectorsCoverTheReconciledSet pins the bypass shapes the redirect
// sink is probed with, by name, for the same reason as the CMDi list.
func TestRedirectVectorsCoverTheReconciledSet(t *testing.T) {
	names := map[string]bool{}
	for _, vector := range redirectVectors {
		names[vector.name] = true
	}
	for _, required := range []string{
		"plain", "protocol-relative", "backslash", "userinfo confusion",
		"path confusion", "fragment smuggling", "encoded at", "trailing dot",
		"uppercase scheme", "tab after scheme", "at after host", "explicit port",
	} {
		if !names[required] {
			t.Errorf("vector %q is gone; it was added to close the gap with upstream VEXOR", required)
		}
	}
	if len(redirectVectors) < 12 {
		t.Errorf("have %d vectors, want at least 12 (upstream documents 10)", len(redirectVectors))
	}
}

// TestRedirectVectorsKeepTheMarkerVerbatim is the reason the mixed-case-authority
// vector is not in the list.
//
// A vector that rewrites the marker cannot name the host it is meant to prove, so
// it stops being evidence. This test states that as a property rather than
// leaving it as a comment, because the next person to want a case-folding vector
// will hit this instead of shipping a probe that proves nothing.
func TestRedirectVectorsKeepTheMarkerVerbatim(t *testing.T) {
	const marker = "rr-redirect-probe.invalid"
	for _, vector := range redirectVectors {
		if !strings.Contains(vector.build(marker), marker) {
			t.Errorf("vector %q does not carry the marker verbatim", vector.name)
		}
	}
}

// TestRedirectAddedVectorsAreDistinct proves the four added shapes are genuinely
// different parse paths rather than four spellings of `plain`.
func TestRedirectAddedVectorsAreDistinct(t *testing.T) {
	const marker = "rr-redirect-probe.invalid"
	added := map[string]bool{
		"encoded at": true, "trailing dot": true, "uppercase scheme": true,
		"tab after scheme": true, "at after host": true, "explicit port": true,
	}
	seen := map[string]string{}
	for _, vector := range redirectVectors {
		if !added[vector.name] {
			continue
		}
		built := vector.build(marker)
		if previous, clash := seen[built]; clash {
			t.Errorf("vectors %q and %q build the same payload %q", previous, vector.name, built)
		}
		if previous, clash := seen[strings.ToLower(built)]; clash {
			t.Errorf("vector %q is a case-folded duplicate of %q: %q", vector.name, previous, built)
		}
		seen[built] = vector.name
		seen[strings.ToLower(built)] = vector.name
	}
}

// TestAtAfterHostDiffersFromUserinfoConfusion pins that the two `@` shapes are
// opposites rather than a restatement of each other.
//
// One puts the trusted host before the marker and the other after it. A test that
// did not pin this would let someone replace one with the other and keep the
// count at twelve.
func TestAtAfterHostDiffersFromUserinfoConfusion(t *testing.T) {
	const marker = "rr-redirect-probe.invalid"
	payloads := map[string]string{}
	for _, vector := range redirectVectors {
		if vector.name == "userinfo confusion" || vector.name == "at after host" {
			payloads[vector.name] = vector.build(marker)
		}
	}
	before, hasBefore := payloads["userinfo confusion"]
	after, hasAfter := payloads["at after host"]
	if !hasBefore || !hasAfter {
		t.Fatalf("both shapes must exist, got %v", payloads)
	}
	if before == after {
		t.Fatal("the two @ shapes build the same payload")
	}
	if !strings.Contains(after, "rr-redirect-probe.invalid@") {
		t.Errorf("at-after-host %q must put the marker before the @", after)
	}
	if !strings.Contains(before, "@rr-redirect-probe.invalid") {
		t.Errorf("userinfo confusion %q must put the marker after the @", before)
	}
}

// The SSRF-to-configuration chain that upstream documents is NOT tested here.
//
// It was going to be: this session wrote `ChainSSRFToCloudCredential`, and then
// found on re-reading the live tree that a neighbouring session had already
// shipped `ChainSSRFToConfigExposure` in `chain_ssrf_exposure.go`, registered and
// covered by eight tests. The rule this module owns is therefore already present,
// and a second implementation of the same chain would be a parallel path — the
// one thing the garbage-collector rule forbids. The duplicate was deleted rather
// than reconciled, because two rules describing the same composition would report
// the same finding twice under two names.
//
// What survives from that attempt is the only part that was not duplicated: the
// detector additions above, and this note, which is why the chain appears in the
// reconciliation table as covered by someone else rather than as work of this
// session.

// The edits below are the ones each test above is supposed to catch. They are
// written out rather than left to memory because a green suite that nobody can
// name a mutation for is a suite whose value is unknown.
//
// The chain entries that were here are gone with the duplicate they tested: the
// SSRF-to-configuration rule belongs to `chain_ssrf_exposure.go`, and its
// mutations belong beside its own tests, not in this file.
var EXPECTED_MUTATIONS = []struct {
	mutation string
	catches  string
}{
	{"drop the `or` syntax from cmdSyntaxes", "TestCMDiSyntaxesCoverTheReconciledSet"},
	{"make encoded newline send a raw newline", "TestCMDiEncodedNewlineActuallyCarriesTheEncoding"},
	{"revert encoded newline to a duplicate of `newline`", "TestCMDiSyntaxesAreDistinct"},
	{"drop the `trailing dot` vector", "TestRedirectVectorsCoverTheReconciledSet"},
	{"upper-case the host inside a redirect vector", "TestRedirectVectorsKeepTheMarkerVerbatim"},
	{"make `at after host` a restatement of `userinfo confusion`", "TestAtAfterHostDiffersFromUserinfoConfusion"},
}
