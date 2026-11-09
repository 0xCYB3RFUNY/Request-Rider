package main

// Tests for the shape gate that keeps a vendor's own rule from accusing a
// minified bundle of a leaked credential.
//
// The defect this came from was found by the operator, not by a test: a crawl of
// ria.ru reported `pinkerton_artifactory_password` with the value
// `APExcludedBlocks`. That is not a credential — it is a property key in
// Yandex.Metrica's minified `context.js`, in the shape `{key:"APExcludedBlocks",
// get: function(){…}}`. The operator's question was "це полний секрет???" and the
// honest answer was no.
//
// Why the rule matched: `pinkerton_artifactory_password` is
// `(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}`. That class admits lowercase, so
// `APExcludedBlocks` — `AP`, then `E` (inside `[\dABCDEF]`), then fourteen
// alphanumerics — is a match. The rule came from Pinkerton, which scans Git
// commits where a JavaScript property name is rarer; against a minified bundle
// the rule matches every property the vendor starts with `AP`.
//
// Measured on the three live bundles this session crawled, 2026-10-04:
//
//	981eec04.js  yandex.ru/ads/system/context.js      433 340 B  1 match  (16 chars)
//	e9666a1d.js  prebid.min.js                         20 895 B  0 matches
//	a39887db.js  jquery-1.12.4.min.js                   39 396 B  0 matches
//
// The one match was the false positive, and the two files that matched nothing
// are the control: the gate must not cost a real token.
//
// The gate is the one this registry already has and this rule was not using.
// `secretValueIsUsable` requires a credential to carry a digit as well as
// letters, because "a credential has structure a label does not". Both
// properties measured above carry no digit at all — `APExcludedBlocks` and its
// sibling `APExceptionBlocks`, 0 of 2. A JFrog reference token is a
// base62 blob of 73 characters, and a 73-character random string without a digit
// has probability (62/62)^… effectively zero: the gate cannot lose a real token.

import (
	"strings"
	"testing"
)

// TestAMinifiedPropertyNamedLikeAnArtifactoryPasswordIsNotASecret is the
// measured false positive, verbatim.
func TestAMinifiedPropertyNamedLikeAnArtifactoryPasswordIsNotASecret(t *testing.T) {
	analysis := analysisOf(t, `
var ads = {key:"APExcludedBlocks", get:function(){return this._excludedBlocks;}};
`)
	for _, rule := range secretRulesOf(analysis.Secrets) {
		if strings.Contains(rule, "artifactory") {
			t.Errorf("a property key was reported as a credential: %v", secretRulesOf(analysis.Secrets))
		}
	}
	// The value itself must not survive into the record either, whatever rule
	// named it — a finding is the rule *and* the value, and either half alone is
	// an accusation.
	for _, secret := range analysis.Secrets {
		if strings.Contains(secret.Value, "ExcludedBlocks") {
			t.Errorf("the property key survived as a secret value: %q", secret.Value)
		}
	}
}

// TestTheSiblingPropertyFromTheSameBundleIsAlsoRejected covers the second
// property measured in that file. One case is a fixture; two is a shape.
func TestTheSiblingPropertyFromTheSameBundleIsAlsoRejected(t *testing.T) {
	analysis := analysisOf(t, `
var ads = {key:"APExceptionBlocks", onload:function(){}};
`)
	for _, rule := range secretRulesOf(analysis.Secrets) {
		if strings.Contains(rule, "artifactory") {
			t.Errorf("a property key was reported as a credential: %v", secretRulesOf(analysis.Secrets))
		}
	}
}

// TestARealArtifactoryTokenIsStillReported is the half that makes the gate a
// gate and not a switch: the same rule, a value of the shape JFrog issues, and
// it must survive.
//
// The lengths are the vendor's, not invented: a JFrog reference token is 73
// characters of base62 after `AP`.
func TestARealArtifactoryTokenIsStillReported(t *testing.T) {
	token := "AP1" + strings.Repeat("kQ7xZp2Lm9Rt4Wv6Ny1Bd3cH2jF5sG8wE0qR3tU6yI9oP", 2)[:70]
	analysis := analysisOf(t, `var cfg = {artifactory_password: "`+token+`"};`)
	found := false
	for _, secret := range analysis.Secrets {
		if strings.Contains(secret.Value, token) {
			found = true
		}
	}
	if !found {
		t.Errorf("a real Artifactory token was dropped by the gate: %v", secretRulesOf(analysis.Secrets))
	}
}

// TestTheArtifactoryApiTokenRuleIsNotSilencedByTheSameGate has both halves, and
// the negative half was missing when this test was first written.
//
// The first version only checked that a real `AKC…` token survives, and the
// mutation run said so: removing the gate from `pinkerton_artifactory_api_token`
// left the test green. That is not a broken mutation — it is a test that cannot
// fail — because a gate applied to a rule that only ever fires on real tokens is
// indistinguishable from no gate at all.
//
// So the sibling rule needs the same pair of cases as the password rule: a
// property key shaped like the token, which must be rejected, and a real token,
// which must survive. The property is invented rather than measured, because
// measuring it needs a bundle that actually contains one: across the three live
// bundles of this session (`yandex.ru/ads/system/context.js`, `prebid.min.js`,
// `jquery-1.12.4.min.js`) there is no `AKC*` identifier at all. It is named here
// after the one the other rule produced, because the two patterns are the same
// shape with a different prefix.
func TestTheArtifactoryApiTokenRuleIsNotSilencedByTheSameGate(t *testing.T) {
	// The negative half, first: without it this test cannot fail.
	analysis := analysisOf(t, `
var sdk = {key:"AKCSessionBlocks", load:function(){return this._blocks;}};
`)
	for _, rule := range secretRulesOf(analysis.Secrets) {
		if strings.Contains(rule, "artifactory") {
			t.Errorf("a property key was reported as a credential: %v", secretRulesOf(analysis.Secrets))
		}
	}
	for _, secret := range analysis.Secrets {
		if strings.Contains(secret.Value, "AKCSessionBlocks") {
			t.Errorf("the property key survived as a secret value: %q", secret.Value)
		}
	}

	// And the positive half: the same rule must not lose a token.
	token := "AKC1" + strings.Repeat("p8rT3wZ6nX9qL2mK5vB4yD7fH0jK3mN6qS9tV2wX5z", 2)[:69]
	kept := analysisOf(t, `var cfg = {artifactory_key: "`+token+`"};`)
	found := false
	for _, secret := range kept.Secrets {
		if strings.Contains(secret.Value, token) {
			found = true
		}
	}
	if !found {
		t.Errorf("a real Artifactory API token was dropped by the gate: %v", secretRulesOf(kept.Secrets))
	}
}
