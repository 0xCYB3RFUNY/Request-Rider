package main

// Tests that a secret survives the JavaScript analyser whole.
//
// The operator's question: «проверь что все секреты ключи отдаются полностью а не
// обрезаются». This file is the measurement for the JavaScript path; the page
// path is measured by `TestAPageSecretComesBackAtFullLength` in `pkg/enrich`,
// because the analyser here lives in `main` and that scan lives there — a test
// cannot reach across that line, and duplicating the analyser to make it reach
// would be a second implementation of one rule.
//
// # What this file measures, and what it deliberately does not
//
// The first version put six realistic secrets into a bundle and asked whether
// they came back whole. Four of the six came back **not at all** — the analyser
// reported nothing for a base62 API token under `api_token`, a Slack token, a
// long random password and a PostgreSQL connection string.
//
// That is a different defect from truncation, and conflating the two produces a
// comfortable lie: "the value was not shortened" reads as a pass when the value
// was never found. So the two questions are separated:
//
//   - **Truncation** — a value a rule *does* match comes back at full length.
//     That is what this file asserts.
//   - **Coverage** — which shapes the rule set matches at all. Measured, and
//     recorded in `DEVELOPMENT_LOG.md` rather than asserted here, because a
//     coverage claim about a 90-rule vendored set is a project of its own and
//     not something to smuggle in as an assertion.
//
// The probe is `generic_api_key_assignment`, reached through `var api_key = "…"`.
// It is the one shape measured to fire whose length is whatever the fixture says,
// so a ceiling anywhere in the path is forced to show itself. Two vendor shapes
// are measured alongside it because they are the ones with history: `slack_token`
// once reached the UI as 32 characters instead of 54, and a 212-character FCM key
// as 152.
//
// # Why a round trip and not a reading of the code
//
// This project has paid for truncation twice and neither was visible in a review.
// Both are recorded in the comment above `secretRules` in this very file. So the
// question is asked of the code, at every length, not of the comment.

import (
	"strings"
	"testing"
)

// truncationLengths are the lengths the probe runs at. 30 is the shortest
// plausible secret, 54 is the length of the Slack token from the earlier defect,
// 212 is the length of the FCM key from the same defect, and 400 is past any
// ceiling someone would have called generous.
var truncationLengths = []int{30, 54, 212, 400}

// probeValue builds a value of exactly `length` characters, from an alphabet the
// generic rule accepts.
//
// The body cycles so the value carries letters and digits: `secretValueIsUsable`
// rejects a value without both, and a value rejected before the truncation
// question is reached proves nothing about truncation.
func probeValue(length int) string {
	const alphabet = "kR7pQ2mX9tL4wB8nZ3vF6yH1sD5gA0cJ7eU2iO4qN6bV8mK3xZ"
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[i%len(alphabet)]
	}
	return string(out)
}

// TestASecretComesBackAtFullLength is the measurement: a value the rule matches
// comes back byte for byte, at every length tried.
func TestASecretComesBackAtFullLength(t *testing.T) {
	for _, length := range truncationLengths {
		value := probeValue(length)
		analysis := analysisOf(t, `var api_key = "`+value+`";`)
		if !carriesWhole(analysis.Secrets, value) {
			t.Errorf("%d characters in, not the same %d characters out; got %d finding(s): %v",
				length, length, len(analysis.Secrets), secretValues(analysis.Secrets))
			continue
		}
		longest := 0
		for _, secret := range analysis.Secrets {
			if len(secret.Value) > longest {
				longest = len(secret.Value)
			}
		}
		// Stated as a number so a failure says how far it fell short.
		if longest != length {
			t.Errorf("%d characters in, %d out: the value was cut at %d", length, longest, longest)
		}
	}
}

// TestTheVendorShapesThatWereTruncatedBeforeAreWholeAgain names the two lengths
// where truncation was actually measured in this project, so a regression at
// exactly those lengths fails on its own rather than as a side effect.
func TestTheVendorShapesThatWereTruncatedBeforeAreWholeAgain(t *testing.T) {
	// Slack: the token is `xoxb-<team>-<bot>-<secret>`; the secret half is 54
	// characters and the whole match is 69. This is the 54 → 32 defect.
	value := probeValue(54)
	slack := analysisOf(t, `var t = "xoxb-1111-2222-`+value+`";`)
	if !carriesWhole(slack.Secrets, "xoxb-1111-2222-"+value) {
		t.Errorf("the Slack token does not come back whole: %v", secretValues(slack.Secrets))
	}

	// Bearer: the match is the whole header value including the scheme, so the
	// expected length is the value plus the word `Bearer` and its space.
	bearer := probeValue(96)
	analysis := analysisOf(t, `var h = {Authorization: "Bearer `+bearer+`"};`)
	if !carriesWhole(analysis.Secrets, "Bearer "+bearer) {
		t.Errorf("the bearer header does not come back whole: %v", secretValues(analysis.Secrets))
	}
}

// TestTheFingerprintDoesNotStandInForTheValue is the half that is easy to get
// wrong in the opposite direction.
//
// `secretFingerprint` returns a six-character prefix and a digest, not the
// secret, and that is by design: the graph is exported into project bundles,
// rendered into reports and pasted into chats. The risk this closes is the silent
// one — a field that is *supposed* to carry the whole value quietly falling back
// to the fingerprint, so the record holds the secret and the report prints six
// characters.
func TestTheFingerprintDoesNotStandInForTheValue(t *testing.T) {
	const secret = "kR7pQ2mX9tL4wB8nZ3vF6yH1sD5gA0cJ7eU2iO4qN6bV8mK3"
	prefix, digest := secretFingerprint(secret)
	if prefix != secret[:6] {
		t.Errorf("the fingerprint prefix is %q, want the first six characters %q", prefix, secret[:6])
	}
	if digest == "" || digest == prefix {
		t.Errorf("the fingerprint digest is %q, which identifies nothing", digest)
	}
	if strings.Contains(digest, secret) {
		t.Errorf("the digest leaks the whole value: %q", digest)
	}

	analysis := analysisOf(t, `var api_key = "`+secret+`";`)
	seen := false
	for _, found := range analysis.Secrets {
		if found.Value != secret {
			continue
		}
		seen = true
		if strings.Contains(found.Fingerprint, secret) {
			t.Errorf("the fingerprint stands in for the value: %q", found.Fingerprint)
		}
	}
	if !seen {
		t.Fatalf("the probe stopped matching, so this test would pass without testing anything")
	}
}

func carriesWhole(secrets []jsSecret, value string) bool {
	for _, secret := range secrets {
		if secret.Value == value {
			return true
		}
	}
	return false
}
