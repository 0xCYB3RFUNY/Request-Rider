package main

import "testing"

// TestASpecificRuleStillWinsItsOwnValue holds down the fold.
//
// One credential is one row: when two rules recognise the same bytes, the first
// rule in priority order claims them and the second is skipped. That fold is what
// stops a report from listing the same key twice — and it is also a way to lose
// information without noticing, because a broad rule claiming a value first turns
// "this is a JWT" into "generic secret assignment" and the row still looks
// perfectly complete.
//
// This test exists because it happened twice in one session, both times from a
// change that looked strictly additive:
//
//   - widening the generic assignment rule's value class to include `.` made it
//     capture a whole three-segment JWT, whose fingerprint then matched
//     `jwt_token`'s. `TestJWTRuleNeedsThreeRealSegments` caught the first.
//   - the same widening made it capture an `xoxb-` token whole, and `slack_token`
//     stopped firing. Nothing failed; this file is what caught it.
//
// The bodies pair a variable name the catch-all accepts with a value a specific
// rule recognises by shape. Every one of them is a value a real bundle carries, and
// every one of them has a name the UI and the report already speak, so losing the
// name breaks lookups written against it.
func TestASpecificRuleStillWinsItsOwnValue(t *testing.T) {
	const catchAll = "generic_api_key_assignment"

	for _, probe := range []struct{ want, body string }{
		{"jwt_token",
			`const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV';`},
		{"slack_token",
			`var token = "xoxb-1111-2222-aBcDeFgHiJkLmNoPqRsTuVwXyZ";`},
		{"hardcoded_password",
			`var password = "Tr0ub4dor3xK9vLmQ2wZxP7";`},
		{"hardcoded_username",
			`var username = "svc_moderator";`},
		{"aws_access_key_id",
			`var api_key = "AKIAZQ7RT4MNPX2VBCDE";`},
		{"github_token",
			`var api_token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";`},
		{"private_key_block",
			`var private_key = "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA1x2y3z";`},
	} {
		reported := applySecretText(probe.body)
		if !containsRuleName(reported, probe.want) {
			t.Errorf("%s was not reported for %q; got %v", probe.want, probe.body, reported)
		}
		// The catch-all still recognises the value — it is only outranked, not
		// switched off. Asserting its absence as well would pin down a different
		// design: this test is about which name wins, not about how many match.
		if containsRuleName(reported, catchAll) && reported[0] == catchAll {
			t.Errorf("%s: the catch-all %q claimed the value first, so the finding "+
				"lost the name that says which credential it is", probe.want, catchAll)
		}
	}
}
