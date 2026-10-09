package enrich

// Tests that a secret survives the page scan whole.
//
// The operator's question: «проверь что все секреты ключи отдаются полностью а не
// обрезаются». This file is the measurement for the page path; the JavaScript
// path is measured by `TestASecretIsReportedWhole` in the engine's main package,
// because the analyser there lives in `main` and this scan lives here — a test
// cannot reach across that line, and duplicating the analyser to make it reach
// would be a second implementation of one rule.
//
// # What this file measures, and what it deliberately does not
//
// The first version of this test put six realistic secrets into a page and asked
// whether they came back whole. Five of the six came back **not at all** — the
// scan reported zero findings for a base62 API token, a Slack token, a long
// random password and a 212-character key.
//
// That is a different defect from truncation, and conflating the two would have
// produced a comfortable lie: "the value was not shortened" reads as a pass when
// the value was never found. So the two questions are separated:
//
//   - **Truncation** — a value the rule set *does* match comes back at full
//     length. That is what this file asserts.
//   - **Coverage** — whether the rule set matches a given secret at all. That is
//     a measurement of the vendored rule set, recorded in
//     `DEVELOPMENT_LOG.md`, and it is not a claim about this scan.
//
// The probe is `kingfisher.clojars.1`, chosen because its tail is
// `[a-z0-9_-]{3,}` — unbounded — so the value can be made any length and the
// ceiling, if there is one, is forced to show itself.
//
// The fixture shape is `clojars ID <value>`: the rule is
// `\bclojars(?:.|[\n\r]){0,32}?(?:ID|USER)(?:.|[\n\r]){0,16}?\b(?P<token>[a-z0-9_-]{3,})\b`,
// so the name and the `ID` marker both have to be present and close enough. The
// first version of this probe wrote `<div id="clojars">value</div>`, which has the
// name but not the marker in the right order, so the rule never fired and the
// test failed with zero findings — a failure that reads like a defect in the scan
// and is actually a defect in the probe. The shape was therefore measured rather
// than guessed, and the fingerprint test below fails loudly when the probe stops
// matching, so a broken probe cannot pass.
//
// # Why a round trip and not a reading of the code
//
// This project has already paid for truncation twice and neither was visible in a
// review: a Slack token handed to the UI as 32 characters instead of 54, and a
// 212-character FCM key as 152. Both are recorded in the comment above
// `secretRules` in `osint_secrets.go`. So the question is asked of the code.

import (
	"strings"
	"testing"
)

// truncationLengths are the lengths the probe is run at. 30 is the shortest
// plausible secret, 54 is the length of the Slack token from the earlier defect,
// 212 is the length of the FCM key from the same defect, and 400 is past any
// ceiling that would have been written as "generous".
var truncationLengths = []int{30, 54, 212, 400}

// probeValue builds a clojars-shaped token of exactly `length` characters.
//
// The alphabet is `[a-z0-9_-]` to match the rule exactly, and the body cycles
// through it so the value carries both letters and digits — `isPlaceholderValue`
// and the character requirements reject a value that does not, and a value
// rejected before the truncation question is reached proves nothing.
func probeValue(length int) string {
	const alphabet = "kR7pQ2mX9tL4wB8nZ3vF6yH1sD5gA0cJ7eU2iO4qN6bV8mK3xZ"
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[i%len(alphabet)]
	}
	return string(out)
}

// TestAPageSecretComesBackAtFullLength is the measurement. A value the rule
// matches must come back byte for byte, at every length tried.
func TestAPageSecretComesBackAtFullLength(t *testing.T) {
	for _, length := range truncationLengths {
		value := probeValue(length)
		body := `<html><body><div>clojars ID ` + value + `</div></body></html>`
		scan := ScanSecrets(body, false)
		if !scanCarries(scan, value) {
			t.Errorf("%d characters in, not the same %d characters out; got %d finding(s): %v",
				length, length, len(scan.Findings), valuesOf(scan.Findings))
			continue
		}
		// And the length, stated as a number, so a failure says how far it went
		// short rather than only that it did.
		longest := 0
		for _, finding := range scan.Findings {
			if len(finding.Value) > longest {
				longest = len(finding.Value)
			}
		}
		if longest != length {
			t.Errorf("%d characters in, %d out: the value was cut at %d",
				length, longest, longest)
		}
	}
}

// TestAPageSecretIsNotShortenedAtTheDocumentedDefectLengths names the two lengths
// where truncation was actually measured in this project, so a regression at
// exactly those lengths fails on its own rather than as a side effect.
func TestAPageSecretIsNotShortenedAtTheDocumentedDefectLengths(t *testing.T) {
	for _, defect := range []struct{ was, want int }{{32, 54}, {152, 212}} {
		value := probeValue(defect.want)
		scan := ScanSecrets(`<html><body><div>clojars ID `+value+`</div></body></html>`, false)
		if !scanCarries(scan, value) {
			t.Errorf("at %d characters the value does not come back whole; the earlier defect shortened it to %d",
				defect.want, defect.was)
		}
	}
}

// TestThePageFingerprintDoesNotStandInForTheValue is the half that is easy to get
// wrong in the opposite direction.
//
// `secretFingerprint` returns a short prefix and a digest, not the secret, and
// that is by design: the page goes into PostgreSQL, into project bundles and into
// exported reports. The risk this closes is the silent one — a field that is
// *supposed* to carry the whole value quietly falling back to the fingerprint, so
// the record holds the secret and the report prints six characters.
func TestThePageFingerprintDoesNotStandInForTheValue(t *testing.T) {
	value := probeValue(96)
	scan := ScanSecrets(`<html><body><div>clojars ID `+value+`</div></body></html>`, false)
	seen := false
	for _, finding := range scan.Findings {
		if finding.Value == value {
			seen = true
			if strings.Contains(finding.Fingerprint, value) {
				t.Errorf("the fingerprint stands in for the value: %q", finding.Fingerprint)
			}
			if len(finding.Value) != len(value) {
				t.Errorf("the finding carries %d characters for a %d-character value",
					len(finding.Value), len(value))
			}
		}
	}
	if !seen {
		t.Fatalf("the probe stopped matching, so the test would pass without testing anything")
	}
}

func scanCarries(scan SecretScan, value string) bool {
	for _, finding := range scan.Findings {
		if finding.Value == value {
			return true
		}
	}
	return false
}

func valuesOf(findings []SecretFinding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Value)
	}
	return out
}

// # A connection string delivered the username where the operator needed the password
//
// The operator's question, verbatim: «мы ниччего не отсикаем все исправить» —
// about the report that a realistic password was not found at all. Measuring it
// found a narrower and worse thing underneath: the password *was* found, matched,
// and then thrown away at the moment the capture group was chosen.
//
// Six of the seven connection-string rules name their groups `username`,
// `password`, `host`. The generator's preference list ranks a group by what it is
// called — `secret`, `secret_key`, `token`, `key`, `api_key` — and `password` is not
// in it, so the choice fell through to the first named group, the username.
// `postgres://app_user:s3cr3tP4ssw0rd7@db.internal:5432/o` reported `app_user`.
//
// The test below is in two halves on purpose. The static half covers every rule in
// the set, including the two whose pattern no fixture in this file matches, because
// "which group holds the credential" is a property of the table and can be asserted
// over the table. The behavioural half then reads the value out of a real scan for
// the shapes a real page carries, because a static assertion cannot tell a working
// fix from an index that happens to be numbered right.

// TestEveryRuleNamingAPasswordGroupDeliversThePassword is the static half: no rule
// in this build may name a `password` group and then deliver anything else.
func TestEveryRuleNamingAPasswordGroupDeliversThePassword(t *testing.T) {
	covered := 0
	for _, rule := range SecretRules() {
		if rule.Regex == nil {
			continue
		}
		index := rule.Regex.SubexpIndex("password")
		if index <= 0 {
			continue
		}
		covered++
		if got := credentialGroup(rule); got != index {
			// The message names the two group numbers and not the value that would
			// be read instead: `*regexp.Regexp` has no `SubexpName`, and inventing
			// a body to make the wrong group legible would be a diagnostic that can
			// itself be wrong. The behavioural half below prints real values.
			t.Errorf("rule %s names group %d as the password but delivers group %d; "+
				"the operator asked for the password", rule.ID, index, got)
		}
	}
	if covered == 0 {
		t.Fatal("no rule in this build names a password group, so the assertion is vacuous")
	}
	if covered < 6 {
		t.Errorf("only %d rules name a password group; the measurement that found the "+
			"defect counted 7, so a rule has gone missing", covered)
	}
}

// TestAConnectionStringDeliversThePasswordWhole is the behavioural half. The value
// must be the password byte for byte — not the username, not a prefix of it.
//
// # Why this asserts the value and not the rule that reported it
//
// The first version of this test looked for `finding.Rule == probe.rule` and failed
// on `kingfisher.credentials.1`. The defect it was written for did not come back:
// the password was delivered, by `requestrider.connection_string_password`, which is
// the same rule set's own rule at upstream `base_score` 60 against this rule's 55.
//
// That is the documented dedup contract — *"identical values found by two rules are
// deduplicated by fingerprint, and the highest-scoring rule wins"* — which until this
// change the code did not honour: it kept whichever rule came first in a 543-entry
// table whose order is upstream's, so the reported severity was an accident of the
// port. The static half above still pins every rule's group; this half pins the
// property that half cannot see, which is the value.
//
// So the assertion is now: the password is delivered exactly, the username is never
// delivered *as the credential*, and the rule that delivered it scores at least as
// high as the rule the probe names. The last clause is what keeps the dedup fix from
// being reverted into something that reports the weaker claim, and it fails loudly
// with both rule names when it does.
func TestAConnectionStringDeliversThePasswordWhole(t *testing.T) {
	cases := []struct {
		rule     string
		body     string
		password string
		username string
	}{
		{"np.postgres.1",
			`postgres://app_user:s3cr3tP4ssw0rd7@db.internal:5432/orders`,
			"s3cr3tP4ssw0rd7", "app_user"},
		{"np.redis.1",
			`redis://cacheuser:s3cr3tP4ssw0rd7@cache.internal:6379/0`,
			"s3cr3tP4ssw0rd7", "cacheuser"},
		{"np.mongodb.1",
			`mongodb://adminuser:Adm1nP4ssw0rd@cluster0.mongo.invalid/db`,
			"Adm1nP4ssw0rd", "adminuser"},
		{"kingfisher.credentials.1",
			`https://ftpuser:F7pP4ssw0rd7@files.invalid/pub`,
			"F7pP4ssw0rd7", "ftpuser"},
		{"kingfisher.curl.1",
			`curl -u apiuser:CurlP4ssw0rd7 https://api.invalid/v1`,
			"CurlP4ssw0rd7", "apiuser"},
	}
	for _, probe := range cases {
		scan := ScanSecrets(`<div data-cfg="`+probe.body+`"></div>`, false)

		delivered, deliveredScore := "", 0
		for _, finding := range scan.Findings {
			if finding.Value == probe.password {
				delivered, deliveredScore = finding.Value, finding.Score
			}
			if finding.Value == probe.username {
				t.Errorf("%s: the username %q was reported as the credential for %q",
					probe.rule, probe.username, probe.body)
			}
		}
		if delivered != probe.password {
			t.Errorf("%s: the password %q was not delivered for the body %q; findings=%v",
				probe.rule, probe.password, probe.body, valuesOf(scan.Findings))
			continue
		}

		want := scoreOfRule(probe.rule)
		if deliveredScore < want {
			t.Errorf("%s scores %d and delivered %q at %d: the weaker claim won the "+
				"dedup, so the report understates the finding",
				probe.rule, want, probe.password, deliveredScore)
		}
	}
}

// scoreOfRule is the table's own score for a rule id, so the assertion above reads
// the number from the table instead of restating it here and letting the two drift.
func scoreOfRule(id string) int {
	for _, rule := range secretRuleRegistry {
		if rule.ID == id {
			return rule.Score
		}
	}
	return 0
}
