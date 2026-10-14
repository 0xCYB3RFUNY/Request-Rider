package enrich

import (
	"regexp"
	"strings"
	"testing"
)

// The rule set is generated. These tests exist because a generated table is
// exactly the thing that can be wrong without anyone noticing: a rule that does
// not compile panics, but a rule that compiled and never matches is invisible.

func TestTitusRuleSetIsPresentAndComplete(t *testing.T) {
	rules := SecretRules()
	if len(rules) < 500 {
		t.Fatalf("the rule set has %d rules; upstream ships 539 and a partial port must not look complete", len(rules))
	}
	ids := map[string]bool{}
	var withGroup, withRequirements, withEntropy, withReject, noisy int
	for _, rule := range rules {
		if rule.ID == "" {
			t.Error("a rule has no id")
			continue
		}
		if ids[rule.ID] {
			t.Errorf("duplicate rule id %s", rule.ID)
		}
		ids[rule.ID] = true
		if rule.Regex == nil {
			t.Errorf("%s: no compiled regex", rule.ID)
			continue
		}
		if rule.Group <= 0 {
			t.Errorf("%s: no capture group, so the rule matches and reports nothing", rule.ID)
		}
		if rule.Name == "" {
			t.Errorf("%s: no name", rule.ID)
		}
		if rule.Group > rule.Regex.NumSubexp() {
			t.Errorf("%s: capture group %d does not exist (only %d)", rule.ID, rule.Group, rule.Regex.NumSubexp())
		}
		if rule.Group > 0 {
			withGroup++
		}
		req := rule.Requirement
		if req.MinDigits+req.MinUpper+req.MinLower+req.MinSpecial > 0 || len(req.IgnoreIfContains) > 0 {
			withRequirements++
		}
		if rule.MinEntropy > 0 {
			withEntropy++
		}
		if rule.Reject != nil {
			withReject++
		}
		if rule.Noisy {
			noisy++
		}
	}
	// Each of these is a number the generator produced; dropping one to zero
	// would be a port that lost a mechanism without any error.
	if withGroup != len(rules) {
		t.Errorf("%d of %d rules carry a capture group", withGroup, len(rules))
	}
	if withRequirements < 150 {
		t.Errorf("only %d rules carry character requirements; upstream has hundreds", withRequirements)
	}
	if withEntropy < 200 {
		t.Errorf("only %d rules carry min_entropy; upstream has hundreds", withEntropy)
	}
	if withReject != 4 {
		t.Errorf("%d rules carry a RE2 reject expression, expected 4 lookaheads rewritten", withReject)
	}
	if noisy == 0 {
		t.Error("no rule is marked noisy; upstream keeps noisy rules out of its default set")
	}
}

func TestScanSecretsFindsVendorKeys(t *testing.T) {
	// AKIA plus exactly sixteen: the documented placeholder
	// `AKIAIOSFODNN7EXAMPLE` has the same length, so the only thing separating a
	// real key from it is the value, not the shape. A 23-character value cannot
	// match the rule at all, which is a different failure and was the reason the
	// first version of this fixture found nothing.
	body := strings.Join([]string{
		`config := map[string]string{`,
		`  "key": "AKIAIOSFODNN7SECRETK",`,
		`  "slack": "xoxb-123456789012-1234567890123-A1b2C3d4E5f6G7h8I9j0K1l2",`,
		`}`,
	}, "\n")
	scan := ScanSecrets(body, false)
	if len(scan.Findings) == 0 {
		t.Fatalf("expected findings, got none; rejected=%+v", scan.Rejected)
	}
	rules := map[string]bool{}
	for _, f := range scan.Findings {
		rules[f.Rule] = true
		if f.Value == "" {
			t.Errorf("%s reported an empty value", f.Rule)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s reported no fingerprint", f.Rule)
		}
		if f.Line <= 0 {
			t.Errorf("%s reported line %d, line numbers are 1-based", f.Rule, f.Line)
		}
		if strings.Contains(f.Fingerprint, f.Value) && len(f.Value) > 8 {
			t.Errorf("%s fingerprint leaks the whole value: %q", f.Rule, f.Fingerprint)
		}
	}
	if !rules["np.aws.1"] {
		t.Errorf("np.aws.1 did not fire on an AWS key; fired: %v", rules)
	}
}

// TestScanSecretsRejectsTheDocumentedAWSPlaceholder: the exclusion that RE2
// cannot express as a lookahead now lives in the rule's Reject expression. If
// that field is dropped, this test is what notices.
func TestScanSecretsRejectsTheDocumentedAWSPlaceholder(t *testing.T) {
	placeholder := "AKIAIOSFODNN7EXAMPLE"
	real := "AKIAIOSFODNN7SECRETK"

	for _, tc := range []struct {
		value string
		want  bool
		why   string
	}{
		{placeholder, false, "the AWS documentation key must be rejected"},
		{real, true, "a real-looking key must be accepted"},
	} {
		scan := ScanSecrets(`key = "`+tc.value+`"`, false)
		fired := false
		for _, f := range scan.Findings {
			if f.Rule == "np.aws.1" {
				fired = true
			}
		}
		if fired != tc.want {
			t.Errorf("%s: np.aws.1 fired=%v, want %v (rejected=%+v)", tc.value, fired, tc.want, scan.Rejected)
		}
		if !tc.want {
			rejected := false
			for _, r := range scan.Rejected {
				if r.Rule == "np.aws.1" && strings.Contains(r.Reason, "EXAMPLE") {
					rejected = true
				}
			}
			if !rejected {
				t.Errorf("%s: expected a rejection naming EXAMPLE, got %+v", tc.value, scan.Rejected)
			}
		}
	}
}

// TestScanSecretsRejectsSnakeCaseConstants is the other RE2 rewrite: an
// ALL_CAPS_SNAKE_CASE name next to `password =` is a configuration key, not a
// credential, and reporting it buries the real ones.
func TestScanSecretsRejectsSnakeCaseConstants(t *testing.T) {
	scan := ScanSecrets(`password = "PASSWORD_MIN_LENGTH"`, false)
	for _, f := range scan.Findings {
		if f.Rule == "np.generic.5" {
			t.Fatalf("an ALL_CAPS_SNAKE_CASE constant was reported as a credential: %+v", f)
		}
	}
}

func TestScanSecretsRejectsPlaceholders(t *testing.T) {
	for _, value := range []string{
		`"sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
		`"AKIAIOSFODNN7EXAMPLE"`,
	} {
		scan := ScanSecrets(`token = "`+value+`"`, false)
		for _, f := range scan.Findings {
			if f.Value == value {
				t.Errorf("%s should have been rejected as a placeholder", value)
			}
		}
	}
}

// TestScanSecretsDedupesOneValueTwoRules: one leaked key reported twice reads as
// two incidents and inflates every count above it.
func TestScanSecretsDedupesOneValueTwoRules(t *testing.T) {
	body := `AKIAIOSFODNN7SECRETK`
	scan := ScanSecrets(body, false)
	seen := map[string]int{}
	for _, f := range scan.Findings {
		seen[f.Value]++
	}
	for value, n := range seen {
		if n > 1 {
			t.Errorf("value %q reported by %d rules, expected once", value, n)
		}
	}
}

func TestScanSecretsNoisyRulesAreOffByDefault(t *testing.T) {
	// A noisy rule must be reachable, and must not inflate the default pass.
	quiet := ScanSecrets("nothing to see here", false)
	loud := ScanSecrets("nothing to see here", true)
	if quiet.RulesRun >= loud.RulesRun {
		t.Errorf("noisy rules are not excluded by default: %d vs %d", quiet.RulesRun, loud.RulesRun)
	}
	if quiet.RulesAvailable != len(SecretRules()) {
		t.Errorf("the report must say how many rules the build carries, got %d of %d",
			quiet.RulesAvailable, len(SecretRules()))
	}
}

func TestScanSecretsOnEmptyBody(t *testing.T) {
	scan := ScanSecrets("", true)
	if len(scan.Findings) != 0 || len(scan.Rejected) != 0 {
		t.Fatalf("empty body must yield nothing, got %+v", scan)
	}
	if scan.RulesAvailable != len(SecretRules()) {
		t.Error("an empty body still has to report the rule inventory")
	}
}

func TestScanSecretsOrdersBySeverityThenLine(t *testing.T) {
	scan := ScanSecrets(`AKIAIOSFODNN7SECRETK
xoxb-123456789012-1234567890123-A1b2C3d4E5f6G7h8I9j0K1l2`, true)
	for i := 1; i < len(scan.Findings); i++ {
		a, b := scan.Findings[i-1], scan.Findings[i]
		if a.Score < b.Score {
			t.Fatalf("findings must be ordered by descending score: %+v", scan.Findings)
		}
		if a.Score == b.Score && a.Line > b.Line {
			t.Fatalf("equal scores must be ordered by line: %+v", scan.Findings)
		}
	}
}

func TestSecretSeverityBands(t *testing.T) {
	cases := map[int]string{90: "critical", 70: "high", 40: "medium", 10: "low"}
	for score, want := range cases {
		if got := secretSeverity(score); got != want {
			t.Errorf("secretSeverity(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestCharacterRequirementsSayWhy(t *testing.T) {
	req := CharacterRequirements{MinDigits: 2, MinUpper: 1, MinLower: 1}
	if ok, _ := req.Satisfied("Str0ngPassw0rd"); !ok {
		t.Error("a value meeting the requirement was rejected")
	}
	ok, reason := req.Satisfied("password")
	if ok {
		t.Error("a value missing digits and uppercase must be rejected")
	}
	if !strings.Contains(reason, "digits") {
		t.Errorf("the rejection must name what failed, got %q", reason)
	}
	ignore := CharacterRequirements{IgnoreIfContains: []string{"example"}}
	if ok, _ := ignore.Satisfied("myEXAMPLEkey"); ok {
		t.Error("ignore_if_contains must reject the value")
	}
}

// Three guards that the first version of this file could not prove. Each one was
// found by a mutation that stayed green, which is the only honest way to find a
// guard nobody is testing: the mutation is the question "is this line load-
// bearing?", and green means nobody has ever depended on it.

// TestCharacterRequirementsRejectThroughTheScanner isolates the requirement check
// from the entropy check. `kingfisher.algolia.2` is the right rule for it: it
// carries `min_digits: 2` and `min_entropy: 2.0`, so ten distinct letters fail
// the requirement while clearing the entropy floor comfortably. Without the
// requirement check, `algolia ABCDEFGHIJ` would be reported as a key.
func TestCharacterRequirementsRejectThroughTheScanner(t *testing.T) {
	body := `algolia ABCDEFGHIJ`
	scan := ScanSecrets(body, true)
	for _, f := range scan.Findings {
		if f.Rule == "kingfisher.algolia.2" {
			t.Fatalf("a value with no digits was accepted: %+v", f)
		}
	}
	found := false
	for _, r := range scan.Rejected {
		if r.Rule == "kingfisher.algolia.2" && strings.Contains(r.Reason, "digits") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rejection naming the digit requirement, got %+v", scan.Rejected)
	}
}

// TestEntropyRejectsThroughTheScanner isolates entropy from the character
// requirements. `kingfisher.airtable.2` has `min_entropy: 3.5` and no character
// requirements at all, so nothing but entropy can reject the value.
func TestEntropyRejectsThroughTheScanner(t *testing.T) {
	low := ScanSecrets(`key AAAA.v1.AAAA.aaaa`, true)
	for _, f := range low.Findings {
		if f.Rule == "kingfisher.airtable.2" {
			t.Fatalf("a low-entropy value was accepted: %+v", f)
		}
	}
	found := false
	for _, r := range low.Rejected {
		if r.Rule == "kingfisher.airtable.2" && strings.Contains(r.Reason, "entropy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an entropy rejection, got %+v", low.Rejected)
	}
	// And the same rule must still accept a value that clears the floor, so the
	// test is about entropy rather than about the rule being broken.
	high := ScanSecrets(`key KX7QP2M9.v1.A1B2C3D4.9f8e7d6c`, true)
	accepted := false
	for _, f := range high.Findings {
		if f.Rule == "kingfisher.airtable.2" {
			accepted = true
		}
	}
	if !accepted {
		t.Fatalf("a high-entropy value must be accepted; rejected=%+v", high.Rejected)
	}
}

// TestEmptyCaptureGroupIsRejected covers the guard no upstream rule can reach.
// A rule whose group is optional matches while capturing nothing; reporting it
// as a finding with an empty value is worse than not reporting it, because the
// count would claim a credential that is not in the text.
func TestEmptyCaptureGroupIsRejected(t *testing.T) {
	rules := []SecretRule{{
		ID:    "test.optional.1",
		Name:  "optional group",
		Regex: regexp.MustCompile(`token(?P<secret>[A-Za-z0-9]{4})?`),
		Group: 1,
		Score: 50,
	}}
	withValue := scanWithRules("tokenAb3d", rules, true)
	if len(withValue.Findings) != 1 || withValue.Findings[0].Value != "Ab3d" {
		t.Fatalf("a rule with a participating group must report the value, got %+v", withValue)
	}
	withoutValue := scanWithRules("token", rules, true)
	if len(withoutValue.Findings) != 0 {
		t.Fatalf("a match with an empty capture group must not be reported: %+v", withoutValue.Findings)
	}
	if len(withoutValue.Rejected) != 1 ||
		!strings.Contains(withoutValue.Rejected[0].Reason, "capture group") {
		t.Fatalf("the empty capture must be rejected with a reason, got %+v", withoutValue.Rejected)
	}
}
