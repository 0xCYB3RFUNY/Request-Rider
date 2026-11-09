package main

// Tests for the secret patterns taken from `m4ll0k/SecretFinder`.
//
// The tool this came from is a list of regular expressions and nothing else, so
// the only honest question is whether each pattern of ours matches the thing it
// names and does not match the things a minified bundle is full of. Both halves
// are tested, because a pattern that matches everything is worse than a missing
// one: it teaches the analyst to ignore a column.
//
// Source read at commit d06119dedd9c1505137d1ec4792d5d5b65c7425d.

import (
	"regexp"
	"strings"
	"testing"
)

// TestThePatternsTakenFromSecretFinderMatchWhatTheyName is the positive half,
// one case per rule, with a value of the length the vendor issues.
func TestThePatternsTakenFromSecretFinderMatchWhatTheyName(t *testing.T) {
	cases := map[string]string{
		"google_oauth_token":      `var t = "ya29.A0ARrdaM9xH4cVv8pLd7Qg2zR1kW6yB3nJ9fT5mX0eC";`,
		"google_captcha_site_key": `var k = "6L` + strings.Repeat("a", 38) + `";`,
		"amazon_mws_auth_token":   `var a = "amzn.mws.1234abcd-12ab-34cd-56ef-1234567890ab";`,
		"facebook_access_token":   `var f = "EAACEdEose0cBAabc123DEF456ghi789JKL012";`,
		"square_access_token":     `var s = "sqOatp-abcdefghijklmnopqrstuv";`,
	}
	for id, source := range cases {
		analysis := analysisOf(t, source)
		if !ruleReported(secretRulesOf(analysis.Secrets), id) {
			t.Errorf("%s did not match its own sample; rules found: %v",
				id, secretRulesOf(analysis.Secrets))
		}
	}
}

// TestTheValuesAreReportedWhole is the half the first version of this file
// missed, and the header of `osint_secrets.go` names it as a defect this project
// already paid for: a rule whose tail is too short reports the first N
// characters of a secret, and a truncated key is indistinguishable from a wrong
// one. Checking only that the rule fired stays green under exactly that bug.
func TestTheValuesAreReportedWhole(t *testing.T) {
	source := `var t = "ya29.A0ARrdaM9xH4cVv8pLd7Qg2zR1kW6yB3nJ9fT5mX0eC";`
	analysis := analysisOf(t, source)
	const full = "ya29.A0ARrdaM9xH4cVv8pLd7Qg2zR1kW6yB3nJ9fT5mX0eC"
	for _, secret := range analysis.Secrets {
		if secret.Rule != "google_oauth_token" {
			continue
		}
		if secret.Value != full {
			t.Errorf("value = %q, want the whole %d-character token", secret.Value, len(full))
		}
		return
	}
	t.Fatalf("google_oauth_token was not reported at all: %v", secretRulesOf(analysis.Secrets))
}

// TestThePatternsTakenFromSecretFinderIgnoreABundle is the half that keeps the
// column readable: each case is something a real minified bundle contains
// constantly, written in the shape that rule would otherwise take.
func TestThePatternsTakenFromSecretFinderIgnoreABundle(t *testing.T) {
	cases := map[string]string{
		"google_oauth_token":      `var u="/assets/app.min.js?v=12";var r="#/ya29";`,
		"google_captcha_site_key": `var h="6Lc";var v="6L"+38;var w="L6` + strings.Repeat("f", 38) + `";`,
		"amazon_mws_auth_token":   `var pkg="amzn.mws.region.us-east-1";`,
		"facebook_access_token":   `var q="EAACEdEose0cBA";var g="facebook_access_token";`,
		"square_access_token":     `var s="sqOatp-not-a-token";var v="EAAAshort";`,
	}
	for id, source := range cases {
		analysis := analysisOf(t, source)
		if ruleReported(secretRulesOf(analysis.Secrets), id) {
			t.Errorf("%s matched ordinary bundle text: %v", id, analysis.Secrets)
		}
	}
}

// TestTheThreeSkippedSecretFinderPatternsAreAbsentHere records the decision that
// the other three of its patterns are not ours, so a later reader does not add
// them back as an oversight and thereby re-introduce the noise.
//
// Each of the three is high-volume in a bundle: `AC` plus 32 characters matches
// any long identifier starting with two letters, `SK` plus 32 hex characters
// matches a good share of the digests in a build, and `basic` plus a character
// class matches the word followed by half a minified file. `osint_secrets.go`
// says why in its own header: a list full of invented findings is worse than a
// short honest one.
func TestTheThreeSkippedSecretFinderPatternsAreAbsentHere(t *testing.T) {
	present := map[string]bool{}
	for _, rule := range secretRules {
		present[rule.id] = true
	}
	// A rule already carries the Twilio API key, through Pinkerton's own list.
	// Naming it here is the point: the omission below is about the *duplicate*,
	// and a reader who adds a second pattern for a key we already catch would
	// double every finding in a bundle that ships one.
	if !present["pinkerton_twilio_api_key"] {
		t.Errorf("pinkerton_twilio_api_key is gone, so the note about not re-adding it is stale")
	}
	for _, skipped := range []string{"twilio_account_sid", "twilio_api_key", "authorization_basic"} {
		if present[skipped] {
			t.Errorf("%s was added; leaving it out was deliberate, so adding it needs a reason, not a habit",
				skipped)
		}
	}
}

// TestTheSkippedPatternsWouldHaveFiredOnRealNoise says what the omission bought,
// so the decision is measured rather than argued. Each sample is a string that
// appears in ordinary bundles and that the skipped pattern would have reported.
func TestTheSkippedPatternsWouldHaveFiredOnRealNoise(t *testing.T) {
	// The three patterns exactly as SecretFinder writes them.
	skipped := map[string]*regexp.Regexp{
		"twilio_account_sid":  regexp.MustCompile(`AC[0-9a-zA-Z_-]{32}`),
		"twilio_api_key":      regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		"authorization_basic": regexp.MustCompile(`basic\s*[a-zA-Z0-9=:_\+\/-]+`),
	}
	noise := map[string]string{
		"twilio_account_sid":  `var accessControlConstantValue = "ACaabbccddeeff00112233445566778899";`,
		"twilio_api_key":      `var digest="SKaabbccddeeff00112233445566778899aabbccdd";`,
		"authorization_basic": `var basicAuth=basic+" "+user;`,
	}
	for id, pattern := range skipped {
		if !pattern.MatchString(noise[id]) {
			t.Fatalf("%s: the sample no longer matches the pattern it was chosen for, so the test proves nothing", id)
		}
		// The Twilio API key is the one case where our rules *do* fire, because
		// Pinkerton already carries that pattern. Its sample is therefore the
		// proof that the pattern was worth having and the omission was only ever
		// about the duplicate; the other two must be silence.
		if id == "twilio_api_key" {
			analysis := analysisOf(t, noise[id])
			if !ruleReported(secretRulesOf(analysis.Secrets), "pinkerton_twilio_api_key") {
				t.Errorf("pinkerton no longer catches the Twilio key: %v", secretRulesOf(analysis.Secrets))
			}
			continue
		}
		analysis := analysisOf(t, noise[id])
		if len(analysis.Secrets) > 0 {
			t.Errorf("%s: our rules reported %v for a sample kept only to show what was left out",
				id, secretRulesOf(analysis.Secrets))
		}
	}
}

// ruleReported answers "was this rule among the reported ones".
func ruleReported(rules []string, id string) bool {
	for _, rule := range rules {
		if rule == id {
			return true
		}
	}
	return false
}
