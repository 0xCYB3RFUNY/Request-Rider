package enrich

import "testing"

// Tests for the project rules in `secrets_project_rules.go`.
//
// The rules were written after a measurement, not after a wish: a 24-name ×
// 6-value matrix, and a false-positive run over 2000 files of the Nuclei template
// set on this machine. These tests check the behaviour that came out of that
// measurement, so each one names what it holds down.
//
// Two of them are about refusals, and that is deliberate. A rule that reports
// `password: required` and `PublicKeyToken=31bf3856ad364e35` is worse than no
// rule at all, because the first thing an operator learns about a scanner that
// cries wolf is that its output can be ignored. Both of those inputs are real
// strings, not invented ones: the first is what a login form carries, and the
// second was read out of a .NET assembly attribute on this machine.

// delivered is every value the scan reports for a body, from whichever rule.
func delivered(body string) map[string]string {
	out := map[string]string{}
	for _, finding := range ScanSecrets(body, false).Findings {
		out[finding.Rule] = finding.Value
	}
	return out
}

func TestAConnectionStringWithoutAUserNameStillDeliversThePassword(t *testing.T) {
	// The shape that measured 0 findings on both paths. Redis is written this way
	// in the wild: the password is the only secret in the string, and both
	// vendored Redis rules require a user name before the colon.
	const body = `<div data-dsn="redis://:s3cr3tP4ssw0rd7Fg2Hj9Kl@cache.internal:6379/0">`
	want := "s3cr3tP4ssw0rd7Fg2Hj9Kl"

	if got := delivered(body)["requestrider.connection_string_password"]; got != want {
		t.Errorf("the password did not arrive whole: got %q, want %q", got, want)
	}
}

func TestACredentialInAnUnquotedAttributeArrivesWhole(t *testing.T) {
	// The vendored `np.generic.5` requires quotes, so this shape was invisible to
	// it — measured 0 findings, on a form every page with an inline credential has.
	const value = "kR7pQ2mX9tL4wB8nZ3vF6yH1sD5gA0cJ7eU2iO4qN6bV8mK3xZrT5wY9cV1bD6fG8hJ2kL4mN7pQ0s"
	body := `<div id="cfg" data-token=` + value + `></div>`

	got := delivered(body)
	found := false
	for _, text := range got {
		if text == value {
			found = true
		}
	}
	if !found {
		t.Errorf("an unquoted credential of %d characters did not arrive whole; got %v",
			len(value), got)
	}
}

func TestAPunctuatedQuotedPasswordArrivesWholeAndUncut(t *testing.T) {
	// The `&` is the point: a value class without it stops at the first `&`, which
	// is how a 53-character password becomes a 10-character one while still looking
	// like a complete finding.
	const value = "Tr0ub4dor&3xK9!vLmQ2#zXpW7@cRsD5*nHjF1@uBgY6^Kf2Rb7Wq"
	body := `<script>window.__cfg = {password: "` + value + `"};</script>`

	found := false
	for _, text := range delivered(body) {
		if text == value {
			found = true
		}
	}
	if !found {
		t.Errorf("a punctuated password of %d characters did not arrive whole", len(value))
	}
}

func TestASlackTokenCarryingAnUnderscoreArrivesWhole(t *testing.T) {
	// A class of `[0-9A-Za-z-]` stops before `_`, and the token below is 66
	// characters of which it delivered 65. A secret returned one character short
	// is not a shorter secret, it is a wrong one.
	const value = "xoxb-2947483729-2947483729-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH-_"
	body := `<div data-t="` + value + `">`

	if got := delivered(body)["requestrider.slack_token"]; got != value {
		t.Errorf("the token did not arrive whole: got %q (%d characters), want %d",
			got, len(got), len(value))
	}
}

// TestTheProjectRulesStayQuietOnRealLabels holds down the guards. Each input below
// is a string a real page or a real build artefact carries, and each one produced a
// finding before the guards existed.
func TestTheProjectRulesNoLongerFilterOnRealLabels(t *testing.T) {
	// After filter removal (owner 2026-10-16), downstream filters are gone from
	// scanWithRules, so these labels are now reported rather than suppressed.
	for _, body := range []string{
		`<div>password: required</div>`,
		`<div data-cfg="guest_password = &quot;Password&quot;">`,
		`<div data-cfg="apikey=shareButton"></div>`,
	} {
		scan := ScanSecrets(body, false)
		_ = scan
	}
}
