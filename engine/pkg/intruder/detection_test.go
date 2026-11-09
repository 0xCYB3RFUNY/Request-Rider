package intruder

import (
	"strings"
	"testing"
)

// The fixtures below are the shapes real CMS login pages answer with. They are
// modelled, not copied, and the same four shapes are then exercised against the
// raised containers by the live test — a unit test that only proves the unit
// works is exactly the "green and useless" case the project rules forbid.

const failedLoginBody = `<html><body><div id="login_error">Unknown username or incorrect password.</div>` +
	`<input name="log" value=""><input name="pwd" value=""><form id="loginform" action="/wp-login.php" method="post"></form>` +
	`<script nonce="a1b2c3d4e5f60718">var t=1712345678;</script></body></html>`

// wordpressSuccess answers what WordPress answers: a 302 away from the login
// form plus the session cookies that only a real session carries.
func wordpressSuccess() Sample {
	return Sample{
		Status:      302,
		Length:      0,
		Fingerprint: FingerprintBody("", nil),
		Location:    "http://127.0.0.1/wp-admin/",
		Cookies:     []string{"wordpress_test_cookie", "wordpress_logged_in_1"},
	}
}

// joomlaSuccess answers what Joomla answers: still 200, still a page, but a
// different one - larger, and with the admin toolbar on it.
func joomlaSuccess() Sample {
	body := strings.Repeat("x", 4360) + `<div class="navbar" id="navbar">Dashboard</div>`
	return Sample{
		Status:      200,
		Length:      len(body),
		Fingerprint: FingerprintBody(body, nil),
		Cookies:     []string{"joomla_user_state"},
	}
}

func failedLoginSample() Sample {
	return Sample{
		Status:      200,
		Length:      len(failedLoginBody),
		Fingerprint: FingerprintBody(failedLoginBody, nil),
		Cookies:     []string{"wordpress_test_cookie"},
	}
}

func defaultConfig() DetectionConfig {
	return DetectionConfig{Enabled: true, Signals: DefaultSignals()}
}

func TestCaptureBaselineUsesEverySample(t *testing.T) {
	// Three answers that differ in length and in fingerprint: a login page with
	// a rotating nonce. A baseline built from one sample would call the second
	// and third responses "different", which is the whole failure this guards.
	baseline := CaptureBaseline([]Sample{
		{Status: 200, Length: 3000, Fingerprint: "aaa", Cookies: []string{"test_cookie"}},
		{Status: 200, Length: 3100, Fingerprint: "bbb", Cookies: []string{"session_hint"}},
		{Status: 200, Length: 3050, Fingerprint: "aaa", Location: "", Cookies: nil},
	})
	if baseline.Status != 200 {
		t.Fatalf("status = %d, want 200", baseline.Status)
	}
	if baseline.MinLength != 3000 || baseline.MaxLength != 3100 {
		t.Fatalf("length band = [%d,%d], want [3000,3100]", baseline.MinLength, baseline.MaxLength)
	}
	if baseline.Samples != 3 {
		t.Fatalf("samples = %d, want 3", baseline.Samples)
	}
	if len(baseline.Fingerprints) != 2 {
		t.Fatalf("fingerprints = %v, want two distinct entries", baseline.Fingerprints)
	}
	// The union, not the first sample: a cookie handed out once is still a
	// cookie a failed login leaves behind.
	if len(baseline.CookieNames) != 2 {
		t.Fatalf("cookie names = %v, want the union of both samples", baseline.CookieNames)
	}
}

func TestCaptureBaselineWithoutSamplesIsHonest(t *testing.T) {
	baseline := CaptureBaseline(nil)
	if baseline.Samples != 0 {
		t.Fatalf("samples = %d, want 0 so callers can tell calibration failed", baseline.Samples)
	}
	// No baseline means no signal may claim a deviation: there is nothing to
	// deviate from.
	verdict := Evaluate(defaultConfig(), baseline, failedLoginSample(), failedLoginBody, nil)
	if len(verdict.Signals) != 0 {
		t.Fatalf("signals = %v, want none without a baseline", verdict.Signals)
	}
}

func TestFingerprintIgnoresABase64CSRFToken(t *testing.T) {
	// Django's `csrfmiddlewaretoken` is base64, not hexadecimal. The first mask
	// handled hex runs only, so the token was cut into a different skeleton on
	// every render and three samples of one page produced three fingerprints.
	// Measured on a live Django admin: every response then differed from all of
	// them and the body signal fired on the whole corpus.
	first := FingerprintBody(`<input name="csrfmiddlewaretoken" value="LivCzeqDTpUFYkLLAhsiPNggjuLKEoxTlOoDCmMfnBpdquwteQPHcVUq">`, nil)
	second := FingerprintBody(`<input name="csrfmiddlewaretoken" value="HxmAcSRWQjuoGgnqrRuWCFfXPEQtAwALVGSlgRUsAOoORuUDjQKCt">`, nil)
	if first != second {
		t.Fatalf("fingerprints differ for the same page with a new base64 token: %s vs %s", first, second)
	}
	// A token of a different length must collapse too, or the length signal fires
	// on every row of a run against a form that rotates its token length.
	longer := FingerprintBody(`<input name="csrfmiddlewaretoken" value="LivCzeqDTpUFYkLLAhsiPNggjuLKEoxTlOoDCmMfnBpdquwteQPHcVUqAndMoreCharactersHere">`, nil)
	if first != longer {
		t.Fatalf("fingerprints differ for the same page with a longer base64 token: %s vs %s", first, longer)
	}
}

func TestFingerprintKeepsRealPageDifferences(t *testing.T) {
	// The mask must not be so wide that it hides the difference the feature
	// exists to find: a different page is still a different page.
	failed := FingerprintBody(`<div id="login_error">Unknown username or incorrect password</div>`, nil)
	success := FingerprintBody(`<div id="wp-admin-bar">Howdy, administrator</div>`, nil)
	if failed == success {
		t.Fatal("two different login pages produced the same fingerprint")
	}
}

func TestFingerprintIgnoresNonceAndDigits(t *testing.T) {
	first := FingerprintBody(`<input name="csrf" value="a1b2c3d4e5f60718"><p>Error at 17:12:34 in 2026</p>`, nil)
	second := FingerprintBody(`<input name="csrf" value="9f8e7d6c5b4a3021"><p>Error at 09:41:02 in 2027</p>`, nil)
	if first != second {
		t.Fatalf("fingerprints differ for the same page with a new nonce: %s vs %s", first, second)
	}
	other := FingerprintBody(`<h1>Dashboard</h1><p>Welcome back</p>`, nil)
	if first == other {
		t.Fatal("a different page produced the same fingerprint")
	}
}

func TestFingerprintMasksInjectedPayload(t *testing.T) {
	// The login page echoes the submitted username back into the error text, so
	// without masking the payload every result would look different from the
	// baseline and the body signal would fire on the whole corpus.
	body := `<p>Unknown password for hunter2</p>`
	withPayload := FingerprintBody(body, []string{"hunter2"})
	plain := FingerprintBody(`<p>Unknown password for xxx</p>`, []string{"xxx"})
	if withPayload != plain {
		t.Fatalf("injected payload was not masked: %s vs %s", withPayload, plain)
	}
}

func TestEvaluateFlagsWordPressRedirect(t *testing.T) {
	baseline := CaptureBaseline([]Sample{failedLoginSample()})
	verdict := Evaluate(defaultConfig(), baseline, wordpressSuccess(), "", map[string]string{
		"Location":   "http://127.0.0.1/wp-admin/",
		"Set-Cookie": "wordpress_test_cookie=WP+Cookie; path=/, wordpress_logged_in_1=admin|1712345678; path=/",
	})
	if !verdict.Matched {
		t.Fatalf("a 302 with a session cookie was not flagged: %+v", verdict)
	}
	for _, want := range []string{SignalStatus, SignalRedirect, SignalCookie} {
		if !containsString(verdict.Signals, want) {
			t.Fatalf("signals %v missing %q", verdict.Signals, want)
		}
	}
}

func TestNormalizedBodyLengthIgnoresPayloadLength(t *testing.T) {
	// The measured trap: a login page echoes the submitted username, calibration
	// submits a 32-character token and a real job submits "admin", so the failed
	// answers differ by 27 raw bytes. Comparing raw sizes would flag every row.
	calibration := NormalizedBodyLength(`<p>Unknown password for a2d6f4d21bb646986ecdb4926815c142</p>`, []string{"a2d6f4d21bb646986ecdb4926815c142"})
	real := NormalizedBodyLength(`<p>Unknown password for admin</p>`, []string{"admin"})
	if calibration != real {
		t.Fatalf("normalized lengths differ for the same failed page: %d vs %d", calibration, real)
	}
	// A page that really is another page is still longer after masking.
	bigger := NormalizedBodyLength(`<p>Welcome back, admin</p>`+strings.Repeat("<p>row</p>", 20), []string{"admin"})
	if bigger <= real {
		t.Fatalf("masked length did not grow for a different page: %d vs %d", bigger, real)
	}
}

func TestEvaluateFlagsJoomlaLengthOnly(t *testing.T) {
	// The hard case the operator described: 200 for the failed login and 200
	// for the successful one, so nothing but the size and the body differ.
	baseline := CaptureBaseline([]Sample{failedLoginSample()})
	success := joomlaSuccess()
	verdict := Evaluate(defaultConfig(), baseline, success, strings.Repeat("x", 4360)+"Dashboard", map[string]string{})
	if !verdict.Matched {
		t.Fatalf("a larger 200 login page was not flagged: %+v", verdict)
	}
	if !containsString(verdict.Signals, SignalLength) {
		t.Fatalf("signals %v missing %q", verdict.Signals, SignalLength)
	}
	if verdict.Delta == 0 {
		t.Fatal("delta is zero although the body grew")
	}
}

func TestRulesDecideOverSignals(t *testing.T) {
	// WordPress answers 200 with two different failure pages: "Unknown username"
	// for a name that does not exist and "The password you entered is incorrect"
	// for a name that does. Both are failures, both differ in size from the
	// calibration page, so the baseline fires on every real username. A rule has
	// to be able to overrule that, or the run marks hundreds of wrong passwords
	// as successes.
	failedUnknownUser := Sample{Status: 200, Length: 3000, Fingerprint: "unknown-user"}
	failedWrongPassword := Sample{Status: 200, Length: 3210, Fingerprint: "wrong-password"}
	baseline := CaptureBaseline([]Sample{failedUnknownUser})

	config := defaultConfig()
	config.Rules = []Rule{{Type: RuleBodyContains, Value: "Dashboard"}}

	noise := Evaluate(config, baseline, failedWrongPassword, "The password you entered is incorrect", nil)
	if noise.Matched {
		t.Fatalf("a wrong password was marked as a match: %+v", noise)
	}
	if len(noise.Signals) == 0 {
		t.Fatal("the length deviation should still be reported even when a rule decided")
	}

	success := joomlaSuccess()
	hit := Evaluate(config, baseline, success, strings.Repeat("x", 4360)+"<div>Dashboard</div>", nil)
	if !hit.Matched {
		t.Fatalf("the configured rule did not mark the successful login: %+v", hit)
	}
	if len(hit.Reasons) == 0 || !strings.Contains(hit.Reasons[0], RuleBodyContains) {
		t.Fatalf("reasons = %v, want the rule named", hit.Reasons)
	}
}

func TestToleranceKeepsNoiseOutOfTheSignal(t *testing.T) {
	// A login page that echoes the submitted username back into its error text
	// changes size by the length of every payload, so an exact byte comparison
	// would mark the whole corpus. Tolerance is the operator's noise floor and
	// its zero is an honest zero: it means "any byte counts", which is a real
	// choice for a page that does not echo anything.
	baseline := CaptureBaseline([]Sample{failedLoginSample()})
	near := failedLoginSample()
	near.Length += 12

	exact := DetectionConfig{Enabled: true, Signals: DefaultSignals()}
	if !Evaluate(exact, baseline, near, failedLoginBody, nil).Matched {
		t.Fatal("a 12-byte difference must be flagged when tolerance is exactly zero")
	}

	tolerant := DetectionConfig{Enabled: true, Signals: DefaultSignals(), Tolerance: 32}
	if containsString(Evaluate(tolerant, baseline, near, failedLoginBody, nil).Signals, SignalLength) {
		t.Fatal("tolerance 32 ignored a 12-byte difference")
	}
	far := failedLoginSample()
	far.Length += 64
	if !containsString(Evaluate(tolerant, baseline, far, "", nil).Signals, SignalLength) {
		t.Fatal("tolerance 32 swallowed a 64-byte difference")
	}
}

func TestDisabledSignalsDoNotFire(t *testing.T) {
	baseline := CaptureBaseline([]Sample{failedLoginSample()})
	config := DetectionConfig{Enabled: true, Signals: []string{SignalLength}}
	verdict := Evaluate(config, baseline, wordpressSuccess(), "", nil)
	if containsString(verdict.Signals, SignalStatus) {
		t.Fatalf("status fired although only %v is enabled: %v", config.Signals, verdict.Signals)
	}
	// The successful answer is still visible as a deviation of size.
	if !verdict.Matched {
		t.Fatal("a redirected login should still be flagged by the enabled signal set")
	}
}

func TestBodySignalIgnoresKnownFingerprint(t *testing.T) {
	body := strings.Replace(failedLoginBody, "a1b2c3d4e5f60718", "ffffffffffffffff", 1)
	sample := Sample{Status: 200, Length: len(body), Fingerprint: FingerprintBody(body, nil)}
	baseline := CaptureBaseline([]Sample{sample})
	signals := Evaluate(defaultConfig(), baseline, sample, body, nil).Signals
	if containsString(signals, SignalBody) {
		t.Fatalf("body signal fired for a fingerprint the baseline already holds: %v", signals)
	}
}

func TestBodySignalFiresOnADifferentPage(t *testing.T) {
	baseline := CaptureBaseline([]Sample{failedLoginSample()})
	// Same status, same length, different page: the length signal is silent and
	// the body signal is the only one left, which is why it needs a test of its
	// own rather than riding on the Joomla case.
	success := Sample{Status: 200, Length: len(failedLoginBody), Fingerprint: FingerprintBody("a dashboard nobody asked for", nil)}
	signals := Evaluate(defaultConfig(), baseline, success, "a dashboard nobody asked for", nil).Signals
	if !containsString(signals, SignalBody) {
		t.Fatalf("body signal did not fire for a page the baseline never showed: %v", signals)
	}
}

func TestCookieSignalStaysQuietOnAFailedLogin(t *testing.T) {
	// The target hands out its test cookie before any credential is checked, so
	// a failed login carries a cookie too. Flagging that would mark every row.
	baseline := CaptureBaseline([]Sample{failedLoginSample()})
	signals := Evaluate(defaultConfig(), baseline, failedLoginSample(), failedLoginBody, nil).Signals
	if containsString(signals, SignalCookie) {
		t.Fatalf("cookie signal fired for a cookie the baseline already had: %v", signals)
	}
}

func TestRuleMatching(t *testing.T) {
	sample := Sample{Status: 302}
	headers := map[string]string{"Location": "http://127.0.0.1/wp-admin/"}
	cases := []struct {
		name string
		rule Rule
		want bool
	}{
		{"status equals", Rule{Type: RuleStatusEquals, Value: "302"}, true},
		{"status not equal", Rule{Type: RuleStatusEquals, Value: "200"}, false},
		{"status not a number", Rule{Type: RuleStatusEquals, Value: "abc"}, false},
		{"body contains literal", Rule{Type: RuleBodyContains, Value: "admin panel"}, true},
		{"body contains regex", Rule{Type: RuleBodyContains, Value: `admin\s+panel`, Regex: true}, true},
		{"body contains broken regex", Rule{Type: RuleBodyContains, Value: `panel-(`, Regex: true}, false},
		{"body contains empty value", Rule{Type: RuleBodyContains, Value: ""}, false},
		{"body not contains", Rule{Type: RuleBodyNotContains, Value: "invalid"}, true},
		{"body not contains when present", Rule{Type: RuleBodyNotContains, Value: "panel"}, false},
		{"header name case insensitive", Rule{Type: RuleHeaderContains, Name: "location", Value: "/wp-admin/"}, true},
		{"header value wrong", Rule{Type: RuleHeaderContains, Name: "Location", Value: "/login"}, false},
		{"header missing", Rule{Type: RuleHeaderContains, Name: "Set-Cookie", Value: "logged_in"}, false},
		{"unknown type", Rule{Type: "totally_made_up", Value: "x"}, false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			reasons := matchRules([]Rule{item.rule}, sample, "welcome to the admin panel", headers)
			if item.want != (len(reasons) > 0) {
				t.Fatalf("rule %+v fired = %v, want %v (reasons %v)", item.rule, len(reasons) > 0, item.want, reasons)
			}
		})
	}
}

func TestRuleReasonNamesTheHeader(t *testing.T) {
	reason := ruleReason(Rule{Type: RuleHeaderContains, Name: "Location", Value: "/wp-admin/"})
	if !strings.Contains(reason, "Location") || !strings.Contains(reason, "/wp-admin/") {
		t.Fatalf("reason %q must name both the header and the value", reason)
	}
}

func TestUseSignalsDropsUnknownNames(t *testing.T) {
	config := DetectionConfig{Signals: []string{"status", "made_up", "*"}}
	signals := config.UseSignals()
	if len(signals) != 1 || signals[0] != SignalStatus {
		t.Fatalf("signals = %v, want only the known name", signals)
	}
	// An empty field means "the documented default", not "nothing", so a stored
	// attack from before this feature still compares something.
	if len(DetectionConfig{}.UseSignals()) != len(DefaultSignals()) {
		t.Fatal("an empty signal field must fall back to the default set")
	}
}

func TestCalibrationAndToleranceClamp(t *testing.T) {
	config := DetectionConfig{}
	if config.CalibrationRequests() != DefaultCalibrationRequests {
		t.Fatalf("calibration = %d, want the documented default", config.CalibrationRequests())
	}
	config.Calibration = 5
	if config.CalibrationRequests() != 5 {
		t.Fatalf("calibration = %d, want the operator's value", config.CalibrationRequests())
	}
	config.Tolerance = -10
	if config.ToleranceBytes() != 0 {
		t.Fatalf("tolerance = %d, want a negative value clamped to 0", config.ToleranceBytes())
	}
}
