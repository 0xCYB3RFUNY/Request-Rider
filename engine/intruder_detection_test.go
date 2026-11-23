package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"intruder/engine/pkg/intruder"
)

// These tests drive the wiring the browser actually reaches: a real HTTP login
// form that answers 200 for both a wrong and a right credential, calibration
// against it, and the verdict that reaches the table. A unit test of the pure
// comparison would stay green even if the engine never calibrated anything, and
// the calibration is the half that decides whether the feature works at all.

func loginRequestInput(target string) requestInput {
	return requestInput{
		Method:  http.MethodPost,
		URL:     target + "/login",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    "user=§user§&pass=§pass§",
	}
}

func TestCalibrationAndVerdictAgainstALiveLoginForm(t *testing.T) {
	// Keep the per-exchange source-IP courtesy lookup from dominating the test:
	// it is a real outbound request to a metadata endpoint that has nothing to do
	// with login detection.
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "50")

	target := httptest.NewServer(newFakeLoginTarget())
	defer target.Close()

	srv := &server{}
	config := normalizedDetectionConfig(&intruder.DetectionConfig{Enabled: true})
	baselines := srv.calibrateLoginBaselines(context.Background(), loginRequestInput(target.URL), *config, nil, []string{"11"}, 1)
	baseline := baselines["11"]
	if baseline.Samples == 0 {
		t.Fatal("calibration captured no sample from a reachable login form")
	}
	if baseline.Status != http.StatusOK {
		t.Fatalf("baseline status = %d, want 200: the failed login answers 200 too", baseline.Status)
	}
	if len(baseline.Lengths) != intruder.DefaultCalibrationRequests {
		t.Fatalf("calibration took %d samples, want %d", len(baseline.Lengths), intruder.DefaultCalibrationRequests)
	}
	// The test target varies its nonce and its echoed username is the generated
	// calibration token, so a single-sample baseline would report a different
	// length on every answer. Several samples is what makes this stable.
	if baseline.MinLength != baseline.MaxLength {
		t.Fatalf("length band [%d,%d] drifted for one unchanged page", baseline.MinLength, baseline.MaxLength)
	}

	run := &attack{detection: config, baselines: map[string]intruder.Baseline{"11": baseline}}
	base := loginRequestInput(target.URL)

	// Both exchanges go through the engine's own execution path with the same
	// marker replacement the runner uses. Hand-writing a result map instead would
	// let the fixture drift from what a real exchange contains - and it did: the
	// first version of this test echoed a username the request never sent, and
	// the body signal correctly reported the mismatch.
	wrong := loginExchange(t, srv, base, "admin", "wrong-password")
	srv.evaluateIntruderResult(run, *config, wrong, []string{"admin", "wrong-password"})
	if matched, _ := wrong["detection"].(map[string]interface{}); matched["matched"] != false {
		t.Fatalf("a wrong password was flagged: %v", wrong["detection"])
	}

	right := loginExchange(t, srv, base, "admin", adminPassword)
	srv.evaluateIntruderResult(run, *config, right, []string{"admin", adminPassword})

	if matched := run.matched; matched != 1 {
		t.Fatalf("run reports %d matches, want exactly 1: the wrong password must not be flagged", matched)
	}
	if run.evaluated != 2 {
		t.Fatalf("evaluated = %d, want 2", run.evaluated)
	}
	verdict, ok := right["detection"].(map[string]interface{})
	if !ok || verdict["matched"] != true {
		t.Fatalf("successful login verdict = %v, want matched", right["detection"])
	}
	signals, _ := verdict["signals"].([]string)
	if len(signals) == 0 {
		t.Fatalf("successful login carries no signal name: %v", verdict)
	}
}

// loginExchange performs one generated request exactly the way the Intruder
// runner does and returns the engine result map.
func loginExchange(t *testing.T, srv *server, base requestInput, user, pass string) map[string]interface{} {
	t.Helper()
	req := cloneRequest(base)
	values := []string{user, pass}
	position := 0
	req.URL, position = intruder.ReplaceAt(req.URL, values, position)
	for _, key := range sortedHeaderKeys(req.Headers) {
		req.Headers[key], position = intruder.ReplaceAt(req.Headers[key], values, position)
	}
	req.Body, _ = intruder.ReplaceAt(req.Body, values, position)
	result, err := srv.executeContext(context.Background(), req)
	if err != nil {
		t.Fatalf("execute %s/%s: %v", user, pass, err)
	}
	return result
}

func TestVerdictRulesOverruleBaselineNoise(t *testing.T) {
	// The case that makes rules necessary rather than decorative: a target that
	// answers 200 with one page for an unknown username and a different page for
	// a wrong password. The baseline only knows the first, so the length signal
	// fires on every real username. With a rule written, the verdict follows the
	// rule and the wrong password is not reported as a success.
	run := &attack{}
	config := normalizedDetectionConfig(&intruder.DetectionConfig{
		Enabled: true,
		Rules:   []intruder.Rule{{Type: intruder.RuleBodyContains, Value: "Welcome back"}},
	})
	wrong := map[string]interface{}{
		"status":  200,
		"size":    3210,
		"body":    "The password you entered is incorrect",
		"headers": map[string]string{},
	}
	run.baselines = map[string]intruder.Baseline{"11": intruder.CaptureBaseline([]intruder.Sample{{Status: 200, Length: 3210, Fingerprint: "wrong-password"}})}
	srv := &server{}
	srv.evaluateIntruderResult(run, *config, wrong, []string{"admin", "wrong"})
	if run.matched != 0 {
		t.Fatalf("a wrong password was flagged as a match with rules present: %v", wrong["detection"])
	}
	right := map[string]interface{}{
		"status":  200,
		"size":    4500,
		"body":    "Welcome back admin",
		"headers": map[string]string{},
	}
	srv.evaluateIntruderResult(run, *config, right, []string{"admin", adminPassword})
	if run.matched != 1 {
		t.Fatalf("the configured rule did not flag the successful login: %v", right["detection"])
	}
}

func TestNormalizedDetectionConfigResolvesDefaults(t *testing.T) {
	normalized := normalizedDetectionConfig(&intruder.DetectionConfig{
		Enabled:     true,
		Signals:     []string{"length", "not_a_signal"},
		Tolerance:   -5,
		Calibration: 0,
	})
	if len(normalized.Signals) != 1 || normalized.Signals[0] != intruder.SignalLength {
		t.Fatalf("signals = %v, want only the known name", normalized.Signals)
	}
	if normalized.Tolerance != 0 {
		t.Fatalf("tolerance = %d, want a negative value clamped to 0", normalized.Tolerance)
	}
	if normalized.Calibration != intruder.DefaultCalibrationRequests {
		t.Fatalf("calibration = %d, want the documented default", normalized.Calibration)
	}
}

func TestBuildDetectionSampleReadsTheResponse(t *testing.T) {
	result := map[string]interface{}{
		"status": 302,
		"size":   0,
		"headers": map[string]string{
			"Location":   "/wp-admin/",
			"Set-Cookie": "wordpress_test_cookie=WP+Cookie; path=/, wordpress_logged_in_1=admin|1712345678; path=/, PHPSESSID=deadbeef; path=/",
		},
	}
	sample := buildDetectionSample(result, nil)
	if sample.Status != 302 || sample.Location != "/wp-admin/" {
		t.Fatalf("sample = %+v, want status 302 and the admin redirect", sample)
	}
	// Cookie values are dropped: a session id changes on every login, so
	// comparing values would flag the target's own housekeeping as a difference.
	want := []string{"wordpress_test_cookie", "wordpress_logged_in_1", "PHPSESSID"}
	if len(sample.Cookies) != len(want) {
		t.Fatalf("cookies = %v, want %v", sample.Cookies, want)
	}
	for index, name := range want {
		if sample.Cookies[index] != name {
			t.Fatalf("cookies = %v, want %v", sample.Cookies, want)
		}
	}
}

func TestBuildDetectionSampleMarksTransportFailures(t *testing.T) {
	sample := buildDetectionSample(map[string]interface{}{"error": "connection refused"}, nil)
	if sample.Status != 0 {
		t.Fatalf("status = %d, want 0 so a network error is not read as a different login page", sample.Status)
	}
}

func TestDetectionSummaryReportsWhatDecided(t *testing.T) {
	off := detectionSummary(nil, nil, 0, 0)
	if off["enabled"] != false {
		t.Fatalf("summary without a config = %v, want disabled", off)
	}
	config := normalizedDetectionConfig(&intruder.DetectionConfig{Enabled: true})
	empty := detectionSummary(config, map[string]intruder.Baseline{}, 0, 0)
	if empty["warning"] != "calibration_unavailable" {
		t.Fatalf("summary without a baseline = %v, want an honest warning", empty)
	}
	if empty["decides"] != "signals" {
		t.Fatalf("decides = %v, want signals when the operator wrote no rules", empty["decides"])
	}
	withRules := normalizedDetectionConfig(&intruder.DetectionConfig{
		Enabled: true,
		Rules:   []intruder.Rule{{Type: intruder.RuleBodyContains, Value: "Dashboard"}},
	})
	summary := detectionSummary(withRules, map[string]intruder.Baseline{"11": intruder.CaptureBaseline([]intruder.Sample{{Status: 200, Length: 10}})}, 3, 7)
	if summary["decides"] != "rules" || summary["matched"] != 3 || summary["checked"] != 7 {
		t.Fatalf("summary = %v, want rules deciding with the counted matches", summary)
	}
	if summary["rules"] != 1 {
		t.Fatalf("rules = %v, want the rule count", summary["rules"])
	}
}

func TestDetectionVerdictJSONOmitsEmptyFields(t *testing.T) {
	empty := detectionVerdictJSON(intruder.Verdict{})
	if len(empty) != 1 || empty["matched"] != false {
		t.Fatalf("empty verdict = %v, want only matched=false", empty)
	}
	full := detectionVerdictJSON(intruder.Verdict{Matched: true, Signals: []string{"length"}, Reasons: []string{"length"}, Delta: -58})
	if full["delta"] != -58 {
		t.Fatalf("delta = %v, want -58 preserved with its sign", full["delta"])
	}
}

func TestCalibrationTokenIsNotARealCredential(t *testing.T) {
	first, err := calibrationToken()
	if err != nil {
		t.Fatalf("calibrationToken: %v", err)
	}
	second, err := calibrationToken()
	if err != nil {
		t.Fatalf("calibrationToken: %v", err)
	}
	if first == second {
		t.Fatal("two calibration tokens are equal, so the baseline is predictable")
	}
	if len(first) != 32 {
		t.Fatalf("token length = %d, want 32", len(first))
	}
	if _, convErr := hex.DecodeString(first); convErr != nil {
		t.Fatalf("token %q is not hexadecimal: %v", first, convErr)
	}
}
