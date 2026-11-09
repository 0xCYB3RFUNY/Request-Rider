package enrich

import (
	"strings"
	"testing"
)

const csrfFixture = `<!doctype html><html><body>
<form action="/login" method="post">
  <input type="hidden" name="csrfmiddlewaretoken" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0">
  <input name="user" value="">
  <button type="submit">Sign in</button>
</form>

<form action="/account/delete" method="POST">
  <input name="confirm" value="1">
  <input type="submit" value="Delete">
</form>

<form action="/search" method="get">
  <input name="q" value="">
</form>

<form action="/profile" method="post">
  <input name="csrf" value="1234567890">
  <input name="bio" value="">
</form>

<form action="/transfer" method="post">
  <input name="_token" value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">
  <input name="amount" value="1">
</form>
</body></html>`

func TestCSRFAssessClassifiesEveryStateChangingForm(t *testing.T) {
	report := CSRFAssess(csrfFixture, false)
	if report.Forms != 5 {
		t.Fatalf("expected 5 forms, got %d", report.Forms)
	}
	byForm := map[string]CSRFIssue{}
	for _, issue := range report.Issues {
		byForm[issue.Form] = issue
	}
	if got := byForm["/login"]; got.Kind != CSRFTokenPresent {
		t.Errorf("/login has a 32-hex token: want token_present, got %s (%s)", got.Kind, got.Reason)
	}
	if got := byForm["/account/delete"]; got.Kind != CSRFInsecure {
		t.Errorf("/account/delete posts with no token: want insecure, got %s (%s)", got.Kind, got.Reason)
	}
	if _, present := byForm["/search"]; present {
		t.Error("a GET form must not be judged: it changes no state")
	}
	if got := byForm["/profile"]; got.Kind != CSRFWeakToken {
		t.Errorf("/profile has a 10-digit token: want weak_token, got %s (%s)", got.Kind, got.Reason)
	}
	if got := byForm["/transfer"]; got.Kind != CSRFWeakToken {
		t.Errorf("/transfer has a static SHA-256 digest: want weak_token, got %s (%s)", got.Kind, got.Reason)
	}
}

// TestCSRFRejectsTheEmptySHA256 is a real false positive caught by the fixture:
// the SHA-256 of the empty string is a constant that appears in thousands of
// projects, and it satisfies every length rule.
func TestCSRFRejectsTheEmptySHA256(t *testing.T) {
	verdict := JudgeToken("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if len(verdict.Weak) == 0 {
		t.Fatal("the empty-string SHA-256 must be judged weak")
	}
	found := false
	for _, reason := range verdict.Weak {
		if strings.Contains(reason, "empty string") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the known-constant reason, got %v", verdict.Weak)
	}
}

func TestCSRFEntropyBeatsLength(t *testing.T) {
	// 32 characters of one repeated letter: long, low entropy, one class.
	verdict := JudgeToken("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if verdict.ShannonEntropy >= 2.5 {
		t.Fatalf("entropy of a repeated character must be 0, got %f", verdict.ShannonEntropy)
	}
	reasons := strings.Join(verdict.Weak, "|")
	if !strings.Contains(reasons, "entropy") || !strings.Contains(reasons, "character class") {
		t.Fatalf("expected entropy and character-class reasons, got %v", verdict.Weak)
	}
	strong := JudgeToken("9f8e7d6c5b4a39281706f5e4d3c2b1a0")
	if len(strong.Weak) != 0 {
		t.Errorf("a 32-hex random token must not be judged weak, got %+v", strong)
	}
}

func TestCSRFSameSiteOnlyIsNotReportedAsSecure(t *testing.T) {
	report := CSRFAssess(`<form action="/x" method="post"><input name="a" value="1"></form>`, true)
	if len(report.Issues) != 1 || report.Issues[0].Kind != CSRFSameSiteOnly {
		t.Fatalf("cookie-only protection must be named, got %+v", report.Issues)
	}
}

func TestCSRFNoFormIsDistinctFromClean(t *testing.T) {
	report := CSRFAssess(`<html><body><p>nothing here</p></body></html>`, false)
	if len(report.Issues) != 1 || report.Issues[0].Kind != CSRFNoForm {
		t.Fatalf("expected no_form, got %+v", report.Issues)
	}
}

// TestCSRFInputsDoNotLeakAcrossForms: an unclosed form followed by another one
// must not inherit the first form's fields. This is the defect that a nested
// full-document scan per form produced.
func TestCSRFInputsDoNotLeakAcrossForms(t *testing.T) {
	body := `<form action="/a" method="post"><input name="csrf" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0"></form>
	         <form action="/b" method="post"><input name="x" value="1"></form>`
	report := CSRFAssess(body, false)
	if len(report.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %+v", report.Issues)
	}
	for _, issue := range report.Issues {
		if issue.Form == "/b" && issue.Kind != CSRFInsecure {
			t.Fatalf("form /b must be insecure on its own, got %s (%+v)", issue.Kind, issue)
		}
	}
}

func TestCSRFUnclosedFormIsClosedAtTheNextOne(t *testing.T) {
	body := `<form action="/a" method="post"><input name="csrf" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0">
	         <form action="/b" method="post"><input name="x" value="1">`
	report := CSRFAssess(body, false)
	kinds := map[string]CSRFKind{}
	for _, i := range report.Issues {
		kinds[i.Form] = i.Kind
	}
	if kinds["/a"] != CSRFTokenPresent {
		t.Errorf("unclosed form /a lost its token: %+v", report.Issues)
	}
	if kinds["/b"] != CSRFInsecure {
		t.Errorf("form /b must not inherit /a's fields: %+v", report.Issues)
	}
}

func TestCSRFTokenFieldsAreRecognisedByLibraryName(t *testing.T) {
	for _, field := range []string{
		"csrfmiddlewaretoken", "authenticity_token", "requestverificationtoken",
		"__requesttoken", "antiforgerytoken", "_token", "xsrf", "csrf",
	} {
		body := `<form action="/x" method="post"><input name="` + field +
			`" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0"></form>`
		report := CSRFAssess(body, false)
		if len(report.Issues) != 1 || report.Issues[0].Kind != CSRFTokenPresent {
			t.Errorf("field %q not recognised: %+v", field, report.Issues)
		}
	}
}

func TestReusedTokenIsReportedOnce(t *testing.T) {
	body := `<form action="/a" method="post"><input name="csrf" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0"></form>
	         <form action="/b" method="post"><input name="csrf" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0"></form>`
	report := CSRFAssess(body, false)
	if len(report.Reused) != 1 {
		t.Fatalf("one token on two forms must be reported once, got %+v", report.Reused)
	}
	if len(report.Reused[0].Forms) != 2 {
		t.Fatalf("reuse must name both forms, got %+v", report.Reused[0])
	}
	if strings.Contains(report.Reused[0].Value, "9f8e7d6c5b4a39281706f5e4d3c2b1a0") {
		t.Errorf("a reused token must be masked in a report, got %q", report.Reused[0].Value)
	}
}

func TestMaskTokenKeepsItIdentifiableNotReadable(t *testing.T) {
	full := "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
	masked := maskToken(full)
	if strings.Contains(masked, full) {
		t.Fatalf("token not masked: %q", masked)
	}
	if !strings.HasPrefix(masked, "9f8e") {
		t.Errorf("masked token must stay identifiable, got %q", masked)
	}
	if got := maskToken("ab"); got != "**" {
		t.Errorf("short values must be fully masked, got %q", got)
	}
}

func TestDetectTokenHash(t *testing.T) {
	cases := map[string]string{
		"0123456789abcdef0123456789abcdef":                                 "md5",
		"0123456789abcdef0123456789abcdef01234567":                         "sha1",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "sha256",
		"not-hex-at-all-but-long-enough-to-be-something":                   "",
	}
	for value, want := range cases {
		if got := detectTokenHash(value); got != want {
			t.Errorf("detectTokenHash(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestSubmitWithoutValueIsNotAToken(t *testing.T) {
	body := `<form action="/x" method="post"><input type="submit" name="submit" value="Send"></form>`
	report := CSRFAssess(body, false)
	if report.Issues[0].Kind != CSRFInsecure {
		t.Fatalf("a submit button must not be mistaken for a token: %+v", report.Issues[0])
	}
}
