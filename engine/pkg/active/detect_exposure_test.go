package active

// Tests for the credential exposure detector.
//
// The decisive test is TestExposureDoesNotPromoteOnOrdinaryEnglishWords. The
// upstream detector treats the bare words "private", "secret" and "internal" as
// evidence that a replayed token was accepted, so a login page whose footer says
// "private" turns a public site key into a verified critical finding — which is
// the exact regression its own CHANGELOG claims to have fixed.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// exposureFixture serves one URL and can behave differently when a credential is
// presented.
type exposureFixture struct {
	anonymous func() (int, string)
	// authenticated answers a request carrying an Authorization header.
	authenticated func(token string) (int, string)
	mu            sync.Mutex
	authTokens    []string
}

func newExposureFixture(t *testing.T, f *exposureFixture) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			status, text := f.anonymous()
			w.WriteHeader(status)
			_, _ = io.WriteString(w, text)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		f.mu.Lock()
		f.authTokens = append(f.authTokens, token)
		f.mu.Unlock()
		status, text := f.authenticated(token)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"1"}},
	}
}

func (Exposure) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return Exposure{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

func jsons(token string) (int, string) {
	return 200, `{"user":"ops","role":"admin","permissions":["write"],"api_key":"` + token + `"}`
}

// The decisive false-positive case. The page contains the word "private" in
// ordinary prose, the value is a public site key, and the server answers
// identically whether or not a credential is presented. Nothing is privileged;
// the upstream signal list would have called this a verified critical.
func TestExposureDoesNotPromoteOnOrdinaryEnglishWords(t *testing.T) {
	token := "pk_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
	page := `<html><body>
		<p>This is a private page, please keep the details secret.</p>
		<p>Internal tools are available to staff.</p>
		<script>var websiteToken = "` + token + `";</script>
	</body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	for _, finding := range findings {
		if finding.Tier == TierVerified {
			t.Fatalf("promoted %q to verified on the strength of an English word; evidence %q",
				finding.Title, finding.Evidence)
		}
		if finding.Severity.Rank() > SeverityMedium.Rank() {
			t.Fatalf("severity %q exceeds medium for an unproven credential", finding.Severity)
		}
	}
}

// A site key is public by design. It is reported — at informational, with the
// reason — rather than dropped, so the operator sees it and can disagree.
func TestExposureReportsPublicByDesignAtInfo(t *testing.T) {
	// The value matches a real pattern and the *name* it is assigned to is the
	// public one. That pairing is the case the rule exists for: a credential
	// pattern under a name the platform publishes is a site key, and a site
	// key reported as critical is the regression the tier prevents.
	token := "sk_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
	page := `<html><body><script>var config = {"websiteToken":"` + token + `"};</script></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	var public *Finding
	for i := range findings {
		if findings[i].Tier == TierPublic {
			public = &findings[i]
		}
	}
	if public == nil {
		t.Fatalf("findings = %d, want a public-by-design row", len(findings))
	}
	if public.Severity != SeverityInfo {
		t.Errorf("severity = %q, want info", public.Severity)
	}
	// The capped flag is not asserted here on purpose: it means a severity was
	// *lowered*, and this row was authored at informational rather than reduced
	// to it. A public-by-design value that arrived claiming high would be capped;
	// one that arrives claiming info never was.
	if public.ClaimedTooHigh() {
		t.Error("row reports a severity above what its tier allows")
	}
	if !strings.Contains(public.Evidence, "by design") {
		t.Errorf("evidence = %q, want the reason stated", public.Evidence)
	}
}

// A placeholder is not a credential. It is reported as its own row so the
// coverage is visible and the operator can see the pattern was checked, but it
// is never counted as a finding.
//
// The value is long enough to match the generic assignment pattern, so what is
// under test is the classification rather than the pattern.
func TestExposureReportsPlaceholdersSeparately(t *testing.T) {
	filler := "your-api-key-here-please-change-it-now"
	// Quoted, because the generic assignment pattern requires them; a value
	// without them is not a match at all, which would test the pattern rather
	// than the classification.
	page := `<html><body><p>API_KEY="` + filler + `"</p></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	var placeholder *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Placeholder") {
			placeholder = &findings[i]
		}
	}
	if placeholder == nil {
		t.Fatalf("findings = %d (%s), want a placeholder row", len(findings), titlesOf(findings))
	}
	if placeholder.Severity != SeverityInfo {
		t.Errorf("severity = %q, want info for filler", placeholder.Severity)
	}
	if !strings.Contains(placeholder.Evidence, "placeholder") {
		t.Errorf("evidence = %q, want the reason stated", placeholder.Evidence)
	}
}

// titlesOf renders findings for an assertion message.
func titlesOf(findings []Finding) string {
	var out []string
	for _, finding := range findings {
		out = append(out, finding.Title)
	}
	return strings.Join(out, " | ")
}

// A credential that the server accepts, shown structurally, is verified. This is
// the positive case of the same distinction.
func TestExposureVerifiesAReplayedCredential(t *testing.T) {
	token := "sk_live_abcdefghijklmnopqrstuvwx"
	// The credential is on the page — that is how it is found at all — and the
	// replay of it is what returns something an anonymous request does not get.
	leaked := `<html><body><script>var cfg = {"apiKey":"` + token + `"};</script></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, leaked },
		authenticated: func(string) (int, string) { return jsons(token) },
	})
	findings := (Exposure{}).probe(t, transport, point)
	var verified *Finding
	for i := range findings {
		if findings[i].Tier == TierVerified {
			verified = &findings[i]
		}
	}
	if verified == nil {
		t.Fatalf("findings = %d, want a verified exposure for an accepted credential", len(findings))
	}
	if !strings.Contains(verified.Evidence, "replayed") {
		t.Errorf("evidence = %q, want the replay stated", verified.Evidence)
	}
	if !strings.Contains(verified.Evidence, "divergence") {
		t.Errorf("evidence = %q, want the measured difference quoted", verified.Evidence)
	}
}

// A 5xx on the authenticated request says nothing about the token. The server
// failed for its own reasons, and a detector that credits the token for it will
// report a critical finding on a service that is simply down.
func TestExposureDoesNotVerifyOnAServerError(t *testing.T) {
	leaked := `<html><body><script>var cfg = {"apiKey":"sk_live_abcdefghijklmnopqrstuvwx"};</script></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, leaked },
		authenticated: func(string) (int, string) { return 500, `{"role":"admin"}` },
	})
	findings := (Exposure{}).probe(t, transport, point)
	for _, finding := range findings {
		if finding.Tier == TierVerified {
			t.Fatalf("verified a credential because the server returned 5xx: %q", finding.Title)
		}
	}
}

// Same status, essentially the same page: the server ignored the token, and a
// page that happens to contain the word "admin" in prose is not proof.
func TestExposureDoesNotVerifyWhenTheAnswerIsEssentiallyTheSame(t *testing.T) {
	page := `<html><body><p>admin panel: ask your administrator for access</p></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	for _, finding := range findings {
		if finding.Tier == TierVerified {
			t.Fatalf("verified on an essentially identical response; evidence %q", finding.Evidence)
		}
	}
}

// A private key block cannot be replayed, so it never rises above potential no
// matter what the page around it says. Replaying a private key proves nothing
// about whether the file it came from was readable.
func TestExposureNeverVerifiesAReplaylessCategory(t *testing.T) {
	key := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890
-----END RSA PRIVATE KEY-----`
	page := `<html><body><pre>` + key + `</pre><p>"role":"admin","permissions":["all"]</p></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	var key_ *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Private Key") {
			key_ = &findings[i]
		}
	}
	if key_ == nil {
		t.Fatalf("findings = %d, want the private key reported", len(findings))
	}
	if key_.Tier == TierVerified {
		t.Error("a private key block was marked verified; no replay could prove anything about it")
	}
	if key_.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, want at most medium for an unproven credential", key_.Severity)
	}
}

// The baseline is the same page as the response, and this detector sends no
// injection. A freshness check applied here would suppress every finding the
// detector exists to produce — the test states that, because the rule belongs to
// the detectors that inject and applying it broadly is an easy mistake.
func TestExposureReportsFromAPageItNeverInjected(t *testing.T) {
	token := "sk_live_abcdefghijklmnopqrstuvwx"
	page := `<html><body><p>key: ` + token + `</p></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	found := false
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Stripe") {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %s, want the credential reported from an uninjected page", titlesOf(findings))
	}
}

// The value in a report must not be usable. A report gets pasted into a bug, a
// chat, a ticket, and a reader there is not the person who ran the scan.
func TestExposureRedactsCredentialValues(t *testing.T) {
	token := "sk_live_abcdefghijklmnopqrstuvwx"
	page := `<html><body><p>key: ` + token + `</p></body></html>`
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, page },
		authenticated: func(string) (int, string) { return 200, page },
	})
	findings := (Exposure{}).probe(t, transport, point)
	if len(findings) == 0 {
		t.Fatal("no findings; the redaction test needs a row to inspect")
	}
	for _, finding := range findings {
		for _, field := range []string{finding.Payload, finding.Evidence, finding.Description} {
			if strings.Contains(field, token) {
				t.Fatalf("the full credential appears in %q", field)
			}
		}
	}
	if redact(token) == token {
		t.Fatal("redact returned the value unchanged")
	}
	// A short value is left alone: redacting half of a five-character string
	// leaves something that identifies nothing.
	if redact("short") != "short" {
		t.Error("redact mangled a value too short to identify")
	}
}

// privilegedStructure is the whole contract, asserted directly.
func TestPrivilegedStructureRequiresStructure(t *testing.T) {
	prose := `<html><body><p>This page is private. The secret is not so secret. Internal use only. ` +
		`Visit admin or contact your administrator.</p></body></html>`
	if privilegedStructure(body(prose), "tok") {
		t.Error("ordinary English prose was accepted as evidence of privilege")
	}
	structural := `{"user":"ops","role":"admin"}`
	if !privilegedStructure(body(structural), "tok") {
		t.Error("a JSON privilege key at a value position was not accepted")
	}
	// A quoted word with no colon after it is prose, not structure.
	if privilegedStructure(body(`<p>the "admin" panel</p>`), "tok") {
		t.Error("a quoted word without a value was accepted")
	}
	if privilegedStructure(nil, "tok") {
		t.Error("accepted with no response")
	}
}

func TestVerifyReplayedNeedsBothHalves(t *testing.T) {
	anonymous := body(`<html><body>Not signed in.</body></html>`)
	if verifyReplayed(nil, anonymous, "tok") {
		t.Error("accepted with no anonymous baseline")
	}
	if verifyReplayed(anonymous, nil, "tok") {
		t.Error("accepted with no authenticated response")
	}
}

// Every pattern needs a capture group, because the value being reported is what
// group one matched. A pattern without one reports an empty credential and looks
// like a detection that found nothing.
func TestExposurePatternsCaptureAValue(t *testing.T) {
	for _, category := range secretCategories {
		sample := sampleFor(category.name)
		if sample == "" {
			t.Errorf("no sample value defined for %q, so its pattern is untested", category.name)
			continue
		}
		match := category.pattern.FindStringSubmatch(sample)
		if match == nil {
			t.Errorf("category %q does not match its own sample %q", category.name, sample)
			continue
		}
		if len(match) < 2 || match[1] == "" {
			t.Errorf("category %q has no capture group with a value", category.name)
		}
	}
}

func TestExposureReportsNothingOnCancellation(t *testing.T) {
	transport, point := newExposureFixture(t, &exposureFixture{
		anonymous:     func() (int, string) { return 200, "sk_live_abcdefghijklmnopqrstuvwx" },
		authenticated: func(string) (int, string) { return 200, "" },
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (Exposure{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

func TestIsPlaceholderAndPublicByDesign(t *testing.T) {
	for _, value := range []string{"your-api-key", "CHANGEME", "xxxxx", "redacted", "notreal"} {
		if !isPlaceholder(value) {
			t.Errorf("isPlaceholder(%q) = false, want true", value)
		}
	}
	if isPlaceholder("sk_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0") {
		t.Error("a real-looking key was classified as a placeholder")
	}
	for _, key := range []string{"websiteToken", "site_key", "pk_live", "recaptcha_site_key"} {
		if !isPublicByDesign(key) {
			t.Errorf("isPublicByDesign(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"db_password", "aws_secret_access_key", "authorization"} {
		if isPublicByDesign(key) {
			t.Errorf("isPublicByDesign(%q) = true; a real credential name must not be exempted", key)
		}
	}
}

// sampleFor gives each pattern something of its own to match, so the table test
// proves the pattern works rather than proving the table is non-empty.
func sampleFor(name string) string {
	switch name {
	case "AWS Access Key ID":
		return "key = AKIAIOSFODNN7EXAMPLE"
	case "Private Key Block":
		return "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
	case "GitHub Token":
		return "token ghp_" + strings.Repeat("a", 36)
	case "Stripe Live Secret Key":
		return "sk_live_" + strings.Repeat("b", 24)
	case "Slack Bot Token":
		return "xoxb-123456789012-abcdefghijkl"
	case "Connection String with Credentials":
		return "postgres://user:s3cret@db.internal:5432/app"
	case "JWT":
		return "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
	case "Google API Key":
		return "AIza" + strings.Repeat("c", 35)
	case "Mailgun API Key":
		return "key-" + strings.Repeat("d", 32)
	case "Twilio API Key":
		return "SK" + strings.Repeat("e", 32)
	case "Bearer Token Literal":
		return "Authorization: Bearer " + strings.Repeat("f", 30)
	case "Hardcoded Password Assignment":
		return `password = "correct-horse-battery"`
	case "Generic API Key or Secret Assignment":
		return `api_key = "` + strings.Repeat("g", 30) + `"`
	}
	return ""
}
