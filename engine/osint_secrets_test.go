package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecretValueIsNeverStored is the rule that matters most here and the one a
// future edit is most likely to break: a credential finding that stored the value
// would turn every exported graph, project bundle and report into a second copy
// of a live key. The test holds the whole result, not one field, because the
// value would survive just as well inside `properties` or a warning.
//
// The key used here is a well-formed AWS key id that is *not* AWS's published
// documentation example, because that example is on the placeholder list and the
// scanner is right to refuse it. A test that used it would have been testing the
// placeholder filter while claiming to test storage.
func TestSecretValueIsNeverStored(t *testing.T) {
	const secret = "AKIA29326ML64LG2TJF8"
	diff := "+++ b/deploy.env\n" +
		"+AWS_ACCESS_KEY_ID=" + secret + "\n" +
		"+AWS_SECRET_ACCESS_KEY=9dRtP4nZ2mLxKv7BqW1sYc6Hj3Gf0Ea8U\n"

	findings := applySecretRules(diff, "acme/infra", "abc1234")
	if len(findings) == 0 {
		t.Fatal("a committed AWS key was not reported at all")
	}
	entity := secretEntity(findings[0])
	encoded, err := json.Marshal(entity)
	if err != nil {
		t.Fatalf("marshal entity: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("the secret reached the entity: %s", encoded)
	}
	if strings.Contains(string(encoded), "9dRtP4nZ2mLxKv7BqW1sYc6Hj3Gf0Ea8U") {
		t.Fatalf("the companion secret key reached the entity: %s", encoded)
	}
	if entity.Properties["secret_value_stored"] != false {
		t.Fatalf("properties[secret_value_stored] = %v, want false stated explicitly",
			entity.Properties["secret_value_stored"])
	}
	// The finding still has to be identifiable, or it is useless: a provider
	// name, a fingerprint that starts with the value's own prefix, and the
	// location it was found.
	if entity.Properties["provider"] != "aws_access_key_id" {
		t.Fatalf("properties[provider] = %v, want the rule that matched", entity.Properties["provider"])
	}
	fingerprint, _ := entity.Properties["fingerprint"].(string)
	if !strings.HasPrefix(fingerprint, secret[:6]) {
		t.Fatalf("fingerprint = %q, want it to start with the value's own prefix", fingerprint)
	}
	if entity.Properties["repository"] != "acme/infra" || entity.Properties["commit"] != "abc1234" {
		t.Fatalf("the finding lost its location: %s", encoded)
	}
}

// TestSecretFingerprintIsStableAndDistinct: the same value must dedupe to one
// finding, and two different values must never collide on one.
func TestSecretFingerprintIsStableAndDistinct(t *testing.T) {
	first := "AKIAIOSFODNN7EXAMPLE"
	second := "AKIAIOSFODNN7EXAMPLF"
	samePrefix, firstDigest := secretFingerprint(first)
	againPrefix, againDigest := secretFingerprint(first)
	otherPrefix, otherDigest := secretFingerprint(second)

	if firstDigest != againDigest {
		t.Fatal("the same value produced two digests, so deduplication cannot work")
	}
	if samePrefix != againPrefix {
		t.Fatal("the same value produced two prefixes")
	}
	if firstDigest == otherDigest {
		t.Fatalf("two different values collided on digest %s", firstDigest)
	}
	// Two AWS keys share a prefix in practice only if the first six characters
	// match, which is why the digest is what dedupes and the prefix is only a
	// human hint. The digest is what has to separate them.
	if otherPrefix == samePrefix && firstDigest == otherDigest {
		t.Fatal("prefix and digest both collided")
	}
}

// TestPlaceholderValuesAreNotReported is the false-positive guard. A finding that
// names a provider but is really a documentation example costs the operator the
// same trust as a missed finding, and templates are everywhere in repositories.
func TestPlaceholderValuesAreNotReported(t *testing.T) {
	for name, diff := range map[string]string{
		"template aws key":  "+AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX\n",
		"your api key":      "+api_key = your-api-key-here-0000000000000\n",
		"example sendgrid":  "+SENDGRID=SG.abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG\n",
		"repeated chars":    "+token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		"changeme":          "+secret_key = changeme0123456789012345\n",
		"redacted in prose": "# set your slack token below\n",
	} {
		if findings := applySecretRules(diff, "acme/app", "deadbee"); len(findings) != 0 {
			t.Fatalf("%s: reported %d findings, want none: %+v", name, len(findings), findings)
		}
	}
}

// TestSecretRulesCatchTheProvidersTheyName: a rule that matches nothing is dead
// weight in a tool an operator has to trust, so each one is shown its own sample.
//
// Every sample is a well-formed value of its provider's real shape, and none of
// them contains a word the placeholder filter is meant to catch — an earlier
// version of this test used AWS's published `AKIAIOSFODNN7EXAMPLE` and an
// all-`X` Slack path, both of which the scanner correctly refuses, so the test
// was passing for the wrong reason.
func TestSecretRulesCatchTheProvidersTheyName(t *testing.T) {
	samples := map[string]struct {
		value string
		// wantLen is the exact length the provider's real key has. It is stated
		// so a truncated fixture fails as a fixture rather than reading as a
		// broken rule: the first version of this test was full of samples one or
		// two characters short, and each of them looked like a rule that had
		// stopped working.
		wantLen int
	}{
		"aws_access_key_id":          {value: "AKIA29326ML64LG2TJF8", wantLen: 20},
		"github_token":               {value: "ghp_Z4SOcMz9CPVNPkNa1Hedcm4pMbXDuCL1mHoO", wantLen: 40},
		"slack_webhook":              {value: "https://hooks.slack.com/services/TpLIix6MEO/BLeMa61EqJo/mTEI1JEzO3joOj37HyVaQXek", wantLen: 80},
		"stripe_secret_key":          {value: "sk_live_TzAeKOmXRrvftva9AW7hipTg", wantLen: 32},
		"google_api_key":             {value: "AIzabh7_wy5yq1XoY1BaIMcAxYmfsB4HbQLXjjl", wantLen: 39},
		"sendgrid_api_key":           {value: "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", wantLen: 69},
		"npm_token":                  {value: "npm_9cbMOeEeUtuieeCIxVc57VVTiY96vwfRE5e3", wantLen: 40},
		"private_key_block":          {value: "-----BEGIN RSA PRIVATE KEY-----\n1d/bWWbjkloG1QX647kdNl9cDo/+GbVMszvR4/EP", wantLen: 72},
		"generic_api_key_assignment": {value: "api_key = ZGz3zBXCOArr/SfiJvo58JB0W/O5PjeJ", wantLen: 42},
	}
	for ruleID, sample := range samples {
		if len(sample.value) != sample.wantLen {
			t.Errorf("fixture for %q is %d chars, want %d — fix the fixture, not the rule",
				ruleID, len(sample.value), sample.wantLen)
			continue
		}
		findings := applySecretRules("+value = "+sample.value+"\n", "acme/app", "abc1234")
		matched := false
		for _, finding := range findings {
			if finding.rule == ruleID {
				matched = true
			}
		}
		if !matched {
			t.Errorf("rule %q did not match its own sample %q (findings: %+v)", ruleID, sample.value, findings)
		}
	}
}

// TestDiffLineNumberPointsAtTheMatch: a finding that says "line 0" cannot be
// acted on, which is the difference between evidence and a curiosity.
func TestDiffLineNumberPointsAtTheMatch(t *testing.T) {
	diff := "line one\nline two\n+AKIA29326ML64LG2TJF8\nline four\n"
	findings := applySecretRules(diff, "acme/app", "abc1234")
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	if findings[0].line != 3 {
		t.Fatalf("line = %d, want 3", findings[0].line)
	}
}

// TestSecretRulesFireOnDiffShapedEvidence: the real input is never a bare
// assignment — it is a unified diff with a file header, an index line, a hunk
// range and a `+` on every added line. A rule set proven only on `"key = value"`
// would be proven on input the transform never actually receives, and the line
// numbers an operator uses to open the file would be off by the hunk offset.
//
// The three providers here are the ones whose real formats are unambiguous, so a
// miss is a broken rule rather than a debatable match.
func TestSecretRulesFireOnDiffShapedEvidence(t *testing.T) {
	realDiff := "diff --git a/config/production.env b/config/production.env\n" +
		"index 3f4a1b2..9c8d7e6 100644\n" +
		"--- a/config/production.env\n" +
		"+++ b/config/production.env\n" +
		"@@ -1,4 +1,9 @@\n" +
		" NODE_ENV=production\n" +
		"+STRIPE_SECRET_KEY=sk_live_TzAeKOmXRrvftva9AW7hipTg\n" +
		"+GITHUB_TOKEN=ghp_Z4SOcMz9CPVNPkNa1Hedcm4pMbXDuCL1mHoO\n" +
		"+AWS_ACCESS_KEY_ID=AKIA29326ML64LG2TJF8\n" +
		" # unchanged below\n" +
		" PORT=8080\n"

	findings := applySecretRules(realDiff, "acme/api", "9f2e1d0")
	fired := map[string]bool{}
	for _, finding := range findings {
		fired[finding.rule] = true
	}
	for _, want := range []string{"stripe_secret_key", "github_token", "aws_access_key_id"} {
		if !fired[want] {
			t.Errorf("rule %q did not fire on diff-shaped evidence (fired: %v)", want, fired)
		}
	}
	// The removed lines start with `-` and are not evidence of what the
	// repository currently serves. A rule that matched them would report a
	// credential the commit deleted.
	for _, finding := range findings {
		if finding.line < 6 {
			t.Errorf("finding %q at line %d points into the diff header rather than an added line", finding.rule, finding.line)
		}
	}
}

// TestSecretRulesDoNotFireOnARealWorldDiff is the false-positive measurement: a
// real kernel commit, 161 added lines and no credentials, must produce no
// findings. A rule set that reports something here would be reporting noise on
// every ordinary diff an operator scans.
func TestSecretRulesDoNotFireOnOrdinaryCodeDiff(t *testing.T) {
	ordinary := "diff --git a/drivers/mtd/cifs.c b/drivers/mtd/cifs.c\n" +
		"@@ -100,4 +100,6 @@ static int cifs_reconnect(void)\n" +
		"-\tif (rc) goto exit;\n" +
		"+\t/* the token argument is the server challenge, not a credential */\n" +
		"+\tif (rc)\n" +
		"+\t\tgoto exit;\n" +
		"+	rc = 0;\n" +
		" \tmutex_unlock(&cifs_chan_lock);\n"
	if findings := applySecretRules(ordinary, "acme/kernel", "a243ede718"); len(findings) != 0 {
		t.Fatalf("ordinary code produced %d credential findings: %+v", len(findings), findings)
	}
}

// TestGitHubScanTargetReadsBothForms: a bare username and a repository URL are the
// two ways an operator names the same target, and only the URL carries a
// repository the scan must not widen away from.
func TestGitHubScanTargetReadsBothForms(t *testing.T) {
	cases := map[string]struct {
		user string
		repo string
	}{
		"torvalds":                          {user: "torvalds"},
		"  torvalds  ":                      {user: "torvalds"},
		"https://github.com/torvalds/linux": {user: "torvalds", repo: "linux"},
		"github.com/torvalds/linux":         {user: "torvalds", repo: "linux"},
		"torvalds/linux":                    {user: "torvalds", repo: "linux"},
		"https://github.com/torvalds":       {user: "torvalds"},
		"":                                  {},
		"https://example.test/":             {},
	}
	for value, want := range cases {
		user, repo := githubScanTarget(value)
		if user != want.user || repo != want.repo {
			t.Errorf("githubScanTarget(%q) = (%q, %q), want (%q, %q)", value, user, repo, want.user, want.repo)
		}
	}
}

// TestGitScanRepositorySecretsCountsWhatItRead: an empty scan has to say what was
// examined, or "nothing found" cannot be told apart from "nothing looked at".
//
// The transform warns "no credential pattern matched in the scanned public diffs",
// and that sentence was unfalsifiable: the result published how many
// repositories, how deep to walk and whether a token was configured, but never how
// many commits were actually read. Measured 2026-10-01 against
// `octocat/Hello-World`, where the reference tool reports two findings and this
// scan reports none: both of theirs are committed by other people and the account
// filter excludes them — correct, and impossible to confirm from the output,
// because the output said nothing about how much had been read.
func TestGitScanRepositorySecretsCountsWhatItRead(t *testing.T) {
	stub := newIdentityStub()
	stub.respond("https://api.github.com/repos/example/repo/commits?per_page=100&page=1",
		`[{"sha":"a1","commit":{"author":{"email":"a@example.test","name":"A"},`+
			`"committer":{"email":"a@example.test","name":"A"}}}]`, 200)
	stub.respond("https://github.com/example/repo/commit/a1.diff",
		"diff --git a/config/production.env b/config/production.env\n"+
			"--- a/config/production.env\n"+
			"+++ b/config/production.env\n"+
			"@@ -1,2 +1,3 @@\n"+
			"+STRIPE_SECRET_KEY=sk_live_TzAeKOmXRrvftva9AW7hipTg\n",
		200)

	var findings []secretFinding
	fetched, examined := gitScanRepositorySecrets(
		context.Background(), identityStubClient(stub), "example",
		githubRepository{Name: "repo", FullName: "example/repo"},
		1, 3, &transformCollector{job: &osintJob{ID: "osint-secrets", done: make(chan struct{}), gate: newPauseGate()},
			ctx: context.Background(), stop: make(chan struct{}), progress: func(transformProgress) {}},
		func(finding secretFinding) { findings = append(findings, finding) },
	)

	if fetched != 1 {
		t.Errorf("fetched = %d, want 1: the stub served exactly one commit", fetched)
	}
	if examined != 1 {
		t.Errorf("examined = %d, want 1: one diff was served and read", examined)
	}
	if len(findings) == 0 {
		t.Error("the seeded diff holds a credential and no finding came back")
	}
	// The value itself must still never be stored, which is the rule the counts
	// are added next to.
	if len(findings) > 0 && findings[0].fingerprint == "" {
		t.Error("the finding carries no fingerprint, so it cannot be reported without the value")
	}
}

// TestGitSecretsResultCarriesTheReadCounts: the counters have to reach the
// result, not only the scan function.
//
// This is a separate assertion from the previous one because it failed there: the
// scan returned the right numbers and the result still said nothing, because the
// two are wired by a `setTransformMetadata` call that no test was watching. The
// mutation "do not publish the counts" left the whole suite green, which is the
// same shape of blind spot the count was added to close — reintroduced one level
// up.
func TestGitSecretsResultCarriesTheReadCounts(t *testing.T) {
	stub := newIdentityStub()
	stub.respond("https://api.github.com/users/example/repos?per_page=100&type=owner&sort=pushed&page=1",
		`[{"name":"repo","full_name":"example/repo","fork":false,"archived":false}]`, 200)
	stub.respond("https://api.github.com/repos/example/repo/commits?per_page=100&page=1",
		`[{"sha":"a1","commit":{"author":{"email":"a@example.test","name":"A"},`+
			`"committer":{"email":"a@example.test","name":"A"}}}]`, 200)
	stub.respond("https://github.com/example/repo/commit/a1.diff",
		"diff --git a/config/production.env b/config/production.env\n"+
			"--- a/config/production.env\n+++ b/config/production.env\n"+
			"@@ -1,2 +1,3 @@\n+STRIPE_SECRET_KEY=sk_live_TzAeKOmXRrvftva9AW7hipTg\n", 200)

	// The transform builds its own client from the tool transport in the context,
	// so the stub is injected there rather than through the server.
	ctx := withToolTransport(context.Background(), roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return stub.record(request), nil
	}))
	var result osintTransformResult
	err := transformGitSecrets(&server{}, ctx, &result,
		osintTransformInput{Transform: "git_secrets", Value: "example", ConfirmNetwork: true},
		&transformCollector{
			job:      &osintJob{ID: "osint-secrets", done: make(chan struct{}), gate: newPauseGate()},
			ctx:      ctx,
			stop:     make(chan struct{}),
			progress: func(transformProgress) {},
		})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	for _, key := range []string{"commits_fetched", "commits_examined"} {
		value, present := result.Metadata[key]
		if !present {
			t.Errorf("%s is not in the result, so an operator cannot tell an empty scan from an empty run", key)
			continue
		}
		if number, ok := value.(int); !ok || number < 1 {
			t.Errorf("%s = %v, want at least 1", key, value)
		}
	}
	if len(result.Entities) == 0 {
		t.Error("the seeded diff holds a credential and no finding came back")
	}
}

// The scan has to leave the first hop. Measured 2026-10-02 on live `.ru` hosts:
// `pravda.ru` answers **301 for every path** and the scan reported
// `paths_checked: 2` with nothing found, because it read the redirect body. The
// shared client is built with `ErrUseLastResponse` so every other OSINT request
// lands in History as sent, and inheriting that meant this scan never followed one.
func TestSecretScanFollowsTheApexRedirect(t *testing.T) {
	// The redirect target has to be the same fixture, or the test asks the real
	// DNS for `www.apex.test` and fails on the network instead of on the
	// behaviour it is here to decide.
	//
	// The record is the whole request URI, not only its path: the marker lives in
	// the query, and recording only `r.URL.Path` makes the assertion about the
	// second hop unsatisfiable — a green test that proves nothing.
	var asked []string
	var served *httptest.Server
	served = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RequestURI())
		if r.URL.Query().Get("from") == "" {
			// The apex redirects everything to the same host, which is the shape
			// that hid it: every `.ru` apex that serves its content on `www`.
			http.Redirect(w, r, served.URL+r.URL.Path+"?from=apex", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "DATABASE_URL=postgres://user:hunter2@db.internal:5432/app\nSECRET_KEY=x\n")
	}))
	defer served.Close()

	// The client must not follow the redirect itself. `s.toolClient` is built with
	// `ErrUseLastResponse` so every other OSINT request lands in History as sent,
	// and inheriting that is what kept this scan on the first hop. A fixture that
	// follows redirects would let the helper pass while the product still failed,
	// because the second request would be the client's and not the scan's.
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	body, status, truncated, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", secretScanDefaultBytes)
	if !ok {
		t.Fatal("the fetch did not complete")
	}
	if truncated {
		t.Fatal("a two-line fixture must not be reported as truncated")
	}
	if status != http.StatusOK {
		t.Fatalf("expected the page on www, got status %d", status)
	}
	if !strings.Contains(body, "hunter2") {
		t.Fatalf("the body read was the redirect, not the page: %q", body)
	}
	joined := strings.Join(asked, ",")
	if !strings.Contains(joined, "/.env") {
		t.Fatalf("paths asked: %v", asked)
	}
	if !strings.Contains(joined, "from=apex") {
		t.Fatalf("the scan stopped at the first hop and read the redirect body; requests: %v", asked)
	}
}

// A chain that never settles must stop rather than keep asking: one redirect is the
// case that matters, and following further would let a host point the scan at any
// third party.
func TestSecretScanDoesNotFollowMoreThanOneRedirect(t *testing.T) {
	// Each hop is a distinct path, so the redirect target stays inside the fixture:
	// a test about hop counting must not depend on the resolver.
	var hops int
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, fmt.Sprintf("/hop%d", hops+1), http.StatusMovedPermanently)
	}))
	defer served.Close()
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	_, _, _, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", secretScanDefaultBytes)
	if hops > 2 {
		t.Fatalf("followed %d hops; one redirect is the case that matters", hops)
	}
	if ok {
		t.Fatal("a chain that never settles reported an answer")
	}
	if hops != 2 {
		t.Fatalf("expected exactly 2 requests before giving up, made %d", hops)
	}
}

// A redirect to a non-HTTP scheme is refused rather than requested.
func TestSecretScanRefusesARedirectOffHTTP(t *testing.T) {
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusMovedPermanently)
	}))
	defer served.Close()
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	body, status, truncated, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", secretScanDefaultBytes)
	if !ok {
		t.Fatal("the fetch did not complete")
	}
	if truncated {
		t.Fatal("a refused redirect reads nothing, so nothing was truncated")
	}
	if status != http.StatusMovedPermanently {
		t.Fatalf("expected the redirect status to be reported, got %d", status)
	}
	if body != "" {
		t.Fatalf("a refused redirect must not return a body, got %q", body)
	}
}

// A relative `Location` has to resolve against the URL it came from, not be
// treated as a hostname.
func TestRequestURLResolvesRelativeAndAbsoluteTargets(t *testing.T) {
	cases := []struct {
		base     string
		location string
		want     string
	}{
		// A relative target resolves against the directory the request came from.
		{"https://apex.test/dir/file", "next", "https://apex.test/dir/next"},
		{"https://apex.test/dir/file", "/root", "https://apex.test/root"},
		// An absolute target replaces the host, which is the apex-to-www case.
		{"https://apex.test/dir/file", "https://www.apex.test/next", "https://www.apex.test/next"},
		{"http://apex.test/dir/file", "https://www.apex.test/next", "https://www.apex.test/next"},
	}
	for _, testCase := range cases {
		resolved, err := requestURL(testCase.base, testCase.location)
		if err != nil {
			t.Fatalf("%s + %s: %v", testCase.base, testCase.location, err)
		}
		if resolved != testCase.want {
			t.Errorf("%s + %s = %s, want %s", testCase.base, testCase.location, resolved, testCase.want)
		}
	}
}
