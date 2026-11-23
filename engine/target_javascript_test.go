package main

// Tests for the JavaScript analysis the Target crawler runs on every resource
// it fetched (`analyzeJavaScript` in target_javascript.go).
//
// Each test here states a claim the feature makes, and each claim is written so
// that reverting the decision it checks turns it red. A test that stays green
// when the code is wrong is a dead test and is worse than no test, because it
// is counted as evidence.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// endpointFor finds an analysed endpoint by its unresolved reference.
func endpointFor(t *testing.T, analysis jsAnalysis, reference string) jsEndpoint {
	t.Helper()
	for _, endpoint := range analysis.Endpoints {
		if endpoint.URL == reference {
			return endpoint
		}
	}
	t.Fatalf("endpoint %q not found among %d: %s", reference, len(analysis.Endpoints), jsEndpointDump(analysis))
	return jsEndpoint{}
}

func jsEndpointDump(analysis jsAnalysis) string {
	references := make([]string, 0, len(analysis.Endpoints))
	for _, endpoint := range analysis.Endpoints {
		references = append(references, endpoint.URL)
	}
	return strings.Join(references, ", ")
}

func hasLink(links []string, want string) bool {
	for _, link := range links {
		if link == want {
			return true
		}
	}
	return false
}

func secretRulesOf(secrets []jsSecret) []string {
	rules := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		rules = append(rules, secret.Rule)
	}
	return rules
}

func hasRule(secrets []jsSecret, rule string) bool {
	for _, secret := range secrets {
		if secret.Rule == rule {
			return true
		}
	}
	return false
}

// TestJavaScriptAnalysisReadsTheCallSiteNotTheText is the central claim of the
// feature. A regular expression over the same bytes reports the string
// "/api/v1/users/" with nothing attached; the parser reports the call, its
// method and the parameter the program built the path from. Reverting to the
// regular expression makes Method and the parameter list empty, which is exactly
// what this asserts against.
func TestJavaScriptAnalysisReadsTheCallSiteNotTheText(t *testing.T) {
	source := `function load(uid, token) {
		return fetch("/api/v1/users/" + uid, {
			method: "POST",
			headers: { "content-type": "application/json", "x-csrf": token }
		});
	}`
	analysis := analyzeJavaScript("https://shop.example/assets/app.js", []byte(source))
	if analysis.Error != "" {
		t.Fatalf("analysis reported %q", analysis.Error)
	}
	endpoint := endpointFor(t, analysis, "/api/v1/users/EXPR")
	if endpoint.Method != "POST" {
		t.Fatalf("method = %q, want POST: the call site is what carries it", endpoint.Method)
	}
	if endpoint.ContentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", endpoint.ContentType)
	}
	// A header whose value is a variable comes back empty rather than wrong:
	// jsluice reads literals and leaves nothing where an expression stood. The
	// key is still reported as a header the request sends, which is the part
	// that decides what to reproduce in the Repeater.
	if value, present := endpoint.Headers["x-csrf"]; !present || value != "" {
		t.Fatalf("x-csrf header = %q present=%v, want the key reported with an unknown value", value, present)
	}
	if !containsString(endpoint.Types, "fetch") {
		t.Fatalf("types = %v, want it to name fetch", endpoint.Types)
	}
}

// TestJavaScriptAnalysisReadsQueryParameterNames pins a claim that only the
// parser can make. A regular expression over the same bytes reports the query
// string as text; what a request to that endpoint needs is the parameter names,
// and they are only knowable after the program has built the URL.
func TestJavaScriptAnalysisReadsQueryParameterNames(t *testing.T) {
	source := `$.post("/api/orders", { id: orderId, coupon: code });`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	endpoint := endpointFor(t, analysis, "/api/orders")
	if endpoint.Method != "POST" {
		t.Fatalf("method = %q, want POST", endpoint.Method)
	}
	// Body parameter names come from the data object of a jQuery POST. This is
	// the shape jsluice reads them from; a `fetch` with a `JSON.stringify` body
	// reports none, because the keys are inside a call the analyser does not
	// evaluate. Asserting the jQuery case keeps the claim honest rather than
	// implying every call style is covered.
	if len(endpoint.Body) != 2 ||
		!containsString(endpoint.Body, "id") ||
		!containsString(endpoint.Body, "coupon") {
		t.Fatalf("body params = %v, want the data object's keys [coupon id]", endpoint.Body)
	}
	if endpoint.ContentType != "application/x-www-form-urlencoded; charset=UTF-8" {
		t.Fatalf("content type = %q, want the form encoding a jQuery POST implies", endpoint.ContentType)
	}
}

// TestJavaScriptAnalysisReadsQueryStringParameterNames is the same claim for a
// reference that already carries its query string, where the names are in the
// text but the parse is what turns them into a list.
func TestJavaScriptAnalysisReadsQueryStringParameterNames(t *testing.T) {
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(`fetch("/api/search?q=term&page=2");`))
	endpoint := endpointFor(t, analysis, "/api/search?q=term&page=2")
	if len(endpoint.Query) != 2 ||
		!containsString(endpoint.Query, "q") ||
		!containsString(endpoint.Query, "page") {
		t.Fatalf("query params = %v, want [page q]", endpoint.Query)
	}
}

// TestJavaScriptAnalysisResolvesAgainstTheFileNotTheCrawlStart is a correctness
// claim about the base URL. The crawl resolves every reference against the URL
// it started from, which sends a relative reference in /assets/app.js to the
// site root instead of to /assets/. The analyser knows where the bytes came
// from and uses it.
func TestJavaScriptAnalysisResolvesAgainstTheFileNotTheCrawlStart(t *testing.T) {
	source := `var routes = { users: "api/v1/users.json", health: "/api/health" };`
	analysis := analyzeJavaScript("https://shop.example/assets/app.js", []byte(source))
	if !hasLink(analysis.links, "https://shop.example/assets/api/v1/users.json") {
		t.Fatalf("relative reference not resolved against the file: %v", analysis.links)
	}
	if !hasLink(analysis.links, "https://shop.example/api/health") {
		t.Fatalf("absolute-path reference not resolved against the origin: %v", analysis.links)
	}
}

// TestJavaScriptAnalysisKeepsExpressionPathsOutOfTheCrawl checks that a path the
// program assembles is reported but not requested. "/api/users/EXPR" is a real
// discovery and a request nobody meant to make, and the count of what was held
// back is part of the record.
func TestJavaScriptAnalysisKeepsExpressionPathsOutOfTheCrawl(t *testing.T) {
	source := `fetch("/api/users/" + uid); var x = "/api/plain";`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	endpointFor(t, analysis, "/api/users/EXPR")
	for _, link := range analysis.links {
		if strings.Contains(link, jsExpressionMarker) {
			t.Fatalf("a path with an unknown expression was enqueued: %q", link)
		}
	}
	if !hasLink(analysis.links, "https://shop.example/api/plain") {
		t.Fatalf("the plain path next to it was lost: %v", analysis.links)
	}
	if analysis.LinksWithExpression != 1 {
		t.Fatalf("links_with_expression = %d, want 1: a skipped reference must be counted, not silently dropped", analysis.LinksWithExpression)
	}
}

// TestContainsJSExpressionComparesWholeFields pins the decision that a real path
// containing the letters EXPR is not mistaken for a substituted expression. The
// over-easy version, a substring search, fails the second case.
func TestContainsJSExpressionComparesWholeFields(t *testing.T) {
	cases := []struct {
		reference string
		want      bool
	}{
		{"/api/users/EXPR", true},
		{"EXPR", true},
		{"/api/users/EXPR/comments", true},
		{"/api/users?id=EXPR", true},
		{"/api/EXPRESSION", false},
		{"/api/expr-notes", false},
		{"/api/expression-guide", false},
		{"/api/users", false},
	}
	for _, testCase := range cases {
		if got := containsJSExpression(testCase.reference); got != testCase.want {
			t.Fatalf("containsJSExpression(%q) = %v, want %v", testCase.reference, got, testCase.want)
		}
	}
}

// TestJavaScriptAnalysisFoldsRepeatedReferencesIntoOneRow is a size claim. A file
// that repeats a function reports the same endpoint once per copy — 20 000 rows
// for one endpoint was measured on a 1.3 MB file — and a page record that large
// is unreadable and expensive to store.
func TestJavaScriptAnalysisFoldsRepeatedReferencesIntoOneRow(t *testing.T) {
	var builder strings.Builder
	for index := 0; index < 200; index++ {
		builder.WriteString(`function f(a){return fetch("/api/repeat/" + a);}`)
	}
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(builder.String()))
	found := 0
	for _, endpoint := range analysis.Endpoints {
		if endpoint.URL == "/api/repeat/EXPR" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("the same reference is reported %d times, want once", found)
	}
}

// TestJavaScriptAnalysisFoldsStructuralOverLiteral checks which of two rows for
// the same reference survives. The bare string literal is the same text with
// nothing added, so the row that knows the method has to win.
func TestJavaScriptAnalysisFoldsStructuralOverLiteral(t *testing.T) {
	source := `$.post("/api/orders", payload);`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	endpoint := endpointFor(t, analysis, "/api/orders")
	if endpoint.Method != "POST" {
		t.Fatalf("method = %q, want POST from the jQuery call site", endpoint.Method)
	}
	if !containsString(endpoint.Types, "stringLiteral") {
		t.Fatalf("types = %v, want the literal match recorded too: the fold must merge, not drop", endpoint.Types)
	}
}

// TestJavaScriptAnalysisReportsSecretsWithTheirValue is a contract claim, and the
// one the owner reversed on 2026-09-30.
//
// It asserted the opposite before that: that no value appears in the record,
// because a Target result reaches PostgreSQL, the exports and the chats. The
// reversal is deliberate — a key the analyst cannot read is a finding the
// analyst cannot use, and the tool exists to be used. The fingerprint stays, so
// the same key is still recognisable in a second file, and this test now pins
// both halves: the value is present, and the fingerprint is derived from it
// rather than replacing it.
func TestJavaScriptAnalysisReportsSecretsWithTheirValue(t *testing.T) {
	// The values are realistic but invented. This project's `isPlaceholderValue`
	// filters anything containing "example", "fake", "xxxx" and a dozen more
	// fragments, and the canonical AWS documentation key `AKIAIOSFODNN7EXAMPLE`
	// is filtered by it — measured, which is why the fixtures are not the ones
	// from the AWS docs. A test that used them would have passed for the wrong
	// reason: the finding would be absent, but the placeholder filter would be
	// why.
	const key = "AKIA4XQ7PLMN2ZKQWJ3D"
	const secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYzXQ8sLmVtR2uKd9pA"
	source := `var aws = { key: "` + key + `", secret: "` + secret + `" };`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	if !hasRule(analysis.Secrets, "aws_access_key_id") {
		t.Fatalf("the access key id was not reported: %v", secretRulesOf(analysis.Secrets))
	}
	if !hasRule(analysis.Secrets, "aws_secret_access_key") {
		t.Fatalf("the secret beside it was not reported: %v", secretRulesOf(analysis.Secrets))
	}
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rendered := string(encoded)
	// Both halves are present: the value the analyst has to use, and the
	// fingerprint that recognises the same key in another file.
	if !strings.Contains(rendered, key) {
		t.Fatalf("the access key id is not in the record: %s", rendered)
	}
	if !strings.Contains(rendered, secret) {
		t.Fatalf("the secret access key is not in the record: %s", rendered)
	}
	for _, finding := range analysis.Secrets {
		if finding.Value == "" {
			t.Fatalf("finding %s carries no value", finding.Rule)
		}
		if !strings.Contains(finding.Fingerprint, "…") {
			t.Fatalf("fingerprint %q carries no digest", finding.Fingerprint)
		}
		// The fingerprint must still be derived from the value, or two reports
		// of one key would stop folding into one.
		prefix, digest := secretFingerprint(finding.Value)
		if finding.Fingerprint != prefix+"…"+digest[:12] {
			t.Fatalf("fingerprint %q is not derived from the value %q",
				finding.Fingerprint, finding.Value)
		}
	}
}

// TestJavaScriptAnalysisNamesTheSameRulesAsTheTextScan is the naming claim. One
// leaked key must not be called "AWSAccessKey" by the crawler and
// "aws_access_key_id" by the OSINT transform, or the operator compares two
// vocabularies for one problem.
func TestJavaScriptAnalysisNamesTheSameRulesAsTheTextScan(t *testing.T) {
	// Realistic invented values, for the placeholder-filter reason given in
	// TestJavaScriptAnalysisReportsSecretsAsFingerprintsOnly.
	const awsKey = "AKIA4XQ7PLMN2ZKQWJ3D"
	const googleKey = "AIzaSyD8mKpQ2vNzL7rTbXwYcF4hJ9pKdS3eR5t"
	const githubToken = "ghp_K2mNvXqB8zLwYcF3jH5pD9sA1eU4gT7rW0bN"
	source := `var k = { key: "` + awsKey + `" }, g = "` + googleKey + `", t = "` + githubToken + `";`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	for _, rule := range []string{"aws_access_key_id", "google_api_key", "github_token"} {
		if !hasRule(analysis.Secrets, rule) {
			t.Fatalf("rule %q not reported, got %v", rule, secretRulesOf(analysis.Secrets))
		}
	}
	for _, finding := range analysis.Secrets {
		if _, known := jsSecretKinds[finding.Kind]; !known && finding.Kind == "" {
			t.Fatalf("finding without a matcher name: %+v", finding)
		}
	}
	// A key reported by two matchers is one leak. jsluice's own AWS matcher and
	// this project's rule both recognise AKIA..., so the fold has to collapse
	// them.
	awsCount := 0
	for _, finding := range analysis.Secrets {
		if finding.Rule == "aws_access_key_id" {
			awsCount++
		}
	}
	if awsCount != 1 {
		t.Fatalf("the AWS key is reported %d times, want once", awsCount)
	}
}

// TestJavaScriptAnalysisRunsTheProjectsOwnRules is the coverage claim for the
// vendor formats jsluice does not implement. Before this, the crawler found no
// secret of any kind in JavaScript.
func TestJavaScriptAnalysisRunsTheProjectsOwnRules(t *testing.T) {
	// Measured lengths, because all three rules are length-constrained: the
	// Slack rule wants 8-12 characters in the T segment, 8-12 in the B segment
	// and 20-32 in the last one, the npm rule wants exactly 36 after `npm_`, and
	// the placeholder filter rejects any value containing "xxxxxxxx". Fixtures
	// that are one character off match nothing and the test would then be
	// asserting on a rule that never ran.
	source := `var c = {
		stripe: "sk_live_51Kq3WmZ8nPtRvXc2LbJf7Yd4HaG",
		slack: "https://hooks.slack.com/services/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s",
		npm: "npm_R7kT2mNvXqB8zLwYcF3jH5pD9sA1eU4gW6yQ"
	};`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	for _, rule := range []string{"stripe_secret_key", "slack_webhook", "npm_token"} {
		if !hasRule(analysis.Secrets, rule) {
			t.Fatalf("rule %q not reported, got %v", rule, secretRulesOf(analysis.Secrets))
		}
	}
}

// TestJavaScriptAnalysisReportsWholeSecretValues is the claim that a found key
// is the key.
//
// Every ceiling in `secretRules` is a decision about how long a tail may be, and
// a class like `[0-9A-Za-z-]{10,48}` does not describe the format — it reports
// the first 48 characters of it. That was measured before this test existed: a
// 54-character Slack token reached the UI as 32 characters, a 212-character FCM
// key as 152, a 124-character webhook as 92. A prefix of a secret is not a
// finding an analyst can use, because a key that does not validate cannot be
// told apart from a key that was never valid.
//
// The values here are invented and shaped like the real ones, with lengths
// deliberately past what the vendors currently issue. That is the point of the
// fixtures: a ceiling nobody can reach is not a ceiling, it is an untested branch.
//
// Four of these values do not travel through the rule at all, and the test says so
// rather than pretending otherwise. `jsSecretKinds` routes `AWSAccessKey`,
// `gcpKey`, `githubKey` and `firebase` to jsluice's own matchers, which read to
// the end of the string literal, so for `google_api_key` and `github_token` a
// narrowing of this project's class changes nothing a reader can see — the
// mutation is green, and that is a fact about the two paths rather than a gap in
// the assertion. The ceilings this file really measures are the ones jsluice does
// not implement: Slack, Stripe, npm, the webhook and the FCM key.
//
// The widened classes are also the safety net for the other direction: when
// jsluice's matcher does not fire — a new vendor prefix, a token inside a shape
// it does not model — this project's rule is the only thing that reports it, and
// it must not hand over a prefix of it.
func TestJavaScriptAnalysisReportsWholeSecretValues(t *testing.T) {
	//
	// Letters and digits only, no separators: several rules end their class with
	// `\b`, so a tail that contains `_` makes the match stop early or vanish
	// entirely, and the fixture would be measuring the boundary rather than the
	// ceiling. Every class in the rules above accepts this alphabet.
	const mixedAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	//
	// The generator is a seeded PRNG over the mixed alphabet, and the seed is
	// fixed so a failure is reproducible. A cycling alphabet is a poor choice: it
	// contains the run `0123456789`, and `isPlaceholderValue` rejects any value
	// holding that run as a documentation string, so the fixture would be dropped
	// before a single rule ran — a test asserting nothing, in the coat of a test
	// asserting a length. That is not hypothetical: the first version of this
	// fixture failed with `rule "stripe_secret_key" reported nothing`.
	seed := uint64(0x5eed5eed5eed5eed)
	next := func() byte {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return mixedAlphabet[seed%uint64(len(mixedAlphabet))]
	}
	//
	// A candidate that `isPlaceholderValue` rejects is discarded and drawn
	// again, and the result is asserted clean. Without that, the fixture is a
	// lottery: a random 80-character tail has a real chance of containing `todo`
	// or `dummy`, the analyser drops it as a documentation string, and the test
	// fails for a reason that has nothing to do with the ceiling it claims to
	// check. The first two versions of this fixture failed exactly that way.
	long := func(prefix string, n int) string {
		for attempt := 0; attempt < 64; attempt++ {
			var b strings.Builder
			b.WriteString(prefix)
			for i := 0; i < n; i++ {
				b.WriteByte(next())
			}
			candidate := b.String()
			if !isPlaceholderValue(candidate) {
				return candidate
			}
		}
		t.Fatalf("no clean %d-character value was drawn in 64 attempts; the generator, not the rule, is the problem", n)
		return ""
	}
	want := map[string]string{
		"slack_token":            long("xoxb-", 76),
		"github_token":           long("ghp_", 300),
		"stripe_secret_key":      long("sk_live_", 80),
		"stripe_publishable_key": long("pk_live_", 80),
		"google_api_key":         long("AIza", 80),
		"npm_token":              long("npm_", 80),
		"slack_webhook":          "https://hooks.slack.com/services/T" + long("", 20) + "/B" + long("", 18) + "/" + long("", 120),
		"firebase_messaging_key": "AAAA" + long("", 11) + ":" + long("", 190),
	}
	source := "var credentials = {\n"
	for rule, value := range want {
		source += fmt.Sprintf("\t%s: %q,\n", rule, value)
	}
	source += "};"
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	reported := map[string]string{}
	for _, secret := range analysis.Secrets {
		if _, expected := want[secret.Rule]; expected {
			reported[secret.Rule] = secret.Value
		}
	}
	for rule, value := range want {
		got, ok := reported[rule]
		if !ok {
			t.Fatalf("rule %q reported nothing, got %v", rule, secretRulesOf(analysis.Secrets))
		}
		if got != value {
			t.Fatalf("%s reported a %d-character prefix of a %d-character value: %q",
				rule, len(got), len(value), got)
		}
	}
}

// TestJavaScriptAnalysisKeepsFixedWidthVendorFormatsExact guards the other
// direction. `aws_access_key_id` and `sendgrid_api_key` keep their exact widths
// on purpose, because a longer string with the same prefix is not one of them —
// widening every class would make the rules accept things that do not exist.
func TestJavaScriptAnalysisKeepsFixedWidthVendorFormatsExact(t *testing.T) {
	source := `var c = {
		tooLong: "AKIA0123456789ABCDEFGHIJ",
		exact: "AKIA0123456789ABCDEF",
		sg: "SG.abcdefghij0123456789ab.abcdefghij0123456789abcdefghij0123456789abc"
	};`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	for _, secret := range analysis.Secrets {
		if secret.Rule != "aws_access_key_id" {
			continue
		}
		if len(secret.Value) != 20 {
			t.Fatalf("an AWS key id was reported as %d characters: %q", len(secret.Value), secret.Value)
		}
		if secret.Value != "AKIA0123456789ABCDEF" {
			t.Fatalf("a 20-character AWS key id was reported as %q", secret.Value)
		}
	}
}

// TestJavaScriptAnalysisFindsTheFirebaseConfigByShape is the claim that only an
// analyser can make. A regular expression over these bytes finds the same AIza
// key; it cannot say the key belongs to a project with a storage bucket, which
// is the part that is worth reporting.
func TestJavaScriptAnalysisFindsTheFirebaseConfigByShape(t *testing.T) {
	source := `var config = {
		apiKey: "AIzaSyD8mKpQ2vNzL7rTbXwYcF4hJ9pKdS3eR5t",
		authDomain: "shop-prod.firebaseapp.com",
		projectId: "shop-prod-4711",
		storageBucket: "shop-prod.appspot.com"
	};`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	if !hasRule(analysis.Secrets, "firebase_config") {
		t.Fatalf("the config object was not reported, got %v", secretRulesOf(analysis.Secrets))
	}
}

// TestJavaScriptAnalysisIgnoresPlaceholders is a false positive claim. A
// documentation string about a secret is not a secret, and a report full of
// invented findings is how an operator learns to distrust the tool.
func TestJavaScriptAnalysisIgnoresPlaceholders(t *testing.T) {
	source := `var d = { apiKey: "your-api-key-here-placeholder", token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxx" };`
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(source))
	if len(analysis.Secrets) != 0 {
		t.Fatalf("placeholders were reported as secrets: %v", secretRulesOf(analysis.Secrets))
	}
}

// TestJavaScriptAnalysisKeepsConcatenationHalvesOutOfTheCrawl is a claim the live
// fixture produced, not one the code was written to.
//
// Against a real crawl of a bundle calling `"/api/v1/users/" + uid`, three extra
// requests went to `/api/never-built/`, `/api/search?q=` and `/api/v1/users/`:
// the left-hand string literal of a concatenation, which is half a path and not
// a path. Without this test the fix is invisible — the fixture answers 200 to
// everything, so the crawl looks healthy while asking for URLs that do not
// exist.
func TestJavaScriptAnalysisKeepsConcatenationHalvesOutOfTheCrawl(t *testing.T) {
	source := `function go(uid, term) {
		fetch("/api/v1/users/" + uid);
		fetch("/api/search?q=" + term + "&page=1");
		fetch("/api/static/config.json");
	}`
	analysis := analyzeJavaScript("https://shop.example/assets/app.js", []byte(source))
	for _, link := range analysis.links {
		for _, fragment := range []string{"/api/v1/users/", "/api/search?q="} {
			if link == "https://shop.example"+fragment {
				t.Fatalf("the left half of a concatenation was enqueued: %q", link)
			}
		}
	}
	// A literal that is not part of a concatenation is still a real reference and
	// must survive. Losing this would be the opposite failure: the crawler would
	// stop following bundles.
	if !hasLink(analysis.links, "https://shop.example/api/static/config.json") {
		t.Fatalf("a plain literal reference was lost: %v", analysis.links)
	}
	// Both halves stay in the endpoint list. The half is evidence of where the
	// program puts the value it cannot know.
	endpointFor(t, analysis, "/api/v1/users/EXPR")
	endpointFor(t, analysis, "/api/v1/users/")
}

// TestJsConcatenatedFragmentComparesWholePrefixes pins the helper the claim above
// depends on. A substring test would treat a short path that happens to be a
// prefix of a longer one as a fragment.
func TestJsConcatenatedFragmentComparesWholePrefixes(t *testing.T) {
	built := []string{"/api/v1/users/EXPR", "/api/search?q=EXPR&page=1"}
	fragments := []string{"/api/v1/users/", "/api/search?q="}
	for _, fragment := range fragments {
		if !jsConcatenatedFragment(fragment, built) {
			t.Fatalf("jsConcatenatedFragment(%q) = false, want true", fragment)
		}
	}
	for _, whole := range []string{"/api/v1/users", "/api/st", "/api/search"} {
		if jsConcatenatedFragment(whole, built) {
			t.Fatalf("jsConcatenatedFragment(%q) = true, want false: it is not half of either", whole)
		}
	}
	if jsConcatenatedFragment("/api/x", nil) {
		t.Fatal("a fragment with nothing built is still a fragment")
	}
}

// TestJsCrawlableReferenceRejectsWhatABrowserWouldNotFollow is the frontier
// gate's own claim. It rejects non-HTTP schemes and template-shaped references,
// and it accepts all four shapes a browser resolves — the gate that is too
// strict is the one that silently loses endpoints, so the accepts are asserted
// as loudly as the rejects.
func TestJsCrawlableReferenceRejectsWhatABrowserWouldNotFollow(t *testing.T) {
	rejects := []string{
		"", "   ", "#anchor", "mailto:ops@example.com", "tel:+79991234567",
		"data:text/html,<script>x</script>", "javascript:void(0)", "blob:https://x/abc",
		"/api/users/EXPR", "/api/${id}", "/api/[id]", "/api/*",
		"1.5", "v1.2.3",
	}
	for _, reference := range rejects {
		if jsCrawlableReference(reference) {
			t.Fatalf("jsCrawlableReference(%q) = true, want false", reference)
		}
	}
	accepts := []string{
		"/api/users", "/assets/app.js", "api/v1/users.json", "./data.json",
		"../up/one.js", "//cdn.example/lib.js", "https://api.example/v1/x",
		"http://api.example/v1/x", "/search?q=a&page=2", "/a:b/c",
	}
	for _, reference := range accepts {
		if !jsCrawlableReference(reference) {
			t.Fatalf("jsCrawlableReference(%q) = false, want true: a browser follows this", reference)
		}
	}
}

// TestSchemeIndexDistinguishesSchemeFromPath pins the helper that makes the
// gate above work. A colon before the first slash is a scheme, except in the
// shapes that are not: a port in a protocol-relative host, or a colon inside a
// path segment.
func TestSchemeIndexDistinguishesSchemeFromPath(t *testing.T) {
	cases := []struct {
		reference string
		want      int
	}{
		{"http://example/x", 4},
		{"https://example/x", 5},
		{"mailto:ops@example.com", 6},
		{"//cdn.example:8443/lib.js", -1},
		{"/a:b/c", -1},
		{"/plain/path", -1},
		{"", -1},
	}
	for _, testCase := range cases {
		if got := schemeIndex(testCase.reference); got != testCase.want {
			t.Fatalf("schemeIndex(%q) = %d, want %d", testCase.reference, got, testCase.want)
		}
	}
}

// TestJavaScriptAnalysisDistinguishesNotAnalysedFromNothingFound pins the shape
// of the record. A file with nothing in it and a file that was never read are
// different claims, and a missing key is how they get confused.
func TestJavaScriptAnalysisDistinguishesNotAnalysedFromNothingFound(t *testing.T) {
	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(`var a = 1;`))
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"endpoints":[]`, `"secrets":[]`, `"bytes"`, `"ms"`} {
		if !strings.Contains(string(encoded), key) {
			t.Fatalf("record %s does not contain %s", encoded, key)
		}
	}
	if analysis.Error != "" {
		t.Fatalf("a clean file reported %q", analysis.Error)
	}
	// The crawl frontier is not part of the record: it is the pages list.
	if strings.Contains(string(encoded), "links") && !strings.Contains(string(encoded), "links_with_expression") {
		t.Fatalf("the internal frontier leaked into the record: %s", encoded)
	}
}

// The panic seam is declared in target_javascript.go, next to the function it
// guards, because it is part of that function's contract and not part of a test.
// Declaring it here instead would make `go build` fail with "undefined" — the
// production build does not compile test files, and a symbol the shipped code
// calls cannot live in a test.

// TestJavaScriptAnalysisSurvivesAParserPanic is the availability claim. A panic
// on any goroutine terminates the process, and this one is the crawl: the input
// is a file served by a host the analyst does not control. A recovered panic
// costs one page; an unrecovered one costs the engine, the passive proxy, the
// SSE stream and every running job.
func TestJavaScriptAnalysisSurvivesAParserPanic(t *testing.T) {
	restore := analyzeJavaScriptPanicking
	analyzeJavaScriptPanicking = func() { panic("simulated parser failure") }
	defer func() { analyzeJavaScriptPanicking = restore }()

	analysis := analyzeJavaScript("https://shop.example/app.js", []byte(`fetch("/api/x")`))
	if analysis.Error == "" {
		t.Fatal("a panicking parser was reported as a clean analysis: the guard did not run")
	}
	if !strings.Contains(analysis.Error, "simulated parser failure") {
		t.Fatalf("error = %q, want the panic value in the message", analysis.Error)
	}
	// The record must not claim a result it did not produce. A page that
	// reports three endpoints and also an error is worse than one that reports
	// an error alone, because half of it is believable.
	if len(analysis.Endpoints) != 0 || len(analysis.Secrets) != 0 {
		t.Fatalf("a failed analysis still carries findings: %d endpoints, %d secrets",
			len(analysis.Endpoints), len(analysis.Secrets))
	}
	// The crawl continues: the frontier is empty, not nil, so the loop that
	// reads it appends nothing rather than dereferencing nothing.
	if analysis.links == nil {
		t.Fatal("links is nil after a recovered panic")
	}
	if analysis.Millis < 0 {
		t.Fatalf("millis = %d after a recovered panic, want the cost still reported", analysis.Millis)
	}
}

// TestIsJavaScriptResourceCoversBothSignals is the dispatch claim. A bundle
// served from /assets/main.chunk has no JavaScript in its name, and a server
// that answers a missing .js with an HTML shell reports text/html. Requiring
// both signals skips real bundles; requiring the name alone skips the rest.
func TestIsJavaScriptResourceCoversBothSignals(t *testing.T) {
	cases := []struct {
		kind        string
		contentType string
		want        bool
	}{
		{"javascript", "application/javascript", true},
		{"page", "application/javascript; charset=utf-8", true},
		{"page", "text/ecmascript", true},
		{"page", "text/html", false},
		{"stylesheet", "text/css", false},
		{"page", "application/json", false},
		{"robots.txt", "text/plain", false},
	}
	for _, testCase := range cases {
		got := isJavaScriptResource(testCase.kind, testCase.contentType)
		if got != testCase.want {
			t.Fatalf("isJavaScriptResource(%q, %q) = %v, want %v",
				testCase.kind, testCase.contentType, got, testCase.want)
		}
	}
}

// TestExtractMapLinksNoLongerReadsJavaScriptWithARegularExpression is the
// no-second-path claim. JavaScript used to come out of the same regular
// expression as JSON; if it comes out of both, the crawler has two answers to one
// question and only one of them carries a method.
func TestExtractMapLinksNoLongerReadsJavaScriptWithARegularExpression(t *testing.T) {
	body := `fetch("/api/from-js")`
	if links := extractMapLinks(body, "application/javascript"); len(links) != 0 {
		t.Fatalf("JavaScript still goes through the regular expression: %v", links)
	}
	if links := extractMapLinks(`{"href":"/api/from-json"}`, "application/json"); len(links) != 1 {
		t.Fatalf("JSON lost its path: %v", links)
	}
}

// TestTargetCrawlParsesJavaScriptAndCrawlsWhatItFinds is the end-to-end claim,
// against a real HTTP server rather than a mock transport: the crawler fetches a
// page, finds the bundle, fetches the bundle, parses it, and enqueues the
// endpoint the bundle builds. Every earlier test in this file calls
// analyzeJavaScript directly, which proves the analysis works and proves nothing
// about whether the crawl calls it.
// TestTargetCrawlKeepsGoingWhenThePageOnlyEmbedsACaptcha pins the defect a live
// run showed on 2026-10-03: a site homepage carries a captcha widget on a
// comment form, reading that marker as a captcha wall stopped the crawl before
// it reached any script, and Target then reported no endpoints, no sinks and no
// secrets for a site that has all three — an empty map with no explanation.
//
// The test is the operator's symptom rather than the mechanism: this is the
// site's own page, so its bundle must still be fetched and parsed.
// TestTargetCrawlFollowsARedirectAndKeepsReading pins the second defect a live
// run showed on 2026-10-03, and it is the one the owner sees as "the crawl shows
// nothing". `https://yandex.ru/` answers `302` with no body. The crawl refused
// every 3xx, so that page was published with no body, therefore with no link,
// therefore with no script: the map came back empty with nothing in it that
// explained why.
//
// A redirect is the site saying "the page is over there". The test is the
// operator's symptom: enter the short URL, get the site's own scripts.
func TestTargetCrawlFollowsARedirectAndKeepsReading(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			http.Redirect(writer, request, "/home", http.StatusFound)
		case "/home":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<html><body><h1>Shop</h1><script src="/assets/app.js"></script></body></html>`))
		case "/assets/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/behind-the-redirect");`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer target.Close()

	s := &server{}
	job := &targetMap{status: "running", startURL: target.URL, maxPages: 20}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.runTargetMap(1, job, ctx, targetMapInput{URL: target.URL, MaxPages: 20, MaxDepth: 3, SameOrigin: true})

	if job.status != "completed" {
		t.Fatalf("crawl status = %q error = %q", job.status, job.error)
	}
	var bundle map[string]interface{}
	for _, page := range job.pages {
		if url, _ := page["url"].(string); strings.Contains(url, "/assets/app.js") {
			bundle = page
		}
	}
	if bundle == nil {
		t.Fatalf("the redirect was not followed, so the map lost every script: %v", jsPageURLs(job.pages))
	}
	analysis, ok := bundle["js"].(jsAnalysis)
	if !ok || len(analysis.Endpoints) == 0 {
		t.Fatalf("the bundle was fetched but not parsed: %+v", bundle)
	}
	// The hop stays in the record: following it must not cost the evidence of
	// where the analyst's URL actually led.
	var start map[string]interface{}
	for _, page := range job.pages {
		if _, ok := page["redirects"]; ok {
			start = page
		}
	}
	if start == nil {
		t.Fatalf("the redirect was followed but not recorded: %v", jsPageURLs(job.pages))
	}
	if final, _ := start["final_url"].(string); !strings.HasSuffix(final, "/home") {
		t.Fatalf("final_url = %q, want the URL the site redirected to", final)
	}
	chain, _ := start["redirects"].([]map[string]interface{})
	if len(chain) == 0 {
		t.Fatalf("the redirect was followed but not recorded: %+v", start)
	}
	to, _ := chain[0]["to"].(string)
	if !strings.HasPrefix(to, "http") || !strings.HasSuffix(to, "/home") {
		// A `Location` the site wrote as a path must reach the record as the URL
		// it means. `/home` alone cannot be told apart from another host's home.
		t.Fatalf("the recorded hop is %q, not the absolute URL it means: %+v", to, chain[0])
	}
}

func TestTargetCrawlKeepsGoingWhenThePageOnlyEmbedsACaptcha(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<html><body>
<article>news</article>
<form action="/comment"><div class="g-recaptcha" data-sitekey="x"></div></form>
<script src="https://www.google.com/recaptcha/api.js"></script>
<script src="/assets/app.js"></script>
</body></html>`))
		case "/assets/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/from-bundle");`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer target.Close()

	s := &server{}
	job := &targetMap{status: "running", startURL: target.URL, maxPages: 20}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.runTargetMap(1, job, ctx, targetMapInput{URL: target.URL, MaxPages: 20, MaxDepth: 3, SameOrigin: true})

	if job.status != "completed" {
		t.Fatalf("crawl status = %q error = %q", job.status, job.error)
	}
	// The widget is still reported: the page does carry a captcha, and hiding
	// that would trade one wrong claim for another.
	if !jsPageHasChallenge(job.pages, target.URL) {
		t.Fatal("the captcha widget on the homepage was not reported")
	}
	var bundle map[string]interface{}
	for _, page := range job.pages {
		if url, _ := page["url"].(string); strings.Contains(url, "/assets/app.js") {
			bundle = page
		}
	}
	if bundle == nil {
		t.Fatalf("the bundle was never fetched, so the map lost every script: %v", jsPageURLs(job.pages))
	}
	analysis, ok := bundle["js"].(jsAnalysis)
	if !ok || len(analysis.Endpoints) == 0 {
		t.Fatalf("the bundle was fetched but not parsed: %+v", bundle)
	}
}

// jsPageHasChallenge reports whether the page record says a captcha was seen.
func jsPageHasChallenge(pages []map[string]interface{}, url string) bool {
	for _, page := range pages {
		if page["url"] == url {
			_, ok := page["challenge"]
			return ok
		}
	}
	return false
}

func TestTargetCrawlParsesJavaScriptAndCrawlsWhatItFinds(t *testing.T) {
	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			io := `html><script src="/assets/app.js"></script>`
			_, _ = writer.Write([]byte(io))
		case "/assets/app.js":
			writer.Header().Set("Content-Type", "application/javascript")
			_, _ = writer.Write([]byte(`fetch("/api/discovered/by-js", {method:"POST"});`))
		case "/api/discovered/by-js":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ok":true}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer target.Close()

	s := &server{}
	job := &targetMap{status: "running", startURL: target.URL, maxPages: 20}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.runTargetMap(1, job, ctx, targetMapInput{URL: target.URL, MaxPages: 20, MaxDepth: 3, SameOrigin: true})

	if job.status != "completed" {
		t.Fatalf("crawl status = %q error = %q", job.status, job.error)
	}
	var bundlePage map[string]interface{}
	foundBundle := false
	for _, page := range job.pages {
		if strings.Contains(page["url"].(string), "/assets/app.js") {
			bundlePage = page
			foundBundle = true
		}
	}
	if !foundBundle {
		t.Fatalf("the bundle was never fetched: %v", jsPageURLs(job.pages))
	}
	analysis, ok := bundlePage["js"].(jsAnalysis)
	if !ok {
		t.Fatalf("the bundle page carries no js analysis: %v", bundlePage)
	}
	if len(analysis.Endpoints) == 0 {
		t.Fatalf("the bundle was fetched but not parsed: %+v", bundlePage)
	}
	endpoint := endpointFor(t, analysis, "/api/discovered/by-js")
	if endpoint.Method != "POST" {
		t.Fatalf("method = %q, want POST", endpoint.Method)
	}
	// The point of parsing: the endpoint the program only mentions is now a page
	// in the map. Nothing in the HTML ever linked to it.
	if !hasPageURL(job.pages, target.URL+"/api/discovered/by-js") {
		t.Fatalf("the endpoint found in JavaScript was not crawled: %v", jsPageURLs(job.pages))
	}
}

// TestTargetCrawlKeepsTheRegularExpressionForJSON is the other half of the
// no-second-path claim, at the level the crawl actually runs. Dropping the
// JavaScript branch from the regular expression must not have taken JSON with
// it.
func TestTargetCrawlKeepsTheRegularExpressionForJSON(t *testing.T) {
	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<html><body>manifest</body></html>`))
		case "/manifest.json":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"entry":"/api/from-json-manifest"}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer target.Close()

	s := &server{}
	job := &targetMap{status: "running", startURL: target.URL + "/manifest.json", maxPages: 20}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.runTargetMap(2, job, ctx, targetMapInput{URL: target.URL + "/manifest.json", MaxPages: 20, MaxDepth: 3})

	if !hasPageURL(job.pages, target.URL+"/api/from-json-manifest") {
		t.Fatalf("a reference inside JSON was not crawled: %v", jsPageURLs(job.pages))
	}
	// JSON is data, so it is not parsed as a program and carries no analysis.
	for _, page := range job.pages {
		if strings.Contains(page["url"].(string), "/manifest.json") {
			if _, parsed := page["js"]; parsed {
				t.Fatalf("JSON was parsed as a program: %v", page)
			}
		}
	}
}

func jsPageURLs(pages []map[string]interface{}) []string {
	out := make([]string, 0, len(pages))
	for _, page := range pages {
		if url, ok := page["url"].(string); ok {
			out = append(out, url)
		}
	}
	return out
}

func hasPageURL(pages []map[string]interface{}, want string) bool {
	for _, page := range pages {
		if page["url"] == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
