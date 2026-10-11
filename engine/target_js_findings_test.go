package main

// Tests for the findings ported from zack0x01/JS-Analyser
// (`target_js_findings.go`) and for the credential rules that came with them.
//
// Every test states a claim the feature makes, and each one is written so that
// reverting the decision it checks turns it red. The fixture in
// `jsAnalyserFixtureSource` is the same file both original tools were run against
// before the port was written, so the expectations here are the upstream
// tool's measured output rather than what the code happens to produce.

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/BishopFox/jsluice"
)

// jsAnalyserFixtureSource is the 2019-byte fixture the original `jsluice` CLI
// and the original Python `JS-Analyser` were both run against. It carries one
// of everything the upstream analyser reports, plus `el.textContent = name` —
// a property assignment that is not a sink — so that a rule matching every
// `receiver.prop =` would be caught here.
const jsAnalyserFixtureSource = `// TODO: remove the legacy admin token before the launch
// SECURITY: the demo password is hardcoded below
/* FIXME: rotate the api key, see SEC-114 */
import { render as renderUtil } from './util.js';

const API_BASE = 'https://api.example.test';

const config = {
  apiKey: 'AIzaSyD-1234567890abcdefghijklmnopqrstu',
  slackToken: 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
  paypalToken: 'access_token$production$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh',
  stripePublishable: 'pk_live_51HxYzKLMNOqrstuvWXYZabcd',
  stripeSecret: 'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
  sessionToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  awsKeyId: 'AKIAZ4X7QWERTYUIOPAS',
};

const dbPassword = 'sup3r-s3cret-db-pass';
const userPassword = 'P@ssw0rd-admin-2024';

const supportEmail = 'security@corp-internal.test';

function renderProfile(user) {
  const box = document.getElementById('profile');
  box.innerHTML = '<b>' + user.name + '</b>';
  document.write('<p>' + user.bio + '</p>');
}

function gotoSearch(term) {
  location.search = '?q=' + term;
}

function unsafeEval() {
  eval('render(' + location.hash.substring(1) + ')');
}

function renderSafe(name) {
  const el = document.createElement('span');
  el.textContent = name;
  return el;
}

function loadComment(id) {
  $('#panel').html(loadBody(id));
  $.ajax({ url: '/api/comments/' + id, method: 'POST', data: { body: loadBody(id) } });
}

async function loadUser(id) {
  const response = await fetch('/api/v1/users/' + id, {
    method: 'GET',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
  });
  return response.json();
}
`

// fixtureFindings runs the ported pass over the shared fixture.
func fixtureFindings(t *testing.T) []jsFinding {
	t.Helper()
	return collectJSFindings(jsluice.NewAnalyzer([]byte(jsAnalyserFixtureSource)), []byte(jsAnalyserFixtureSource))
}

// findingFor returns the finding with the given kind and subject.
func findingFor(t *testing.T, findings []jsFinding, kind, subject string) jsFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.Kind == kind && finding.Subject == subject {
			return finding
		}
	}
	t.Fatalf("finding %s/%q not found among %d: %s", kind, subject, len(findings), jsFindingDump(findings))
	return jsFinding{}
}

func jsFindingDump(findings []jsFinding) string {
	parts := make([]string, 0, len(findings))
	for _, finding := range findings {
		parts = append(parts, finding.Kind+"/"+finding.Subject)
	}
	return strings.Join(parts, ", ")
}

// TestJavaScriptFindingsCoverEveryPortedCategory is the contract: the four
// categories that were ported are all present on the file the upstream analyser
// read. Removing any one query — or reverting the port entirely — leaves one of
// the four assertions without its subject.
func TestJavaScriptFindingsCoverEveryPortedCategory(t *testing.T) {
	findings := fixtureFindings(t)

	// The upstream tool reported six XSS rows on this file, two of them the
	// same line twice. The five distinct call sites are what the parse tree
	// can actually name, and one row per call site is the correction.
	if got := countKind(findings, jsFindingSink); got != 5 {
		t.Fatalf("sinks = %d, want 5 (innerHTML, document.write, location.search, eval, jQuery html): %s", got, jsFindingDump(findings))
	}
	// Two upstream xss_functions: the one with innerHTML/write and the one with
	// eval. `gotoSearch` (location.search) and `loadComment` (jQuery) were not
	// in that list upstream, and are not invented here.
	if got := countKind(findings, jsFindingFunction); got != 2 {
		t.Fatalf("functions = %d, want 2 (renderProfile, unsafeEval): %s", got, jsFindingDump(findings))
	}
	if got := countKind(findings, jsFindingComment); got != 3 {
		t.Fatalf("comments = %d, want 3 (TODO, SECURITY, FIXME): %s", got, jsFindingDump(findings))
	}
	if got := countKind(findings, jsFindingEmail); got != 1 {
		t.Fatalf("emails = %d, want 1: %s", got, jsFindingDump(findings))
	}
}

func countKind(findings []jsFinding, kind string) int {
	total := 0
	for _, finding := range findings {
		if finding.Kind == kind {
			total++
		}
	}
	return total
}

// TestJavaScriptSinkSeveritiesAndFunctions checks the parts of a sink record an
// analyst acts on: which write it is, how serious, and inside which function.
func TestJavaScriptSinkSeveritiesAndFunctions(t *testing.T) {
	findings := fixtureFindings(t)

	html := findingFor(t, findings, jsFindingSink, "box.innerHTML")
	if html.Severity != jsSeverityHigh {
		t.Fatalf("innerHTML severity = %q, want %q", html.Severity, jsSeverityHigh)
	}
	if html.Function != "renderProfile" {
		t.Fatalf("innerHTML function = %q, want renderProfile", html.Function)
	}
	// The line is read by locating the evidence in the file, so it is the line a
	// person would open.
	if html.Line != 25 {
		t.Fatalf("innerHTML line = %d, want 25 (evidence %q)", html.Line, html.Evidence)
	}

	// `eval('render(' + location.hash…)` reads from the address bar, so it is the
	// one sink that outranks a DOM write.
	evaluated := findingFor(t, findings, jsFindingSink, "eval")
	if evaluated.Severity != jsSeverityCritical {
		t.Fatalf("eval severity = %q, want %q (its argument names location.hash)", evaluated.Severity, jsSeverityCritical)
	}
	if evaluated.Function != "unsafeEval" {
		t.Fatalf("eval function = %q, want unsafeEval", evaluated.Function)
	}

	// Navigation is a redirect, not script execution in the origin.
	navigation := findingFor(t, findings, jsFindingSink, "location.search")
	if navigation.Severity != jsSeverityMedium {
		t.Fatalf("location.search severity = %q, want %q", navigation.Severity, jsSeverityMedium)
	}

	function := findingFor(t, findings, jsFindingFunction, "renderProfile")
	if function.Severity != jsSeverityHigh {
		t.Fatalf("renderProfile severity = %q, want %q", function.Severity, jsSeverityHigh)
	}
}

// TestJavaScriptSinksIgnoreNonSinkAssignments is the false-positive contract.
// `el.textContent = name` is the same tree shape as `box.innerHTML = …`; the
// difference is the property name. A matcher that fired on the shape would
// report every assignment in every bundle.
func TestJavaScriptSinksIgnoreNonSinkAssignments(t *testing.T) {
	findings := fixtureFindings(t)
	for _, finding := range findings {
		if finding.Kind == jsFindingSink && finding.Subject == "el.textContent" {
			t.Fatalf("textContent reported as a sink: %+v", finding)
		}
	}
}

// TestJavaScriptEvalWithoutUserInputIsNotCritical keeps `critical` meaningful.
// Upstream calls any `eval` "with user input"; a program that evaluates a
// constant is still a sink, but it is not the finding an analyst drops
// everything else for.
func TestJavaScriptEvalWithoutUserInputIsNotCritical(t *testing.T) {
	source := "function total() {\n  return eval('1+1');\n}\n"
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	evaluated := findingFor(t, findings, jsFindingSink, "eval")
	if evaluated.Severity != jsSeverityHigh {
		t.Fatalf("eval('1+1') severity = %q, want %q", evaluated.Severity, jsSeverityHigh)
	}
}

// TestJavaScriptFindingsNameArrowFunctionsAndObjectMethods covers the two shapes
// a declaration does not carry a name for. The name lives on whatever holds the
// function, and a report that says "a function" instead of "renderRow" is a
// report the analyst has to go and find by hand.
func TestJavaScriptFindingsNameArrowFunctionsAndObjectMethods(t *testing.T) {
	source := `const renderRow = (row) => {
  row.el.innerHTML = row.html;
};
const view = {
  paint(node) {
    node.outerHTML = node.outerHTML;
  },
};
`
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	arrow := findingFor(t, findings, jsFindingSink, "row.el.innerHTML")
	if arrow.Function != "renderRow" {
		t.Fatalf("arrow function = %q, want renderRow", arrow.Function)
	}
	method := findingFor(t, findings, jsFindingSink, "node.outerHTML")
	if method.Function != "paint" {
		t.Fatalf("object method = %q, want paint", method.Function)
	}
}

// TestJavaScriptFindingsReadReactAndJQuerySinks covers the two sinks the object
// and chain queries exist for.
func TestJavaScriptFindingsReadReactAndJQuerySinks(t *testing.T) {
	source := `function Comment({ text }) {
  const props = { dangerouslySetInnerHTML: { __html: text } };
  jQuery('#panel').append(text);
  return props;
}
`
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	react := findingFor(t, findings, jsFindingSink, jsReactSinkProperty)
	if react.Severity != jsSeverityHigh {
		t.Fatalf("dangerouslySetInnerHTML severity = %q, want %q", react.Severity, jsSeverityHigh)
	}
	jquery := findingFor(t, findings, jsFindingSink, "jQuery(...).append")
	if jquery.Severity != jsSeverityMedium {
		t.Fatalf("jQuery append severity = %q, want %q", jquery.Severity, jsSeverityMedium)
	}
}

// TestJavaScriptCommentCategoriesAreAnchored states the deliberate narrowing: a
// marker at the head of a comment is a finding, the same word in the middle of a
// sentence is not, and a comment that says neither is not reported at all.
func TestJavaScriptCommentCategoriesAreAnchored(t *testing.T) {
	source := `// TODO: rotate
/* SECURITY: do not ship */
// password: the seed account
// this bundle handles the auth token on every request
// just a comment
`
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	if got := countKind(findings, jsFindingComment); got != 2 {
		t.Fatalf("interesting comments = %d, want 2 (TODO, SECURITY): %s", got, jsFindingDump(findings))
	}
	if got := countKind(findings, jsFindingSuspicious); got != 1 {
		t.Fatalf("suspicious comments = %d, want 1: %s", got, jsFindingDump(findings))
	}
	suspicious := findingFor(t, findings, jsFindingSuspicious, "password")
	if suspicious.Severity != jsSeverityMedium {
		t.Fatalf("suspicious comment severity = %q, want %q", suspicious.Severity, jsSeverityMedium)
	}
	// The comment nobody acts on must not reach the record.
	for _, finding := range findings {
		if finding.Kind == jsFindingComment && finding.Evidence == "just a comment" {
			t.Fatalf("a comment with no marker was reported: %+v", finding)
		}
	}
}

// TestJavaScriptEmailsComeFromStringLiteralsOnce states both halves of the email
// rule: one row per address however many times it appears, and an address
// inside a comment is not an address a program carries.
func TestJavaScriptEmailsComeFromStringLiteralsOnce(t *testing.T) {
	source := `// reachable at abuse@corp-internal.test
const first = 'ops@corp-internal.test';
const second = "ops@corp-internal.test";
const third = 'not-an-address';
`
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	emails := 0
	for _, finding := range findings {
		if finding.Kind == jsFindingEmail {
			emails++
			if finding.Subject != "ops@corp-internal.test" {
				t.Fatalf("unexpected address %q", finding.Subject)
			}
		}
	}
	if emails != 1 {
		t.Fatalf("emails = %d, want 1 (deduplicated, comment excluded)", emails)
	}
}

// TestJavaScriptFindingsFoldRepeatedWrites is the minified-bundle contract. A
// file that repeats one write reports it once with a count, the same way
// `mergeJSEndpoints` folds twenty thousand copies of one endpoint: the record is
// a table a person reads, and twenty thousand identical rows are a denial of
// service against that table.
func TestJavaScriptFindingsFoldRepeatedWrites(t *testing.T) {
	var builder strings.Builder
	for index := 0; index < 25; index++ {
		builder.WriteString("function paint" + itoa(index) + "(el, html) { el.innerHTML = html; }\n")
	}
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(builder.String())), []byte(builder.String()))
	if got := countKind(findings, jsFindingSink); got != 25 {
		t.Fatalf("sinks = %d, want 25 distinct receivers", got)
	}

	var repeated strings.Builder
	for index := 0; index < 25; index++ {
		repeated.WriteString("el.innerHTML = html;\n")
	}
	folded := collectJSFindings(jsluice.NewAnalyzer([]byte(repeated.String())), []byte(repeated.String()))
	if got := countKind(folded, jsFindingSink); got != 1 {
		t.Fatalf("identical writes = %d rows, want 1 folded row", got)
	}
	if row := findingFor(t, folded, jsFindingSink, "el.innerHTML"); row.Count != 25 {
		t.Fatalf("folded count = %d, want 25", row.Count)
	}
}

// itoa keeps the fixture builder free of strconv in every test.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

// TestJavaScriptFindingsSurviveUnparsableInput keeps the record honest about
// rubbish. A file that is not JavaScript must produce an empty list, never a
// panic and never a null the browser has to guard against.
func TestJavaScriptFindingsSurviveUnparsableInput(t *testing.T) {
	for _, source := range []string{"", "<<<>>>", "\x00\x01\x02", "'unterminated"} {
		findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
		if len(findings) != 0 {
			t.Fatalf("source %q produced %d findings: %s", source, len(findings), jsFindingDump(findings))
		}
	}
}

// TestJavaScriptAnalysisCarriesTheFindingsThrough is the glue assertion, and it
// is the one that catches the wiring rather than the analysis. Every other test
// in this file calls `collectJSFindings` directly, so a build where the crawl
// stopped calling it — a commented line, a dropped assignment — would leave all
// of them green while the product reported nothing. This one goes through
// `analyzeJavaScript`, which is what the crawler actually runs.
func TestJavaScriptAnalysisCarriesTheFindingsThrough(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/app.js", []byte(jsAnalyserFixtureSource))
	if len(analysis.Findings) == 0 {
		t.Fatal("the crawl produced a page record with no findings")
	}
	if got := countKind(analysis.Findings, jsFindingSink); got != 5 {
		t.Fatalf("sinks through the crawl = %d, want 5: %s", got, jsFindingDump(analysis.Findings))
	}
	if got := countKind(analysis.Findings, jsFindingEmail); got != 1 {
		t.Fatalf("emails through the crawl = %d, want 1", got)
	}
	// The crawl frontier is still the parser's business: the sink pass reads the
	// same tree and must not have replaced it.
	if !hasLink(analysis.links, "https://example.test/api/comments/EXPR") &&
		len(analysis.Endpoints) == 0 {
		t.Fatalf("endpoints disappeared from the record: %s", jsEndpointDump(analysis))
	}
}

// TestJavaScriptAnalysisSerialisesEmptyFindings states that an analysed file
// with nothing in it says so, and does not say it with a missing key: the
// browser and every export read this record.
func TestJavaScriptAnalysisSerialisesEmptyFindings(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/plain.js", []byte("export const x = 1;\n"))
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"findings":[]`) {
		t.Fatalf("record has no empty findings list: %s", encoded)
	}
}

// TestJavaScriptFindingLinesAreTheLinesInTheFile states the line number, which
// is the part of the record a person acts on. It is computed by locating the
// evidence in the bytes the crawler already holds, and the first version of that
// search was off by one on every finding — this test is what makes that a red
// build instead of a silently wrong report.
func TestJavaScriptFindingLinesAreTheLinesInTheFile(t *testing.T) {
	lines := strings.Split(jsAnalyserFixtureSource, "\n")
	for _, finding := range fixtureFindings(t) {
		if finding.Line <= 0 || finding.Line > len(lines) {
			t.Fatalf("%s/%s reports line %d, file has %d lines", finding.Kind, finding.Subject, finding.Line, len(lines))
		}
		// The evidence is the source collapsed onto one line, so a finding whose
		// line does not contain its own evidence is pointing somewhere else.
		if !strings.Contains(lines[finding.Line-1], firstWord(finding.Evidence)) {
			t.Fatalf("%s/%s claims line %d (%q) which does not contain %q",
				finding.Kind, finding.Subject, finding.Line, lines[finding.Line-1], firstWord(finding.Evidence))
		}
	}
}

// firstWord is the first token of an evidence string, long enough to be
// distinctive and short enough to survive the whitespace collapse.
func firstWord(evidence string) string {
	fields := strings.Fields(evidence)
	if len(fields) == 0 {
		return ""
	}
	if len(fields[0]) > 12 {
		return fields[0][:12]
	}
	return fields[0]
}

// TestJavaScriptCredentialsFromThePortedRules is the glue: the credential
// categories are not findings of this file, they are rules, and the rule set the
// crawler runs over the parse tree is the same one the OSINT scan runs over
// text. The five rules below are the ones the upstream analyser reported on the
// fixture and that neither `jsSecretKinds` nor the pre-existing registry knew.
func TestJavaScriptCredentialsFromThePortedRules(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/app.js", []byte(jsAnalyserFixtureSource))
	want := []string{
		"google_api_key",
		"aws_access_key_id",
		"stripe_secret_key",
		"stripe_publishable_key",
		"slack_token",
		"paypal_token",
		"jwt_token",
		"hardcoded_password",
	}
	for _, rule := range want {
		if !hasRule(analysis.Secrets, rule) {
			t.Fatalf("rule %q not reported, got %v", rule, secretRulesOf(analysis.Secrets))
		}
	}
}

// TestJavaScriptPasswordRuleReportsTheValueNotTheName is the point of an
// assignment-shaped rule. The name is what makes the pattern match; the value is
// what the analyst has to act on. A rule that reported the name would report
// `dbPassword` on every line of every bundle.
func TestJavaScriptPasswordRuleReportsTheValueNotTheName(t *testing.T) {
	source := "const dbPassword = 'sup3r-s3cret-db-pass';\n"
	analysis := analyzeJavaScript("https://example.test/creds.js", []byte(source))
	found := false
	for _, secret := range analysis.Secrets {
		if secret.Rule == "hardcoded_password" {
			found = true
			if secret.Value != "sup3r-s3cret-db-pass" {
				t.Fatalf("password value = %q, want the value, not the variable name", secret.Value)
			}
			if secret.Line != 1 {
				t.Fatalf("password line = %d, want 1", secret.Line)
			}
		}
	}
	if !found {
		t.Fatalf("no hardcoded_password finding: %v", secretRulesOf(analysis.Secrets))
	}
}

// TestJavaScriptPasswordRuleIgnoresBooleansAndPlaceholders keeps the credential
// rule from accusing a form of naming its fields. Upstream's own filter list
// carries `password: false`, `password: null` and `your_api_key` for this
// reason; here the same three cases must not become findings.
func TestJavaScriptPasswordRuleIgnoresBooleansAndPlaceholders(t *testing.T) {
	source := `const password = false;
const password2 = null;
const apiKey = 'your_api_key_here';
`
	analysis := analyzeJavaScript("https://example.test/form.js", []byte(source))
	if hasRule(analysis.Secrets, "hardcoded_password") {
		t.Fatalf("a boolean field named password became a credential: %v", secretRulesOf(analysis.Secrets))
	}
}

// TestSecretAssignmentRulesReportOneFindingPerLine states the correction to the
// upstream double report: `dbPassword = '…'` matched upstream's `password`
// pattern and its `db_password` pattern, so one line produced two findings
// saying the same thing.
func TestSecretAssignmentRulesReportOneFindingPerLine(t *testing.T) {
	source := "const dbPassword = 'sup3r-s3cret-db-pass';\n"
	findings := applySecretRules(source, "owner/app", "abc123")
	total := 0
	for _, finding := range findings {
		if finding.rule == "hardcoded_password" {
			total++
		}
	}
	if total != 1 {
		t.Fatalf("hardcoded_password findings = %d, want 1: %+v", total, findings)
	}
}

// TestJWTRuleNeedsThreeRealSegments is the filter upstream applied in code,
// moved into the pattern. A base64 payload that happens to start with `eyJ` must
// not become a token.
func TestJWTRuleNeedsThreeRealSegments(t *testing.T) {
	short := "const blob = 'eyJhbGciOiJIUzI1NiJ9';\n"
	if containsRuleName(applySecretText(short), "jwt_token") {
		t.Fatalf("a single JWT segment was reported as a token")
	}
	long := "const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV';\n"
	if !containsRuleName(applySecretText(long), "jwt_token") {
		t.Fatalf("a three-segment JWT was not reported")
	}
}

// applySecretText runs the text scan over one string and returns its rules.
func applySecretText(source string) []string {
	findings := applySecretRules(source, "owner/app", "abc123")
	rules := make([]string, 0, len(findings))
	for _, finding := range findings {
		rules = append(rules, finding.rule)
	}
	return rules
}

// containsRuleName reports whether a list of rule names contains one. The
// `[]jsSecret` helper in target_javascript_test.go answers the same question for
// the analysis record; this one answers it for the raw text scan, which has no
// record type of its own.
func containsRuleName(rules []string, want string) bool {
	for _, rule := range rules {
		if rule == want {
			return true
		}
	}
	return false
}

// TestJavaScriptEmailsAreFoundInTemplateLiterals is a measured regression, not a
// hypothesis. The OWASP Juice Shop bundles were run through this port and through
// the original analyser: the application's own addresses appear in
// `(template_string)` twelve times and in `(string)` zero times, so a query that
// reads only string literals reports no address at all in the application that
// ships them on purpose.
func TestJavaScriptEmailsAreFoundInTemplateLiterals(t *testing.T) {
	source := "const accounts = {testingUsername: `testing@juice-sh.op`, admin: 'admin@juice-sh.op'};\n"
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	seen := map[string]bool{}
	for _, finding := range findings {
		if finding.Kind == jsFindingEmail {
			seen[finding.Subject] = true
		}
	}
	for _, want := range []string{"testing@juice-sh.op", "admin@juice-sh.op"} {
		if !seen[want] {
			t.Fatalf("address %q not found among %v", want, seen)
		}
	}
}

// TestJavaScriptDocumentWriteOnAnOpenedWindow covers the shape that a receiver
// test reading only the identifier `document` misses. Measured on the Juice Shop
// main bundle: `window.open(“,`_blank`,`width=500`)?.document.write(this.userData)`.
func TestJavaScriptDocumentWriteOnAnOpenedWindow(t *testing.T) {
	source := "function openPrint() {\n  window.open('', '_blank', 'width=500')?.document.write(this.userData);\n}\n"
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	found := findingFor(t, findings, jsFindingSink, "document.write")
	if found.Severity != jsSeverityHigh {
		t.Fatalf("document.write severity = %q, want %q", found.Severity, jsSeverityHigh)
	}
	if found.Function != "openPrint" {
		t.Fatalf("document.write function = %q, want openPrint", found.Function)
	}
}

// TestJavaScriptEventHandlerAssignmentsAreSinks covers the category upstream
// listed among its function patterns and we had no rule for at all: a handler
// attached by assignment is the same code execution as a handler written in
// markup. The set is measured rather than a prefix test — see
// `jsEventHandlerProperties`, where `onTouched` is the counter-example.
func TestJavaScriptEventHandlerAssignmentsAreSinks(t *testing.T) {
	source := `function wire(img) {
  img.onerror = function () { console.log('broken'); };
  el.onclick = loadRow;
  card.onTouched = notify;
}
`
	findings := collectJSFindings(jsluice.NewAnalyzer([]byte(source)), []byte(source))
	for _, want := range []string{"img.onerror", "el.onclick"} {
		finding := findingFor(t, findings, jsFindingSink, want)
		if finding.Severity != jsSeverityMedium {
			t.Fatalf("%s severity = %q, want %q", want, finding.Severity, jsSeverityMedium)
		}
		if finding.Function != "wire" {
			t.Fatalf("%s function = %q, want wire", want, finding.Function)
		}
	}
	// An Angular event binding is not a DOM handler and must stay unreported.
	for _, finding := range findings {
		if finding.Kind == jsFindingSink && strings.Contains(finding.Subject, "onTouched") {
			t.Fatalf("an Angular binding was reported as a DOM handler: %+v", finding)
		}
	}
}

// TestJavaScriptTranslationLabelsAreNotCredentials is a false positive found on
// a live target, not a thought experiment: the translation bundle of vk.com
// carries `"guest_password":"Password"`, `"login_enter":"Sign in"` and four more
// labels, and all six were reported as hardcoded credentials. The fix is a shape
// requirement on the value — a credential has a digit as well as letters and is
// one token rather than a sentence — and it applies to the tree path and the
// text path alike, because two answers to one question is how a rule starts
// disagreeing with itself.
func TestJavaScriptTranslationLabelsAreNotCredentials(t *testing.T) {
	// Тільки підписи. Справжні паролі у цьому ж файлі перевіряє наступний
	// тест: мішати їх тут означало б, що тест очікує нуль від файлу, де нуль
	// неправильна відповідь.
	source := `const strings = {
  guest_password: "Password",
  login_enter: "Sign in",
  password_placeholder: "Enter the password",
  login_wrong_email_pwd: "Incorrect login or password.",
};
`
	analysis := analyzeJavaScript("https://vk.com/lang3.js", []byte(source))
	if len(analysis.Secrets) != 0 {
		t.Fatalf("a translation label was reported as a credential: %v", secretRulesOf(analysis.Secrets))
	}
}

// TestJavaScriptCodeSplitKeysAreNotCredentials is the second false positive the
// live target showed: the vk.com loader carries `"entry/web/login":"9ab740b017dee983"`
// — a code-splitting map, where the value is a module id. An unanchored rule
// matched the `login:` at the tail of that key and accused the file of carrying a
// hardcoded username. The rule has to match the whole name.
func TestJavaScriptCodeSplitKeysAreNotCredentials(t *testing.T) {
	source := `const chunks = {
  "entry/web/likes": "696c4331f39945c8",
  "entry/web/login": "9ab740b017dee983",
};
`
	analysis := analyzeJavaScript("https://vk.com/loader.js", []byte(source))
	if len(analysis.Secrets) != 0 {
		t.Fatalf("a code-splitting map was read as credentials: %v", secretRulesOf(analysis.Secrets))
	}
}

// TestJavaScriptRealCredentialsSurviveTheShapeRequirement is the other half: a
// filter that rejects everything is not a filter. Both values from the fixture
// the original analyser was measured on must still be reported.
func TestJavaScriptRealCredentialsSurviveTheShapeRequirement(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/app.js", []byte(jsAnalyserFixtureSource))
	count := 0
	for _, secret := range analysis.Secrets {
		if secret.Rule == "hardcoded_password" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("hardcoded_password findings = %d, want 2 (the fixture's two real passwords): %v",
			count, secretRulesOf(analysis.Secrets))
	}
}

// The three categories below are the ports of the parts of the three originals
// that this project's analysis did not answer at all:
//
//   - `tools/jsvar.sh`      (KathanP19/JSFScan.sh, step 7) — variable names
//   - `tools/findomxss.sh`  (KathanP19/JSFScan.sh, step 8) — DOM XSS sources
//   - `jsurls-sinks`        (BishopFox/jsluice)          — request call sites
//
// The fixture is one file carrying one instance of each, so a missing port is a
// zero count rather than a count that happens to be equal.

func TestEveryVariableShapeIsReportedNotJustVarDeclarations(t *testing.T) {
	source := "var configUrl = 1;\nlet settingsRef = 2;\nconst sessionKey = 3;\n" +
		"window.overlayRoot = 4;\nvar config = { cacheDir: 5 };\nvar x = 1;\n"
	analysis := analyzeJavaScript("https://example.test/vars.js", []byte(source))
	byName := make(map[string]jsVariable)
	for _, variable := range analysis.Variables {
		byName[variable.Name] = variable
	}
	for _, want := range []struct{ name, kind string }{
		{"configUrl", "declaration"},
		{"settingsRef", "declaration"},
		{"sessionKey", "declaration"},
		{"overlayRoot", "assignment"},
		{"cacheDir", "property"},
	} {
		got, ok := byName[want.name]
		if !ok {
			t.Errorf("variable %q missing, got %v", want.name, variableNames(analysis.Variables))
			continue
		}
		if got.Kind != want.kind {
			t.Errorf("variable %q kind = %q, want %q", want.name, got.Kind, want.kind)
		}
		if got.Line == 0 {
			t.Errorf("variable %q has no line", want.name)
		}
	}
	// Upstream's own floor: `awk 'length($1) >= 3'`. A two-letter name is a loop
	// counter, and a wordlist of loop counters is a wordlist of noise.
	if _, present := byName["x"]; present {
		t.Errorf("a two-character name was reported, upstream's length floor was dropped")
	}
}

// `jsvar.sh` greps `var NAME` out of the text. A bundle written as ES6 has almost
// no `var`, so this is the row where "the original answers and we answer nothing"
// would have read as "there was nothing to find".
func TestVariablesCoverLetConstAndAssignmentsWhereVarGrepFindsNothing(t *testing.T) {
	source := "let handlerRef = 1;\nconst overlayNode = 2;\n"
	analysis := analyzeJavaScript("https://example.test/es6.js", []byte(source))
	if len(analysis.Variables) != 2 {
		t.Fatalf("variables = %v, want handlerRef and overlayNode", variableNames(analysis.Variables))
	}
	imported := upstreamVarGrepCount(source)
	if imported != 0 {
		t.Fatalf("the fixture is not the shape this test claims: upstream grep found %d", imported)
	}
}

// upstreamVarGrepCount is `jsvar.sh`'s own line, so the test above can prove the
// fixture is one the original reports nothing for rather than assuming it.
func upstreamVarGrepCount(source string) int {
	count := 0
	for _, line := range strings.Split(source, "\n") {
		for _, name := range jsVarGrep.FindAllString(line, -1) {
			if len(strings.TrimSpace(name)) >= 3 {
				count++
			}
		}
	}
	return count
}

var jsVarGrep = regexp.MustCompile(`var\s+([a-zA-Z0-9_]+)`)

func variableNames(variables []jsVariable) []string {
	names := make([]string, 0, len(variables))
	for _, variable := range variables {
		names = append(names, variable.Name)
	}
	return names
}

// `findomxss.sh`'s pattern is `(document|location|window)\.(URL|documentURI|
// search|hash|referrer|(location\.)?href|name)`. Upstream greps text; this port
// asks the tree, so a source named inside a string or a comment is not a finding.
func TestEveryDomSourceFindomxssNamesIsReported(t *testing.T) {
	source := "var a = document.URL;\nvar b = location.search;\nvar c = document.referrer;\n" +
		"var d = window.name;\nvar e = window.location.href;\nvar f = location.hash;\n" +
		"var g = document.documentURI;\n// location.hash in a comment\nvar h = 'document.URL';\n"
	analysis := analyzeJavaScript("https://example.test/dom.js", []byte(source))
	found := make(map[string]bool)
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingDOMSource {
			found[finding.Subject] = true
		}
	}
	for _, want := range []string{
		"document.URL", "location.search", "document.referrer", "window.name",
		"window.location.href", "location.hash", "document.documentURI",
	} {
		if !found[want] {
			t.Errorf("DOM source %q not reported, got %v", want, findingSubjects(analysis.Findings, jsFindingDOMSource))
		}
	}
	// The two false positives a text grep produces on this very source. Upstream
	// reports them too — that is why this is a port and not a copy of the bug.
	if found["'document.URL'"] || strings.Contains(strings.Join(findingSubjects(analysis.Findings, jsFindingDOMSource), " "), "comment") {
		t.Errorf("a source named inside a string or a comment was reported: %v",
			findingSubjects(analysis.Findings, jsFindingDOMSource))
	}
}

// A DOM source carries no severity of its own; what makes it actionable is the
// sink it reaches, and the enclosing function is what names the code to read.
func TestADomSourceCarriesTheEnclosingFunction(t *testing.T) {
	source := "function readFragment() {\n  var page = location.hash;\n  return page;\n}\n"
	analysis := analyzeJavaScript("https://example.test/dom2.js", []byte(source))
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingDOMSource && finding.Subject == "location.hash" {
			if finding.Function != "readFragment" {
				t.Fatalf("function = %q, want readFragment", finding.Function)
			}
			if finding.Severity != jsSeverityMedium {
				t.Fatalf("severity = %q, want %q", finding.Severity, jsSeverityMedium)
			}
			return
		}
	}
	t.Fatalf("no location.hash finding: %v", findingSubjects(analysis.Findings, jsFindingDOMSource))
}

// `jsurls-sinks` is jsluice's own answer to "which call site carries this URL".
// Reporting only the URL loses the difference between `$.get('/api/x')` and
// `$.post('/api/x')`, which is the whole question that mode exists to answer.
// The subject is upstream's own output format, read off
// `cmd/jsurls-sinks/main.go`: `fmt.Printf("%s (arg %d)\n", callName, position)`.
// The first version of this test asserted bare callee names, and it was the test
// that was wrong — the port produces what the original prints.
//
// `$.ajax({url: '/api/five'})` is deliberately absent from the expectations.
// Upstream's rule requires a *string literal* argument (`startsWithString` reads
// the node's first byte), and an options object is not one, so the original does
// not report it either. Claiming it would be us covering more than the original.
func TestEveryRequestCallSiteIsReportedInTheOriginalsOwnFormat(t *testing.T) {
	source := "fetch('/api/one');\n$.get('/api/two');\n$.post('/api/three');\n" +
		"$.getJSON('/api/four');\n$.ajax({url: '/api/five'});\naxios.get('/api/six');\n" +
		"axios.post('/api/seven');\nvar x = new XMLHttpRequest();\nx.open('POST', '/api/eight');\n"
	analysis := analyzeJavaScript("https://example.test/calls.js", []byte(source))
	found := make(map[string]bool)
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingRequestCall {
			found[finding.Subject] = true
		}
	}
	for _, want := range []string{
		// `x.open`, not `XMLHttpRequest.open`: upstream reports the callee the
		// bundle spells, and a variable is named by its binding.
		"fetch (arg 0)", "$.get (arg 0)", "$.post (arg 0)", "$.getJSON (arg 0)",
		"axios.get (arg 0)", "axios.post (arg 0)", "x.open (arg 1)",
	} {
		if !found[want] {
			t.Errorf("request call %q not reported, got %v", want, findingSubjects(analysis.Findings, jsFindingRequestCall))
		}
	}
	if found["$.ajax (arg 0)"] {
		t.Error("$.ajax with an options object was reported; upstream does not report it")
	}
}

// The position counts named arguments only — upstream's `arg.IsNamed()` — so
// `xhr.open('POST', url)` is `(arg 1)`. Counting raw children instead shifts
// every call with a non-argument child by one.
func TestTheArgumentPositionCountsNamedArgumentsLikeUpstream(t *testing.T) {
	source := "x.open('POST', '/api/eight');\n"
	analysis := analyzeJavaScript("https://example.test/pos.js", []byte(source))
	found := findingSubjects(analysis.Findings, jsFindingRequestCall)
	if len(found) != 1 || found[0] != "x.open (arg 1)" {
		t.Fatalf("findings = %v, want [x.open (arg 1)]", found)
	}
}

// `couldBePath` upstream keeps its length floors: `/` and `/a` are not request
// targets there, and importing them here would make every short string a call.
func TestShortStringsAreNotRequestPathsLikeUpstream(t *testing.T) {
	source := "log('/a');\ntrack('/');\nload('/ab');\nfetch('/api/real');\n"
	analysis := analyzeJavaScript("https://example.test/short.js", []byte(source))
	found := findingSubjects(analysis.Findings, jsFindingRequestCall)
	if len(found) != 1 || found[0] != "fetch (arg 0)" {
		t.Fatalf("findings = %v, want only fetch (arg 0): upstream's floors are len > 3 for a path", found)
	}
}

// The second of upstream's two shapes: a plain assignment whose right side is a
// path. `basePath = '/api/v2'` names where the program's requests start, and no
// endpoint row carries it.
func TestAPathAssignmentIsReportedTheWayUpstreamReportsIt(t *testing.T) {
	source := "basePath = '/api/v2';\nvar counter = 7;\n"
	analysis := analyzeJavaScript("https://example.test/assign.js", []byte(source))
	found := findingSubjects(analysis.Findings, jsFindingRequestCall)
	if len(found) != 1 || found[0] != "basePath (assignment)" {
		t.Fatalf("findings = %v, want [basePath (assignment)]", found)
	}
}

// Calling `fetch` is not a defect. A category that reports it as one is a
// category an analyst learns to skip, and the severity is the difference.
func TestARequestCallIsInfoAndNotAVulnerability(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/info.js", []byte("fetch('/api/x');\n"))
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingRequestCall && finding.Severity != jsSeverityInfo {
			t.Fatalf("severity = %q, want %q: calling fetch is not a defect", finding.Severity, jsSeverityInfo)
		}
	}
}

// The tree walk must not be an open door: a member call that is not a request
// call is not reported, or every `element.classList.add` on a live bundle is a
// finding.
func TestNonRequestMemberCallsAreNotRequestCalls(t *testing.T) {
	source := "element.classList.add('x');\nrender();\nwidget.configure(1);\n"
	analysis := analyzeJavaScript("https://example.test/other.js", []byte(source))
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingRequestCall {
			t.Fatalf("non-request call reported: %s", finding.Subject)
		}
	}
}

// `document.cookie` is not in `findomxss.sh`'s pattern, and this port does not
// add it: it is a claim about the original that the original does not make. The
// `eval` taint rule reads it instead.
func TestDocumentCookieIsNotInventedIntoTheDomSourceSet(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/cookie.js", []byte("var c = document.cookie;\n"))
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingDOMSource && finding.Subject == "document.cookie" {
			t.Fatalf("document.cookie was reported as a dom_source, which upstream's pattern does not list")
		}
	}
}

func findingSubjects(findings []jsFinding, kind string) []string {
	subjects := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.Kind == kind {
			subjects = append(subjects, finding.Subject)
		}
	}
	return subjects
}

// A file with no names still has to answer. A missing key and an empty list are
// different claims, and the second one is a claim about the file.
func TestTheVariableListIsEmptyAndNotAbsentWhenThereAreNoNames(t *testing.T) {
	analysis := analyzeJavaScript("https://example.test/empty.js", []byte("fetch('/api/x');\n"))
	if analysis.Variables == nil {
		t.Fatal("variables is nil: a consumer cannot tell an empty file from a key that was never written")
	}
	if len(analysis.Variables) != 0 {
		t.Fatalf("variables = %v, want none", variableNames(analysis.Variables))
	}
}

// `secretValueIsUsable` requires a digit as well as a letter, which threw away
// `login = 'admin_root'` and `userName = 'svc_moderator'` — measured on the
// capability fixture, where JS-Analyser reported both and this project reported
// neither. A username is the one credential that routinely has no digit in it.
func TestAnAlphabeticUsernameIsNotThrownAwayByTheShapeCheck(t *testing.T) {
	source := "var login = 'admin_root';\nvar userName = 'svc_moderator';\n"
	analysis := analyzeJavaScript("https://example.test/user.js", []byte(source))
	found := make(map[string]bool)
	for _, secret := range analysis.Secrets {
		if secret.Rule == "hardcoded_username" {
			found[secret.Value] = true
		}
	}
	for _, want := range []string{"admin_root", "svc_moderator"} {
		if !found[want] {
			t.Errorf("username %q not reported, got %v", want, secretValues(analysis.Secrets))
		}
	}
}

// The digit-and-letter shape check is what keeps `password: "true"` out of the
// findings, so lifting it for usernames must not have lifted it for passwords.
func TestAPasswordStillNeedsTheShapeCheckToBeQuiet(t *testing.T) {
	source := "var dbPassword = 'true';\n"
	analysis := analyzeJavaScript("https://example.test/pw.js", []byte(source))
	for _, secret := range analysis.Secrets {
		if secret.Rule == "hardcoded_password" && secret.Value == "true" {
			t.Fatal("the shape check stopped protecting passwords: `password: \"true\"` is a flag, not a credential")
		}
	}
}

// JS-Analyser's generic token pattern names `token`, `secret` and `auth_token`.
// This project's rule listed only the qualified names, so `token = '…'` was
// reported by the original and dropped here.
func TestABareTokenAssignmentIsReported(t *testing.T) {
	source := "var token = 'b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7';\n"
	analysis := analyzeJavaScript("https://example.test/token.js", []byte(source))
	found := false
	for _, secret := range analysis.Secrets {
		if secret.Rule == "generic_api_key_assignment" && strings.Contains(secret.Value, "b7c9d1e3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a bare `token = '…'` assignment was not reported, got %v", secretValues(analysis.Secrets))
	}
}

// Widening the generic rule to the bare word `token` must not turn every
// `token: length` into a credential — the length floor and the assignment shape
// are what prevent it, and this is the test that says so.
func TestTheWidenedGenericRuleStillIgnoresNonCredentialWords(t *testing.T) {
	source := "var token = length;\nvar secret = null;\nvar apiKey = undefined;\n"
	analysis := analyzeJavaScript("https://example.test/noise.js", []byte(source))
	for _, secret := range analysis.Secrets {
		if secret.Rule == "generic_api_key_assignment" {
			t.Fatalf("a non-credential was reported by the generic rule: %q", secret.Value)
		}
	}
}

func secretValues(secrets []jsSecret) []string {
	values := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		values = append(values, secret.Rule+"="+secret.Value)
	}
	return values
}

// Upstream's `startsWithString` reads the first byte of the right-hand side, so
// an assignment whose right side is a concatenation *starting* with a literal is
// reported by the original. A node-type check misses it — the node is a binary
// expression, not a string — and this test is the difference.
func TestAPathAssignmentStartingWithALiteralCountsLikeUpstream(t *testing.T) {
	source := "window.location.href = 'https://tracker.test/collect?e=' + encodeURIComponent(q);\n" +
		"page = document.URL + location.search;\n"
	analysis := analyzeJavaScript("https://example.test/assign2.js", []byte(source))
	found := findingSubjects(analysis.Findings, jsFindingRequestCall)
	if len(found) != 1 || found[0] != "window.location.href (assignment)" {
		t.Fatalf("findings = %v, want only window.location.href (assignment): the second right side starts with an identifier", found)
	}
}

// Upstream's second comment pattern is
// `/\*[\s\S]*?(TODO|FIXME|…)[\s\S]*?\*/` — a marker **anywhere inside** a block
// comment. The head-anchor that upstream's first pattern genuinely needs was
// being applied to block comments too, and the exhaustive fixture showed it:
// upstream 19 comments, this 18, and the two missing were exactly a one-line
// block comment and a four-line one, both with the marker in the middle.
func TestAMarkerInsideABlockCommentIsFound(t *testing.T) {
	source := "/* block comment with TODO buried in the middle of it */\n" +
		"/*\n   multi-line\n   FIXME: still here\n   still here\n*/\n"
	analysis := analyzeJavaScript("https://example.test/block.js", []byte(source))
	found := make(map[string]bool)
	for _, finding := range analysis.Findings {
		if finding.Kind == jsFindingComment {
			found[finding.Subject] = true
		}
	}
	for _, want := range []string{"TODO", "FIXME"} {
		if !found[want] {
			t.Errorf("marker %q inside a block comment not reported, got %v",
				want, findingSubjects(analysis.Findings, jsFindingComment))
		}
	}
}

// The converse: the head-anchor that upstream's first pattern genuinely requires
// must stay. A line comment that merely mentions TODO halfway through is not a
// `TODO:` marker upstream either — `//\s*` only allows whitespace before it.
func TestALineCommentNeedsTheMarkerAtItsHead(t *testing.T) {
	source := "// this sentence mentions TODO only in the middle\n// TODO: real one\n"
	analysis := analyzeJavaScript("https://example.test/line.js", []byte(source))
	found := findingSubjects(analysis.Findings, jsFindingComment)
	if len(found) != 1 || found[0] != "TODO" {
		t.Fatalf("comments = %v, want exactly [TODO]: a marker mid-sentence is not upstream's `//\\s*`", found)
	}
}

// A block comment with no marker in it stays unreported. Un-sinking the anchor
// must not turn every block comment into a finding, and the count is what says
// so: the exhaustive fixture carries plain block comments among the marked ones.
func TestABlockCommentWithoutAMarkerIsNotAFinding(t *testing.T) {
	// The text deliberately avoids every marker word: the first version of this
	// fixture said "just a note", and `NOTE` is a marker, so the test was
	// measuring its own wording rather than the rule it claims to check.
	source := "/*\n   prose that names nothing on the list\n   second line\n*/\n"
	analysis := analyzeJavaScript("https://example.test/plain.js", []byte(source))
	if found := findingSubjects(analysis.Findings, jsFindingComment); len(found) != 0 {
		t.Fatalf("comments = %v, want none", found)
	}
}
