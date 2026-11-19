package main

// Tests for the capabilities glued onto the JavaScript analyser: the build
// manifest routes, the internal services, the privileged endpoints, the
// hardcoded authentication tokens, the Vite markers and the parameter wordlist.
//
// Every test here is written against the analyser as the product runs it — the
// same `analyzeJavaScript` the crawl calls — so a capability that exists only in
// a helper cannot pass.

import (
	"strings"
	"testing"
)

// analysisOf is the fixture helper: one analysis of a JavaScript file served
// from a first-party page.
func analysisOf(t *testing.T, body string) jsAnalysis {
	t.Helper()
	return analyzeJavaScript("https://shop.example/app/bundle.js", []byte(body))
}

// findingOf returns the finding of a kind whose subject contains a fragment.
func findingOf(findings []jsFinding, kind, fragment string) (jsFinding, bool) {
	for _, finding := range findings {
		if finding.Kind == kind && strings.Contains(finding.Subject, fragment) {
			return finding, true
		}
	}
	return jsFinding{}, false
}

func hasRoute(analysis jsAnalysis, route string) bool {
	for _, entry := range analysis.Routes {
		if entry.Route == route {
			return true
		}
	}
	return false
}

func hasFrontierLink(links []string, want string) bool {
	for _, link := range links {
		if link == want {
			return true
		}
	}
	return false
}

func candidateSources(analysis jsAnalysis, name string) []string {
	for _, candidate := range analysis.Params {
		if candidate.Name == name {
			return candidate.Sources
		}
	}
	return nil
}

func hasSource(sources []string, want string) bool {
	for _, source := range sources {
		if source == want {
			return true
		}
	}
	return false
}

// # Build manifest routes

// TestTheBuildManifestRoutesJoinTheCrawlFrontier is the Next.js trick from the
// operator's list — print `__BUILD_MANIFEST.sortedPages` — with the difference
// that the routes are not printed. The page `/admin/settings` is not linked from
// anywhere, so before this the crawl never requested it, and now the frontier
// carries it.
func TestTheBuildManifestRoutesJoinTheCrawlFrontier(t *testing.T) {
	analysis := analysisOf(t, `
self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB.push([{sortedPages:[
"/_next/static/a1b2c3/pages/index",
"/_next/static/a1b2c3/pages/admin/settings",
"/_next/static/a1b2c3/pages/_app"
]}]);
`)
	if !hasRoute(analysis, "/admin/settings") {
		t.Fatalf("the manifest route is missing from the record: %+v", analysis.Routes)
	}
	if hasRoute(analysis, "/_app") {
		t.Errorf("_app is a build file, not a route: %+v", analysis.Routes)
	}
	if !hasFrontierLink(analysis.links, "https://shop.example/admin/settings") {
		t.Errorf("the route did not reach the crawl frontier: %v", analysis.links)
	}
	if finding, ok := findingOf(analysis.Findings, jsFindingRoute, "/admin/settings"); !ok {
		t.Errorf("the route is not reported as a finding: %+v", analysis.Findings)
	} else if finding.Severity != jsSeverityInfo {
		t.Errorf("a route is inventory, severity %q is a claim about the target", finding.Severity)
	}
}

// TestAWebpackRouteKeyBecomesARoute covers the other shape Next.js ships: a
// production manifest stores the same information as object keys, and a detector
// that only knew the array shape would report no routes at all there.
func TestAWebpackRouteKeyBecomesARoute(t *testing.T) {
	analysis := analysisOf(t, `
self.__BUILD_MANIFEST={"pages":{"/_next/static/deadbeef/pages/reports":[1],
"/_next/static/deadbeef/pages/index":[2],"/_next/static/deadbeef/pages/_document":[3]}};
`)
	if !hasRoute(analysis, "/reports") {
		t.Fatalf("the webpack route key was not read as a route: %+v", analysis.Routes)
	}
	if hasRoute(analysis, "/_document") {
		t.Errorf("_document is a build file: %+v", analysis.Routes)
	}
}

// TestADynamicRouteStaysInTheRecordAndNotOnTheFrontier is the boundary between
// "the application has this route" and "there is a URL to request". A dynamic
// segment is evidence and not a path, and requesting `/blog/` would be a request
// nobody asked for.
func TestADynamicRouteStaysInTheRecordAndNotOnTheFrontier(t *testing.T) {
	analysis := analysisOf(t, `
self.__BUILD_MANIFEST={sortedPages:["/_next/static/a1/pages/blog/[slug]","/_next/static/a1/pages/pricing"]};
`)
	if !hasRoute(analysis, "/blog/[slug]") {
		t.Errorf("a dynamic route is still a route and belongs in the record: %+v", analysis.Routes)
	}
	if hasFrontierLink(analysis.links, "https://shop.example/blog/[slug]") {
		t.Errorf("a route with an interpolation must not reach the frontier: %v", analysis.links)
	}
	if !hasFrontierLink(analysis.links, "https://shop.example/pricing") {
		t.Errorf("the static route of the same manifest did not reach the frontier: %v", analysis.links)
	}
}

// TestAnArrayOfStringsThatIsNotARouteListIsNotRoutes is the control for the
// query that reads "the array of strings whose key says what it is". A bundle
// lists allowed origins and mime types in exactly that shape, and a detector
// that reported them as routes would put `text/html` on the crawl frontier.
func TestAnArrayOfStringsThatIsNotARouteListIsNotRoutes(t *testing.T) {
	analysis := analysisOf(t, `
var mimeTypes=["image/png","text/html"];var allowed=["https://a.example/","https://b.example/"];
`)
	if len(analysis.Routes) != 0 {
		t.Fatalf("an array that is not a route list produced routes: %+v", analysis.Routes)
	}
}

// # Internal services

// TestALoopbackServiceInAStringIsReported is the "look at main.js for localhost,
// 127.0.0.1, host, port" step, for the address-shaped half of it.
func TestALoopbackServiceInAStringIsReported(t *testing.T) {
	analysis := analysisOf(t, `
var api = "http://localhost:3000/v1/internal";
var metrics = "127.0.0.1:9090";
`)
	for _, subject := range []string{"localhost:3000", "127.0.0.1:9090"} {
		if _, ok := findingOf(analysis.Findings, jsFindingInternalService, subject); !ok {
			t.Errorf("service %q is missing: %+v", subject, analysis.Findings)
		}
	}
}

// TestALoopbackNameInProseIsNotAService is the false-positive control, and it has
// two halves on purpose.
//
// The first version of this check asked only what follows the match, and the
// fixture only had prose on that side — so the half that asks what *precedes* it
// was never exercised, and removing it left every test green. Both directions now
// have their own sentence: `run this on localhost first` is prose after, and
// `connect to localhost/api` is prose before with a genuine address continuation
// after it, which is the shape that fools a one-sided check.
func TestALoopbackNameInProseIsNotAService(t *testing.T) {
	analysis := analysisOf(t, `
var help = "run this on localhost first";
var note = "connect to localhost/api when the app is up";
var wiki = "the 127.0.0.1 rule is documented in the wiki";
var peek = "see 127.0.0.1:8080/api for the metrics";
`)
	for _, prose := range []string{"localhost", "127.0.0.1"} {
		if _, ok := findingOf(analysis.Findings, jsFindingInternalService, prose); ok {
			t.Errorf("a hostname inside prose is not a service: %+v", analysis.Findings)
		}
	}
}

// TestAHostKeywordNamesAnInternalService covers the keyword half: the two halves
// of an address are in different places, so neither matches a loopback pattern,
// and the case that matters most is a private address a client cannot reach.
func TestAHostKeywordNamesAnInternalService(t *testing.T) {
	analysis := analysisOf(t, `
const config = {host: "10.0.4.7", port: 5432, db_host: "postgres.internal"};
`)
	if _, ok := findingOf(analysis.Findings, jsFindingInternalService, "10.0.4.7"); !ok {
		t.Errorf("a private host keyword is not reported: %+v", analysis.Findings)
	}
	if _, ok := findingOf(analysis.Findings, jsFindingInternalService, "postgres.internal"); !ok {
		t.Errorf("an internal hostname keyword is not reported: %+v", analysis.Findings)
	}
}

// TestAPublicHostKeywordIsNotAService is the control for the keyword pass: a
// `host:` key with a public name is the ordinary case in every configuration
// file ever written, and reporting it would make the badge unreadable.
func TestAPublicHostKeywordIsNotAService(t *testing.T) {
	analysis := analysisOf(t, `
const config = {host: "api.example.com", port: 443, base_url: "https://api.example.com/v2"};
`)
	if _, ok := findingOf(analysis.Findings, jsFindingInternalService, "api.example.com"); ok {
		t.Errorf("a public host is not an internal service: %+v", analysis.Findings)
	}
}

// TestTheServiceNameRefusesAPublicAddress is the gate the control above cannot
// reach on its own.
//
// There are two checks between a `host:` key and a finding: the one in
// `collectHostPortKeywords` that asks whether the value is internal at all, and
// the one in `jsServiceName` that refuses anything that is not an address. The
// The public-host fixture above is stopped by the first, so the second had no
// test of its own and removing it left everything green — which is the "green
// test that is not a test" this project's own rules are about.
func TestTheServiceNameRefusesAPublicAddress(t *testing.T) {
	if got := jsServiceName("api.example.com"); got != "" {
		t.Errorf("a public address is not a service, got %q", got)
	}
	if got := jsServiceName("example.com/path"); got != "" {
		t.Errorf("a path is not a service, got %q", got)
	}
	if got := jsServiceName("postgres.internal"); got != "postgres.internal" {
		t.Errorf("an internal host name is a service, got %q", got)
	}
	if got := jsServiceName("10.0.4.7:5432"); got != "10.0.4.7:5432" {
		t.Errorf("a private address with a port is a service, got %q", got)
	}
	if got := jsServiceName("10.0.0.1.example.com"); got != "" {
		t.Errorf("a public host whose name starts with a private range is not a service, got %q", got)
	}
}

// # Privileged endpoints and hardcoded tokens

// TestAPrivilegedEndpointIsReported is the "find the sensitive path in the JS"
// step, and the path is taken from the analyser's own endpoint list rather than
// from a second extraction of the file.
func TestAPrivilegedEndpointIsReported(t *testing.T) {
	analysis := analysisOf(t, `
fetch("https://project.app/RedactedAppBackend/dashboard/addAdmin.php",{method:"POST"});
`)
	if _, ok := findingOf(analysis.Findings, jsFindingPrivilegedEndpoint, "addAdmin.php"); !ok {
		t.Fatalf("the privileged endpoint is missing: %+v", analysis.Findings)
	}
}

// TestAHostNameWithAdminInItIsNotAPrivilegedEndpoint is the false-positive control
// for that step. `admin.example.com` is a hostname, not an admin panel, and a
// pattern asked about the whole URL cannot tell the two apart.
func TestAHostNameWithAdminInItIsNotAPrivilegedEndpoint(t *testing.T) {
	analysis := analysisOf(t, `
fetch("https://admin.example.com/api/v1/ping");
`)
	if _, ok := findingOf(analysis.Findings, jsFindingPrivilegedEndpoint, "admin.example.com"); ok {
		t.Errorf("a host name is not a privileged path: %+v", analysis.Findings)
	}
}

// TestAHardcodedTokenIsReported is the payload of the technique the operator's
// list describes: a token and the admin endpoint it authorises, both read out of
// a bundle by a person who had the source.
//
// The name is one the credential rules do not already cover, and that is not an
// accident: `token = "…"` with a credential-shaped value is matched by the
// generic secret rule and lands in `secrets`, so this category is for the names
// the generic rule does not know — a header name, `bearer`, `sessionId` — and for
// those a reader would otherwise have to find by hand.
func TestAHardcodedTokenIsReported(t *testing.T) {
	analysis := analysisOf(t, `
var cfg = {"x-auth-token": "k3n9b2qw7er4t6yu1i8o"};
var h = {"x-internal-auth": "q7wn3z8yt2bk5m4xr9pd"};
`)
	for _, name := range []string{"x-auth-token", "x-internal-auth"} {
		if _, ok := findingOf(analysis.Findings, jsFindingHardcodedAuthToken, name); !ok {
			t.Errorf("the header-shaped token name %q is missing: %+v", name, analysis.Findings)
		}
	}
}

// TestAnAuthorizationBearerIsASecretAndNotASecondRow is the boundary of this
// category, and it is a boundary somebody already got wrong once: the Pinkerton
// rule `pinkerton_authorization_bearer` reports `authorization: "Bearer …"` with
// its value, so a second row here would be one credential in two vocabularies.
func TestAnAuthorizationBearerIsASecretAndNotASecondRow(t *testing.T) {
	bearer := "Bearer a91kd0mz7xq4"
	analysis := analysisOf(t, `var headers = {authorization: "`+bearer+`"};`)
	reported := false
	for _, secret := range analysis.Secrets {
		if secret.Rule == "pinkerton_authorization_bearer" && secret.Value == bearer {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the fixture did not produce the secret row the boundary is about: %+v", analysis.Secrets)
	}
	if _, ok := findingOf(analysis.Findings, jsFindingHardcodedAuthToken, "authorization"); ok {
		t.Errorf("one credential produced two rows in two vocabularies: %+v", analysis.Findings)
	}
}

// TestTheTokenNextToAPrivilegedEndpointIsRaised is the pair, and it is the whole
// of the vulnerability the technique describes: an endpoint that creates an
// administrator, and the credential that authorises it, four lines apart in one
// bundled config object. Either row alone is a lead.
func TestTheTokenNextToAPrivilegedEndpointIsRaised(t *testing.T) {
	body := `
var api = "https://project.app/RedactedAppBackend/dashboard/addAdmin.php";
var session = {apiKey: "k3n9b2qw7er4t6yu1i8o"};
fetch(api, {method: "POST", body: JSON.stringify(session)});
`
	analysis := analysisOf(t, body)
	endpoint, ok := findingOf(analysis.Findings, jsFindingPrivilegedEndpoint, "addAdmin.php")
	if !ok {
		t.Fatalf("the privileged endpoint is missing: %+v", analysis.Findings)
	}
	if endpoint.Severity != jsSeverityHigh {
		t.Errorf("a credential beside a privileged endpoint is the pairing, severity %q: %+v",
			endpoint.Severity, analysis.Findings)
	}
}

// TestAPrivilegedEndpointWithNoCredentialBesideItStaysMedium is the control for
// that pairing. Every file that names an admin path is not a takeover, and
// raising every one of them would be the same as raising none.
func TestAPrivilegedEndpointWithNoCredentialBesideItStaysMedium(t *testing.T) {
	analysis := analysisOf(t, `
fetch("/dashboard/reports.php");
fetch("/admin/login.php");
`)
	endpoint, ok := findingOf(analysis.Findings, jsFindingPrivilegedEndpoint, "reports.php")
	if !ok {
		t.Fatalf("the privileged endpoint is missing: %+v", analysis.Findings)
	}
	if endpoint.Severity != jsSeverityMedium {
		t.Errorf("no credential is near this endpoint, severity %q claims otherwise: %+v",
			endpoint.Severity, analysis.Findings)
	}
}

// TestACredentialTheSecretPassAlreadyFoundIsNotReportedTwice is the one-fold
// rule. A GitHub token is a credential: the secret pass reports it with its
// value, and reporting it a second time under a second name is the two
// vocabularies for one problem this project removed once already.
func TestACredentialTheSecretPassAlreadyFoundIsNotReportedTwice(t *testing.T) {
	token := "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	analysis := analysisOf(t, `const authToken = "`+token+`";`)
	reportedSecret := false
	for _, secret := range analysis.Secrets {
		if secret.Value == token {
			reportedSecret = true
		}
	}
	if !reportedSecret {
		t.Fatalf("the fixture did not produce a secret row, so the test proves nothing: %+v", analysis.Secrets)
	}
	if _, ok := findingOf(analysis.Findings, jsFindingHardcodedAuthToken, "authToken"); ok {
		t.Errorf("one leaked key produced two rows in two vocabularies: %+v", analysis.Findings)
	}
}

// TestAFlagIsNotAToken is the false-positive control for the token pass. The
// technique's one-liner fires on `var` names, and a name-based rule that reports
// `token: "true"` trains the reader to skip the badge.
func TestAFlagIsNotAToken(t *testing.T) {
	analysis := analysisOf(t, `
var token = "true"; var authRequired = "false"; var apiKey = "undefined";
`)
	if _, ok := findingOf(analysis.Findings, jsFindingHardcodedAuthToken, "token"); ok {
		t.Errorf("a boolean flag is not a credential: %+v", analysis.Findings)
	}
}

// TestTheTokenEvidenceDoesNotCarryTheWholeCredential is the redaction contract:
// the value is in `secrets`, and the evidence column is a column a table renders.
func TestTheTokenEvidenceDoesNotCarryTheWholeCredential(t *testing.T) {
	analysis := analysisOf(t, `var headers = {"x-auth-token": "k3n9b2qw7er4t6yu1i8o"};`)
	finding, ok := findingOf(analysis.Findings, jsFindingHardcodedAuthToken, "x-auth-token")
	if !ok {
		t.Fatalf("the token is missing: %+v", analysis.Findings)
	}
	if strings.Contains(finding.Evidence, "k3n9b2qw7er4t6yu1i8o") {
		t.Errorf("the evidence carries the whole credential: %q", finding.Evidence)
	}
}

// # Vite dev server

// TestTheViteMarkersAreReported covers the precondition of the arbitrary file
// read in GHSA-x574-m823-4x7w: `/@fs/` serves files outside the project root,
// and a production bundle that still contains it is a bundle built by a dev
// server that is meant to be reachable.
func TestTheViteMarkersAreReported(t *testing.T) {
	analysis := analysisOf(t, `
import.meta.env.DEV;
const load = p => import("/@fs/" + p);
`)
	if _, ok := findingOf(analysis.Findings, jsFindingViteDevServer, "@fs"); !ok {
		t.Fatalf("the /@fs/ marker is missing: %+v", analysis.Findings)
	}
	if _, ok := findingOf(analysis.Findings, jsFindingViteDevServer, "import.meta.env"); !ok {
		t.Errorf("the import.meta.env marker is missing: %+v", analysis.Findings)
	}
}

// TestAProductionBundleHasNoViteFinding is the control: the marker is what makes
// the row a claim, and a row without it would be the scanner accusing every
// bundle on the internet.
func TestAProductionBundleHasNoViteFinding(t *testing.T) {
	analysis := analysisOf(t, `
var config = {api: "https://api.example.com", retry: 3};
function render(el){el.textContent=config.api;}
`)
	if _, ok := findingOf(analysis.Findings, jsFindingViteDevServer, ""); ok {
		t.Errorf("a bundle with no Vite marker produced a Vite row: %+v", analysis.Findings)
	}
}

// # Parameter wordlist

// TestTheWordlistJoinsQueryBodyAndVariableNames is GAP's "get all parameters"
// and the one-liner's `var` wordlist in one list, with each name carrying the
// sources it came from — because a name read off a call site is evidence and a
// name read off a variable is a hypothesis, and the reader has to be able to
// tell them apart without opening the file.
func TestTheWordlistJoinsQueryBodyAndVariableNames(t *testing.T) {
	analysis := analysisOf(t, `
var redirectTo = "/next";
fetch("/login?redirect=" + encodeURIComponent(redirectTo), {method: "POST", body: JSON.stringify({username: "x"})});
`)
	// The query parameter is read off the call site, so it is evidence.
	if !hasSource(candidateSources(analysis, "redirect"), jsParamSourceQuery) {
		t.Errorf("a query parameter of a call site is not in the wordlist: %+v", analysis.Params)
	}
	// The variable name is the technique's hypothesis, and it is reported as such
	// rather than being merged into the evidence rows.
	if !hasSource(candidateSources(analysis, "redirectTo"), jsParamSourceVariable) {
		t.Errorf("a variable name is not in the wordlist: %+v", analysis.Params)
	}
	// The key the body object carries is a name too.
	if candidateSources(analysis, "username") == nil {
		t.Errorf("a body object key is not in the wordlist: %+v", analysis.Params)
	}
}

// TestTheWordlistExcludesRequestOptions is the noise control for the same list.
// `{method: "POST", body: …}` is a pair in the tree, so the variable pass reads
// `method` and `body` as names — and they are options of the request rather than
// names the server accepts. They were the first two rows of this fixture's list
// before the filter existed, which is the measurement that required it.
func TestTheWordlistExcludesRequestOptions(t *testing.T) {
	analysis := analysisOf(t, `
fetch("/login", {method: "POST", headers: {"x-csrf": "1"}, body: "a=1"});
`)
	for _, option := range []string{"method", "body", "headers"} {
		if candidateSources(analysis, option) != nil {
			t.Errorf("%q is a request option, not a parameter candidate: %+v", option, analysis.Params)
		}
	}
}

// TestTheWordlistExcludesLanguageKeywords is the noise control. A bundle binds
// `const`, `return` and `window` like any other name, and a wordlist of those is
// a list the operator has to read past to find the one name worth trying.
func TestTheWordlistExcludesLanguageKeywords(t *testing.T) {
	analysis := analysisOf(t, `var widget=1;let buffer=[];function render(){return window;}`)
	for _, forbidden := range []string{"const", "return", "window", "function", "let"} {
		if candidateSources(analysis, forbidden) != nil {
			t.Errorf("%q is not a parameter candidate: %+v", forbidden, analysis.Params)
		}
	}
	if candidateSources(analysis, "widget") == nil {
		t.Errorf("a real name was dropped: %+v", analysis.Params)
	}
}

// # Contracts the record has to keep

// TestAnEmptyFileProducesEmptyListsAndNotNull is the contract every field of the
// record carries: a missing key and an empty result are different claims, and a
// page whose JS was analysed and had nothing must serialise as empty lists.
func TestAnEmptyFileProducesEmptyListsAndNotNull(t *testing.T) {
	analysis := analyzeJavaScript("https://shop.example/app/empty.js", nil)
	if analysis.Routes == nil || analysis.Params == nil || analysis.Findings == nil ||
		analysis.Endpoints == nil || analysis.Secrets == nil || analysis.Variables == nil {
		t.Fatalf("an empty file serialises a nil list: %+v", analysis)
	}
}

// TestTheCapabilitiesSurviveTheParserRecover is the one property every field of
// this pass shares with the pass above it: a file that makes tree-sitter panic
// reports an error on that page and resets the lists, rather than carrying the
// half-filled ones into the record.
func TestTheCapabilitiesSurviveTheParserRecover(t *testing.T) {
	restore := analyzeJavaScriptPanicking
	analyzeJavaScriptPanicking = func() { panic("boom") }
	defer func() { analyzeJavaScriptPanicking = restore }()

	analysis := analyzeJavaScript("https://shop.example/app/bundle.js", []byte(`
self.__BUILD_MANIFEST={sortedPages:["/_next/static/a1/pages/admin"]};
var headers = {"x-auth-token": "k3n9b2qw7er4t6yu1i8o"};
`))
	if analysis.Error == "" {
		t.Fatal("a parser panic produced no error on the page")
	}
	if len(analysis.Routes) != 0 || len(analysis.Findings) != 0 || len(analysis.Params) != 0 {
		t.Errorf("a recovered file kept half-filled lists: %+v", analysis)
	}
}
