package enrich

import (
	"strings"
	"testing"
)

// TestExtensionOfReadsTheSuffixNotTheQuery is the case that a naive
// `strings.LastIndex(url, ".")` gets wrong: `a.php?id=1` is a PHP file.
// Reverting the `url.Parse` in ExtensionOf reddens this test.
func TestExtensionOfReadsTheSuffixNotTheQuery(t *testing.T) {
	cases := []struct {
		raw      string
		wantName string
		wantSev  int
		wantOK   bool
	}{
		{"https://site.test/a.php", "php", SeverityHigh, true},
		{"https://site.test/a.php?id=1&x=.png", "php", SeverityHigh, true},
		{"https://site.test/a.php#frag", "php", SeverityHigh, true},
		{"https://site.test/backup.tar.gz", "tar.gz", SeverityMedium, true},
		{"https://site.test/backup.tar.bz2", "tar.bz2", SeverityMedium, true},
		{"https://site.test/a.PHP", "php", SeverityHigh, true},
		{"https://site.test/config%2Eenv", "env", SeverityLow, true},
		{"https://site.test/dir.php/page", "", 0, false},
		{"https://site.test/", "", 0, false},
		{"https://site.test/noext", "", 0, false},
		{"https://site.test/.hidden", "", 0, false},
		{"https://site.test/a.", "", 0, false},
		{"https://site.test/a.unknownext", "", 0, false},
	}
	for _, tc := range cases {
		got, ok := ExtensionOf(tc.raw)
		if ok != tc.wantOK || got.Name != tc.wantName || got.Severity != tc.wantSev {
			t.Errorf("ExtensionOf(%q) = %+v ok=%v, want {%q %d} ok=%v",
				tc.raw, got, ok, tc.wantName, tc.wantSev, tc.wantOK)
		}
	}
}

// TestCompoundSuffixBeatsItsTail pins the longest-match rule. Map iteration order
// in Go is randomised, so the old "first candidate that matches" version passed
// or failed depending on the run — which is exactly the kind of test that cannot
// be trusted. This one is deterministic.
func TestCompoundSuffixBeatsItsTail(t *testing.T) {
	for i := 0; i < 200; i++ {
		got, ok := ExtensionOf("https://site.test/x.tar.bz2")
		if !ok || got.Name != "tar.bz2" {
			t.Fatalf("iteration %d: got %+v ok=%v, want tar.bz2", i, got, ok)
		}
	}
	got, _ := ExtensionOf("https://site.test/x.tgz.gz")
	if got.Name != "gz" {
		t.Fatalf("plain tail must still win when no compound matches, got %+v", got)
	}
}

// TestNotableFilesOrderAndDedupe: severity descending, discovery order kept for
// ties, and each URL counted once even when discovered twice.
func TestNotableFilesOrderAndDedupe(t *testing.T) {
	in := []string{
		"https://site.test/logo.png",
		"https://site.test/a.php",
		"https://site.test/a.php",
		"https://site.test/notes.txt",
		"https://site.test/report.pdf",
	}
	got := NotableFiles(in, SeverityLow)
	if len(got) != 3 {
		t.Fatalf("expected 3 ranked files after dedupe, got %d: %+v", len(got), got)
	}
	wantOrder := []string{"report.pdf", "a.php", "notes.txt"}
	for i, want := range wantOrder {
		if !strings.HasSuffix(got[i].URL, want) {
			t.Fatalf("position %d = %q, want suffix %q (full: %+v)", i, got[i].URL, want, got)
		}
	}
	if got[0].Severity < got[1].Severity {
		t.Fatalf("severity must be descending, got %+v", got)
	}
	// The table carries no image rows: a .png is not a finding, and ranking it
	// would bury the .php. Pinned here so adding images later is a deliberate
	// change rather than an accident.
	if _, ranked := ExtensionOf("https://site.test/logo.png"); ranked {
		t.Error("image extensions must not be ranked as notable files")
	}
}

// TestNotableFilesRespectsMinimum: a threshold of 5 must drop a .txt and a .png
// and keep a .php. Reverting the `ext.Severity < minSeverity` guard reddens it.
func TestNotableFilesRespectsMinimum(t *testing.T) {
	in := []string{
		"https://site.test/logo.png",
		"https://site.test/notes.txt",
		"https://site.test/a.php",
		"https://site.test/x.pdf",
	}
	got := NotableFiles(in, SeverityHigh)
	if len(got) != 2 {
		t.Fatalf("threshold 5 must keep only php and pdf, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Severity < SeverityHigh {
			t.Fatalf("file below threshold survived: %+v", f)
		}
	}
}

// TestExtensionTableHasNoConflicts guards the table itself: a duplicate suffix
// would make the ranking depend on init order.
func TestExtensionTableHasNoConflicts(t *testing.T) {
	seen := map[string]int{}
	for _, e := range Extensions() {
		if e.Severity < SeverityLow || e.Severity > SeverityCritical {
			t.Errorf("extension %q has severity %d, outside 1..7", e.Name, e.Severity)
		}
		if prev, dup := seen[e.Name]; dup {
			t.Errorf("extension %q declared twice with severities %d and %d", e.Name, prev, e.Severity)
		}
		seen[e.Name] = e.Severity
	}
	if len(seen) < 90 {
		t.Errorf("table shrank to %d rows; the port is not complete", len(seen))
	}
}

const patternFixture = `GET /admin HTTP/1.1
Host: site.test
X-Api-Key: AKIAIOSFODNN7EXAMPLE
Server: nginx/1.18.0
X-Other: AKIAIOSFODNN7SECONDX

a = "unterminated
https://cdn.site.test/app.js
<form action="/login"><input type="file" name="up"></form>
<?php
$conn = mysql_connect("localhost","root","hunter2");
system($_GET["c"]);
?>`

// TestMatchCountsOccurrencesNotLines is the unit rule from the porting contract.
// gf's `-o` prints one match per line, so a line carrying two AWS keys prints
// one; our matcher is per occurrence, and a comparison that counts lines would
// read as a shortfall of one on exactly this fixture.
func TestMatchCountsOccurrencesNotLines(t *testing.T) {
	matches := Match([]string{"aws-keys"}, patternFixture)
	if len(matches) != 2 {
		t.Fatalf("expected 2 occurrences of aws-keys, got %d: %+v", len(matches), matches)
	}
	counts := CountByPattern(matches)
	if counts["aws-keys"] != 2 {
		t.Fatalf("counts = %v, want aws-keys=2", counts)
	}
	if matches[0].Line == matches[1].Line {
		t.Fatalf("the two keys are on different lines; line numbers wrong: %+v", matches)
	}
	for i, m := range matches {
		if m.Line < 1 {
			t.Fatalf("line numbers are 1-based, got %d", m.Line)
		}
		if i > 0 && m.Line < matches[i-1].Line {
			t.Fatalf("matches must be ordered by line: %+v", matches)
		}
	}
}

func TestMatchKnownPatterns(t *testing.T) {
	cases := []struct {
		id    string
		body  string
		wants int
	}{
		{"servers", "Server: nginx/1.18.0\n", 1},
		{"upload-fields", `<form><input type="file" name="up"></form>`, 1},
		{"urls", `see https://cdn.site.test/app.js and http://a.test/x`, 2},
		{"php-sources", `<?php $x = $_GET["a"]; ?>`, 1},
		{"php-sinks", `system($_GET["c"]);`, 1},
		{"php-errors", `PHP Warning: something`, 1},
		{"ip", `host 10.0.0.5 and 8.8.8.8`, 2},
		{"base64", `eyJhbGciOiJIUzI1NiJ9`, 1},
		{"json-sec", `{"api_key": "abcdef123456"}`, 1},
		{"takeovers", `There is no app configured at that hostname`, 1},
		{"debug-pages", "Traceback (most recent call last):", 1},
	}
	for _, tc := range cases {
		if got := len(Match([]string{tc.id}, tc.body)); got != tc.wants {
			t.Errorf("Match(%s) found %d, want %d", tc.id, got, tc.wants)
		}
	}
}

// TestPatternsAllCompileAndAreReachable walks the whole registry rather than a
// sample: a pattern that compiles but is unreachable from PatternIDs would be
// coverage the report claims and the code cannot deliver.
func TestPatternsAllCompileAndAreReachable(t *testing.T) {
	registry := Patterns()
	ids := PatternIDs()
	if len(ids) != len(registry) {
		t.Fatalf("PatternIDs has %d entries, registry has %d", len(ids), len(registry))
	}
	if len(ids) < 23 {
		t.Fatalf("registry has %d patterns; upstream ships 23 — port is incomplete", len(ids))
	}
	for _, id := range ids {
		p, ok := registry[id]
		if !ok || len(p.Regexes) == 0 {
			t.Fatalf("pattern %q missing or has no compiled regex", id)
		}
		if p.Title == "" {
			t.Errorf("pattern %q has no title", id)
		}
	}
}

func TestMatchIgnoresUnknownPattern(t *testing.T) {
	if got := Match([]string{"definitely-not-a-pattern"}, "anything"); got != nil {
		t.Fatalf("unknown pattern must yield no matches, got %+v", got)
	}
	if got := Match(nil, ""); got != nil {
		t.Fatalf("empty text must yield no matches, got %+v", got)
	}
}

func TestMatchIsCaseSensitiveWhereUpstreamIsNot(t *testing.T) {
	// `servers` in gf is lowercase-only; ours adds (?i). The finding is the same
	// either way, so the test asserts the case-insensitive behaviour we chose
	// rather than pretending we copied grep's flags verbatim.
	if len(Match([]string{"servers"}, "SERVER: nginx")) != 1 {
		t.Fatal("servers pattern must match case-insensitively")
	}
}

const referenceFixture = `<!doctype html>
<html><head>
<base href="https://site.test/app/">
<link rel="stylesheet" href="/css/main.css">
<script src="https://cdn.site.test/lib.js"></script>
</head><body>
<a href="#top">top</a>
<a href="/about">about</a>
<a href="//static.site.test/logo.png">logo</a>
<a href="mailto:admin@site.test">mail</a>
<a href="javascript:void(0)">js</a>
<img src="/img/hero.jpg" alt="hero">
<iframe src="https://player.site.test/v/1"></iframe>
<area href="/map/1">
<form action="/login" method="post"></form>
<a href="a/b:c">scheme-looking path</a>
<script>var s = "<a href='/not-a-link'>";</script>
<!-- <a href="/commented"> -->
</body></html>`

// TestExtractReferencesByAttributeName is the capability the original reaches only
// by accident: reading `src` from every tag finds `img@src` as a side effect and
// finds nothing that is not a src. Reading by name is what makes this assertable.
func TestExtractReferencesByAttributeName(t *testing.T) {
	refs := ExtractReferences(referenceFixture)
	// Keyed with a slice, not a single value: several `<a>` tags carry `href`,
	// and a one-value map silently keeps only the last one — which is how a
	// reference extractor "passes" while reporting one link out of five.
	got := map[string][]string{}
	for _, r := range refs {
		key := r.Tag + "/" + r.Attribute
		got[key] = append(got[key], r.Raw)
	}
	want := map[string]string{
		"link/href":   "/css/main.css",
		"script/src":  "https://cdn.site.test/lib.js",
		"a/href":      "/about",
		"img/src":     "/img/hero.jpg",
		"iframe/src":  "https://player.site.test/v/1",
		"area/href":   "/map/1",
		"form/action": "/login",
		"base/href":   "https://site.test/app/",
	}
	for key, value := range want {
		if !contains(got[key], value) {
			t.Errorf("%s missing %q, got %v", key, value, got[key])
		}
	}
	if len(got["a/href"]) < 5 {
		t.Errorf("expected every <a href> in the fixture, got %v", got["a/href"])
	}
}

func TestExtractReferencesClassifiesInsteadOfMixing(t *testing.T) {
	refs := ExtractReferences(referenceFixture)
	byRaw := map[string]Reference{}
	for _, r := range refs {
		byRaw[r.Raw] = r
	}
	if r, ok := byRaw["javascript:void(0)"]; !ok || !r.Inline || r.Scheme != "javascript" {
		t.Errorf("javascript: must be Inline, got %+v", r)
	}
	if r, ok := byRaw["mailto:admin@site.test"]; !ok || !r.Inline || r.Scheme != "mailto" {
		t.Errorf("mailto: must be Inline, got %+v", r)
	}
	if r, ok := byRaw["//static.site.test/logo.png"]; !ok || !r.ProtocolRelative || r.Inline {
		t.Errorf("//host/path must be protocol-relative, not a path and not inline: %+v", r)
	}
	if r, ok := byRaw["a/b:c"]; !ok || r.Inline || r.Scheme != "" {
		t.Error("`a/b:c` is a relative path containing a colon, not a scheme")
	}
	if _, ok := byRaw["#top"]; ok {
		t.Error("bare fragment `#top` must be dropped")
	}
	if _, ok := byRaw["/not-a-link"]; ok {
		t.Error("a tag inside a script string literal is not a reference")
	}
	if _, ok := byRaw["/commented"]; ok {
		t.Error("a tag inside an HTML comment is not a reference")
	}
}

func TestSplitURLsAndPaths(t *testing.T) {
	refs := ExtractReferences(referenceFixture)
	urls, paths := SplitURLsAndPaths(refs)
	for _, u := range urls {
		if !strings.Contains(u, "//") {
			t.Errorf("url side must not contain a bare path: %q", u)
		}
	}
	for _, p := range paths {
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			t.Errorf("path side must not contain an absolute URL: %q", p)
		}
	}
	if !contains(urls, "https://cdn.site.test/lib.js") {
		t.Errorf("absolute URL missing from url side: %v", urls)
	}
	if !contains(urls, "//static.site.test/logo.png") {
		t.Errorf("protocol-relative reference belongs to the url side: %v", urls)
	}
	if !contains(paths, "/about") {
		t.Errorf("site-relative path missing from path side: %v", paths)
	}
}

func TestFetchableExcludesInline(t *testing.T) {
	refs := ExtractReferences(referenceFixture)
	for _, r := range Fetchable(refs) {
		if strings.HasPrefix(strings.ToLower(r), "javascript:") || strings.HasPrefix(strings.ToLower(r), "mailto:") {
			t.Errorf("inline reference must not be reported as fetchable: %q", r)
		}
	}
}

func TestHosts(t *testing.T) {
	refs := ExtractReferences(referenceFixture)
	got := Hosts(refs)
	for _, want := range []string{"site.test", "cdn.site.test", "player.site.test", "static.site.test"} {
		if !contains(got, want) {
			t.Errorf("host %q missing, got %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("hosts must be deduplicated, got %v", got)
	}
}

func TestReadTagKeepsQuotedAngleBrackets(t *testing.T) {
	// A `>` inside an attribute value must not end the tag, and a repeated
	// attribute must not overwrite the first one.
	refs := ExtractReferences(`<a href="/first" title="a > b" href="/second">x</a>`)
	if len(refs) != 1 || refs[0].Raw != "/first" {
		t.Fatalf("expected the first href and a full attribute scan, got %+v", refs)
	}
}

const infoFixture = `<html><head>
<!-- build 2026-10-03, db host 10.1.2.3, admin@site.test -->
<meta name="UA-12345-1" content="">
</head><body>
<script src="https://www.google-analytics.com/analytics.js"></script>
<img src="https://cdn.site.test/logo.png">
<a href="https://t.me/sitedesk">telegram</a>
<p>backup at 192.168.1.10 and public 8.8.8.8</p>
<!-- api_key = "AKIAIOSFODNN7EXAMPLE" -->
<form action="/login">Contact: security@site.test</form>
</body></html>`

func TestFindInfoClasses(t *testing.T) {
	infos := FindInfo(infoFixture)
	byKind := map[InfoKind][]Info{}
	for _, i := range infos {
		byKind[i.Kind] = append(byKind[i.Kind], i)
	}
	for _, kind := range []InfoKind{InfoEmail, InfoHTMLComment, InfoInternalIP, InfoIPv4, InfoMarketingTag, InfoSocialLink, InfoCommentedCredential} {
		if len(byKind[kind]) == 0 {
			t.Errorf("no %s finding in fixture; got %+v", kind, infos)
		}
	}
}

// TestInternalIPIsNotAlsoReportedAsIPv4: without this, every RFC1918 address in
// a report appears twice under two names and the count overstates the finding.
func TestInternalIPIsNotAlsoReportedAsIPv4(t *testing.T) {
	infos := FindInfo(infoFixture)
	for _, i := range infos {
		if i.Kind == InfoIPv4 && strings.HasPrefix(i.Value, "10.") {
			t.Fatalf("private address reported as plain IPv4 too: %+v", i)
		}
	}
	for _, i := range infos {
		if i.Kind == InfoIPv4 && i.Value == "8.8.8.8" {
			return
		}
	}
	t.Fatalf("public address must still be reported as IPv4, got %+v", infos)
}

func TestFindInfoOrderAndDedup(t *testing.T) {
	infos := FindInfo(infoFixture)
	for i := 1; i < len(infos); i++ {
		if infos[i].Line < infos[i-1].Line {
			t.Fatalf("findings must be ordered by line: %+v", infos)
		}
	}
	seen := map[string]bool{}
	for _, i := range infos {
		key := string(i.Kind) + i.Value + itoa(i.Line)
		if seen[key] {
			t.Errorf("duplicate finding %+v", i)
		}
		seen[key] = true
	}
}

func TestFindInfoOnEmptyBody(t *testing.T) {
	if got := FindInfo("   \n\t  "); got != nil {
		t.Fatalf("empty body must yield nothing, got %+v", got)
	}
}

func TestCommentBodies(t *testing.T) {
	got := CommentBodies(infoFixture)
	if len(got) != 2 {
		t.Fatalf("expected 2 comments, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "db host 10.1.2.3") {
		t.Errorf("first comment text = %q", got[0])
	}
}

func TestInfoRuleOfMissingKind(t *testing.T) {
	if infoRuleOf(InfoKind("nope")) != nil {
		t.Error("unknown kind must return nil")
	}
	if infoRuleOf(InfoHTMLComment) == nil {
		t.Error("html comment rule must resolve")
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// TestDefaultPatternSetExcludesTheBuildingBlock pins a decision made from a
// measurement, not a preference: on help.mail.ru (2026-10-03) `strings` produced
// 7448 of 7804 hits and pushed php-sinks (11) and takeovers (1) out of view. It
// stays reachable by name — reverting this guard restores the wall of noise.
func TestDefaultPatternSetExcludesTheBuildingBlock(t *testing.T) {
	defaults := DefaultPatternIDs()
	for _, id := range defaults {
		if id == "strings" {
			t.Fatal("`strings` matches every quoted string and must not run by default")
		}
	}
	if len(defaults) != len(PatternIDs())-1 {
		t.Fatalf("expected exactly one pattern excluded, got %d of %d", len(defaults), len(PatternIDs()))
	}
	if _, ok := Patterns()["strings"]; !ok {
		t.Error("`strings` must stay available when named explicitly")
	}
	if got := len(Match([]string{"strings"}, `a "quoted" b "pair"`)); got != 2 {
		t.Errorf("explicit strings request must still work, got %d matches", got)
	}
}

// TestSVGDoesNotOutrankJavaScript pins the severity correction. At severity 7
// eleven icon files outranked every script on the site, which is a list nobody
// reads.
func TestSVGDoesNotOutrankJavaScript(t *testing.T) {
	svg, ok := ExtensionOf("https://site.test/icon.svg")
	if !ok {
		t.Fatal("svg must still be ranked")
	}
	js, ok := ExtensionOf("https://site.test/app.js")
	if !ok {
		t.Fatal("js must still be ranked")
	}
	if svg.Severity > js.Severity {
		t.Fatalf("svg (%d) must not outrank js (%d)", svg.Severity, js.Severity)
	}
	pdf, _ := ExtensionOf("https://site.test/report.pdf")
	if svg.Severity >= pdf.Severity {
		t.Fatalf("svg (%d) must still rank below a leaked pdf (%d)", svg.Severity, pdf.Severity)
	}
}

// Words that begin like an IPv6 unique-local prefix are not addresses. Measured
// on rutube.ru 2026-10-03: the rule reported `FEFF` (a byte-order mark), `feed`
// and `fede` as internal addresses. A finding that is a word is worse than no
// finding, because it is counted.
func TestInternalIPDoesNotMatchWordsBeginningLikeIPv6(t *testing.T) {
	for _, word := range []string{"FEFF", "feed", "fede", "FEED", "face", "beef", "dead"} {
		if internalIPRe.MatchString(word) {
			t.Errorf("%q was reported as an internal IP address", word)
		}
	}
	// The forms that are addresses must still be found, or the rule is just
	// narrowed until it matches nothing.
	for _, address := range []string{"fe80::1", "fe80::a00:27ff:fe4e:66a1", "feff::1", "10.0.0.1", "192.168.1.1", "172.16.0.1"} {
		if !internalIPRe.MatchString(address) {
			t.Errorf("%q is an internal address and must be reported", address)
		}
	}
	// A public address is still not an internal one.
	for _, address := range []string{"8.8.8.8", "93.184.216.34", "2606:2800:220:1::1"} {
		if internalIPRe.MatchString(address) {
			t.Errorf("%q is public and must not be reported as internal", address)
		}
	}
}
