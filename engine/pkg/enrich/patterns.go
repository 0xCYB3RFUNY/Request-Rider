package enrich

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Pattern is one named matcher: a set of Go regular expressions plus the label
// reported to the analyst.
//
// Port of `tomnomnom/gf` (MIT, upstream commit dcd4c361f9f5ba302294ed38b8ce278e8ba69006).
// Because gf is MIT the pattern bodies are carried over as written — they are the
// value of the tool and they are the part worth having. What is *not* carried
// over is the execution model, and that difference is deliberate:
//
//   - gf shells out to `grep` and passes the flag string through (`-oriahE`).
//     Flag semantics belong to grep: `-o` "one match per line", `-a` binary as
//     text, `-i` case-insensitive, `-E` extended. A caller who wants all four
//     needs all four, and none of them is expressible in a Go regexp.
//   - gf's `-o` means one match *per line*, so a line with three AWS keys prints
//     one key. Counting gf's output therefore under-counts, and a comparison
//     against gf that counts lines is comparing two different units.
//
// Ours is a compiled `regexp` per pattern, so `Match` is per line and `FindAll`
// is per occurrence. That is the difference the AGENTS.md rule about folded
// repeats asks to be measured rather than assumed: gf collapsing repeats into a
// single counted row looks like a shortfall of N-1, and it is not one.
//
// Multi-pattern files (`{"patterns": [...]}`) become alternations, which is
// what gf does when it hands the joined expression to grep.
type Pattern struct {
	// Name identifies the pattern set in the UI and in the report.
	Name string
	// Title is a human label; it is never translated here, the UI owns language.
	Title string
	// Regexes are the alternations this set matches.
	Regexes []*regexp.Regexp
}

// Matches is one hit of one pattern.
type Matches struct {
	Pattern string   `json:"pattern"`
	Line    int      `json:"line"`
	Value   string   `json:"value"`
	Spans   []string `json:"spans,omitempty"`
}

// patternSet is the registry loaded once. Compiling two hundred regular
// expressions on every crawled page would dominate the crawl cost, and the set
// never changes at runtime.
var patternSet struct {
	once sync.Once
	byID map[string]*Pattern
	ids  []string
}

var patternSpec = []struct {
	id    string
	title string
	// body is a Go regexp source. `raw` blocks hold the alternation exactly as
	// gf stored it, joined with `|` the way gf joins `patterns`.
	body string
}{
	{
		id: "urls", title: "Absolute URLs",
		body: `https?://[^"'> ]+`,
	},
	{
		id: "aws-keys", title: "AWS access key ids",
		body: `([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}`,
	},
	{
		id: "base64", title: "Base64 blobs",
		body: `([^A-Za-z0-9+/]|^)(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}`,
	},
	{
		id: "cors", title: "CORS headers",
		body: `Access-Control-Allow`,
	},
	{
		id: "debug-pages", title: "Debug and error pages",
		body: `(Application-Trace|Routing Error|DEBUG"? ?[=:] ?True|Caused by:|stack trace:|Microsoft .NET Framework|Traceback|[0-9]:in ` + "`" + `|#!/us|WebApplicationException|java\.lang\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE)`,
	},
	{
		id: "firebase", title: "Firebase endpoints",
		body: `firebaseio\.com`,
	},
	{
		id: "fw", title: "Framework fingerprints",
		body: `(django|laravel|symfony|graphite|grafana|X-Drupal-Cache|struts|code ?igniter|cake ?php|grails|elastic ?search|kibana|log ?stash|tomcat|jenkins|hudson|com\.atlassian\.jira|Apache Subversion|Chef Server|RabbitMQ Management|Mongo|Travis CI - Enterprise|BMC Remedy|artifactory)`,
	},
	{
		id: "go-functions", title: "Go function definitions",
		body: `func [a-z0-9_]+\(`,
	},
	{
		id: "http-auth", title: "HTTP Basic credentials",
		body: `[a-z0-9_/\.:-]+@[a-z0-9-]+\.[a-z0-9.-]+`,
	},
	{
		id: "ip", title: "IPv4 addresses",
		body: `(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])`,
	},
	{
		id: "json-sec", title: "Secrets in JSON or HTML entities",
		body: `(\\?"|&quot;|%22)[a-z0-9_-]*(api[_-]?key|S3|aws_|secret|passw|auth)[a-z0-9_-]*(\\?"|&quot;|%22): ?(\\?"|&quot;|%22)[^"&]+(\\?"|&quot;|%22)`,
	},
	{
		id: "meg-headers", title: "HTTP response headers",
		body: `(?m)^< [a-z0-9_\-]+: .*`,
	},
	{
		id: "php-curl", title: "PHP curl options",
		body: `CURLOPT_(HTTPHEADER|HEADER|COOKIE|RANGE|REFERER|USERAGENT|PROXYHEADER)`,
	},
	{
		id: "php-errors", title: "PHP errors",
		body: `(?i)(php warning|php error|fatal error|uncaught exception|include_path|undefined index|undefined variable|<\?php|<\?[^x]|stack trace:|expects parameter [0-9]*|Debug Trace)`,
	},
	{
		id: "php-serialized", title: "PHP serialized data",
		body: `(a:[0-9]+:\{|O:[0-9]+:"|s:[0-9]+:")`,
	},
	{
		id: "php-sinks", title: "PHP sink calls",
		body: `(?i)(?:^|[^a-z0-9_])(system|exec|popen|pcntl_exec|eval|create_function|unserialize|file_exists|md5_file|filemtime|filesize|assert) ?\(`,
	},
	{
		id: "php-sources", title: "PHP superglobals",
		body: `(\$_(POST|GET|COOKIE|REQUEST|SERVER|FILES)|php://(input|stdin))`,
	},
	{
		id: "s3-buckets", title: "S3 bucket names",
		body: `([a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com|[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)|//s3\.amazonaws\.com/[a-z0-9._-]+|//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+)`,
	},
	{
		id: "sec", title: "Secrets in listings",
		body: `(?i)(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|aws_|secret|ssh-rsa AA)`,
	},
	{
		id: "servers", title: "Server banners",
		body: `(?i)server: `,
	},
	{
		id: "strings", title: "Quoted strings",
		body: `("[^"]+"|'[^']+')`,
	},
	{
		id: "takeovers", title: "Subdomain takeover banners",
		body: strings.Join([]string{
			"There is no app configured at that hostname",
			"NoSuchBucket",
			"No Such Account",
			"You're Almost There",
			"a GitHub Pages site here",
			"There's nothing here",
			"project not found",
			"Your CNAME settings",
			"InvalidBucketName",
			"PermanentRedirect",
			"The specified bucket does not exist",
			"Repository not found",
			"Sorry, We Couldn't Find That Page",
			"The feed has not been found.",
			"The thing you were looking for is no longer here, or never was",
			"Please renew your subscription",
			"There isn't a Github Pages site here.",
			"We could not find what you're looking for.",
			"No settings were found for this company:",
			"No such app",
			"is not a registered InCloud YouTrack",
			"Unrecognized domain",
			"project not found",
			"This UserVoice subdomain is currently available!",
			"Do you want to register",
			"Help Center Closed",
		}, "|"),
	},
	{
		id: "upload-fields", title: "File upload inputs",
		body: `<input[^>]+type=["']?file["']?`,
	},
}

// Patterns returns the compiled registry keyed by id.
//
// It is exported so the UI can offer the operator a real choice of what to look
// for instead of running everything on every page and hiding the result.
func Patterns() map[string]*Pattern {
	patternSet.once.Do(buildPatterns)
	return patternSet.byID
}

// PatternIDs returns the registry ids in sorted order, so a report renders the
// same way twice.
func PatternIDs() []string {
	patternSet.once.Do(buildPatterns)
	ids := make([]string, len(patternSet.ids))
	copy(ids, patternSet.ids)
	sort.Strings(ids)
	return ids
}

// DefaultPatternIDs is the set that runs when the caller names none.
//
// It is the registry minus the building blocks. `strings` matches every quoted
// string on the page: measured on help.mail.ru it produced 7448 of 7804 total
// hits, which left the findings that matter — 11 `php-sinks`, 1 `takeovers`,
// 2 `sec` — three rows under a wall of quoted text. A pattern whose own design
// is "match everything" is a tool for building other patterns, not a finding,
// so it is available by name and off by default.
func DefaultPatternIDs() []string {
	Patterns() // ensures the registry is built before its ids are read
	ids := make([]string, 0, len(patternSet.ids))
	for _, id := range patternSet.ids {
		if id == "strings" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func buildPatterns() {
	patternSet.byID = make(map[string]*Pattern, len(patternSpec))
	patternSet.ids = make([]string, 0, len(patternSpec))
	for _, spec := range patternSpec {
		compiled, err := regexp.Compile(spec.body)
		if err != nil {
			// A pattern that does not compile is a build-time defect in this
			// file, not a runtime condition. Skipping it silently would produce
			// a registry that quietly lies about what it covers, and the
			// reconciliation registry would then claim a capability that does
			// not work. Panic here: this is the same class as an unresolved
			// symbol in a table of rules.
			panic(fmt.Sprintf("enrich: pattern %q does not compile: %v", spec.id, err))
		}
		patternSet.byID[spec.id] = &Pattern{Name: spec.id, Title: spec.title, Regexes: []*regexp.Regexp{compiled}}
		patternSet.ids = append(patternSet.ids, spec.id)
	}
}

// Match runs the named patterns over text and returns every hit, one entry per
// occurrence, ordered by pattern id then by line.
//
// Line numbers are 1-based because that is what the analyst will read against
// the raw body; a 0-based line is a number that has to be adjusted every time it
// is compared with an editor.
func Match(ids []string, text string) []Matches {
	if text == "" {
		return nil
	}
	Patterns()
	if len(ids) == 0 {
		ids = DefaultPatternIDs()
	}
	lines := strings.Split(text, "\n")
	var out []Matches
	for _, id := range ids {
		pattern, ok := patternSet.byID[id]
		if !ok {
			continue
		}
		for _, re := range pattern.Regexes {
			for i, line := range lines {
				found := re.FindAllString(line, -1)
				for _, value := range found {
					out = append(out, Matches{
						Pattern: id,
						Line:    i + 1,
						Value:   value,
						Spans:   re.SubexpNames(),
					})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// CountByPattern reduces a match list to one number per pattern id. It is what
// the status line shows, and what a fixture comparison counts — per occurrence,
// never per line, because that is the unit our matcher produces and the unit a
// comparison must use to be a comparison at all.
func CountByPattern(matches []Matches) map[string]int {
	counts := make(map[string]int, len(matches))
	for _, m := range matches {
		counts[m.Pattern]++
	}
	return counts
}
