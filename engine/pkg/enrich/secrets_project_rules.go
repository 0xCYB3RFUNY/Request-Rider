package enrich

import "regexp"

// Project rules for shapes the vendored rule set does not carry.
//
// # Why these three exist and why they live here
//
// `secrets_data.go` holds 539 upstream rules. Measuring the page path against
// realistic credentials found three shapes it reports nothing for at all, and all
// three were measured with the vendor patterns in their current state:
//
//   - `redis://:s3cr3tP4ssw0rd7@cache.internal:6379/0` — 0 findings. Both
//     `np.redis.1` and `np.redis.2` require a non-empty user name before the
//     colon, and the common form of a Redis URL has none: the password is the
//     only secret in the string. Redis and Postgres were the two schemes the
//     operator named, and this is the shape that lost one of them.
//   - `password = "Tr0ub4dor3xK9vLmQ2wZxP7@"` in page text — 0 findings. The
//     vendored generic rules want a provider-ish name; a bare `password` is the
//     most ordinary credential name there is and none of them takes it.
//   - `xoxb-2947483729-2947483729-aBcDeFgHiJkLmNoPq…-_` — 0
//     findings. The JavaScript path has `slack_token`; the page path did not.
//
// They are added by appending to the same registry the vendored set is loaded
// into, which is the mechanism the project already uses rather than a second
// scanner: `osint_secrets.go` does `secretRules = append(secretRules,
// pinkertonRules...)` for exactly this reason. A second code path would have to
// answer the same placeholder, entropy and requirement questions a second time,
// and two answers to "is this a credential" is one answer too many.
//
// # What guards them from becoming noise
//
// The same question was measured before it was answered, on a live target: the
// vk.com translation bundle carries `"guest_password":"Password"`,
// `"login_enter":"Sign in"` and four more labels whose left side names a
// credential. All were reported by a naive assignment rule. The requirement that
// survives that measurement is one digit in the value, and it is carried as data
// (`MinDigits`) rather than folded into the pattern, so a rejection can name the
// part that failed instead of vanishing.

// projectRules are the rules this project adds to the vendored set.
var projectRules = []SecretRule{
	{
		ID:   "requestrider.connection_string_password",
		Name: "credential in connection string",
		// The user name is optional, which is the whole point: `redis://:pass@host`
		// has no user name, and both vendored Redis rules require one. The
		// password group stops at the first `@`, so a host with a port and a path
		// does not end up inside the secret.
		Regex: regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]{1,31}://[a-z0-9._~%!$&'()*+,;=-]{0,128}:([^@/\s'"<>` + "`" + `]{4,256})@[a-z0-9.\-]+`),
		Group: 1,
		// One digit, for the measured reason above. `guest:guest` is therefore not
		// reported, and that is a deliberate loss: a default pair with no digit is
		// far more often a documentation example than a leaked credential, and the
		// same trade-off `osint_secrets.go` already makes for assignment rules.
		Requirement: CharacterRequirements{MinDigits: 1},
		Score:       60,
		Categories:  []string{"Generic"},
	},
	{
		ID:   "requestrider.credential_assignment",
		Name: "credential assigned in page text",
		// The name has to say credential. `password`, `passwd`, `pwd` and the
		// credential-shaped words are taken; a bare `key` is not, because a page
		// carries `key` as ordinary configuration and a rule that reads it produces
		// findings about a site's plumbing rather than about its secrets.
		//
		// The value is quoted, and that is the split from
		// `requestrider.credential_assignment_bare`. It was one rule with an
		// optional quote, and the looseness was measured rather than argued: on 2000
		// real files (`RR_FP_CORPUS` pointed at the Nuclei template set, 99025 files
		// on this machine) a single permissive value class ran the capture straight
		// through `apikey=shareButton&fingerprint=0487c2fb-96…` and reported the
		// pair as one secret. Quoting is the author's signal that the whole run of
		// characters is the value, and it is the only signal available — which is why
		// the two rules differ in class rather than one of them being dropped.
		//
		// Two more narrowings came out of the same corpus run, and both are named
		// classes rather than a general tightening:
		//
		//   - .NET's `PublicKeyToken=31bf3856ad364e35` and ASP.NET's
		//     `__RequestValidationToken=ac1906a5-…` were caught because a bare
		//     `token` matches the end of any compound word. `token` therefore needs a
		//     word boundary or a separator in front of it, which keeps
		//     `access_token`, `api_token` and `refresh_token`. Three true positives
		//     rode the same names — a Google Tag Manager `gtm_auth`, a HERE `apiKey`
		//     and a Tumblr `api_key` — and all three survive the narrowing.
		//   - template placeholders such as `{c2f_value}` pass a digit gate and are
		//     not credentials. Braces and angle brackets are out of the class.
		//
		// The digit requirement is the same trade-off `osint_secrets.go` makes, for
		// the same measured reason: the vk.com translation bundle carries
		// `"guest_password":"Password"` and four more labels whose left side names a
		// credential. `password: required` and `guest_password: "Password"` are both
		// refused, and both were checked rather than argued about.
		Regex: regexp.MustCompile(`(?i)\b([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|pwd|credentials?|api[_-]?key|apikey|api[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?key|encryption[_-]?key|secret[_-]?key|jwt|(?:\b|[_-])token|auth\b|secret)(?:[_-][A-Za-z0-9]+)*)["']?\s*[:=]>?\s*["']([^"'\s{}<>]{8,256})["']`),
		// Group 1 is the name the pattern needs in order to match at all, so the
		// value is group 2 — the same shape as the assignment rule in
		// `osint_secrets.go`, which is why this is a group number and not an id.
		Group:       2,
		Requirement: CharacterRequirements{MinDigits: 1},
		Score:       55,
		Categories:  []string{"Generic"},
	},
	{
		ID:   "requestrider.credential_assignment_bare",
		Name: "credential in an unquoted attribute",
		// The value is not quoted, which is how a credential reaches an HTML
		// attribute: `data-token=kR7pQ2mX9tL4wB8nZ3vF6yH1sD5gA0cJ7eU2iO4q`. The
		// vendored set requires quotes everywhere and reports nothing for this
		// shape; across the 24-name matrix this rule closed every remaining cell on
		// the page path, and the quoted rule above does not see it.
		//
		// Its class is narrower than the quoted rule's, and that asymmetry is the
		// design rather than an inconsistency: **a raw `&` cannot occur in an unquoted
		// HTML attribute value**, so an `&` inside a bare value means the run did not
		// stop where the author meant it to. `&`, `=`, `?`, `,`, `(`, `)`, `;`, `\`,
		// `{}`, `<>`, quotes and whitespace are all out.
		//
		// What that costs is a punctuated password written bare — and a bare value
		// carrying `&` is not valid HTML in the first place, so what it costs is a
		// value that cannot be written. The quoted rule is where a punctuated
		// password is found, and it is the one that keeps `&`.
		Regex:       regexp.MustCompile(`(?i)\b([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|pwd|credentials?|api[_-]?key|apikey|api[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?key|encryption[_-]?key|secret[_-]?key|jwt|(?:\b|[_-])token|auth\b|secret)(?:[_-][A-Za-z0-9]+)*)["']?\s*[:=]>?\s*([A-Za-z0-9_\-/+.$!~^#@*]{8,256})["']?`),
		Group:       2,
		Requirement: CharacterRequirements{MinDigits: 1},
		Score:       52,
		Categories:  []string{"Generic"},
	},
	{
		ID:   "requestrider.slack_token",
		Name: "Slack token",
		// The underscore is in the class because its absence truncated the value.
		// Measured: for `xoxb-2947483729-2947483729-aBcDeFgHiJkLmNoPq…-_`
		// a class of `[0-9A-Za-z-]` stopped at the `-` and delivered 65 characters of
		// a 66-character token — the same class of defect this session was opened
		// to measure, in a rule written minutes earlier.
		Regex:      regexp.MustCompile(`\b(xox[baprse]-[0-9A-Za-z_-]{10,300})\b`),
		Group:      1,
		Score:      70,
		Categories: []string{"Slack"},
	},
	{
		ID:   "requestrider.password_hash",
		Name: "password hash (md5/sha/bcrypt)",
		Regex: regexp.MustCompile(`(?i)(?:\\?"|&quot;|['"])?\b([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|pwd|hash|secret)[a-z0-9_.\-]*)(?:\\?"|&quot;|['"])?\s*[:=]>?\s*(?:\\?"|&quot;|['"])([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|[a-f0-9]{128})(?:\\?"|&quot;|['"])`),
		Group: 2,
		Score: 85,
		Categories: []string{"Credentials", "Password Hash"},
	},
	{
		ID:   "requestrider.credential_pair",
		Name: "credential pair (username and password)",
		Regex: regexp.MustCompile(`(?i)(?:\\?"|&quot;|['"])?\b([a-z0-9_.\-]*(?:user(?:name)?|login|email)[a-z0-9_.\-]*)(?:\\?"|&quot;|['"])?\s*[:=]\s*(?:\\?"|&quot;|['"])([^"'\s\r\n]{3,128})(?:\\?"|&quot;|['"])\s*[,;]?\s*(?:\\?"|&quot;|['"])?\b([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|pwd)[a-z0-9_.\-]*)(?:\\?"|&quot;|['"])?\s*[:=]\s*(?:\\?"|&quot;|['"])(?P<password>[^"'\s\r\n]{4,128})(?:\\?"|&quot;|['"])`),
		Group: 4,
		Score: 90,
		Categories: []string{"Credentials", "Account"},
	},
	{
		ID:   "requestrider.credential_pair_inverted",
		Name: "credential pair (password and username)",
		Regex: regexp.MustCompile(`(?i)(?:\\?"|&quot;|['"])?\b([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|pwd)[a-z0-9_.\-]*)(?:\\?"|&quot;|['"])?\s*[:=]\s*(?:\\?"|&quot;|['"])(?P<password>[^"'\s\r\n]{4,128})(?:\\?"|&quot;|['"])\s*[,;]?\s*(?:\\?"|&quot;|['"])?\b([a-z0-9_.\-]*(?:user(?:name)?|login|email)[a-z0-9_.\-]*)(?:\\?"|&quot;|['"])?\s*[:=]\s*(?:\\?"|&quot;|['"])([^"'\s\r\n]{3,128})(?:\\?"|&quot;|['"])`),
		Group: 2,
		Score: 90,
		Categories: []string{"Credentials", "Account"},
	},
}

func init() {
	secretRuleRegistry = append(append([]SecretRule{}, titusRules...), projectRules...)
}
