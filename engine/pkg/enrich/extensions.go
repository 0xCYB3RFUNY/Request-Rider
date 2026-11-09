// Package enrich holds the per-page analysers that the Target crawler runs on
// every exchange it reads.
//
// Nothing in this package performs I/O. Every function takes the bytes that were
// already read and returns a description of what was found in them. That is what
// makes the analysers testable against a fixture byte-for-byte and what makes it
// possible to state, for a finding, exactly which function produced it.
//
// The analysers are ports. Each one names the upstream it was ported from in its
// doc comment, and each port is held to the project's reconciliation contract:
// `cariddi_reconciliation.md` in this directory holds one row per capability of
// the original, and `cariddi_reconciliation_test.go` fails if a row is missing a
// verdict, a reason, or a symbol that is not actually in the tree.
package enrich

import (
	"net/url"
	"path"
	"strings"
)

// Severity ranks how much a discovered file is worth the analyst's attention.
//
// The scale is 1..7 and it is deliberately a judgement about *the extension*, not
// about this particular file. A `.php` is worth more than a `.png` because a PHP
// source left where a browser can fetch it is the interesting case; it is not a
// claim that the file on this host is misconfigured. Reporting it as a fact
// would be the wrong kind of claim, and the UI labels it as a ranking.
const (
	SeverityLow      = 1
	SeverityMedium   = 3
	SeverityHigh     = 5
	SeverityCritical = 7
)

// Extension is one entry of the file-extension table.
type Extension struct {
	// Name is the lower-case extension without the leading dot.
	Name string
	// Severity is 1..7; higher deserves earlier attention.
	Severity int
}

// NotableFile is a discovered URL whose extension put it in the table.
type NotableFile struct {
	URL      string `json:"url"`
	Ext      string `json:"extension"`
	Severity int    `json:"severity"`
	Depth    int    `json:"depth,omitempty"`
	Kind     string `json:"kind,omitempty"`
}

// extensionTable is the file-extension ranking.
//
// Port of the capability, not the code: `edoardottt/cariddi`
// (`pkg/scanner/extensions.go`, upstream commit 5ae392d2f064bc6e3a59ed999e337c4a03f4e9e4)
// is GPL-3.0, so nothing is copied; the list of extensions and their relative
// ordering is factual and is re-expressed here in our own shape. Our table is
// keyed on the *last* path segment's suffix and understands multi-part suffixes
// (`tar.gz`, `tar.bz2`), which the original splits on a single dot and therefore
// cannot rank.
//
// Where the original's list contains obvious filler — `pdf1`, `txt1`, `bak1`,
// `log1` — those rows are dropped rather than copied, because they are
// placeholders in the upstream table, not extensions that exist. The verdict for
// that decision is recorded in the reconciliation registry.
var extensionTable = []Extension{
	// 1 — credentials and leftovers. Anything with these on the name is a
	// question before it is an answer.
	{"key", SeverityLow}, {"env", SeverityLow}, {"pem", SeverityLow},
	{"git", SeverityLow}, {"ovpn", SeverityLow}, {"log", SeverityLow},
	{"secret", SeverityLow}, {"secrets", SeverityLow}, {"access", SeverityLow},
	{"bak", SeverityLow}, {"dat", SeverityLow}, {"db", SeverityLow},
	{"sql", SeverityLow}, {"pwd", SeverityLow}, {"passwd", SeverityLow},
	{"gitignore", SeverityLow}, {"crt", SeverityLow}, {"csr", SeverityLow},
	{"keychain", SeverityLow},

	// 2 — configuration.
	{"properties", 2}, {"dtd", 2}, {"conf", 2}, {"cfg", 2},
	{"config", 2}, {"configs", 2}, {"apk", 2}, {"swp", 2},
	{"dbf", 2}, {"mdb", 2}, {"sqlite", 2}, {"ini", 2},

	// 3 — source and configuration in a scripting or data language.
	{"cgi", SeverityMedium}, {"sh", SeverityMedium}, {"py", SeverityMedium},
	{"txt", SeverityMedium}, {"xml", SeverityMedium}, {"java", SeverityMedium},
	{"rb", SeverityMedium}, {"rs", SeverityMedium}, {"go", SeverityMedium},
	{"yml", SeverityMedium}, {"yaml", SeverityMedium}, {"toml", SeverityMedium},
	{"php4", SeverityMedium}, {"json", SeverityMedium}, {"plist", SeverityMedium},
	{"md5", SeverityMedium}, {"torrent", SeverityMedium}, {"rst", SeverityMedium},
	{"bin", SeverityMedium},

	// 3 — archives. `tar.gz` and `tar.bz2` are ranked as themselves; a naive
	// last-dot split would call both `gz`/`bz2` and lose the archive.
	{"zip", SeverityMedium}, {"tar", SeverityMedium}, {"tar.gz", SeverityMedium},
	{"tar.bz2", SeverityMedium}, {"rar", SeverityMedium}, {"7z", SeverityMedium},
	{"gz", SeverityMedium}, {"bz2", SeverityMedium}, {"xz", SeverityMedium},

	// 4 — documents and client code.
	{"doc", 4}, {"docx", 4}, {"csv", 4}, {"odt", 4}, {"xls", 4},
	{"xlsx", 4}, {"ts", 4}, {"js", 4}, {"mjs", 4}, {"cjs", 4}, {"md", 4},

	// 5 — server-side source. A PHP/ASP/JSP file served as text is the case
	// this whole table exists to surface.
	{"php", SeverityHigh}, {"asp", SeverityHigh}, {"aspx", SeverityHigh},
	{"jsp", SeverityHigh}, {"phtml", SeverityHigh}, {"php5", SeverityHigh},
	{"php7", SeverityHigh}, {"pht", SeverityHigh}, {"phar", SeverityHigh},

	// 6 — markup.
	{"html", 6}, {"htm", 6}, {"xhtml", 6},

	// 7 — documents that leak layout and sometimes content.
	{"pdf", SeverityCritical}, {"psd", SeverityCritical}, {"ai", SeverityCritical},
	{"epub", SeverityCritical}, {"mobi", SeverityCritical},
	{"ppt", SeverityCritical}, {"pptx", SeverityCritical},
	{"dochtml", SeverityCritical},

	// SVG is markup that renders in the browser, so it is grouped with the other
	// client-visible formats rather than with the documents that leak layout.
	// It was at 7 in the first version and, measured on help.mail.ru, eleven
	// icons outranked every JavaScript file on the site — a ranking that makes
	// the list useless is not a ranking.
	{"svg", 4},
}

// extensionIndex is the lookup form of extensionTable. Built once at init so the
// crawler does not rebuild a map per discovered URL, which at a few thousand
// pages is a measurable waste for no reason.
var extensionIndex = func() map[string]int {
	index := make(map[string]int, len(extensionTable))
	for _, entry := range extensionTable {
		if _, exists := index[entry.Name]; !exists {
			index[entry.Name] = entry.Severity
		}
	}
	return index
}()

// Extensions returns the ranked extension table.
//
// It is exported so the UI can render the ranking as data rather than as prose
// written by hand, and so a test can assert that no two rows disagree about a
// suffix.
func Extensions() []Extension {
	out := make([]Extension, len(extensionTable))
	copy(out, extensionTable)
	return out
}

// ExtensionOf returns the ranked extension of rawURL, if it has one.
//
// Query strings and fragments are removed before the suffix is read: `a.php?id=1`
// is a PHP file, and reading the suffix off the raw string would answer `php?id=1`.
// Percent-encoding is decoded first so `config%2Eenv` is not silently invisible.
func ExtensionOf(rawURL string) (Extension, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Extension{}, false
	}
	p := parsed.Path
	if p == "" {
		p = parsed.Opaque
	}
	if decoded, err := decodePercent(p); err == nil {
		p = decoded
	}
	return extensionOfPath(p)
}

func extensionOfPath(p string) (Extension, bool) {
	base := path.Base(p)
	if base == "." || base == "/" || base == "" {
		return Extension{}, false
	}
	dot := strings.LastIndex(base, ".")
	if dot <= 0 || dot == len(base)-1 {
		return Extension{}, false
	}
	suffix := strings.ToLower(base[dot+1:])

	// A multi-part suffix wins over its tail: `backup.tar.gz` is the archive,
	// not a bare `gz`. `longestSuffix` picks the longest match so that `tar.bz2`
	// is never shadowed by `bz2`; map iteration order is not stable, so "try
	// them and take the first that matches" would be a coin flip.
	if compound := longestSuffix(base); compound != "" {
		if severity, ok := extensionIndex[compound]; ok {
			return Extension{Name: compound, Severity: severity}, true
		}
	}
	if severity, ok := extensionIndex[suffix]; ok {
		return Extension{Name: suffix, Severity: severity}, true
	}
	return Extension{}, false
}

// multiPartSuffixes holds the dotted suffixes the table ranks as one unit.
// Iteration order is irrelevant — the longest match must win, which the caller
// enforces by comparing lengths before accepting a candidate.
var multiPartSuffixes = map[string]struct{}{
	"tar.bz2": {}, "tar.gz": {},
}

func longestSuffix(base string) string {
	best := ""
	lowered := strings.ToLower(base)
	for candidate := range multiPartSuffixes {
		if len(candidate) <= len(best) {
			continue
		}
		if strings.HasSuffix(lowered, candidate) {
			best = candidate
		}
	}
	return best
}

// NotableFiles ranks rawURLs by the table and returns those at or above
// minSeverity, ordered by descending severity and then by the order they were
// discovered. The input order is the crawl order, so a tie keeps the order the
// analyst would have read the map in.
//
// The returned slice holds copies; the caller owns it.
func NotableFiles(rawURLs []string, minSeverity int) []NotableFile {
	out := make([]NotableFile, 0, 16)
	seen := make(map[string]bool, 16)
	for _, raw := range rawURLs {
		if seen[raw] {
			continue
		}
		seen[raw] = true
		ext, ok := ExtensionOf(raw)
		if !ok || ext.Severity < minSeverity {
			continue
		}
		out = append(out, NotableFile{URL: raw, Ext: ext.Name, Severity: ext.Severity})
	}
	sortNotableBySeverity(out)
	return out
}

func sortNotableBySeverity(files []NotableFile) {
	// Insertion sort: the slice is short in practice (a crawl of a few thousand
	// pages yields tens of ranked files, not thousands), and this keeps the
	// order stable for equal severities without importing a comparison closure
	// that would have to carry state.
	for i := 1; i < len(files); i++ {
		item := files[i]
		j := i - 1
		for j >= 0 && files[j].Severity < item.Severity {
			files[j+1] = files[j]
			j--
		}
		files[j+1] = item
	}
}

// decodePercent percent-decodes a path, returning the input unchanged when the
// escape sequence is malformed. A malformed escape must not turn into an error
// the crawler propagates: the URL is still a URL, we simply could not read a
// suffix out of it.
func decodePercent(p string) (string, error) {
	if !strings.ContainsRune(p, '%') {
		return p, nil
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		if p[i] != '%' || i+2 >= len(p) {
			b.WriteByte(p[i])
			continue
		}
		hi, ok1 := hexVal(p[i+1])
		lo, ok2 := hexVal(p[i+2])
		if !ok1 || !ok2 {
			b.WriteByte(p[i])
			continue
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
