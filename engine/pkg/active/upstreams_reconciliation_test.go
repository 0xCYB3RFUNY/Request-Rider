// Machine check for upstreams_reconciliation.md.
//
// Six upstreams are reconciled in one register, so this file has one job beyond
// the VEXOR register's: it must be possible for a capability of the *sixth* tool
// to be lost in exactly the way the first one's were — a row that was simply never
// written, because the list being compared was "what we have" rather than "what
// they have". The dynamic check at the bottom is the part that answers that, and
// it exists because a register cannot enumerate a capability it does not know
// about.
//
// What this test catches:
//
//   - a removed row,
//   - an empty or unknown verdict,
//   - a verdict outside the three allowed values,
//   - a symbol claimed as ported that is absent from the tree,
//   - `не перенесено` with no stated reason,
//   - a capability we have that no row covers,
//   - a missing upstream commit.
//
// What it cannot catch is an upstream capability in neither the register nor our
// tree, because a test has nothing to name it. That is caught by the per-tool
// requirement lists below, which are written by hand *from the upstream file
// trees* and pinned by name — and the reason they are pinned by name is that a
// capability nobody listed cannot be missed by a comparison, only by an absence.

package active

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	upstreamsRegisterFile = "upstreams_reconciliation.md"

	// Upstream commits. A register compared against an unstated upstream is a
	// register about an unstated subject, so every one of the six is required to
	// be written down — not only the ones whose rows happen to cite them.
	arachniCommit   = "9cd73f2541ef57814312b0aefe079ad428722b84"
	jaelesCommit    = "d40305ffe42a831b2b144e48d0428de4def4270a"
	flanCommit      = "6588b07751f14180ba151842458b97510490fa58"
	blackwidowComit = "c9eb24e238c390b03897a04c79e55cb17ec35b8c"
	backslashCommit = "1194cf8651aec69f79e22bf4100f18ec9685d8c5"
	eagleCommit     = "bde6c28af7736ec88edbab51828e3c080791eaa6"
)

// upstreamCommits is the set that must be recorded.
var upstreamCommits = []string{
	arachniCommit, jaelesCommit, flanCommit, blackwidowComit, backslashCommit, eagleCommit,
}

// The verdict vocabulary — `verdictMatched`, `verdictImproved`, `verdictLost` and
// the `allowedVerdicts` set — is declared once, in `vexor_reconciliation_test.go`,
// and is deliberately NOT redeclared here.
//
// Two registers in one package sharing a closed set of three values is exactly
// the situation where the two copies drift: a typo in one file's spelling turns a
// legitimate verdict into a failure in one register and not the other, and the
// first thing a maintainer does then is "fix" the test rather than the register.
// One vocabulary for the package is the only arrangement where the two registers
// can be compared to each other at all — and comparing them is the whole point:
// a capability claimed as carried from VEXOR and the same capability claimed here
// must mean the same thing by the same word.

// registerRowPattern matches one row: a table row with a capability in the first
// cell and a verdict in the third.
var registerRowPattern = regexp.MustCompile(
	`^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|`)

// requiredUpstreamCapabilities is the per-tool floor.
//
// Every entry is a capability or file named in a row of the register, and every
// entry was taken from that tool's *file tree* rather than from the register —
// otherwise the guard would only re-read what the register already claims, and
// would pass exactly when the register forgot something. Each tool's list is
// pinned separately so that a row cannot be quietly relabelled from one tool's
// section into another's and still satisfy a different tool's requirement.
var requiredUpstreamCapabilities = map[string][]string{
	"arachni": {
		"SQLi", "NoSQL", "XPath", "LDAP", "XXE", "Code injection", "CSRF",
		"Session fixation", "Response splitting", "Source code disclosure",
		"Sensitive files", "Directory listing", "Emails", "Insecure cookies",
		"Allowed methods", "Path traversal", "OS command injection",
		"CVS / SVN users", "HTML objects", "Password autocomplete",
		"Form upload", "Backdoors", "Localstart ASP", "Insecure client access policy",
		"Cross-domain policy", "XSS",
	},
	"jaeles": {
		"Підпис як окремий артефакт", "Генератор payloads", "Passive-підписи",
		"Фільтри рівня", "Конкурентний надсилач", "Прогрес і завершення",
		"Співпрацювальник",
	},
	"flan": {
		"Сканування TCP-портів", "Визначення версії сервісу", "Матчинг CVE",
		"Звіти LaTeX", "Вивантаження в GCS", "Розгортання в Kubernetes",
	},
	"blackwidow": {
		"Збір URL", "Збір динамічних параметрів", "Збір форм", "Збір субдоменів",
		"Збір email-адрес", "Збір телефонів", "Open Redirect", "SQLi",
		"Directory Traversal", "LFI", "RFI", "SSTI", "Command Execution",
	},
	"backslash-powered-scanner": {
		"Аналіз трансформації", "Набір 19 спецсимволів", "Decode-based payloads",
		"Визначення мови екранування", "Bulk scan", "Diffing-скан",
	},
	"ours": {
		"Сліпий NoSQL-диференціал", "Свіжість на fingerprint", "Розрізнення «м'який 404»",
		"Доказ запису через PUT", "Аналіз стеку екранування", "Арифметика з простих",
		"Реєстр звірки як механізм",
	},
	"eagle": {
		"CRLF-ін'єкція", "Sensitive files", "Сумісність Spider", "HTTP Request Smuggling",
		"Subdomain takeover", "Anonymous FTP", "S3 bucket", "Firebase", "Відсутній SPF-запис",
		"Path Traversal", "CVE-2012-1823", "CVE-2014-6271", "CVE-2018-11776",
		"CVE-2019-2725", "CVE-2019-3396", "CVE-2019-5418", "CVE-2019-8451",
		"CVE-2019-10098",
	},
}

// requiredUpstreamRowCount is *this* register's row count, pinned in both
// directions.
//
// It is a separate constant from the VEXOR register's `requiredRowCount` and is
// deliberately not shared. The two registers count different subjects — one
// reconciles one upstream, the other reconciles six — so one counter for both would
// force the VEXOR guard to move whenever a sixth tool gained a row, and a guard
// whose number moves for unrelated reasons is a guard nobody trusts.
//
// Pinning only downwards would let a capability vanish unnoticed; pinning only
// upwards would let the table grow without anyone deciding it should. Both
// directions are checked.
// It moved 115 → 119 on 2026-10-03, when the four capabilities from the owner's
// list were given rows of their own here as well as in the VEXOR register. Both
// registers guard the same dynamic coverage test, and a row in only one of them
// would have been found by whichever guard read the other — which is the same
// false alarm in reverse: a capability that demonstrably has a row reported as
// unclassified because the guard that ran was not the guard that read.
// verdictHeader is the third column of every capability table in the register. The
// tables differ in their first two columns — one is keyed by upstream
// capability, another by the detector name as it appears in the report — so the
// verdict column is the one cell they all share, and it is what a table is
// recognised by.
const verdictHeader = "вердикт"

const requiredUpstreamRowCount = 133

// loadUpstreamRegister parses the six-upstream register into this file's own row
// type.
//
// A conversion rather than a shared type on purpose: the two registers have
// different columns and different sectioning, and unifying them would couple two
// guards that are allowed to change for unrelated reasons. The only thing they must
// share is the verdict vocabulary, which they do share because it is one package
// constant.
func loadUpstreamRegister(t *testing.T) []registerRow {
	t.Helper()
	parsed := readUpstreamRegister(t)
	out := make([]registerRow, 0, len(parsed))
	for _, row := range parsed {
		out = append(out, registerRow{row.capability, row.symbol, row.verdict, row.reason, row.line})
	}
	return out
}

type upstreamRegisterRow struct {
	tool       string
	capability string
	symbol     string
	verdict    string
	reason     string
	line       string
}

// readUpstreamRegister parses the register.
//
// A line that looks like a table row but has fewer than four cells is a failure
// rather than a row to skip: a capability row that lost its reason cell is exactly
// how a `не перенесено` loses the reason that makes it honest.
func readUpstreamRegister(t *testing.T) []upstreamRegisterRow {
	t.Helper()
	source, err := os.ReadFile(upstreamsRegisterFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v", upstreamsRegisterFile, err)
	}
	tool := ""
	inCapabilityTable := false
	var rows []upstreamRegisterRow
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			// A numbered heading names the tool from here on. The headings are
			// written `## 1. Arachni — …`, so the tool is the second word.
			if strings.HasPrefix(trimmed, "## ") {
				tool = ""
				inCapabilityTable = false
				if name := upstreamToolFromHeading(trimmed); name != "" {
					tool = name
				}
				if strings.Contains(trimmed, "Наші власні здатності") ||
					strings.Contains(trimmed, "Модулі цього порту") {
					tool = "ours"
				}
			}
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) < 4 {
			if len(cells) == 2 || upstreamTableFurniture(trimmed) {
				continue
			}
			t.Errorf("a capability row has %d cells, needs 4: %s", len(cells), trimmed)
			continue
		}
		match := registerRowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		capability, symbol, verdict, reason := match[1], match[2], match[3], match[4]
		// A row counts as a capability row only when it belongs to a *capability*
		// table, which is decided by that table's own header rather than by where
		// it sits in the file.
		//
		// The earlier rule was positional — metadata lives above the first numbered
		// heading — and a section that carries its own `### Коміти upstream` table
		// inside a numbered section broke it: the commit hashes of that table were
		// read as verdicts. The guard itself was right and its assumption was
		// wrong, so the assumption went, not the guard: a capability row that loses
		// its verdict still sits in the capability table and is still reported.
		if strings.EqualFold(strings.TrimSpace(cells[2]), verdictHeader) {
			inCapabilityTable = true
			continue
		}
		if !inCapabilityTable {
			continue
		}
		if strings.EqualFold(capability, "здатність upstream") ||
			strings.HasPrefix(capability, "---") || verdict == "вердикт" {
			continue
		}
		rows = append(rows, upstreamRegisterRow{
			tool: tool, capability: strings.TrimSpace(capability),
			symbol: strings.TrimSpace(symbol), verdict: strings.TrimSpace(verdict),
			reason: strings.TrimSpace(reason), line: trimmed,
		})
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no rows; it parses as empty rather than as complete", upstreamsRegisterFile)
	}
	return rows
}

// upstreamToolFromHeading reads the tool name out of a `## N. Name — tree` heading.
//
// The heading is `## 1. Arachni — components/checks/active`, so the name is the
// first field after the `##` that does not end in a dot. Selecting by index
// instead — "field 1" — looks equivalent and is not: `fields[1]` is `1.` on every
// heading, so every tool resolved to the same name and all six sections were
// attributed to one tool. That is the shape of a guard that reports every tool as
// empty while every tool's rows are present, and it was caught here by the test
// failing on a register that was, row for row, complete.
func upstreamToolFromHeading(heading string) string {
	fields := strings.Fields(heading)
	// Only a *numbered* heading names an upstream: `## 3. flan — …`. An
	// unnumbered heading (`## Коміти upstream`, `## Вердикти`) must return "",
	// which resets the current tool — otherwise a section title is read as the
	// name of a tool and everything under it is attributed to it.
	for index, field := range fields {
		if field == "##" {
			continue
		}
		if !strings.HasSuffix(field, ".") {
			return ""
		}
		if index+1 < len(fields) {
			return strings.ToLower(strings.Trim(fields[index+1], ".,:;—"))
		}
	}
	return ""
}

// upstreamTableFurniture reports whether a short line is a header separator.
func upstreamTableFurniture(line string) bool {
	for _, cell := range strings.Split(strings.Trim(line, "|"), "|") {
		cell = strings.TrimSpace(cell)
		if cell == "" {
			continue
		}
		if !strings.HasPrefix(cell, "-") {
			return false
		}
	}
	return true
}

// TestEveryUpstreamCommitIsRecorded: six upstreams, six commits, all written down.
func TestEveryUpstreamCommitIsRecorded(t *testing.T) {
	source, err := os.ReadFile(upstreamsRegisterFile)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	text := string(source)
	for _, commit := range upstreamCommits {
		if !strings.Contains(text, commit) {
			t.Errorf("the register does not record upstream commit %s", commit)
		}
	}
}

// TestEveryUpstreamToolHasRows is the six-tool counterpart of the VEXOR register's
// "is it empty" check: a tool whose section lost every row would otherwise leave
// the register looking complete.
func TestEveryUpstreamToolHasRows(t *testing.T) {
	rows := readUpstreamRegister(t)
	counted := map[string]int{}
	for _, row := range rows {
		if row.tool != "" {
			counted[row.tool]++
		}
	}
	for tool, required := range requiredUpstreamCapabilities {
		if counted[tool] == 0 {
			t.Errorf("no register row belongs to %q; its section lost every row", tool)
		}
		if counted[tool] < len(required) {
			t.Errorf("%q has %d rows, but %d of its capabilities are required by name",
				tool, counted[tool], len(required))
		}
	}
}

// TestEveryRequiredUpstreamCapabilityIsPresent answers a deleted row, per tool.
//
// The per-tool split is the part that matters. A single flat requirement list
// would be satisfied by the same row name appearing in any section, so moving a
// row from Eagle's section into Arachni's — which is what a careless merge looks
// like — would keep the suite green while losing the classification.
func TestEveryRequiredUpstreamCapabilityIsPresent(t *testing.T) {
	rows := readUpstreamRegister(t)
	for tool, required := range requiredUpstreamCapabilities {
		section := make([]upstreamRegisterRow, 0, len(rows))
		for _, row := range rows {
			if row.tool == tool {
				section = append(section, row)
			}
		}
		for _, capability := range required {
			found := false
			for _, row := range section {
				if strings.Contains(row.capability, capability) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: required row %q is gone; the register is incomplete for this upstream",
					tool, capability)
			}
		}
	}
}

// TestRowCountIsPinnedInBothDirections.
func TestRowCountIsPinnedInBothDirections(t *testing.T) {
	rows := readUpstreamRegister(t)
	if len(rows) != requiredUpstreamRowCount {
		t.Errorf("the register has %d rows, want %d; a count that drifts in either direction "+
			"means the table changed without anyone deciding it should", len(rows), requiredUpstreamRowCount)
	}
}

// TestEveryRowHasAVerdictFromTheAllowedThree is the core of the rule.
func TestEveryUpstreamRowHasAVerdictFromTheAllowedThree(t *testing.T) {
	for _, row := range readUpstreamRegister(t) {
		if row.verdict == "" {
			t.Errorf("row %q has no verdict; silence is not a verdict", row.capability)
			continue
		}
		if !allowedVerdicts[row.verdict] {
			t.Errorf("row %q has verdict %q, which is not one of %s / %s / %s",
				row.capability, row.verdict, verdictMatched, verdictImproved, verdictLost)
		}
	}
}

// TestEveryRowNamesACapabilityWithText guards the parse itself: a row whose
// capability cell is empty claims a completeness it does not have.
func TestEveryUpstreamRowNamesACapabilityWithText(t *testing.T) {
	for _, row := range readUpstreamRegister(t) {
		capability := strings.TrimSpace(row.capability)
		if capability == "" || capability == "—" || capability == "-" {
			t.Errorf("a register row has no capability name: %s", row.line)
		}
	}
}

// TestLostRowsStateAReason is what makes `не перенесено` usable: it has to say
// what is missing and why, or it is indistinguishable from a row never written.
func TestUpstreamLostRowsStateAReason(t *testing.T) {
	for _, row := range readUpstreamRegister(t) {
		if row.verdict != verdictLost {
			continue
		}
		reason := strings.TrimSpace(row.reason)
		if reason == "" {
			t.Errorf("row %q is %q with no reason; that is the silent-loss shape", row.capability, verdictLost)
		}
		if len([]rune(reason)) < 40 {
			t.Errorf("row %q gives a %d-character reason, too short to be one: %q",
				row.capability, len([]rune(reason)), reason)
		}
	}
}

// upstreamClaimedIdentifier pulls Go identifiers out of a symbol cell.
//
// Only backticked text is read, and only from cells that look like a symbol list.
// An earlier version scanned every word in the cell, which made `FNV-1a` demand a
// symbol called `FNV` and reported sixteen missing symbols, all of them
// inventions — and a guard that reports inventions is a guard whose real findings
// stop being read.
var upstreamBackticked = regexp.MustCompile("`([^`]+)`")
var upstreamIdentifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// upstreamFileExtension matches a cell that names a file rather than a symbol.
//
// The extension set is the set this project actually cites: Go and Markdown for
// our own tree, and Ruby, Java, Python, shell, JSON, YAML and Nmap-script for the
// six upstreams.
var upstreamFileExtension = regexp.MustCompile(
	`(?i)\.(go|md|rb|java|py|txt|sh|json|ya?ml|nse|ps1|bat)$`)

// TestClaimedSymbolsExistInTheTree stops a register from claiming a port that is
// not in the code.
//
// A `не перенесено` row carries no symbol by definition and is skipped. A cell
// whose backticked content is a file path, a command or prose is skipped rather
// than guessed at, for the reason above.
func TestUpstreamClaimedSymbolsExistInTheTree(t *testing.T) {
	for _, row := range readUpstreamRegister(t) {
		if row.verdict == verdictLost {
			continue
		}
		for _, match := range upstreamBackticked.FindAllStringSubmatch(row.symbol, -1) {
			for _, name := range upstreamIdentifiers(match[1]) {
				if !declaredInActivePackage(name) {
					t.Errorf("row %q claims symbol %q, which is not declared in the package",
						row.capability, name)
				}
			}
		}
	}
}

// upstreamIdentifiers returns the identifiers one backticked cell names.
func upstreamIdentifiers(cell string) []string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cell), "*"))
	if trimmed == "" {
		return nil
	}
	// A prose value, a path, a command, or a hash name: nothing here is a symbol
	// the package could declare.
	if strings.ContainsAny(trimmed, " /\\=") {
		return nil
	}
	// A file name is the case that got through. `upstreams_reconciliation_test.go`
	// has no slash and no `=`, so it survived both tests above and then reduced to
	// the identifier `go` after the last dot was stripped — an invented symbol,
	// reported as missing, for a file that is sitting right there in the package.
	if upstreamFileExtension.MatchString(trimmed) {
		return nil
	}
	base := trimmed
	if index := strings.LastIndex(base, "."); index >= 0 {
		base = base[index+1:]
	}
	if index := strings.Index(base, "("); index >= 0 {
		base = base[:index]
	}
	var out []string
	for _, candidate := range upstreamIdentifier.FindAllString(base, -1) {
		out = append(out, candidate)
	}
	return out
}

// declaredInActivePackage reports whether the package declares a top-level
// identifier, in production or test code.
//
// The split between the two is deliberate and is inherited from the VEXOR guard: a
// register row may cite a test as its own evidence, so a `Test…` name may live in
// a test file. But a feature row pointing at a test would be claiming a port
// proven by a test alone, which is the confusion this whole mechanism exists to
// stop.
func declaredInActivePackage(name string) bool {
	isTest := strings.HasPrefix(name, "Test")
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(name) + `\s*[\(\{]`),
		regexp.MustCompile(`(?m)^func\s+\([^)]*\)\s*\*?` + regexp.QuoteMeta(name) + `\s*[\(\{]`),
		regexp.MustCompile(`(?m)^type\s+` + regexp.QuoteMeta(name) + `\b`),
		regexp.MustCompile(`(?m)^var\s+` + regexp.QuoteMeta(name) + `\b`),
		regexp.MustCompile(`(?m)^\t` + regexp.QuoteMeta(name) + `\s+[A-Za-z\[\*]`),
		// A grouped `const`/`var` entry is `Name = value` on an indented line,
		// which the two patterns above miss: the first wants a type after the name
		// and the const has none. Without this the guard reported a perfectly
		// real declaration as missing, and a guard that reports declarations that
		// exist is a guard whose real findings get ignored.
		regexp.MustCompile(`(?m)^\t` + regexp.QuoteMeta(name) + `\s*=[^=]`),
		regexp.MustCompile(`(?m)^const\s+` + regexp.QuoteMeta(name) + `\b`),
	}
	// The module tree, not this directory: a port of this register landed in the
	// root package (`jsFindingSink` in `target_js_findings.go`), and a guard that
	// only looks where it stands reports a real declaration as missing. Two
	// guards with two scopes on the same word is also how one of them starts
	// disagreeing with the other, so both read the same file list now.
	entries, err := moduleGoFiles()
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry, "_test.go") != isTest {
			continue
		}
		body, readErr := os.ReadFile(entry)
		if readErr != nil {
			continue
		}
		text := string(body)
		for _, pattern := range patterns {
			if pattern.MatchString(text) {
				return true
			}
		}
	}
	return false
}

// TestEveryDetectorOfThisPortIsClassified is the direction that catches a
// capability arriving unclassified.
//
// It is the same hole the VEXOR guard closes, for the same reason: a hand-written
// list of our own capabilities has to be remembered, so a detector added to
// `AllModules()` joins the scanner without a row and every other test still
// passes. Reading the coverage from the code instead means adding a detector is a
// change that cannot be made quietly.
func TestEveryDetectorOfThisPortIsClassified(t *testing.T) {
	rows := readUpstreamRegister(t)
	// Sibling registers count too. This guard asks "is every detector classified
	// *somewhere*", and loading one file made the answer wrong for every detector
	// a later port added: the register existed, the detector had a row in it, and
	// the report said otherwise. A guard narrower than its subject produces false
	// alarms, and the answer to that is to widen the guard.
	rows = append(rows, xssRegisterRowsForNarrowGuard(t)...)
	// The Burp register is the third sibling, for the same reason: twelve checks
	// arrived from Burp Suite's scan list, which is neither this port's six
	// upstreams nor the XSS one.
	rows = append(rows, burpRegisterRowsForNarrowGuard(t)...)
	// `modulesFor` is asked directly rather than `AllModules`, because
	// `AllModules()` hands out `Redirect{}` with an empty marker and this check is
	// about the *set*, not about one detector's construction.
	for _, module := range modulesFor("example.invalid", 0) {
		if !upstreamRowMentions(rows, module.Name()) {
			t.Errorf("detector %q has no row in the upstream register, so its verdict is unclassified: "+
				"a detector that joined the scanner without a row is a capability nobody decided on",
				module.Name())
		}
	}
}

// upstreamRowMentions reports whether any cell of any row names the given subject.
func upstreamRowMentions(rows []upstreamRegisterRow, name string) bool {
	wanted := strings.ToLower(name)
	for _, row := range rows {
		for _, cell := range []string{row.capability, row.symbol, row.reason} {
			if strings.Contains(strings.ToLower(cell), wanted) {
				return true
			}
		}
	}
	return false
}

// TestThePortDetectorsAreTheOnesThisRegisterDescribes pins the count.
//
// The dynamic check above is only as good as what it reads, and it reads the
// detector set. A silent change to that set would still satisfy every row in the
// register — the register would simply stop describing the scanner. So the count
// is asserted, and so is the presence of every detector this port added by name,
// because a detector renamed without a register edit would otherwise pass as
// covered by its old name.
func TestThePortDetectorsAreTheOnesThisRegisterDescribes(t *testing.T) {
	modules := modulesFor("example.invalid", 0)
	names := make([]string, 0, len(modules))
	for _, module := range modules {
		names = append(names, module.Name())
	}
	added := []string{
		"nosql", "xpath", "ldap", "xxe", "codeinj", "crlf",
		"methods", "escaping", "csrf", "sessionfixation", "srcdisc", "pii", "cookies",
	}
	for _, name := range added {
		found := false
		for _, candidate := range names {
			if candidate == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("this port added detector %q and it is no longer in the detector set; "+
				"either it was removed on purpose — in which case the register needs an "+
				"`%s` row saying so — or it was renamed without the register being told",
				name, verdictLost)
		}
	}
	sort.Strings(names)
	t.Logf("the detector set this register describes is %v", names)
	if len(modules) == 0 {
		t.Fatal("the detector set is empty, so every check above is asserting nothing")
	}
}

// TestVerdictVocabularyHasNoFourthState documents the closed set in code, so the
// test and the register cannot drift apart.
func TestVerdictVocabularyIsSharedWithTheOtherRegister(t *testing.T) {
	want := []string{verdictImproved, verdictLost, verdictMatched}
	sort.Strings(want)
	got := make([]string, 0, len(allowedVerdicts))
	for verdict := range allowedVerdicts {
		got = append(got, verdict)
	}
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the verdict vocabulary is %v, want exactly %v", got, want)
	}
}
