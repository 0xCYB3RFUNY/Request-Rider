package active

// Machine check for xss_upstreams_reconciliation.md.
//
// The six tools reconciled in this register are not one scanner split six ways:
// three of them are XSS tools, one is a 130-detector Rust scanner, one is a
// 121-module pentest framework and one is a Django wrapper around other people's
// binaries. That mixture is the reason this file exists separately from
// `upstreams_reconciliation_test.go` even though both parse the same row shape —
// the loss this register has to catch is not "a module went missing", it is "a
// whole capability family was classified by analogy with the five tools next to
// it and therefore never got a row".
//
// What this test catches:
//
//   - a removed row,
//   - an empty or unknown verdict,
//   - a symbol claimed as ported that is absent from the tree,
//   - `не перенесено` with no stated reason,
//   - a capability this package has that no row covers,
//   - a missing upstream commit.
//
// What it cannot catch is a capability of an upstream that is in neither the
// register nor our tree, because a test has nothing to name it. That is caught
// by the requirement lists at the bottom, which are written by hand from the
// upstream file trees and pinned by name — a capability nobody listed cannot be
// missed by a comparison, only by an absence.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	xssRegisterFile = "xss_upstreams_reconciliation.md"

	// Upstream commits. A register compared against an unstated upstream is a
	// register about an unstated subject, so all six have to be written down —
	// not only the ones whose rows happen to cite them.
	xsstronCommit = "e953389d7ee8e1a81d9a043a081a440acabf1750"
	redteamCommit = "2bbf08de9958c91bc7e239598a5a66f109a703ad"
	lonkeroCommit = "bc1e4859b321e0a6fb125f804b9d7e35975790cc"
	dalfoxCommit  = "709bec946762b0c2e1101f0f37d31e4f108e1936"
	tidosCommit   = "4098187c28236b0b72b6b8102992e259d280dbc9"
	xsserCommit   = "dc72706d2c0dcfe52e355194d1be3b1aed4afca2"
)

// xssUpstreamCommits is the set that must be recorded.
var xssUpstreamCommits = []string{
	xsstronCommit, redteamCommit, lonkeroCommit, dalfoxCommit, tidosCommit, xsserCommit,
}

// xssRegisterRow matches one row: capability, symbol, verdict, reason.
var xssRegisterRow = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|`)

// commitsSection is the heading of the provenance table, whose rows are not verdicts.
const commitsSection = "Коміти upstream"

// moduleTableSection is the heading of the table that names the modules this port
// added. Its rows are coverage rows — a module name and the detector behind it —
// and their third cell is a symbol rather than a verdict, so they answer "is this
// detector classified?" and must not be asked "what is its verdict?".
const moduleTableSection = "Модулі, які додав цей порт"

// commitCell matches the commit column of the provenance table, which shares the
// row shape with a verdict row and would otherwise be read as a verdict.
var commitCell = regexp.MustCompile("^[0-9a-f]{7,40}$")

// identifierCell matches a symbol the tree can be asked about.
var identifierCell = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*$")

// symbolTokens splits a symbol cell into the symbols it names.
//
// Backticks, commas, slashes, brackets and the em dash are separators, so a cell
// reading "`Fresh`, `stripEcho`" yields two symbols and prose around them is
// dropped for being prose rather than a name.
func symbolTokens(cell string) []string {
	spaced := strings.Map(func(r rune) rune {
		switch r {
		case '`', ',', '(', ')', '/', '\u2014', ';':
			return ' '
		}
		return r
	}, cell)
	var out []string
	for _, field := range strings.Fields(spaced) {
		field = strings.Trim(field, " \"'")
		if field == "" || !identifierCell.MatchString(field) {
			continue
		}
		out = append(out, field)
	}
	return out
}

// xssRegisterRowValue is one parsed row.
type xssRegisterRowValue struct {
	capability string
	symbol     string
	verdict    string
	reason     string
	section    string
	line       int
}

// parseXSSRegister reads every capability row of the register.
//
// Two kinds of row are skipped and both skips are explicit rather than silent:
// the commits table (its third column is a hash, and a hash read as a verdict
// would make every register fail for the wrong reason) and the header and
// separator rows.
func parseXSSRegister(t *testing.T) []xssRegisterRowValue {
	t.Helper()
	raw, err := os.ReadFile(xssRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", xssRegisterFile, err)
	}
	var rows []xssRegisterRowValue
	section := ""
	for index, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			continue
		}
		// The provenance table shares a row shape with a verdict table, and its
		// third column is a commit hash. Skipping it by section rather than by
		// column content is deliberate: a hash read as a verdict would fail every
		// register for a reason that has nothing to do with the register.
		if section == "" || section == commitsSection {
			continue
		}
		match := xssRegisterRow.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		capability := strings.TrimSpace(match[1])
		verdict := strings.Trim(strings.TrimSpace(match[3]), "`")
		if strings.HasPrefix(capability, "-") || verdict == "" || commitCell.MatchString(verdict) {
			continue
		}
		// The repeated column header of each table is not a row about a
		// capability; its verdict cell is the word "вердикт".
		if strings.HasPrefix(capability, "здатність") || verdict == "вердикт" {
			continue
		}
		rows = append(rows, xssRegisterRowValue{
			capability: capability,
			symbol:     strings.TrimSpace(match[2]),
			verdict:    verdict,
			reason:     strings.TrimSpace(match[4]),
			section:    section,
			line:       index + 1,
		})
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no capability rows", xssRegisterFile)
	}
	return rows
}

// goTreeText is every identifier-bearing byte of this package, read once.
func goTreeText(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var builder strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		content, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		builder.Write(content)
	}
	return builder.String()
}

func TestXSSRegisterRowsHaveAVerdict(t *testing.T) {
	for _, row := range parseXSSRegister(t) {
		if row.section == moduleTableSection {
			continue
		}
		if !allowedVerdicts[row.verdict] {
			t.Errorf("%s:%d row %q has verdict %q, which is not one of %s / %s / %s",
				xssRegisterFile, row.line, row.capability, row.verdict,
				verdictMatched, verdictImproved, verdictLost)
		}
	}
}

// A `не перенесено` row that does not say what is missing and why is
// indistinguishable from a row that was never written. That is the whole point
// of the row, so the reason has to be there and has to be a sentence.
func TestXSSRegisterLostRowsStateAReason(t *testing.T) {
	for _, row := range parseXSSRegister(t) {
		if row.section == moduleTableSection {
			continue
		}
		if row.verdict != verdictLost {
			continue
		}
		if len(row.reason) < 40 {
			t.Errorf("%s:%d row %q is %q with a %d-character reason, too short to be one: %q",
				xssRegisterFile, row.line, row.capability, verdictLost, len(row.reason), row.reason)
		}
	}
}

// A symbol claimed as ported has to exist. A row that names a symbol this package
// does not define is the shape that lets a capability look carried while the code
// was never written.
func TestXSSRegisterSymbolsExistInTheTree(t *testing.T) {
	tree := goTreeText(t)
	for _, row := range parseXSSRegister(t) {
		if row.section == moduleTableSection {
			continue
		}
		if row.symbol == "" || row.symbol == "—" {
			continue
		}
		// The cell is prose-friendly markdown — backticks, several symbols, a
		// comment — so it is tokenised and every symbol in it is checked. A cell
		// that yields no symbol at all is a failure rather than a skip: "the row
		// names nothing" and "the row names something this package does not have"
		// are the same failure, and only one of them is visible.
		tokens := symbolTokens(row.symbol)
		if len(tokens) == 0 {
			t.Errorf("%s:%d row %q names no symbol this package could check",
				xssRegisterFile, row.line, row.capability)
			continue
		}
		for _, token := range tokens {
			root := token
			if dot := strings.IndexByte(root, '.'); dot > 0 {
				root = root[:dot]
			}
			if !regexp.MustCompile(`\b` + regexp.QuoteMeta(root) + `\b`).MatchString(tree) {
				t.Errorf("%s:%d row %q claims the symbol %q, which is not in the tree",
					xssRegisterFile, row.line, row.capability, token)
			}
		}
	}
}

func TestXSSRegisterNamesEveryUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(xssRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", xssRegisterFile, err)
	}
	for _, commit := range xssUpstreamCommits {
		if !strings.Contains(string(raw), commit) {
			t.Errorf("%s does not record upstream commit %s", xssRegisterFile, commit)
		}
	}
}

// xssRequiredCapabilities is the floor, written by hand from the upstream file
// trees and from this package's own symbols.
//
// It exists because the register can only be compared against a list, and the
// list of "what we have" is exactly the list that let three capabilities be lost
// in a previous port. Every entry is either a capability of one of the six
// upstreams named in a row, or a symbol this package introduced for them.
var xssRequiredCapabilities = []string{
	// XSSTRON.
	"Вихід із RCDATA", "Вихід із JS-рядка одинарною каткою",
	"Вихід із JS-рядка подвійною каткою", "Вихід із шаблонного літерала",
	"Вихід з некатованого значення атрибута", "Зовнішній `//host/x.php`",
	"Інокуляція **фрагмента**", "Перевірка **POST**-форм",
	// Dalfox payloads.
	"HTML-шаблони з обробником події", "Розрив атрибута",
	"JS-прориви: рядки, літерали, сирі позиції", "CSS-сім'ї payload-ів",
	"Пакетна проба спеціальних символів", "Регулярні вирази в JS-контексті",
	"Каталог після обчисленого closer-а", "Екранована кавичка",
	"Вихід із елемента `<script>`",
	// lonkero.
	"`redos.rs`",
	"98 обробників подій", "Autofire-вектори", "mXSS (11 шаблонів",
	"DOM clobbering (8 шаблонів)", "Обхід CSP", "Сліпий XSS через OAST",
	// Dalfox analysis.
	"Класифікація контексту відображення", "Придушення хибних спрацювань",
	"DOM-підтвердження без браузера", "Перевірка JS-контексту через AST",
	"Статичний taint-аналіз DOM", "Визначення технологій",
	"Сторонні бібліотеки з CVE", "9 кодувальників",
	"Виявлення WAF і 15 мутацій обходу",
	// lonkero.
	"Web cache deception", "Server-Side Includes", "`prototype_pollution.rs`",
	"`race_condition.rs`", "`redos.rs`", "`http_smuggling.rs`",
	"`graphql*.rs`", "`bola.rs`", "`cve_2025_5518*.rs`",
	"`cloud_*`", "`favicon_hash_scanner.rs`",
	"`ml/features.rs` (23 ознаки)", "`hybrid_xss/*`",
	// TIDoS.
	"`Severe/xss.py`", "`Severe/shellshock.py`", "`Severe/strutsshock.py`",
	"`Misconfig/hhi.py`", "`xsstrace.py`", "`InfoDisclose/internalip.py`",
	"`ScanningEnumeration/waf.py`", "`Other/{ftp,pop,smtp,sql,ssh,telnet,xmpp}brute.py`",
	"`0x01-PortScanning/*`", "`Severe/subdom0x00.py`", "`files/signaturedb/*.py`",
	// xsser.
	"Оракул виконуваного контексту", "Фільтр хибних спрацювань",
	"Евристика фільтра: 41 проба", "`--checkaturl`", "`--reverse-check`",
	"XSA / XSR / COO", "IND / HTTPrs", "XST: `TRACE /`",
	"Контекстні payload-и AngularJS", "Поліграми (7)",
	// The browser confirmation and the payload table it used to come with. Two
	// rows, because they are two capabilities and one of them did move.
	"Підтвердження виконанням у браузері", "27 DOM-векторів `--Dom`",
	// RedTeam_toolkit.
	"Apache Path Traversal CVE-2021-41773", "HTTP verb tampering",
	"ProxyShell CVE-2021-34523/34473/31207", "F5 BIG-IP CVE-2022-1388",
	"XSS finder (конвеєр", "Web crawler для URL", "Перелік субдоменів",
	"CVE-опитувач CIRCL", "nmap / rustscan / crowbar",
}

// xssRequiredSymbols is what this package introduced for those capabilities, and
// what a row has to cover.
var xssRequiredSymbols = []string{
	"XSSEscape", "xsseRCdataEscapes", "xsseAttributeEscapes", "xsseMarkupEscapes",
	"jsStringEscapes", "jsStringDelimiter", "javascriptURIAssigns",
	"jsBreakoutPlan", "closingOf", "jsBreakoutName", "jsEscapeCatalog", "jsEscapeEntry",
	"jsRegexStartsAt", "jsRegexEnd", "jsKeywordsBeforeRegex", "isJSWordByte",
	"unescapedCloser", "probeFilter", "xsseProbeChars", "xsseFilter",
	"xsseFilter.allowsString", "probeReflected", "segmentContains", "betweenMarkers",
	"inStyleContext", "hasUnclosedStyle", "styleAttributeEscapes",
	"xsseStyleAttributeEscapes", "xsseStyleElementEscapes", "cssContext",
	"ReDoS", "redosFamilies", "redosFamily.payload", "redosControl", "redosMeasureFamily",
	"redosVerdict", "redosEvidence", "redosMinGrowthMS", "redosControlUnit", "isTimeout",
	"confirmInjectedElement", "confirmHandlerInjectedIntoTag", "confirmScriptBreak",
	"scriptIsExecutable", "insideOpenTag", "insideRawTextElement", "attributeAt",
	"eventHandlerName", "JSLibrary", "jsLibraryRules", "jsVersionBelow",
	"jsLibraryVersion", "SSI", "ssiDirectives", "WebCacheDeception",
	"stripDynamicNoise", "rotatingValuePatterns",
	// Browser execution confirmation. `xsser`'s `check_hash_using_dom` is the
	// upstream capability, and these are the four symbols that carry it: the
	// marker, the payload rewrite, the address the run watches, and the proof
	// that raises a row.
	"executeInBrowser", "BrowserProvable", "browserProofPayloads",
	// CSTI, the DOM vector table and prototype pollution: three modules added after
	// the browser channel existed, each with the symbols a row has to name.
	"ClientTemplate", "cstiFrameworks", "cstiProbeSurfaces", "cstiProofPayloads",
	"cstiNamedEngine", "cstiReflects", "cstiEnginePresent", "cstiWrapStart", "cstiWrapEnd",
	"DOMVectors", "domVectors", "domVectorPayload", "domVectorProofPayloads",
	"domVectorSkeleton", "domMarker", "ProtoPollution", "ppProbes", "ppJudge",
	"ppNotPorted", "ppErrorWords", "ppPollutionKeys", "ppFirstKey",
	"xsseMarkerProof", "xsseMarkerURL", "xsseMarkerToken",
	"xsseProofPayload", "proofURL", "Renderer", "WorkerRenderer", "BrowserPage",
	"BrowserPage.Requested", "countUnexecutedEscapes",
}

func TestXSSRegisterCoversTheRequiredFloor(t *testing.T) {
	raw, err := os.ReadFile(xssRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", xssRegisterFile, err)
	}
	text := string(raw)
	for _, capability := range xssRequiredCapabilities {
		if !strings.Contains(text, capability) {
			t.Errorf("%s does not name the capability %q", xssRegisterFile, capability)
		}
	}
	for _, symbol := range xssRequiredSymbols {
		if !strings.Contains(text, symbol) {
			t.Errorf("%s does not name the symbol %q this package defines", xssRegisterFile, symbol)
		}
	}
}

// Every capability this package added has to be accounted for. The list is
// spelled out rather than derived from the tree so that adding a detector without
// adding a row is a test failure instead of a silent divergence.
func TestXSSRegisterCoversEverySymbolThisPackageAdded(t *testing.T) {
	raw, err := os.ReadFile(xssRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", xssRegisterFile, err)
	}
	text := string(raw)
	for _, symbol := range []string{"XSSEscape", "JSLibrary", "SSI", "WebCacheDeception"} {
		if !strings.Contains(text, symbol) {
			t.Errorf("%s does not cover the detector %q", xssRegisterFile, symbol)
		}
	}
	// The four detectors must be registered in the run, or the register describes
	// code that never fires.
	source := goTreeText(t)
	for _, module := range []string{"XSSEscape{}", "JSLibrary{}", "SSI{}", "WebCacheDeception{}"} {
		if !strings.Contains(source, module) {
			t.Errorf("modulesFor does not run %q: the register describes a detector the run never reaches", module)
		}
	}
}

// The register names seven libraries and so does the detector. If the two drift,
// the register's "супадає" row becomes a claim about a table that no longer
// exists.
func TestXSSRegisterLibraryCountMatchesTheDetector(t *testing.T) {
	names := jsLibraryNames()
	if len(names) != 7 {
		t.Fatalf("jsLibraryRules has %d libraries, want the 7 the register names", len(names))
	}
	raw, err := os.ReadFile(xssRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", xssRegisterFile, err)
	}
	for _, name := range names {
		if !strings.Contains(string(raw), name) {
			t.Errorf("%s does not name the library %q the detector reports", xssRegisterFile, name)
		}
	}
}

// The register's sorted list of what was consciously not carried is the summary a
// reader reads first, and it is the part that goes stale silently. Every heading
// in that section has to name at least one capability that also has a row.
func TestXSSRegisterClosingListIsNotEmpty(t *testing.T) {
	raw, err := os.ReadFile(xssRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", xssRegisterFile, err)
	}
	text := string(raw)
	marker := "## Що залишилось некласифікованим"
	index := strings.Index(text, marker)
	if index < 0 {
		t.Fatalf("%s has no closing section", xssRegisterFile)
	}
	closing := text[index:]
	bullets := strings.Count(closing, "\n1.")
	if bullets == 0 {
		t.Errorf("%s closing section lists nothing, which is what 'nothing was lost' looks like", xssRegisterFile)
	}
	// Every tool has to appear in the closing list too: a register that names a
	// tool only in its provenance table has reconciled nothing about it.
	for _, tool := range []string{"XSSTRON", "Dalfox", "lonkero", "TIDoS", "xsser", "RedTeam_toolkit"} {
		if !strings.Contains(text, tool) {
			t.Errorf("%s does not name %s outside the commits table", xssRegisterFile, tool)
		}
	}
	sort.Strings(xssUpstreamCommits)
	if xssUpstreamCommits[0] == "" {
		t.Error("upstream commit set is empty")
	}
}

// loadXSSRegister reads this port's register into the row type the package's
// older guard already uses.
//
// The guard in `vexor_reconciliation_test.go` asks every detector whether *any*
// register classifies it, and it loads two files by name. A third register added
// by a later port is therefore invisible to it, and the guard reports a detector
// that demonstrably has a row as unclassified — a false alarm produced by a guard
// narrower than the thing it guards. Widening the guard is the fix; stopping the
// report would be the failure mode the guard exists to prevent.
func loadXSSRegister(t *testing.T) []registerRow {
	t.Helper()
	var out []registerRow
	for _, row := range parseXSSRegister(t) {
		out = append(out, registerRow{
			capability: row.capability,
			symbol:     row.symbol,
			verdict:    row.verdict,
			reason:     row.reason,
			line:       strconv.Itoa(row.line),
		})
	}
	return out
}

// xssRegisterRowsForNarrowGuard is the same content in the six-upstream guard's
// own row type, for the same reason and with the same one-line change on its side.
func xssRegisterRowsForNarrowGuard(t *testing.T) []upstreamRegisterRow {
	t.Helper()
	var out []upstreamRegisterRow
	for _, row := range parseXSSRegister(t) {
		out = append(out, upstreamRegisterRow{
			tool:       "this port's six upstreams",
			capability: row.capability,
			symbol:     row.symbol,
			verdict:    row.verdict,
			reason:     row.reason,
			line:       strconv.Itoa(row.line),
		})
	}
	return out
}
