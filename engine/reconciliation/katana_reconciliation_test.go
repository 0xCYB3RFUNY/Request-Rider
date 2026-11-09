// Machine check for katana_reconciliation.md.
//
// The register this test guards exists because three capabilities of the vexor
// port were lost silently: every row existed, the suite was green, and a
// capability nobody ported could not appear in a list ordered by "compare what
// we have". The gap was closed by taking the capability list from upstream's
// FILES and by making the register checkable rather than prose.
//
// What this test can catch, stated plainly so it is not oversold:
//
//   - a removed row,
//   - an empty or unknown verdict, or a verdict outside the three allowed,
//   - a symbol claimed as ported that is absent from OUR tree,
//   - `не перенесено` with no stated reason,
//   - a capability we have that no row covers,
//   - a missing upstream commit,
//   - an upstream parser that no row names (the list is pinned below).
//
// What it CANNOT catch is an upstream capability that is in neither the register
// nor our tree, because a test has nothing to name it. That is caught by the
// upstream file listing in the register header plus TestEveryUpstreamParserIsNamed
// — neither can be satisfied from memory, and memory is what produced the loss.

package reconciliation

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	katanaRegister    = "katana_reconciliation.md"
	katanaCommit      = "04a51b8"
	katanaRowCount    = 126
	verdictMatched    = "совпадає"
	verdictImproved   = "улучшено"
	verdictLost       = "не перенесено"
	upstreamCloneHint = "~/katana"
)

var allowedVerdicts = map[string]bool{
	verdictMatched:  true,
	verdictImproved: true,
	verdictLost:     true,
}

// upstreamParsers is the parser registry read out of upstream's own source, not
// from the README and not from memory.
//
// It is the mechanical answer to "an ability nobody transferred": a parser added
// upstream and absent from every row is a named diff in this file, so the guard
// fires instead of the register quietly omitting it. The earlier failure mode was
// a fixture carrying three of ten markers — parity on a subset picked to match
// our own answer compares nothing. So the list is the whole registry.
//
// Names and line numbers are taken from `NewResponseParser()` in
// ~/katana/pkg/engine/parser/parser.go.
var upstreamParsers = map[string]string{
	"headerContentLocationParser":       "parser.go:122",
	"headerLinkParser":                  "parser.go:132",
	"headerRefreshParser":               "parser.go:155",
	"headerLocationParser":              "parser.go:145",
	"bodyATagParser":                    "parser.go:173",
	"bodyLinkHrefTagParser":             "parser.go:188",
	"bodyEmbedTagParser":                "parser.go:199",
	"bodyFrameTagParser":                "parser.go:210",
	"bodyIframeTagParser":               "parser.go:221",
	"bodyInputSrcTagParser":             "parser.go:239",
	"bodyIsindexActionTagParser":        "parser.go:250",
	"bodyScriptSrcTagParser":            "parser.go:261",
	"bodyBackgroundTagParser":           "parser.go:272",
	"bodyAudioTagParser":                "parser.go:283",
	"bodyAppletTagParser":               "parser.go:306",
	"bodyImgTagParser":                  "parser.go:321",
	"bodyObjectTagParser":               "parser.go:354",
	"bodySvgTagParser":                  "parser.go:375",
	"bodyTableTagParser":                "parser.go:394",
	"bodyVideoTagParser":                "parser.go:411",
	"bodyBlockquoteCiteTagParser":       "parser.go:432",
	"bodyMapAreaTagParser":              "parser.go:443",
	"bodyBaseHrefTagParser":             "parser.go:458",
	"bodyImportImplementationTagParser": "parser.go:469",
	"bodyButtonFormactionTagParser":     "parser.go:480",
	"bodyHtmlManifestTagParser":         "parser.go:491",
	"bodyHtmlDoctypeTagParser":          "parser.go:502",
	"bodyMetaContentTagParser":          "parser.go:613",
	"bodyHtmxAttrParser":                "parser.go:627",
	"customFieldRegexParser":            "parser.go:781",
}

// requiredRows is the set of capabilities the register has to carry.
//
// It exists because a removed row was invisible to the guard: nothing counted
// rows and nothing named them, so deleting the CMDi line left the suite green —
// the exact failure the register was written to prevent, reproduced inside the
// mechanism meant to catch it. So the rows are pinned by name AND the count is
// pinned, which makes both deletion and silent growth deliberate.
var requiredRows = []string{
	// pkg/engine/standard + common — the crawl loop itself
	"стандартний HTTP-обхід BFS/DFS",
	"повтор запиту + `Retry-After`",
	"ланцюг редиректів як доказ",
	"читання тіла без межі",
	"cookie jar на весь обхід",
	"імітація TLS ClientHello",
	"адаптивний backoff за хостом",
	"глобальний і per-host rate limit",
	// pkg/utils
	"дедуплікація URL",
	"дедуплікація контенту MD5",
	"детекція редирект-циклу",
	"BFS з пріоритетом глибини",
	"DFS через стек",
	"черга з виходом по context",
	"відновлення після зупинки",
	"фільтр розширень",
	"фільтр URL за regex",
	"фільтр за DSL-умовою",
	"фільтр за типом сторінки",
	"власні regex-поля з YAML",
	"14 вбудованих полів URL",
	"шаблон виводу `{{field}}`",
	"сховище сирих обмінів на диску",
	"лічильник результатів",
	"помилковий потік JSONL",
	// pkg/engine/parser/files
	"robots.txt",
	"sitemap.xml",
	// pkg/types + knowledgebase
	"визначення технологій wappalyzer",
	"база знань про тип сторінки",
	"видобуток секретів",
	"жива валідація секретів",
	"класифікація ендпоінтів",
	// pkg/similarity
	"фільтр схожості simhash",
	"фільтр схожості TF-IDF / BM25",
	"кластеризація сторінок",
	"нормалізація тексту для схожості",
	// parser output and JS extraction
	"збереження JS-аналізу на тілі сторінки",
	"інлайн-аналіз тексту `<script>`",
	"видобуток ендпоінтів з JS/CSS",
	"видобуток з довільного текстового тіла",
	"захист від бінарного тіла",
	"jsluice AST",
	"пропуск бібліотек JS",
	// hybrid engine
	"гібридний рушій",
	"XHR-відловлення",
	"обхід shadow DOM",
	"симуляція `onclick`",
	"відстеження навігації з JS",
	"стратегії завантаження сторінки",
	"гачки гібрида",
	// pure headless engine
	"чисто-headless рушій",
	"граф обходу",
	"відбиток стану сторінки",
	"відновлення стану в три етапи",
	"нормалізатор DOM",
	"прискорення таймерів у браузері",
	"перехоплення навігаційних джерел",
	"зняття подій DOM",
	"stealth-ін'єкція",
	"блокування cookie-згоди",
	"автозаповнення форм у браузері",
	"автологін",
	"відтворення записаного флоу",
	"перевірка успіху автентифікації",
	"захоплення стану сесії",
	"уникнення logout",
	"CAPTCHA-виявлення",
	"ідентифікація CAPTCHA",
	"розв'язання CAPTCHA",
	"інтеграція CapSolver",
	"ін'єкція токена CAPTCHA",
	"дамп діагностики обходу",
	"живий дебагер обходу",
	"класифікація помилок дій",
	"запобіжник серії помилок",
	"парсинг відповідей браузера",
	"витяг елементів сторінки",
	"пропуск неактивних елементів",
	// runtime
	"версія, банер, самоновичення",
	"health-check діагностика",
	"pprof-сервер",
	"YAML-конфіг прапорців",
	"обмеження розміру тіла 4 Мб",
	"TLS-клон інструменту не перевіряє сертифікат",
	"затискання TLS за Burp",
	"детекція тротлінгу 429/503",
	"max depth зі звітом",
	"фільтр розширень (76 типово)",
	// our own capabilities
	"повний сирий обмін у History",
	"джерельний IP за обміном",
	"бар'єр generation",
	"виявлення gate і зупинка обходу",
	"аналіз JS на тілі сторінки",
	"нумерація ID за вмістом",
}

type registerRow struct {
	capability string
	symbol     string
	verdict    string
	reason     string
	line       string
}

// rowPattern matches one register row: a table row with a verdict in the third
// column and a symbol in the second.
var rowPattern = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|`)

// symbolPattern pulls identifiers out of backticks in a symbol cell.
//
// Only backticked text is read. A cell is a cell and not a paragraph, and an
// earlier version scanned the whole cell for identifier-shaped tokens, which made
// "JA3" demand a symbol called `JA3` and a filename demand `md`. The detector
// then reported a dozen missing symbols, all of them inventions, and a detector
// that reports inventions is one whose real findings stop being read.
var symbolPattern = regexp.MustCompile("`([^`]+)`")

// loadRegister reads the register and returns its rows.
//
// A line that looks like a table row but does not parse into four cells is a
// failure, not a row to skip. The earlier version skipped it, which meant a row
// that lost its reason column simply ceased to exist as far as the guard was
// concerned — and a `не перенесено` with no reason is the one thing this
// register exists to prevent.
func loadRegister(t *testing.T) []registerRow {
	t.Helper()
	source, err := os.ReadFile(katanaRegister)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	var rows []registerRow
	// Блок, помічений як measurement-table, — це числа вимірювання, а не
	// здібності: у ньому немає вердикту, бо вердикт там не ставиться.
	//
	// Без цієї позначки таблиця вимірювання проходила б як рядок здібностей із
	// вердиктом «з» (колонка «з»), і тест падав би на правильному файлі.
	// Позначка зроблена явною, а не «домовленістю», щоб наступний агент не
	// вирішив, що таблиця просто не вдала формату.
	inMeasurementTable := false
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "<!--MEASUREMENT-TABLE-->" {
			inMeasurementTable = true
			continue
		}
		if trimmed == "<!--/MEASUREMENT-TABLE-->" {
			inMeasurementTable = false
			continue
		}
		if inMeasurementTable || !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) < 4 {
			if len(cells) == 2 || isTableFurniture(trimmed) {
				continue
			}
			t.Errorf("a capability row has %d cells, needs 4: %s", len(cells), trimmed)
			continue
		}
		match := rowPattern.FindStringSubmatch(unescapePipes(line))
		if match == nil {
			continue
		}
		capability, symbol, verdict, reason := match[1], match[2], match[3], match[4]
		capability = restorePipes(capability)
		symbol = restorePipes(symbol)
		reason = restorePipes(reason)
		if strings.EqualFold(capability, "здатність upstream") || strings.HasPrefix(capability, "---") {
			continue
		}
		if verdict == "вердикт" {
			continue
		}
		rows = append(rows, registerRow{capability, symbol, verdict, reason, line})
	}
	if len(rows) == 0 {
		t.Fatalf("the register has no rows; it parses as empty rather than as complete")
	}
	return rows
}

// unescapePipes hides an escaped pipe from the column split.
//
// A Markdown table cell may legitimately contain a pipe, written `\|`. Several
// register rows name an HTML attribute with a choice in it — `<iframe src\|srcdoc>`,
// `<img dynsrc\|lowsrc\|src>` — because those attribute sets ARE the capability
// being classified. The raw line still contains a `|` character there, so the
// column regex cut the row short and every such row was read as a row whose
// verdict was the symbol cell. The fix is to swap the escaped pipe for a byte the
// pattern cannot match, and put it back in the cells afterwards, so the reader
// sees the real text and the splitter sees a real column boundary.
//
// This is not a workaround for a broken register: the register renders correctly
// and reads correctly. It is the parser learning that Markdown escapes exist.
func unescapePipes(line string) string {
	return strings.ReplaceAll(line, `\|`, "\x00")
}

// restorePipes turns the placeholder back into the character it stood for.
func restorePipes(cell string) string {
	return strings.ReplaceAll(cell, "\x00", "|")
}

// isTableFurniture reports whether a short line is a header separator rather than
// a broken row.
func isTableFurniture(line string) bool {
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

// TestEveryUpstreamParserIsNamed is the mechanical answer to the vexor failure.
//
// A parser registered upstream and named in no row is a capability whose verdict
// is unclassified, which reads as "nothing to lose" because nothing mentions it.
// The list is pinned in this file from upstream's own `NewResponseParser()`, so
// adding a parser upstream produces a failing diff here rather than a silent gap.
func TestEveryUpstreamParserIsNamed(t *testing.T) {
	if len(upstreamParsers) < 25 {
		t.Fatalf("upstreamParsers holds %d entries; the registry has 30, so the list is truncated",
			len(upstreamParsers))
	}
	source, err := os.ReadFile(katanaRegister)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	body := string(source)
	for name, at := range upstreamParsers {
		if !strings.Contains(body, name) {
			t.Errorf("upstream parser %s (%s) is named in no register row, so its "+
				"verdict is unclassified: a parser we did not consider reads as a parser "+
				"we covered", name, at)
		}
	}
}

// TestRequiredRowsArePresent is the answer to a removed row.
func TestRequiredRowsArePresent(t *testing.T) {
	rows := loadRegister(t)
	present := make([]string, 0, len(rows))
	for _, row := range rows {
		present = append(present, strings.TrimSpace(row.capability))
	}
	for _, required := range requiredRows {
		found := false
		for _, capability := range present {
			if strings.Contains(capability, required) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required row %q is gone; the register is incomplete", required)
		}
	}
	if len(rows) != katanaRowCount {
		t.Errorf("the register has %d rows, want %d; a count that drifts in either "+
			"direction means the table changed without anyone deciding it should",
			len(rows), katanaRowCount)
	}
}

// TestEveryRowHasAVerdictFromTheAllowedThree is the core of the rule.
func TestEveryRowHasAVerdictFromTheAllowedThree(t *testing.T) {
	for _, row := range loadRegister(t) {
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

// TestLostRowsStateAReason is what makes `не перенесено` usable: it has to say
// what is missing and why, otherwise it is indistinguishable from a row that was
// never written.
func TestLostRowsStateAReason(t *testing.T) {
	for _, row := range loadRegister(t) {
		if row.verdict != verdictLost {
			continue
		}
		reason := strings.TrimSpace(row.reason)
		if reason == "" {
			t.Errorf("row %q is %q with no reason; that is the silent-loss shape", row.capability, verdictLost)
		}
		if len(reason) < 20 {
			t.Errorf("row %q gives a %d-character reason, too short to be one: %q",
				row.capability, len(reason), reason)
		}
	}
}

// TestClaimedSymbolsExistInOurTree stops a register from claiming a port that is
// not in the code.
//
// Only rows that assert a port are checked. A `не перенесено` row carries no
// symbol by definition, and a cell whose content is prose rather than an
// identifier is skipped rather than guessed at.
//
// The search is NOT restricted to this package. These rows name symbols in
// `package main` at the engine root — `runTargetMap`, `crawlRedirectChain`,
// `analyzeJavaScript` — and a search scoped to `./` would report every one of them
// missing while the port plainly exists. That was the documented failure mode:
// "the symbol check must search every layer where the claimed thing lives".
func TestClaimedSymbolsExistInOurTree(t *testing.T) {
	for _, row := range loadRegister(t) {
		if row.verdict == verdictLost {
			continue
		}
		if strings.TrimSpace(row.symbol) == "" || strings.TrimSpace(row.symbol) == "—" {
			continue
		}
		names := symbolPattern.FindAllStringSubmatch(row.symbol, -1)
		if len(names) == 0 {
			continue
		}
		for _, match := range names {
			for _, name := range identifiersIn(match[1]) {
				if !declaredSomewhere(t, name) {
					t.Errorf("row %q claims symbol %q, which is not declared anywhere in our "+
						"engine tree (engine root, pkg/, browser-worker, templates)", row.capability, name)
				}
			}
		}
	}
}

// declarationPatterns recognise the ways this tree declares a top-level name.
//
// Go, Python and the inline JavaScript of the template are all here, because a
// register row may legitimately name a symbol in any of them: `runTargetMap` is
// Go, `register_endpoint` is a Django model method, `renderTargetMap` is
// JavaScript in the template.
var declarationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*func\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({\[]`),
	regexp.MustCompile(`(?m)^\s*func\s+\([^)]*\)\s*\*?([A-Za-z_][A-Za-z0-9_]*)\s*[({\[]`),
	regexp.MustCompile(`(?m)^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\b`),
	regexp.MustCompile(`(?m)^\s*(?:var|const)\s+([A-Za-z_][A-Za-z0-9_]*)\b`),
	regexp.MustCompile(`(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`),
	regexp.MustCompile(`(?m)^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(:]`),
	regexp.MustCompile(`(?m)^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`),
	regexp.MustCompile(`(?m)^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=`),
}

// declaredIndex is every top-level name the engine declares, gathered once.
//
// It replaces a check that walked the tree again for every symbol of every row.
// That version was correct and unusably slow: the template is 911 KB, the tree
// holds a few hundred files, and the register names hundreds of symbols, so it
// ran tens of thousands of regular expressions over the same bytes. Under `-race`
// that is minutes, and a check that times out under the project's own mandatory
// race level is a check the project cannot rely on.
//
// Gathering the names once turns the cost into "read each file once" and leaves
// every lookup a map read. The semantics are unchanged: a name is in the index
// only if some file DECLARES it, so a row naming a symbol the code merely calls
// still fails.
func declaredIndex(t *testing.T) map[string]bool {
	t.Helper()
	if declaredNames != nil {
		return declaredNames
	}
	index := map[string]bool{}
	roots := []string{"..", "../../browser-worker", "../../web"}
	extensions := map[string]bool{".go": true, ".py": true, ".html": true}
	skipped := []string{"/.git/", "/.venv/", "/SKILLS-AI-MD/", "/node_modules/", "/__pycache__/", "/migrations/"}
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			for _, skip := range skipped {
				if strings.Contains(path, skip) {
					return nil
				}
			}
			if !extensions[filepath.Ext(path)] {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			isTestFile := strings.HasSuffix(path, "_test.go")
			for _, pattern := range declarationPatterns {
				for _, match := range pattern.FindAllStringSubmatch(string(body), -1) {
					name := match[1]
					// A `Test…` name is evidence only if it is a test. Without this a
					// feature row could claim a port by pointing at a test that
					// mentions it, which is the confusion this file exists to stop.
					if strings.HasPrefix(name, "Test") != isTestFile {
						continue
					}
					index[name] = true
				}
			}
			return nil
		})
	}
	if len(index) == 0 {
		t.Fatal("the engine tree declares nothing, so the symbol check is asserting nothing")
	}
	declaredNames = index
	return index
}

// declaredNames holds the gathered index for the duration of one test binary run.
var declaredNames map[string]bool

// cellIdentifier pulls Go/Python identifiers out of one backticked cell value.
//
// A cell may name a symbol, a short list, a receiver-qualified form like
// `Suite.Run`, or a call like `ClassifyContext`. What it must not do is describe
// something in prose, because prose is not a symbol and treating it as one is how
// the check starts reporting words.
var cellIdentifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func identifiersIn(cell string) []string {
	trimmed := strings.TrimSpace(cell)
	trimmed = strings.TrimPrefix(trimmed, "*")
	if trimmed == "" {
		return nil
	}
	// A file path, a path with a line number, a hash name, or prose: none of
	// these is a symbol the tree could declare.
	//
	// The path case was a real false positive, not a hypothetical one. A cell
	// reading `pkg/engine/parser/parser.go:122` was cut at its last dot and
	// asked the tree for a symbol called `go`, so every row that cited an
	// upstream location reported a missing symbol — and a detector that reports
	// thirty inventions is a detector whose real findings stop being read.
	if strings.ContainsAny(trimmed, " -/\\:") {
		return nil
	}
	for _, suffix := range []string{".go", ".py", ".md", ".js", ".json", ".yaml", ".yml", ".txt"} {
		if strings.HasSuffix(trimmed, suffix) {
			return nil
		}
	}
	base := trimmed
	if index := strings.LastIndex(base, "."); index >= 0 {
		base = base[index+1:]
	}
	if index := strings.Index(base, "("); index >= 0 {
		base = base[:index]
	}
	return cellIdentifier.FindAllString(base, -1)
}

// declaredSomewhere reports whether any file in the tree declares a name.
//
// The check is for a DECLARATION rather than a use, because a row naming a symbol
// the tree only calls would still be describing someone else's code. A method
// counts: most of what our engine exposes is a method on a receiver
// (`func (s *server) runTechnologyProbe`), and a helper matching only plain
// `func Name` reported real symbols missing. A detector that cries wolf on most
// rows is one whose output gets ignored, and then it catches nothing at all.
func declaredSomewhere(t *testing.T, name string) bool {
	return declaredIndex(t)[name]
}

// TestOurOwnCapabilitiesAreCovered is the direction the original rule forgot.
//
// Listing upstream's capabilities catches what we failed to take. It does not
// catch what we built and never wrote down, which is the same silence from the
// other side.
func TestOurOwnCapabilitiesAreCovered(t *testing.T) {
	ours := []struct {
		capability string
		symbol     string
	}{
		{"повний сирий обмін у History", "crawlRedirectChain"},
		{"джерельний IP за обміном", "startSourceIPLookup"},
		{"бар'єр generation", "bindRouteContext"},
		{"виявлення gate і зупинка обходу", "challengeIsGate"},
		{"аналіз JS на тілі сторінки", "analyzeJavaScript"},
	}
	rows := loadRegister(t)
	for _, capability := range ours {
		covered := false
		for _, row := range rows {
			if strings.Contains(row.capability, capability.capability) ||
				strings.Contains(row.symbol, "`"+capability.symbol+"`") {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("our capability %q (symbol %q) is in no register row", capability.capability, capability.symbol)
		}
	}
}

// TestUpstreamCommitIsRecorded: a register compared against an unstated upstream
// is a register about an unstated subject.
func TestUpstreamCommitIsRecorded(t *testing.T) {
	source, err := os.ReadFile(katanaRegister)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	body := string(source)
	if !strings.Contains(body, katanaCommit) {
		t.Errorf("the register does not record upstream commit %s", katanaCommit)
	}
	// The commit alone is not enough: a register that names the clone but not the
	// place to check it is a claim the next agent cannot reproduce.
	if !strings.Contains(body, upstreamCloneHint) {
		t.Errorf("the register does not record where the upstream tree lives (%s)", upstreamCloneHint)
	}
}

// TestEveryRegisterRowNamesACapabilityWithText guards the parse itself: a row whose
// capability cell is a placeholder means the register claims a completeness it does
// not have.
func TestEveryRegisterRowNamesACapabilityWithText(t *testing.T) {
	for _, row := range loadRegister(t) {
		capability := strings.TrimSpace(row.capability)
		if capability == "" || capability == "—" || capability == "-" {
			t.Errorf("a register row has no capability name: %s", row.line)
		}
	}
}

// TestVerdictVocabularyHasNoFourthState documents the closed set in code, so the
// test above and the rule cannot drift apart.
func TestVerdictVocabularyHasNoFourthState(t *testing.T) {
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

// TestTheParserListIsPinned guards the guard.
//
// A test that names three of thirty parsers is a test that passes while twenty-seven
// are unclassified, which is the "3 = 3" failure this register was written after.
// The count is asserted so a truncated list cannot be mistaken for a complete one.
func TestTheParserListIsPinned(t *testing.T) {
	t.Logf("upstream registry lists %d parser(s) from ~/katana/pkg/engine/parser/parser.go",
		len(upstreamParsers))
	if len(upstreamParsers) != 30 {
		t.Errorf("upstreamParsers holds %d entries, want 30; upstream's NewResponseParser "+
			"registers 30 (3 header + 26 body + 1 custom field) plus a conditional Location "+
			"parser, and a shortened list would pass while real parsers go unnamed",
			len(upstreamParsers))
	}
}

// TestPortingRowsNameASymbol is the guard that catches the guard.
//
// A row that says `улучшено` or `совпадає` claims a port, and the symbol check is
// the only thing that makes such a claim mean anything: it asks whether the code
// exists. But the check only asks when the symbol cell actually yields an
// identifier — and a cell holding only a file path and a flag, such as
// `runner/options.go:396` `-u`, yields none.
//
// That is not a hypothetical. A row for the httpx input path read
// `runSubdomainTransformWithCollector` in its REASON cell, so the symbol cell held
// only an upstream path, the check ran on zero identifiers, and the row passed
// without ever being verified. A mutation that replaced the symbol with a
// nonexistent one stayed green.
//
// So the empty case is a failure in its own right. A row asserting a port must
// name a symbol of ours that the tree can be asked about; otherwise the claim is
// prose with a verdict attached.
func TestPortingRowsNameASymbol(t *testing.T) {
	registries := map[string]func(t *testing.T) []registerRow{
		katanaRegister: loadRegister,
		httpxRegister:  loadHttpxRegister,
	}
	for name, load := range registries {
		for _, row := range load(t) {
			if row.verdict == verdictLost {
				continue
			}
			var names []string
			for _, match := range symbolPattern.FindAllStringSubmatch(row.symbol, -1) {
				names = append(names, identifiersIn(match[1])...)
			}
			if len(names) == 0 {
				t.Errorf("%s: row %q claims verdict %q but names no symbol of ours, so "+
					"nothing can be asked about the claim; put our symbol in the symbol cell",
					name, strings.TrimSpace(row.capability), row.verdict)
			}
		}
	}
}
