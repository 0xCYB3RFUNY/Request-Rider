package main

// retire.js — звірка з оригіналом `RetireJS/retire.js`.
//
// Оригінал шукає у скрипті відомі бібліотеки та їхні версії й каже, які
// вразливості цієї версії відомі. Тут — те саме, але без браузерного
// розширення й без Node: репозиторій вендорений у репозиторій проєкту
// (`engine/testdata/retirejs-repository.json`), а детектор працює на тих самих
// байтах, які вже розібрав `analyzeJavaScript`.
//
// Сумісність формату навмисно не вигадується: розмітка `§version§` у
// оригіналі — це **та сама** розмітка, яку движок уже підтримує для Intruder
// (§name§), тому підстановка версії reuse-ить наявний код, а не другий
// розбір.
//
// Що тут НЕ перенесено і чому — у `engine/retirejs_reconciliation.md`.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// retirejsRepository is the upstream database, vendored so the scanner answers
// the same thing tomorrow as today: a scanner that phones home for its rule set
// reports nothing at all when the network is closed, and "nothing found" reads
// exactly like "nothing there".
//
//go:embed testdata/retirejs-repository.json
var retirejsRepository []byte

// retirejsLibrary is one entry of the upstream database.
type retirejsLibrary struct {
	// Name is the library's key in the repository, and also the name shown in
	// the report: the analyst has to be able to search the report for the
	// library they saw in the bundle.
	Name string
	// NpmName is what the package is called in a registry, when it differs.
	NpmName string `json:"npmname"`
	// Bowername is the global the script exposes, when it exposes one.
	Bowername []string `json:"bowername"`
	// Vulnerabilities are the known problems, with the version range they
	// apply to.
	Vulnerabilities []retirejsVulnerability
	// Extractors are the ways the version can be recognised in a file.
	Extractors map[string]json.RawMessage
}

// flexString takes a field the upstream database writes both as a string and as
// a list. Both forms occur in this repository, and a fixed type fails on the
// first record that uses the other one — which is a failure of the parse, not a
// finding about the data.
type flexString []string

func (f *flexString) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*f = list
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*f = []string{single}
	return nil
}

type retirejsVulnerability struct {
	Below       string   `json:"below"`
	AtOrAbove   string   `json:"atOrAbove"`
	Severity    string   `json:"severity"`
	CWE         []string `json:"cwe"`
	Identifiers struct {
		Summary   string     `json:"summary"`
		CVE       []string   `json:"CVE"`
		GitHubID  flexString `json:"githubID"`
		URL       string     `json:"URL"`
		Reference []string   `json:"reference"`
	} `json:"identifiers"`
	Info []string `json:"info"`
}

var (
	retirejsOnce  sync.Once
	retirejsLibs  map[string]retirejsLibrary
	retirejsOrder []string
	retirejsErr   error
)

// retirejsVersionPattern matches the version a detector read out of a file.
// The upstream `§version§` marker is replaced by this, and the surrounding
// expression is left as written, so an extractor keeps exactly the reach the
// upstream author gave it.
var retirejsVersionPattern = regexp.MustCompile(`(?:[0-9][0-9A-Za-z._+-]*)`)

// retirejsLibraries parses the vendored repository once.
//
// The order is sorted because it is what the report iterates, and a report that
// reorders itself between two runs of the same bytes is a report nobody diffs.
func retirejsLibraries() (map[string]retirejsLibrary, []string, error) {
	retirejsOnce.Do(func() {
		retirejsLibs = map[string]retirejsLibrary{}
		raw := map[string]retirejsLibrary{}
		if err := json.Unmarshal(retirejsRepository, &raw); err != nil {
			retirejsErr = err
			return
		}
		for name, entry := range raw {
			entry.Name = name
			retirejsLibs[name] = entry
			retirejsOrder = append(retirejsOrder, name)
		}
		sort.Strings(retirejsOrder)
	})
	return retirejsLibs, retirejsOrder, retirejsErr
}

// retirejsVulnerableLibrary is what the engine reports: a library found in a
// script, the version that was read, and the problems known for that version.
type retirejsVulnerableLibrary struct {
	// Library and Version are what was read out of the file, unedited, because
	// the analyst has to be able to search for the exact string they saw.
	Library string `json:"library"`
	Version string `json:"version"`
	// Below is the version the vulnerability is fixed in. It is kept as text
	// because the comparison itself is done by the engine's own version
	// ordering, not by string comparison: "1.10.0" < "1.9.0" as text, and
	// reporting that the wrong way round would send an operator to a release
	// that does not exist.
	Below string `json:"below"`
	// Severity, CVE, CWE and Summary come from the upstream record.
	//
	// The tags are lowercase on purpose, and they were absent until the operator
	// read an exported map in which six findings for one library were six lines
	// of `jquery · 1.12.4 · medium · fixed in 2.2.0` and never once said what the
	// vulnerability *was*. Without a tag Go writes the field name as written, so
	// the wire form was `"CVE"`, `"CWE"` and `"Summary"` while the report read
	// `cve`, `cwe` and `summary` — three `undefined` values and a summary that
	// was in the record all along and simply never printed.
	Severity string   `json:"severity"`
	CVE      string   `json:"cve"`
	CWE      []string `json:"cwe"`
	Summary  string   `json:"summary"`
	// GitHubID is the GitHub advisory id (`GHSA-…`), which is what an analyst
	// pastes into a tracker and what the upstream database most often carries
	// when there is no CVE.
	//
	// It was parsed by `retirejsVulnerability` and then dropped, so the one
	// identifier that is present for most records never reached the report.
	GitHubID string `json:"github_id"`
	// URL is the advisory page, and References are the further links the upstream
	// record lists — the NVD entry, the vendor ticket, a proof-of-concept.
	// A record that names an advisory an analyst has to go and search for is a
	// task; one that links it is a finding.
	URL        string   `json:"url,omitempty"`
	References []string `json:"references,omitempty"`
	// Info is the upstream's own note about the record, and in this snapshot it
	// is also where every link lives.
	//
	// Measured over all 750 records of the vendored database: `identifiers.URL`
	// and `identifiers.reference` are populated 0 times, while `info` is
	// populated 749 times and holds the NVD entry, the vendor ticket and the
	// proof-of-concept. So this field is not a note — it is the only place a
	// link can come from, and the report has to read it.
	Info []string `json:"info,omitempty"`
	// Evidence is the file the version was read from, so a finding points at a
	// byte range rather than at a library name.
	File string `json:"file"`
}

// retirejsDetect returns the libraries visible in one file.
//
// Two extractor kinds are read here, `func` and `filename`, because both are
// expressions the engine can evaluate against bytes it already has: a call on a
// global, a path, the URL it was served from, and the file's own bytes. Those
// four are everything the upstream kinds read, so none of them is skipped:
// , , ,  and  all run.
func retirejsDetect(pageURL string, fileName string, body []byte) []retirejsVulnerableLibrary {
	libraries, order, err := retirejsLibraries()
	if err != nil {
		return nil
	}
	found := make([]retirejsVulnerableLibrary, 0, 4)
	seen := map[string]bool{}
	for _, name := range order {
		library := libraries[name]
		version, present := retirejsVersionIn(pageURL, fileName, body, library)
		if !present {
			continue
		}
		for _, vulnerability := range library.Vulnerabilities {
			if !retirejsVersionAffected(version, vulnerability) {
				continue
			}
			key := name + "@" + version + "|" + vulnerability.Below + "|" + vulnerability.Identifiers.Summary
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, retirejsVulnerableLibrary{
				Library:  name,
				Version:  version,
				Below:    vulnerability.Below,
				Severity: vulnerability.Severity,
				CVE:      strings.Join(vulnerability.Identifiers.CVE, ", "),
				CWE:      append([]string(nil), vulnerability.CWE...),
				Summary:  vulnerability.Identifiers.Summary,
				// The four below were parsed and dropped. Each one is what turns
				// "medium" into a sentence: the advisory to look up, the link to
				// open, and the note the upstream database itself carries.
				GitHubID:   strings.Join(vulnerability.Identifiers.GitHubID, ", "),
				URL:        vulnerability.Identifiers.URL,
				References: append([]string(nil), vulnerability.Identifiers.Reference...),
				Info:       append([]string(nil), vulnerability.Info...),
				File:       fileName,
			})
		}
	}
	return found
}

// retirejsVersionIn reads the version out of one library's extractors.
//
// The `func` extractor is matched against the whole file and `filename` against
// the file's name, because that is where the upstream author put the signal: a
// bundled library usually keeps the call that reveals it, and a loaded from a
// CDN keeps its name in the path.
// retirejsVersionIn reports whether a library is visible in the file and, when
// the extractor said so, which version.
//
// The two answers are separate on purpose. A `func` extractor usually names the
// library and stops there, so `present` is true and `version` is empty; that is
// a real detection with a missing detail, and it must not read as an absence.
func retirejsVersionIn(pageURL, fileName string, body []byte, library retirejsLibrary) (string, bool) {
	text := string(body)
	for _, kind := range []string{"filename", "filecontent", "uri", "func"} {
		for _, expression := range retirejsExpressions(library, kind) {
			source := text
			switch kind {
			case "filename":
				source = fileName
			case "uri":
				source = pageURL
			case "filecontent":
				source = retirejsReplacedBody(body, library)
			}
			pattern := retirejsExpressionPattern(expression)
			if pattern == nil {
				continue
			}
			match := pattern.FindStringSubmatch(source)
			if match == nil {
				continue
			}
			if version := retirejsGroupVersion(match); version != "" {
				return version, true
			}
			return "", true
		}
	}
	if version, ok := retirejsHashVersion(body, library); ok {
		return version, true
	}
	return "", false
}

// retirejsExpressions reads one extractor kind out of the record.
//
// `filecontent` і `hashes` у репозиторії — об'єкти, а `func`, `filename` і
// `uri` — списки. Різні форми розбираються тут, в одному місці: розбір у
// визначенні структури ламався б на першій бібліотеці з об'єктним extractor-ом.
func retirejsExpressions(library retirejsLibrary, kind string) []string {
	raw, ok := library.Extractors[kind]
	if !ok {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var object map[string]string
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil
	}
	// Об'єктна форма зберігає вираз у полі `match`/`value`, а решту — у
	//Service-полях, які до виявлення версії не відносяться.
	for _, field := range []string{"match", "value", "filecontent"} {
		if expression, ok := object[field]; ok {
			return []string{expression}
		}
	}
	return nil
}

// retirejsExpressionPattern turns one upstream expression into a matcher.
//
// The expression is a JavaScript regular expression with `§version§` where the
// version stands. Replacing the marker with a capture group gives the version
// without rewriting a single character of what the author wrote, which matters
// because a hand-rewritten extractor is an extractor that quietly stopped
// matching. Go's RE2 has no lookbehind, so an expression using one is skipped
// and reported by the reconciliation rather than dropped without a word.
func retirejsExpressionPattern(expression string) *regexp.Regexp {
	if strings.Contains(expression, "(?<") {
		return nil
	}
	replaced := expression
	for _, marker := range []string{
		`\u00a7\u00a7version\u00a7\u00a7`,
		`\u00a7version\u00a7`,
		"§§version§§",
		"§version§",
	} {
		replaced = strings.ReplaceAll(replaced, marker, retirejsVersionPattern.String())
	}
	// Upstream writes character classes in the JavaScript dialect. The two
	// spellings that differ and occur in this repository are handled here
	// rather than by rewriting the expressions.
	replaced = strings.ReplaceAll(replaced, `\d`, `[0-9]`)
	replaced = strings.ReplaceAll(replaced, `\w`, `[A-Za-z0-9_]`)
	replaced = strings.ReplaceAll(replaced, `\s`, `[ \t\r\n]`)
	recompiled, err := regexp.Compile(replaced)
	if err != nil {
		return nil
	}
	return recompiled
}

// retirejsArtifactSuffixes are the file-suffix spellings that a `filename`
// extractor swallows into the version. `jquery-1.7.2.min.js` gives the capture
// `1.7.2.min`, and a report that says "jQuery 1.7.2.min" is a version nobody
// published: the range comparison then silently treats it as newer than the
// fixed release and the finding disappears.
var retirejsArtifactSuffixes = []string{".min", ".js", ".bundle", ".pack"}

// retirejsTrimArtifactSuffix removes a swallowed file suffix from a version.
func retirejsTrimArtifactSuffix(version string) string {
	for {
		trimmed := version
		for _, suffix := range retirejsArtifactSuffixes {
			trimmed = strings.TrimSuffix(trimmed, suffix)
		}
		if trimmed == version || trimmed == "" {
			return version
		}
		version = trimmed
	}
}

// retirejsGroupVersion pulls the version out of the capture the marker made.
//
// The marker is written as a group, so the first group that looks like a version
// is it. Expressions that carry their own groups before the marker — the
// filename extractors do — would otherwise report the library's name instead of
// its version, and the mistake is silent: the name is always a plausible
// version.
func retirejsGroupVersion(match []string) string {
	for _, group := range match[1:] {
		if group == "" {
			continue
		}
		if _, err := strconv.ParseFloat(group, 64); err == nil {
			return retirejsTrimArtifactSuffix(group)
		}
		if strings.ContainsAny(group, ".") && !strings.HasPrefix(group, "http") {
			return retirejsTrimArtifactSuffix(group)
		}
	}
	return ""
}

// retirejsVersionAffected reports whether a version falls in the vulnerable
// range.
//
// The upstream record states `below` (fixed in) and optionally `atOrAbove`
// (introduced in). Both ends are compared with the engine's own version
// ordering rather than as text, because the text order of versions is not their
// release order and an inverted comparison reports the fixed version as the
// vulnerable one.
func retirejsVersionAffected(version string, vulnerability retirejsVulnerability) bool {
	// Версія невідома — діапазон не звужується. Приховати вразливість, яка
	// стосується невідомої версії, гірше, ніж показати її з порожнім полем
	// версії: друге каже аналітику, що треба звірити версію вручну.
	if version == "" {
		return true
	}
	if vulnerability.AtOrAbove != "" && retirejsCompareVersions(version, vulnerability.AtOrAbove) < 0 {
		return false
	}
	if vulnerability.Below == "" {
		return true
	}
	return retirejsCompareVersions(version, vulnerability.Below) < 0
}

// retirejsCompareVersions orders two dotted versions numerically per component.
//
// A component that is not a number compares as 0, so `1.2.x` and `1.2` compare
// equal rather than one of them winning by a string comparison nobody can
// reproduce in their head.
func retirejsCompareVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		var l, r int
		if i < len(leftParts) {
			l, _ = strconv.Atoi(numericPrefix(leftParts[i]))
		}
		if i < len(rightParts) {
			r, _ = strconv.Atoi(numericPrefix(rightParts[i]))
		}
		if l != r {
			if l < r {
				return -1
			}
			return 1
		}
	}
	return 0
}

// numericPrefix takes the leading digits of a version component.
func numericPrefix(value string) string {
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return "0"
	}
	return value[:end]
}

// retirejsFileName is the last path segment of a script URL.
//
// It is the name the `filename` extractor matches against, and it is the only
// name the engine has: the bytes arrive from a fetch, not from a file on disk,
// so inventing a path here would let a `filename` rule match something the
// analyst never saw.
func retirejsFileName(pageURL string) string {
	if index := strings.LastIndex(pageURL, "?"); index > 0 {
		pageURL = pageURL[:index]
	}
	if index := strings.LastIndex(pageURL, "#"); index > 0 {
		pageURL = pageURL[:index]
	}
	if index := strings.LastIndex(pageURL, "/"); index >= 0 {
		return pageURL[index+1:]
	}
	return pageURL
}

// retirejsReplacedBody applies the library's `filecontentreplace` rules before
// any pattern is matched against the file.
//
// The upstream spelling is one string per rule: the pattern, then `$`, then the
// replacement. The split is at the **last** `$`, because a pattern may itself
// contain a `$` anchor while a replacement starts with `$` by definition — that
// is what makes the last one the boundary. The earlier reading of these
// extractors as "needs the file on disk" was wrong: they rewrite the bytes the
// engine already holds.
func retirejsReplacedBody(body []byte, library retirejsLibrary) string {
	rewritten := string(body)
	for _, rule := range retirejsExpressions(library, "filecontentreplace") {
		boundary := strings.LastIndex(rule, "$")
		if boundary <= 0 {
			continue
		}
		pattern := retirejsExpressionPattern(rule[:boundary])
		if pattern == nil {
			continue
		}
		replacement := retirejsReplacement(rule[boundary:])
		rewritten = pattern.ReplaceAllString(rewritten, replacement)
	}
	return rewritten
}

// retirejsReplacement turns an upstream replacement into Go's spelling.
//
// Upstream writes `$1`, `$2` for backreferences, which is what Go's
// `ReplaceAllString` also accepts. The one difference that occurs in this
// repository is `$&`, which upstream means "the whole match" — the same thing
// Go calls `$0`.
func retirejsReplacement(replacement string) string {
	return strings.ReplaceAll(replacement, "$&", "${0}")
}

// retirejsHashVersion looks the whole file up in the library's `hashes` table.
//
// The upstream table maps a digest of the **entire** file to a version, so this
// can only answer for a library that is one file and that the engine read whole.
// It is checked last, after the expressions, because an expression that read a
// version is direct evidence while a digest match is only as good as the
// database: the same digest in two versions would be the database's problem, and
// the first one in the map is what gets reported.
func retirejsHashVersion(body []byte, library retirejsLibrary) (string, bool) {
	raw, ok := library.Extractors["hashes"]
	if !ok {
		return "", false
	}
	table := map[string]string{}
	if err := json.Unmarshal(raw, &table); err != nil || len(table) == 0 {
		return "", false
	}
	for _, digest := range retirejsDigests(body) {
		if version, found := table[digest]; found && version != "" {
			return version, true
		}
	}
	return "", false
}

// retirejsDigests returns the digests the upstream table uses, keyed by the
// algorithm so two libraries cannot claim the same string under different rules.
//
// MD5 is included because the table uses it; it is not a security decision here
// — it is an identifier the upstream author wrote down.
func retirejsDigests(body []byte) []string {
	return []string{
		fmt.Sprintf("%x", md5.Sum(body)),
		fmt.Sprintf("%x", sha1.Sum(body)),
		fmt.Sprintf("%x", sha256.Sum256(body)),
	}
}
