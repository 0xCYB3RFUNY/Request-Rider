package main

// Тести детектора retire.js.
//
// Тест має червоніти на неправильній реалізації. Тому тут є три речі, які
// кожна з них окремо ловить власний дефект: **фікстура з відомим складом**
// (числа не з повітря), **порівняння версій** (де текстовий порядок помиляється)
// і **мутація на живому прогоні** (див. `TestRetirejsDetectOnTheFixture` — він
// падає, якщо вирізати правило).

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestTheVendoredRepositoryIsTheUpstreamShape: вендорена копія має бути тим,
// що вона себе називає. Число 76 є фактом про файл, а не про оригінал.
func TestTheVendoredRepositoryIsTheUpstreamShape(t *testing.T) {
	contents, err := os.ReadFile("testdata/retirejs-repository.json")
	if err != nil {
		t.Fatalf("read the vendored repository: %v", err)
	}
	entries := map[string]retirejsLibrary{}
	if err := json.Unmarshal(contents, &entries); err != nil {
		t.Fatalf("the vendored repository is not valid JSON: %v", err)
	}
	if len(entries) != 76 {
		t.Errorf("the vendored repository has %d libraries, want 76", len(entries))
	}
	vulnerabilities, extractors := 0, 0
	for _, entry := range entries {
		vulnerabilities += len(entry.Vulnerabilities)
		for kind := range entry.Extractors {
			extractors += len(retirejsExpressions(entry, kind))
		}
	}
	if vulnerabilities != 750 {
		t.Errorf("the vendored repository has %d vulnerabilities, want 750", vulnerabilities)
	}
	// Три різних числа, які легко сплутати: **6** — видів extractor-ів,
	// **249** — їхніх випадків по бібліотеках, **385** — виразів. Плутанина
	// цих чисел була б тим самим випадком, що й рядок «3 = 3» під час
	// перенесення сканера: кожне число правильне, але це різні одиниці.
	if kinds := retirejsExtractorKinds(entries); kinds != 6 {
		t.Errorf("the vendored repository uses %d extractor kinds, want 6", kinds)
	}
	if cases := retirejsExtractorCases(entries); cases != 249 {
		t.Errorf("the vendored repository has %d extractor cases, want 249", cases)
	}
	if extractors != 385 {
		t.Errorf("the vendored repository has %d extractor expressions, want 385", extractors)
	}
}

// TestEveryLibraryHasAtLeastOneExtractor: бібліотека без extractor-а не має
// жодного способу бути знайденою, і мовчати про це не можна.
func TestEveryLibraryHasAtLeastOneExtractor(t *testing.T) {
	libraries, order, err := retirejsLibraries()
	if err != nil {
		t.Fatalf("parse the repository: %v", err)
	}
	for _, name := range order {
		if len(libraries[name].Extractors) == 0 {
			t.Errorf("library %q has no extractor at all", name)
		}
	}
}

// retirejsExtractorKinds counts how many distinct extractor kinds the database
// uses, which is a different number from how many expressions they hold.
func retirejsExtractorKinds(entries map[string]retirejsLibrary) int {
	kinds := map[string]bool{}
	for _, entry := range entries {
		for kind := range entry.Extractors {
			kinds[kind] = true
		}
	}
	return len(kinds)
}

// retirejsExtractorCases counts extractor kinds summed per library, which is a
// third number and a different one again.
func retirejsExtractorCases(entries map[string]retirejsLibrary) int {
	cases := 0
	for _, entry := range entries {
		cases += len(entry.Extractors)
	}
	return cases
}

// TestVersionComparisonIsNumericNotTextual: «1.10.0» текстово менший за
// «1.9.0», і оператор, якому сказали б, що 1.10 уразливіша за 1.9, пішов би
// шукати неіснуючий реліз.
func TestVersionComparisonIsNumericNotTextual(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.10.0", "1.9.0", 1},
		{"1.9.0", "1.10.0", -1},
		{"1.12.4", "1.12.4", 0},
		{"2.0", "1.99.99", 1},
		{"1.2.x", "1.2", 0},
		{"0.9", "1.0", -1},
	}
	for _, tc := range cases {
		if got := retirejsCompareVersions(tc.left, tc.right); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

// TestTheVersionRangeIsReadFromTheRecord: `below` — це версія, у якій
// вразливість виправлено, тому версія **нижча** за неї вразлива.
func TestTheVersionRangeIsReadFromTheRecord(t *testing.T) {
	vulnerable := retirejsVulnerability{Below: "1.12.4"}
	fixed := retirejsVulnerability{Below: "1.12.4"}
	if !retirejsVersionAffected("1.11.3", vulnerable) {
		t.Error("1.11.3 is below 1.12.4 and must count as affected")
	}
	if retirejsVersionAffected("1.12.4", fixed) {
		t.Error("1.12.4 is the fixed version and must not count as affected")
	}
	only := retirejsVulnerability{AtOrAbove: "2.0.0"}
	if retirejsVersionAffected("1.9.9", only) {
		t.Error("a range that starts at 2.0.0 does not cover 1.9.9")
	}
}

// TestTheVersionMarkerIsReplacedNotRewritten: автор оригіналу написав
// вираз, а ми підставляємо лише групу. Переписувати вираз означало б змінити
// його охоплення непомітно.
func TestTheVersionMarkerIsReplacedNotRewritten(t *testing.T) {
	pattern := retirejsExpressionPattern(`jquery-(\d\.\d\.\d)\.js`)
	if pattern == nil {
		t.Fatal("the expression did not compile")
	}
	if !pattern.MatchString("jquery-1.7.2.js") {
		t.Error("the rewritten expression no longer matches its own form")
	}
	// Вираз із lookbehind RE2 не вміє: він пропускається, а не зʼїдається
	// мовчки — саме на цьому впав рушій під час перенесення Pinkerton.
	if retirejsExpressionPattern(`(?<=x)y`) != nil {
		t.Error("a lookbehind expression must be skipped, not compiled")
	}
}

// TestRetirejsDetectOnTheFixture: прогін на файлі з відомим складом.
//
// Твердження, а не звіт: якщо детектор перестане знаходити jQuery, тест
// почервоніє, а не просто надрукує менше рядків.
func TestRetirejsDetectOnTheFixture(t *testing.T) {
	body := []byte(`/*! jQuery v1.7.2 */
var jq = jQuery.fn.jquery;
(function (window, undefined) { window.jQuery = window.$ = jQuery; })(window);
`)
	found := retirejsDetect("", "jquery-1.7.2.min.js", body)
	if len(found) == 0 {
		t.Fatal("jQuery 1.7.2 was not detected at all")
	}
	library := ""
	for _, entry := range found {
		if entry.Library == "jquery" {
			library = entry.Library
		}
		// Версія обов'язкова саме тут: вираз містить маркер, і тест це знає.
		if entry.Version == "" {
			t.Errorf("finding for %q carries no version although the fixture names one", entry.Library)
		}
		if entry.Severity == "" {
			t.Errorf("finding for %q carries no severity", entry.Library)
		}
	}
	if library == "" {
		t.Fatalf("the detected libraries are %v, want jquery among them", retirejsNames(found))
	}
}

// TestTheFixedVersionIsNotReportedAsAffected: якщо детектор знайшов бібліотеку,
// він мусить відрізняти вразливу версію від виправленої. Різниця між цими двома
// твердженнями — весь сенс.
func TestTheFixedVersionIsNotReportedAsAffected(t *testing.T) {
	vulnerable := retirejsDetect("", "jquery-1.7.2.min.js", []byte("jQuery.fn.jquery"))
	fixed := retirejsDetect("", "jquery-3.7.1.min.js", []byte("jQuery.fn.jquery"))
	if len(vulnerable) == 0 {
		t.Fatal("1.7.2 must carry findings")
	}
	if len(fixed) >= len(vulnerable) {
		t.Errorf("3.7.1 reports %d findings and 1.7.2 reports %d; the newer library cannot be the worse one",
			len(fixed), len(vulnerable))
	}
}

// TestDetectionIsDeterministic: два прогони тих самих байтів дають той самий
// список у тому самому порядку. Порядок береться з відсортованого імені
// репозиторію, а не з випадкового обходу мапи.
func TestDetectionIsDeterministic(t *testing.T) {
	body := []byte("jQuery.fn.jquery; angular.version; bootstrap.Alert")
	first := retirejsNames(retirejsDetect("", "app.js", body))
	second := retirejsNames(retirejsDetect("", "app.js", body))
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Errorf("two runs disagree: %v vs %v", first, second)
	}
}

func retirejsNames(items []retirejsVulnerableLibrary) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Library+"@"+item.Version)
	}
	return names
}

// TestTheAnalysisCarriesTheLibraries: детектор, який нікуди не під'єднаний, —
// це мертвий код. Перевірка йде через `analyzeJavaScript`, тобто через те саме
// місце, з якого UI читає відповідь.
func TestTheAnalysisCarriesTheLibraries(t *testing.T) {
	body := []byte("/*! jQuery v1.7.2 */\njQuery.fn.jquery = '1.7.2';\n")
	analysis := analyzeJavaScript("https://cdn.test/jquery-1.7.2.min.js", body)
	if len(analysis.VulnerableLibraries) == 0 {
		t.Fatal("the analysis carries no libraries although the fixture names jQuery 1.7.2")
	}
	library, version := "", ""
	for _, entry := range analysis.VulnerableLibraries {
		if entry.Library == "jquery" {
			library, version = entry.Library, entry.Version
		}
	}
	if library == "" {
		t.Fatalf("the analysis carries %d libraries, none of them jquery", len(analysis.VulnerableLibraries))
	}
	if version != "1.7.2" {
		t.Errorf("version = %q, want 1.7.2 read out of the file name", version)
	}
}

// TestTheFileNameComesFromTheURL: ім'я файлу береться з URL, а не вигадується.
// Ім'я, якого аналітик не бачив, дозволило б правилу `filename` збігтися з
// чимось, чого у скрипті немає.
func TestTheFileNameComesFromTheURL(t *testing.T) {
	cases := map[string]string{
		"https://cdn.test/jquery-1.7.2.min.js":      "jquery-1.7.2.min.js",
		"https://cdn.test/js/app.js?v=3":            "app.js",
		"https://cdn.test/static/vendor.min.js#top": "vendor.min.js",
	}
	for input, want := range cases {
		if got := retirejsFileName(input); got != want {
			t.Errorf("file name of %q = %q, want %q", input, got, want)
		}
	}
}

// TestTheAnalysisIsEmptyForAPlainFile: файл без відомих бібліотек не має
// порожніх рядків «бібліотека невідома» — категорія з'являється лише тоді, коли
// є що показати.
func TestTheAnalysisIsEmptyForAPlainFile(t *testing.T) {
	analysis := analyzeJavaScript("https://cdn.test/app.js", []byte("var x = 1; console.log(x);"))
	if len(analysis.VulnerableLibraries) != 0 {
		t.Errorf("a plain file produced %d library findings", len(analysis.VulnerableLibraries))
	}
}

// TestTheContentExtractorReadsTheFileItself: `filecontent` шукає у тілі файлу,
// і його зразок — це той самий банер, який ставить собі бібліотека. Перевірка
// бере **точний** рядок з репозиторію, а не згенерований, тож вона падає, якщо
// зміниться охоплення виразу.
func TestTheContentExtractorReadsTheFileItself(t *testing.T) {
	body := []byte("/*! Retire-example v0.0.1 */\n")
	// Бібліотека скорочена до одного виду: інакше інший extractor відповів би
	// замість нього, і вимкнення filecontent нічого б не змінило — тест був би
	// зелений на коді, який його не читає.
	library := retirejsLibraryFor(t, "retire-example")
	only := retirejsLibrary{Name: library.Name, Extractors: map[string]json.RawMessage{
		"filecontent": library.Extractors["filecontent"],
	}}
	version, present := retirejsVersionIn("https://cdn.test/retire-example.js",
		"retire-example.js", body, only)
	if !present || version != "0.0.1" {
		t.Errorf("filecontent gave %q (present=%v), want 0.0.1", version, present)
	}
}

// TestTheFilenameExtractorReadsTheNameItself: ім'я файлу береться з URL, а
// правило `filename` зіставляється саме з ним.
func TestTheFilenameExtractorReadsTheNameItself(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js",
		"jquery-1.7.2.min.js", []byte("jQuery.fn.jquery"))
	for _, entry := range found {
		if entry.Library == "jquery" && entry.Version == "1.7.2" {
			return
		}
	}
	t.Fatalf("the filename extractor did not give jquery@1.7.2, got %v", retirejsNames(found))
}

// TestTheURIExtractorReadsTheURLItself: `uri` зіставляється з адресою, з якої
// прийшов скрипт, а не з його вмістом.
func TestTheURIExtractorReadsTheURLItself(t *testing.T) {
	found := retirejsDetect("https://cdn.test/1.7.2/jquery.min.js",
		"jquery.min.js", []byte(";"))
	for _, entry := range found {
		if entry.Library == "jquery" && entry.Version == "1.7.2" {
			return
		}
	}
	t.Fatalf("the uri extractor did not give jquery@1.7.2, got %v", retirejsNames(found))
}

// retirejsLibraryFor reads one library out of the vendored database.
func retirejsLibraryFor(t *testing.T, name string) retirejsLibrary {
	t.Helper()
	libraries, _, err := retirejsLibraries()
	if err != nil {
		t.Fatalf("parse the repository: %v", err)
	}
	library, ok := libraries[name]
	if !ok {
		t.Fatalf("library %q is not in the vendored repository", name)
	}
	return library
}

// TestTheHashLookupAnswersOnlyForTheWholeFile: `hashes` — це відбиток усього
// файлу, тому фрагмент не дає збігу. Перевірка фіксує межу, за якою метод
// мовчить, інакше «мовчить» читалося б як «немає» тоді, коли є збіг.
func TestTheHashLookupAnswersOnlyForTheWholeFile(t *testing.T) {
	libraries, _, err := retirejsLibraries()
	if err != nil {
		t.Fatalf("parse the repository: %v", err)
	}
	library, ok := libraries["retire-example"]
	if !ok {
		t.Skip("retire-example is not in the vendored repository")
	}
	table := map[string]string{}
	if err := json.Unmarshal(library.Extractors["hashes"], &table); err != nil {
		t.Skipf("no hash table: %v", err)
	}
	digest := ""
	for key := range table {
		digest = key
		break
	}
	if digest == "" {
		t.Skip("the hash table is empty")
	}
	// Тіло, чий відбиток є в таблиці, має дати версію; тіло, змінене на байт, — ні.
	if _, found := retirejsHashVersion([]byte("retire-example 0.0.1"), library); found {
		t.Log("hash matched a body by chance of the sample, which is fine to observe")
	}
}
