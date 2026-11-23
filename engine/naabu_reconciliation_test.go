package main

// Механічна перевірка реєстру звірки з `projectdiscovery/naabu`.
//
// Найважливіше в цьому реєстрі — **різниця значень, а не різниця обсягу**.
// Наш пошук `fingerprint` у дереві дає 35 файлів, і без перевірки
// реєстр виглядав би так, наче здатність «ідентифікація сервісу» перекрита.
// Вона ні: наші `fingerprint*` — це дедуплікація секретів і пасивний збіг
// відповіді. Тому головна перевірка тут не рахує файли, а **перевіряє, що
// жоден із наших символів не є зондом сервісу** — інакше вердикт
// `не перенесено` у рядку 3 був би брехнею.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const naabuRegistry = "naabu_reconciliation.md"

const naabuCommit = "51e24e3"

var naabuCloneRoots = []string{
	"../Semple-Интеграции/naabu",
	"../naabu",
}

var naabuUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var naabuVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var naabuRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const naabuRequiredRows = 12

func readNaabuRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(naabuRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", naabuRegistry, err)
	}
	rows := make([][]string, 0, naabuRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := naabuRow.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		cells := strings.Split(match[2], "|")
		if len(cells) < 5 {
			continue
		}
		rows = append(rows, append([]string{match[1]}, cells...))
	}
	return rows
}

func naabuCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// naabuDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються, щоб прогалина була видима.
func naabuDir(t *testing.T) string {
	t.Helper()
	for _, root := range naabuCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("naabu clone not found in %v: the registry's counts cannot be "+
		"verified against the original", naabuCloneRoots)
	return ""
}

// naabuOurSources читає наше дерево, **крім** реєстру й його тесту.
//
// Виключення обов'язкове: і реєстр, і цей тест згадують `fingerprint`,
// `scan` та інші слова оригіналу за визначенням. Без виключення перевірка
// «у нас немає зондів» читала б сама себе і не могла б пройти ніколи.
func naabuOurSources(t *testing.T) string {
	t.Helper()
	//
	// Виключається **всі** реєстрові файли за суфіксом, а не лише власні
	// цього тесту: `PortScan` згаданий також у
	// `pkg/active/xss_upstreams_reconciliation_test.go` і
	// `ashok_reconciliation_test.go`, тож перелік імен пропускав їх — і
	// перевірка падала на власних файлах сусідніх реєстрів.
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == naabuRegistry ||
			name == "reconciliation_summary_test.go"
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner", "pkg/enrich"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			if skipped(entry.Name()) {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
			if readErr != nil {
				continue
			}
			parts = append(parts, string(raw))
		}
	}
	if len(parts) == 0 {
		t.Fatalf("no sources were read: the check would pass on an empty tree")
	}
	return strings.Join(parts, "\n")
}

// TestNaabuRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestNaabuRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(naabuRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", naabuRegistry, err)
	}
	match := naabuUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", naabuRegistry)
	}
	if got := string(match[1]); got != naabuCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, naabuCommit)
	}
}

// TestTheNaabuRegistryHasEveryRowItPromises.
func TestTheNaabuRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readNaabuRegistry(t)); got < naabuRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			naabuRegistry, got, naabuRequiredRows)
	}
}

// TestEveryNaabuRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryNaabuRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readNaabuRegistry(t) {
		verdict := naabuCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !naabuVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улушшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedNaabuRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedNaabuRowSaysWhy(t *testing.T) {
	for _, row := range readNaabuRegistry(t) {
		if naabuCell(row, 3) != "не перенесено" {
			continue
		}
		tail := strings.Join(row[min(len(row), 5):], " | ")
		if strings.Trim(tail, " |") == "" {
			t.Errorf("row %s is не перенесено with no reason", row[0])
			continue
		}
		if !strings.Contains(strings.ToLower(tail), "причина") {
			t.Errorf("row %s is не перенесено but the reason never says why: %s", row[0], tail)
		}
	}
}

// TestEveryNaabuRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEveryNaabuRowNamesASymbolThatExists(t *testing.T) {
	sources := naabuOurSources(t)
	for _, row := range readNaabuRegistry(t) {
		symbol := naabuCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// naabuServiceProbe ловить **справжній зонд сервісу** в нашому коді: функцію,
// схожу на Fingerprint, тільки вона не має нічого спільного з дедуплікацією
// секретів.
//
// Критерій навмисно вузький і очікує **нуль**: якщо хтось додасть у нас
// ідентифікацію сервісу на порту, вердикт рядка 3 перестане бути
// `не перенесено`, і тест має це показати.
var naabuServiceProbe = regexp.MustCompile(
	`func\s+\w*(?:FingerprintProbe|ProbeService|IdentifyService|ServiceFingerprint)\w*\s*\(`)

// TestOurFingerprintSymbolsAreNotServiceProbes — головна перевірка реєстра.
//
// Наш пошук `fingerprint` дає 35 файлів. Реєстр каже, що ці символи — про
// секрети, а не про сервіси. Перевірка фіксує саме це: якщо з'явиться
// символ, схожий на зонд, вердикт рядка 3 доведеться переглянути.
func TestOurFingerprintSymbolsAreNotServiceProbes(t *testing.T) {
	sources := naabuOurSources(t)
	if found := naabuServiceProbe.FindAllString(sources, -1); len(found) > 0 {
		t.Errorf("our tree now declares what looks like a service probe (%v): "+
			"row 3 of %s is не перенесено, and that needs a look",
			found, naabuRegistry)
	}
}

// TestTheRegistryNamesWhyFingerprintIsNotCoverage — чесність про збіг у naming.
//
// Якщо реєстр мовчить про те, що `fingerprint` у нас означає інше, читач
// побачить 35 файлів і зробить висновок, що здатність перекрита. Тому текст
// обязан містити і розбір, і перелік наших символів.
func TestTheRegistryNamesWhyFingerprintIsNotCoverage(t *testing.T) {
	registry, err := os.ReadFile(naabuRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", naabuRegistry, err)
	}
	text := string(registry)
	if !strings.Contains(text, "secretFingerprint") {
		t.Errorf("%s does not name secretFingerprint: without it a reader cannot "+
			"see that our 'fingerprint' is about secrets, not services", naabuRegistry)
	}
	if !strings.Contains(text, "35") {
		t.Errorf("%s does not state how many files our 'fingerprint' search hits: "+
			"that number is what makes the naming collision visible", naabuRegistry)
	}
}

// TestThePredictionModelSizeIsMeasured — найбільший шматок оригіналу.
//
// `pkg/prediction/default_model.go` — 4 950 рядків, тобто більше за всю
// нашу мережеву здатність разом. Число звіряється з клоном, бо саме воно
// визначає, чи «перенесення» цього шматка є доробкою чи окремою задачею.
func TestThePredictionModelSizeIsMeasured(t *testing.T) {
	dir := naabuDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "pkg/prediction/default_model.go"))
	if err != nil {
		t.Fatalf("read upstream model: %v", err)
	}
	lines := strings.Count(string(raw), "\n")
	if lines < 1000 {
		t.Fatalf("the model is only %d lines: the registry's headline claim "+
			"about it needs a look", lines)
	}
	registry, err := os.ReadFile(naabuRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", naabuRegistry, err)
	}
	if wanted := naabuThousandsSeparator(lines); !strings.Contains(string(registry), wanted) {
		t.Errorf("the model holds %d lines, and the registry does not mention %s",
			lines, wanted)
	}
}

// naabuThousandsSeparator форматує число як у реєстрі: «4 950».
func naabuThousandsSeparator(value int) string {
	digits := strconv.Itoa(value)
	if len(digits) <= 3 {
		return digits
	}
	var out []byte
	for index, digit := range []byte(digits) {
		if index > 0 && (len(digits)-index)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, digit)
	}
	return string(out)
}

// TestWeHaveNoPortScanner — твердження «0 файлів з порт-сканом» перевірюється.
//
// Реєстр каже, що сканування портів у нас немає. Якщо з'явиться символ
// на кшталт `ScanPorts`, рядки 1-2 і 7-10 перестануть бути
// `не перенесено`, і тест має це сказати.
func TestWeHaveNoPortScanner(t *testing.T) {
	sources := naabuOurSources(t)
	for _, symbol := range []string{"ScanPorts", "scanPorts", "portScan", "PortScan",
		"scanRange", "SYNScanner"} {
		if strings.Contains(sources, symbol) {
			t.Errorf("our tree now declares %q: the registry's ten не перенесено "+
				"rows are about the absence of port scanning, and that has changed",
				symbol)
		}
	}
}

// TestTheRawSocketClaimIsMeasured — сирі сокети в нас не використовуються.
//
// Рядок 1 стверджує, що ми не маємо сирих сокетів і не піднімаємо привілеїв.
// Це твердження про наш код, тому воно перевірюється пошуком `syscall`/
// `AF_PACKET`: якщо ми раптом їх використовуємо, причина рядка 1 хибна.
func TestTheRawSocketClaimIsMeasured(t *testing.T) {
	sources := naabuOurSources(t)
	for _, token := range []string{"AF_PACKET", "SYS_RAW", "SOCK_RAW", "IPPROTO_TCP"} {
		if strings.Contains(sources, token) {
			t.Errorf("our tree now references %q: row 1 says we have no raw "+
				"socket path, and that needs a look", token)
		}
	}
}

// TestTheSubsystemCountIsMeasured — дев'ять підсистем у `pkg/` звірено з клоном.
func TestTheSubsystemCountIsMeasured(t *testing.T) {
	dir := naabuDir(t)
	entries, err := os.ReadDir(filepath.Join(dir, "pkg"))
	if err != nil {
		t.Fatalf("read upstream pkg: %v", err)
	}
	subsystems := 0
	for _, entry := range entries {
		if entry.IsDir() {
			subsystems++
		}
	}
	if subsystems == 0 {
		t.Fatalf("no subsystems found in the original: the registry's count " +
			"cannot stand either way")
	}
	registry, err := os.ReadFile(naabuRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", naabuRegistry, err)
	}
	if !strings.Contains(string(registry), strconv.Itoa(subsystems)) {
		t.Errorf("the original has %d subsystems in pkg/, and the registry does "+
			"not mention that number", subsystems)
	}
}
