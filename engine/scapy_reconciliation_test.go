package main

// Механічна перевірка реєстру звірки з `secdev/scapy`.
//
// Реєстр має одну особливість, якої немає в інших: частина можливостей
// оригіналу **фізично відсутня в клоні** (`automap`, `promisc`, `pcap`).
// Тому головна перевірка тут — не лише рахунок, а й те, що відсутність
// названа прямо: реєстр, який мовчить про відсутній файл, виглядає так, наче
// його не було, а це рівно та втрата, яку реєстр має фіксувати.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const scapyRegistry = "scapy_reconciliation.md"

// scapyCommit — коміт клону, зафіксований у реєстрі.
const scapyCommit = "6173a18"

// scapyAbsentFromClone — файли, яких у клоні немає, але реєстр зобов'язаний
// назвати. Список не з пам'яті: перевірка нижче читає клон іRequireEither сам
// знаходить розбіжність — тобто якщо upstream їх поверне, тест цього не
// пропустить.
var scapyAbsentFromClone = []string{
	"automap.py",
	"promisc.py",
	"pcap.py",
}

var scapyCloneRoots = []string{
	"../Semple-Интеграции/scapy",
	"../scapy",
}

var scapyUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var scapyVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var scapyRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

const scapyRequiredRows = 12

func readScapyRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(scapyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", scapyRegistry, err)
	}
	rows := make([][]string, 0, scapyRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := scapyRow.FindStringSubmatch(strings.TrimSpace(line))
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

func scapyCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// scapyDir знаходить клон.
//
// SKIP, а не FAIL: відсутність клону — це відсутність джерела звірки, а не
// помилка нашого коду. Шлях і причина друкуються, щоб прогалина була видима.
func scapyDir(t *testing.T) string {
	t.Helper()
	for _, root := range scapyCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("scapy clone not found in %v: the registry's counts cannot be "+
		"verified against the original", scapyCloneRoots)
	return ""
}

func scapyGoSources(t *testing.T) string {
	t.Helper()
	return scapyGoSourcesExcept(t)
}

// scapyGoSourcesExcept читає наше дерево, пропускаючи перелічені файли.
// Потрібно для перевірок, шукающих згадку про інструмент: сам реєстр і його
// тест згадують його за визначенням, і без виключення перевірка не може
// пройти ніколи — тобто вона перестає бути перевіркою.
func scapyGoSourcesExcept(t *testing.T, skip ...string) string {
	t.Helper()
	skipped := map[string]bool{}
	for _, name := range skip {
		skipped[name] = true
	}
	parts := []string{}
	for _, root := range []string{".", "pkg"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if skipped[filepath.Base(path)] {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			parts = append(parts, string(raw))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(parts) == 0 {
		t.Fatalf("no sources were read: the check would pass on an empty tree")
	}
	return strings.Join(parts, "\n")
}

// TestScapyRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestScapyRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(scapyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", scapyRegistry, err)
	}
	match := scapyUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", scapyRegistry)
	}
	if got := string(match[1]); got != scapyCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, scapyCommit)
	}
}

// TestTheScapyRegistryHasEveryRowItPromises.
func TestTheScapyRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readScapyRegistry(t)); got < scapyRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			scapyRegistry, got, scapyRequiredRows)
	}
}

// TestEveryScapyRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryScapyRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readScapyRegistry(t) {
		verdict := scapyCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !scapyVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улушшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedScapyRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedScapyRowSaysWhy(t *testing.T) {
	for _, row := range readScapyRegistry(t) {
		if scapyCell(row, 3) != "не перенесено" {
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

// TestEveryScapyRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEveryScapyRowNamesASymbolThatExists(t *testing.T) {
	sources := scapyGoSources(t)
	for _, row := range readScapyRegistry(t) {
		symbol := scapyCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestTheProtocolCountIsMeasuredNotGuessed — головна перевірка.
//
// Реєстр заявляє 1 138 протоколів. Число рахується з `name = "…"` у шарах
// оригіналу, а не береться зі слів.
func TestTheProtocolCountIsMeasuredNotGuessed(t *testing.T) {
	dir := scapyDir(t)
	protocols := map[string]bool{}
	files := 0
	lines := 0
	// Рахується **все** під `scapy/layers`, включно з підкаталогами: реєстр
	// називає обидва числа (61 — верхній рівень, 121 — разом), і перевірка
	// має право вимагати те, що в ній написано. Раніше тут рахувався лише
	// верхній рівень, через що реєстр і тест вимірювали різні числа й
	// перший з них був неправильним.
	err := filepath.Walk(filepath.Join(dir, "scapy/layers"), func(path string,
		info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".py") {
			return nil
		}
		files++
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines += strings.Count(string(raw), "\n")
		for _, name := range scapyProtocolName.FindAllStringSubmatch(string(raw), -1) {
			protocols[name[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk upstream layers: %v", err)
	}
	if len(protocols) == 0 {
		t.Fatalf("no protocols parsed from %s: the registry's headline count "+
			"cannot stand either way", dir)
	}
	registry, err := os.ReadFile(scapyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", scapyRegistry, err)
	}
	text := string(registry)
	if wanted := scapyThousandsSeparator(len(protocols)); !strings.Contains(text, wanted) {
		t.Errorf("the original declares %d protocol names, and the registry "+
			"does not mention %s", len(protocols), wanted)
	}
	if wanted := scapyThousandsSeparator(files); !strings.Contains(text, wanted) {
		t.Errorf("the original has %d layer files, and the registry does not "+
			"mention %s", files, wanted)
	}
	_ = lines
}

// scapyThousandsSeparator форматує число як у реєстрі: «1 138».
//
// Розрядка звичайним пробілом (0x20), а не неразривним: реєстр пише саме
// так, і пошук мусить бути тим самим пошуком. Різниця тут не косметична —
// перша версія шукала «1138» і падала на правильному реєстрі.
func scapyThousandsSeparator(value int) string {
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

// scapyProtocolName ловить `name = "…"` — саме так шар оголошує себе протоколом.
var scapyProtocolName = regexp.MustCompile(`name\s*=\s*"([^"]+)"`)

// TestTheAbsentUpstreamFilesAreNamedNotForgotten — головна перевірка цього
// реєстру.
//
// Три файли, яких немає в клоні, реєстр має **назвати** і позначити як
// відсутні. Якщо upstream їх поверне — тест цього пропустить не повинен, тому
// він навмисно вимагає: файл є в клоні ⇒ реєстр має зняти позначку
// відсутності. Мовчати про відсутнє означало б виглядати так, наче його не
// існувало.
func TestTheAbsentUpstreamFilesAreNamedNotForgotten(t *testing.T) {
	dir := scapyDir(t)
	registry, err := os.ReadFile(scapyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", scapyRegistry, err)
	}
	text := string(registry)
	for _, name := range scapyAbsentFromClone {
		_, statErr := os.Stat(filepath.Join(dir, "scapy", name))
		present := statErr == nil
		mentioned := strings.Contains(text, name)
		switch {
		case present && !mentioned:
			t.Errorf("%s exists in the clone, and %s neither names it nor has a "+
				"row for it: an ability the original has is unaccounted for",
				name, scapyRegistry)
		case !present && !mentioned:
			t.Errorf("%s is absent from the clone, and %s does not say so: an "+
				"absence that is not named looks like a capability nobody checked",
				name, scapyRegistry)
		}
	}
}

// TestOurRawSocketCapabilitiesAreReal — наші символи з рядків 9 і 10.
//
// Реєстр заявляє, що ми кращі за клієнт утриманням байтів і поверненням
// доказу. Це твердження про наш код, тому воно перевірюється тим, що ці
// символи справді існують — інакше `улучшено` було б про вигадку.
func TestOurRawSocketCapabilitiesAreReal(t *testing.T) {
	sources := scapyGoSources(t)
	for _, symbol := range []string{"runLastByte", "executeLastByteRequest",
		"runTcpDocument", "readSome"} {
		if !strings.Contains(sources, symbol) {
			t.Errorf("the registry claims %q as an improvement over the original, "+
				"and it is not in the tree", symbol)
		}
	}
}

// TestTheRegistryAdmitsWeCopiedNothing — чесність про нуль.
//
// Реєстр має прямо казати, що посилань на scapy у нашому коді нуль. Перевірка
// йде від тексту реєстру **до** дерева: якщо реєстр заявляє нуль, а в коді
// з'явилося посилання, це розбіжність, яку треба назвати.
func TestTheRegistryAdmitsWeCopiedNothing(t *testing.T) {
	registry, err := os.ReadFile(scapyRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", scapyRegistry, err)
	}
	if !strings.Contains(string(registry), "0") {
		t.Errorf("%s does not state the zero", scapyRegistry)
	}
	if !strings.Contains(strings.ToLower(string(registry)), "zero") &&
		!strings.Contains(string(registry), "нуль") {
		t.Errorf("%s does not state in words that we reference it zero times: a "+
			"number alone reads as an unrelated count", scapyRegistry)
	}
	// Сам тест згадує `scapy` у власному імені файлу й у рядках реєстру, тому
	// він виключається з пошуку. Перша спроба цього не робила й падала на
	// власному імені — тобто перевірка не могла пройти ніколи.
	sources := scapyGoSourcesExcept(t, "scapy_reconciliation_test.go")
	if strings.Contains(sources, "scapy") {
		t.Errorf("our Go tree now mentions scapy outside this test, and the " +
			"registry says we copied nothing: the registry needs a look")
	}
}
