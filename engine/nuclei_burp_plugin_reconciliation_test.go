package main

// Механічна перевірка реєстру звірки з `projectdiscovery/nuclei-burp-plugin`.
//
// Репозиторій — **Java-плагін для Burp Suite на 6 387 рядків**, і його
// головна особливість вимірювана: він **не перехоплює** HTTP. Жоден з
// інтерфейсів Burp для перехоплення (`IBurpExtender`, `IHttpListener`,
// `IScannerCheck`, `ICheck`) у `src/main` не згаданий.
//
// Тому перевірка має чотири шари:
//
//  1. предмет звірки — коміт зафіксовано;
//  2. **відсутність** перехоплення — вимірюється по клону, а не asserted;
//     якщо хтось додасть `IHttpListener`, реєстр мусить це помітити;
//  3. наші символи;
//  4. **`-validate` ми прибрали** — рядок 4 каже це, і твердження має
//     залишатися правдивим: якщо ми знову ввімкнемо `-validate`, вердикт
//     «не перенесено» стане частково хибним, і це треба побачити.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const nucleiBurpPluginRegistry = "nuclei_burp_plugin_reconciliation.md"

const nucleiBurpPluginCommit = "5dc46f9"

const nucleiBurpPluginRequiredRows = 12

var nucleiBurpPluginCloneRoots = []string{
	"../Semple-Интеграции/nuclei-burp-plugin",
	"../nuclei-burp-plugin",
}

var nucleiBurpPluginUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var nucleiBurpPluginVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var nucleiBurpPluginRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readNucleiBurpPluginRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(nucleiBurpPluginRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiBurpPluginRegistry, err)
	}
	rows := make([][]string, 0, nucleiBurpPluginRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := nucleiBurpPluginRow.FindStringSubmatch(strings.TrimSpace(line))
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

func nucleiBurpPluginCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func nucleiBurpPluginDir(t *testing.T) string {
	t.Helper()
	for _, root := range nucleiBurpPluginCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("nuclei-burp-plugin clone not found in %v: the registry's counts "+
		"cannot be verified against the original", nucleiBurpPluginCloneRoots)
	return ""
}

func nucleiBurpPluginOurSources(t *testing.T) string {
	t.Helper()
	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == nucleiBurpPluginRegistry ||
			name == "reconciliation_summary_test.go"
	}
	parts := []string{}
	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner", "pkg/intruder"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				skipped(entry.Name()) {
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

// TestTheNucleiBurpPluginRegistryFixesTheUpstreamCommit.
func TestTheNucleiBurpPluginRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(nucleiBurpPluginRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiBurpPluginRegistry, err)
	}
	match := nucleiBurpPluginUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", nucleiBurpPluginRegistry)
	}
	if got := string(match[1]); got != nucleiBurpPluginCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, nucleiBurpPluginCommit)
	}
}

// TestTheNucleiBurpPluginRegistryHasEveryRowItPromises.
func TestTheNucleiBurpPluginRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readNucleiBurpPluginRegistry(t)); got < nucleiBurpPluginRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			nucleiBurpPluginRegistry, got, nucleiBurpPluginRequiredRows)
	}
}

// TestEveryNucleiBurpPluginRowHasAVerdictFromTheThree.
func TestEveryNucleiBurpPluginRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readNucleiBurpPluginRegistry(t) {
		verdict := nucleiBurpPluginCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !nucleiBurpPluginVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedNucleiBurpPluginRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedNucleiBurpPluginRowSaysWhy(t *testing.T) {
	for _, row := range readNucleiBurpPluginRegistry(t) {
		if nucleiBurpPluginCell(row, 3) != "не перенесено" {
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

// TestEveryNucleiBurpPluginRowNamesASymbolThatExists — символ має бути в дереві.
func TestEveryNucleiBurpPluginRowNamesASymbolThatExists(t *testing.T) {
	sources := nucleiBurpPluginOurSources(t)
	for _, row := range readNucleiBurpPluginRegistry(t) {
		symbol := nucleiBurpPluginCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in our tree: a symbol "+
				"from the original's Java code is not evidence about ours",
				row[0], symbol)
		}
	}
}

// TestTheOriginalTrulyDoesNotInterceptHTTP — головна знахідка цього реєстру.
//
// Реєстр стверджує: плагін **не перехоплює** HTTP, він лише генерує шаблон
// з контекстного меню. Це неочевидне твердження — «Burp-плагін» читається як
// «інтегрований у сканування».
//
// Тому воно вимірюється, а не декларується: якщо upstream додасть
// `IHttpListener` або `IScannerCheck`, нуль зникне — і реєстр опише вже не
// той предмет.
func TestTheOriginalTrulyDoesNotInterceptHTTP(t *testing.T) {
	dir := nucleiBurpPluginDir(t)
	for _, iface := range []string{
		"IBurpExtender",
		"IHttpListener",
		"IScannerCheck",
		"ICheck",
		"IHttpRequestHandler",
		"IScannerInsertionPoint",
	} {
		hits := 0
		err := filepath.Walk(filepath.Join(dir, "src", "main"), func(path string,
			info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".java") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(raw), iface) {
				hits++
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
		if hits != 0 {
			t.Errorf("the original now implements %s in %d files: the registry "+
				"says it does not intercept HTTP, and that is no longer true",
				iface, hits)
		}
	}
}

// TestTheRegistrySaysThePluginOnlyGenerates.
//
// Реєстр має прямо сказати, що здатність «перехоплення подій Burp» у
// оригіналі **не існує**. Без цього читач вирішить, що прогалина — наша.
func TestTheRegistrySaysThePluginOnlyGenerates(t *testing.T) {
	raw, err := os.ReadFile(nucleiBurpPluginRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiBurpPluginRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "генер") {
		t.Error("the registry never says what the plugin does: a reader would " +
			"have to guess whether it scans or generates")
	}
	if !strings.Contains(text, "не існує в оригіналі") &&
		!strings.Contains(text, "немає в оригіналі") {
		t.Error("the registry does not state that HTTP interception is absent " +
			"FROM THE ORIGINAL: without that sentence the gap reads as ours")
	}
}

// TestTheValidateRetirementClaimStillHolds — рядок 4.
//
// Реєстр каже `не перенесено` і називає причину: **`-validate` ми свідомо
// прибрали**, бо валідатор і сканер розходяться на `flow:`.
//
// Твердження двостороннє, і обидві частини мають бути правдиві:
//
//   - код мусить досі фіксувати, що проходу `-validate` немає;
//   - `-validate` не має з'явитися як **виконуваний** аргумент.
//
// Якщо ми знову ввімкнемо реальний виклик, вердикт «ми не валідуємо» стане
// частково хибним, і реєстр треба перечитати.
func TestTheValidateRetirementClaimStillHolds(t *testing.T) {
	sources := nucleiBurpPluginOurSources(t)

	if !strings.Contains(sources, "There is no `-validate` pass") &&
		!strings.Contains(sources, "NOT the `-validate` pass") {
		t.Error("our code no longer records that the `-validate` pass was " +
			"removed: row 4 cites that removal as the reason we do not " +
			"validate while editing, so the reason has vanished")
	}

	// Реальний виклик виглядає як аргумент у списку, а не як згадка в
	// коментарі. Шукаємо `"`-validate`"` — це рядковий літерал, який
	// потрапив би в argv.
	//
	// Важливо: перевіряємо **лише продуктивний код**, без `*_test.go`.
	// `pkg/scanner/nuclei_dast_test.go:168` тримає рядок `"-validate"` —
	// саме тому, що тест перевіряє, що ми НЕ запускаємо цей прохід. Якщо
	// не виключити тести, перевірка читала б власний тест і стверджувала б,
	// що ми знову увімкнули `-validate`.
	if strings.Contains(nucleiBurpPluginProductionSources(t), "\"-validate\"") {
		t.Error("our code passes `-validate` to the binary again: row 4 claims " +
			"we do not validate, and that is no longer true")
	}
}

// nucleiBurpPluginProductionSources — джерела без тестів.
//
// Окрема функція, а не параметр наведеної вище: `TestWeStillRunBoth…` і
// `TestEveryRowNamesASymbol…` мають право бачити тести (символ може жити в
// `pkg/intruder`), а перевірка «ми більше не запускаємо `-validate`» — ні,
// бо її цікавить тільки те, що піде в `argv`.
func nucleiBurpPluginProductionSources(t *testing.T) string {
	t.Helper()
	parts := []string{}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		parts = append(parts, string(raw))
		return nil
	})
	if err != nil {
		t.Fatalf("walk our tree: %v", err)
	}
	if len(parts) == 0 {
		t.Fatalf("no production sources were read: the check would pass on an " +
			"empty tree")
	}
	return strings.Join(parts, "\n")
}

// TestTheLiveCVEGapIsNotMistakenForAField — рядки 7 і 8.
//
// У нас є поле `CVE string` у `retirejs.go`, але воно приходить із
// **вбудованого** `retirejs-repository.json`, а не з NVD. Тому реєстр має
// назвати саме **живий** запит, щоб наявність поля не читалася як покриття.
func TestTheLiveCVEGapIsNotMistakenForAField(t *testing.T) {
	raw, err := os.ReadFile(nucleiBurpPluginRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiBurpPluginRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "живого nvd-запиту в нас немає") &&
		!strings.Contains(text, "живого nvd") {
		t.Error("the registry does not say the NVD lookup is absent from our " +
			"code: our `CVE` field exists, and without this sentence rows 7 and " +
			"8 read as a mismatch of naming rather than a missing capability")
	}

	// І навпаки: якщо ми додамо живий запит до NVD, ці два рядки стануть
	// брехнею, і це теж треба побачити.
	sources := nucleiBurpPluginOurSources(t)
	if strings.Contains(sources, "services.nvd.nist.gov") {
		t.Error("our code now queries services.nvd.nist.gov: rows 7 and 8 " +
			"claim we have no live NVD lookup, and that is no longer true")
	}
}

// TestTheIntruderModesAreASupersetOfTheOriginal.
//
// Оригінал має три режими: `batteringram`, `pitchfork`, `clusterbomb`.
// Реєстр стверджує, що в нас усі три **плюс** `sniper`.
//
// Твердження «надмножина» перевірюється механічно: кожен режим оригіналу
// мусить бути в нашому коді, і `sniper` мусить бути наш власний.
func TestTheIntruderModesAreASupersetOfTheOriginal(t *testing.T) {
	sources := nucleiBurpPluginOurSources(t)
	for _, mode := range []string{"batteringram", "pitchfork", "clusterbomb", "sniper"} {
		if !strings.Contains(sources, `"`+mode+`"`) {
			t.Errorf("row 2 claims mode %q is in our code, and it is not", mode)
		}
	}
}
