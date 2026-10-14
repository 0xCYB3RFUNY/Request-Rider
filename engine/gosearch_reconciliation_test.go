package main

// Механічна перевірка реєстру звірки з `ibnaleem/gosearch`.
//
// Те саме, що `pinkerton_reconciliation_test.go`, `jsfscan_reconciliation_test.go`
// і `js_analyser_reconciliation_test.go`. Причина та ж: порт активного сканера
// був оголошений законченим з трьома мовчки втраченими здатностями, а звірка
// була написана — і нічого не помітила.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const gosearchRegistry = "gosearch_reconciliation.md"

// gosearchUpstreamCommit вимагає зафіксований коміт: таблиця без нього описує
// невідомий стан оригіналу.
var gosearchUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

// gosearchVerdicts — рівно три відповіді. Четвертої не існує: «в процесі»,
// «частково» і порожнє — це словами прикривають втрату.
var gosearchVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

// Рядок реєстру: номер, потім сім колонок. Вимога до кількості колонок — не
// прикраса: таблиці «прогалин» у інших реєстрах мають іншу ширину, і без цієї
// перевірки їхні рядки проходили б як рядки реєстру — з вердиктом у стовпці
// «причина».
var gosearchRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readGosearchRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(gosearchRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchRegistry, err)
	}
	rows := make([][]string, 0, 24)
	for _, line := range strings.Split(string(raw), "\n") {
		match := gosearchRow.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		cells := strings.Split(match[2], "|")
		if len(cells) < 6 {
			continue
		}
		rows = append(rows, append([]string{match[1]}, cells...))
	}
	return rows
}

func TestGosearchRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(gosearchRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchRegistry, err)
	}
	if !gosearchUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit; a table against an unknown commit is a declaration",
			gosearchRegistry)
	}
}

// TestEveryGosearchRowHasAVerdictFromTheThree
func TestEveryGosearchRowHasAVerdictFromTheThree(t *testing.T) {
	rows := readGosearchRegistry(t)
	if len(rows) == 0 {
		t.Fatalf("%s has no numbered rows at all", gosearchRegistry)
	}
	for _, row := range rows {
		if len(row) < 4 {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		verdict := strings.Trim(strings.TrimSpace(row[3]), "`")
		if !gosearchVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено", row[0], verdict)
		}
	}
}

// TestEveryNotPortedGosearchRowHasAReasonAndAnAlternative — причина обов'язкова, і
// так само обов'язково сказано, що використовується замість.
func TestEveryNotPortedGosearchRowHasAReasonAndAnAlternative(t *testing.T) {
	for _, row := range readGosearchRegistry(t) {
		if len(row) < 6 {
			t.Errorf("row %s has no reason cell", row[0])
			continue
		}
		if strings.Trim(strings.TrimSpace(row[3]), "`") != "не перенесено" {
			continue
		}
		reason := strings.TrimSpace(row[5])
		if reason == "" || reason == "—" || reason == "-" {
			t.Errorf("row %s is не перенесено with no reason", row[0])
		}
		if !strings.Contains(strings.ToLower(reason), "причина") {
			t.Errorf("row %s is не перенесено but the reason does not say why: %s", row[0], reason)
		}
	}
}

// TestEveryGosearchRowNamesASymbolThatExists — заявлений символ має бути в дереві.
// Пошук іде по **всіх** шарах, де живе заявлене: `.go`, `pkg/`, шаблони. Пошук
// лише по кореневих `*.go` відзвістував би «немає» про наявний код, і перевірка
// стала б декорацією.
func TestEveryGosearchRowNamesASymbolThatExists(t *testing.T) {
	sources := gosearchEngineSources(t)
	for _, row := range readGosearchRegistry(t) {
		if len(row) < 7 {
			t.Errorf("row %s names no symbol", row[0])
			continue
		}
		symbol := strings.Trim(strings.TrimSpace(row[6]), "`")
		if symbol == "" || symbol == "—" || symbol == "-" {
			t.Errorf("row %s names no symbol", row[0])
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// gosearchEngineSources reads every Go file in the engine, plus the web templates,
// so a symbol that lives in `pkg/` or in a template is found rather than reported
// missing.
//
// `filepath.WalkDir` is used rather than a fixed list of files precisely because a
// fixed list goes stale: the day a symbol moves, the check starts reporting "no"
// about code that is right there, and a check that cries wolf is a check nobody
// reads.
func gosearchEngineSources(t *testing.T) string {
	t.Helper()
	parts := []string{}
	for _, root := range []string{".", "pkg", "web/templates"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				switch info.Name() {
				case ".git", "node_modules", "__pycache__":
					return filepath.SkipDir
				}
				return nil
			}
			switch filepath.Ext(path) {
			case ".go", ".html", ".py":
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return nil
				}
				parts = append(parts, string(data))
			}
			return nil
		})
		if err != nil {
			t.Logf("walk %s: %v", root, err)
		}
	}
	return strings.Join(parts, "\n")
}

// TestTheGosearchRegistryCoversEveryUpstreamCapability — перелік рядків знято з
// файлів оригіналу, і число має бути зафіксовано: рядок, який зник, читається
// як «ніколи не було».
func TestTheGosearchRegistryCoversEveryUpstreamCapability(t *testing.T) {
	rows := readGosearchRegistry(t)
	// 24 експортовані функції здатностей оригіналу без `theme` (19 функцій
	// кольору — це вивід, а не здатність).
	if len(rows) != 24 {
		t.Errorf("the registry carries %d rows, want one per upstream capability (24)", len(rows))
	}
	// І номери не мають пропускатися: дірка в нумерації — це рядок, який
	// вирішили не писати.
	for index, row := range rows {
		if row[0] != strconv.Itoa(index+1) {
			t.Errorf("row %d is numbered %s; the sequence has a gap, which is a row nobody wrote",
				index+1, row[0])
		}
	}
}

// TestTheThreePortedSourcesAreNamedInTheRegistry — те, що ми називаємо перенесеним,
// має бути і в реєстрі, і в коді. Реєстр, який забув про власну ітерацію, читається
// як повний.
func TestTheThreePortedSourcesAreNamedInTheRegistry(t *testing.T) {
	raw, err := os.ReadFile(gosearchRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchRegistry, err)
	}
	text := string(raw)
	for _, source := range []string{"ProxyNova", "BreachDirectory", "weakpass"} {
		if !strings.Contains(text, source) {
			t.Errorf("the registry does not name %s, the source this session ported", source)
		}
	}
	if entry := transformRegistryEntry("breach_exposure"); entry == nil {
		t.Error("breach_exposure is not in the transform registry, so the port exists only as a file")
	}
}

// TestTheRegistryCoversEveryCapabilityWithNoSilentGaps: реєстр має 24 рядки — по
// одному на кожну експортову функцію оригіналу — і жодного рядка `не перенесено`.
//
// Чому саме нуль, а не «менше 8»: вісім рядків, які спершу були `не перенесено`,
// виявилися переносними (чотири GitHub-ендпоінти, Gravatar, Keybase, HudsonRock,
// домени) або такими, що перенесені **замість** оригінальної форми (файли, CLI,
// завантаження каталогу). Тест, який вимагає «менше 8», дозволив би цим рядкам
// лишитися мовчки ще на одну ітерацію — а саме мовчання про втрату і є те, що
// алгоритм перенесення забороняє. Якщо колись з'явиться справжня прогалина,
// вона має бути рядком із причиною, і тоді цей тест треба переписати разом із
// ним — разом, а не тихо.
func TestTheRegistryCoversEveryCapabilityWithNoSilentGaps(t *testing.T) {
	rows := readGosearchRegistry(t)
	if len(rows) != 24 {
		t.Fatalf("the registry carries %d rows, want one per upstream capability (24)", len(rows))
	}
	for _, row := range rows {
		if len(row) < 4 {
			t.Fatalf("row %s has no verdict cell", row[0])
		}
		if strings.Trim(strings.TrimSpace(row[3]), "`") == "не перенесено" {
			t.Errorf("row %s is still не перенесено: %s", row[0], strings.TrimSpace(row[5]))
		}
	}
}

// TestEveryUpstreamCapabilityNamesSomethingThatExists: вердикт без символа — це
// твердження без предмета. Кожен рядок має вказати, де в дереві живе те, що він
// переносить.
func TestEveryUpstreamCapabilityNamesSomethingThatExists(t *testing.T) {
	for _, row := range readGosearchRegistry(t) {
		if len(row) < 6 {
			t.Errorf("row %s names no symbol", row[0])
			continue
		}
		// The "у нас" column names the function or the transform.
		ours := strings.TrimSpace(row[4])
		if ours == "" || ours == "—" || ours == "-" {
			t.Errorf("row %s is classified but names nothing of ours", row[0])
		}
	}
}

// TestTheRegistryRecordsTheLiveRun: вимір, який нікого не перевіряє, — це число в
// тексті. Прогін 2026-10-07 дав 18 адрес і 19 кредів, і саме ця розбіжність
// довела, що ProxyNova повертає одну адресу двома різними паролями.
func TestTheRegistryRecordsTheLiveRun(t *testing.T) {
	raw, err := os.ReadFile(gosearchRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", gosearchRegistry, err)
	}
	text := string(raw)
	for _, needle := range []string{"687f9ed", "count: 3458", "200804al3xis", "akkord@pravda.ru"} {
		if !strings.Contains(text, needle) {
			t.Errorf("the registry does not record %q from the live run", needle)
		}
	}
}
