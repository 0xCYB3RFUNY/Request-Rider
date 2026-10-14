package main

// Механічна перевірка реєстру звірки з `projectdiscovery/nuclei-action`.
//
// Це **CI-обгортка на 383 рядки JavaScript**: вона ставить бінарник nuclei,
// розбирає аргументи й кешує шаблони між запусками GitHub Actions.
//
// Тому перевірка має три шари:
//
//  1. предмет звірки — коміт зафіксовано;
//  2. **контракт Action** — 7 inputs / 2 outputs знімаються з `action.yaml`
//     клону. Кількість полів звіряється: Action з доданим полем зобов'язаний
//     отримати рядок у реєстрі;
//  3. наші символи — причому **з `start.sh`**, бо половина наших
//     відповідей на здатності цього Action живе саме там, а не в Go.
//
// Окремо перевіряється рядок 1 (пін версії): це єдине місце, де ми сильніші
// за заміну, і воно мусить лишатися сильнішим.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const nucleiActionRegistry = "nuclei_action_reconciliation.md"

const nucleiActionCommit = "ca21b89"

const nucleiActionRequiredRows = 11

var nucleiActionCloneRoots = []string{
	"../Semple-Интеграции/nuclei-action",
	"../nuclei-action",
}

var nucleiActionUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var nucleiActionVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var nucleiActionRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readNucleiActionRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(nucleiActionRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiActionRegistry, err)
	}
	rows := make([][]string, 0, nucleiActionRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := nucleiActionRow.FindStringSubmatch(strings.TrimSpace(line))
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

func nucleiActionCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func nucleiActionDir(t *testing.T) string {
	t.Helper()
	for _, root := range nucleiActionCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("nuclei-action clone not found in %v: the registry's counts "+
		"cannot be verified against the original", nucleiActionCloneRoots)
	return ""
}

// nucleiActionOurTree читає наш код **і `start.sh`**.
//
// Окрема функція, а не лише Go: половина здатностей цього Action — це
// встановлення бінарника, його закріплення версії та режим «лише
// встановити», і все це живе в `start.sh`. Перевірка, що читає тільки Go,
// не бачила б наших відповідей і впала б на порожньому дереві.
func nucleiActionOurTree(t *testing.T) string {
	t.Helper()
	parts := []string{}

	raw, err := os.ReadFile("../start.sh")
	if err != nil {
		t.Fatalf("read start.sh: %v", err)
	}
	parts = append(parts, string(raw))

	skipped := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == nucleiActionRegistry ||
			name == "reconciliation_summary_test.go"
	}
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
	if len(parts) <= 1 {
		t.Fatalf("no Go sources were read: the check would pass on start.sh alone")
	}
	return strings.Join(parts, "\n")
}

// TestTheNucleiActionRegistryFixesTheUpstreamCommit.
func TestTheNucleiActionRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(nucleiActionRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiActionRegistry, err)
	}
	match := nucleiActionUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", nucleiActionRegistry)
	}
	if got := string(match[1]); got != nucleiActionCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, nucleiActionCommit)
	}
}

// TestTheNucleiActionRegistryHasEveryRowItPromises.
func TestTheNucleiActionRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readNucleiActionRegistry(t)); got < nucleiActionRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			nucleiActionRegistry, got, nucleiActionRequiredRows)
	}
}

// TestEveryNucleiActionRowHasAVerdictFromTheThree.
func TestEveryNucleiActionRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readNucleiActionRegistry(t) {
		verdict := nucleiActionCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !nucleiActionVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedNucleiActionRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedNucleiActionRowSaysWhy(t *testing.T) {
	for _, row := range readNucleiActionRegistry(t) {
		if nucleiActionCell(row, 3) != "не перенесено" {
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

// TestEveryNucleiActionRowNamesASymbolThatExists.
func TestEveryNucleiActionRowNamesASymbolThatExists(t *testing.T) {
	tree := nucleiActionOurTree(t)
	for _, row := range readNucleiActionRegistry(t) {
		symbol := nucleiActionCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(tree, symbol) {
			t.Errorf("row %s claims symbol %q, which is neither in our Go code "+
				"nor in start.sh", row[0], symbol)
		}
	}
}

// nucleiActionInputNames дістає імена inputs з `action.yaml` клону.
var nucleiActionInputLine = regexp.MustCompile(`^\s{2}([a-z][a-z0-9-]*):\s*$`)

// TestEveryActionInputIsAccountedFor — головна перевірка цього реєстру.
//
// Перелік inputs знімається з **оригіналу**, а не з того, що вже є в
// реєстрі: інакше input, доданий upstream, просто не потрапив би у
// перелік і виглядав би так, наче його немає.
func TestEveryActionInputIsAccountedFor(t *testing.T) {
	dir := nucleiActionDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "action.yaml"))
	if err != nil {
		t.Fatalf("read action.yaml: %v", err)
	}
	registry, err := os.ReadFile(nucleiActionRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiActionRegistry, err)
	}
	text := string(registry)

	inInputs := false
	found := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "inputs:") {
			inInputs = true
			continue
		}
		if inInputs && len(line) > 0 && line[0] != ' ' {
			inInputs = false
		}
		if !inInputs {
			continue
		}
		match := nucleiActionInputLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		found++
		if !strings.Contains(text, "`"+match[1]+"`") {
			t.Errorf("the original declares input %q, and %s has no row "+
				"naming it", match[1], nucleiActionRegistry)
		}
	}
	if found == 0 {
		t.Fatalf("no inputs parsed out of %s: the registry's input table "+
			"cannot stand either way", filepath.Join(dir, "action.yaml"))
	}
}

// TestTheOutputContractIsNamed.
//
// Два outputs (`stdout`, `stderr`) — це те, заради чого Action взагалі
// існує: без них CI-крок не має результату. Реєстр мусить їх назвати.
func TestTheOutputContractIsNamed(t *testing.T) {
	raw, err := os.ReadFile(nucleiActionRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", nucleiActionRegistry, err)
	}
	text := string(raw)
	for _, name := range []string{"stdout", "stderr"} {
		if !strings.Contains(text, name) {
			t.Errorf("the original exposes output %q and the registry never "+
				"names it", name)
		}
	}
}

// TestOurVersionIsPinnedAndTheirsIsNot — рядок 1, наша єдина перевага.
//
// Реєстр стверджує `улучшено`: ми закріпили версію (`v3.11.1`), оригінал
// бере `latest`. Обидві частини мають бути правдиві:
//
//   - в `start.sh` мусить бути пін із `RR_NUCLEI_VERSION`;
//   - в клоні мусить бути `latest` за замовчуванням.
//
// Якщо ми знімемо пін, вердикт «ми сильніші» перестане бути виміряним.
func TestOurVersionIsPinnedAndTheirsIsNot(t *testing.T) {
	dir := nucleiActionDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "action.yaml"))
	if err != nil {
		t.Fatalf("read action.yaml: %v", err)
	}
	if !strings.Contains(string(raw), `default: "latest"`) {
		t.Error("the original no longer defaults to `latest`: row 1 claims " +
			"it resolves a moving target, and that is no longer true")
	}

	tree := nucleiActionOurTree(t)
	if !strings.Contains(tree, "RR_NUCLEI_VERSION") {
		t.Error("our start.sh no longer reads RR_NUCLEI_VERSION: row 1 claims " +
			"we pin the version, and the pin is gone")
	}
	if !strings.Contains(tree, "v3.11.1") {
		t.Error("our pinned nuclei version is gone from start.sh: row 1 quotes " +
			"the pin as the measured difference, and there is nothing to quote")
	}
}

// TestTheInstallOnlyRowNamesARealBranchInsteadOfAFlag.
//
// Рядок 9 каже, що `install-only` у нас **є**, але не як перемикач, а як
// гілка `start.sh`, яка виходить, коли бінарник уже на місці. Твердження
// неочевидне, тож перевіряється пошуком нашої гілки.
func TestTheInstallOnlyRowNamesARealBranchInsteadOfAFlag(t *testing.T) {
	tree := nucleiActionOurTree(t)
	if !strings.Contains(tree, "ensure_nuclei") {
		t.Error("start.sh no longer has ensure_nuclei: row 9 calls it the place " +
			"where our install-only behaviour lives")
	}
	if strings.Contains(tree, "install-only") {
		t.Error("start.sh grew an `install-only` switch: row 9 says the " +
			"behaviour is a branch and not a separate mode, and that is no " +
			"longer true")
	}
}
