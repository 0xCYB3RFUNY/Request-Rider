package main

// Механічна перевірка реєстру звірки з `OpenVulnScan`.
//
// Це **платформа керування вразливостями**, а не сканер, і головне вимірювання
// тут таке: **163 рядки з 3 785 — це весь скануючий шар**. Решта — база, ролі,
// черга, розклад, SIEM і агент на хості.
//
// Тому перевірка мірить саме це:
//
//  1. предмет звірки — коміт зафіксовано;
//  2. **наш код теж читається з `web/lab/`**, бо `ProjectEndpoint`,
//     `export_bundle` і `WORKFLOW_CELERY_ENABLED` живуть у Django, а не в Go.
//     Перевірка, що читає тільки Go, назвала б їх відсутніми;
//  3. рядок 6 — Celery у нас є, але **вимкнений свідомо**, і саме це
//     відрізняє `не перенесено` від «ми не вміємо».

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const openvulnRegistry = "openvulnscan_reconciliation.md"

const openvulnCommit = "f16a9de"

const openvulnRequiredRows = 11

// Скануючий шар оригіналу — головне вимірювання цього реєстру.
const (
	openvulnScannerLines = 163
	openvulnTotalLines   = 3785
)

var openvulnCloneRoots = []string{
	"../Semple-Интеграции/OpenVulnScan",
	"../OpenVulnScan",
}

var openvulnUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40})` + "`")

var openvulnVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var openvulnRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

func readOpenvulnRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(openvulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", openvulnRegistry, err)
	}
	rows := make([][]string, 0, openvulnRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := openvulnRow.FindStringSubmatch(strings.TrimSpace(line))
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

func openvulnCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

func openvulnDir(t *testing.T) string {
	t.Helper()
	for _, root := range openvulnCloneRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	t.Skipf("OpenVulnScan clone not found in %v: the registry's counts cannot "+
		"be verified against the original", openvulnCloneRoots)
	return ""
}

// openvulnOurTree збирає наш код з Go **і** Django.
//
// Окрема функція, а не лише Go: половина наших відповідей на здатності цього
// репозиторію (`ProjectEndpoint`, `export_bundle`, `WORKFLOW_CELERY_ENABLED`)
// живе у `web/lab/*.py`. Перевірка, що читає тільки `engine/`, назвала б їх
// відсутніми й змусила б або вигадати символи, або викинути рядки.
func openvulnOurTree(t *testing.T) string {
	t.Helper()
	parts := []string{}

	skip := func(name string) bool {
		return strings.HasSuffix(name, "_reconciliation_test.go") ||
			name == openvulnRegistry ||
			name == "reconciliation_summary_test.go"
	}
	appendDir := func(dir string, suffix string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) ||
				skip(entry.Name()) {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
			if readErr != nil {
				continue
			}
			parts = append(parts, string(raw))
		}
	}

	for _, root := range []string{".", "pkg", "pkg/active", "pkg/scanner",
		"pkg/intruder", "pkg/enrich"} {
		appendDir(root, ".go")
	}
	appendDir("../web/lab", ".py")
	appendDir("../web/core", ".py")

	if len(parts) == 0 {
		t.Fatalf("no sources were read: the check would pass on an empty tree")
	}
	return strings.Join(parts, "\n")
}

// TestTheOpenvulnRegistryFixesTheUpstreamCommit.
func TestTheOpenvulnRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(openvulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", openvulnRegistry, err)
	}
	match := openvulnUpstreamCommit.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("%s does not record the upstream commit", openvulnRegistry)
	}
	if got := string(match[1]); got != openvulnCommit {
		t.Errorf("the registry pins commit %s, while this test expects %s: either "+
			"the clone moved and the registry needs a look, or the test is stale",
			got, openvulnCommit)
	}
}

// TestTheOpenvulnRegistryHasEveryRowItPromises.
func TestTheOpenvulnRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readOpenvulnRegistry(t)); got < openvulnRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d",
			openvulnRegistry, got, openvulnRequiredRows)
	}
}

// TestEveryOpenvulnRowHasAVerdictFromTheThree.
func TestEveryOpenvulnRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readOpenvulnRegistry(t) {
		verdict := openvulnCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !openvulnVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedOpenvulnRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedOpenvulnRowSaysWhy(t *testing.T) {
	for _, row := range readOpenvulnRegistry(t) {
		if openvulnCell(row, 3) != "не перенесено" {
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

// TestEveryOpenvulnRowNamesASymbolThatExists.
func TestEveryOpenvulnRowNamesASymbolThatExists(t *testing.T) {
	tree := openvulnOurTree(t)
	for _, row := range readOpenvulnRegistry(t) {
		symbol := openvulnCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(tree, symbol) {
			t.Errorf("row %s claims symbol %q, which is neither in our Go code "+
				"nor in web/lab", row[0], symbol)
		}
	}
}

// openvulnLinesIn рахує рядки у файлах, які відповідають префіксу `dir`.
func openvulnLinesIn(t *testing.T, root string, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil {
		t.Fatalf("read %s/%s: %v", root, dir, err)
	}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".py") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(root, dir, entry.Name()))
		if readErr != nil {
			continue
		}
		total += strings.Count(string(raw), "\n")
	}
	return total
}

// TestTheScannerLayerIsFourPercentOfTheOriginal — головне вимірювання.
//
// Реєстр каже: 163 рядки з 3 785 — це весь скануючий шар, тобто 4,3 %.
// Число тримає на собі весь вердикт «це платформа, а не сканер», тому воно
// вимірюється з клону, а не береться з реєстру.
func TestTheScannerLayerIsFourPercentOfTheOriginal(t *testing.T) {
	dir := openvulnDir(t)
	scanners := openvulnLinesIn(t, dir, "scanners")
	if scanners != openvulnScannerLines {
		t.Errorf("the original's scanners/ package holds %d lines, the registry "+
			"claims %d", scanners, openvulnScannerLines)
	}
	if scanners*100/openvulnTotalLines > 10 {
		t.Errorf("scanners/ is %d%% of the codebase, and the registry calls it "+
			"under 5%%: the 'platform, not a scanner' reading no longer holds",
			scanners*100/openvulnTotalLines)
	}
}

// TestTheScannerShellsOutToNmapAndWhatweb.
//
// Рядки 1 і 2 кажуть `не перенесено`, бо ми не маємо ні Nmap, ні зовнішнього
// WhatWeb. Твердження перевіряється **пошуком у клону**: якщо оригінал
// перейде на власний сканер, вердикт треба перечитати.
func TestTheScannerShellsOutToNmapAndWhatweb(t *testing.T) {
	dir := openvulnDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "scanners", "nmap_runner.py"))
	if err != nil {
		t.Fatalf("read nmap_runner.py: %v", err)
	}
	if !strings.Contains(string(raw), "shutil.which(\"nmap\")") &&
		!strings.Contains(string(raw), "nmap") {
		t.Error("the original no longer invokes nmap: row 1 says we lack nmap " +
			"because the original shells out to it")
	}

	raw, err = os.ReadFile(filepath.Join(dir, "utils", "webtech.py"))
	if err != nil {
		t.Fatalf("read webtech.py: %v", err)
	}
	if !strings.Contains(string(raw), "whatweb") {
		t.Error("the original no longer invokes whatweb: row 2 says we do not " +
			"add it because the original shells out to it")
	}
}

// TestTheCveLookupStillHitsOsv — рядок 3.
func TestTheCveLookupStillHitsOsv(t *testing.T) {
	dir := openvulnDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "services", "cve_service.py"))
	if err != nil {
		t.Fatalf("read cve_service.py: %v", err)
	}
	if !strings.Contains(string(raw), "api.osv.dev") {
		t.Error("the original no longer queries api.osv.dev: row 3 claims the " +
			"gap on our side is that we make no live CVE request at all")
	}
}

// TestWeHaveNoSiemAndNoOsv — рядки 3 і 4.
//
// Дві відсутності, на яких стоять ці рядки. Якщо ми додамо SIEM або живий
// CVE-запит, ці рядки треба перечитати — і перевірка це покаже.
func TestWeHaveNoSiemAndNoOsv(t *testing.T) {
	tree := openvulnOurTree(t)
	lower := strings.ToLower(tree)

	for _, token := range []string{"send_syslog_message", "syslog", "splunk", "api.osv.dev"} {
		for _, line := range strings.Split(lower, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, token) {
				t.Errorf("our code now mentions %q: %s\nrows 3 and 4 say this is "+
					"absent from our project", token, trimmed)
			}
		}
	}
}

// TestCeleryIsOursButOffByDefault — рядок 6, найтонший випадок.
//
// `не перенесено` тут означає «**є, але вимкнено свідомо**», а не «відсутнє».
// Тому перевірка двостороння:
//
//   - `WORKFLOW_CELERY_ENABLED` мусить лишатися в нашому Django-коді;
//   - реєстр мусить пояснювати, чому його не вмикають.
//
// Якщо прапорця зникне, рядок 6 перестане бути «вимкнено свідомо» і стане
// звичайним `не перенесено`.
func TestCeleryIsOursButOffByDefault(t *testing.T) {
	tree := openvulnOurTree(t)
	if !strings.Contains(tree, "WORKFLOW_CELERY_ENABLED") {
		t.Error("WORKFLOW_CELERY_ENABLED is gone from our code: row 6 says the " +
			"broker path exists and is deliberately off by default, and the " +
			"flag that decides it no longer exists")
	}

	raw, err := os.ReadFile(openvulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", openvulnRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "вимкнено") && !strings.Contains(text, "не піднімається") {
		t.Error("the registry does not say Celery is switched off on purpose: " +
			"without that, row 6 reads as a missing capability and a reader " +
			"would advise enabling a flag AGENTS.md forbids enabling")
	}
}

// TestTheRegistryStillCallsItAPlatformNotAScanner.
func TestTheRegistryStillCallsItAPlatformNotAScanner(t *testing.T) {
	raw, err := os.ReadFile(openvulnRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", openvulnRegistry, err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "керування вразливостями") &&
		!strings.Contains(text, "платформа") {
		t.Error("the registry never calls it a vulnerability-management " +
			"platform: a reader would take it for another scanner, which is " +
			"exactly the wrong reading")
	}
}
