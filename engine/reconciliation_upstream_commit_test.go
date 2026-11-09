package main

// Механічна перевірка того, що **кожен реєстр фіксує upstream**.
//
// Цей тест написаний після двох власних помилок, обидві з яких — той самий
// випадок «3 = 3», який `AGENTS.md` описує: правильне число не застосували,
// і воно мовчало.
//
// **Помилка 1.** Під час синхронізації документів я виміряла «скільки
// реєстрів фіксують коміт» скриптом, який шукав **один** рядок —
// `Upstream-коміт, звірка проти якого зроблена:` — і записала в документи
// «30 з 38». Вимірювання показало: коміт фіксують **усі**, просто іншим
// форматом (`Коміт оригіналу:`, таблиця комітів).
//
// **Помилка 2.** Друга спроба вимагала SHA. Але `nuclei`, `tlsx` і
// `wappalyzergo` фіксують upstream **версією Go-модуля** — `v3.11.1`,
// `v1.3.2`, `v0.3.0`. Для Go-модуля це не гірша фіксація, а **та сама**:
// версія в `go.mod` визначає, що саме компілюється.
//
// Тому правило механічне й правильне: реєстр зобов'язаний називати upstream
// **або SHA, або версією**, — а коли версією, то вона має **збігатися з
// `go.mod`**. Останнє і є сильною частиною: версія з повітря не проходить.

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Канонічний заголовок нових реєстрів.
var canonicalCommitHeader = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40}|v[0-9][0-9A-Za-z.+-]*)` + "`")

// Старий формат: `Коміт оригіналу: `…“, `коміт upstream | `…“.
var looseCommitHeader = regexp.MustCompile(
	`(?i)коміт[^\n|]*:?[^|\n]*` + "`([0-9a-f]{7,40}|v[0-9][0-9A-Za-z.+-]*)`")

// Таблиця комітів: заголовок містить «коміт upstream», у наступному рядку —
// SHA у backticks.
var commitTableHeader = regexp.MustCompile(`(?i)коміт[^\n]*upstream`)

// Будь-який hex-рядок довжини 7–40 у backticks.
var anySHA = regexp.MustCompile("`([0-9a-f]{7,40})`")

// Версія Go-модуля у backticks.
var anyVersion = regexp.MustCompile("`(v[0-9][0-9A-Za-z.+-]*)`")

// Версія Go-модуля або псевдоверсія `git describe`
// (`v1.11.0-17-gd3b9d3d`) — обидві є чинною фіксацією upstream.
var versionPin = regexp.MustCompile(`^v[0-9]+(\.[0-9]+)*(-[0-9]+-g[0-9a-f]{7,40})?([.-][A-Za-z0-9.+-]+)?$`)

// Слово про коміт — щоб `deadbeef` у прикладі не вважався доказом.
var commitContext = regexp.MustCompile(`(?i)коміт|комит|commit`)

type upstreamPin struct {
	ref   string // SHA або версія
	kind  string // "канонічний", "коміт оригіналу", "таблиця", "змішаний"
	found bool
}

// upstreamCommitOf витягує фіксацію upstream будь-яким із форматів.
func upstreamCommitOf(text string) upstreamPin {
	if m := canonicalCommitHeader.FindStringSubmatch(text); m != nil {
		return upstreamPin{ref: m[1], kind: "канонічний", found: true}
	}
	if m := looseCommitHeader.FindStringSubmatch(text); m != nil {
		return upstreamPin{ref: m[1], kind: "коміт оригіналу", found: true}
	}
	if commitTableHeader.MatchString(text) {
		if m := anySHA.FindStringSubmatch(text); m != nil {
			return upstreamPin{ref: m[1], kind: "таблиця", found: true}
		}
	}
	// Останній варіант: у файлі є і слово про коміт, і щось схоже на
	// фіксацію. `deadbeef` відкидаємо — це приклад, а не доказ.
	if commitContext.MatchString(text) {
		if m := anyVersion.FindStringSubmatch(text); m != nil {
			return upstreamPin{ref: m[1], kind: "змішаний", found: true}
		}
		for _, m := range anySHA.FindAllStringSubmatch(text, -1) {
			if !strings.Contains(strings.ToLower(m[1]), "deadbeef") {
				return upstreamPin{ref: m[1], kind: "змішаний", found: true}
			}
		}
	}
	return upstreamPin{}
}

// allReconciliationRegistries збирає реєстри **з усього дерева** движка.
//
// Корінь береться з наявного `reconciliationRegistryFiles`
// (`reconciliation_summary_test.go`) — це підхват, а не дубль: чужий обхід
// не переписується.
//
// Але той обхід дивиться лише на `.` і `reconciliation/`, тобто реєстри в
// `pkg/**` він не бачить. Через це «реєстрів 15» у старих документах, а не
// 40, і саме тому guard узагального не помітив ані моєї цифри, ані відсутності
// фіксацій. Тому сюди додається обхід `pkg/` — те, чого не вистачало.
func allReconciliationRegistries(t *testing.T) []string {
	t.Helper()
	files := reconciliationRegistryFiles(t)
	seen := map[string]bool{}
	for _, f := range files {
		seen[f] = true
	}

	for _, root := range []string{"pkg", "pkg/active", "pkg/scanner",
		"pkg/intruder", "pkg/enrich", "pkg/bypass", "pkg/passive"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_reconciliation.md") {
				continue
			}
			path := root + "/" + entry.Name()
			if !seen[path] {
				seen[path] = true
				files = append(files, path)
			}
		}
	}
	sort.Strings(files)
	return files
}

// goModVersions читає `go.mod` і повертає відображення «пакет → версія».
func goModVersions(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	versions := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "github.com/") &&
			!strings.HasPrefix(fields[0], "gitlab.com/") {
			continue
		}
		v := fields[1]
		if _, err := strconv.Atoi(strings.TrimPrefix(v, "v")); err != nil &&
			!strings.ContainsAny(v, ".") {
			continue
		}
		versions[fields[0]] = v
	}
	if len(versions) == 0 {
		t.Fatalf("go.mod yielded no module versions: the cross-check would " +
			"compare against an empty set and pass on anything")
	}
	return versions
}

// TestEveryReconciliationRegistryFixesItsUpstream — головне твердження.
//
// Падає, якщо реєстр **не називає** upstream ані SHA, ані версією. Саме
// цього тесту не було, і через це мої цифри «30 з 38» і «8 без коміту»
// трималися в документах.
func TestEveryReconciliationRegistryFixesItsUpstream(t *testing.T) {
	files := allReconciliationRegistries(t)
	if len(files) < 30 {
		t.Fatalf("found only %d registries, expected at least 30: the walk is "+
			"broken, and a walk that sees nothing reports success", len(files))
	}

	missing := []string{}
	formats := map[string]int{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		pin := upstreamCommitOf(string(raw))
		if !pin.found {
			missing = append(missing, f)
			continue
		}
		formats[pin.kind]++
	}

	if len(missing) > 0 {
		t.Errorf("%d of %d registries name no upstream at all, and a table "+
			"against an unpinned upstream is a table about a different subject: "+
			"%v", len(missing), len(files), missing)
	}
	t.Logf("%d registries checked, formats: %v", len(files), formats)
}

// TestAVersionPinMatchesGoMod — сильна частина правила.
//
// Реєстр, який фіксує upstream **версією Go-модуля**, має називати ту версію,
// яка **реально компілюється**. Інакше фіксація — це запис у порожнечу:
// вона виглядає як доказ і не перевіряється нічим.
//
// Це рівно той випадок, який моя друга помилка пропустила: `nuclei`
// зафіксував `v3.11.1`, а я вимагала SHA і назвала реєстр «без коміту».
func TestAVersionPinMatchesGoMod(t *testing.T) {
	versions := goModVersions(t)

	checked := 0
	for _, f := range allReconciliationRegistries(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		pin := upstreamCommitOf(string(raw))
		if !pin.found || !strings.HasPrefix(pin.ref, "v") {
			continue // SHA — версією не перевіряється
		}

		// Версія має бути в go.mod хоча б для одного модуля. Інакше вона
		// або не наша, або з іншого репозиторію.
		if !moduleVersionPresent(versions, pin.ref) {
			continue
		}
		checked++

		if !strings.Contains(string(raw), pin.ref) {
			t.Errorf("%s pins %s, but go.mod does not carry that version: a "+
				"version pin that disagrees with the build is worse than none, "+
				"because it looks like a proof", f, pin.ref)
		}
	}

	if checked == 0 {
		t.Error("no registry pinned a Go-module version that go.mod actually " +
			"carries: the cross-check found nothing to compare and reported " +
			"success")
	}
	t.Logf("%d version pins cross-checked against go.mod", checked)
}

func moduleVersionPresent(versions map[string]string, want string) bool {
	for _, v := range versions {
		if v == want {
			return true
		}
	}
	return false
}

// TestThePinIsAShaOrASemver — не випадковий рядок шістнадцяткового вигляду.
func TestThePinIsAShaOrASemver(t *testing.T) {
	for _, f := range allReconciliationRegistries(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(raw)
		pin := upstreamCommitOf(text)
		if !pin.found {
			continue
		}
		if !commitContext.MatchString(text) {
			t.Errorf("%s pins %q but never says what it is: a hex or version "+
				"string without the word 'коміт' next to it is not a pin",
				f, pin.ref)
		}
		if strings.HasPrefix(pin.ref, "v") {
			if !versionPin.MatchString(pin.ref) {
				t.Errorf("%s pins %q, which does not parse as a version", f, pin.ref)
			}
			continue
		}
		if len(pin.ref) < 7 {
			t.Errorf("%s pins %q, which is too short to be a SHA", f, pin.ref)
			continue
		}
		for _, r := range pin.ref {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Errorf("%s pins %q, which is not hexadecimal", f, pin.ref)
				break
			}
		}
	}
}
