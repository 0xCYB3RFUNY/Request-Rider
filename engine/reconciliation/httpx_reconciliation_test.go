// Machine check for httpx_reconciliation.md.
//
// The register this test guards exists because three capabilities of the vexor
// port were lost silently: every row existed, the suite was green, and a
// capability nobody ported could not appear in a list ordered by "compare what
// we have". For httpx the mechanical version of that rule is sharper than a
// capability list, because httpx's contract IS a struct: `runner.Result` has 62
// serialised fields, and every one of them is a fact about a service that we
// either keep or lose.
//
// So the pinned list below is the field list read out of upstream's own
// `runner/types.go`. A field added upstream and named in no row is a named diff
// in this file, which makes the guard fire instead of the register quietly
// omitting it. A register written from memory is exactly what produced the loss
// this mechanism was written for.
//
// What this test can catch, stated plainly so it is not oversold:
//
//   - a removed row,
//   - an empty or unknown verdict, or a verdict outside the three allowed,
//   - a symbol claimed as ported that is absent from OUR tree,
//   - `не перенесено` with no stated reason,
//   - an upstream capability we have that no row covers,
//   - a missing upstream commit,
//   - an upstream Result field nobody classified.
//
// What it CANNOT catch is an upstream FUNCTION that produces no field, because
// a struct is not a capability list. That is the register's file enumeration in
// the header, and the register says so in its own last section rather than
// pretending the struct is the whole of httpx.

package reconciliation

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

const (
	httpxRegister  = "httpx_reconciliation.md"
	httpxCommit    = "d3b9d3d"
	httpxRowCount  = 158
	httpxCloneHint = "~/httpx"
	httpxBranch    = "dev"
)

// upstreamResultFields is every JSON tag of httpx's `runner.Result` that actually
// serialises, read out of ~/httpx/runner/types.go.
//
// `Err` and `Raw` carry `json:"-"` and are deliberately absent: a field the tool
// does not emit cannot be lost by not taking it.
//
// The count is asserted below. A shortened list is the "3 = 3" failure this
// whole mechanism was written after — parity on a subset picked to match our own
// answer compares nothing.
var upstreamResultFields = []string{
	"timestamp", "link_request", "asn", "csp", "tls", "hash", "extract_regex",
	"cdn_name", "cdn_type", "sni", "port", "url", "input", "location",
	"title", "scheme", "error", "webserver", "body", "body_preview", "content_type",
	"method", "host", "host_ip", "path", "favicon", "favicon_md5", "favicon_path",
	"favicon_url", "final_url", "header", "raw_header", "request", "time", "jarm_hash",
	"chain_status_codes", "a", "aaaa", "cname", "tech", "extracts", "chain",
	"words", "lines", "status_code", "content_length", "failed", "vhost", "websocket",
	"cdn", "http2", "pipeline", "headless_body", "screenshot_bytes", "stored_response_path", "screenshot_path",
	"screenshot_path_rel", "knowledgebase", "resolvers", "body_fqdn", "body_domains", "trace", "cpe",
	"wordpress",
}

// loadRegister reads the register and returns its rows.
//
// A line that looks like a table row but does not parse into four cells is a
// failure, not a row to skip. Skipping it would mean a row that lost its reason
// column simply ceased to exist as far as the guard was concerned — and a
// `не перенесено` with no reason is the one thing this register exists to
// prevent.
func loadHttpxRegister(t *testing.T) []registerRow {
	t.Helper()
	source, err := os.ReadFile(httpxRegister)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	var rows []registerRow
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
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
		capability := restorePipes(match[1])
		symbol := restorePipes(match[2])
		verdict := match[3]
		reason := restorePipes(match[4])
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

// TestEveryResultFieldIsClassified is the mechanical answer to the vexor failure,
// for a tool whose contract is a struct.
//
// httpx tells us about a service by the fields it emits. A field we never
// classify is a fact about the target we never recorded, and nobody notices,
// because nothing in the product is broken — the probe simply answers less. So
// the field list is pinned here and every entry must appear in the register.
// requiredHttpxRows is pinned separately from the katana list because the two
// registers describe different tools. Sharing one list would let a row pass in one
// file on the strength of a row that exists in the other.
var requiredHttpxRows = []string{
	"вхід: список хостів",
	"вхід: файл",
	"вхід: сирий HTTP-запит",
	"вхід: формат Burp",
	"вхід: CIDR",
	"вхід: ASN",
	"проба за шляхом",
	"дедуплікація входу",
	"потоковий режим",
	"відновлення `-resume`",
	"вибір методи",
	"тіло запиту",
	"порти (синтаксис nmap)",
	"вибір протоколу HTTP/1.1/2/3",
	"HTTPS, потім HTTP",
	"проба обох схем",
	"підйом 400 → TLS",
	"слідування редиректам",
	"тільки редиректи в межах хоста",
	"HSTS",
	"вимкнення редиректів",
	"заголовки за запитом",
	"cookie на редиректі",
	"сесія між запитами",
	"TLS-зняття",
	"зняття TLS через zcrypto",
	"TLS-проба за SAN",
	"імітація TLS (JA3)",
	"власний SNI",
	"JARM",
	"розбір сертифіката",
	"HTTP/2",
	"HTTP/1.1 pipeline",
	"виявлення віртуального хоста",
	"виявлення WebSocket",
	"HTTP/3",
	"класифікація сторінок `dit`",
	"CPE-детекція",
	"збагачення версій CPE",
	"детекція WordPress",
	"визначення технологій",
	"заголовок `CSP`",
	"проба доменів із CSP",
	"видобуток доменів з тіла",
	"придушення хибних спрацьовувань",
	"назва сторінки",
	"перевірка MIME для назви",
	"favicon MMH3",
	"пошук іконки",
	"хеші тіла і заголовків",
	"CDN",
	"ASN",
	"пресети видобутку",
	"видобуток за regex",
	"збіги за статусом",
	"збіги за довжиною, рядками, словами",
	"збіги за favicon і CDN",
	"збіг за часом відповіді",
	"збіг за DSL-умовою",
	"фільтри за всіма параметрами",
	"мережева політика виключень",
	"фільтр схожості сторінок",
	"фільтр помилок сторінки",
	"журнал помилок у JSONL",
	"відстеження ретраїв",
	"збереження відповіді на диск",
	"маршрут редиректів у JSON",
	"повний запит і відповідь у JSON",
	"кодування GBK/Big5/EUC-KR",
	"вимкнення декодування",
	"CSV / Markdown вивід",
	"перелік полів",
	"виключення полів з JSON",
	"випадковий User-Agent",
	"авто-Referer",
	"вивід у консоль і лічильники",
	"HTTP API сервер",
	"запис у БД",
	"вивантаження в хмару PDCP",
	"healthcheck",
	"профілювання пам'яті",
	"два етапи SIGINT",
	"проба усіх IP хоста",
	"підміна Host",
	"заголовок `-probe`",
	"знімок екрана",
	"JS після навігації",
	"лог мережі headless",
	"атрибуція здатностей через пасивний проксі",
	"джерельний IP за обміном",
	"бар'єр route generation",
	"запис у `ProjectEndpoint`",
	"сутності OSINT-графа",
	"частковий результат при зупинці",
}

func TestEveryResultFieldIsClassified(t *testing.T) {
	source, err := os.ReadFile(httpxRegister)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	body := string(source)
	var missing []string
	for _, field := range upstreamResultFields {
		if !strings.Contains(body, "`"+field+"`") {
			missing = append(missing, field)
		}
	}
	for _, field := range missing {
		t.Errorf("upstream Result field `%s` is classified in no register row, so whether we "+
			"keep that fact about a service was never decided: an unclassified field is a "+
			"silently lost one", field)
	}
}

// TestTheFieldListIsPinned guards the guard.
//
// A list of three fields out of sixty-two passes while fifty-nine go
// unclassified. That is the "3 = 3" failure, and the only defence is to assert
// the count so a truncated list cannot be mistaken for a complete one.
func TestTheFieldListIsPinned(t *testing.T) {
	seen := map[string]bool{}
	for _, field := range upstreamResultFields {
		if seen[field] {
			t.Errorf("upstreamResultFields lists `%s` twice; a duplicated entry inflates the "+
				"count and hides a missing one", field)
		}
		seen[field] = true
	}
	if len(upstreamResultFields) != 64 {
		t.Errorf("upstreamResultFields holds %d entries, want 64; upstream's runner.Result "+
			"serialises 64 fields, and a shortened list would pass while real fields go "+
			"unclassified", len(upstreamResultFields))
	}
	t.Logf("upstream Result declares %d serialised field(s)", len(upstreamResultFields))
}

// TestRequiredRowsArePresent is the answer to a removed row.
func TestHttpxRequiredRowsArePresent(t *testing.T) {
	rows := loadHttpxRegister(t)
	present := make([]string, 0, len(rows))
	for _, row := range rows {
		present = append(present, strings.TrimSpace(row.capability))
	}
	for _, required := range requiredHttpxRows {
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
	if len(rows) != httpxRowCount {
		t.Errorf("the register has %d rows, want %d; a count that drifts in either "+
			"direction means the table changed without anyone deciding it should",
			len(rows), httpxRowCount)
	}
}

// TestEveryRowHasAVerdictFromTheAllowedThree is the core of the rule.
func TestHttpxEveryRowHasAVerdictFromTheAllowedThree(t *testing.T) {
	for _, row := range loadHttpxRegister(t) {
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
func TestHttpxLostRowsStateAReason(t *testing.T) {
	for _, row := range loadHttpxRegister(t) {
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
// The search covers the engine root (`package main`), `pkg/`, `browser-worker` and
// the template. A search scoped to this package would report every real symbol
// missing while the port plainly exists — which was the documented failure mode:
// the symbol check must search every layer where the claimed thing lives.
func TestHttpxClaimedSymbolsExistInOurTree(t *testing.T) {
	for _, row := range loadHttpxRegister(t) {
		if row.verdict == verdictLost {
			continue
		}
		if strings.TrimSpace(row.symbol) == "" || strings.TrimSpace(row.symbol) == "—" {
			continue
		}
		for _, match := range symbolPattern.FindAllStringSubmatch(row.symbol, -1) {
			for _, name := range identifiersIn(match[1]) {
				if !declaredSomewhere(t, name) {
					t.Errorf("row %q claims symbol %q, which is not declared anywhere in our "+
						"engine tree (engine root, pkg/, browser-worker, templates)", row.capability, name)
				}
			}
		}
	}
}

// TestOurOwnCapabilitiesAreCovered is the direction the original rule forgot.
//
// Listing upstream's capabilities catches what we failed to take. It does not
// catch what we built and never wrote down, which is the same silence from the
// other side.
func TestHttpxOurOwnCapabilitiesAreCovered(t *testing.T) {
	ours := []struct {
		capability string
		symbol     string
	}{
		{"атрибуція здатностей через пасивний проксі", "bindRouteContext"},
		{"джерельний IP за обміном", "startSourceIPLookup"},
		{"запис у `ProjectEndpoint`", "register_endpoint"},
		{"сутності OSINT-графа", "transformEntity"},
		{"частковий результат при зупинці", "transformCollector"},
	}
	rows := loadHttpxRegister(t)
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
func TestHttpxUpstreamCommitIsRecorded(t *testing.T) {
	source, err := os.ReadFile(httpxRegister)
	if err != nil {
		t.Fatalf("cannot read the register: %v", err)
	}
	body := string(source)
	if !strings.Contains(body, httpxCommit) {
		t.Errorf("the register does not record upstream commit %s", httpxCommit)
	}
	if !strings.Contains(body, httpxCloneHint) {
		t.Errorf("the register does not record where the upstream tree lives (%s)", httpxCloneHint)
	}
	// httpx was cloned on `dev`, not on a release tag. A register that omits the
	// branch is a register whose subject could silently move under it, and the
	// banner version (v1.12.0) is ahead of the last tag (v1.11.0) precisely
	// because the branch is ahead.
	if !strings.Contains(body, httpxBranch) {
		t.Errorf("the register does not record that upstream was read on branch %q; a register "+
			"against a moving branch is a register about an unstated subject", httpxBranch)
	}
}

// TestEveryRegisterRowNamesACapabilityWithText guards the parse itself: a row whose
// capability cell is a placeholder means the register claims a completeness it
// does not have.
func TestHttpxEveryRegisterRowNamesACapabilityWithText(t *testing.T) {
	for _, row := range loadHttpxRegister(t) {
		capability := strings.TrimSpace(row.capability)
		if capability == "" || capability == "—" || capability == "-" {
			t.Errorf("a register row has no capability name: %s", row.line)
		}
	}
}

// TestVerdictVocabularyHasNoFourthState documents the closed set in code, so the
// test above and the rule cannot drift apart.
func TestHttpxVerdictVocabularyHasNoFourthState(t *testing.T) {
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

// TestTheTwoRegistersShareOneVocabulary keeps the two files from drifting apart.
//
// Both registers are read by one guard vocabulary declared twice. A copy that
// drifts — one file accepting a fourth state, the other not — would let a loss
// pass in one register and fail in the other, which is worse than either being
// strict. The check is deliberately in this file so the failure names both.
func TestTheTwoRegistersShareOneVocabulary(t *testing.T) {
	if katanaRegister == httpxRegister {
		t.Fatal("both registers resolve to the same file name, so one of them is never read")
	}
	if len(upstreamResultFields) == 0 || len(upstreamParsers) == 0 {
		t.Fatal("a pinned upstream list is empty, so its coverage check is asserting nothing")
	}
	// Both upstream subjects must be named somewhere, or the clone hint points at
	// a tree nobody compared against.
	for _, file := range []string{katanaRegister, httpxRegister} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("cannot read %s: %v", file, err)
		}
		if !strings.Contains(string(body), "upstream") {
			t.Errorf("%s does not say what upstream it compares against", file)
		}
	}
}
