package main

// Tests for `breach_exposure` — the three breach lookups ported from
// `ibnaleem/gosearch` at commit `687f9ed`.
//
// The defects these cover are not hypothetical. Each one was read out of the
// original's source before this file was written:
//
//   - proxynova.go:57 split on ":" and kept the pair only when there were
//     **exactly** two parts, so a password containing a colon was dropped;
//   - breachdirectory.go:45-51 printed the weakpass answer **instead of** the
//     entry's own password, so an entry that already carried a readable password
//     lost it whenever weakpass also answered;
//   - breachdirectory.go:44 called weakpass once per entry, so one credential
//     in forty sources cost forty identical requests;
//   - breachdirectory.go:23,28 used `log.Fatal` inside a goroutine, which kills
//     the host process, not the failing request;
//   - not one of the three modules set a timeout, so a hung upstream hung the
//     process for good.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// breachFixture is the three upstream answers gosearch would have read, on one
// server, so all three paths are exercised against the same bytes.
//
// The values are real in shape and absent from any placeholder list, because a
// fixture made of `example.com` measures our own filtering rather than our
// coverage — the failure mode the porting rule in AGENTS.md names by name.
type breachFixture struct {
	proxynovaBody  string
	directoryBody  string
	weakpassByHash map[string]string

	mu              sync.Mutex
	weakpassAsked   []string
	directoryAsked  []string
	proxynovaAsked  []string
	directoryStatus int
}

func (fixture *breachFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/comb", func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.proxynovaAsked = append(fixture.proxynovaAsked, r.URL.Query().Get("query"))
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, fixture.proxynovaBody)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/search/") {
			hash := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/search/"), ".json")
			fixture.mu.Lock()
			fixture.weakpassAsked = append(fixture.weakpassAsked, hash)
			password, ok := fixture.weakpassByHash[strings.ToLower(hash)]
			fixture.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if !ok {
				fmt.Fprint(w, `{"type":"hash","hash":"`+hash+`","pass":""}`)
				return
			}
			fmt.Fprintf(w, `{"type":"hash","hash":%q,"pass":%q}`, hash, password)
			return
		}
		fixture.mu.Lock()
		fixture.directoryAsked = append(fixture.directoryAsked, r.URL.Query().Get("term"))
		status := fixture.directoryStatus
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"message":"unauthorized"}`)
			return
		}
		fmt.Fprint(w, fixture.directoryBody)
	})
	return mux
}

// serve points the three endpoints at one fixture server and restores them.
func (fixture *breachFixture) serve(t *testing.T) {
	t.Helper()
	served := httptest.NewServer(fixture.handler(t))
	previous := []string{breachProxyNovaEndpoint, breachDirectoryEndpoint, breachWeakpassEndpointPrefix}
	breachProxyNovaEndpoint = served.URL + "/comb"
	breachDirectoryEndpoint = served.URL + "/"
	breachWeakpassEndpointPrefix = served.URL + "/search/"
	t.Cleanup(func() {
		breachProxyNovaEndpoint, breachDirectoryEndpoint, breachWeakpassEndpointPrefix = previous[0], previous[1], previous[2]
		served.Close()
	})
}

func (fixture *breachFixture) counts() (weakpass, directory, proxynova int) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return len(fixture.weakpassAsked), len(fixture.directoryAsked), len(fixture.proxynovaAsked)
}

// runFixture drives the transform against the fixture with the directory key
// present, which is the full three-source path.
func runFixture(t *testing.T, fixture *breachFixture, value string, options map[string]interface{}) *osintTransformResult {
	t.Helper()
	fixture.serve(t)
	t.Setenv(breachExposureAPIKeyEnv, "fixture-key")
	server := &server{}
	input := osintTransformInput{
		Transform:      "breach_exposure",
		Value:          value,
		Options:        options,
		ConfirmNetwork: true,
	}
	result, err := server.runOSINTTransformWithCollector(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("breach_exposure returned %v", err)
	}
	return &result
}

// TestBreachExposureRelatesEveryFindingToTheQuery: граф має відповісти на
// запитання, яке поставили. Живий прогін 2026-10-07 на ProxyNova дав 20 знахідок
// для одного запиту — і без ребра `exposed_in_breach` між адресою, про яку
// запитали, і знахідками результат був набором облікових даних, до яких не
// приєднано нічого: двадцять вузлів без жодного зв'язку з питанням.
func TestBreachExposureRelatesEveryFindingToTheQuery(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":3,"lines":["found.one@yandex.ru:Summer2018","found.two@yandex.ru:p:a:ss","found.three@yandex.ru:Autumn2020"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "someone", nil)

	if len(result.Relations) != 3 {
		t.Fatalf("got %d relations, want one per finding: %+v", len(result.Relations), result.Relations)
	}
	for _, relation := range result.Relations {
		if relation.Type != "exposed_in_breach" {
			t.Errorf("relation type %q, want exposed_in_breach", relation.Type)
		}
		if relation.SourceType != "username" || relation.Source != "someone" {
			t.Errorf("relation source %s/%s, want username/someone — the identity that was queried",
				relation.SourceType, relation.Source)
		}
		if relation.TargetType != "email" {
			t.Errorf("relation target type %q, want email", relation.TargetType)
		}
	}
	// The relation carries the credential, so the edge is usable on its own.
	if result.Relations[0].Properties["credential"] == nil {
		t.Error("the relation carries no credential; an edge that needs a second lookup is a lookup that will not happen")
	}
}

// TestBreachExposureDoesNotWriteASelfRelation: знахідка з тією самою адресою, що й
// запит, не створює ребро в саму себе. Рендерер кожен такий edge малює, читач
// його не використовує.
func TestBreachExposureDoesNotWriteASelfRelation(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "leaked.user@yandex.ru", nil)

	for _, relation := range result.Relations {
		if relation.Source == relation.Target {
			t.Errorf("the run wrote a self-relation %s → %s", relation.Source, relation.Target)
		}
	}
	// The query is still recorded, so the run says what it asked about — but on
	// the finding that already claims the address, not as a second node at the
	// same identity. Two nodes at one address are one node drawn twice.
	for _, item := range result.Entities {
		if item.Properties["kind"] == "queried_identity" {
			t.Error("the query was written as a separate node at an identity a finding already claims")
		}
		if item.Identity == "leaked.user@yandex.ru" && item.Properties["queried_for"] == nil {
			t.Error("the finding that is the queried identity does not record that it was the query")
		}
	}
	var matching int
	for _, item := range result.Entities {
		if item.Identity == "leaked.user@yandex.ru" {
			matching++
		}
	}
	if matching != 1 {
		t.Errorf("%d nodes share the identity leaked.user@yandex.ru, want exactly 1", matching)
	}
}

// TestBreachExposureWritesTheQueriedIdentityWhenNothingClaimsIt: запит, який нічого
// не знайшов, все одно має бути видимим. Інакше в графі немає ні вузла, ні ребра,
// і запис про «джерела відповіли, знахідок немає» висить у warnings без вузла,
// до якого він належить.
func TestBreachExposureWritesTheQueriedIdentityWhenNothingClaimsIt(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":0,"lines":[]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "clean.user@yandex.ru", nil)

	var queried bool
	for _, item := range result.Entities {
		if item.Properties["kind"] == "queried_identity" {
			queried = item.Type == "email" && item.Identity == "clean.user@yandex.ru"
		}
	}
	if !queried {
		t.Errorf("a run that found nothing left no node for the identity it queried: %v",
			breachSummarise(result))
	}
}

// TestBreachExposureIdentifiesEachFindingByItsAddress: сутність має ключем мати
// адресу, а не хеш. Живий прогін 2026-10-07 дав 20 знахідок, які без
// адреси-identity усі мали б одну й ту саму identity — граф показав би один вузол
// двадцять разів, а адреса лишалася б властивістю.
func TestBreachExposureIdentifiesEachFindingByItsAddress(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":2,"lines":["one@yandex.ru:pw-one","two@yandex.ru:pw-two"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "someone", nil)

	identities := map[string]bool{}
	for _, item := range result.Entities {
		identities[item.Identity] = true
	}
	for _, want := range []string{"one@yandex.ru", "two@yandex.ru"} {
		if !identities[want] {
			t.Errorf("no entity is identified by %s; identities present: %v", want, identities)
		}
	}
}

// TestBreachExposureReadsAllThreeAnswers is the port's central claim: the three
// sources gosearch ran are three reads here, and both of their payload fields
// arrive.
func TestBreachExposureReadsAllThreeAnswers(t *testing.T) {
	const sha1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	fixture := &breachFixture{
		proxynovaBody: `{"count":2,"lines":["leaked.user@yandex.ru:Summer2018","second.user@yandex.ru:p:a:ss:word"]}`,
		directoryBody: `{"found":1,"result":[{"email":"leaked.user@yandex.ru","password":"Winter2019","sha1":"` + sha1 + `","sources":"Telegram; Yahoo"}]}`,
		weakpassByHash: map[string]string{
			sha1: "Summer2018",
		},
	}
	result := runFixture(t, fixture, "leaked.user@yandex.ru", nil)

	weakpass, directory, proxynova := fixture.counts()
	if proxynova != 1 {
		t.Errorf("ProxyNova was asked %d times, want exactly 1", proxynova)
	}
	if directory != 1 {
		t.Errorf("BreachDirectory was asked %d times, want exactly 1", directory)
	}
	// The chain: one hash came back, so weakpass is asked once. The original
	// asked it once per entry, which for a single entry happens to be the same —
	// TestBreachExposureAsksWeakpassOncePerDistinctHash is the one that pins it.
	if weakpass != 1 {
		t.Errorf("weakpass was asked %d times for one hash, want 1", weakpass)
	}

	// Two addresses, not three findings: `leaked.user@yandex.ru` came from both
	// sources, and one identity is one node however many sources reported it. The
	// third finding is counted in the metadata and carried in the node's
	// `credentials` list, which is where a second password has to live.
	if breachFindings(result) != 2 {
		t.Fatalf("got %d credential nodes, want 2 (leaked.user@yandex.ru from two sources, second.user from one): %v",
			breachFindings(result), breachSummarise(result))
	}
	breachCheckMetadata(t, result, 3)
	if got := breachCredentialCount(result); got != 3 {
		t.Errorf("the nodes carry %d credentials, want all 3 findings — grouping must not drop one", got)
	}
	if result.LocalOnly || !result.NetworkUsed {
		t.Error("a run that asked three third parties cannot report local_only")
	}

	// The ProxyNova line with two colons in the password is the case the
	// original dropped: `strings.Split` gave three parts, `len(parts) == 2` was
	// false, and the credential was never printed.
	passwords := breachPasswords(result)
	for _, want := range []string{"Summer2018", "p:a:ss:word", "Winter2019"} {
		if !breachHasPassword(passwords, want) {
			t.Errorf("password %q is missing from the run; the three answers were not fully read: %v",
				want, passwords)
		}
	}

	// And the source list the original printed but never put on an entity.
	var sources string
	for _, item := range result.Entities {
		rows, _ := item.Properties["credentials"].([]map[string]interface{})
		for _, row := range rows {
			if row["breach_sources"] != nil {
				sources = fmt.Sprint(row["breach_sources"])
			}
		}
	}
	if sources != "Telegram; Yahoo" {
		t.Errorf("breach_sources = %q, want %q", sources, "Telegram; Yahoo")
	}
}

// TestBreachExposureKeepsEveryPasswordForOneAddress — дефект, знайдений живим
// прогоном 2026-10-07. ProxyNova відповів двома рядками для однієї адреси з
// **різними** паролями (`200804` і `200804al3xis`) і двома рядками з однаковим.
// Один вузол на адресу — правильна форма, але тоді список `credentials` є єдиним
// місцем, де другий пароль може жити: якщо його немає, він втрачено мовчки, а
// лічильник знахідок цього не показує.
// TestBreachExposureKeepsEveryRowTheSourceSent — дефект, знайдений живим
// прогоном 2026-10-07 і виправлений за вимогою оператора. ProxyNova відповів
// двома рядками для однієї адреси з **різними** паролями (`200804` і
// `200804al3xis`) і двома рядками з **однаковим**. Перша версія зливала
// ідентичні рядки й повідомляла 19 замість 20 — менше, ніж надрукував
// оригінал, без жодного рядка про те, що фільтр з'їв дані. Тепер зберігається
// **кожен** рядок, а число різних публікується окремо.
func TestBreachExposureKeepsEveryRowTheSourceSent(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":4,"lines":["al3xis@pravda.ru:200804","al3xis@pravda.ru:200804al3xis","akkord@pravda.ru:69d67e","akkord@pravda.ru:69d67e"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "someone", nil)

	// Two addresses — one node each — carrying all four rows between them.
	if breachFindings(result) != 2 {
		t.Fatalf("got %d credential nodes, want 2: %v", breachFindings(result), breachSummarise(result))
	}
	if got := breachCredentialCount(result); got != 4 {
		t.Errorf("the nodes carry %d credentials, want all 4 rows the source sent", got)
	}

	// `findings` is what the source sent; `distinct_findings` is the same data
	// with repeats removed. Both are published, because reporting only the smaller
	// one would look like a filter had eaten rows.
	breachCheckMetadata(t, result, 4)
	if result.Metadata["distinct_findings"] != 3 {
		t.Errorf("distinct_findings = %v, want 3 — two of the four rows are identical",
			result.Metadata["distinct_findings"])
	}
	if result.Metadata["identities"] != 2 {
		t.Errorf("identities = %v, want 2", result.Metadata["identities"])
	}

	for _, item := range breachCredentialEntities(result) {
		rows, ok := item.Properties["credentials"].([]map[string]interface{})
		if !ok {
			t.Fatalf("%s carries no credentials list", item.Identity)
		}
		switch item.Identity {
		case "al3xis@pravda.ru":
			if len(rows) != 2 {
				t.Errorf("al3xis@pravda.ru carries %d credentials, want both passwords", len(rows))
			}
			if item.Properties["distinct_credential_count"] != 2 {
				t.Errorf("distinct_credential_count = %v, want 2", item.Properties["distinct_credential_count"])
			}
			// The scalars stay: the operator must see a password and a hash
			// without opening a list, and the counts beside them say the field is
			// the first of several rather than the only one.
			if item.Properties["password"] == nil || item.Properties["sha1"] == nil {
				t.Error("a node with two credentials names neither `password` nor `sha1` in the scalars")
			}
			if !breachHasPassword(breachPasswords(result), "200804") ||
				!breachHasPassword(breachPasswords(result), "200804al3xis") {
				t.Error("one of the two passwords for al3xis@pravda.ru is missing from the run")
			}
		case "akkord@pravda.ru":
			// The identical repeat is **kept** — that is the point — and reported
			// as a repeat rather than hidden.
			if len(rows) != 2 {
				t.Errorf("akkord@pravda.ru carries %d credentials, want both identical rows", len(rows))
			}
			if item.Properties["distinct_credential_count"] != 1 {
				t.Errorf("distinct_credential_count = %v, want 1", item.Properties["distinct_credential_count"])
			}
			sources, _ := item.Properties["reporting_sources"].([]string)
			if len(sources) != 1 || sources[0] != "proxynova" {
				t.Errorf("reporting_sources = %v, want the one source that reported it", sources)
			}
		}
	}
}
func TestBreachExposureKeepsBothPasswords(t *testing.T) {
	const sha1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	fixture := &breachFixture{
		proxynovaBody: `{"count":0,"lines":[]}`,
		directoryBody: `{"found":1,"result":[{"email":"svc.admin@yandex.ru","password":"Winter2019","sha1":"` + sha1 + `","sources":"Telegram"}]}`,
		weakpassByHash: map[string]string{
			sha1: "Summer2018",
		},
	}
	result := runFixture(t, fixture, "svc.admin@yandex.ru", nil)

	if breachFindings(result) != 1 {
		t.Fatalf("got %d credentials, want 1: %v", breachFindings(result), breachSummarise(result))
	}
	breachCheckMetadata(t, result, 1)
	properties := breachCredentialEntities(result)[0].Properties
	if properties["password"] != "Winter2019" {
		t.Errorf("password = %v, want the entry's own %q; the crack overwrote it",
			properties["password"], "Winter2019")
	}
	if properties["password_from_weakpass"] != false {
		t.Error("an entry whose own password was kept must not be marked as cracked by weakpass")
	}
}

// TestBreachExposureFillsAnEmptyPasswordFromTheCrack is the other half: where the
// entry carried no password, the crack is the answer and it must be labelled as
// coming from weakpass, because those are different kinds of evidence.
func TestBreachExposureFillsAnEmptyPasswordFromTheCrack(t *testing.T) {
	const sha1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	fixture := &breachFixture{
		proxynovaBody: `{"count":0,"lines":[]}`,
		directoryBody: `{"found":1,"result":[{"email":"svc.admin@yandex.ru","password":"","sha1":"` + sha1 + `","sources":"Telegram"}]}`,
		weakpassByHash: map[string]string{
			sha1: "Summer2018",
		},
	}
	result := runFixture(t, fixture, "svc.admin@yandex.ru", nil)

	if breachFindings(result) != 1 {
		t.Fatalf("got %d credentials, want 1", breachFindings(result))
	}
	properties := breachCredentialEntities(result)[0].Properties
	if properties["password"] != "Summer2018" {
		t.Errorf("password = %v, want the cracked %q", properties["password"], "Summer2018")
	}
	if properties["password_from_weakpass"] != true {
		t.Error("a password that came from weakpass must be marked as such")
	}
}

// TestBreachExposureAsksWeakpassOncePerDistinctHash is the third defect: the
// original called weakpass once per entry, so one credential reported against
// forty sources cost forty identical requests to a free third party. Distinct
// hashes are asked once; the count is measured, not asserted from a comment.
func TestBreachExposureAsksWeakpassOncePerDistinctHash(t *testing.T) {
	const repeated = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	entries := make([]string, 0, 12)
	for _, source := range []string{"Telegram", "Yahoo", "Adobe", "Dropbox", "Canva", "Spotify",
		"Netflix", "GitHub", "Steam", "Twitter", "Reddit", "MyFitnessPal"} {
		entries = append(entries, fmt.Sprintf(
			`{"email":"svc.admin@yandex.ru","password":"","sha1":"%s","sources":%q}`, repeated, source))
	}
	fixture := &breachFixture{
		proxynovaBody:  `{"count":0,"lines":[]}`,
		directoryBody:  `{"found":12,"result":[` + strings.Join(entries, ",") + `]}`,
		weakpassByHash: map[string]string{repeated: "Summer2018"},
	}
	result := runFixture(t, fixture, "svc.admin@yandex.ru", nil)

	weakpass, _, _ := fixture.counts()
	if weakpass != 1 {
		t.Errorf("weakpass was asked %d times for 12 entries sharing one hash; the original made one call per entry", weakpass)
	}
	// Twelve sources, one address: one node. The dedup that matters here is on the
	// *lookup* (weakpass was asked once), not on the findings — the twelve sources
	// are still twelve facts and they all have to be readable.
	if breachFindings(result) != 1 {
		t.Errorf("got %d credential nodes, want 1 — twelve sources for one address are one node", breachFindings(result))
	}
	if got := breachCredentialCount(result); got != 12 {
		t.Errorf("the node carries %d credentials, want 12; deduplicating the lookup must not deduplicate the findings", got)
	}
	breachCheckMetadata(t, result, 12)
}

// TestBreachExposureRefusesWithoutTheDirectoryKey is the "a source that did not
// answer is named" rule. A missing key must disable that one source and leave
// the other two working, and it must say so — silence reads as "no breaches".
func TestBreachExposureRefusesWithoutTheDirectoryKey(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody: `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody: `{"found":1,"result":[{"email":"leaked.user@yandex.ru","password":"x","sha1":"abc","sources":"Telegram"}]}`,
	}
	fixture.serve(t)
	// An explicitly empty key: the engine must not inherit a developer's shell
	// value by accident.
	t.Setenv(breachExposureAPIKeyEnv, "")

	server := &server{}
	result, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform:      "breach_exposure",
		Value:          "leaked.user@yandex.ru",
		ConfirmNetwork: true,
	}, nil)
	if err != nil {
		t.Fatalf("breach_exposure returned %v", err)
	}

	_, directory, proxynova := fixture.counts()
	if directory != 0 {
		t.Errorf("BreachDirectory was asked %d times without a key", directory)
	}
	if proxynova != 1 {
		t.Errorf("ProxyNova was asked %d times, want 1 — one missing key must not disable the others", proxynova)
	}
	if breachFindings(&result) != 1 {
		t.Fatalf("got %d credentials, want the one ProxyNova finding: %v",
			breachFindings(&result), breachSummarise(&result))
	}

	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, breachExposureAPIKeyEnv) && strings.Contains(warning, "not asked") {
			named = true
		}
	}
	if !named {
		t.Errorf("the skipped source is not named in the warnings: %v", result.Warnings)
	}
}

// TestBreachExposureNamesAFailingSource: a 500 is not "no breaches found". The
// run must say the source failed, because the clean reading is the one an
// operator acts on.
func TestBreachExposureNamesAFailingSource(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:   `{"count":0,"lines":[]}`,
		directoryBody:   `{}`,
		directoryStatus: 429,
		weakpassByHash:  map[string]string{},
	}
	result := runFixture(t, fixture, "leaked.user@yandex.ru", nil)

	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "429") && strings.Contains(warning, "BreachDirectory") {
			named = true
		}
	}
	if !named {
		t.Errorf("the 429 from BreachDirectory is not named in the warnings: %v", result.Warnings)
	}
	if breachFindings(result) != 0 {
		t.Errorf("got %d credentials, want 0", breachFindings(result))
	}
}

// TestBreachExposureAnswersWhenTheRunIsCancelled covers the original's hardest
// failure: not one of the three modules carried a timeout or a context, so a hung
// upstream was a hung process. A cancelled context must end the run.
func TestBreachExposureAnswersWhenTheRunIsCancelled(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-make(chan struct{}):
		}
	}))
	defer hang.Close()
	previousProxyNova := breachProxyNovaEndpoint
	breachProxyNovaEndpoint = hang.URL + "/comb"
	defer func() { breachProxyNovaEndpoint = previousProxyNova }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	server := &server{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := server.runOSINTTransformWithCollector(ctx, osintTransformInput{
			Transform:      "breach_exposure",
			Value:          "leaked.user@yandex.ru",
			Options:        map[string]interface{}{"timeout_ms": 30000},
			ConfirmNetwork: true,
		}, nil)
		if err != nil {
			t.Errorf("a cancelled run returned %v; cancellation is not an error", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled run did not return: the request ignored ctx, which is the original's defect")
	}
}

// TestBreachExposureHonoursTheReadLimitAndPublishesIt: the limit is a default the
// caller can widen, and the number that governed the read is in the metadata —
// a bound nobody can see is the hidden restriction this project forbids.
func TestBreachExposureHonoursTheReadLimitAndPublishesIt(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "leaked.user@yandex.ru", nil)

	if result.Metadata["max_bytes"] != int(breachExposureDefaultBytes) {
		t.Errorf("max_bytes = %v, want the published default %d",
			result.Metadata["max_bytes"], breachExposureDefaultBytes)
	}
	if result.Metadata["body_bytes_unlimited"] != false {
		t.Error("body_bytes_unlimited = false expected: the default is a bound")
	}
	if result.Metadata["timeout_ms"] != breachExposureDefaultTimeout.Milliseconds() {
		t.Errorf("timeout_ms = %v, want %d",
			result.Metadata["timeout_ms"], breachExposureDefaultTimeout.Milliseconds())
	}

	// And zero means no bound, exactly as `max_bytes` means in `secret_scan`.
	unlimited := runFixture(t, &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}, "leaked.user@yandex.ru", map[string]interface{}{"max_bytes": 0})
	if unlimited.Metadata["max_bytes"] != int(breachExposureUnlimitedBytes) {
		t.Errorf("max_bytes: 0 was read as %v, want 0 (no bound)", unlimited.Metadata["max_bytes"])
	}
	if unlimited.Metadata["body_bytes_unlimited"] != true {
		t.Error("body_bytes_unlimited must be true when max_bytes is 0")
	}
}

// TestBreachExposureParsesAPlainUsername: both search endpoints accept a bare
// username, and the findings must hang off a `username` entity — a graph cannot
// hold an email it was not given.
func TestBreachExposureParsesAPlainUsername(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["someone@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "ibnaleem", nil)

	// The queried identity is a username node and the findings are email nodes,
	// and the edge is what joins them. Typing the findings by the *query* would
	// have written twenty email addresses into the graph as `username` — the live
	// run on 2026-10-07 returned findings that all carried addresses while the
	// query was a username.
	var queriedUsername, emailFindings bool
	for _, item := range result.Entities {
		switch {
		case item.Properties["kind"] == "queried_identity":
			queriedUsername = item.Type == "username" && item.Identity == "ibnaleem"
		case item.Properties["kind"] == "compromised_credential":
			emailFindings = item.Type == "email"
		}
	}
	if !queriedUsername {
		t.Errorf("the queried identity is not a username node: %v", breachSummarise(result))
	}
	if !emailFindings {
		t.Errorf("a finding carrying an address must be an email node: %v", breachSummarise(result))
	}
	// And the edge names the username as the source, not the address.
	for _, relation := range result.Relations {
		if relation.SourceType != "username" || relation.Source != "ibnaleem" {
			t.Errorf("relation %s/%s → %s/%s, want a username source",
				relation.SourceType, relation.Source, relation.TargetType, relation.Target)
		}
	}
	// And the username was sent as the query, not turned into an email first.
	fixture.mu.Lock()
	sent := fixture.proxynovaAsked
	fixture.mu.Unlock()
	if len(sent) == 0 || sent[0] != "ibnaleem" {
		t.Errorf("ProxyNova was asked about %v, want [ibnaleem]", sent)
	}
}

// TestBreachExposureReportsEveryLineWhenTheCountDisagrees: a source that says
// count=1 and sends three lines is disagreeing with itself. Trusting the count
// loses two findings silently.
func TestBreachExposureReportsEveryLineWhenTheCountDisagrees(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["a@yandex.ru:one","b@yandex.ru:two","c@yandex.ru:three"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "a@yandex.ru", nil)

	if breachFindings(result) != 3 {
		t.Errorf("got %d credentials, want all 3 lines; the count field is not a cap", breachFindings(result))
	}
	breachCheckMetadata(t, result, 3)
	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "count=1") {
			named = true
		}
	}
	if !named {
		t.Errorf("the count/line disagreement is not reported: %v", result.Warnings)
	}
}

// TestBreachExposureRequiresNetworkConfirmation: the value leaves the machine, so
// the transform is gated the same way every other networked transform is — by
// being registered `network: true` and refusing without the flag.
func TestBreachExposureRequiresNetworkConfirmation(t *testing.T) {
	entry := transformRegistryEntry("breach_exposure")
	if entry == nil {
		t.Fatal("breach_exposure is not in the registry, so the UI cannot offer it")
	}
	if entry["network"] != true {
		t.Error("breach_exposure must be registered network: true — it sends the value to third parties")
	}
	if entry["concurrency"] == true {
		t.Error("breach_exposure asks three fixed services, so there is no pool for the operator to size")
	}

	server := &server{}
	_, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform: "breach_exposure",
		Value:     "leaked.user@yandex.ru",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Errorf("without confirm_network the error is %v, want NETWORK_CONFIRMATION_REQUIRED", err)
	}
}

// TestBreachExposureSaysSoWhenThereIsNothing: zero findings must be a statement
// about the sources that answered, never about the value alone.
func TestBreachExposureSaysSoWhenThereIsNothing(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":0,"lines":[]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "leaked.user@yandex.ru", nil)

	if breachFindings(result) != 0 {
		t.Fatalf("got %d credentials, want 0", breachFindings(result))
	}
	var explained bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "not proof that none exists") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("a clean empty result is not qualified: %v", result.Warnings)
	}
}

// TestBreachExposureDoesNotWriteAPasswordFile is the one structural difference
// from the original, and it is worth pinning: the original wrote plaintext
// passwords to files with `os.ModePerm` (0777) and never deleted them
// (`utils.go:25`). Nothing here writes a file.
func TestBreachExposureDoesNotWriteAPasswordFile(t *testing.T) {
	before, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the engine directory: %v", err)
	}
	fixture := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	result := runFixture(t, fixture, "leaked.user@yandex.ru", nil)
	if breachFindings(result) != 1 {
		t.Fatalf("got %d credentials, want 1", breachFindings(result))
	}
	after, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the engine directory: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("the run created %d file(s) in the engine directory; the result belongs in the graph",
			len(after)-len(before))
	}
}

// TestBreachExposureReadBytesAndTimeout pins the two option readers, including the
// refusal to clamp a negative number rather than guess at it.
func TestBreachExposureReadBytesAndTimeout(t *testing.T) {
	bytesCases := []struct {
		name    string
		options map[string]interface{}
		want    int64
	}{
		{"absent falls back to the default", map[string]interface{}{}, breachExposureDefaultBytes},
		{"zero means no bound", map[string]interface{}{"max_bytes": 0}, breachExposureUnlimitedBytes},
		{"a number is taken as given", map[string]interface{}{"max_bytes": 4096}, 4096},
		{"a float is taken as given", map[string]interface{}{"max_bytes": float64(8192)}, 8192},
		{"a string is parsed", map[string]interface{}{"max_bytes": "16384"}, 16384},
		{"a negative value is refused, not clamped", map[string]interface{}{"max_bytes": -1}, breachExposureDefaultBytes},
		{"rubbish falls back", map[string]interface{}{"max_bytes": "lots"}, breachExposureDefaultBytes},
		{"an unusable type falls back", map[string]interface{}{"max_bytes": []int{1}}, breachExposureDefaultBytes},
	}
	for _, testCase := range bytesCases {
		if got := breachExposureReadBytes(testCase.options); got != testCase.want {
			t.Errorf("%s: max_bytes read as %d, want %d", testCase.name, got, testCase.want)
		}
	}

	if got := breachExposureTimeout(map[string]interface{}{}); got != breachExposureDefaultTimeout {
		t.Errorf("absent timeout_ms gave %s, want %s", got, breachExposureDefaultTimeout)
	}
	if got := breachExposureTimeout(map[string]interface{}{"timeout_ms": 2500}); got.Milliseconds() != 2500 {
		t.Errorf("timeout_ms 2500 gave %s", got)
	}
	if got := breachExposureTimeout(map[string]interface{}{"timeout_ms": 0}); got != breachExposureDefaultTimeout {
		t.Errorf("timeout_ms 0 gave %s, want the default %s", got, breachExposureDefaultTimeout)
	}
}

// TestBreachExposureDoesNotAskWeakpassWithoutAHash: the chain is driven by the
// hashes the search sources produced. No hash means no request — weakpass has no
// username lookup to ask.
func TestBreachExposureDoesNotAskWeakpassWithoutAHash(t *testing.T) {
	fixture := &breachFixture{
		proxynovaBody:  `{"count":1,"lines":["leaked.user@yandex.ru:Summer2018"]}`,
		directoryBody:  `{"found":0,"result":[]}`,
		weakpassByHash: map[string]string{},
	}
	runFixture(t, fixture, "leaked.user@yandex.ru", nil)

	weakpass, _, _ := fixture.counts()
	if weakpass != 0 {
		t.Errorf("weakpass was asked %d times although no source returned a hash", weakpass)
	}
}

// breachPasswords reads every password the run carries, from the scalar fields and
// from the `credentials` list alike.
//
// Reading only the scalars is what makes this test look wrong when it is right: an
// identity seen with two passwords carries no scalar at all, precisely so a node
// cannot claim one password for a credential it does not have alone.
func breachPasswords(result *osintTransformResult) []string {
	out := make([]string, 0, len(result.Entities))
	for _, item := range result.Entities {
		if item.Properties["kind"] != "compromised_credential" {
			continue
		}
		if password, ok := item.Properties["password"].(string); ok && password != "" {
			out = append(out, password)
		}
		rows, _ := item.Properties["credentials"].([]map[string]interface{})
		for _, row := range rows {
			if password, ok := row["password"].(string); ok && password != "" {
				out = append(out, password)
			}
		}
	}
	return out
}

// breachFindings counts only the credentials, not the identity that was queried.
//
// The two are separate entities with separate kinds, and a test that counted
// `len(result.Entities)` would be asserting on the queried-identity node too —
// which is why the count assertions below read the metadata the run publishes
// instead. That number is the run's own claim about findings, and a test that
// checks the claim against the entities is checking that the two agree.
func breachFindings(result *osintTransformResult) int {
	return len(breachCredentialEntities(result))
}

func breachCredentialEntities(result *osintTransformResult) []transformEntity {
	out := make([]transformEntity, 0, len(result.Entities))
	for _, item := range result.Entities {
		if item.Properties["kind"] == "compromised_credential" {
			out = append(out, item)
		}
	}
	return out
}

// breachCredentialCount sums the credentials carried by the nodes, so a test can
// assert that grouping did not drop any of them.
//
// One node per identity is the shape the graph needs, and the count of findings is
// then a number that is *not* visible in the entity list — which is exactly the
// condition under which a loss goes unnoticed.
func breachCredentialCount(result *osintTransformResult) int {
	total := 0
	for _, item := range breachCredentialEntities(result) {
		rows, ok := item.Properties["credentials"].([]map[string]interface{})
		if !ok {
			total++
			continue
		}
		total += len(rows)
	}
	return total
}

func breachHasPassword(passwords []string, want string) bool {
	for _, password := range passwords {
		if password == want {
			return true
		}
	}
	return false
}

func breachSummarise(result *osintTransformResult) string {
	parts := make([]string, 0, len(result.Entities))
	for _, item := range result.Entities {
		parts = append(parts, fmt.Sprintf("%s/%v", item.Type, item.Properties["password"]))
	}
	return strings.Join(parts, ", ")
}

// breachCheckMetadata asserts the run's own claim against the entities it
// produced.
//
// The count in the metadata is what an operator reads next to the findings, so
// if the two ever disagree the report is wrong even when both are individually
// plausible — and no test that only checks one of them would notice.
func breachCheckMetadata(t *testing.T, result *osintTransformResult, want int) {
	t.Helper()
	claimed, ok := result.Metadata["findings"].(int)
	if !ok {
		t.Errorf("the run publishes no integer `findings` count: %v", result.Metadata["findings"])
		return
	}
	if claimed != want {
		t.Errorf("the run reports findings=%d while carrying %d credentials", claimed, want)
	}
	if want != 0 {
		claimedProxynova, _ := result.Metadata["proxynova_findings"].(int)
		claimedDirectory, _ := result.Metadata["breachdirectory_findings"].(int)
		if claimedProxynova+claimedDirectory != want {
			t.Errorf("per-source counts %d+%d do not sum to the %d findings reported",
				claimedProxynova, claimedDirectory, want)
		}
	}
}
