package main

// Tests for `identity_graph` — Gravatar, Keybase and HudsonRock, ported from
// `ibnaleem/gosearch` at commit `687f9ed`.
//
// The defects these cover were read out of the original's source before the code
// was written:
//
//   - hudsonrock.go:99 decides "nothing found" by comparing the service's prose
//     `message` against a 140-character literal. Reword that sentence and the
//     comparison fails, which turns **"no compromise" into "compromise
//     detected"** — the one direction of error that reports an innocent person;
//   - keybase.go:110 returns a **zero-valued** user whenever `status.code != 0`,
//     and the display code reads a zero value as "No Keybase profile found", so a
//     service refusal becomes a statement about the person;
//   - social-accounts.go:33 decodes the body into a slice **before** checking the
//     status, so GitHub's `404` object fails to unmarshal and is reported as a
//     fetch error;
//   - not one of the three carries a timeout or a context, so a hung service hung
//     the process for good.
//
// What the engine had before this: two URLs in a list inside `email_recon`
// (`osint_transforms.go:737`), asked as **HTML** and judged by status code. Both
// services answer `200` for a profile that holds nothing, so that read could not
// see a profile's linked accounts or Keybase's verified proofs — which is the
// whole capability the modules exist for.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// identityGraphFixture serves all three services from one server, so the endpoint
// each pass chose is a fact about the requests rather than a claim.
type identityGraphFixture struct {
	mu sync.Mutex

	gravatarBody   string
	gravatarStatus int
	// gravatarDigestOnly makes the fixture answer `404` for every Gravatar path
	// except the recorded digest, which is how the live service behaves for an
	// address. Empty means "answer every path".
	gravatarDigest     string
	gravatarDigestOnly bool
	keybaseBody        string
	keybaseStatus      int
	hudsonBody         string
	hudsonStatus       int

	askedQuery []string
	askedPath  []string
}

func (fixture *identityGraphFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, status := fixture.answer(r.URL.Path, r.URL.RawQuery)
		fixture.mu.Lock()
		fixture.askedPath = append(fixture.askedPath, r.URL.Path)
		fixture.askedQuery = append(fixture.askedQuery, r.URL.RawQuery)
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
		}
		fmt.Fprint(w, body)
	})
	return mux
}

func (fixture *identityGraphFixture) answer(path, _ string) (string, int) {
	switch {
	case strings.HasPrefix(path, "/gravatar"):
		// `gravatarDigestOnly` reproduces the live service for an address: the raw
		// form answers 404 while the MD5 form answers 200. Without it the fixture
		// would answer every Gravatar path with the same body, and the digest
		// lookup this file now performs could not fail — which is the mistake that
		// let a dead HudsonRock path ship green.
		if fixture.gravatarDigestOnly && path != "/gravatar/"+fixture.gravatarDigest+".json" {
			return `"User not found"`, http.StatusNotFound
		}
		if fixture.gravatarStatus != 0 {
			return `{"message":"error"}`, fixture.gravatarStatus
		}
		return fixture.gravatarBody, http.StatusOK
	case strings.HasPrefix(path, "/keybase"):
		if fixture.keybaseStatus != 0 {
			// Keybase signals "no such user" **inside a 200**, with a non-zero
			// `status.code`. That is the shape the original's own reading depends
			// on (`keybase.go:110`), so the fixture reproduces it rather than a
			// 404 — a 404 would have been a different failure and this test would
			// have passed for the wrong reason.
			return `{"status":{"code":205,"name":"user not found","desc":"no such user"}}`, http.StatusOK
		}
		return fixture.keybaseBody, http.StatusOK
	case strings.HasPrefix(path, "/hudsonrock"):
		if fixture.hudsonStatus != 0 {
			return `{}`, fixture.hudsonStatus
		}
		return fixture.hudsonBody, http.StatusOK
	}
	return `{}`, http.StatusNotFound
}

func (fixture *identityGraphFixture) serve(t *testing.T) {
	t.Helper()
	served := httptest.NewServer(fixture.handler(t))
	previous := []string{
		identityGraphGravatarEndpoint,
		identityGraphKeybaseEndpoint,
		identityGraphHudsonRockByUsername,
		identityGraphHudsonRockByEmail,
	}
	identityGraphGravatarEndpoint = served.URL + "/gravatar"
	identityGraphKeybaseEndpoint = served.URL + "/keybase"
	identityGraphHudsonRockByUsername = served.URL + "/hudsonrock/search-by-username"
	identityGraphHudsonRockByEmail = served.URL + "/hudsonrock/search-by-email"
	t.Cleanup(func() {
		identityGraphGravatarEndpoint = previous[0]
		identityGraphKeybaseEndpoint = previous[1]
		identityGraphHudsonRockByUsername = previous[2]
		identityGraphHudsonRockByEmail = previous[3]
		served.Close()
	})
}

func (fixture *identityGraphFixture) sawPath(part string) bool {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for _, path := range fixture.askedPath {
		if strings.Contains(path, part) {
			return true
		}
	}
	return false
}

func identityGraphRun(t *testing.T, fixture *identityGraphFixture, value string, options map[string]interface{}) *osintTransformResult {
	t.Helper()
	fixture.serve(t)
	server := &server{}
	result, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform:      "identity_graph",
		Value:          value,
		Options:        options,
		ConfirmNetwork: true,
	}, nil)
	if err != nil {
		t.Fatalf("identity_graph returned %v", err)
	}
	return &result
}

// identityGraphQuiet is a fixture where all three services answer "nothing found",
// for the tests that only care about one pass.
func identityGraphQuiet() *identityGraphFixture {
	return &identityGraphFixture{
		gravatarBody: `{"entry":[]}`,
		keybaseBody:  `{"status":{"code":0},"them":[]}`,
		hudsonBody:   `{"message":"This username is not associated with a computer infected by an info-stealer."}`,
	}
}

// TestIdentityGraphReadsTheLinkedAccountsIsTheCapability: the HTML probe asked
// Gravatar's page and judged the status. This reads the JSON, and the linked
// accounts are what it holds — an email's owner is reachable from here in a way
// the status code could never have said.
func TestIdentityGraphReadsTheLinkedAccounts(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.gravatarBody = `{"entry":[{"hash":"abc123","requestHash":"ibnaleem","preferredUsername":"ibnaleem","displayName":"Ibnaleem","aboutMe":"security","emails":[{"value":"ibnaleem@yandex.ru"}],"accounts":[{"url":"https://mastodon.social/@ibnaleem","username":"ibnaleem","name":"mastodon"},{"url":"https://example.org/~ibnaleem","username":"ibnaleem","name":""}]}]}`
	result := identityGraphRun(t, fixture, "ibnaleem", nil)

	var profile bool
	var accounts int
	var address bool
	for _, item := range result.Entities {
		if item.Properties["kind"] == "identity_profile" {
			profile = item.Properties["service"] == "gravatar"
		}
		if item.Properties["kind"] == "social_account" {
			accounts++
		}
		if item.Type == "email" && item.Identity == "ibnaleem@yandex.ru" {
			address = true
		}
	}
	if !profile {
		t.Errorf("no gravatar profile entity: %v", identityGraphSummarise(result))
	}
	if accounts != 2 {
		t.Errorf("got %d linked accounts, want 2 — the HTML read could not have found either", accounts)
	}
	if !address {
		t.Errorf("the profile's published address was not recorded: %v", identityGraphSummarise(result))
	}
	// The relation is what makes the address reachable from the name.
	var published bool
	for _, relation := range result.Relations {
		if relation.Type == "publishes_email" && relation.Target == "ibnaleem@yandex.ru" {
			published = true
		}
	}
	if !published {
		t.Error("no relation links the profile to the address it publishes")
	}
}

// TestIdentityGraphKeybaseProofsBecomeRelations: Keybase's proofs are the links the
// person **verified**. The original printed them without ever joining them to the
// profile (`keybase.go:154`), so they were text in a table rather than evidence in
// a graph.
func TestIdentityGraphKeybaseProofsBecomeRelations(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.keybaseBody = `{"status":{"code":0},"them":[{"id":"9f1","basics":{"username":"ibnaleem","username_cased":"Ibnaleem","ctime":1600000000,"mtime":1700000000},"profile":{"full_name":"Ibnaleem","location":"Tbilisi","bio":"security"},"pictures":{"primary":{"url":"https://example.org/a.png"}},"stellar":{"primary":{"account_id":"GA7..."}},"devices":{"desktop":{"type":"desktop","name":"workstation"}},"cryptocurrency_addresses":{"btc":[{"address":"1Example"}]},"proofs_summary":{"all":[{"proof_type":"twitter","nametag":"ibnaleem","service_url":"https://twitter.com/ibnaleem"},{"proof_type":"github","nametag":"ibnaleem","service_url":"https://github.com/ibnaleem"}]}}]}`
	result := identityGraphRun(t, fixture, "ibnaleem", nil)

	proofs := 0
	for _, relation := range result.Relations {
		if relation.Properties["verified_by"] == "keybase" {
			proofs++
			if relation.Properties["proof_type"] == "" {
				t.Errorf("a proof relation carries no proof_type: %+v", relation)
			}
		}
	}
	if proofs != 2 {
		t.Errorf("got %d verified-proof relations, want 2: %v", proofs, identityGraphSummarise(result))
	}

	// Devices and coin addresses have no kind in this graph, so they ride on the
	// profile — and dropping them would be the silent loss the porting rule names.
	var devices, coins []string
	for _, item := range result.Entities {
		if item.Properties["kind"] != "identity_profile" {
			continue
		}
		devices, _ = item.Properties["devices"].([]string)
		coins, _ = item.Properties["cryptocurrency_addresses"].([]string)
		if item.Properties["full_name"] != "Ibnaleem" {
			t.Errorf("full_name = %v, want Ibnaleem", item.Properties["full_name"])
		}
		if item.Properties["created_at"] == "" {
			t.Error("created_at is empty although the answer carried ctime")
		}
	}
	if len(devices) != 1 || !strings.Contains(devices[0], "workstation") {
		t.Errorf("devices = %v, want the one device the answer carried", devices)
	}
	if len(coins) != 1 || !strings.Contains(coins[0], "1Example") {
		t.Errorf("cryptocurrency_addresses = %v, want the one address the answer carried", coins)
	}
}

// TestIdentityGraphKeybaseRefusalIsNotAnAbsence is the original's second defect.
// A non-zero `status.code` is the service saying "no such user", and the original
// returned a zero-valued user that its own display code then rendered as "No
// Keybase profile found" — a service refusal and a person who does not exist
// became the same sentence.
func TestIdentityGraphKeybaseRefusalIsNotAnAbsence(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.keybaseStatus = 1 // the fixture then answers 200 carrying code 205

	result := identityGraphRun(t, fixture, "ibnaleem", nil)

	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "205") && strings.Contains(warning, "user not found") {
			named = true
		}
	}
	if !named {
		t.Errorf("Keybase's refusal was not reported with its code: %v", result.Warnings)
	}
	for _, item := range result.Entities {
		if item.Properties["service"] == "keybase" {
			t.Errorf("a keybase profile was written from a refused lookup: %+v", item)
		}
	}
}

// TestIdentityGraphStealerLogIsRecordedInFull is the capability the engine had
// **not at all**: `subdomains` reads HudsonRock's `urls-by-domain`, which yields
// hostnames of infected machines and says nothing about a person. Every field the
// log carries has to survive, because "this machine was hit on this date by this
// family" is the finding and the rest is its context.
func TestIdentityGraphStealerLogIsRecordedInFull(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.hudsonBody = `{"message":"","stealers":[{"date_compromised":"2026-09-30T10:00:00Z","stealer_family":"RedLine","computer_name":"DESKTOP-AB12","operating_system":"Windows 11","malware_path":"C:\\Users\\dev\\AppData\\Local\\Temp\\x.exe","ip":"203.0.113.7","total_corporate_services":12,"total_user_services":40,"top_passwords":["Summer2018","Winter2019"],"top_logins":["https://mail.example.ru"],"antiviruses":"Kaspersky"}]}`

	result := identityGraphRun(t, fixture, "svc.admin@yandex.ru", nil)

	var found bool
	for _, item := range result.Entities {
		if item.Properties["kind"] != "infostealer_compromise" {
			continue
		}
		found = true
		if item.Type != "email" {
			t.Errorf("an email lookup produced a %s entity for the stealer record", item.Type)
		}
		if item.Properties["stealer_family"] != "RedLine" {
			t.Errorf("stealer_family = %v", item.Properties["stealer_family"])
		}
		if item.Properties["computer_name"] != "DESKTOP-AB12" {
			t.Errorf("computer_name = %v", item.Properties["computer_name"])
		}
		if item.Properties["operating_system"] != "Windows 11" {
			t.Errorf("operating_system = %v", item.Properties["operating_system"])
		}
		if item.Properties["malware_path"] == nil || item.Properties["ip"] != "203.0.113.7" {
			t.Errorf("malware_path/ip not carried: %v / %v", item.Properties["malware_path"], item.Properties["ip"])
		}
		passwords, _ := item.Properties["top_passwords"].([]string)
		if len(passwords) != 2 {
			t.Errorf("top_passwords = %v, want both", passwords)
		}
		logins, _ := item.Properties["top_logins"].([]string)
		if len(logins) != 1 {
			t.Errorf("top_logins = %v, want the one login the machine held", logins)
		}
		if item.Properties["total_corporate_services"] != 12 || item.Properties["total_user_services"] != 40 {
			t.Errorf("the service counts were dropped: %v / %v",
				item.Properties["total_corporate_services"], item.Properties["total_user_services"])
		}
	}
	if !found {
		t.Errorf("no infostealer_compromise entity: %v", identityGraphSummarise(result))
	}
	if !fixture.sawPath("search-by-email") {
		t.Error("an email lookup did not reach the search-by-email endpoint")
	}
}

// TestIdentityGraphHudsonRockEmptyStealersMeansNothingFound is the original's first
// defect, and the one with the worst failure mode: it compared a 140-character
// prose literal, so any rewording turns "no compromise" into "compromise
// detected". Here the **absence of `stealers`** decides, and a message that says
// something else entirely is still a negative answer.
func TestIdentityGraphHudsonRockEmptyStealersMeansNothingFound(t *testing.T) {
	fixture := identityGraphQuiet()
	// A message that shares no prefix with the literal the original compared to.
	fixture.hudsonBody = `{"message":"Nothing on file for this identifier.","stealers":[]}`

	result := identityGraphRun(t, fixture, "svc.admin@yandex.ru", nil)

	for _, item := range result.Entities {
		if item.Properties["kind"] == "infostealer_compromise" {
			t.Fatalf("an empty stealers list produced a compromise record: %+v", item)
		}
	}
	// And the message is carried, so the two can never disagree.
	var carried bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "Nothing on file") {
			carried = true
		}
	}
	if !carried {
		t.Errorf("the service's own wording was dropped: %v", result.Warnings)
	}
}

// TestIdentityGraphPicksTheHudsonRockEndpointForTheDirection: the two endpoints are
// different, and asking the username one with an address would answer about a
// different person. Which one was chosen is a fact about the request, not a promise
// in a comment.
func TestIdentityGraphPicksTheHudsonRockEndpointForTheDirection(t *testing.T) {
	// Each direction runs in its own subtest because `serve` swaps the endpoint
	// variables and restores them in `t.Cleanup` — which fires at the end of the
	// **test**, not the end of a run. Two runs in one test would have the second
	// capture the first's already-closed server as its "previous" value, and both
	// assertions would then pass or fail for reasons unrelated to the endpoint.
	t.Run("email", func(t *testing.T) {
		byEmail := identityGraphQuiet()
		identityGraphRun(t, byEmail, "svc.admin@yandex.ru", nil)
		if !byEmail.sawPath("search-by-email") {
			t.Error("an email lookup did not use search-by-email")
		}
		if byEmail.sawPath("search-by-username") {
			t.Error("an email lookup used search-by-username; that endpoint answers about a different person")
		}
	})

	t.Run("username", func(t *testing.T) {
		byName := identityGraphQuiet()
		identityGraphRun(t, byName, "ibnaleem", nil)
		if !byName.sawPath("search-by-username") {
			t.Error("a username lookup did not use search-by-username")
		}
		if byName.sawPath("search-by-email") {
			t.Error("a username lookup used search-by-email")
		}
	})
}

// TestIdentityGraphHudsonRockEmailEndpointIsNotTheDeadOne is the defect this pass
// actually shipped with, and the fixture above cannot catch it on its own: pointing
// the endpoint variable at a fixture server makes **any** path answer, so the test
// suite was green while every real email lookup was asking a URL the service had
// retired.
//
// Measured 2026-10-08 against the live host:
//
//	/api/json/v2/osint-tools/stealersbyemail?email=… -> 404 "Cannot GET …"
//	/api/json/v2/osint-tools/search-by-email?email=…  -> 200 {"message":…,"stealers":[…],…}
//
// The old path answered `404` with an HTML error page, which the pass could not
// tell from a dropped connection, so a wrong URL was reported to the operator as
// "HudsonRock did not answer within 20s" — a statement about the service that the
// evidence did not support. This pins the served path, because the whole cost of
// this bug was that nothing in the repository could tell a wrong URL from a slow
// one.
func TestIdentityGraphHudsonRockEmailEndpointIsNotTheDeadOne(t *testing.T) {
	const deadPath = "/api/json/v2/osint-tools/stealersbyemail"
	if strings.Contains(identityGraphHudsonRockByEmail, deadPath) {
		t.Fatalf("the email pass is pointed at %s, which the service answers 404; "+
			"the run reports that as 'did not answer', hiding a wrong URL behind a slow service", deadPath)
	}
	if !strings.Contains(identityGraphHudsonRockByEmail, "search-by-email") {
		t.Errorf("the email endpoint is %s; the served path measured on 2026-10-08 is search-by-email",
			identityGraphHudsonRockByEmail)
	}
}

// TestIdentityGraphKeybaseIsNotHandedAnAddress is the other defect that the fixture
// could not catch, for the same reason: the fixture answers `205 user not found` for
// **any** query, so it agreed with a run that sent `?usernames=petya@yandex.ru`.
//
// Measured against the live endpoint: an address in `usernames` is turned away by
// Keybase's own parser with `code 100 INPUT_ERROR (bad list value)`, while the local
// part answers `code 0` with a real profile. There is no email-addressable Keybase
// endpoint to use instead — `?emails=` and `?email=` both answer `219
// MISSING_PARAMETER` — so the local part is the only form of an address Keybase can
// answer at all.
//
// The test asserts the **request**, because the request is where the defect was: the
// run must not put an address into a parameter the service parses as a username.
func TestIdentityGraphKeybaseIsNotHandedAnAddress(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.keybaseBody = `{"status":{"code":0},"them":[{"id":"1","basics":{"username":"petya"},"proofs_summary":{"all":[]}}]}`

	result := identityGraphRun(t, fixture, "petya@yandex.ru", nil)

	fixture.mu.Lock()
	queries := append([]string(nil), fixture.askedQuery...)
	fixture.mu.Unlock()

	var keybaseQuery string
	for _, query := range queries {
		if strings.Contains(query, "usernames=") {
			keybaseQuery = query
		}
	}
	if keybaseQuery == "" {
		t.Fatalf("Keybase was not asked at all: %v", queries)
	}
	if strings.Contains(keybaseQuery, "yandex.ru") || strings.Contains(keybaseQuery, "%40") {
		t.Errorf("Keybase was handed an address: %q — it answers code 100 INPUT_ERROR to that", keybaseQuery)
	}
	if !strings.Contains(keybaseQuery, "usernames=petya") {
		t.Errorf("Keybase was asked %q; the local part is the only form of an address it answers", keybaseQuery)
	}

	// And the finding says which question produced it. A profile called `petya` is
	// not the same claim as "petya@yandex.ru belongs to it", and the node has to
	// carry the difference or the operator cannot see it.
	var candidate bool
	for _, item := range result.Entities {
		if item.Properties["service"] != "keybase" {
			continue
		}
		candidate = true
		if item.Properties["match_basis"] != "email_local_part_candidate" {
			t.Errorf("a Keybase profile from an address lookup carries match_basis=%v, "+
				"so it reads as a confirmed identity", item.Properties["match_basis"])
		}
		if item.Properties["queried_as"] != "petya" {
			t.Errorf("queried_as = %v, want petya — the operator cannot see which name was asked",
				item.Properties["queried_as"])
		}
		if item.Properties["caveat"] == "" {
			t.Error("the candidate carries no caveat, so it reads as a statement about the address")
		}
	}
	if !candidate {
		t.Errorf("the local part resolved a Keybase profile and no entity was written: %v", identityGraphSummarise(result))
	}
}

// TestIdentityGraphGravatarAsksAnAddressByItsDigest: Gravatar keys an address on the
// MD5 of its lowercased trimmed form, so asking the address as typed answers `404`
// for **every** address that does have a profile. Measured: `support@ghost.org`
// returns its profile and two linked accounts by digest, and `404` as raw text.
//
// This was the quietest of the three defects — a wrong question, answered with a
// confident "no profile" and no warning — so the test asserts the profile is found,
// not merely that the digest was requested.
func TestIdentityGraphGravatarAsksAnAddressByItsDigest(t *testing.T) {
	fixture := identityGraphQuiet()
	// The live service answers `404` for the raw address and `200` for its MD5, so
	// the fixture is told which single path may answer. Only the digest can then
	// produce the profile, and a pass that asked the address as typed would find
	// nothing — which is the defect under test.
	digest := identityGraphGravatarDigest("support@ghost.org")
	fixture.gravatarDigest = digest
	fixture.gravatarDigestOnly = true
	fixture.gravatarBody = `{"entry":[{"hash":"75e958a6","requestHash":"` + digest + `","preferredUsername":"johnonolan","displayName":"John O'Nolan","aboutMe":"designer","accounts":[{"url":"https://x.com/JohnONolan","username":"JohnONolan","name":"X"},{"url":"https://example.org/john","username":"john","name":""}]}]}`

	result := identityGraphRun(t, fixture, "support@ghost.org", nil)

	var found bool
	for _, item := range result.Entities {
		if item.Properties["service"] == "gravatar" {
			found = true
			if item.Properties["display_name"] != "John O'Nolan" {
				t.Errorf("display_name = %v; the digest form was not read", item.Properties["display_name"])
			}
		}
		if item.Properties["kind"] == "social_account" {
			found = true
		}
	}
	if !found {
		t.Errorf("an address with a real Gravatar profile produced nothing: %v / %v",
			identityGraphSummarise(result), result.Warnings)
	}
}

// TestIdentityGraphGravatarDigestIsTheKeyGravatarUses pins the digest itself. The MD5
// is over the **lowercased, trimmed** address — measured that the raw-case form of
// `support@GHOST.org` hashes to a different value and the service answers `404` for
// it — so a digest computed on the value as typed is wrong in exactly the way that
// looks like "no profile".
func TestIdentityGraphGravatarDigestIsTheKeyGravatarUses(t *testing.T) {
	if got, want := identityGraphGravatarDigest("support@GHOST.org"), "2bfa103a13c88b5ffd26da6f982f11df"; got != want {
		t.Errorf("digest of the untrimmed, upper-cased address = %s, want %s — "+
			"Gravatar keys on md5(lower(trim(address)))", got, want)
	}
	if got, want := identityGraphGravatarDigest("  support@ghost.org  "), "2bfa103a13c88b5ffd26da6f982f11df"; got != want {
		t.Errorf("digest with surrounding spaces = %s, want %s", got, want)
	}
	if identityGraphGravatarDigest("ibnaleem") == "2bfa103a13c88b5ffd26da6f982f11df" {
		t.Error("a username hashed to the same digest as an address; the two forms must stay distinct")
	}
}

// TestIdentityGraphUsernameCandidate covers the address→name reduction, including the
// cases where it must refuse rather than invent: a name has no local part, and an
// address like `@host` has an empty one.
func TestIdentityGraphUsernameCandidate(t *testing.T) {
	cases := []struct {
		value string
		want  string
		ok    bool
	}{
		{"petya@yandex.ru", "petya", true},
		{"  petya@yandex.ru  ", "petya", true},
		{"a.b+c@sub.domain.ru", "a.b+c", true},
		{"ibnaleem", "", false},
		{"@yandex.ru", "", false},
		{"user@", "", false},
	}
	for _, testCase := range cases {
		got, ok := identityGraphUsernameCandidate(strings.TrimSpace(testCase.value))
		if got != testCase.want || ok != testCase.ok {
			t.Errorf("%q -> (%q, %v), want (%q, %v)", testCase.value, got, ok, testCase.want, testCase.ok)
		}
	}
}

// TestIdentityGraphEmailDetection pins what counts as an address, because two
// decisions hang on it: which HudsonRock endpoint is chosen, and whether Gravatar is
// asked for a digest as well. A value with an `@` but no address shape must not be
// sent down the address path.
func TestIdentityGraphEmailDetection(t *testing.T) {
	for _, value := range []string{"petya@yandex.ru", "a.b+c@sub.domain.ru"} {
		if !isIdentityGraphEmail(value) {
			t.Errorf("%q was not recognised as an address", value)
		}
	}
	for _, value := range []string{"ibnaleem", "@handle", "user name@host", "https://host/@path", ""} {
		if isIdentityGraphEmail(value) {
			t.Errorf("%q was treated as an address", value)
		}
	}
}

// TestIdentityGraphRetriesSurviveADroppedConnection: HudsonRock was measured both at
// ~0.4 s and past 45 s on the same host, so a single dropped connection cost the whole
// pass and the report said "did not answer" — true of the attempt, false of the
// service. The fixture hangs the first request and answers the second, which is the
// shape of a connection that drops, and the pass has to come back with the answer.
func TestIdentityGraphRetriesSurviveADroppedConnection(t *testing.T) {
	var mu sync.Mutex
	seen := 0
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/hudsonrock") {
			return
		}
		mu.Lock()
		seen++
		attempt := seen
		mu.Unlock()
		if attempt == 1 {
			// Hijack and close without a response: the request never became an
			// answer, which is the only failure a repeat can change.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("the fixture server cannot hijack, so the drop cannot be simulated")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			connection.Close()
			return
		}
		fmt.Fprint(w, `{"message":"","stealers":[{"date_compromised":"2026-10-08T00:00:00Z","stealer_family":"RedLine","computer_name":"DESKTOP-AB12","operating_system":"Windows 11"}]}`)
	}))
	defer hang.Close()

	fixture := identityGraphQuiet()
	previous := identityGraphHudsonRockByEmail
	identityGraphHudsonRockByEmail = hang.URL + "/hudsonrock/search-by-email"
	defer func() { identityGraphHudsonRockByEmail = previous }()

	server := &server{}
	result, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform:      "identity_graph",
		Value:          "svc.admin@yandex.ru",
		Options:        map[string]interface{}{"timeout_ms": 30000},
		ConfirmNetwork: true,
	}, nil)
	if err != nil {
		t.Fatalf("identity_graph returned %v", err)
	}

	var found bool
	for _, item := range result.Entities {
		if item.Properties["kind"] == "infostealer_compromise" {
			found = true
		}
	}
	_ = fixture
	if !found {
		t.Errorf("a dropped connection cost the pass its answer: %v / %v",
			identityGraphSummarise(&result), result.Warnings)
	}
}

// TestIdentityGraphRetriesAreVisibleAndOverridable: a bound the operator cannot see is
// the hidden restriction this project forbids. `retries` has to be readable, `0` has
// to stay a real value — `positiveIntOption` would turn `0` into the default, which
// is exactly the "silently clamped bound" the timeout reader refuses elsewhere — and
// the applied number has to be published in the metadata.
func TestIdentityGraphRetriesAreVisibleAndOverridable(t *testing.T) {
	applied := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", nil)
	if applied.Metadata["hudsonrock_attempts"] != identityGraphHudsonRockAttempts {
		t.Errorf("hudsonrock_attempts = %v, want the published default %d",
			applied.Metadata["hudsonrock_attempts"], identityGraphHudsonRockAttempts)
	}

	none := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", map[string]interface{}{"retries": 0})
	if none.Metadata["hudsonrock_attempts"] != 1 {
		t.Errorf("retries: 0 gave hudsonrock_attempts = %v; zero must mean 'try once', not 'fall back to the default'",
			none.Metadata["hudsonrock_attempts"])
	}

	raised := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", map[string]interface{}{"retries": 3})
	if raised.Metadata["hudsonrock_attempts"] != 4 {
		t.Errorf("retries: 3 gave hudsonrock_attempts = %v, want 4", raised.Metadata["hudsonrock_attempts"])
	}

	for _, options := range []map[string]interface{}{
		{"retries": -1},
		{"retries": "lots"},
		{"retries": []int{1}},
	} {
		if got := identityGraphRetries(options); got != identityGraphHudsonRockAttempts-1 {
			t.Errorf("identityGraphRetries(%v) = %d, want the default %d",
				options, got, identityGraphHudsonRockAttempts-1)
		}
	}
	if got := identityGraphRetries(map[string]interface{}{}); got != identityGraphHudsonRockAttempts-1 {
		t.Errorf("an absent retries gave %d, want the default %d", got, identityGraphHudsonRockAttempts-1)
	}
}

// TestIdentityGraphPublishesTheQuestionItAsked: for an address none of the three
// services is asked the address itself, so "nothing found" is unreadable without the
// question. The run has to publish which form each service was given.
func TestIdentityGraphPublishesTheQuestionItAsked(t *testing.T) {
	byEmail := identityGraphRun(t, identityGraphQuiet(), "petya@yandex.ru", nil)

	digest := identityGraphGravatarDigest("petya@yandex.ru")
	askedGravatar, _ := byEmail.Metadata["asked_gravatar"].(string)
	if !strings.Contains(askedGravatar, digest) {
		t.Errorf("asked_gravatar = %q, want the digest %s in it — the digest is the form Gravatar answers for an address",
			askedGravatar, digest)
	}
	askedKeybase, _ := byEmail.Metadata["asked_keybase"].(string)
	if !strings.Contains(askedKeybase, "petya") || strings.Contains(askedKeybase, "@yandex.ru\"") {
		t.Errorf("asked_keybase = %q, want the local part named as a candidate", askedKeybase)
	}
	askedHudson, _ := byEmail.Metadata["asked_hudsonrock"].(string)
	if !strings.Contains(askedHudson, "petya@yandex.ru") {
		t.Errorf("asked_hudsonrock = %q, want the address — that endpoint is asked by address", askedHudson)
	}

	// A username is asked as itself, on every service.
	byName := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", nil)
	nameGravatar, _ := byName.Metadata["asked_gravatar"].(string)
	if nameGravatar != "ibnaleem" {
		t.Errorf("asked_gravatar = %q, want the username itself — a name keys on itself", nameGravatar)
	}
}

// TestIdentityGraphHudsonRockEndpointGoneIsNotAnAbsence: a `404` from HudsonRock means
// the **endpoint** was retired, not that the service holds nothing about the person.
// The old code reported both as "did not answer", which is why a wrong URL survived
// in the repository while every test stayed green.
func TestIdentityGraphHudsonRockEndpointGoneIsNotAnAbsence(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.hudsonStatus = http.StatusNotFound

	result := identityGraphRun(t, fixture, "ibnaleem", nil)

	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "404") && strings.Contains(warning, "HudsonRock") {
			named = true
		}
	}
	if !named {
		t.Errorf("a 404 from HudsonRock was not reported as the status it is: %v", result.Warnings)
	}
	for _, item := range result.Entities {
		if item.Properties["kind"] == "infostealer_compromise" {
			t.Errorf("a 404 produced a compromise record: %+v", item)
		}
	}
	// And the other two services still answered — one dead endpoint must not cost
	// the run the rest.
	answered, _ := result.Metadata["services_answered"].([]string)
	if len(answered) != 2 {
		t.Errorf("services_answered = %v, want gravatar and keybase", answered)
	}
}

// TestIdentityGraphReportsTheDirection: the metadata says which way the lookup ran,
// so "HudsonRock did not answer" is never confused with "HudsonRock was not asked".
func TestIdentityGraphReportsTheDirection(t *testing.T) {
	byEmail := identityGraphRun(t, identityGraphQuiet(), "svc.admin@yandex.ru", nil)
	if byEmail.Metadata["lookup"] != "email" {
		t.Errorf("lookup = %v, want email", byEmail.Metadata["lookup"])
	}
	byName := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", nil)
	if byName.Metadata["lookup"] != "username" {
		t.Errorf("lookup = %v, want username", byName.Metadata["lookup"])
	}
}

// TestIdentityGraphNamesTheServiceThatDidNotAnswer: silence reads as "nothing
// found", and "nothing found" is the reading an operator acts on.
func TestIdentityGraphNamesTheServiceThatDidNotAnswer(t *testing.T) {
	fixture := identityGraphQuiet()
	fixture.hudsonStatus = http.StatusInternalServerError

	result := identityGraphRun(t, fixture, "ibnaleem", nil)

	var named bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "HudsonRock") && strings.Contains(warning, "500") {
			named = true
		}
	}
	if !named {
		t.Errorf("the failing service is not named with its status: %v", result.Warnings)
	}
	// And the run still reports what the others found. The three services run
	// concurrently precisely so one that is down does not cost the run the others.
	if !fixture.sawPath("/gravatar") || !fixture.sawPath("/keybase") {
		t.Error("one failing service stopped the others from being asked")
	}
	answered, _ := result.Metadata["services_answered"].([]string)
	if len(answered) != 2 {
		t.Errorf("services_answered = %v, want gravatar and keybase", answered)
	}
}

// TestIdentityGraphPublishesTheLimitItApplied: a bound the operator cannot see is
// the hidden restriction this project forbids, and `max_bytes: 0` has to keep
// meaning "no bound" exactly as it does in the other transforms.
func TestIdentityGraphPublishesTheLimitItApplied(t *testing.T) {
	result := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", nil)
	if result.Metadata["max_bytes"] != int(identityGraphDefaultBytes) {
		t.Errorf("max_bytes = %v, want the published default", result.Metadata["max_bytes"])
	}
	if result.Metadata["body_bytes_unlimited"] != false {
		t.Error("body_bytes_unlimited = false expected: the default is a bound")
	}
	if result.Metadata["timeout_ms"] != identityGraphDefaultTimeout.Milliseconds() {
		t.Errorf("timeout_ms = %v, want %d", result.Metadata["timeout_ms"], identityGraphDefaultTimeout.Milliseconds())
	}

	unlimited := identityGraphRun(t, identityGraphQuiet(), "ibnaleem", map[string]interface{}{"max_bytes": 0})
	if unlimited.Metadata["body_bytes_unlimited"] != true {
		t.Error("max_bytes: 0 must mean no bound")
	}
}

// TestIdentityGraphRequiresNetworkConfirmation: the value leaves the machine, so the
// transform is gated by being registered `network: true` and refusing without the
// flag — not by a hand-written list that could drift.
func TestIdentityGraphRequiresNetworkConfirmation(t *testing.T) {
	entry := transformRegistryEntry("identity_graph")
	if entry == nil {
		t.Fatal("identity_graph is not in the registry, so the UI cannot offer it")
	}
	if entry["network"] != true {
		t.Error("identity_graph must be registered network: true — it sends the value to third parties")
	}

	server := &server{}
	_, err := server.runOSINTTransformWithCollector(context.Background(), osintTransformInput{
		Transform: "identity_graph",
		Value:     "ibnaleem",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Errorf("without confirm_network the error is %v, want NETWORK_CONFIRMATION_REQUIRED", err)
	}
}

// TestIdentityGraphAnswersWhenTheRunIsCancelled covers the original's hardest
// failure: not one of the three modules carried a context, so a hung service was a
// hung process.
func TestIdentityGraphAnswersWhenTheRunIsCancelled(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-make(chan struct{}):
		}
	}))
	defer hang.Close()
	previous := identityGraphGravatarEndpoint
	identityGraphGravatarEndpoint = hang.URL + "/gravatar"
	defer func() { identityGraphGravatarEndpoint = previous }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	server := &server{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := server.runOSINTTransformWithCollector(ctx, osintTransformInput{
			Transform:      "identity_graph",
			Value:          "ibnaleem",
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
		t.Fatal("a cancelled run did not return: a request ignored ctx, which is the original's defect")
	}
}

// TestIdentityGraphEndpointsMatchTheOriginal reads the upstream sources rather than
// quoting them. All three endpoints share one failure mode — a wrong path answers
// 404, which reads as "this service knows nothing about the value" — so a silent
// divergence is indistinguishable from a correct negative answer.
func TestIdentityGraphEndpointsMatchTheOriginal(t *testing.T) {
	cases := map[string][]string{
		"internal/modules/gravatar/gravatar.go":     {"gravatar.com", ".json"},
		"internal/modules/keybase/keybase.go":       {"keybase.io", "lookup.json"},
		"internal/modules/hudsonrock/hudsonrock.go": {"hudsonrock.com", "search-by-username"},
	}
	for relative, needles := range cases {
		body, err := readGosearchUpstream(t, relative)
		if err != nil {
			t.Skipf("the upstream clone is not present at %s: %v", gosearchCloneRoot, err)
		}
		for _, needle := range needles {
			if !strings.Contains(body, needle) {
				t.Errorf("%s no longer contains %q; the ported endpoint must be re-checked", relative, needle)
			}
		}
	}
}

// TestIdentityGraphOptionReaders pins the two option readers, including the refusal
// to clamp a negative number rather than guess at it.
func TestIdentityGraphOptionReaders(t *testing.T) {
	bytesCases := []struct {
		name    string
		options map[string]interface{}
		want    int64
	}{
		{"absent falls back", map[string]interface{}{}, identityGraphDefaultBytes},
		{"zero means no bound", map[string]interface{}{"max_bytes": 0}, identityGraphUnlimitedBytes},
		{"a number is taken as given", map[string]interface{}{"max_bytes": 4096}, 4096},
		{"a string is parsed", map[string]interface{}{"max_bytes": "8192"}, 8192},
		{"a negative value is refused, not clamped", map[string]interface{}{"max_bytes": -1}, identityGraphDefaultBytes},
		{"rubbish falls back", map[string]interface{}{"max_bytes": "lots"}, identityGraphDefaultBytes},
		{"an unusable type falls back", map[string]interface{}{"max_bytes": []int{1}}, identityGraphDefaultBytes},
	}
	for _, testCase := range bytesCases {
		if got := identityGraphReadBytes(testCase.options); got != testCase.want {
			t.Errorf("%s: max_bytes read as %d, want %d", testCase.name, got, testCase.want)
		}
	}
	if got := identityGraphTimeout(map[string]interface{}{}); got != identityGraphDefaultTimeout {
		t.Errorf("absent timeout_ms gave %s", got)
	}
	if got := identityGraphTimeout(map[string]interface{}{"timeout_ms": 2500}); got.Milliseconds() != 2500 {
		t.Errorf("timeout_ms 2500 gave %s", got)
	}
	if got := identityGraphUnixTime(0); got != "" {
		t.Errorf("a zero epoch gave %q; 1970 would be printed as a real creation date", got)
	}
}

func identityGraphSummarise(result *osintTransformResult) string {
	parts := make([]string, 0, len(result.Entities))
	for _, item := range result.Entities {
		parts = append(parts, item.Type+"/"+fmt.Sprint(item.Properties["kind"]))
	}
	return strings.Join(parts, ", ")
}
