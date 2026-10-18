package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The identity search is the second user of the project's transport seam.
// `withToolTransport` is the path a recorded tool run takes, so a test that
// installs the stub through it exercises the real `toolClient` instead of
// wiring a second client of its own.
type identityStub struct {
	mutex    sync.Mutex
	bodies   map[string]string
	statuses map[string]int
	headers  map[string]map[string]string
	// methodBodies and methodStatuses answer one method at one address, for the
	// platforms that take GET and refuse HEAD. Keyed by `"METHOD address"`.
	methodBodies   map[string]string
	methodStatuses map[string]int
	requests       []string
	methods        []string
}

func newIdentityStub() *identityStub {
	return &identityStub{
		bodies:         map[string]string{},
		statuses:       map[string]int{},
		headers:        map[string]map[string]string{},
		methodBodies:   map[string]string{},
		methodStatuses: map[string]int{},
	}
}

func (stub *identityStub) respond(path, body string, status int) *identityStub {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	stub.bodies[path] = body
	stub.statuses[path] = status
	return stub
}

// respondToMethod answers one method at one address and leaves the other method
// unanswered, so a test can express a platform that refuses the cheap method.
// The measured case is the Aparat API: `GET` answers 200 for a real account and
// 404 for a name that does not exist, and `HEAD` answers 405.
func (stub *identityStub) respondToMethod(method, path, body string, status int) *identityStub {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	key := method + " " + path
	stub.methodBodies[key] = body
	stub.methodStatuses[key] = status
	return stub
}

func (stub *identityStub) redirect(path, location string, status int) *identityStub {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	stub.statuses[path] = status
	stub.headers[path] = map[string]string{"Location": location}
	return stub
}

func (stub *identityStub) record(request *http.Request) *http.Response {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	stub.requests = append(stub.requests, request.URL.String())
	stub.methods = append(stub.methods, request.Method)
	key := request.URL.String()
	body := stub.bodies[key]
	status, ok := stub.statuses[key]
	if !ok {
		// A platform that answers one method and refuses the other is the case
		// the HEAD fallback has to survive, and a stub keyed only by address
		// cannot express it: a second `respond` for the same address would
		// overwrite the first. The method-keyed answer wins, so a test can say
		// "HEAD → 405, GET → 200 with a profile" for one address — which is
		// exactly what the Aparat API does.
		methodKey := request.Method + " " + key
		if methodStatus, has := stub.methodStatuses[methodKey]; has {
			body, status, ok = stub.methodBodies[methodKey], methodStatus, true
		}
	}
	if !ok {
		status = http.StatusNotFound
	}
	headers := http.Header{}
	for name, value := range stub.headers[key] {
		headers.Set(name, value)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
		Request:    request,
	}
}

func (stub *identityStub) count() int {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	return len(stub.requests)
}

func (stub *identityStub) methodsUsed() []string {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()
	out := make([]string, len(stub.methods))
	copy(out, stub.methods)
	return out
}

// identityRun drives the transform through the real entry point, so validation,
// the confirmation gate and the dispatch are all part of what the test proves.
// identityOptions builds the option map the way the gateway does: a request body
// that came through JSON, so a list is `[]interface{}` of `string` and not
// `[]string`. Writing `[]string` here would have tested a shape the transport
// never produces, and the filter under test would have been silently skipped —
// which is exactly what happened the first time this test was run.
func identityOptions(sites []string, exclude []string) map[string]interface{} {
	options := map[string]interface{}{"delay_ms": 0, "concurrency": 4}
	if len(sites) > 0 {
		list := make([]interface{}, 0, len(sites))
		for _, site := range sites {
			list = append(list, site)
		}
		options["sites"] = list
	}
	if len(exclude) > 0 {
		list := make([]interface{}, 0, len(exclude))
		for _, site := range exclude {
			list = append(list, site)
		}
		options["exclude_sites"] = list
	}
	return options
}

// identityStubClient is a real `http.Client` wired to the stub, for the tests
// that call `probeIdentitySite` directly instead of going through the transform.
//
// The redirect policy matters and is the production one: `ErrUseLastResponse`,
// so a 3xx reaching `probeIdentitySite` is the platform's final answer. A client
// that followed redirects would make the `errorUrl` test pass for the wrong
// reason.
func identityStubClient(stub *identityStub) *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			return stub.record(request), nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func identityRun(stub *identityStub, input osintTransformInput) (osintTransformResult, error) {
	ctx := withToolTransport(context.Background(), roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return stub.record(request), nil
	}))
	return (&server{}).runOSINTTransformWithCollector(ctx, input, nil)
}

func identityInput(value string, sites []string) osintTransformInput {
	return osintTransformInput{
		Transform:      "username_search",
		Value:          value,
		ConfirmNetwork: true,
		Options:        identityOptions(sites, nil),
	}
}

// TestIdentityProbeAsksEverySherlockPlatform: the whole sherlock half of the
// merge was dead before 2026-10-01, and nothing in the runtime noticed.
//
// Measured cause: sherlock writes its placeholder as `{}` (478 of its 481
// records) and maigret writes `{username}`. The merge copied sherlock's URL
// verbatim, so the 149 platforms that only sherlock has kept a `{}` the engine
// never substitutes — and `identityProbeURL` refuses any template that still
// holds a `{`, so all 149 were skipped with "no usable URL for this username".
// A live run of the original tool on `adam` found 5 accounts across 7 of those
// platforms; ours answered 0 of 10, all with that refusal.
//
// These two records are the real merged entries, so this test fails if the
// catalogue goes back to `{}` and passes only when the platform is genuinely
// asked at an address that carries the name.
func TestIdentityProbeAsksEverySherlockPlatform(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	byName := map[string]identitySite{}
	for _, site := range catalogue {
		for _, name := range siteIdentityNames(site) {
			byName[name] = site
		}
	}
	// 9GAG and AdmireMe.Vip were both confirmed live: the original sherlock
	// asked them and got a real answer for `adam`, ours refused to ask.
	for _, name := range []string{"9gag", "admireme.vip"} {
		site, ok := byName[name]
		if !ok {
			t.Fatalf("%s is gone from the catalogue: the sherlock half of the merge was dropped", name)
		}
		endpoint, usable := identityProbeURL(site, "adam")
		if !usable {
			t.Errorf("%s: no usable URL for \"adam\" — a template that still holds sherlock's `{}` "+
				"is silently never asked, which is how 149 platforms went missing", name)
			continue
		}
		if strings.Contains(endpoint, "{") {
			t.Errorf("%s: rendered %q still holds a placeholder", name, endpoint)
		}
		if !strings.Contains(endpoint, "adam") {
			t.Errorf("%s: rendered %q does not carry the username", name, endpoint)
		}
	}
}

// TestUsernameSearchFindsSherlockOnlyPlatforms: the end-to-end proof, through
// the real transform. GitHub is a maigret record and its URL already carried
// `{username}`, so it was never affected — it is here as the control: if both
// platforms are reported found, the one that was repaired is asked for the same
// reason as the one that always worked.
func TestUsernameSearchFindsSherlockOnlyPlatforms(t *testing.T) {
	stub := newIdentityStub()
	// GitHub asks its `urlProbe` (the JSON API), because the HTML page renders
	// only after login. That is the control: it worked before the fix and must
	// keep working, so a failure here means the run asked neither platform.
	stub.respond("https://api.github.com/users/adam", "", 200)
	stub.respond("https://www.9gag.com/u/adam", "<html>profile</html>", 200)

	result, err := identityRun(stub, identityInput("adam", []string{"github", "9gag"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	found := identitySitesFound(result)
	for _, want := range []string{"GitHub", "9GAG"} {
		if !found[want] {
			t.Errorf("%s was not reported; a platform that only the sherlock half of the catalogue has "+
				"has to be asked like any other", want)
		}
	}
	if result.Metadata["sites_found"] != 2 {
		t.Errorf("sites_found = %v, want 2", result.Metadata["sites_found"])
	}
	if result.Metadata["sites_skipped"] != 0 {
		t.Errorf("sites_skipped = %v, want 0", result.Metadata["sites_skipped"])
	}
}

// TestUsernameSearchReadsSherlockAbsenceMarker: `errorMsg` is how a sherlock
// `message` platform says "no profile". The merge did not read it at all, so
// after repairing the placeholder alone, 43 platforms would have reported every
// username as found. This is that 43, and the assertion is the false positive
// itself rather than a field name.
func TestUsernameSearchReadsSherlockAbsenceMarker(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	var site identitySite
	for _, candidate := range catalogue {
		if candidate.source == "sherlock" && candidate.check == "message" && len(candidate.absent) > 0 {
			site = candidate
			break
		}
	}
	if site.name == "" {
		t.Fatal("no sherlock `message` platform carries an absence marker: `errorMsg` is not being merged, " +
			"and such a platform reports every username as found")
	}
	stub := newIdentityStub()
	endpoint, usable := identityProbeURL(site, "noonewouldeverusethis7")
	if !usable {
		t.Fatalf("%s: no usable URL for the test name", site.name)
	}
	stub.respond(endpoint, "<html>"+site.absent[0]+"</html>", 200)

	result, err := identityRun(stub, identityInput("noonewouldeverusethis7", []string{strings.ToLower(site.name)}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(result.Entities) != 0 {
		t.Errorf("%s reported an account for a name the platform itself marks absent: %+v",
			site.name, result.Entities)
	}
	if result.Metadata["sites_found"] != 0 {
		t.Errorf("sites_found = %v, want 0 — the platform's own absence marker was in the body",
			result.Metadata["sites_found"])
	}
}

// TestUsernameSearchKeepsAbsenceBlindApart: 275 of the 5648 records are
// `message` platforms with no absence marker — measured field by field against
// the vendored maigret data, and 43 more were removed by the `errorMsg` fix.
// They can report an account; they cannot report that there is none, because
// nothing in their record could ever say it.
//
// Counting their negative answer as `sites_absent` publishes a gap in our
// catalogue as a fact about a person. So they get their own counter, and the
// test names a real GitLab record, which is what the engine family produces.
func TestUsernameSearchKeepsAbsenceBlindApart(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	var blind identitySite
	for _, candidate := range catalogue {
		if candidate.canOnlyAnswerPresent() {
			blind = candidate
			break
		}
	}
	if blind.name == "" {
		t.Fatal("no one-sided platform in the catalogue: the counter that keeps them apart would never run")
	}
	stub := newIdentityStub()
	endpoint, usable := identityProbeURL(blind, "definitelynotarealaccount7")
	if !usable {
		t.Fatalf("%s: no usable URL for the test name", blind.name)
	}
	// A body that carries no absence marker, because the record has none to
	// carry, and no presence marker either.
	stub.respond(endpoint, "<html>a generic page</html>", 404)

	result, err := identityRun(stub, identityInput("definitelynotarealaccount7", []string{strings.ToLower(blind.name)}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if result.Metadata["sites_absent"] != 0 {
		t.Errorf("sites_absent = %v, want 0 — a record with no absence marker cannot say "+
			"\"no profile\", and counting it as absent publishes a catalogue gap as a fact",
			result.Metadata["sites_absent"])
	}
	if result.Metadata["sites_absence_blind"] != 1 {
		t.Errorf("sites_absence_blind = %v, want 1", result.Metadata["sites_absence_blind"])
	}
	if !strings.Contains(strings.Join(result.Warnings, "\n"), "cannot tell") {
		t.Errorf("the one-sided platform is not named in the report: %v", result.Warnings)
	}
}

// TestUsernameSearchReadsErrorUrlAsAbsence: sherlock's `errorUrl` is where a
// `response_url` platform sends a missing profile. Before it was merged such a
// platform could only be believed on 2xx plus a body marker, so a redirect to its
// own "not found" page was refused as "a redirect is not an answer" and the
// account was never reported either way.
func TestUsernameSearchReadsErrorUrlAsAbsence(t *testing.T) {
	site := identitySite{
		name: "example-platform", main: "https://example.com",
		url: "https://example.com/u/{username}", check: "response_url",
		absentURL: "/u/not-found",
	}
	stub := newIdentityStub()
	stub.redirect("https://example.com/u/ghost", "https://example.com/u/not-found", 302)

	outcome := probeIdentitySite(context.Background(), identityStubClient(stub), site, "ghost", identityDefaultTimeout)
	if outcome.skipped {
		t.Fatalf("skipped: %s", outcome.skippedBy)
	}
	if outcome.found {
		t.Error("found = true, want false: the redirect target is the platform's own not-found address")
	}
	if outcome.absenceMarker != "/u/not-found" {
		t.Errorf("absenceMarker = %q, want the platform's own errorUrl", outcome.absenceMarker)
	}

	// The same platform with a real profile still reports it: the errorUrl is a
	// statement about one destination, not a permanent negative.
	stub.respond("https://example.com/u/real", "<html>profile</html>", 200)
	found := probeIdentitySite(context.Background(), identityStubClient(stub), site, "real", identityDefaultTimeout)
	if !found.found {
		t.Errorf("found = false for a real profile: %s", found.detail)
	}
}

// TestUsernameSearchReadsTheAbsentStatusTheRecordPublishes: a platform that
// publishes its own absent status can say "no" on the status alone.
//
// This is the third way to say no, and it arrived with the WhatsMyName and argus
// catalogues (`e_code` and `not_found_status`). The gain is small and measured —
// 16 of 5897 records — and it is worth being exact about what it buys, because
// "it adds a verdict" would be the wrong claim:
//
//   - The verdict itself is **not** new. `404` is already settled by the global
//     rule, and all 16 decisive records publish `404`. What the published status
//     adds is that the record is **not one-sided**: without it a record with no
//     body marker is `sites_absence_blind`, and its negative answer is counted as
//     "cannot say" rather than as an absence.
//   - The second thing it buys is subtler and would be a defect without it. The
//     global rule runs at the very end, *after* `weak` has been decided. A
//     marker-less record answering 404 passes the presence half first, so `weak`
//     is set — and then the status flips `found` to false, leaving the run
//     claiming a weak **and** an absent profile for the same platform. Two
//     opposite claims about one answer is the exact failure this file exists to
//     prevent, so the status is read before the markers, not after them.
func TestUsernameSearchReadsTheAbsentStatusTheRecordPublishes(t *testing.T) {
	site := identitySite{
		name: "example-platform", main: "https://example.com",
		url: "https://example.com/u/{username}", check: "message",
		// No absence marker and no presence marker: the body says nothing either
		// way. The status is the only channel the record publishes.
		absentCode: []int{404},
	}
	stub := newIdentityStub()
	stub.respond("https://example.com/u/ghost", "<html>a page that says nothing</html>", 404)

	outcome := probeIdentitySite(context.Background(), identityStubClient(stub), site, "ghost", identityDefaultTimeout)
	if outcome.skipped {
		t.Fatalf("skipped: %s", outcome.skippedBy)
	}
	if outcome.found {
		t.Error("found = true, want false: the record publishes 404 as its absent status")
	}
	if outcome.weak {
		t.Error("weak = true on an absent answer: the record would be reported as a weak profile and a " +
			"missing one at the same time, which are opposite claims about the same answer")
	}
	if outcome.absenceBlind {
		t.Error("absenceBlind = true, but the record publishes a status that decides absence on its own")
	}
	if outcome.absenceMarker == "" {
		t.Error("absenceMarker is empty: the answer would say only \"not found\" without saying which " +
			"rule decided it")
	}

	// The other half, and it is the half that matters for honesty: a record that
	// publishes an absent status still cannot say **present** on the same
	// strength. A 200 with a body that names nothing is a weak maybe, not an
	// account, and publishing `m_code` does not change that — WhatsMyName's
	// `m_code` is `404` in 431 of 717 records, which is a default, not a
	// measurement.
	stub.respond("https://example.com/u/real", "<html>maybe</html>", 200)
	other := probeIdentitySite(context.Background(), identityStubClient(stub), site, "real", identityDefaultTimeout)
	if !other.found {
		t.Errorf("found = false for a 200 with no absence marker present: %s", other.detail)
	}
	if !other.weak {
		t.Error("weak = false: the record declares no presence marker, so nothing in the body claims the name")
	}
}

// TestUsernameSearchKeepsAbsentStatusRecordsOutOfTheBlindCount: the catalogue
// assertion proves the field is present; this proves the run uses it, which is a
// different claim and the one the counters depend on.
func TestUsernameSearchKeepsAbsentStatusRecordsOutOfTheBlindCount(t *testing.T) {
	decisive := identitySite{
		name: "with-status", main: "https://example.com",
		url: "https://example.com/u/{username}", check: "message",
		absentCode: []int{404},
	}
	blind := identitySite{
		name: "without-status", main: "https://example.com",
		url: "https://example.com/v/{username}", check: "message",
	}
	if !decisive.absentStatusIsDecisive() {
		t.Error("a record publishing 404 as absent is not treated as able to answer")
	}
	// The two are separate claims and both are asserted. `absentStatusIsDecisive`
	// alone does not survive a change to `canOnlyAnswerPresent`, and that change
	// is the one that moves the record out of `sites_absence_blind` — measured:
	// reverting it to ignore the status leaves every test green, because the
	// runtime branch still returns the right verdict and only the *accounting*
	// silently reverts.
	if decisive.canOnlyAnswerPresent() {
		t.Error("a marker-less record that publishes a decisive absent status is still counted as " +
			"one-sided, so its negative answer stays in sites_absence_blind instead of sites_absent")
	}
	if blind.absentStatusIsDecisive() {
		t.Error("a record publishing no absent status claims it can answer anyway")
	}
	if blind.canOnlyAnswerPresent() != true {
		t.Error("a marker-less record with no published status is not one-sided, so its negative answer " +
			"would be published as an absence")
	}
	// A status that cannot carry a profile but is *also* published as present is
	// not decisive: the record is saying the code means both things, which means
	// it says nothing.
	contradictory := identitySite{
		name: "contradictory", main: "https://example.com",
		url: "https://example.com/w/{username}", check: "message",
		absentCode: []int{200}, presentCode: []int{200},
	}
	if contradictory.absentStatusIsDecisive() {
		t.Error("a status published as both absent and present was treated as decisive")
	}
}

func TestIdentityProbeSkipsAProbeThatNamesNoUser(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	var site identitySite
	for _, candidate := range catalogue {
		if candidate.probe != "" && !strings.Contains(candidate.probe, "{username}") &&
			strings.Contains(candidate.url, "{username}") {
			site = candidate
			break
		}
	}
	if site.name == "" {
		t.Skip("no merged record declares a probe that names no user; the fallback is not exercised by the catalogue")
	}
	endpoint, usable := identityProbeURL(site, "adam")
	if !usable {
		t.Fatalf("%s: no usable URL — a probe that cannot be asked about the name must not hide a usable profile URL",
			site.name)
	}
	if !strings.Contains(endpoint, "adam") {
		t.Errorf("%s: rendered %q does not carry the username", site.name, endpoint)
	}
	if site.probe != "" && endpoint == site.probe {
		t.Errorf("%s: still asked at the bare probe %q", site.name, site.probe)
	}
}

// TestIdentityCatalogueHasNoPlatformAskedTwice is the contract behind
// "one profile page, one platform".
//
// The two upstreams spell the same forum differently — maigret has `admire me`
// and sherlock has `admireme.vip`, maigret has `aniworld` and sherlock has
// `ani world`, and 63 more pairs. The merge joins by name, so all of them
// arrived as separate records, and every run asked the same URL twice: two
// round trips, two relations, and a chance of the same node appearing twice in
// the graph under two platform names.
//
// The test walks the whole catalogue and renders every address the way
// `identityProbeURL` does. If two records render the same, the run will ask it
// twice, so the test fails rather than reporting a count.
func TestIdentityCatalogueHasNoPlatformAskedTwice(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	byAddress := map[string][]string{}
	for _, site := range catalogue {
		probe, usable := identityProbeURL(site, "USERNAME")
		if !usable {
			continue
		}
		byAddress[probe] = append(byAddress[probe], site.name)
	}
	var repeated []string
	for address, names := range byAddress {
		if len(names) > 1 {
			repeated = append(repeated, fmt.Sprintf("%s ← %v", address, names))
		}
	}
	sort.Strings(repeated)
	if len(repeated) > 0 {
		limit := len(repeated)
		if limit > 10 {
			limit = 10
		}
		t.Errorf("%d profile addresses are asked by more than one platform record, so the run queries them twice:\n  %s",
			len(repeated), strings.Join(repeated[:limit], "\n  "))
	}
}

// TestIdentityFilterAnswersToEveryNameOfAPlatform: the merge keeps one record
// and hangs the other name off it as an alias. The filter has to read those
// aliases, or an operator who selects `admireme.vip` — the name sherlock
// publishes — gets nothing, while the same run selecting `admire me` gets the
// forum. One platform, one answer, whichever name was typed.
func TestIdentityFilterAnswersToEveryNameOfAPlatform(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	var aliased identitySite
	for _, site := range catalogue {
		if len(site.aliases) > 0 {
			aliased = site
			break
		}
	}
	if aliased.name == "" {
		t.Fatal("no platform carries an alias: the duplicates were not collapsed, or the aliases were dropped")
	}
	for _, name := range siteIdentityNames(aliased) {
		selected, err := identityUsableSites(identityOptions([]string{name}, nil))
		if err != nil {
			t.Fatalf("filter by %q: %v", name, err)
		}
		if len(selected) != 1 || selected[0].name != aliased.name {
			t.Errorf("filtering by %q returned %d platforms, want exactly the one record %q",
				name, len(selected), aliased.name)
		}
	}
	// Excluding by either name has to exclude the platform too, or `exclude_sites`
	// silently keeps it and the run still queries a forum the operator removed.
	for _, name := range siteIdentityNames(aliased) {
		selected, err := identityUsableSites(identityOptions([]string{name}, []string{name}))
		if err != nil {
			t.Fatalf("exclude %q: %v", name, err)
		}
		if len(selected) != 0 {
			t.Errorf("excluding by %q still returned %d platforms", name, len(selected))
		}
	}
}

// TestUsernameSearchAsksWithGetWhenAPlatformRefusesHead: the HEAD
// optimisation for `status_code` platforms was a false negative, and this is the
// measurement that found it.
//
// `HEAD` was added on 2026-10-01 because 2838 of 5577 records are decided by the
// status code alone and a full run was downloading every profile page to learn
// "200". But HEAD is a **preference, not a contract**: the Aparat API answers
// `GET` with `200` for a real account and `404` for a name that does not exist —
// a perfect `status_code` detector — and answers `HEAD` with `405`, because the
// method is not allowed on that route. The blanket HEAD read that `405` as "no
// account", so a real account was reported absent, and the live comparison
// against the original sherlock found it.
//
// The rule under test is therefore not "use HEAD" but "use HEAD, and when the
// platform refuses the method, ask again with GET" — the refusal is the trigger,
// not a guess about which platforms dislike HEAD.
func TestUsernameSearchAsksWithGetWhenAPlatformRefusesHead(t *testing.T) {
	site := identitySite{
		name: "aparat", main: "https://www.aparat.com",
		probe: "https://www.aparat.com/api/fa/v1/user/user/information/username/{username}",
		check: "status_code", claimed: "jadi", unclaimed: "noonewouldeverusethis7",
		source: "maigret",
	}
	stub := newIdentityStub()
	// The real API's shape, measured: HEAD → 405, GET → 200 with a profile.
	stub.respondToMethod("HEAD", "https://www.aparat.com/api/fa/v1/user/user/information/username/jadi", "", 405)
	stub.respondToMethod("GET", "https://www.aparat.com/api/fa/v1/user/user/information/username/jadi",
		`{"data":{"type":"Profile","id":"31718"}}`, 200)

	outcome := probeIdentitySite(context.Background(), identityStubClient(stub), site, "jadi", identityDefaultTimeout)
	if !outcome.found {
		t.Errorf("found = false: %s — a 405 to HEAD must be retried with GET, not read as \"no account\"", outcome.detail)
	}
	methods := stub.methodsUsed()
	if len(methods) != 2 || methods[0] != "HEAD" || methods[1] != "GET" {
		t.Errorf("methods = %v, want [HEAD GET]: the cheap method first, the refused one retried", methods)
	}

	// And a platform that answers HEAD is not asked twice: that is the whole
	// point of preferring it.
	plain := newIdentityStub()
	plain.respond("https://example.com/u/real", "", 200)
	fast := probeIdentitySite(context.Background(), identityStubClient(plain),
		identitySite{name: "example", main: "https://example.com", url: "https://example.com/u/{username}",
			check: "status_code"}, "real", identityDefaultTimeout)
	if !fast.found {
		t.Errorf("found = false for a HEAD that answered 200: %s", fast.detail)
	}
	if methods := plain.methodsUsed(); len(methods) != 1 || methods[0] != "HEAD" {
		t.Errorf("methods = %v, want a single HEAD", methods)
	}
}

// TestIdentityKeepsPlatformsItCannotAsk: nothing is lost, and what cannot be
// asked says why.
//
// The build used to drop records it judged unaskable, and that was a deletion of
// capability rather than a filter: the platform disappeared from the site
// filter, from the report and from `sites_available`, so an operator could not
// learn it existed and no run could ever name it. Seven records are in that state
// — `discord`, whose probe carries the username in a request body this client
// does not send, and six with no detection model upstream at all.
//
// The contract under test: they are loaded, selectable, counted, and skipped
// with the catalogue's own reason rather than a generic refusal.
func TestIdentityKeepsPlatformsItCannotAsk(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	var unaskable identitySite
	for _, site := range catalogue {
		if site.needs != "" {
			unaskable = site
			break
		}
	}
	if unaskable.name == "" {
		t.Fatal("no record carries a reason it cannot be asked: the catalogue either lost them or hides them")
	}
	// Selectable by name, like any other platform.
	selected, err := identityUsableSites(identityOptions([]string{strings.ToLower(unaskable.name)}, nil))
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("filtering by %q returned %d platforms, want 1 — a platform that cannot be asked yet "+
			"must still be selectable, or the operator cannot even try it", unaskable.name, len(selected))
	}
	// And the run says the catalogue's reason, not a generic "no usable URL".
	stub := newIdentityStub()
	result, err := identityRun(stub, identityInput("someone", []string{strings.ToLower(unaskable.name)}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if available, _ := result.Metadata["sites_available"].(int); available < 2 {
		t.Errorf("sites_available = %v, want the whole catalogue — a platform that cannot be asked yet is "+
			"still a platform the operator can select, so it belongs in the count", result.Metadata["sites_available"])
	}
	joined := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joined, unaskable.needs) {
		t.Errorf("the run did not name why %s cannot be asked: %v", unaskable.name, result.Warnings)
	}
	if !strings.Contains(joined, unaskable.name) {
		t.Errorf("the unaskable platform was not named in the report: %v", result.Warnings)
	}
}

func identitySitesFound(result osintTransformResult) map[string]bool {
	found := map[string]bool{}
	for _, item := range result.Entities {
		found[fmt.Sprint(item.Properties["site"])] = true
	}
	return found
}

// TestUsernameSearchNeedsExplicitConfirmation: the transform asks a dozen
// external platforms. Without the explicit confirmation it must not run at all,
// because every request leaves on the operator's behalf.
func TestUsernameSearchNeedsExplicitConfirmation(t *testing.T) {
	stub := newIdentityStub()
	_, err := identityRun(stub, osintTransformInput{Transform: "username_search", Value: "torvalds"})
	if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Fatalf("without confirmation err = %v, want NETWORK_CONFIRMATION_REQUIRED", err)
	}
	if stub.count() != 0 {
		t.Fatalf("the transform issued %d requests without confirmation", stub.count())
	}
}

// TestUsernameSearchSeparatesFoundFromAbsent is the contract that matters most:
// a platform with an account and a platform without one must land on opposite
// sides, and an operator must never see a whole run reported as "found".
func TestUsernameSearchSeparatesFoundFromAbsent(t *testing.T) {
	// The addresses are the ones the catalogue asks, not the ones a reader would
	// guess. GitHub, GitLab and HackerNews all publish a `urlProbe`, and the
	// engine asks the probe when there is one — that is how a platform that
	// renders profiles only after login is asked at all. Stubbing the human
	// page address made every one of these three tests fail for a reason that
	// had nothing to do with what they assert: the stub returned its default
	// 404 for an address nobody requested.
	stub := newIdentityStub()
	stub.respond("https://api.github.com/users/torvalds", "", 200)
	// GitLab's record has no presence marker, so a 403 would otherwise read as
	// "the absence marker is not in the body" and become a confirmed account.
	stub.respond("https://gitlab.com/api/v4/users?username=torvalds", "", 403)
	// HackerNews declares `"created"` as its presence marker and nothing as its
	// absence marker, so a 200 whose body has no `"created"` is not an account.
	stub.respond("https://hacker-news.firebaseio.com/v0/user/torvalds.json?shallow=true",
		`{"error":true}`, 200)

	result, err := identityRun(stub, identityInput("torvalds", []string{"github", "gitlab", "hackernews"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	found := identitySitesFound(result)
	if !found["GitHub"] {
		t.Errorf("GitHub answered 200 and was not reported as found: %+v", found)
	}
	if found["GitLab"] {
		t.Errorf("GitLab answered 403 — a refusal — and was reported as a confirmed account: %+v", found)
	}
	if found["HackerNews"] {
		t.Errorf("HackerNews answered without its presence marker and was reported as found: %+v", found)
	}
	if got := result.Metadata["sites_found"]; got != 1 {
		t.Errorf("sites_found = %v, want 1", got)
	}
}

// TestUsernameSearchCountsRelationsForEveryPlatformAnswered: a platform where
// the person has no account is still an answer and still belongs in the graph,
// because "checked and absent" is what stops the next run from asking again.
func TestUsernameSearchCountsRelationsForEveryPlatformAnswered(t *testing.T) {
	stub := newIdentityStub()
	// GitHub 200, HackerNews 200 with a body carrying no presence marker. Both
	// are answers, and both belong in the graph: a `message` platform that
	// cannot say "no" still says something, and losing that would make the next
	// run ask the same platform the same question.
	stub.respond("https://api.github.com/users/ghost", "", 200)
	stub.respond("https://admireme.vip/ghost", "<html>nothing about the name</html>", 200)

	result, err := identityRun(stub, identityInput("ghost", []string{"github", "admireme.vip"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(result.Relations) != 2 {
		t.Fatalf("relations = %d, want one per platform asked: %+v", len(result.Relations), result.Relations)
	}
	for _, relation := range result.Relations {
		if relation.Type != "registered_as" {
			t.Errorf("relation type = %q, want registered_as", relation.Type)
		}
		if !strings.Contains(relation.Target, "ghost") {
			t.Errorf("relation target %q does not name the username that was asked", relation.Target)
		}
	}
	// Two platforms answered, and both answers are in the graph: GitHub's 200
	// and AdmireMe.Vip's "nothing either way". Only the second is a weak claim,
	// and that is recorded on the node rather than by dropping it — a run that
	// deleted one-sided answers would re-ask those platforms on every pass.
	if len(result.Entities) != 2 {
		t.Errorf("entities = %d, want 2 — both platforms answered", len(result.Entities))
	}
}

// TestUsernameSearchTreatsRedirectAsAbsent is the false-positive defence, and it
// is the one that matters in practice. Patreon and a dozen other platforms
// answer a missing profile with a redirect to their own search page; any client
// that follows it sees a 200 and reports every single username as claimed.
func TestUsernameSearchTreatsRedirectAsAbsent(t *testing.T) {
	stub := newIdentityStub()
	stub.redirect("https://github.com/nobody-here", "https://github.com/nobody-here/", 301)

	result, err := identityRun(stub, identityInput("nobody-here", []string{"github"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(result.Entities) != 0 {
		t.Fatalf("a redirect to the platform's own search page was reported as an account: %+v", result.Entities)
	}
	if len(result.Warnings) == 0 {
		t.Error("an empty run said nothing; the operator cannot tell an absent account from an unchecked one")
	}
}

// TestUsernameSearchFollowsOneRedirectAndJudgesTheDestination is the redirect
// contract, and it is the second half of a measured comparison rather than a
// guess.
//
// Until 2026-10-01 a 3xx was reported as "no usable answer". Two of the seven
// platforms compared against the original sherlock answer 301 on every request
// — 9GAG to `http://9gag.com/u/<name>`, AdmireMe.Vip to `/<name>/` — so refusing
// the redirect cost one real account and one real absence per run. The original
// follows redirects; the fix follows one hop and then judges the destination by
// that platform's own rules.
//
// The protections that existed for a reason are kept and are asserted here, so
// "follows redirects" cannot later become "believes any page a redirect points
// at": a `noRedirect` record still means "no account", a destination the
// platform itself names as its not-found address still means "no account", and a
// redirect back to the address already asked is refused rather than looped.
func TestUsernameSearchFollowsOneRedirectAndJudgesTheDestination(t *testing.T) {
	// GitHub redirects to a trailing slash and the destination holds the
	// account: the canonical case, and the one the original resolves.
	stub := newIdentityStub()
	stub.redirect("https://api.github.com/users/ghost", "/users/ghost/", 301)
	stub.respond("https://api.github.com/users/ghost/", "", 200)
	result, err := identityRun(stub, identityInput("ghost", []string{"github"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if result.Metadata["sites_found"] != 1 {
		t.Errorf("sites_found = %v, want 1 — the destination answered 200 for a redirect that only added a slash",
			result.Metadata["sites_found"])
	}

	// The same platform redirecting to its own not-found address is an absence,
	// and the catalogue's `errorUrl` is what says so.
	notFound := newIdentityStub()
	notFound.redirect("https://example.com/u/ghost", "/u/no-such-user", 302)
	site := identitySite{name: "example", main: "https://example.com",
		url: "https://example.com/u/{username}", check: "response_url", absentURL: "/u/no-such-user"}
	outcome := probeIdentitySite(context.Background(), identityStubClient(notFound), site, "ghost", identityDefaultTimeout)
	if outcome.skipped || outcome.found {
		t.Errorf("skipped=%v found=%v, want skipped=false found=false: the destination is the platform's own not-found address",
			outcome.skipped, outcome.found)
	}

	// A platform whose record says its redirect means "no account" is still read
	// as absent without a second request. This is `t.me`, measured: it sent every
	// missing name to telegram.org, whose page carried the marker phrase.
	telegram := newIdentityStub()
	telegram.redirect("https://t.me/ghost", "https://telegram.org/", 302)
	telegram.respond("https://telegram.org/", "<html>You can contact @ghost right away.</html>", 200)
	tg := identitySite{name: "Telegram", main: "https://t.me", url: "https://t.me/{username}",
		check: "message", noRedirect: true, present: []string{"You can contact"}}
	tgOutcome := probeIdentitySite(context.Background(), identityStubClient(telegram), tg, "ghost", identityDefaultTimeout)
	if tgOutcome.found {
		t.Error("found = true: a noRedirect platform sent us to its own front page, which is the false positive this record exists to prevent")
	}
	if telegram.count() != 1 {
		t.Errorf("a noRedirect platform was asked %d times, want 1 — the redirect is the answer, so it is not followed", telegram.count())
	}

	// A redirect back to the address already asked is refused instead of looped.
	loop := newIdentityStub()
	loop.redirect("https://api.github.com/users/loop", "https://api.github.com/users/loop", 301)
	loopOutcome := probeIdentitySite(context.Background(), identityStubClient(loop),
		identitySite{name: "GitHub", main: "https://www.github.com/", url: "https://api.github.com/users/{username}",
			check: "status_code"}, "loop", identityDefaultTimeout)
	if !loopOutcome.skipped {
		t.Error("a redirect to the same address was not refused; the run would loop")
	}
}

// TestUsernameSearchMarksAMessageFindingAsWeak: a `message` platform that answers
// 200 without showing its absence marker is reported as found — that is the
// upstream contract, and it is the only reading under which such a platform can
// find anything at all. But it is a weaker claim than a confirmed one, and the
// difference has to survive into the export rather than living only in a log.
func TestUsernameSearchMarksAMessageFindingAsWeak(t *testing.T) {
	stub := newIdentityStub()
	// A `message` record with no presence markers at all: the platform declares
	// only an absence string, so a 200 whose body shows nothing either way cannot
	// be told from a profile. It is reported, and reported as weak.
	//
	// `AdmireMe.Vip` is the fixture, and it is one of the 149 platforms that came
	// from sherlock — a record this merge would not have been able to use before
	// 2026-10-01, because its URL still carried sherlock's `{}`.
	stub.respond("https://admireme.vip/ambiguous", "<html>a page without the marker</html>", 200)

	result, err := identityRun(stub, identityInput("ambiguous", []string{"admireme.vip"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(result.Entities) != 1 {
		t.Fatalf("entities = %d, want 1: a `message` platform that showed no absence marker is a found account", len(result.Entities))
	}
	if strength := result.Entities[0].Properties["evidence_strength"]; strength != "weak" {
		t.Errorf("evidence_strength = %v, want weak — the presence marker was never seen", strength)
	}
	if result.Metadata["sites_found_weak"] != 1 {
		t.Errorf("sites_found_weak = %v, want 1", result.Metadata["sites_found_weak"])
	}
}

// TestUsernameSearchKeepsFoundAndAbsentApart: a platform that was never asked and
// a platform that answered "no" are opposite claims, and collapsing them turns
// "we did not look" into "there is nothing there".
func TestUsernameSearchKeepsFoundAndAbsentApart(t *testing.T) {
	stub := newIdentityStub()
	stub.respond("https://api.github.com/users/real", "", 200)
	stub.respond("https://gitlab.com/api/v4/users?username=real", "", 403)
	// HackerNews is the awkward case and the reason the counters exist. Its
	// record declares a presence marker (`"created"`) and no absence marker, so
	// a 200 with an empty body is not an account: nothing in the body claims the
	// name. That is an answer of "not present", not a weak yes.
	//
	// The weak case is a different platform and a different shape: a `message`
	// record with no presence markers at all, whose body shows nothing either way.
	// `AdmireMe.Vip` is one, and it is one of the 149 sherlock platforms, so the
	// fixture is a live example of the record shape rather than a made-up one.
	stub.respond("https://hacker-news.firebaseio.com/v0/user/real.json?shallow=true", "", 200)
	stub.respond("https://admireme.vip/real", "<html>a page that says nothing about the name</html>", 200)

	result, err := identityRun(stub, identityInput("real", []string{"github", "gitlab", "hackernews", "admireme.vip"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if result.Metadata["sites_found"] != 2 {
		t.Errorf("sites_found = %v, want 2 — GitHub confirmed, AdmireMe.Vip weak", result.Metadata["sites_found"])
	}
	if result.Metadata["sites_found_weak"] != 1 {
		t.Errorf("sites_found_weak = %v, want 1 — only AdmireMe.Vip has no presence marker to show", result.Metadata["sites_found_weak"])
	}
	// GitLab's 403 is a refusal, not an absence: it did not look. It is counted
	// as neither, which is the whole point of the check.
	if result.Metadata["sites_absent"] != 0 {
		t.Errorf("sites_absent = %v, want 0 — a 403 is a refusal, not \"no account\"", result.Metadata["sites_absent"])
	}
	if result.Metadata["sites_skipped"] != 1 {
		t.Errorf("sites_skipped = %v, want 1 — GitLab refused", result.Metadata["sites_skipped"])
	}
	// Three of the four answered: GitHub found, HackerNews "not present",
	// AdmireMe.Vip found weakly. GitLab refused, so it is in neither total.
	if result.Metadata["sites_answered"] != 3 {
		t.Errorf("sites_answered = %v, want 3 — the three that did not refuse", result.Metadata["sites_answered"])
	}
	// The weak finding must say so on the node, not only in a counter, because
	// the node is what survives into the export.
	var weak int
	for _, item := range result.Entities {
		if item.Properties["evidence_strength"] == "weak" {
			weak++
			if item.Identity == "" {
				t.Errorf("a weak entity has no URL: %+v", item)
			}
		}
	}
	if weak != 1 {
		t.Errorf("entities marked weak = %d, want 1", weak)
	}
}

// TestUsernameSearchUsesHeadOnlyWhereTheAnswerNeedsNoBody: a profile page is
// megabytes, and a `status_code` platform answers from the status line alone.
// Asking for the body would multiply the traffic for no extra evidence.
func TestUsernameSearchUsesHeadOnlyWhereTheAnswerNeedsNoBody(t *testing.T) {
	stub := newIdentityStub()
	stub.respond("https://api.github.com/users/probe", "", 200)
	stub.respond("https://t.me/probe", "<html>You can contact @probe right away.</html>", 200)

	if _, err := identityRun(stub, identityInput("probe", []string{"github", "telegram"})); err != nil {
		t.Fatalf("transform: %v", err)
	}
	seen := map[string]bool{}
	for _, method := range stub.methodsUsed() {
		seen[method] = true
	}
	if !seen["HEAD"] {
		t.Error("no HEAD request was made; a status-code platform was asked for its whole page")
	}
	if !seen["GET"] {
		t.Error("no GET request was made; a body-marker platform cannot be decided from HEAD")
	}
}

// TestUsernameSearchHonoursExplicitPlatformList: the operator must be able to
// ask one platform, and a filter that ignored the list would quietly ask all of
// them — requests to third parties that were never named.
func TestUsernameSearchHonoursExplicitPlatformList(t *testing.T) {
	stub := newIdentityStub()
	result, err := identityRun(stub, identityInput("torvalds", []string{"github"}))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if stub.count() != 1 {
		t.Fatalf("asked %d platforms, want only the named one", stub.count())
	}
	if result.Metadata["sites_requested"] != 1 {
		t.Errorf("sites_requested = %v, want 1", result.Metadata["sites_requested"])
	}
	if result.Metadata["sites_available"] == result.Metadata["sites_requested"] {
		t.Error("the run reported every catalogue site as requested; the filter was not applied")
	}
}

// TestUsernameSearchRejectsAnEmptySelection: filters that match nothing must say
// so, rather than reporting "no platform holds this account" — which would be a
// claim about the world when nothing was asked.
func TestUsernameSearchRejectsAnEmptySelection(t *testing.T) {
	stub := newIdentityStub()
	input := osintTransformInput{
		Transform:      "username_search",
		Value:          "torvalds",
		ConfirmNetwork: true,
		Options:        identityOptions(nil, identityCatalogueNames()),
	}
	_, err := identityRun(stub, input)

	if err == nil || !strings.Contains(err.Error(), "NO_SITES_SELECTED") {
		t.Fatalf("excluding every platform returned err = %v, want NO_SITES_SELECTED", err)
	}
	if stub.count() != 0 {
		t.Fatalf("an empty selection still issued %d requests", stub.count())
	}
}

// identityCatalogueNames is the catalogue's own names, read from it rather than
// written out here — so the test keeps working when a platform is added and
// does not quietly stop excluding the new one.
func identityCatalogueNames() []string {
	sites, err := identitySites()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(sites))
	for _, site := range sites {
		names = append(names, site.name)
	}
	return names
}

// TestUsernameSearchReportsCancelledSlotsByName is the regression for a real
// defect this transform had: when the context was cancelled the loop broke out
// and left the remaining slots zero-valued, so every unasked platform would have
// been reported as a nameless site holding a nameless account.
func TestUsernameSearchReportsCancelledSlotsByName(t *testing.T) {
	stub := newIdentityStub()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = withToolTransport(ctx, roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return stub.record(request), nil
	}))

	result, err := (&server{}).runOSINTTransformWithCollector(ctx, osintTransformInput{
		Transform: "username_search", Value: "torvalds", ConfirmNetwork: true,
	}, nil)
	_ = err
	for _, item := range result.Entities {
		if name := fmt.Sprint(item.Properties["site"]); name == "" || name == "<nil>" {
			t.Fatalf("a cancelled run produced an entity with no platform name: %+v", item)
		}
	}
	for _, relation := range result.Relations {
		if strings.TrimSpace(relation.Target) == "" {
			t.Fatalf("a cancelled run produced a relation with no target: %+v", relation)
		}
	}
}

// TestIdentityCatalogueIsWellFormed: the catalogue is vendored from two
// upstream projects and merged by a script, so it is checked here rather than
// trusted. Every failure mode below is a platform that is silently never asked,
// or asked with a URL that names no user.
func TestIdentityCatalogueIsWellFormed(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	if len(catalogue) < 1000 {
		t.Fatalf("catalogue holds %d platforms; the merge is supposed to produce thousands, "+
			"so this is a broken build rather than a small catalogue", len(catalogue))
	}
	seen := map[string]bool{}
	byCheck := map[string]int{}
	bySource := map[string]int{}
	withEngine := 0
	oneSided := 0
	oneSidedLikeIncomplete := 0
	byDecisiveAbsentStatus := 0
	noPair := 0
	noClaimed := 0
	withAbsentFromSherlock := 0
	sherlockMessage := 0
	sherlockMessageWithoutMarker := 0
	for _, site := range catalogue {
		// A record that cannot be asked is **kept**, and says why. Dropping it
		// removed the platform from the filter, the report and
		// `sites_available` — that is losing the record, not filtering it. So the
		// shape check is: a record is either complete, or it carries the reason
		// it is not, and the two are counted so neither can grow unnoticed.
		if site.needs != "" {
			oneSidedLikeIncomplete++
			if site.check != "" && site.carriesUsername() {
				t.Errorf("%s: carries a reason it cannot be asked (%q) but has a complete record — "+
					"the reason is stale and hides a working platform", site.name, site.needs)
			}
		} else if site.name == "" || site.url == "" || site.main == "" {
			// A record with no platform address is a row an operator cannot open
			// and a probe failure cannot be traced back from. maigret omits
			// `urlMain` for 388 of its 6206 records and the first merge copied
			// that omission, so this has been red on those rows since the
			// catalogue landed; the build now derives the origin from the profile
			// URL, which is what maigret itself does.
			t.Errorf("%s: incomplete record — name=%q url=%q main=%q; a record with no platform address cannot be opened or traced",
				site.name, site.name, site.url, site.main)
			continue
		}
		if seen[site.name] {
			t.Errorf("duplicate platform %q", site.name)
		}
		seen[site.name] = true
		bySource[site.source]++
		if site.engine != "" {
			withEngine++
		}
		// Counted in both directions on purpose: how many sherlock `message`
		// records carry an absence marker, and how many do not. The first number
		// alone cannot fail — a merge that dropped `errorMsg` entirely still
		// leaves the *count* non-zero if any record was filled from elsewhere. The
		// second is the one that goes to zero, so it is the one asserted.
		if site.source == "sherlock" {
			if site.check == "message" {
				sherlockMessage++
				if len(site.absent) > 0 {
					withAbsentFromSherlock++
				} else {
					sherlockMessageWithoutMarker++
				}
			}
		}
		// Every record that is meant to be asked must be askable. maigret writes
		// `{username}` and sherlock writes `{}`, and the first merge copied
		// sherlock's URLs verbatim, so 149 platforms kept a `{}` the engine never
		// substitutes: they were silently never asked, and the whole sherlock
		// half of the merge contributed nothing. A live check found 5 accounts on
		// 7 of those platforms with the original tool and 0 with ours.
		if site.needs == "" && !site.carriesUsername() {
			t.Errorf("%s: url %q / probe %q name no username, so every input gets the same answer",
				site.name, site.url, site.probe)
		}
		if strings.Contains(site.url, "{}") || strings.Contains(site.probe, "{}") {
			t.Errorf("%s: url %q kept sherlock's `{}` placeholder, which this engine does not substitute",
				site.name, site.url)
		}
		switch site.check {
		case "status_code", "message", "response_url":
			byCheck[site.check]++
		case "":
			// Kept for visibility, with the reason in `needs` — checked above.
		default:
			t.Errorf("%s: unknown check type %q", site.name, site.check)
		}
		// A `message` platform needs a way to say no. There are now **three**
		// ways, and the third arrived with the WhatsMyName and argus catalogues:
		//
		//   1. a declared absence marker in the body;
		//   2. a redirect it only sends for a missing profile (`noRedirect`);
		//   3. a status it publishes about itself that can never carry a profile —
		//      404, 410, 204 — which settles the question without a body.
		//
		// Upstream publishes none of the three for a large minority of records, so
		// the catalogue is allowed to hold them, and the run is required to count
		// them apart (`sites_absence_blind`) instead of calling them absent. That
		// is what TestUsernameSearchKeepsAbsenceBlindApart checks at runtime.
		//
		// The rule below is therefore "no absence marker **and** no decisive
		// status", not "no absence marker". Widening it to ignore the status would
		// have hidden a real defect instead of catching it: it did exactly that
		// once, and the record it hid was `goodreads`, which has no body marker and
		// publishes `404` as its absent status.
		if site.check == "message" && len(site.absent) == 0 && !site.noRedirect {
			if site.absentStatusIsDecisive() {
				byDecisiveAbsentStatus++
				continue
			}
			oneSided++
			if !site.canOnlyAnswerPresent() {
				t.Errorf("%s: message record with no absence marker is not recognised as one-sided, "+
					"so its negative answer would be counted as an absence", site.name)
			}
		}
		// The claimed/unclaimed pair is what makes a status answer trustworthy
		// when somebody re-measures this file. It is carried per source, because
		// the two upstreams do not publish the same fields: maigret ships both,
		// sherlock ships `username_claimed` for all 481 of its records and
		// `username_unclaimed` for none of them (measured against the file, not
		// read from its docs). A pair that upstream does not publish is not a
		// merge bug, and inventing an unclaimed name would be a claim nobody
		// made.
		if site.claimed == "" {
			// Measured: exactly one upstream record, maigret's `Byond`, which
			// ships no `usernameClaimed` at all. Anyone re-measuring this
			// catalogue needs to know that number, so it is stated rather than
			// papered over with a made-up name.
			noClaimed++
		}
		if site.unclaimed == "" {
			// `Byond` is the same record as the no-claimed case above: maigret
			// publishes neither name for it, so it is counted once here and
			// named once above rather than being reported as a merge loss.
			if site.source == "maigret" && site.claimed != "" {
				t.Errorf("%s: maigret publishes an unclaimed name for every record but one, "+
					"and this is not that record, so the pair was dropped in the merge", site.name)
			}
			noPair++
		}
		if site.claimed != "" && site.claimed == site.unclaimed {
			t.Errorf("%s: the confirmed and unconfirmed names are the same, so the pair proves nothing", site.name)
		}
	}
	// The numbers are measurements, not limits: a change in either upstream has
	// to be visible here rather than silent, and a merge that stopped reading
	// `errorMsg` (which is what left 43 `message` platforms with no marker) has
	// to fail.
	// 84 is the exact count after the merge collapsed duplicates, and it is the
	// one that would collapse to zero if a merge stopped reading the second
	// upstream. It is not "at least 100": that number was right before the
	// duplicates were folded, and a threshold that no longer describes the
	// catalogue only hides a change in its shape.
	//
	// It fell from 86 to 84 for a reason worth naming: `github` and
	// `admireme.vip` are now kept as the **maigret** record with the sherlock name
	// attached as an alias, because a record's detection model belongs to the
	// upstream that owns the platform. WhatsMyName had taken both over on marker
	// count, and for `github` that meant gist markers on the `/users/` endpoint.
	if bySource["sherlock"] < 84 {
		t.Errorf("only %d platforms come from sherlock; the second upstream was dropped", bySource["sherlock"])
	}
	if oneSided == 0 {
		t.Errorf("no `message` platform is one-sided; the check that counts them apart would never run")
	}
	// Every `message` record from sherlock carries an absence marker, and the
	// check is an exact equality rather than a threshold because the exact set is
	// the whole point: sherlock declares `errorMsg` for each of them, and a merge
	// that stopped reading it would leave **zero**, not "a few fewer".
	//
	// A count threshold was the previous form and it was the wrong shape: it said
	// "at least N", so a merge that lost half the markers still passed. 29 of 29
	// fails loudly and names the field.
	if sherlockMessage > 0 && sherlockMessageWithoutMarker != 0 {
		t.Errorf("%d of %d sherlock `message` platforms carry no absence marker; `errorMsg` is not being "+
			"read, so those platforms report every username as found",
			sherlockMessageWithoutMarker, sherlockMessage)
	}
	// The three detection models have to all be present, or one of them is
	// carried in the file and never used.
	for _, kind := range []string{"status_code", "message", "response_url"} {
		if byCheck[kind] == 0 {
			t.Errorf("no platform uses %s detection; the catalogue is missing a model", kind)
		}
	}
	// The vendor templates are the whole point of merging maigret: 3425 of its
	// platforms describe no URL of their own.
	if withEngine < 1000 {
		t.Errorf("only %d platforms use a vendor template; the engine merge did not run", withEngine)
	}
	// 65 of 5898. The number is a **measurement of the merge**, not of one
	// upstream: sherlock publishes `username_claimed` for all 481 of its records
	// and `username_unclaimed` for none of them (measured against the file, not
	// read from its docs), so every platform whose record came from sherlock has
	// no pair unless the maigret record for the same platform supplied one.
	// WhatsMyName is the third source and it *does* publish a pair — its `known`
	// list — so most WhatsMyName-only platforms do carry one.
	//
	// A different number means the merge changed shape, and that has to be
	// visible rather than silent.
	if noPair != 65 {
		t.Errorf("%d platforms carry no unclaimed name, want 65 — the sherlock-only platforms that publish "+
			"no such field, plus the records that ship neither name", noPair)
	}
	if bySource["sherlock"] != 84 {
		t.Errorf("%d platforms carry sherlock as their source, want 84 — 481 records less the ones a "+
			"maigret record owns for the same platform, where the maigret record is kept and the sherlock "+
			"name becomes an alias", bySource["sherlock"])
	}
	// Every record that was absorbed still has to be reachable by its own name,
	// or an operator filtering `admireme.vip` gets nothing while the same run
	// filtering `admire me` gets the forum. The two names are one platform.
	if len(seen) != 5897 {
		t.Errorf("catalogue holds %d platforms, want 5897 — four upstream catalogues (maigret 5506, "+
			"sherlock 481, WhatsMyName 717, argus 52), 166 records collapsed into a name their address "+
			"already carried, and 16 kept although they cannot be asked yet", len(seen))
	}
	// 16 records cannot be asked yet, and that number is a measurement, not a
	// target: it must be visible so a run that silently answers for fewer
	// platforms than it claims to know is not mistaken for a complete result.
	//
	// It grew from 7 to 16 when WhatsMyName and argus were added, and every one of
	// the nine new records names a platform whose upstream publishes an address
	// that does not carry the username, or publishes no detection model at all.
	// They are kept with the reason rather than deleted, because deleting them
	// removed the platform from the filter, the report and `sites_available`.
	if oneSidedLikeIncomplete != 16 {
		t.Errorf("%d records cannot be asked yet, want 16 — records whose upstream address does not carry "+
			"the username, or publishes no detection model at all. If this number grew, a merge or a loader "+
			"stopped reading a field.", oneSidedLikeIncomplete)
	}
	// 5, and their names: maigret's `Byond` plus four platforms that arrive only
	// from argus (`icann`, `threema`, `twitter/x`, `wire`) and publish no claimed
	// name upstream. Printing them here is what makes the number checkable rather
	// than asserted.
	if noClaimed != 5 {
		t.Errorf("%d platforms carry no confirmed name, want 5 — `byond` from maigret and `icann`, "+
			"`threema`, `twitter/x`, `wire` from argus", noClaimed)
	}
	// The third way to say no is not decoration: if no record used a decisive
	// status, the whole `absent_code` column would be data nobody reads.
	if byDecisiveAbsentStatus == 0 {
		t.Errorf("no `message` platform answers on its published absent status; the status column is inert")
	}
}

// TestIdentityCatalogueOrderIsStable: the file is a JSON object, so Go map
// iteration would hand back a different order every run, and two reports of the
// same search could not be diffed.
func TestIdentityCatalogueOrderIsStable(t *testing.T) {
	first, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	second, err := loadIdentityCatalogue()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("two loads gave %d and %d platforms", len(first), len(second))
	}
	for index := range first {
		if first[index].name != second[index].name {
			t.Fatalf("platform %d differs between loads: %q and %q",
				index, first[index].name, second[index].name)
		}
	}
	for index := 1; index < len(first); index++ {
		if first[index-1].name > first[index].name {
			t.Fatalf("catalogue is not sorted at %d: %q before %q",
				index, first[index-1].name, first[index].name)
		}
	}
}

// TestIdentityCatalogueCarriesBothUpstreams: a merge that silently dropped one
// side would still pass every other test here, and the loss would only show up
// as a platform missing from a report.
func TestIdentityCatalogueCarriesBothUpstreams(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	sources := map[string]int{}
	for _, site := range catalogue {
		sources[site.source]++
	}
	if sources["maigret"] == 0 {
		t.Error("no platform came from maigret")
	}
	if sources["sherlock"] == 0 {
		t.Error("no platform came from sherlock; the merge dropped one side")
	}
}

// TestIdentityProbeURLEscapesTheUsername: a username with a slash would otherwise
// address a different page, and the answer would be about that page.
func TestIdentityProbeURLEscapesTheUsername(t *testing.T) {
	site := identitySite{name: "Test", main: "https://x/", url: "https://x/u/{username}"}
	endpoint, ok := identityProbeURL(site, "a/b")
	if !ok {
		t.Fatal("a usable username was refused")
	}
	if strings.Contains(strings.TrimPrefix(endpoint, "https://x/u/"), "a/b") {
		t.Errorf("the slash was not escaped: %s", endpoint)
	}
	if _, ok := identityProbeURL(identitySite{name: "Broken", main: "https://x/"}, "x"); ok {
		t.Error("a site with no template reported a usable URL")
	}
}

// TestIdentityUsableSitesFiltersWithoutTouchingTheCatalog: `max_sites` is a
// politeness default, and its zero value has to mean "no bound" — otherwise a
// catalogue the operator extended by hand would silently lose entries.
func TestIdentityUsableSitesFiltersWithoutTouchingTheCatalog(t *testing.T) {
	catalogue, err := identitySites()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	all, err := identityUsableSites(map[string]interface{}{})
	if err != nil {
		t.Fatalf("no filters: %v", err)
	}
	if len(all) != len(catalogue) {
		t.Fatalf("no filters gave %d sites, want all %d", len(all), len(catalogue))
	}
	unbounded, err := identityUsableSites(map[string]interface{}{"max_sites": 0})
	if err != nil {
		t.Fatalf("max_sites=0: %v", err)
	}
	if len(unbounded) != len(catalogue) {
		t.Errorf("max_sites=0 gave %d sites, want %d — zero must mean unbounded", len(unbounded), len(catalogue))
	}
	bounded, err := identityUsableSites(map[string]interface{}{"max_sites": 2})
	if err != nil {
		t.Fatalf("max_sites=2: %v", err)
	}
	if len(bounded) != 2 {
		t.Errorf("max_sites=2 gave %d sites", len(bounded))
	}
	// The tag filter is read through the same JSON-shaped helper as the site
	// list, so it is given `[]interface{}` too. Handing it a `[]string` would
	// make the filter silently select nothing and the assertion below would pass
	// for the wrong reason — which is exactly what happened on the first run.
	tagged, err := identityUsableSites(map[string]interface{}{
		"tags": []interface{}{"coding"},
	})
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if len(tagged) == 0 || len(tagged) >= len(catalogue) {
		t.Errorf("the coding tag selected %d of %d sites", len(tagged), len(catalogue))
	}
	for _, site := range tagged {
		if !siteHasAnyTag(site, map[string]bool{"coding": true}) {
			t.Errorf("%s was selected by the coding tag but does not carry it: %v", site.name, site.tags)
		}
	}
	// Order is the result order, and a randomised one would make two runs of the
	// same search produce reports that cannot be diffed.
	if !sortIsAscending(all) {
		t.Error("the selected sites are not in a stable order; two runs would report different sequences")
	}
}

func sortIsAscending(sites []identitySite) bool {
	for index := 1; index < len(sites); index++ {
		if sites[index-1].name > sites[index].name {
			return false
		}
	}
	return true
}

// TestIdentityDefaultTimeoutIsADeadlineNotABudget: several slow platforms that
// each answer in nine seconds are a legitimate answer. A timeout that cut them
// off would report "absent" for all of them, which is a different and wrong
// claim, so the default has to be generous and overridable.
func TestIdentityDefaultTimeoutIsADeadlineNotABudget(t *testing.T) {
	if identityDefaultTimeout < 5*time.Second {
		t.Errorf("the default timeout is %s, too tight to survive a slow platform", identityDefaultTimeout)
	}
	if got := identityTimeout(map[string]interface{}{"timeout_ms": 45000}); got != 45*time.Second {
		t.Errorf("an explicit timeout was not honoured: %s", got)
	}
	if got := identityTimeout(map[string]interface{}{"timeout_ms": 0}); got != identityDefaultTimeout {
		t.Errorf("timeout_ms=0 gave %s, want the documented default %s", got, identityDefaultTimeout)
	}
}

// TestIdentityDelayIsAPolitenessBoundAndNotACap: zero has to mean "no pause",
// because an operator checking their own slow host needs to be able to say so.
func TestIdentityDelayIsAPolitenessBoundAndNotACap(t *testing.T) {
	if got := identityDelay(map[string]interface{}{"delay_ms": 0}); got != 0 {
		t.Errorf("delay_ms=0 gave %s, want no pause", got)
	}
	if got := identityDelay(map[string]interface{}{"delay_ms": 750}); got.Milliseconds() != 750 {
		t.Errorf("delay_ms=750 gave %s", got)
	}
	if got := identityDelay(map[string]interface{}{}); got != identityDefaultDelay {
		t.Errorf("no option gave %s, want the documented default %s", got, identityDefaultDelay)
	}
}

// TestUsernameSearchReportsProgressWhileItRuns: a run over the full catalogue is
// 5897 requests and takes minutes, so a progress panel that only moves at the end
// is the same as no panel at all.
//
// It was measured, not assumed: a live run against the whole catalogue reported
// `0 / 5897` at 21 s and at every poll after it, and was still `0 / 5897` when
// the run ended at **1109 s**. The counter was written only after `wait.Wait()` —
// every platform had already answered before the first line was published — so the
// number an operator watched described work that was finished.
//
// The fix keeps the catalogue-order pass at the end and adds a report per finished
// platform. The assertion below is the one that catches a regression: progress has
// to be published while the run is provably still in flight, which is only
// observable if some platform has answered and others have not.
func TestUsernameSearchReportsProgressWhileItRuns(t *testing.T) {
	const platformCount = 6
	stub := newIdentityStub()
	sites := make([]identitySite, platformCount)
	for index := range sites {
		name := fmt.Sprintf("platform-%d", index)
		sites[index] = identitySite{
			name: name, main: "https://example.com",
			url: "https://example.com/" + name + "/{username}", check: "status_code",
		}
		stub.respond("https://example.com/"+name+"/real", "", 404)
	}

	ctx := context.Background()
	var mutex sync.Mutex
	var seen []int
	collector := &transformCollector{
		job:     &osintJob{ID: "osint-identity", done: make(chan struct{}), gate: newPauseGate()},
		indexes: platformCount,
		ctx:     ctx,
		stop:    make(chan struct{}),
		progress: func(update transformProgress) {
			mutex.Lock()
			seen = append(seen, update.Indexes)
			mutex.Unlock()
		},
	}

	finished := make(chan struct{})
	// A per-request pause is what makes "while it runs" observable at all. Six
	// requests against an in-process stub finish faster than a test can look at
	// them, so without a pause the only reports a reader could ever see would be
	// the ones published after the fan-out — which is exactly the defect.
	const perRequestPause = 40 * time.Millisecond
	go func() {
		runIdentityChecks(ctx, identityStubClient(stub), sites, "real", 1, perRequestPause,
			identityDefaultTimeout, collector)
		close(finished)
	}()

	var during []int
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		mutex.Lock()
		during = append(during, seen...)
		seen = nil
		mutex.Unlock()
		if len(during) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("the fan-out did not finish")
	}
	mutex.Lock()
	after := append(append([]int(nil), during...), seen...)
	mutex.Unlock()

	if len(during) == 0 {
		t.Fatalf("no progress was published while the run was in flight; only the %d reports after it "+
			"ended exist, which is the defect being fixed", len(after))
	}
	if during[len(during)-1] >= platformCount {
		t.Errorf("the first published progress already reads %d of %d, so it came from the pass after the "+
			"fan-out rather than during it: %v", during[len(during)-1], platformCount, during)
	}
	if after[len(after)-1] != platformCount {
		t.Errorf("final progress = %d, want %d: every platform answers, so the counter has to reach the "+
			"total or the panel understates what was asked", after[len(after)-1], platformCount)
	}
}
