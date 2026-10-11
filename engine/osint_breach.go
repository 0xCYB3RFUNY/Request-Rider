package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// `breach_exposure` — the three breach lookups gosearch ran, as a graph transform.
//
// The reference implementation asks three services the same question in three
// different shapes and writes the answers to a file:
//
//   - ProxyNova      GET api.proxynova.com/comb?query=<value>  → {"count":N,"lines":["email:password"]}
//   - BreachDirectory GET breachdirectory.p.rapidapi.com/?func=auto&term=<value>  → {"found":N,"result":[{email,password,sha1,sources}]}
//   - weakpass       GET weakpass.com/api/v1/search/<sha1>.json → {"pass":"…"}
//
// The third is not a search of its own: gosearch feeds every SHA-1 it got from
// BreachDirectory back into weakpass to turn the hash back into a plaintext
// password. That chain is kept, because dropping it would report a hash where
// the original reported a password — a silent loss, which is the one thing the
// porting rule in AGENTS.md exists to catch.
//
// Three departures from the original, each of them a measurement rather than a
// preference:
//
//  1. The original starts one goroutine per site and per module with a bare
//     `&http.Client{}` and **no timeout on any of them**. A hung upstream hung
//     the process forever. Every request here carries a per-request deadline
//     and the whole run derives from `ctx`.
//  2. `log.Fatal` inside a goroutine (breachdirectory.go:23,28) kills the host
//     process. Errors here are returned as warnings, so a failing third party
//     degrades the result instead of ending the request.
//  3. The original writes plaintext passwords into files with `os.ModePerm`
//     (0777) and never deletes them. The result goes into the graph and is
//     exported through the same report as everything else; no file is created.
//
// The reference needs a RapidAPI key for BreachDirectory. It is read from
// `BREACHDIRECTORY_API_KEY`, and its absence disables that **one** source and
// says so — the other two keep working, because a missing key must not turn two
// working sources into a failed run.

// breachExposureSources are the services this transform asks, in a fixed order so a
// run reports its findings the same way twice.
//
// The first three are gosearch's, at commit `687f9ed`. The fourth is not in the
// original and is here because it answers a question the original leaves open.
const breachExposureSources = "proxynova,breachdirectory,weakpass,pwnedpasswords"

// breachExposurePwnedEndpoint is Pwned Passwords' k-anonymity range API.
//
// It is **not** in the original: gosearch resolves a hash into a plaintext and
// stops there. This asks the opposite question — not "what password is this hash"
// but "how many times has this password been in a breach" — and the answer is the
// number an operator acts on. A leaked password used once and a leaked password
// in eight thousand breaches are not the same finding, and without this number the
// run cannot tell them apart.
//
// Only the first five hex characters of a SHA-1 ever leave the machine
// (`api.pwnedpasswords.com/range/<prefix>`): the service returns every suffix
// sharing that prefix and the match is made locally. A full hash would turn this
// lookup into an oracle for the passwords it is given, which is the one thing the
// range API exists to prevent.
var breachExposurePwnedEndpoint = "https://api.pwnedpasswords.com/range/"

// breachExposureDefaults are a default, not a cap. `timeout_ms` and `max_bytes`
// are caller-overridable and the applied values are published in the run
// metadata, because a bound the operator cannot see — and cannot widen — is the
// hidden restriction this project forbids.
const (
	breachExposureDefaultTimeout = 20 * time.Second
	breachExposureDefaultBytes   = 1 << 20
)

// breachExposureUnlimitedBytes is what `max_bytes: 0` means.
const breachExposureUnlimitedBytes = 0

// breachExposureTimeout reads the per-request deadline.
//
// It is a deadline on a hung socket, not a budget on the run: three slow
// services that each answer in fifteen seconds are a legitimate answer, and a
// budget that cut them off would report "no breach found" for all three. Absent
// means the documented default, which the run publishes in its metadata.
func breachExposureTimeout(options map[string]interface{}) time.Duration {
	if positiveIntOption(options, "timeout_ms", 0) <= 0 {
		return breachExposureDefaultTimeout
	}
	return time.Duration(positiveIntOption(options, "timeout_ms", 0)) * time.Millisecond
}

// breachExposureReadBytes reads the caller's `max_bytes`.
//
// `0` reads the whole body and a negative value is refused rather than clamped —
// a caller who wrote `-1` meant something, and guessing for them is the failure
// this rule exists to prevent. These answers are small JSON documents, so the
// default is generous; it exists so a misbehaving upstream cannot stream an
// unbounded body into the engine's memory, not to shape a normal answer.
func breachExposureReadBytes(options map[string]interface{}) int64 {
	raw, present := options["max_bytes"]
	if !present {
		return breachExposureDefaultBytes
	}
	var value int64
	switch typed := raw.(type) {
	case float64:
		value = int64(typed)
	case int:
		value = int64(typed)
	case int64:
		value = typed
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return breachExposureDefaultBytes
		}
		value = parsed
	default:
		return breachExposureDefaultBytes
	}
	if value < 0 {
		return breachExposureDefaultBytes
	}
	return value
}

// breachExposureCountKnownPasswords asks Pwned Passwords how often each password
// was breached.
//
// The password is never sent. Only the first five characters of its SHA-1 leave the
// machine, the service returns every suffix sharing that prefix, and the comparison
// happens here — which is what the range API is for, and the alternative (posting
// the password or its full hash) would make this transform an oracle for any
// password an operator ran it on.
//
// The count is attached to the credential rows, so `password_count` sits beside the
// password on the entity. A password in one breach and a password in nine thousand
// are different findings, and the original printed neither number.
func breachExposureCountKnownPasswords(ctx context.Context, client *http.Client, findings []breachExposureResult, timeout time.Duration, readBytes int64) (map[string]int, []string) {
	// Only distinct passwords are asked about, and only those long enough to have
	// a SHA-1 the service knows. One lookup per password, not per finding: the same
	// password in forty breaches is one question with one answer.
	seen := map[string]bool{}
	var passwords []string
	for _, finding := range findings {
		password := finding.Pass
		if password == "" || seen[password] {
			continue
		}
		seen[password] = true
		passwords = append(passwords, password)
	}
	if len(passwords) == 0 {
		return nil, nil
	}
	sort.Strings(passwords)

	counts := make(map[string]int, len(passwords))
	warnings := []string{}
	for _, password := range passwords {
		sum := sha1.Sum([]byte(password))
		hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
		if len(hexed) < 5 {
			continue
		}
		prefix, suffix := hexed[:5], hexed[5:]

		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		endpoint := breachExposurePwnedEndpoint + prefix
		body, status, _, ok := breachExposureFetch(requestCtx, client, "pwnedpasswords", endpoint, password, readBytes)
		cancel()
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"Pwned Passwords did not answer for one password within %s; its breach count is left absent rather than zero.",
				timeout))
			continue
		}
		if status == http.StatusNotFound {
			// The range API answers **404 when the prefix is absent from the
			// corpus**, and that is the answer for a password nobody has breached
			// — not a failure. Measured 2026-10-07 against the live endpoint: a
			// prefix with no matches returns 404 with an empty body.
			//
			// Reading it as an error would have written no count for every clean
			// password, which is the half of the corpus an operator most wants
			// distinguished from the half nobody asked about.
			counts[password] = 0
			continue
		}
		if status < 200 || status >= 300 {
			warnings = append(warnings, fmt.Sprintf(
				"Pwned Passwords answered %d for one password; its breach count is left absent rather than zero.", status))
			continue
		}

		// The body is `<SUFFIX>:<count>` per line, over every hash sharing the
		// prefix. The match is exact on the suffix, which is what makes the
		// five-character request safe: everything else in the body is someone
		// else's hash and is discarded unread.
		found := false
		for _, line := range strings.Split(body, "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], suffix) {
				continue
			}
			number, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				continue
			}
			counts[password] = number
			found = true
			break
		}
		if !found {
			// Absent, not zero: this password is not in the range, which is a
			// different fact from "the service could not tell us".
			counts[password] = 0
		}
	}
	return counts, warnings
}

// breachExposureWeakpassCalls bounds the hash lookups within one run.
//
// weakpass is queried once per distinct SHA-1 that BreachDirectory returned,
// so an account present in forty sources would otherwise cost forty requests
// against a free third-party endpoint. The bound is applied to the **number of
// hashes**, not to the findings: the overflow is stated in the run warnings, so
// a truncated run never reads as a complete one. `0` removes the bound.
const breachExposureWeakpassCalls = 25

// breachExposureEndpoints are the upstreams. They are variables, not constants,
// so the tests can point them at a fixture instead of reaching the internet, and
// so an operator behind a mirror can be moved onto it without a rebuild.
//
// The hosts are the ones the original used, read from its source at commit
// `687f9ed`: proxynova.go:31, gobreach/gobreach.go:57, weakpass.go:22.
var (
	breachProxyNovaEndpoint      = "https://api.proxynova.com/comb"
	breachDirectoryEndpoint      = "https://breachdirectory.p.rapidapi.com/"
	breachWeakpassEndpointPrefix = "https://weakpass.com/api/v1/search/"
)

// breachExposureAPIKeyEnv names the environment variable that carries the
// BreachDirectory key. The original read it from a `.env` file through godotenv
// and refused to start without it; here it is optional, and a run without it
// reports the two sources that do work.
const breachExposureAPIKeyEnv = "BREACHDIRECTORY_API_KEY"

// breachExposureResult is one compromised credential, whichever source reported
// it.
//
// `sha1` is kept even when the plaintext is known: the hash is what identifies
// the credential across sources, and it is the key weakpass is queried with.
type breachExposureResult struct {
	Source  string
	Email   string
	Pass    string
	SHA1    string
	Sources string
	// Weakpassed is true when `Pass` came from cracking `SHA1` rather than from
	// the source that reported the credential.
	Weakpassed bool
	// BreachedCount is how many times Pwned Passwords has seen this password,
	// and CountKnown says whether the number was actually obtained.
	//
	// The pair exists because "not in the corpus" and "the corpus was not
	// asked" are different facts, and a single integer cannot carry both: a zero
	// written after a failed lookup reads as "never breached", which is the one
	// conclusion nobody may draw from an error.
	BreachedCount int
	CountKnown    bool
}

// transformBreachExposure asks the three breach sources whether an email or a
// username appears in a known compromise.
//
// Unlike the two secret scans in this engine, this one returns the credential
// itself, and the registry entry says so in the description the operator reads
// before confirming a network run. `git_secrets` and `secret_scan` keep
// fingerprinting, because there the value is a credential in *your own* live
// system and the fingerprint is all a graph needs; here the value is the
// finding — "this address was reused across forty breaches, here is what it
// was reused as" — and a fingerprint would make the transform useless for the
// one question it exists to answer.
func transformBreachExposure(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED",
			"the breach lookup sends the value to three third-party breach services")
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return transformError("INVALID_EMAIL", "an email address or username is required")
	}

	timeout := breachExposureTimeout(input.Options)
	readBytes := breachExposureReadBytes(input.Options)
	setTransformMetadata(result, "sources", breachExposureSources)
	setTransformMetadata(result, "timeout_ms", timeout.Milliseconds())
	setTransformMetadata(result, "max_bytes", int(readBytes))
	setTransformMetadata(result, "body_bytes_unlimited", readBytes == breachExposureUnlimitedBytes)
	// Stated as a fact, not a promise: the operator can see from the response
	// whether a value was stored without reading the source.
	setTransformMetadata(result, "credential_values_returned", true)

	// ProxyNova and BreachDirectory are independent and each is slow enough that
	// running them in series doubles the wall clock for no reason. weakpass is
	// sequential because it is a chain: it needs the hashes BreachDirectory
	// returned.
	var (
		waitGroup sync.WaitGroup
		mutex     sync.Mutex
		findings  []breachExposureResult
		warnings  []string
		asked     int
	)

	record := func(outcomes ...breachExposureResult) {
		mutex.Lock()
		defer mutex.Unlock()
		findings = append(findings, outcomes...)
	}
	note := func(format string, arguments ...interface{}) {
		mutex.Lock()
		defer mutex.Unlock()
		warnings = append(warnings, fmt.Sprintf(format, arguments...))
	}

	client := s.toolClient(ctx)

	// Two requests, one pool of two workers. The original ran these from two
	// goroutines with no limit at all; two is the whole set, so the bound costs
	// nothing and makes the cancellation path honest.
	waitGroup.Add(2)
	for _, source := range []string{"proxynova", "breachdirectory"} {
		source := source
		go func() {
			defer waitGroup.Done()
			if err := collector.checkpoint(ctx); err != nil {
				return
			}
			mutex.Lock()
			asked++
			position := asked
			mutex.Unlock()
			if collector != nil {
				collector.indexPosition(ctx, source, position-1, 2)
			}
			found, sourceWarnings := breachExposureQuerySource(ctx, client, source, value, timeout, readBytes)
			record(found...)
			for _, warning := range sourceWarnings {
				note("%s", warning)
			}
		}()
	}
	waitGroup.Wait()

	// The chain: every distinct hash BreachDirectory produced is offered to
	// weakpass, and a hash that comes back with a password upgrades the
	// matching finding rather than adding a second one for the same credential.
	if err := collector.checkpoint(ctx); err != nil {
		return nil
	}
	if collector != nil {
		collector.indexPosition(ctx, "weakpass", 2, 3)
	}
	if len(findings) > 0 {
		cracked, chainWarnings := breachExposureCrackHashes(ctx, client, findings, timeout, readBytes)
		breachExposureApplyCrack(findings, cracked)
		for _, warning := range chainWarnings {
			note("%s", warning)
		}
	}

	// The count of breaches each password appears in. Not in the original, and it
	// runs after the weakpass chain so a cracked password is counted too — the
	// point of cracking it is to learn how far it spreads.
	if err := collector.checkpoint(ctx); err != nil {
		return nil
	}
	if collector != nil {
		collector.indexPosition(ctx, "pwnedpasswords", 3, 4)
	}
	if len(findings) > 0 {
		counts, countWarnings := breachExposureCountKnownPasswords(ctx, client, findings, timeout, readBytes)
		breachExposureApplyCounts(findings, counts)
		for _, warning := range countWarnings {
			note("%s", warning)
		}
	}

	// Deterministic order. Two runs over the same answers print them in the
	// same order, so a diff between two reports is a change in the data rather
	// than in the goroutine schedule.
	sort.SliceStable(findings, func(left, right int) bool {
		if findings[left].Email != findings[right].Email {
			return findings[left].Email < findings[right].Email
		}
		if findings[left].SHA1 != findings[right].SHA1 {
			return findings[left].SHA1 < findings[right].SHA1
		}
		return findings[left].Source < findings[right].Source
	})

	result.LocalOnly = false
	result.NetworkUsed = true

	// Every finding hangs off the identity that was queried, through an edge. The
	// live run on 2026-10-07 returned twenty `email` nodes and no edge saying
	// which account they were found for — a set of credentials with nothing
	// connecting them to the question, which is the state in which a graph cannot
	// be read.
	subjectType := breachExposureSubject(value)
	subjectIdentity := strings.ToLower(value)

	// The queried identity becomes a node of its own **unless** a finding already
	// claims it. An identity plus a kind is the graph's primary key, so writing
	// both would put two nodes at the same address — one node drawn twice. When a
	// finding does claim it, the query is marked on that finding instead: the
	// question and its answer belong on one node, and the edge between them would
	// be a self-edge.
	queriedAlone := true

	// One node per identity, with **every** credential that identity was seen
	// with. The live run on 2026-10-07 measured why: ProxyNova returned
	// `al3xis@pravda.ru` twice with two different passwords (`200804` and
	// `200804al3xis`), and `akkord@pravda.ru` twice with the same one. Writing one
	// node per finding put two nodes at each address, and since an identity plus a
	// kind is the graph's primary key the pair would have been stored as one node —
	// silently keeping whichever arrived last. One password per address is not the
	// answer to "which passwords was this account reused as", which is the whole
	// question.
	grouped := map[string]*breachExposureGroup{}
	order := make([]string, 0, len(findings))
	for _, finding := range findings {
		findingType, findingIdentity := breachExposureIdentity(finding)
		if findingIdentity == "" {
			// A finding with no address, no hash and no source name is not
			// something the graph can hold, and writing an entity with an empty
			// identity would merge every such finding into one nameless node.
			continue
		}
		key := findingType + "\x00" + findingIdentity
		group, seen := grouped[key]
		if !seen {
			group = &breachExposureGroup{kind: findingType, identity: findingIdentity}
			grouped[key] = group
			order = append(order, key)
		}
		group.add(finding)

		// An edge is written only when the finding is an address that is **not**
		// the identity that was queried. The first case would be a self-edge; the
		// second would be a `username → username` edge whose target is a
		// credential, which no reader can act on.
		isQueried := findingType == subjectType && strings.EqualFold(findingIdentity, subjectIdentity)
		if isQueried || findingType != "email" {
			continue
		}
		// One edge per identity, not one per finding: the relation says the
		// account was exposed, and the credentials it was exposed with are on the
		// node. Twenty edges to the same target is one fact drawn twenty times.
		if group.linked {
			continue
		}
		group.linked = true
		result.Relations = append(result.Relations, transformRelation{
			Type:       "exposed_in_breach",
			SourceType: subjectType,
			Source:     subjectIdentity,
			TargetType: findingType,
			Target:     findingIdentity,
			Properties: map[string]interface{}{
				"source":     finding.Source,
				"credential": finding.Pass,
				"sha1":       finding.SHA1,
			},
		})
	}

	for _, key := range order {
		group := grouped[key]
		group.sort()
		groupEntity := breachExposureEntity(group)
		if group.kind == subjectType && strings.EqualFold(group.identity, subjectIdentity) {
			queriedAlone = false
			groupEntity.Properties["queried_for"] = breachExposureSources
		}
		result.Entities = append(result.Entities, groupEntity)
	}

	// Nothing claimed the queried identity, so it becomes a node here — after the
	// findings, so the entity list reads as "the findings, then the question they
	// were asked for".
	if queriedAlone {
		result.Entities = append(result.Entities,
			entity(subjectType, subjectIdentity,
				map[string]interface{}{"kind": "queried_identity", "queried_for": breachExposureSources},
				map[string]interface{}{"source": "breach_lookup_request"}))
	}

	// The counts are of **credentials**, not of raw source lines. ProxyNova answered
	// the live run with `akkord@pravda.ru` twice under one password, and counting
	// lines would have reported a finding twice — a number an operator acts on
	// ("this account was reused across 4 breaches") that the data does not say.
	perSource := map[string]int{}
	credentialsHeld := 0
	distinctHeld := 0
	for _, key := range order {
		group := grouped[key]
		credentialsHeld += len(group.credentials)
		distinctHeld += group.unique()
		for _, credential := range group.credentials {
			perSource[credential.Source]++
		}
	}
	// `findings` is the number of rows the sources sent — the number the original
	// printed. `distinct_findings` is the same data with repeats removed. Both are
	// published because a run that reported only the smaller one would look like a
	// filter had eaten rows.
	setTransformMetadata(result, "findings", credentialsHeld)
	setTransformMetadata(result, "distinct_findings", distinctHeld)
	setTransformMetadata(result, "identities", len(order))
	setTransformMetadata(result, "proxynova_findings", perSource["proxynova"])
	setTransformMetadata(result, "breachdirectory_findings", perSource["breachdirectory"])
	setTransformMetadata(result, "cracked", len(breachExposureCracked(findings)))

	// A source that never answered is named. Reporting "no breaches found"
	// after a source returned 500 is how a broken integration reads as a clean
	// bill of health, which is the reading that matters most and the one that
	// must never be produced by an error.
	result.Warnings = append(result.Warnings, warnings...)
	if len(findings) == 0 {
		result.Warnings = append(result.Warnings,
			"No compromised credential was reported for "+value+
				" by the sources that answered. A source that did not answer is named above; a name that is absent from every public breach corpus is not proof that none exists.")
	}
	return nil
}

// breachExposureSubject picks the kind of entity the findings hang off.
//
// ProxyNova and BreachDirectory both accept an email or a username, so the
// subject is whichever kind the value actually is. Guessing wrong would attach
// every finding to an entity the graph cannot hold.
func breachExposureSubject(value string) string {
	if strings.Contains(value, "@") {
		return "email"
	}
	return "username"
}

// breachExposureQuerySource asks one of the two search endpoints.
func breachExposureQuerySource(ctx context.Context, client *http.Client, source, value string, timeout time.Duration, readBytes int64) ([]breachExposureResult, []string) {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Warnings name the source as the operator knows it, not as the registry
	// spells it: the run's own id is `breachdirectory`, and a warning reading
	// "breachdirectory answered 429" is a name the operator cannot match to the
	// list in the registry entry or to the service they configured.
	label := breachExposureSourceLabel(source)

	endpoint, warnings := breachExposureRequestURL(source, value)
	if endpoint == "" {
		return nil, warnings
	}

	body, status, read, ok := breachExposureFetch(requestCtx, client, source, endpoint, value, readBytes)
	if !ok {
		return nil, append(warnings, fmt.Sprintf(
			"%s did not answer for %s within %s, so nothing is reported for it — the run is not a statement about this source.",
			label, value, timeout))
	}
	if status < 200 || status >= 300 {
		return nil, append(warnings, fmt.Sprintf(
			"%s answered %d for %s, so nothing is reported for it.", label, status, value))
	}
	if read {
		warnings = append(warnings, fmt.Sprintf(
			"The %s answer for %s was larger than max_bytes and was read only in part; a finding past that point was not looked for.",
			label, value))
	}

	switch source {
	case "proxynova":
		found, parseWarnings := breachExposureParseProxyNova(body, value)
		return found, append(warnings, parseWarnings...)
	case "breachdirectory":
		found, parseWarnings := breachExposureParseBreachDirectory(body, value)
		return found, append(warnings, parseWarnings...)
	}
	return nil, warnings
}

// breachExposureSourceLabel is the name a source is known by in prose. The
// registry spells it `breachdirectory`, which is an id, not a service name.
func breachExposureSourceLabel(source string) string {
	switch source {
	case "breachdirectory":
		return "BreachDirectory"
	case "weakpass":
		return "weakpass"
	}
	return source
}

// breachExposureRequestURL builds the endpoint for one source and reports why a
// source is not going to be asked.
//
// BreachDirectory is the only one that needs a key, and a missing key disables
// that source alone — which is why the key is read here and not in the caller.
func breachExposureRequestURL(source, value string) (string, []string) {
	switch source {
	case "proxynova":
		return breachProxyNovaEndpoint + "?query=" + url.QueryEscape(value), nil
	case "breachdirectory":
		apiKey := strings.TrimSpace(os.Getenv(breachExposureAPIKeyEnv))
		if apiKey == "" {
			return "", []string{
				"Breach Directory was not asked: it needs a key and " + breachExposureAPIKeyEnv +
					" is not set in the engine's environment. The other sources ran; this one is silent rather than empty.",
			}
		}
		return breachDirectoryEndpoint + "?func=auto&term=" + url.QueryEscape(value), nil
	}
	return "", []string{"unknown breach source " + source}
}

// breachExposureFetch reads one answer, bounded and with a deadline.
//
// `readBytes` is the caller's `max_bytes`; zero reads the whole body. The bool
// it returns says the body was cut short, so the caller can say "no match" for a
// document it only read in part instead of reporting a clean negative.
func breachExposureFetch(ctx context.Context, client *http.Client, source, endpoint, value string, readBytes int64) (string, int, bool, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", 0, false, false
	}
	request.Header.Set("User-Agent", archiveUserAgent)
	request.Header.Set("Accept", "application/json")
	if source == "breachdirectory" {
		request.Header.Set("x-rapidapi-key", strings.TrimSpace(os.Getenv(breachExposureAPIKeyEnv)))
		request.Header.Set("x-rapidapi-host", breachDirectoryHost)
	}

	response, err := client.Do(request)
	if err != nil {
		return "", 0, false, false
	}
	defer response.Body.Close()

	var reader io.Reader = response.Body
	truncated := false
	if readBytes > breachExposureUnlimitedBytes {
		// One byte past the limit, so "did not fit" is a measurement rather
		// than an assumption — the same reasoning as `secretScanFetch`.
		reader = io.LimitReader(response.Body, readBytes+1)
	}
	body, err := io.ReadAll(reader)
	if int64(len(body)) > readBytes && readBytes > breachExposureUnlimitedBytes {
		body = body[:readBytes]
		truncated = true
	}
	if err != nil {
		return string(body), response.StatusCode, truncated, true
	}
	return string(body), response.StatusCode, truncated, true
}

// breachDirectoryHost is the RapidAPI host the original sent as a header.
const breachDirectoryHost = "breachdirectory.p.rapidapi.com"

// breachExposureParseProxyNova reads `{"count":N,"lines":["email:password"]}`.
//
// The original split each line on `:` and kept the pair only when there were
// **exactly** two parts (`proxynova.go:57`), so a password containing a colon
// was dropped and one containing none was dropped too. `SplitN` keeps both, and
// a line that has no colon at all is reported rather than skipped silently —
// that is a malformed answer, and a malformed answer is a fact about the source.
func breachExposureParseProxyNova(body, value string) ([]breachExposureResult, []string) {
	var response struct {
		Count int      `json:"count"`
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		return nil, []string{fmt.Sprintf("Proxy Nova's answer for %s could not be read as JSON, so nothing is reported for it.", value)}
	}
	// A count of 0 with lines present, or lines with a count of 0, is a
	// disagreement between two fields of one answer. Trusting the larger of the
	// two is the only reading that does not lose a finding.
	claimed := response.Count
	if len(response.Lines) > claimed {
		claimed = len(response.Lines)
	}
	if claimed == 0 {
		return nil, nil
	}

	warnings := []string{}
	if response.Count != len(response.Lines) {
		warnings = append(warnings, fmt.Sprintf(
			"Proxy Nova reported count=%d and sent %d lines for %s; every line was parsed, because dropping them to match the count would lose findings.",
			response.Count, len(response.Lines), value))
	}

	found := make([]breachExposureResult, 0, len(response.Lines))
	for _, line := range response.Lines {
		at := strings.Index(line, ":")
		if at <= 0 {
			warnings = append(warnings, fmt.Sprintf(
				"A Proxy Nova line for %s carried no `email:password` separator and was not parsed.", value))
			continue
		}
		found = append(found, breachExposureResult{
			Source: "proxynova",
			Email:  strings.TrimSpace(line[:at]),
			Pass:   strings.TrimSpace(line[at+1:]),
		})
	}
	return found, warnings
}

// breachExposureParseBreachDirectory reads the RapidAPI answer
// `{"found":N,"result":[{"email","password","sha1","sources"}]}`.
//
// Every field of every entry is kept, including `sources`, which names where
// the credential appeared. The original printed email, sha1 and sources but
// **never the email or the `password` field from the entry** — it only printed
// whatever weakpass returned for the hash, and printed `entry.Password` only
// when the crack came back empty. The entry's own password is therefore data
// the original had and did not show; it is kept here.
func breachExposureParseBreachDirectory(body, value string) ([]breachExposureResult, []string) {
	var response struct {
		Found  int `json:"found"`
		Result []struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			SHA1     string `json:"sha1"`
			Sources  string `json:"sources"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		return nil, []string{fmt.Sprintf("Breach Directory's answer for %s could not be read as JSON, so nothing is reported for it.", value)}
	}
	if response.Found == 0 && len(response.Result) == 0 {
		return nil, nil
	}
	warnings := []string{}
	if response.Found != len(response.Result) {
		warnings = append(warnings, fmt.Sprintf(
			"Breach Directory reported found=%d and sent %d entries for %s; every entry was parsed.",
			response.Found, len(response.Result), value))
	}
	found := make([]breachExposureResult, 0, len(response.Result))
	for _, entry := range response.Result {
		if entry.Email == "" && entry.SHA1 == "" && entry.Password == "" {
			continue
		}
		found = append(found, breachExposureResult{
			Source:  "breachdirectory",
			Email:   strings.TrimSpace(entry.Email),
			Pass:    entry.Password,
			SHA1:    strings.ToLower(strings.TrimSpace(entry.SHA1)),
			Sources: strings.TrimSpace(entry.Sources),
		})
	}
	return found, warnings
}

// breachExposureCrackHashes runs the weakpass chain over every distinct hash the
// search sources produced.
//
// gosearch called weakpass once per BreachDirectory entry
// (`breachdirectory.go:44`), so one account present in forty sources cost forty
// requests to a free third party for the same hash forty times. Distinct hashes
// are asked once here, and the bound is on the number of requests, with the
// overflow stated rather than hidden.
func breachExposureCrackHashes(ctx context.Context, client *http.Client, findings []breachExposureResult, timeout time.Duration, readBytes int64) (map[string]string, []string) {
	hashes := make([]string, 0, len(findings))
	seen := map[string]bool{}
	for _, finding := range findings {
		hash := strings.TrimSpace(finding.SHA1)
		if hash == "" || seen[hash] {
			continue
		}
		seen[hash] = true
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		return nil, nil
	}

	// Deterministic order, so a run with the same answers reports them in the
	// same sequence.
	sort.Strings(hashes)

	warnings := []string{}
	if breachExposureWeakpassCalls > 0 && len(hashes) > breachExposureWeakpassCalls {
		warnings = append(warnings, fmt.Sprintf(
			"%d distinct hashes were reported and weakpass was asked about %d of them, in hash order. A hash beyond the first %d was not looked up; raise the bound in the code or split the run to cover it.",
			len(hashes), breachExposureWeakpassCalls, breachExposureWeakpassCalls))
		hashes = hashes[:breachExposureWeakpassCalls]
	}

	cracked := map[string]string{}
	for _, hash := range hashes {
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		endpoint := breachWeakpassEndpointPrefix + url.PathEscape(hash) + ".json"
		body, status, _, ok := breachExposureFetch(requestCtx, client, "weakpass", endpoint, hash, readBytes)
		cancel()
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"weakpass did not answer for one hash within %s; that hash is reported unhashed-broken, exactly as Breach Directory returned it.", timeout))
			continue
		}
		if status < 200 || status >= 300 {
			warnings = append(warnings, fmt.Sprintf(
				"weakpass answered %d for one hash; it is reported as Breach Directory returned it.", status))
			continue
		}
		var answer struct {
			Pass string `json:"pass"`
		}
		if err := json.Unmarshal([]byte(body), &answer); err != nil {
			warnings = append(warnings, "A weakpass answer could not be read as JSON; that hash is reported as Breach Directory returned it.")
			continue
		}
		if answer.Pass != "" {
			cracked[strings.ToLower(hash)] = answer.Pass
		}
	}
	return cracked, warnings
}

// breachExposureApplyCrack upgrades the findings a crack answers.
//
// The original printed the cracked password **instead of** the entry's own
// password (`breachdirectory.go:45-51`), so an account whose entry carried a
// readable password lost it whenever weakpass also answered. Here the crack wins
// where the entry had no password at all and fills in where it had one, and
// `weakpassed` records which happened — a graph that cannot tell the two apart
// cannot answer "where did this value come from".
func breachExposureApplyCrack(findings []breachExposureResult, cracked map[string]string) {
	for index := range findings {
		password, ok := cracked[strings.ToLower(strings.TrimSpace(findings[index].SHA1))]
		if !ok {
			continue
		}
		if findings[index].Pass == "" {
			findings[index].Pass = password
			findings[index].Weakpassed = true
		}
	}
}

// breachExposureApplyCounts attaches each password's breach count.
//
// A count of zero is written as zero and an unavailable service leaves the field
// absent. Those are different facts and collapsing them would put a `0` next to a
// credential the service simply failed to answer about, which reads as "never
// breached" — the one reading nobody may get from an unanswered service.
func breachExposureApplyCounts(findings []breachExposureResult, counts map[string]int) {
	for index := range findings {
		if count, ok := counts[findings[index].Pass]; ok {
			findings[index].BreachedCount = count
			findings[index].CountKnown = true
		}
	}
}

// breachExposureCracked counts the findings whose password came from weakpass.
func breachExposureCracked(findings []breachExposureResult) []breachExposureResult {
	out := make([]breachExposureResult, 0, len(findings))
	for _, finding := range findings {
		if finding.Weakpassed {
			out = append(out, finding)
		}
	}
	return out
}

// breachExposureEntity turns one finding into a graph entity.
//
// The credential is the payload here — this is the transform whose whole point is
// the value — and every field the source reported is kept, including the
// plaintext and the hash, because the hash is what correlates this credential
// with the same credential seen from another source.
//
// The identity is the **email address** the credential belongs to, not the hash.
// It was the hash first, because a hash is what identifies the same credential
// across two sources, and the live run on 2026-10-07 showed what that costs:
// twenty entities all sharing one identity made the graph show a single node
// twenty times over, and the address — the thing an operator needs to act on —
// was a property on it rather than the key. The hash stays as a property, where
// correlation still works.
func breachExposureEntity(group *breachExposureGroup) transformEntity {
	properties := map[string]interface{}{
		"kind":             "compromised_credential",
		"email":            group.email,
		"credential_count": len(group.credentials),
		// The distinct figure and the source list sit beside the raw count, so a
		// reader can tell "20 rows, 18 distinct" without re-deriving it, and a
		// repeat is visible as a fact rather than hidden by a merge.
		"distinct_credential_count": group.unique(),
		"reporting_sources":         group.sources(),
		"credential_stored":         true,
		"evidence":                  "public_breach_corpus",
	}
	// The scalar fields always name a credential, so the common case — one address,
	// one password — reads without walking the list, and **every** credential and
	// hash is additionally carried in `credentials`. The choice of which one the
	// scalars name is the sort order, not the arrival order, so two runs of the
	// same answer produce the same node; when there is more than one, `credential_count`
	// says so next to the field, so a reader sees that `password` is the first of
	// several rather than the only one.
	if len(group.credentials) > 0 {
		first := group.credentials[0]
		properties["source"] = first.Source
		properties["password"] = first.Pass
		properties["credential"] = first.Pass
		properties["sha1"] = first.SHA1
		properties["password_from_weakpass"] = first.Weakpassed
		if first.Sources != "" {
			properties["breach_sources"] = first.Sources
		}
		// Written only when the count was actually obtained. A zero here would be
		// indistinguishable from "the service failed to answer", and that is the
		// one number nobody may read as reassurance.
		if first.CountKnown {
			properties["password_breach_count"] = first.BreachedCount
		}
	}
	credentials := make([]map[string]interface{}, 0, len(group.credentials))
	for _, credential := range group.credentials {
		row := map[string]interface{}{
			"source":        credential.Source,
			"password":      credential.Pass,
			"sha1":          credential.SHA1,
			"from_weakpass": credential.Weakpassed,
		}
		if credential.CountKnown {
			row["password_breach_count"] = credential.BreachedCount
		}
		if credential.Sources != "" {
			row["breach_sources"] = credential.Sources
		}
		credentials = append(credentials, row)
	}
	properties["credentials"] = credentials
	return entity(group.kind, group.identity, properties,
		map[string]interface{}{"source": "breach_corpus_lookup"})
}

// breachExposureIdentity picks the kind and the identity of a finding.
//
// The address comes first, because that is what an operator acts on and what the
// graph can key on. The hash is the fallback for a finding that arrived without
// an address — a BreachDirectory entry that named only the digest — and it is
// typed `username` rather than `email`, because a SHA-1 is not an address and
// storing it as one would have the graph offer to resolve it as mail.
//
// The kind is decided from the identity itself rather than from the value that
// was queried. Those are different things, and the live run on 2026-10-07 showed
// why: a query for a **username** returned findings that all carried email
// addresses, and typing them by the query would have written twenty email
// addresses into the graph as `username` nodes.
// breachExposureGroup collects everything one identity was seen with.
//
// The live run on 2026-10-07 is why this type exists: ProxyNova answered with
// `al3xis@pravda.ru` **twice** under two different passwords and
// `akkord@pravda.ru` twice under one. Both are legitimate lines in its answer,
// and one node per line would put two nodes at each address — which, since an
// identity plus a kind is the graph's key, means one of the two passwords would
// be stored and the other lost with nothing saying so.
type breachExposureGroup struct {
	kind        string
	identity    string
	email       string
	credentials []breachExposureResult
	// linked records that this group already has an edge to the queried identity,
	// so a second finding for the same address does not add a second edge.
	linked bool
}

// add records one credential for this identity, skipping a repeat of a credential
// already held. The skip is on the whole tuple and not on the identity alone,
// because two entries that agree on every field are one finding reported twice
// and two entries that differ on the password are two findings.
func (group *breachExposureGroup) add(finding breachExposureResult) {
	if group.email == "" {
		group.email = finding.Email
	}
	group.credentials = append(group.credentials, finding)
}

// unique counts the credentials this identity holds without repetition.
//
// Reported beside the raw count because "20 rows, 18 distinct" is a fact about the
// data, while collapsing the two into one number loses whichever one the reader did
// not have in mind. Measured against the original 2026-10-07: ProxyNova sent 20
// rows of which 18 were distinct, the original printed all 20, and a run that
// merged them reported 18 — a smaller number than the source's, with nothing to say
// a filter had eaten rows.
func (group *breachExposureGroup) unique() int {
	seen := make(map[string]bool, len(group.credentials))
	for _, credential := range group.credentials {
		seen[credential.Source+"\x00"+credential.Pass+"\x00"+credential.SHA1+"\x00"+credential.Sources] = true
	}
	return len(seen)
}

// sources lists the distinct sources that reported this identity.
func (group *breachExposureGroup) sources() []string {
	seen := make(map[string]bool, len(group.credentials))
	names := make([]string, 0, len(group.credentials))
	for _, credential := range group.credentials {
		name := strings.TrimSpace(credential.Source)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// sort orders a group's credentials so the one the scalar fields name is the same
// on every run. Without this, `password` on the entity would depend on which
// goroutine finished first, and two reports of the same answer would differ.
func (group *breachExposureGroup) sort() {
	sort.SliceStable(group.credentials, func(left, right int) bool {
		if group.credentials[left].Pass != group.credentials[right].Pass {
			return group.credentials[left].Pass < group.credentials[right].Pass
		}
		return group.credentials[left].Source < group.credentials[right].Source
	})
}

// breachExposureIdentity picks the kind and the identity of a finding.
func breachExposureIdentity(finding breachExposureResult) (string, string) {
	if address := strings.TrimSpace(finding.Email); address != "" {
		return "email", address
	}
	if hash := strings.TrimSpace(finding.SHA1); hash != "" {
		return "username", "sha1:" + hash
	}
	return "username", strings.TrimSpace(finding.Sources)
}
