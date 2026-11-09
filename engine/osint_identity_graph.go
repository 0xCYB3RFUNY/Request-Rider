package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// `identity_graph` — the three identity services gosearch read as modules and the
// project read as bare HTML.
//
// At commit `687f9ed` these are three packages:
//
//	gravatar.go:37    GET https://gravatar.com/<user>.json
//	keybase.go:87     GET https://keybase.io/_/api/1.0/user/lookup.json?usernames=<user>
//	hudsonrock.go:70  GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=<user>
//
// What the project had before this: two URLs in a list inside `email_recon`
// (`osint_transforms.go:737`) — `https://en.gravatar.com/%s` and
// `https://keybase.io/%s` — asked as **HTML** and judged by status code. That is
// not a weaker version of the capability; it is a different question. The HTML
// answers "does this page exist", and Gravatar and Keybase both answer `200` for
// a profile that has nothing on it. The JSON endpoints answer the question the
// modules exist to answer: what does this service hold about this name, and — for
// Gravatar — which accounts does it link to.
//
// HudsonRock was not present at all. `subdomains` reads a **different** HudsonRock
// endpoint (`urls-by-domain`, `osint_transforms.go:4597`) which yields hostnames of
// infected machines and nothing about a person. The module's endpoint returns the
// infostealer log itself: when the machine was hit, which stealer family, the
// computer name, the OS, the malware path, the IP, and the passwords and logins
// the machine held.
//
// The directions differ, so this is one transform with three paths rather than
// three transforms. Measured against the live services 2026-10-08, because the
// first version asked all three the **value itself** and each answered differently
// for an address:
//
//   - **Gravatar** keys an address on the MD5 of its lowercased, trimmed form.
//     Asked the address as typed it answers `404` for every address that *does*
//     have a profile — measured, and silent. Both forms are now asked.
//   - **Keybase** indexes usernames and refuses an address in its `usernames`
//     parameter with `code 100 INPUT_ERROR (bad list value)`, from its own parser
//     rather than from a status code. It has no email-addressable endpoint
//     (`?emails=` and `?email=` both answer `219 MISSING_PARAMETER`), so the local
//     part is the only form of an address it can answer — a candidate, and the
//     entity says so.
//   - **HudsonRock** is asked by address on `search-by-email` and by name on
//     `search-by-username`. These are different endpoints answering about
//     different subjects.
//
// A **username** is asked of all three by name. The question each service was
// actually given is published as `asked_<service>`, because for an address none of
// the three is asked the address itself and "nothing found" is unreadable without
// knowing what was asked.
//
// The stealer log is the strongest thing in this file and the reason it exists: a
// machine that was infected reports what the operator's browser had saved on it,
// which is a fact about the account that no other source in this engine holds.

// identityGraphSources are the services, in the order the original ran them.
const identityGraphSources = "gravatar,keybase,hudsonrock"

// identityGraphDefaults are defaults, not caps. Both are caller-overridable and
// the applied values are published in the run metadata.
const (
	identityGraphDefaultTimeout = 20 * time.Second
	identityGraphDefaultBytes   = 2 << 20
)

// identityGraphUnlimitedBytes is what `max_bytes: 0` means.
const identityGraphUnlimitedBytes = 0

// identityGraphEndpoints are variables so the tests can point them at a fixture
// instead of reaching the internet, and so a mirror can be used without a rebuild.
//
// The hosts and paths are the ones the original used, read from its source at
// `687f9ed`: gravatar.go:47, keybase.go:89, hudsonrock.go:72.
//
// The email endpoint is **`search-by-email`**, not the `stealersbyemail` path the
// original read at `687f9ed`. Measured 2026-10-08 against the live host:
//
//	stealersbyemail?email=… -> HTTP 404 "Cannot GET /api/json/v2/osint-tools/stealersbyemail"
//	search-by-email?email=…  -> HTTP 200 {"message":…,"stealers":[…],…}
//
// The dead path answers `404` with an HTML error page, which the pass read as a
// transport failure and reported as a timeout — a wrong endpoint therefore looked
// exactly like a slow service. That is the same failure shape this file already
// names for every endpoint: a wrong path answers `404`, which is indistinguishable
// from "this service knows nothing about the value".
var (
	identityGraphGravatarEndpoint     = "https://gravatar.com"
	identityGraphKeybaseEndpoint      = "https://keybase.io/_/api/1.0/user/lookup.json"
	identityGraphHudsonRockByUsername = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
	identityGraphHudsonRockByEmail    = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
)

// identityGraphDomainHostPrefix is where the candidates are asked. It is a variable
// so the tests can point all twenty-six at one fixture; the production value is the
// plain `http://` origin the original used.
var identityGraphDomainHostPrefix = "http://"

// identityGraphDomainTLDs is the list `utils.BuildDomains` builds (utils.go:82).
//
// Kept verbatim, because the size of the list is part of what the pass costs and a
// trimmed list would be a bound nobody could see. Twenty-six candidates at one
// request each is the whole price.
var identityGraphDomainTLDs = []string{
	".com", ".net", ".org", ".biz", ".info", ".name", ".pro", ".cat",
	".co", ".me", ".io", ".tech", ".dev", ".app", ".shop", ".fail",
	".xyz", ".blog", ".portfolio", ".store", ".online", ".about",
	".space", ".lol", ".fun", ".social",
}

// identityGraphDomainChecked reports whether one candidate domain answered.
//
// The original counted a domain as found on any non-error status
// (`search.go:66`), which includes `404` and `403` — so it reported a domain as
// registered whenever something answered at all, and a parked page answers `200`
// with nothing on it. The check here is narrower on purpose: a candidate counts
// only when the host answered and said something other than "not here", which is
// the difference between "this name is taken" and "something is listening". Both
// answers are still recorded — the run reports what it saw, not only what it
// counts.
func identityGraphDomainChecked(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusGone, http.StatusMethodNotAllowed:
		return false
	}
	return status >= 200 && status < 400
}

// isIdentityGraphEmail says whether the value is an address rather than a name.
//
// It is a single `@` in a value that has no space or slash, which is what the
// transform's own `accepts` list claims (`email`, `username`) and what the two
// HudsonRock directions are chosen on. It is written out here rather than reused
// from the call site because the Gravatar pass needs it too, and a second
// `strings.Contains(value, "@")` in two places is how the two drift apart.
func isIdentityGraphEmail(value string) bool {
	at := strings.LastIndex(value, "@")
	if at <= 0 || at == len(value)-1 {
		// Nothing on one side of the `@` is not an address: `@handle` is a Mastodon
		// handle and `user@` is a typo, and treating either as an address would
		// send Keybase a value its own parser rejects and Gravatar a digest of
		// nothing.
		return false
	}
	return !strings.ContainsAny(value, " \t\r\n/\\")
}

// identityGraphGravatarDigest is Gravatar's own key for an address.
//
// Measured 2026-10-08, because the pass was asking the wrong question for every
// email and answering it silently:
//
//	gravatar.com/<md5(lower(trim(address)))>.json -> 200 + the real profile
//	gravatar.com/<address>.json                   -> 404 "User not found"
//
// `support@ghost.org` is the live proof of both halves: its MD5 form returns the
// profile with two linked accounts, and the raw-address form returns `404`. A
// username still keys on itself, so the two forms are not interchangeable — the
// pass therefore asks **both** for an address, because the digest is how Gravatar
// publishes a profile for an address and the address itself is how it publishes
// nothing. Asking only the raw form reported "no profile" for addresses that do
// have one, and it reported it without a word, which is the worst of the three
// outcomes: a wrong answer with no trace that a question was mis-asked.
func identityGraphGravatarDigest(address string) string {
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(address))))
	return hex.EncodeToString(sum[:])
}

// identityGraphUsernameCandidate is the part of an address before `@`.
//
// Keybase indexes **usernames**, not addresses, and it says so in the only way it
// can when handed one. Measured 2026-10-08 against the live endpoint:
//
//	lookup.json?usernames=petya@yandex.ru -> {"status":{"code":100,"name":"INPUT_ERROR","desc":"bad list value"}}
//	lookup.json?usernames=petya           -> {"status":{"code":0},"them":[{…}]}
//
// There is no email-addressable Keybase endpoint to fall back to: `?emails=` and
// `?email=` both answer `219 MISSING_PARAMETER`, and `autocomplete.json` answers
// `404`. So the local part is the **only** Keybase-addressable form of an address,
// and it is a candidate rather than the address — `petya@yandex.ru` and
// `petra@yandex.ru` both reduce to a name Keybase may or may not hold.
//
// It is therefore reported as a candidate on the entity, never as the address's
// owner: the whole point of the fix is that the operator can see which question
// was asked. Dropping the Keybase pass for addresses instead would have been the
// smaller change and would have thrown away a real lookup — `petya@yandex.ru` does
// resolve a live Keybase profile with verified proofs, which is exactly the
// strongest linking evidence this transform collects.
func identityGraphUsernameCandidate(value string) (string, bool) {
	if !isIdentityGraphEmail(value) {
		return "", false
	}
	local := strings.TrimSpace(value[:strings.LastIndex(value, "@")])
	if local == "" {
		return "", false
	}
	return local, true
}

// identityGraphDumpSuffix is the extension of the file `utils.WriteToFile` writes
// (`utils.go:45`) — kept so a file written here and a file written by the
// original are recognisably the same artefact.
//
// The mode is **not** kept. The original opens with `os.ModePerm` — 0777,
// world-readable and world-writable — so every plaintext credential it printed also
// landed in a file any account on the machine could read. `0640` keeps the file
// readable by the group the application already runs as and writable by its owner,
// which is the capability without the exposure. This is the one place the port
// deliberately differs from upstream in behaviour rather than in structure, and it
// differs in the direction that does not lose anything.
const identityGraphDumpSuffix = ".txt"

// identityGraphDumpFile is `utils.WriteToFile` and `utils.WriteEmailToFile`, which
// in the original are two functions writing two files: one for the report, one for
// the addresses.
//
// They are ported as **one** file per run, written only when the caller asks for it
// with `dump_file: true`. Three differences from the original, each a measurement:
//
//   - It is opt-in. The original wrote a file on **every** run, unconditionally, so
//     every invocation of a tool left credentials on disk whether the operator
//     wanted a file or not. Here nothing is written unless it is asked for.
//   - The original had a real race: `WriteToFile` locks a mutex (`utils.go:27`) and
//     `WriteEmailToFile` does **not** (`utils.go:56`), while both are called from
//     concurrent goroutines — so addresses were written from several of them into
//     one file. Here the whole dump is assembled in memory and written once.
//   - The addresses go in their own section of the same file rather than a second
//     one, so the two can never disagree about which run produced them.
//
// The path is the directory `dump_path` names, or the operating system's
// temporary directory. Nothing outside it is touched.
func identityGraphDumpFile(result *osintTransformResult, value string, options map[string]interface{}) (string, error) {
	if !identityGraphDumpRequested(options) {
		return "", nil
	}
	directory := strings.TrimSpace(fmt.Sprint(options["dump_path"]))
	if directory == "" {
		directory = os.TempDir()
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", fmt.Errorf("create the report directory %s: %w", directory, err)
	}
	name := value
	for _, character := range `/\:*?"<>|` {
		name = strings.ReplaceAll(name, string(character), "_")
	}
	if name == "" {
		name = "identity"
	}
	path := filepath.Join(directory, name+"_"+time.Now().Format("2006-01-02")+identityGraphDumpSuffix)

	// Both reads go through a typed accessor rather than a type assertion. The
	// metadata is `map[string]interface{}` and `sources` is a **string** while
	// `services_answered` is a slice — asserting the wrong one panics inside the
	// dump, which is the one place in the run where a panic takes the request down
	// after every answer has already been collected.
	services, _ := result.Metadata["sources"].(string)
	answered, _ := result.Metadata["services_answered"].([]string)
	if services == "" {
		services = identityGraphSources
	}

	sections := map[string][]transformEntity{}

	var builder strings.Builder
	builder.WriteString(strings.Repeat("⎯", 85))
	builder.WriteByte('\n')
	builder.WriteString(":: Query                                :  ")
	builder.WriteString(value)
	builder.WriteByte('\n')
	builder.WriteString(":: Written                              :  ")
	builder.WriteString(time.Now().UTC().Format(time.RFC3339))
	builder.WriteByte('\n')
	builder.WriteString(":: Services queried                     :  ")
	builder.WriteString(services)
	builder.WriteByte('\n')
	builder.WriteString(":: Services that answered               :  ")
	builder.WriteString(strings.Join(answered, ", "))
	builder.WriteByte('\n')
	// Each entity is routed to exactly one section, by what it **is** rather than
	// by which service wrote it. The first version filtered on
	// `Properties["service"]` and then also accepted anything with the stealer
	// kind, which put the same compromise record under Gravatar and Keybase as
	// well — three lines for one finding, in a file whose whole purpose is to be
	// read by a person deciding something.
	put := func(section string, item transformEntity) {
		sections[section] = append(sections[section], item)
	}
	for _, item := range result.Entities {
		switch item.Properties["kind"] {
		case "infostealer_compromise":
			put("HudsonRock", item)
		case "identity_profile":
			// The service name is lower-cased in the metadata because it is an id
			// there; the report is read by a person, so it is titled.
			put(strings.Title(strings.ToLower(fmt.Sprint(item.Properties["service"]))), item) //nolint:staticcheck
		case "social_account":
			put("Linked accounts", item)
		case "domain_candidate":
			put("Domain candidates", item)
		}
	}
	for _, label := range []string{"gravatar", "Keybase", "HudsonRock", "Linked accounts", "Domain candidates"} {
		items := sections[label]
		if len(items) == 0 {
			continue
		}
		builder.WriteString("\n:: ")
		builder.WriteString(label)
		builder.WriteByte('\n')
		for _, item := range items {
			builder.WriteString("   ↳ ")
			builder.WriteString(identityGraphDescribe(item))
			builder.WriteByte('\n')
		}
	}

	// The addresses get their own section, and only when there are any. An empty
	// section reads as "checked and found nothing", which is a claim the run may
	// not support, so the section is written only with content.
	var addresses []string
	for _, item := range result.Entities {
		if item.Type == "email" && item.Properties["kind"] != "infostealer_compromise" {
			addresses = append(addresses, item.Identity)
		}
	}
	if len(addresses) > 0 {
		sort.Strings(addresses)
		builder.WriteString("\n:: Emails\n")
		for _, address := range addresses {
			builder.WriteString("   ↳ ")
			builder.WriteString(address)
			builder.WriteByte('\n')
		}
	}
	if len(result.Warnings) > 0 {
		builder.WriteString("\n:: Warnings\n")
		for _, warning := range result.Warnings {
			builder.WriteString("   ↳ ")
			builder.WriteString(warning)
			builder.WriteByte('\n')
		}
	}

	if err := os.WriteFile(path, []byte(builder.String()), 0o640); err != nil {
		return "", fmt.Errorf("write the report %s: %w", path, err)
	}
	return path, nil
}

// identityGraphDescribe renders one entity as one report line.
//
// The stealer record's `top_passwords` and `top_logins` are rendered by hand
// because they are lists, not scalars — and they are the reason a person opens this
// file at all. A generic field walk that only handled strings would have produced a
// line naming the machine and omitted every credential it held, which is a report
// that reads as "nothing useful here".
func identityGraphDescribe(item transformEntity) string {
	fields := []string{item.Identity}
	for _, key := range []string{
		"display_name", "full_name", "location", "stealer_family", "computer_name",
		"operating_system", "malware_path", "date_compromised", "key_id",
		"key_type", "digest", "stellar_account", "username",
	} {
		if value, ok := item.Properties[key].(string); ok && value != "" {
			fields = append(fields, key+"="+value)
		}
	}
	for _, key := range []string{"top_passwords", "top_logins", "devices", "cryptocurrency_addresses"} {
		values, ok := item.Properties[key].([]string)
		if !ok || len(values) == 0 {
			continue
		}
		fields = append(fields, key+": "+strings.Join(values, ", "))
	}
	return strings.Join(fields, "  ")
}

// identityGraphDumpRequested reads the `dump_file` option.
func identityGraphDumpRequested(options map[string]interface{}) bool {
	raw, present := options["dump_file"]
	if !present {
		return false
	}
	switch typed := raw.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return err == nil && parsed
	case float64:
		return typed != 0
	case int:
		return typed != 0
	}
	return false
}

// identityGraphDomainPass is `SearchDomains` — twenty-six candidates of
// `<username><tld>`, asked in parallel and reported as one node each.
//
// It is **off by default**, and that default is published in the run metadata
// rather than applied silently. The reason is measured: twenty-six requests of
// which most answer a parked page is a noisy pass whose hits are mostly other
// people's domains, and an operator who runs the identity lookup for every value
// would pay it every time without choosing to. The option is `check_domains`, so
// the pass is reachable and its absence from a run is a stated fact.
func identityGraphDomainPass(ctx context.Context, client *http.Client, username string, timeout time.Duration, readBytes int64, result *osintTransformResult, _ *transformCollector) (int, error) {
	var (
		waitGroup sync.WaitGroup
		mutex     sync.Mutex
		answers   = make([]int, len(identityGraphDomainTLDs))
		found     int
	)

	for index, tld := range identityGraphDomainTLDs {
		waitGroup.Add(1)
		go func(index int, tld string) {
			defer waitGroup.Done()
			host := strings.ToLower(username) + tld
			requestCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			// Plain HTTP, as the original asked (`search.go:40`). An https probe
			// would answer `404` for a domain that exists and serves nothing on
			// 443, and the difference would read as "not taken".
			request, err := http.NewRequestWithContext(requestCtx, http.MethodGet,
				identityGraphDomainHostPrefix+host+"/", nil)
			if err != nil {
				return
			}
			request.Header.Set("User-Agent", archiveUserAgent())
			request.Header.Set("Accept", "text/html,application/xhtml+xml")
			response, err := client.Do(request)
			if err != nil {
				return
			}
			defer response.Body.Close()
			if _, err := identityGraphDrain(response.Body, readBytes); err != nil {
				return
			}
			mutex.Lock()
			answers[index] = response.StatusCode
			if identityGraphDomainChecked(response.StatusCode) {
				found++
			}
			mutex.Unlock()
		}(index, tld)
	}
	waitGroup.Wait()

	for index, status := range answers {
		if status == 0 {
			continue
		}
		host := strings.ToLower(username) + identityGraphDomainTLDs[index]
		registered := identityGraphDomainChecked(status)
		properties := map[string]interface{}{
			"kind":        "domain_candidate",
			"host":        host,
			"tld":         identityGraphDomainTLDs[index],
			"http_status": status,
			// Stated on the node: a parked page and a site both answer, and the
			// difference is what an operator has to judge.
			"answered": registered,
			"evidence": "http_probe",
			"caveat":   "a non-error status means something answered at this name; it does not mean the account is registered here",
		}
		result.Entities = append(result.Entities, entity("domain", host, properties,
			map[string]interface{}{"source": "domain_candidate_probe"}))
	}
	setTransformMetadata(result, "domains_probed", len(identityGraphDomainTLDs))
	setTransformMetadata(result, "domains_answered", found)
	return found, nil
}

// identityGraphDrain reads and discards a body under the caller's limit.
//
// The status is the answer for a domain probe, so the body is not parsed — but it
// still has to be read off the socket, or the connection is not reusable and the
// next candidate pays for a fresh handshake.
func identityGraphDrain(body io.Reader, readBytes int64) (int64, error) {
	limit := readBytes
	if limit <= identityGraphUnlimitedBytes {
		limit = 64 << 10
	}
	read, err := io.Copy(io.Discard, io.LimitReader(body, limit))
	return read, err
}

// transformIdentityGraph asks the three identity services what they hold.
//
// The three run concurrently because none of them needs another's answer, and each
// has its own deadline: a hung Gravatar must not cost the run its Keybase answer.
func transformIdentityGraph(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED",
			"the identity lookup sends the value to three third-party services")
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return transformError("INVALID_EMAIL", "an email address or username is required")
	}

	isEmail := isIdentityGraphEmail(value)
	timeout := identityGraphTimeout(input.Options)
	readBytes := identityGraphReadBytes(input.Options)
	setTransformMetadata(result, "sources", identityGraphSources)
	setTransformMetadata(result, "lookup", identityGraphLookupKind(isEmail))
	setTransformMetadata(result, "timeout_ms", timeout.Milliseconds())
	setTransformMetadata(result, "max_bytes", int(readBytes))
	setTransformMetadata(result, "body_bytes_unlimited", readBytes == identityGraphUnlimitedBytes)
	retries := identityGraphRetries(input.Options)
	setTransformMetadata(result, "hudsonrock_attempts", retries+1)

	// The question each service is actually asked is published, because for an
	// address none of the three is asked the address itself and the difference is
	// the whole reading of the result: Keybase is asked for the local part, and
	// Gravatar is asked for the MD5 of the address. An operator reading
	// "nothing found" needs to know which question came back empty.
	asked := map[string]string{
		"gravatar":   value,
		"keybase":    value,
		"hudsonrock": value,
	}
	if isEmail {
		asked["gravatar"] = value + " and md5(" + identityGraphGravatarDigest(value) + ")"
		if local, ok := identityGraphUsernameCandidate(value); ok {
			asked["keybase"] = local + " (local part of " + value + ", a candidate)"
		}
		asked["hudsonrock"] = value + " (by address)"
	}
	for service, question := range asked {
		setTransformMetadata(result, "asked_"+service, question)
	}

	// Every pass writes into **its own** result, and the results are merged after
	// the last one finishes. The first version handed the shared `result` to three
	// goroutines at once, which `-race` reported as a real data race: two passes
	// appending to `Entities` is a slice header written by two goroutines at once,
	// and the losing append is not a lost finding but a corrupted slice. The mutex
	// below protected the two local lists and gave a false sense of safety; the
	// shared write was outside it.
	type pass struct {
		name string
		run  func(context.Context, *osintTransformResult) ([]string, error)
	}
	// The list of passes depends on the kind, and the published list says which —
	// so "HudsonRock did not answer" is never confused with "HudsonRock was not
	// asked", and the two are not the same fact.
	newResult := func() *osintTransformResult {
		return &osintTransformResult{
			Transform:   result.Transform,
			ObservedAt:  result.ObservedAt,
			LocalOnly:   true,
			NetworkUsed: true,
			Entities:    []transformEntity{},
			Relations:   []transformRelation{},
			Warnings:    []string{},
		}
	}
	passes := []pass{
		{"gravatar", func(c context.Context, into *osintTransformResult) ([]string, error) {
			return identityGraphGravatar(c, s.toolClient(ctx), value, timeout, readBytes, into)
		}},
		{"keybase", func(c context.Context, into *osintTransformResult) ([]string, error) {
			return identityGraphKeybase(c, s.toolClient(ctx), value, timeout, readBytes, into)
		}},
	}
	// HudsonRock is asked in both directions, and they are **different
	// endpoints**: `stealersbyemail` takes an address, `search-by-username` takes a
	// name (`hudsonrock.go:72`). Asking the username endpoint with an address would
	// answer about a different person, so the direction is chosen rather than
	// guessed.
	if isEmail {
		passes = append(passes, pass{"hudsonrock", func(c context.Context, into *osintTransformResult) ([]string, error) {
			return identityGraphHudsonRockEmail(c, s.toolClient(ctx), value, timeout, readBytes, into)
		}})
	} else {
		passes = append(passes, pass{"hudsonrock", func(c context.Context, into *osintTransformResult) ([]string, error) {
			return identityGraphHudsonRockUsername(c, s.toolClient(ctx), value, timeout, readBytes, into)
		}})
	}

	// The domain pass is opt-in and its default is **published**, not applied
	// silently. The reason is in the registry entry and in the description: 26
	// candidates of which most answer a parked page is a pass whose hits are
	// mostly other people's domains, and every run would pay for it.
	checkDomains := identityGraphCheckDomains(input.Options)
	setTransformMetadata(result, "check_domains", checkDomains)
	setTransformMetadata(result, "domain_candidates", len(identityGraphDomainTLDs))
	if checkDomains {
		passes = append(passes, pass{"domains", func(c context.Context, into *osintTransformResult) ([]string, error) {
			if _, err := identityGraphDomainPass(c, s.toolClient(ctx), value, timeout, readBytes, into, collector); err != nil {
				return nil, err
			}
			return []string{"domains"}, nil
		}})
	}

	result.LocalOnly = false
	result.NetworkUsed = true

	var (
		waitGroup sync.WaitGroup
		mutex     sync.Mutex
		warnings  []string
		ran       []string
		// collected holds one result per pass, in pass order, so the merge below
		// is deterministic: concurrent completion order must not decide what the
		// entity list looks like, or two runs of the same data would differ.
		collected = make([]*osintTransformResult, len(passes))
	)

	for index := range passes {
		if err := collector.checkpoint(ctx); err != nil {
			break
		}
		if collector != nil {
			collector.indexPosition(ctx, passes[index].name, index, len(passes))
		}
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			item := passes[index]
			passCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			// The retry count is bound per pass rather than read inside the read,
			// so the published metadata and the applied behaviour cannot disagree.
			passCtx = withIdentityGraphRetries(passCtx, retries)
			into := newResult()
			collected[index] = into
			_, err := item.run(passCtx, into)
			mutex.Lock()
			if err != nil {
				warnings = append(warnings, err.Error())
			} else {
				// The pass's **name** is what is recorded, not what it returned.
				// A pass that answered "nothing found" returns an empty list, and
				// recording that would have reported a service that answered as
				// one that was never asked — the exact confusion the list exists to
				// prevent.
				ran = append(ran, item.name)
			}
			mutex.Unlock()
		}(index)
	}
	waitGroup.Wait()

	for _, into := range collected {
		if into == nil {
			continue
		}
		result.Entities = append(result.Entities, into.Entities...)
		result.Relations = append(result.Relations, into.Relations...)
		result.Warnings = append(result.Warnings, into.Warnings...)
	}

	setTransformMetadata(result, "services_answered", ran)

	// Deterministic order. Three concurrent services write into one list, and a
	// list that reads differently on every run cannot be diffed against the
	// previous one — which is the only reason anyone keeps two.
	sort.Strings(ran)

	// The file dump is the last thing the run does, and its path is published
	// whether it succeeded or failed. Writing it after every pass means a run that
	// half-answered still leaves a file that says which half.
	written, err := identityGraphDumpFile(result, value, input.Options)
	if err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if written != "" {
		setTransformMetadata(result, "report_path", written)
	}

	result.Warnings = append(result.Warnings, warnings...)
	if len(ran) == 0 {
		result.Warnings = append(result.Warnings,
			"No service answered for "+value+". The names above say which were asked and which did not reply; "+
				"no answer is not the same as no profile.")
	}
	return nil
}

// identityGraphLookupKind names the direction of the lookup, for the metadata and
// for the warnings.
func identityGraphLookupKind(isEmail bool) string {
	if isEmail {
		return "email"
	}
	return "username"
}

// identityGraphGravatar reads `https://gravatar.com/<user>.json`.
//
// The answer is `{"entry":[{hash, requestHash, preferredUsername, displayName,
// aboutMe, emails:[{value}], accounts:[{url, username, name}]}]}`.
//
// Two details the original handled and that are worth keeping:
//
//   - A `404` is "no profile", which is an answer. The original returned early on
//     404 and printed "No Gravatar profile found" — correct, and the project's
//     version has to say the same thing rather than report a parse failure.
//   - An **empty** `entry` is also "no profile" (`gravatar.go:66`), and the
//     original checked it. A `200` with no entry is the shape a service returns
//     when it has nothing, so treating it as an empty result rather than an error
//     is what keeps "no profile" out of the error list.
//
// When `entry` carries no `emails`, the original printed the SHA-256 hash and a
// hashcat command (`gravatar.go:96-104`). The hash is kept — it is the address's
// digest and it identifies the record. The hashcat line is not: it is advice for
// an offline cracking workflow, not a finding, and it does not belong in a graph
// of observations.
func identityGraphGravatar(ctx context.Context, client *http.Client, username string, timeout time.Duration, readBytes int64, result *osintTransformResult) ([]string, error) {
	endpoint := identityGraphGravatarEndpoint + "/" + url.PathEscape(username) + ".json"
	body, status, _, ok := identityGraphFetch(ctx, client, endpoint, readBytes)

	// An address is not a Gravatar username. Gravatar keys an address on the MD5
	// of its lowercased, trimmed form, so the address as typed answers `404` for
	// every address that **does** have a profile — measured, and the miss was
	// silent. The digest form is therefore asked as well, and only for addresses,
	// because a username keys on itself.
	if isIdentityGraphEmail(username) && status == http.StatusNotFound {
		digest := identityGraphGravatarDigest(username)
		digestBody, digestStatus, _, digestOK := identityGraphFetch(ctx, client,
			identityGraphGravatarEndpoint+"/"+digest+".json", readBytes)
		if !digestOK {
			return nil, fmt.Errorf("Gravatar did not answer for %s (by address and by digest) within %s, so nothing is reported for it.",
				username, timeout)
		}
		if digestStatus == http.StatusNotFound {
			return nil, nil
		}
		if digestStatus < 200 || digestStatus >= 300 {
			return nil, fmt.Errorf("Gravatar answered %d for the digest of %s, so nothing is reported for it.", digestStatus, username)
		}
		body, status = digestBody, digestStatus
		username = digest
	}

	if !ok {
		return nil, fmt.Errorf("Gravatar did not answer for %s within %s, so nothing is reported for it.", username, timeout)
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Gravatar answered %d for %s, so nothing is reported for it.", status, username)
	}

	var answer struct {
		Entry []struct {
			Hash              string `json:"hash"`
			RequestHash       string `json:"requestHash"`
			PreferredUsername string `json:"preferredUsername"`
			DisplayName       string `json:"displayName"`
			AboutMe           string `json:"aboutMe"`
			Emails            []struct {
				Value string `json:"value"`
			} `json:"emails"`
			Accounts []struct {
				URL      string `json:"url"`
				Username string `json:"username"`
				Name     string `json:"name"`
			} `json:"accounts"`
		} `json:"entry"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		return nil, fmt.Errorf("Gravatar's answer for %s could not be read as JSON, so nothing is reported for it.", username)
	}
	if len(answer.Entry) == 0 {
		return nil, nil
	}

	entry := answer.Entry[0]
	identity := strings.TrimSpace(entry.RequestHash)
	if identity == "" {
		identity = strings.TrimSpace(entry.PreferredUsername)
	}
	if identity == "" {
		identity = strings.TrimSpace(username)
	}

	properties := map[string]interface{}{
		"kind":          "identity_profile",
		"service":       "gravatar",
		"requested_for": username,
		"display_name":  entry.DisplayName,
		"about":         entry.AboutMe,
		"digest":        entry.Hash,
		"evidence":      "third_party_profile",
	}
	result.Entities = append(result.Entities, entity("username", identity, properties,
		map[string]interface{}{"source": "gravatar_json"}))

	for _, address := range entry.Emails {
		value := strings.TrimSpace(address.Value)
		if value == "" || !strings.Contains(value, "@") {
			continue
		}
		result.Entities = append(result.Entities, entity("email", strings.ToLower(value),
			map[string]interface{}{"source": "gravatar_json"}, map[string]interface{}{"source": "gravatar_json"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "publishes_email",
			SourceType: "username",
			Source:     identity,
			TargetType: "email",
			Target:     strings.ToLower(value),
			Properties: map[string]interface{}{"service": "gravatar"},
		})
	}

	// The linked accounts are the capability the HTML probe could not reach: this
	// is how an email leads to the other places its owner is.
	for _, account := range entry.Accounts {
		link := strings.TrimSpace(account.URL)
		if link == "" {
			continue
		}
		provider := strings.TrimSpace(account.Name)
		if provider == "" {
			provider = identityGraphAccountHost(link)
		}
		result.Entities = append(result.Entities, entity("url", link,
			map[string]interface{}{
				"kind":     "social_account",
				"provider": provider,
				"username": strings.TrimSpace(account.Username),
				"url_main": link,
				"evidence": "third_party_profile",
			}, map[string]interface{}{"source": "gravatar_json"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "accounts_for",
			SourceType: "username",
			Source:     identity,
			TargetType: "url",
			Target:     link,
			Properties: map[string]interface{}{"provider": provider, "service": "gravatar"},
		})
	}
	return []string{"gravatar"}, nil
}

// identityGraphKeybase reads `_/api/1.0/user/lookup.json?usernames=<user>`.
//
// The answer carries a `status.code`: `0` is success and anything else is the
// service saying no (`keybase.go:110`). The original returns a **zero-valued**
// user in that case, which its own display code then reads as "No Keybase profile
// found" — two different outcomes collapsed into one shape, and a service error
// became a statement about the person. Here a non-zero `status.code` is reported
// with its code and name.
func identityGraphKeybase(ctx context.Context, client *http.Client, username string, timeout time.Duration, readBytes int64, result *osintTransformResult) ([]string, error) {
	// Keybase's `usernames` parameter rejects anything that is not a username, and
	// it does so with `code 100 INPUT_ERROR (bad list value)` rather than a status
	// code — so an address reached the service and was turned away by its own
	// parser. The local part is the one form of an address Keybase can answer, and
	// it is a candidate: the entity below says so, in the same place an operator
	// reads everything else about the finding.
	candidate := false
	lookup := username
	if local, ok := identityGraphUsernameCandidate(username); ok {
		lookup = local
		candidate = true
	}

	endpoint := identityGraphKeybaseEndpoint + "?usernames=" + url.QueryEscape(lookup)
	body, status, _, ok := identityGraphFetch(ctx, client, endpoint, readBytes)
	if !ok {
		return nil, fmt.Errorf("Keybase did not answer for %s within %s, so nothing is reported for it.", lookup, timeout)
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Keybase answered %d for %s, so nothing is reported for it.", status, lookup)
	}

	var answer struct {
		Status struct {
			Code int    `json:"code"`
			Name string `json:"name"`
			Desc string `json:"desc"`
		} `json:"status"`
		Them []struct {
			ID     string `json:"id"`
			Basics struct {
				Username      string `json:"username"`
				UsernameCased string `json:"username_cased"`
				Ctime         int64  `json:"ctime"`
				Mtime         int64  `json:"mtime"`
			} `json:"basics"`
			Profile struct {
				FullName string `json:"full_name"`
				Location string `json:"location"`
				Bio      string `json:"bio"`
			} `json:"profile"`
			Pictures struct {
				Primary *struct {
					URL string `json:"url"`
				} `json:"primary"`
			} `json:"pictures"`
			Stellar struct {
				Primary *struct {
					AccountID string `json:"account_id"`
				} `json:"primary"`
			} `json:"stellar"`
			Devices map[string]struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"devices"`
			CryptocurrencyAddresses map[string][]struct {
				Address string `json:"address"`
			} `json:"cryptocurrency_addresses"`
			ProofsSummary struct {
				All []struct {
					ProofType  string `json:"proof_type"`
					Nametag    string `json:"nametag"`
					ServiceURL string `json:"service_url"`
				} `json:"all"`
			} `json:"proofs_summary"`
		} `json:"them"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		return nil, fmt.Errorf("Keybase's answer for %s could not be read as JSON, so nothing is reported for it.", lookup)
	}
	if answer.Status.Code != 0 {
		return nil, fmt.Errorf("Keybase refused the lookup for %s: code %d %s (%s), so nothing is reported for it.",
			lookup, answer.Status.Code, answer.Status.Name, answer.Status.Desc)
	}
	if len(answer.Them) == 0 || answer.Them[0].Basics.Username == "" {
		return nil, nil
	}

	user := answer.Them[0]
	identity := strings.TrimSpace(user.Basics.Username)
	if identity == "" {
		identity = strings.TrimSpace(lookup)
	}
	properties := map[string]interface{}{
		"kind":           "identity_profile",
		"service":        "keybase",
		"requested_for":  username,
		"user_id":        user.ID,
		"username_cased": user.Basics.UsernameCased,
		"full_name":      user.Profile.FullName,
		"location":       user.Profile.Location,
		"bio":            user.Profile.Bio,
		"created_at":     identityGraphUnixTime(user.Basics.Ctime),
		"updated_at":     identityGraphUnixTime(user.Basics.Mtime),
		"evidence":       "third_party_profile",
	}
	if candidate {
		// Stated on the node, because the two are different claims: "Keybase holds
		// a profile called `petya`" and "petya@yandex.ru belongs to that profile"
		// are not the same sentence, and only the first one was established.
		properties["queried_as"] = lookup
		properties["match_basis"] = "email_local_part_candidate"
		properties["caveat"] = "Keybase indexes usernames, not addresses; this is the profile for the part of " +
			"the address before @, and it is not proof that the address belongs to it"
	}
	if user.Pictures.Primary != nil {
		properties["avatar_url"] = user.Pictures.Primary.URL
	}
	if user.Stellar.Primary != nil {
		properties["stellar_account"] = user.Stellar.Primary.AccountID
	}
	// The index is taken **before** appending, because the devices and the coin
	// addresses below are written back onto this entity after the proof links have
	// been added. Writing to `Entities[len-1]` at that point would have landed
	// them on the last proof link instead — which is the shape of bug that only
	// shows up when a profile has proofs.
	profileIndex := len(result.Entities)
	result.Entities = append(result.Entities, entity("username", identity, properties,
		map[string]interface{}{"source": "keybase_json"}))

	// The proofs are the point of Keybase: each is a link the person **verified**.
	// They are the strongest account-linking evidence any of these three services
	// holds, and the original printed them without ever joining them to the
	// profile (`keybase.go:154`).
	for _, proof := range user.ProofsSummary.All {
		target := strings.TrimSpace(proof.ServiceURL)
		if target == "" {
			continue
		}
		properties := map[string]interface{}{
			"kind":     "social_account",
			"provider": identityGraphAccountHost(target),
			"evidence": "third_party_verified_link",
		}
		if proof.Nametag != "" {
			properties["username"] = proof.Nametag
		}
		result.Entities = append(result.Entities, entity("url", target, properties,
			map[string]interface{}{"source": "keybase_json"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "accounts_for",
			SourceType: "username",
			Source:     identity,
			TargetType: "url",
			Target:     target,
			Properties: map[string]interface{}{
				"service":     "keybase",
				"proof_type":  proof.ProofType,
				"verified_by": "keybase",
			},
		})
	}

	// Devices and coin addresses have no place in this graph's kinds, so they ride
	// on the profile rather than becoming nodes of an invented type. Dropping them
	// would be a silent loss, and the registry has to say what happened.
	// The devices map is keyed by a device id and carries the human name inside the
	// value, so the id is kept alongside it: the original printed only type and name
	// sorted (`keybase.go:189`), which loses the id — and the id is what a person
	// would revoke.
	devices := make([]string, 0, len(user.Devices))
	for id, device := range user.Devices {
		label := strings.TrimSpace(device.Name)
		if label == "" {
			label = id
		}
		devices = append(devices, label+" ("+device.Type+", "+id+")")
	}
	sort.Strings(devices)
	if len(devices) > 0 {
		result.Entities[profileIndex].Properties["devices"] = devices
	}
	coins := make([]string, 0)
	for coin, addresses := range user.CryptocurrencyAddresses {
		for _, address := range addresses {
			if strings.TrimSpace(address.Address) != "" {
				coins = append(coins, coin+":"+address.Address)
			}
		}
	}
	sort.Strings(coins)
	if len(coins) > 0 {
		result.Entities[profileIndex].Properties["cryptocurrency_addresses"] = coins
	}
	return []string{"keybase"}, nil
}

// identityGraphHudsonRockByEmailQuery reads the infostealer log for an address.
//
// This is the pass the engine had no equivalent of. `subdomains` reads HudsonRock's
// `urls-by-domain`, which answers "which hostnames appear in infostealer logs" and
// says nothing about a person; this endpoint answers "was a machine holding this
// address's logins infected, and when".
//
// HudsonRock signals "nothing found" with a **prose message**, not a status or an
// empty array (`hudsonrock.go:99`), and the original compared that message against
// a 140-character literal. Comparing prose breaks the moment the sentence is
// reworded — which turns "nothing found" into "compromise detected", the one
// direction of error that gets an innocent person reported. Here the absence of
// `stealers` is what decides, and the message is carried on the result when there
// is one, so the two can never disagree.
func identityGraphHudsonRockEmail(ctx context.Context, client *http.Client, address string, timeout time.Duration, readBytes int64, result *osintTransformResult) ([]string, error) {
	endpoint := identityGraphHudsonRockByEmail + "?email=" + url.QueryEscape(address)
	body, status, _, ok := identityGraphFetchRetry(ctx, client, endpoint, readBytes)
	if !ok {
		return nil, fmt.Errorf("HudsonRock did not answer for %s within %s, so nothing is reported for it.", address, timeout)
	}
	if status == http.StatusNotFound {
		// A `404` here is the service saying the **endpoint** is gone, not that it
		// holds nothing about the address. The two must not read alike: the first
		// is a fault in this code, the second is a finding about the person. This
		// pass is reached only because the path was once `stealersbyemail`, which
		// now answers exactly this, so the distinction is the whole point.
		return nil, fmt.Errorf("HudsonRock answered 404 for %s: the endpoint %s is not served, so nothing is reported for it — "+
			"this is a fault in the request, not a statement about the address.", address, identityGraphHudsonRockByEmail)
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("HudsonRock answered %d for %s, so nothing is reported for it.", status, address)
	}
	return identityGraphStealerLog(address, "email", body, result), nil
}

// identityGraphHudsonRockUsername reads the same log, keyed by username — the
// endpoint the original used (`hudsonrock.go:72`).
func identityGraphHudsonRockUsername(ctx context.Context, client *http.Client, username string, timeout time.Duration, readBytes int64, result *osintTransformResult) ([]string, error) {
	endpoint := identityGraphHudsonRockByUsername + "?username=" + url.QueryEscape(username)
	body, status, _, ok := identityGraphFetchRetry(ctx, client, endpoint, readBytes)
	if !ok {
		return nil, fmt.Errorf("HudsonRock did not answer for %s within %s, so nothing is reported for it.", username, timeout)
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("HudsonRock answered 404 for %s: the endpoint %s is not served, so nothing is reported for it — "+
			"this is a fault in the request, not a statement about the name.", username, identityGraphHudsonRockByUsername)
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("HudsonRock answered %d for %s, so nothing is reported for it.", status, username)
	}
	return identityGraphStealerLog(username, "username", body, result), nil
}

// identityGraphHudsonRockAttempts is how many times a HudsonRock read is tried.
//
// HudsonRock is the slowest of the three and the only one measured to drop
// connections rather than answer: its own free endpoints were observed both at
// ~0.4 s and past 45 s on the same host and the same day. A single dropped
// connection therefore cost the whole pass, and the report said "did not answer",
// which is true of the attempt and false of the service.
//
// It is a **default, not a cap**: `retries` overrides it, zero is honoured as a
// real value, and the applied number is published as `hudsonrock_attempts`. The
// wait between tries is bounded by the run's own deadline rather than by a hidden
// constant, so a caller who lowers `timeout_ms` gets fewer tries, not a longer run.
const identityGraphHudsonRockAttempts = 2

// identityGraphHudsonRockRetryWait is the pause between two HudsonRock tries.
//
// It is short on purpose: the point of the second try is to survive a dropped
// connection, not to wait out a rate limit — a service that is deliberately slow
// should be waited on by the caller's `timeout_ms`, which is visible, rather than
// by a number the caller cannot see.
const identityGraphHudsonRockRetryWait = 400 * time.Millisecond

// identityGraphFetchRetry reads one HudsonRock answer, trying again after a
// dropped connection.
//
// Only a **transport** failure is retried: `client.Do` returning an error means no
// answer was received at all. A `4xx` or `5xx` is a decision the service made and
// repeating the question does not change it, so retrying it would spend the run's
// remaining time on a refusal.
func identityGraphFetchRetry(ctx context.Context, client *http.Client, endpoint string, readBytes int64) (string, int, bool, bool) {
	attempts := identityGraphRetriesFrom(ctx) + 1
	for attempt := 1; ; attempt++ {
		body, status, truncated, ok := identityGraphFetch(ctx, client, endpoint, readBytes)
		if ok || attempt >= attempts {
			return body, status, truncated, ok
		}
		select {
		case <-ctx.Done():
			return body, status, truncated, ok
		case <-time.After(identityGraphHudsonRockRetryWait):
		}
	}
}

// identityGraphRetriesKey carries the applied retry count to the read, because the
// read has no options map of its own.
type identityGraphRetriesKey struct{}

// withIdentityGraphRetries binds the applied retry count to one pass's context.
func withIdentityGraphRetries(ctx context.Context, retries int) context.Context {
	return context.WithValue(ctx, identityGraphRetriesKey{}, retries)
}

// identityGraphRetriesFrom reads the bound retry count.
func identityGraphRetriesFrom(ctx context.Context) int {
	if ctx == nil {
		return identityGraphHudsonRockAttempts - 1
	}
	if value, ok := ctx.Value(identityGraphRetriesKey{}).(int); ok && value >= 0 {
		return value
	}
	return identityGraphHudsonRockAttempts - 1
}

// identityGraphStealerLog reads the shared shape of both HudsonRock endpoints.
func identityGraphStealerLog(subject, subjectKind, body string, result *osintTransformResult) []string {
	var answer struct {
		Message  string `json:"message"`
		Stealers []struct {
			DateCompromised        string      `json:"date_compromised"`
			StealerFamily          string      `json:"stealer_family"`
			ComputerName           string      `json:"computer_name"`
			OperatingSystem        string      `json:"operating_system"`
			MalwarePath            string      `json:"malware_path"`
			IP                     string      `json:"ip"`
			TotalCorporateServices int         `json:"total_corporate_services"`
			TotalUserServices      int         `json:"total_user_services"`
			TopPasswords           []string    `json:"top_passwords"`
			TopLogins              []string    `json:"top_logins"`
			Antiviruses            interface{} `json:"antiviruses"`
		} `json:"stealers"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		result.Warnings = append(result.Warnings,
			"HudsonRock's answer for "+subject+" could not be read as JSON, so nothing is reported for it.")
		return nil
	}
	if len(answer.Stealers) == 0 {
		// Nothing found, said in the service's own words when it gave them. The
		// check is the **absence of stealers**, never the wording.
		if strings.TrimSpace(answer.Message) != "" {
			result.Warnings = append(result.Warnings, "HudsonRock for "+subject+": "+strings.TrimSpace(answer.Message))
		}
		return []string{"hudsonrock"}
	}

	for index, stealer := range answer.Stealers {
		identity := subjectKind + "-stealer:" + subject + "#" + strconv.Itoa(index)
		properties := map[string]interface{}{
			"kind":                     "infostealer_compromise",
			"subject":                  subject,
			"stealer_family":           stealer.StealerFamily,
			"date_compromised":         stealer.DateCompromised,
			"computer_name":            stealer.ComputerName,
			"operating_system":         stealer.OperatingSystem,
			"malware_path":             stealer.MalwarePath,
			"ip":                       stealer.IP,
			"total_corporate_services": stealer.TotalCorporateServices,
			"total_user_services":      stealer.TotalUserServices,
			"top_passwords":            stealer.TopPasswords,
			"top_logins":               stealer.TopLogins,
			"antiviruses":              stealer.Antiviruses,
			// Stated on the entity, so it survives into the export: a compromise
			// record and a guessed password list are different things to read.
			"evidence":                   "infostealer_log",
			"credential_values_returned": true,
		}
		result.Entities = append(result.Entities, entity(subjectKind, identity, properties,
			map[string]interface{}{"source": "hudsonrock_stealer_log"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "compromised_on_device",
			SourceType: subjectKind,
			Source:     subject,
			TargetType: subjectKind,
			Target:     identity,
			Properties: map[string]interface{}{
				"stealer_family":   stealer.StealerFamily,
				"date_compromised": stealer.DateCompromised,
				"computer_name":    stealer.ComputerName,
			},
		})
	}
	return []string{"hudsonrock"}
}

// identityGraphFetch reads one answer, bounded and with a deadline.
func identityGraphFetch(ctx context.Context, client *http.Client, endpoint string, readBytes int64) (string, int, bool, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", 0, false, false
	}
	request.Header.Set("User-Agent", archiveUserAgent())
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return "", 0, false, false
	}
	defer response.Body.Close()

	var reader io.Reader = response.Body
	truncated := false
	if readBytes > identityGraphUnlimitedBytes {
		reader = io.LimitReader(response.Body, readBytes+1)
	}
	body, err := io.ReadAll(reader)
	if int64(len(body)) > readBytes && readBytes > identityGraphUnlimitedBytes {
		body = body[:readBytes]
		truncated = true
	}
	if err != nil {
		return string(body), response.StatusCode, truncated, true
	}
	return string(body), response.StatusCode, truncated, true
}

// identityGraphAccountHost is the host of a profile URL, used as the provider name
// when the service does not name one.
func identityGraphAccountHost(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// identityGraphUnixTime renders a Keybase epoch as RFC 3339, or "" for the zero
// value. A zero epoch is 1970 and would be printed as a real creation date.
func identityGraphUnixTime(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

// identityGraphCheckDomains reads the `check_domains` option.
//
// The default is false and the value is published in the run metadata under the
// same name, so a run without the pass says why it has no domain nodes instead of
// looking like a run that probed 26 names and found nothing.
func identityGraphCheckDomains(options map[string]interface{}) bool {
	raw, present := options["check_domains"]
	if !present {
		return false
	}
	switch typed := raw.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return err == nil && parsed
	case float64:
		return typed != 0
	case int:
		return typed != 0
	}
	return false
}

// identityGraphTimeout reads the per-request deadline.
func identityGraphTimeout(options map[string]interface{}) time.Duration {
	if positiveIntOption(options, "timeout_ms", 0) <= 0 {
		return identityGraphDefaultTimeout
	}
	return time.Duration(positiveIntOption(options, "timeout_ms", 0)) * time.Millisecond
}

// identityGraphRetries reads the caller's `retries`.
//
// Zero is honoured as a real value — "try once, never again" is a decision an
// operator is entitled to make — and an absent or unusable value falls back to the
// published default. `positiveIntOption` cannot be used here because it treats zero
// as "absent", which would make `retries: 0` silently become the default.
func identityGraphRetries(options map[string]interface{}) int {
	raw, present := options["retries"]
	if !present {
		return identityGraphHudsonRockAttempts - 1
	}
	var value int
	usable := true
	switch typed := raw.(type) {
	case float64:
		value = int(typed)
	case int:
		value = typed
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			value = int(parsed)
		} else {
			usable = false
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			value = parsed
		} else {
			usable = false
		}
	default:
		usable = false
	}
	// An unusable value falls back to the default, and a negative one is refused
	// rather than clamped — the same two rules `max_bytes` follows, so a caller
	// who mistypes one option does not silently get a different bound from the
	// other. What is **not** treated as unusable is `0`: "try once" is a decision.
	if !usable || value < 0 {
		return identityGraphHudsonRockAttempts - 1
	}
	return value
}

// identityGraphReadBytes reads the caller's `max_bytes`.
func identityGraphReadBytes(options map[string]interface{}) int64 {
	raw, present := options["max_bytes"]
	if !present {
		return identityGraphDefaultBytes
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
			return identityGraphDefaultBytes
		}
		value = parsed
	default:
		return identityGraphDefaultBytes
	}
	if value < 0 {
		return identityGraphDefaultBytes
	}
	return value
}
