package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// identityCatalogueFile is the vendored catalogue. `go:embed` rather than a
// runtime read: the engine serves this from memory, a missing file must be a
// build failure rather than a feature that silently does nothing, and the file
// has to be present in any deployment of the binary.
//
//go:embed osint_identity_catalogue.json
var identityCatalogueFile []byte

// identitySite is one platform to ask about a username.
//
// The catalogue is the real thing: maigret's and sherlock's, merged, both MIT,
// vendored as `osint_identity_catalogue.json`. It is a file rather than a
// Go literal for three reasons that were all paid for:
//
//   - maigret alone carries 5500 platforms, and 3425 of them describe no URL of
//     their own — they are a Discourse, XenForo or MediaWiki forum, and the
//     fields come from a shared template. A Go literal would have to inline
//     3.4 thousand copies of one template.
//   - the operator can extend it without a rebuild, which is why maigret keeps
//     it in JSON too.
//   - it can be counted. The `counts` block in the file is how we know the
//     catalogue holds 5649 platforms and not the 8 a literal would have.
//
// Detection semantics are maigret's, transcribed rather than reinvented, because
// that part was measured on thousands of real forums:
//
//	presence      no declared `present` markers -> any page counts as presence,
//	              except that a non-ASCII username must appear literally in the
//	              body, since a page that never names it is a generic error page.
//	message       claimed when no `absent` marker matched AND presence holds.
//	status_code   claimed on any 2xx.
//	response_url  claimed on 2xx AND presence, redirects disabled.
type identitySite struct {
	name    string
	main    string
	subpath string
	// url is the profile URL template. `{urlMain}`, `{urlSubpath}` and
	// `{username}` are the placeholders the upstream catalogue uses.
	url string
	// probe is asked instead of `url` when it exists. It is how a platform that
	// renders profiles only after login is asked at all: the vendor's JSON API
	// answers, the HTML page does not.
	probe string
	// check is `status_code`, `message` or `response_url`.
	check   string
	claimed string
	// unclaimed is a name the platform itself says does not exist. It is unused
	// at runtime and carried so that re-measuring this catalogue needs only this
	// file — it is what makes a status answer trustworthy.
	unclaimed string
	present   []string
	absent    []string
	// absentURL is sherlock's `errorUrl` and applies to `response_url`
	// platforms: a substring of the final address that means the profile does
	// not exist. Without it such a platform can say "present" but never "no".
	absentURL string
	// absentCode and presentCode are the status codes this platform itself
	// publishes: `e_code`/`m_code` in WhatsMyName, `not_found_status` in argus.
	//
	// They are not decoration, and they are the reason a global rule could not
	// be right. HackerNews answers `200` for a name that does not exist — only the
	// body says otherwise — and a record that declares `200` as its absence status
	// turns that platform from a "weak maybe yes" into a proper answer. 727 of the
	// 5898 records carry such a code; before this field was read they were all
	// read through one global rule that knew only 404/410/204.
	absentCode  []int
	presentCode []int
	// errors are the platform's own bot-wall and challenge strings. A response
	// containing one is a page about the firewall, not about the account.
	errors map[string]string
	// headers are the platform's own request headers, kept because some platforms
	// answer differently without them.
	headers map[string]string
	// aliases are the other names the same platform carries in the two upstreams.
	// `admire me` and `admireme.vip` are one forum, not two: the merge keeps one
	// record and attaches the other's name here, so an operator filtering by
	// either name still gets the platform, and the run asks the forum once
	// instead of twice. Read from 2026-10-01; before that the 71 duplicated
	// records were separate rows and each was asked separately.
	aliases []string
	// needs is why this record cannot be asked yet — the address names no
	// username, or upstream declares no detection model. The record is kept so
	// the platform is visible in the filter and in `sites_available`, and a run
	// that selects it says this instead of silently dropping it.
	needs  string
	tags   []string
	source string
	engine string
	rank   int
	// noRedirect marks a platform whose redirect means "no account" rather than
	// "no information". Measured: `t.me` answers 200 for a name that exists and
	// 302 to telegram.org for one that does not.
	noRedirect bool
}

// identityCatalogueDoc is the file's shape.
type identityCatalogueDoc struct {
	Sources map[string]struct {
		Project string `json:"project"`
		License string `json:"license"`
		Sites   int    `json:"sites"`
		Engines int    `json:"engines"`
	} `json:"sources"`
	Counts struct {
		Sites            int `json:"sites"`
		OnlyFromSherlock int `json:"only_from_sherlock"`
		EnginesApplied   int `json:"engines_applied"`
		// DuplicatesCollapsed is how many records the build merged into
		// another because they render to the same profile address.
		DuplicatesCollapsed int            `json:"duplicates_collapsed"`
		ByCheck             map[string]int `json:"by_check"`
		BySource            map[string]int `json:"by_source"`
		ByEngine            map[string]int `json:"by_engine"`
	} `json:"counts"`
	Sites map[string]struct {
		Name      string   `json:"name"`
		URL       string   `json:"url"`
		Main      string   `json:"main"`
		Subpath   string   `json:"subpath"`
		Probe     string   `json:"probe"`
		Check     string   `json:"check"`
		Claimed   string   `json:"claimed"`
		Unclaimed string   `json:"unclaimed"`
		Present   []string `json:"present"`
		Absent    []string `json:"absent"`
		// AbsentURL is sherlock's `errorUrl`: for a `response_url` platform it
		// is the substring of the final address that means "no profile". It was
		// carried nowhere before 2026-10-01, and such a platform could only be
		// believed on 2xx plus a body marker.
		AbsentURL string `json:"absent_url"`
		// AbsentCode and PresentCode are the statuses the platform itself
		// publishes for "no profile" and "profile". WhatsMyName calls them
		// `e_code`/`m_code`, argus `not_found_status`.
		AbsentCode  []int             `json:"absent_code"`
		PresentCode []int             `json:"present_code"`
		Errors      map[string]string `json:"errors"`
		// Aliases are the other names the same platform carries in the other
		// upstream. The build collapses records that render to the same profile
		// address into one and keeps the rest of the names here, so filtering by
		// any of them still selects the platform.
		Aliases []string `json:"aliases"`
		// Needs is why a record cannot be asked yet. The record is kept either
		// way: removing it would take the platform out of the filter, the report
		// and the `sites_available` count, and nobody could learn it exists.
		Needs  string   `json:"needs"`
		Tags   []string `json:"tags"`
		Source string   `json:"source"`
		Engine string   `json:"engine"`
		Rank   int      `json:"rank"`
	} `json:"sites"`
}

// loadIdentityCatalogue parses the vendored file.
//
// A parse failure is fatal and says so, because a silently empty catalogue would
// turn the transform into "found nothing" — which reads exactly like "this
// person has no accounts" and is the one answer this tool must never give
// wrongly.
func loadIdentityCatalogue() ([]identitySite, error) {
	var doc identityCatalogueDoc
	if err := json.Unmarshal(identityCatalogueFile, &doc); err != nil {
		return nil, fmt.Errorf("identity catalogue is unreadable: %w", err)
	}
	sites := make([]identitySite, 0, len(doc.Sites))
	for _, raw := range doc.Sites {
		// Records that cannot be asked **right now** are loaded, not dropped.
		// Seven of them exist (2026-10-01, measured): `discord` publishes a
		// probe whose username belongs in a request body, and six publish no
		// detection model at all. Dropping them removed the platform from the
		// filter, the report and the `sites_available` count, so an operator
		// could not even learn they exist — that is losing the record, not
		// filtering it. They are carried with the reason, and the run says so
		// per platform when one is selected.
		needs := raw.Needs
		if raw.URL == "" && raw.Probe == "" {
			needs = "the record carries no address"
		} else if raw.Check == "" {
			needs = "the record declares no detection model"
		} else if !strings.Contains(raw.URL, "{username}") &&
			!strings.Contains(raw.Probe, "{username}") {
			needs = "the address does not carry the username, so the name is expected elsewhere in the request"
		}
		sites = append(sites, identitySite{
			name: raw.Name, main: raw.Main, subpath: raw.Subpath,
			url: raw.URL, probe: raw.Probe, check: raw.Check,
			claimed: raw.Claimed, unclaimed: raw.Unclaimed,
			present: raw.Present, absent: raw.Absent, errors: raw.Errors,
			absentURL:   raw.AbsentURL,
			absentCode:  raw.AbsentCode,
			presentCode: raw.PresentCode,
			aliases:     raw.Aliases,
			needs:       needs,
			tags:        raw.Tags,
			source:      raw.Source,
			engine:      raw.Engine,
			rank:        raw.Rank,
			// Measured, not assumed: `t.me` answers 200 for a name that exists
			// and 302 to telegram.org for one that does not.
			noRedirect: strings.EqualFold(raw.Name, "Telegram"),
		})
	}
	// The catalogue is a JSON object, so Go's map iteration would hand back a
	// different order on every run. Two runs of the same search must produce the
	// same report, otherwise they cannot be diffed.
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].name < sites[j].name })
	return sites, nil
}

// identityCatalogue caches the parsed catalogue.
//
// It is loaded once and shared by every run: the file does not change while the
// process lives, and re-parsing three megabytes per request would be a waste
// that shows up as latency on the one transform that is already slow.
var identityCatalogue struct {
	once  sync.Once
	sites []identitySite
	err   error
}

func identitySites() ([]identitySite, error) {
	identityCatalogue.once.Do(func() {
		identityCatalogue.sites, identityCatalogue.err = loadIdentityCatalogue()
	})
	return identityCatalogue.sites, identityCatalogue.err
}

// identityDefaults size a run that costs one request per platform.
const (
	identityDefaultWorkers = 16
	identityDefaultDelay   = 120 * time.Millisecond
	identityDefaultTimeout = 10 * time.Second
)

// identityUserAgent is an ordinary browser string, and it has to be one: a bot
// User-Agent is what earns the 403 that GitLab and Reddit answer every request
// with. A detector that cannot ask a platform anything is not a detector.
const identityUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// identityBodyLimit bounds how much of a page is read when the detection needs

// the body. It is a prefix, not a refusal: the marker a `message` site keys on
// is in the first kilobyte in practice, and a profile page that puts it in the
// fortieth megabyte is not what the operator is waiting for.
const identityBodyLimit = 512 << 10

// identityUsableSites filters the catalog for this run.
//
// Three things remove a site, and all three are stated to the operator rather
// than silently applied:
//
//   - a named list, so the operator can run one platform or exclude one;
//   - a tag list, so the operator can run "only coding platforms";
//   - `max_sites`, which is a politeness default and not a restriction — 0 means
//     every site the filters left.
func identityUsableSites(options map[string]interface{}) ([]identitySite, error) {
	all, err := identitySites()
	if err != nil {
		return nil, err
	}
	only := lowerSet(stringSliceOption(options, "sites"))
	exclude := lowerSet(stringSliceOption(options, "exclude_sites"))
	tags := lowerSet(stringSliceOption(options, "tags"))
	engines := lowerSet(stringSliceOption(options, "engines"))
	limit := positiveIntOption(options, "max_sites", 0)

	usable := make([]identitySite, 0, len(all))
	for _, site := range all {
		// A platform is selected by **any** of the names it carries. The merge
		// collapsed the duplicates into one record with the other names in
		// `aliases`, so matching only `name` would make the name that lost the
		// merge unroutable: an operator filtering `admireme.vip` would get
		// nothing, and the same run filtering `admire me` would get the forum.
		// Both are the same forum and must be the same answer.
		names := siteIdentityNames(site)
		if len(only) > 0 && !namesIntersect(only, names) {
			continue
		}
		if len(exclude) > 0 && namesIntersect(exclude, names) {
			continue
		}
		if len(tags) > 0 && !siteHasAnyTag(site, tags) {
			continue
		}
		if len(engines) > 0 && !engines[strings.ToLower(site.engine)] {
			continue
		}
		usable = append(usable, site)
		if limit > 0 && len(usable) >= limit {
			break
		}
	}
	return usable, nil
}

// siteIdentityNames is every name one platform answers to: its own plus the
// aliases the merge attached when it collapsed a duplicate record.
func siteIdentityNames(site identitySite) []string {
	names := make([]string, 0, 1+len(site.aliases))
	names = append(names, strings.ToLower(site.name))
	for _, alias := range site.aliases {
		names = append(names, strings.ToLower(alias))
	}
	return names
}

func namesIntersect(wanted map[string]bool, names []string) bool {
	for _, name := range names {
		if wanted[name] {
			return true
		}
	}
	return false
}

func siteHasAnyTag(site identitySite, wanted map[string]bool) bool {
	for _, tag := range site.tags {
		if wanted[strings.ToLower(tag)] {
			return true
		}
	}
	return false
}

func lowerSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, value := range values {
		if trimmed := strings.ToLower(strings.TrimSpace(value)); trimmed != "" {
			out[trimmed] = true
		}
	}
	return out
}

// identityOutcome is one platform's answer.
type identityOutcome struct {
	site      identitySite
	found     bool
	status    int
	detail    string
	skipped   bool
	skippedBy string
	// weak marks an account reported present on weaker evidence than the other
	// findings: a platform that answered 200 without showing its presence
	// marker. It is not a different kind of account, it is a weaker claim, and
	// the graph has to be able to say so.
	weak bool
	// absenceBlind marks a `message` platform that declared no absence marker,
	// so it can report an account but can never report that there is none. Its
	// negative answer is "this record cannot answer", not "no account exists",
	// and the two must not be counted together.
	absenceBlind bool
	// present is whether the platform's own presence rule was satisfied. It is
	// recorded so that a finding made without it is visible as weaker evidence
	// rather than passing for a confirmed account.
	present bool
	// presenceMarker / absenceMarker name the string that decided it, so the
	// operator can check the platform's own words instead of trusting ours.
	presenceMarker string
	absenceMarker  string
	// username is the name that was asked about, kept on the outcome so the URL
	// an operator opens is built from the value that was actually checked
	// rather than reassembled from the catalog. Reassembling it would be a
	// second, unchecked path to the same string.
	username string
}

// carriesUsername reports whether this record's address takes the name, which is
// what makes it askable at all: an address that does not is a landing page, and
// every input would be asked the same question.
func (site identitySite) carriesUsername() bool {
	return strings.Contains(site.url, "{username}") || strings.Contains(site.probe, "{username}")
}

// canOnlyAnswerPresent reports whether this record can say "no".
//
// Measured on the merged catalogue, not assumed: 275 of the 5648 platforms are
// `message` records with an empty `absent` list — 147 from maigret (upstream
// publishes no `absenceStrs` for them either, verified field by field against
// the vendored file) and 128 from the GitLab engine template, where maigret's own
// detection is "the page renders". The first `errorMsg` fix removed 43 of the 150
// `message` records that had arrived from sherlock with no marker at all.
//
// A `message` record with no absence marker is not broken: with a presence
// marker it still reports a real account correctly. It is one-sided, and the
// report has to be able to say which side it is on.
//
// A record whose absent status is **decisive** is not one-sided even with an
// empty `absent` list: 404, 410 and 204 never carry a profile, so a record
// that publishes one of them answers "no" on its own.
//
// A status that is *not* decisive does not lift the record out of being
// one-sided. That is the measured shape of WhatsMyName: 727 records publish
// an absent status and the overwhelming majority of them publish `200`,
// because the platform serves its "no such user" page with 200 and puts the
// verdict in the body. Calling such a record able to say "no" would publish
// its guess as a fact.
func (site identitySite) canOnlyAnswerPresent() bool {
	if site.absentStatusIsDecisive() {
		return false
	}
	return site.check == "message" && len(site.absent) == 0 && !site.noRedirect
}

// absentStatusIsDecisive reports whether this record publishes a status that
// alone means "no profile" — one that can never carry a profile, and that the
// record does not also publish as its present status.
//
// Both halves matter and both were measured. The status half is why a `404`
// record can answer without a body marker. The "not also present" half is why a
// `200` record cannot: WhatsMyName publishes `e_code: 200` **and** `m_code: 200`
// for the same site, which says the code means nothing and only the body does.
func (site identitySite) absentStatusIsDecisive() bool {
	for _, code := range site.absentCode {
		if site.codeIsPresent(code) {
			continue
		}
		if identityStatusMeansGone(code) {
			return true
		}
	}
	return false
}

// codeIsAbsent reports whether the platform itself publishes this status as the
// answer "there is no such profile".
//
// This is not a copy of `identityStatusMeansGone`. That one asks "can this status
// ever carry a profile?" and answers yes for `404`; this one asks "did the
// catalogue record say this status means absent?", and for HackerNews the record
// says `200`. The two disagree on purpose: the record is the platform telling us
// how it speaks, and a record that says nothing falls back to the global rule.
func (site identitySite) codeIsAbsent(status int) bool {
	for _, code := range site.absentCode {
		if code == status {
			return true
		}
	}
	return false
}

// codeIsPresent reports whether the platform publishes this status as the answer
// "the profile is there" — WhatsMyName's `m_code`.
//
// It is carried in the record and it is deliberately **not acted on**, and the
// measurement is why: `m_code` is `404` in 431 of 717 records, which is a default
// a generator filled in rather than something anyone observed. Acting on it would
// manufacture accounts out of a missing observation — a claim with no evidence
// behind it, which is the one thing a username search must not publish. The
// function stays because the data is real and the rule is the right reading of
// it; a later catalogue that measures these statuses properly can be honoured
// without changing anything else.
func (site identitySite) codeIsPresent(status int) bool {
	for _, code := range site.presentCode {
		if code == status {
			return true
		}
	}
	return false
}

// profileURL is the URL an operator opens to look at the answer.
func (outcome identityOutcome) profileURL() string {
	if outcome.site.url == "" || outcome.username == "" {
		return outcome.site.main
	}
	return identityRenderURL(outcome.site, outcome.site.url, outcome.username)
}

// transformUsernameSearch asks every catalogued platform whether it holds this
// username.
//
// This is the transform that replaces `username_enum`, which is local-only and
// deliberately could not enumerate externally. The enumeration now exists, and
// it lives behind the same explicit confirmation every other network transform
// uses.
func transformUsernameSearch(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "the username search queries external platforms")
	}
	username, err := validateUsernameValue(input.Value)
	if err != nil {
		return err
	}
	sites, err := identityUsableSites(input.Options)
	if err != nil {
		return err
	}
	if len(sites) == 0 {
		return transformError("NO_SITES_SELECTED", "no platforms matched the site, exclude or tag filters")
	}
	result.LocalOnly = false
	result.NetworkUsed = true

	workers := positiveIntOption(input.Options, "concurrency", identityDefaultWorkers)
	if workers <= 0 {
		workers = 1
	}
	delay := identityDelay(input.Options)
	timeout := identityTimeout(input.Options)

	setTransformMetadata(result, "username", username)
	setTransformMetadata(result, "sites_available", len(identityCatalogue.sites))
	setTransformMetadata(result, "sites_requested", len(sites))
	setTransformMetadata(result, "concurrency", workers)
	setTransformMetadata(result, "delay_ms", delay.Milliseconds())
	setTransformMetadata(result, "timeout_ms", timeout.Milliseconds())
	setTransformMetadata(result, "source_ip", result.SourceIP)

	if collector != nil {
		collector.setIndexTotal(ctx, len(sites))
	}

	client := s.toolClient(ctx)
	outcomes := runIdentityChecks(ctx, client, sites, username, workers, delay, timeout, collector)

	found, weak, absent, skipped, oneSided := 0, 0, 0, 0, 0
	for _, outcome := range outcomes {
		if outcome.skipped {
			skipped++
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"%s did not give a usable answer about %q: %s",
				outcome.site.name, username, outcome.skippedBy))
			continue
		}
		if outcome.found {
			found++
			if outcome.weak {
				weak++
			}
			result.Entities = append(result.Entities, identitySiteEntity(outcome))
		} else if outcome.absenceBlind {
			// The platform answered, and its answer was "no" — but only because
			// the record carries no string that could have said no. Counting this
			// as `sites_absent` would publish a gap in our catalogue as a fact
			// about a person, which is the one claim this transform must not make
			// wrongly. It gets its own counter and its own warning.
			oneSided++
		} else {
			// Only a platform that actually answered counts as absent. Counting a
			// platform that was never asked would turn "we did not look" into
			// "there is nothing there", which are opposite claims.
			absent++
		}
		result.Relations = append(result.Relations, transformRelation{
			Type:       "registered_as",
			SourceType: "username",
			Source:     username,
			TargetType: "url",
			Target:     outcome.profileURL(),
		})
	}

	setTransformMetadata(result, "sites_found", found)
	setTransformMetadata(result, "sites_found_weak", weak)
	setTransformMetadata(result, "sites_absent", absent)
	setTransformMetadata(result, "sites_absence_blind", oneSided)
	setTransformMetadata(result, "sites_skipped", skipped)
	setTransformMetadata(result, "sites_answered", found+absent+oneSided)
	if oneSided > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d of the %d platforms that answered reported no account, but their catalogue record carries no absence marker, so they cannot tell \"no profile\" from \"this platform did not say\". They are counted separately from the %d that can, and are not evidence that %q has no account there.",
			oneSided, found+absent+oneSided, absent, username))
	}

	if found == 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"No catalogued platform reports an account for %q out of the %d asked. That is a statement about those platforms at this moment: a platform that gates its profile page behind a login answers every visitor the same way, and one that has renamed its routes answers 404 for a real account.",
			username, len(sites)))
	}
	return nil
}

// runIdentityChecks asks the platforms concurrently and returns the outcomes in
// the order the sites were given.
//
// Concurrency is the point: twenty sequential profile pages is twenty sequential
// round trips, and the pause between them would dominate the run. The pause is
// kept as a per-request gate rather than a sleep between everything, so the
// politeness bound is on the rate and not on the duration.
func runIdentityChecks(
	ctx context.Context,
	client *http.Client,
	sites []identitySite,
	username string,
	workers int,
	delay, timeout time.Duration,
	collector *transformCollector,
) []identityOutcome {
	outcomes := make([]identityOutcome, len(sites))
	var wait sync.WaitGroup
	slots := make(chan struct{}, workers)
	// answered counts the platforms that have finished, so the panel moves while
	// the run is still going.
	//
	// It was reported only after `wait.Wait()` below, in catalogue order, which
	// made the log tidy and the panel useless: a run over the full catalogue is
	// 5897 requests, and the operator watched `0 / 5897` for the whole of it —
	// measured 2026-10-01 at 323 s and still 0. A counter that never moves reads
	// as a hung tool, and a hung tool is the one reading an operator cannot act
	// on. The final catalogue-order pass is kept, so the last state an operator
	// reads is still the order the catalogue declares.
	var answered atomic.Int64

	for index, site := range sites {
		if ctx.Err() != nil {
			// The remaining slots are still zero-valued, and a zero-valued site
			// would be reported as a platform named "" that found an account at
			// "". Every slot is filled with a named refusal instead, so a
			// cancelled run reports how far it got rather than how many
			// nameless accounts it invented.
			for remaining := index; remaining < len(sites); remaining++ {
				outcomes[remaining] = identityOutcome{
					site: sites[remaining], username: username,
					skipped: true, skippedBy: "run cancelled before this platform was asked",
				}
			}
			break
		}
		wait.Add(1)
		go func(index int, site identitySite) {
			defer wait.Done()
			// Reported from a defer so every exit counts: asked, refused,
			// cancelled and skipped all advance the panel, because a platform
			// that was never asked is not a platform still waiting.
			defer func() {
				if collector != nil {
					collector.indexPosition(ctx, site.name, int(answered.Add(1)), len(sites))
				}
			}()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				outcomes[index] = identityOutcome{
					site: site, username: username, skipped: true, skippedBy: "run cancelled",
				}
				return
			}
			defer func() { <-slots }()

			// The gate is per request, so it caps the rate without serialising
			// the whole run behind one sleep.
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					outcomes[index] = identityOutcome{
						site: site, username: username, skipped: true, skippedBy: "run cancelled",
					}
					return
				}
			}
			if err := collector.checkpoint(ctx); err != nil {
				outcomes[index] = identityOutcome{
					site: site, username: username, skipped: true, skippedBy: "run cancelled",
				}
				return
			}
			outcomes[index] = probeIdentitySite(ctx, client, site, username, timeout)
		}(index, site)
	}
	wait.Wait()

	// Progress is reported after the fan-out, in catalog order, so the sequence
	// an operator reads in the log is the sequence the catalog declares rather
	// than the order the network happened to answer in.
	//
	// The count is `index + 1`, not `index`: the loop variable is the position
	// being published, and the number of platforms **finished** after it is one
	// more than its position. Passing the index made a completed run of 6 read
	// "5 / 6" — a panel that understated the work by one on every run, which is
	// the kind of small wrongness that trains an operator to distrust it.
	if collector != nil {
		for index := range outcomes {
			collector.indexPosition(ctx, outcomes[index].site.name, index+1, len(sites))
		}
	}
	return outcomes
}

// identityAsk makes one request at a platform with the headers its catalogue
// record declares. The headers are per platform because the catalogue was
// written by people who read that platform's behaviour, and they win over ours.
func identityAsk(ctx context.Context, client *http.Client, site identitySite,
	method, endpoint string, timeout time.Duration) (*http.Response, error) {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	// The cancel is deliberately not deferred to the caller: the response body is
	// still being read after this function returns, and cancelling on return
	// would cut the body off mid-read. The context is released when the body is
	// closed, which is the only point at which it is no longer needed.
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	request.Header.Set("User-Agent", identityUserAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	for name, value := range site.headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		cancel()
		return nil, err
	}
	response.Body = &cancelOnClose{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

// cancelOnClose releases the request's context when the body is closed, which is
// the only moment the deadline is no longer needed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelOnClose) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

// identityStatusRefusesMethod reports whether a status means "this route does
// not take that method", which is the platform refusing HEAD rather than
// answering the question.
//
// Measured: the Aparat API answers `GET` with `200` for a real account and `404`
// for a name that does not exist, and answers `HEAD` with `405` on the same
// route. Reading that `405` as "no account" reported an existing account as
// absent, which the live comparison against the original sherlock found.
func identityStatusRefusesMethod(status int) bool {
	switch status {
	case http.StatusNotImplemented, http.StatusMethodNotAllowed,
		http.StatusBadGateway, http.StatusServiceUnavailable:
		return true
	}
	return false
}

// probeIdentitySite asks one platform and reads the answer.
func probeIdentitySite(ctx context.Context, client *http.Client, site identitySite, username string, timeout time.Duration) identityOutcome {
	endpoint, ok := identityProbeURL(site, username)
	if !ok {
		reason := "no usable URL for this username"
		if site.needs != "" {
			// The catalogue's own reason, not a generic refusal: the operator
			// learns that the platform exists and what is missing, instead of a
			// message that reads as "this platform says nothing".
			reason = site.needs
		}
		return identityOutcome{site: site, username: username, skipped: true, skippedBy: reason}
	}
	endpointURL, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return identityOutcome{site: site, username: username, skipped: true, skippedBy: "the platform address could not be parsed"}
	}
	// A status-code platform is decided by the code alone, so its body is never
	// read. HEAD is the request that says so: the answer is the same and the page
	// is not downloaded in order to be thrown away. maigret asks the same way.
	// Measured reason: 2838 of the 5577 records are `status_code`, so a full run
	// that fetched every profile page downloaded megabytes to learn "200".
	//
	// It is a preference, not a rule, and the reason it is not a rule is
	// measured: the Aparat API answers `GET` with `200` for a real account and
	// `404` for a name that does not exist — a perfect `status_code` detector —
	// and answers **`HEAD` with `405`**, because the method is not allowed on
	// that route. A blanket HEAD therefore turned a found account into "absent",
	// and the live comparison against the original sherlock caught it. So a
	// platform that refuses the method is asked again with GET, and the refusal
	// is what triggers the second request, not a guess about the platform.
	method := http.MethodGet
	if site.check == "status_code" {
		method = http.MethodHead
	}
	response, err := identityAsk(ctx, client, site, method, endpoint, timeout)
	if err != nil {
		return identityOutcome{site: site, username: username, detail: identityErrorSummary(err)}
	}
	if method == http.MethodHead && identityStatusRefusesMethod(response.StatusCode) {
		response.Body.Close()
		method = http.MethodGet
		response, err = identityAsk(ctx, client, site, method, endpoint, timeout)
		if err != nil {
			return identityOutcome{site: site, username: username, detail: identityErrorSummary(err)}
		}
	}
	defer response.Body.Close()

	outcome := identityOutcome{site: site, username: username, status: response.StatusCode}

	// A redirect is never read as a body. Where the platform's redirect means
	// "no account" it is the answer; anywhere else it says nothing, because the
	// landing page's text has nothing to do with the account that was asked
	// about. `t.me` sent every missing name to telegram.org, whose page happened
	// to carry the marker phrase — three runs, three false positives.
	//
	// The one redirect that IS an answer is a `response_url` platform whose own
	// `errorUrl` names where it sends a missing profile: the catalogue states
	// the destination, so following the pointer is reading the platform's
	// decision rather than guessing from a landing page's text. It is checked
	// before the generic branch because it is the more specific rule.
	// A redirect is followed once. The original sherlock follows redirects, and
	// refusing to follow lost a real account: 9GAG answers 301 to
	// `http://9gag.com/u/<name>` and AdmireMe.Vip answers 301 to `/<name>/`, so a
	// run that stopped at the 3xx reported neither. Measured on the same seven
	// platforms on 2026-10-01: the original found 5 accounts, we found 0 while
	// refusing every redirect, and after the fix 3 — the two lost are these.
	//
	// What the refusal protected against is kept in the two forms that have
	// evidence behind them. A platform whose record says its redirect means "no
	// account" (`noRedirect`, measured on `t.me`, which sent every missing name to
	// telegram.org whose page carried the marker phrase — three runs, three false
	// positives), and a platform that names its own not-found destination
	// (`errorUrl`, read from the same upstream that publishes the redirect
	// behaviour). A redirect to an ordinary landing page is then judged by that
	// page's own markers, which is what the original does.
	if isIdentityRedirect(response.StatusCode) {
		location := response.Header.Get("Location")
		if site.noRedirect {
			outcome.found = false
			outcome.detail = fmt.Sprintf("HTTP %d redirect to %s — this platform redirects a missing profile, read as absent",
				response.StatusCode, location)
			return outcome
		}
		if site.absentURL != "" && strings.Contains(location, site.absentURL) {
			outcome.found = false
			outcome.absenceMarker = site.absentURL
			outcome.detail = fmt.Sprintf(
				"HTTP %d redirect to %s — that is the platform's own %q, read as no profile",
				response.StatusCode, location, site.absentURL)
			return outcome
		}
		// `Location` may be absolute (`https://9gag.com/u/adam`, which 9GAG sends)
		// or relative (`/adam/`, which AdmireMe.Vip sends). Both are answered
		// correctly on the wire; reading an absolute one as a path would ask
		// `https://9gag.com/https://9gag.com/u/adam`.
		target, targetErr := url.Parse(location)
		if targetErr != nil {
			outcome.skipped = true
			outcome.skippedBy = fmt.Sprintf("HTTP %d redirect to %q, which is not an address", response.StatusCode, location)
			return outcome
		}
		if !target.IsAbs() {
			target = endpointURL.ResolveReference(target)
		}
		if target.String() == endpointURL.String() {
			outcome.skipped = true
			outcome.skippedBy = fmt.Sprintf("HTTP %d redirect to the address already asked", response.StatusCode)
			return outcome
		}
		if site.check == "response_url" && site.absentURL != "" &&
			strings.Contains(target.String(), site.absentURL) {
			outcome.found = false
			outcome.absenceMarker = site.absentURL
			outcome.detail = fmt.Sprintf(
				"HTTP %d redirect to %s — that is the platform's own %q, read as no profile",
				response.StatusCode, location, site.absentURL)
			return outcome
		}
		response.Body.Close()
		second, secondErr := identityAsk(ctx, client, site, method, target.String(), timeout)
		if secondErr != nil {
			outcome.skipped = true
			outcome.skippedBy = fmt.Sprintf("HTTP %d redirect that could not be followed: %s",
				response.StatusCode, identityErrorSummary(secondErr))
			return outcome
		}
		// The destination may also refuse the method, exactly as the first
		// address did: a `status_code` platform that redirects to a JSON route
		// which takes GET only would otherwise be read as "no account".
		if method == http.MethodHead && identityStatusRefusesMethod(second.StatusCode) {
			second.Body.Close()
			method = http.MethodGet
			second, secondErr = identityAsk(ctx, client, site, method, target.String(), timeout)
			if secondErr != nil {
				outcome.skipped = true
				outcome.skippedBy = "the redirect destination could not be asked with GET: " + identityErrorSummary(secondErr)
				return outcome
			}
		}
		defer second.Body.Close()
		redirectedFrom := outcome.status
		response = second
		outcome.status = second.StatusCode
		outcome.detail = fmt.Sprintf("HTTP %d redirected to %s, which answered %d",
			redirectedFrom, target, second.StatusCode)
	}

	// A refusal is not an answer, and reading it as one is the false positive
	// this whole file is built against. GitLab answers 403 to a rate-limited
	// client with the same body it serves a real profile, and because its record
	// declares no presence marker (`message` with `absent: ["[]"]` and no
	// `presenseStrs`) a 403 read as "not absent" reads as a confirmed account.
	//
	// These statuses say the platform refused the question: it did not look, so
	// it cannot have said no and certainly did not say yes. They are skipped with
	// the status named, never counted as absent and never counted as found.
	if identityStatusIsRefusal(response.StatusCode) {
		outcome.skipped = true
		outcome.skippedBy = fmt.Sprintf(
			"HTTP %d — the platform refused the question, which is not an answer about this account",
			response.StatusCode)
		return outcome
	}

	body := readIdentityBody(response.Body)

	// A declared error string means the platform served a firewall rather than
	// the page. Reading that page as a profile is the commonest false positive on
	// real forums, and the catalogue already names the strings for the platforms
	// that publish them.
	for marker, meaning := range site.errors {
		if marker != "" && strings.Contains(body, marker) {
			outcome.skipped = true
			outcome.skippedBy = "the platform served a known error page (" + meaning + ")"
			return outcome
		}
	}

	// Presence, as maigret defines it: with no declared markers any page counts,
	// except that a non-ASCII username has to appear literally, because a page
	// that never names it is a generic page and not a profile.
	present := true
	switch {
	case len(site.present) > 0:
		present = false
		for _, marker := range site.present {
			if marker != "" && strings.Contains(body, marker) {
				present = true
				outcome.presenceMarker = marker
				break
			}
		}
	default:
		if hasNonASCII(username) && !strings.Contains(body, username) {
			present = false
			outcome.detail = "the page never names the username, so it is a generic page rather than a profile"
		}
	}
	outcome.present = present

	// A status the record publishes is read before the generic rules, because it
	// is the platform telling us how it speaks — but **only an absent status that
	// is decisive**, and "decisive" is much narrower than it looks.
	//
	// Two measurements set that bar, and both cut the gain down:
	//
	//   - `e_code` is `200` in 707 of WhatsMyName's 717 records. That is not "the
	//     profile is missing, trust the status", it is "this platform serves its
	//     absent page with 200 and the body says which it is". Honouring it alone
	//     destroyed the record: on the live fixture it took `sites_found` from 2
	//     to 0, declaring real accounts missing.
	//   - `m_code` is `404` in 431 of 717 — a **default**, not a measurement, so a
	//     published present status cannot be trusted to produce an account either.
	//     It is carried as data and never acted on.
	//
	// What is left is the case the field exists for: a status that can never carry
	// a profile (404/410/204), published as absent and not also published as
	// present. 13 of the 5898 records are in that state, `linkedin`
	// (`absent_code: [404, 999]`, no `present_code`) among them. Small is the
	// honest number: 727 records publish a code, and 13 of them publish one that
	// decides anything by itself.
	if site.absentStatusIsDecisive() && site.codeIsAbsent(response.StatusCode) {
		outcome.found = false
		outcome.absenceBlind = false
		outcome.absenceMarker = fmt.Sprintf("HTTP %d, the platform's own absent status", response.StatusCode)
		outcome.detail = fmt.Sprintf("HTTP %d — the record publishes this status as %q, and a status "+
			"that can never carry a profile is not published as %q, so the status itself is the answer",
			response.StatusCode, "absent", "present")
		return outcome
	}

	switch site.check {
	case "status_code":
		outcome.found = response.StatusCode >= 200 && response.StatusCode < 300
	case "response_url":
		// sherlock's `errorUrl`: a final address carrying this substring is the
		// platform's own way of saying the profile is not there. It is checked
		// before the 2xx test, because a platform that answers 200 with its own
		// "user not found" page would otherwise pass as an account.
		if site.absentURL != "" && strings.Contains(response.Request.URL.String(), site.absentURL) {
			outcome.found = false
			outcome.absenceMarker = site.absentURL
			outcome.detail = fmt.Sprintf("HTTP %d, final address %s carries the platform's own %q — read as no profile",
				response.StatusCode, response.Request.URL, site.absentURL)
			return outcome
		}
		outcome.found = response.StatusCode >= 200 && response.StatusCode < 300 && present
	default:
		absent := false
		for _, marker := range site.absent {
			if marker != "" && strings.Contains(body, marker) {
				absent = true
				outcome.absenceMarker = marker
				break
			}
		}
		// Both halves, not one. A `message` platform that declares no presence
		// marker would report every username as found the moment the absence
		// marker is gone, and the presence half is what stops it.
		outcome.found = !absent && present
		if outcome.found && len(site.present) == 0 && outcome.presenceMarker == "" {
			outcome.weak = true
			if outcome.detail == "" {
				outcome.detail = fmt.Sprintf("HTTP %d, no absence marker present, but the platform declares no presence marker",
					response.StatusCode)
			}
		}
		// A `message` platform with no absence marker can still say "present",
		// but it structurally cannot say "no": with nothing to match, every
		// answer it gives is a positive one. That is a property of the upstream
		// record rather than of this run, so it is decided once per platform —
		// and it is recorded, because counting such a platform as "absent" is
		// how a catalogue gap would be published as a fact about a person.
		if !absent && site.canOnlyAnswerPresent() {
			outcome.absenceBlind = true
		}
	}

	if outcome.detail == "" {
		outcome.detail = fmt.Sprintf("HTTP %d, presence=%v", response.StatusCode, present)
	}
	// No platform serves a profile with 404 or 410, whatever its markers say, so
	// that status settles the question after everything above has run.
	if outcome.found && identityStatusMeansGone(response.StatusCode) {
		outcome.found = false
		outcome.detail += " — but this status never carries a profile"
	}
	return outcome
}

// hasNonASCII reports whether a string has a non-ASCII rune, which is what
// maigret calls a non-ASCII username.
func hasNonASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return true
		}
	}
	return false
}

// isIdentityRedirect reports whether a status is a redirect.
//
// The shared `toolClient` answers every redirect with `ErrUseLastResponse`, so a
// redirect here is a final answer rather than a question, and each detection has
// to decide what it means instead of letting the client resolve it.
func isIdentityRedirect(status int) bool {
	return status >= 300 && status < 400
}

// identityStatusMeansGone reports whether a status can only mean "no account".
//
// These codes are the HTTP way of saying the resource is not there, and no
// platform answers a profile with one of them. A body may still contain
// something, but that something is an error page, not a person.
func identityStatusMeansGone(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusGone, http.StatusNoContent:
		return true
	}
	return false
}

// identityStatusIsRefusal reports whether a status means "the platform did not
// answer", as opposed to "the account is not there".
//
// The distinction is not cosmetic. GitLab answers 403 to a rate-limited or
// bot-detected client with the same body shape it serves a real profile, and its
// catalogue record declares no presence marker at all (`check: message`,
// `absent: ["[]"]`, no `presenseStrs`) — so a 403 read as "the absence marker
// is not in the body" is a confirmed account that does not exist. That is the
// false positive the counters and the `weak` flag exist to prevent, and it was
// reachable before this check.
//
// 429 and 5xx are here for the same reason: a platform that is busy has not
// looked. 401 and 403 are access decisions, not answers about a name.
func identityStatusIsRefusal(status int) bool {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden,
		status == http.StatusTooManyRequests,
		status == http.StatusRequestTimeout,
		status == http.StatusProxyAuthRequired,
		status == 407, status == 451:
		return true
	case status >= 500:
		return true
	}
	return false
}

// identityRenderURL expands a catalogue URL template.
//
// Three placeholders, all from upstream: `{urlMain}` and `{urlSubpath}` describe
// the installation, and `{username}` is the name. A template naming an unknown
// placeholder is refused rather than sent — a URL still containing `{...}` would
// be asked once for every input and return the same page each time.
func identityRenderURL(site identitySite, template, username string) string {
	rendered := strings.NewReplacer(
		"{urlMain}", site.main,
		"{urlSubpath}", site.subpath,
		"{username}", url.PathEscape(username),
	).Replace(template)
	return rendered
}

// identityProbeURL builds the URL to ask about.

// A site may declare a separate `probe`: the visible profile URL can be a poor
// question — a platform that redirects every input to the same canonical path
// answers 302 whatever the username is — while the canonical path itself
// distinguishes an account from a 404. The probe is what gets asked in that
// case, and the template stays the URL the operator is given to open.
func identityProbeURL(site identitySite, username string) (string, bool) {
	// The probe is only preferred when it can actually be asked about this
	// name. `anilist` publishes `urlProbe: https://graphql.anilist.co/` — a
	// bare GraphQL endpoint whose query lives in a body we do not send — while
	// its profile URL is an ordinary `https://anilist.co/user/{username}/`.
	// Preferring the probe unconditionally asked the bare endpoint, found no
	// username in the rendered address, and refused the platform outright: the
	// original sherlock finds that account and we reported "no usable URL".
	template := site.probe
	if template == "" || !strings.Contains(template, "{username}") {
		template = site.url
	}
	if template == "" {
		return "", false
	}
	endpoint := identityRenderURL(site, template, username)
	// A template that does not take the username would ask about the same page
	// for every input, and every username would get the same answer.
	if strings.Contains(endpoint, "{") || !strings.Contains(endpoint, url.PathEscape(username)) {
		return "", false
	}
	return endpoint, true
}

// readIdentityBody reads a prefix of the response for a marker check.
func readIdentityBody(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, identityBodyLimit))
	if err != nil && len(data) == 0 {
		return ""
	}
	return string(data)
}

// identityErrorSummary names a transport failure without pretending it is a
// verdict on the account.
func identityErrorSummary(err error) string {
	message := err.Error()
	if index := strings.LastIndex(message, ": "); index > 0 && index+2 < len(message) {
		message = message[index+2:]
	}
	return "request failed: " + message
}

// identityDelay reads the pause between requests.
func identityDelay(options map[string]interface{}) time.Duration {
	raw, present := options["delay_ms"]
	if !present {
		return identityDefaultDelay
	}
	var milliseconds int
	switch typed := raw.(type) {
	case float64:
		milliseconds = int(typed)
	case int:
		milliseconds = typed
	}
	if milliseconds < 0 {
		return 0
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// identityTimeout reads the per-request deadline.
//
// It is a deadline on a hung socket, not a budget on the work: twenty slow
// platforms that each answer in nine seconds are a legitimate answer, and a
// timeout that cut them off would report "absent" for every one.
func identityTimeout(options map[string]interface{}) time.Duration {
	if positiveIntOption(options, "timeout_ms", 0) <= 0 {
		return identityDefaultTimeout
	}
	return time.Duration(positiveIntOption(options, "timeout_ms", 0)) * time.Millisecond
}

// identitySiteEntity turns a found account into a graph entity.
//
// The evidence is kept on the entity because "this platform answered 200" and
// "this platform redirected to its login page" are very different claims, and a
// graph that showed only the URL would flatten them into one.
func identitySiteEntity(outcome identityOutcome) transformEntity {
	properties := map[string]interface{}{
		"kind":        "social_account",
		"site":        outcome.site.name,
		"url_main":    outcome.site.main,
		"detection":   outcome.site.check,
		"http_status": outcome.status,
		"evidence":    outcome.detail,
		"catalog":     outcome.site.source,
	}
	if len(outcome.site.tags) > 0 {
		properties["tags"] = outcome.site.tags
	}
	if outcome.weak {
		// Stated on the entity rather than only in a warning, so it survives
		// into the export. A warning is read once; a graph node is looked at
		// again days later when the decision is actually made.
		properties["evidence_strength"] = "weak"
	}
	return entity("url", outcome.profileURL(), properties,
		map[string]interface{}{"source": "username_platform_probe"})
}
