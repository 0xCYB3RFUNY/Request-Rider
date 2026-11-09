package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type osintTransformInput struct {
	Transform string `json:"transform"`
	Value     string `json:"value"`
	// EntityType is the kind of entity the caller is holding. It is optional,
	// because the application does not send it yet, and it is not guessed from
	// anything when it is absent — the value's own shape is the fallback, and
	// `transformApplicabilityError` says which of the two it used. The day the
	// application starts sending it, the exact answer replaces the inferred one
	// and no caller can be talked into a lookup it did not mean to make.
	EntityType     string                 `json:"entity_type,omitempty"`
	Options        map[string]interface{} `json:"options"`
	ConfirmNetwork bool                   `json:"confirm_network"`
	toolRunRoute
}

type transformEntity struct {
	Type         string                 `json:"type"`
	Identity     string                 `json:"identity"`
	DisplayValue string                 `json:"display_value,omitempty"`
	RiskScore    int                    `json:"risk_score,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
	Provenance   map[string]interface{} `json:"provenance,omitempty"`
}

type transformRelation struct {
	Type       string                 `json:"type"`
	SourceType string                 `json:"source_type"`
	Source     string                 `json:"source"`
	TargetType string                 `json:"target_type"`
	Target     string                 `json:"target"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Provenance map[string]interface{} `json:"provenance,omitempty"`
}

type osintTransformResult struct {
	Transform   string                 `json:"transform"`
	ObservedAt  string                 `json:"observed_at"`
	LocalOnly   bool                   `json:"local_only"`
	NetworkUsed bool                   `json:"network_used"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	Entities    []transformEntity      `json:"entities"`
	Relations   []transformRelation    `json:"relations"`
	Warnings    []string               `json:"warnings"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var githubUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// subdomainTransform is the transform that discovers the names under a host. It
// is the only transform that queries the certificate indexes.
const subdomainTransform = "subdomains"

// transformRegistry is the engine's own list of what it can do, and `accepts` on
// each entry is the answer to the question the registry could not answer before:
// which kind of entity the transform is about. The engine used to validate the
// value and nothing else, so `subdomains` on a port value ran four certificate
// indexes and a DNS pass, and `github_recon` on a technology value looked up a
// stranger's account. A list of accepted kinds turns "guess from the string" into
// a stated contract that both the engine and the caller can be held to.
//
// The kinds are the entity types the graph knows. `subdomain` is listed next to
// `domain` everywhere a name is accepted, because DNS cannot tell a subdomain from
// a domain — the string is the same kind of thing — so refusing one and allowing
// the other would be refusing on a distinction the value does not carry.
//
// The table is measured, not aspirational: every pair below was run against a real
// `.ru` site and lists what the transform actually does. Two pairs the application offers are therefore NOT
// here, because they fail on a well-formed value and are recorded as product bugs
// in DEVELOPMENT_LOG.md rather than papered over with a wider `accepts`:
// `domain_normalize` on a URL entity (INVALID_DOMAIN) and `ip_geo` on a CIDR
// entity (INVALID_IP).
var transformRegistry = []map[string]interface{}{
	// `email_recon` is the network counterpart of `email_domain`, and it is
	// registered `network: true` because it performs network requests. It was
	// registered `network: false` while the body already contained a sixty-platform
	// probe, and that flag is the only thing the page reads before it asks:
	// `osintTransformIsNetwork` answers from the registry, so `network: false`
	// meant the confirmation dialog never appeared, the page sent
	// `confirm_network: false`, and the probe was unreachable — the run answered
	// with the local normalization and a warning that said the verification was
	// disabled, which is what an operator was told while the code that performs it
	// sat unentered below. The gate is read from this flag on the engine's side
	// too (`transformIsNetwork`), so the flag and the behaviour cannot disagree
	// the way they did. `email_domain` remains the local transform: this one is
	// what asks sixty platforms whether they hold the address.
	{"id": "email_recon", "network": true, "accepts": []string{"email"}, "description": "Normalize the address and its domain, then ask a catalogue of public profile platforms whether they hold an account for the local-part, recording each match as a profile entity with the status code it answered. A platform that answers every visitor the same way is reported with the status it gave, not as a confirmed account. Requires explicit network confirmation, because the local-part is sent to third parties."},
	{"id": "username_enum", "network": false, "accepts": []string{"username"}, "description": "Local username normalization for graph correlation, without network access. To ask platforms whether they hold this username, run username_search: it is the network counterpart of this transform and requires explicit network confirmation."},
	// The network counterpart of `username_enum`, and the replacement for what
	// Sherlock and Maigret do. It merges their catalogues rather than choosing
	// between them, and it merges their detection models too — `status_code`,
	// `message` and `response_url` — because a platform that redirects a
	// missing profile looks exactly like one with a profile to any client that
	// follows the redirect, and that is the largest source of false positives
	// in this whole family of tools.
	{"id": "username_search", "network": true, "accepts": []string{"username"}, "description": "Ask every catalogued platform (Sherlock and Maigret catalogues merged) whether it holds this username, using status-code, body-marker or redirect detection. Reports the platform URL and the evidence; a platform that gates profiles behind a login answers every visitor the same way. Requires explicit network confirmation."},
	{"id": "ip_geo", "network": false, "accepts": []string{"ip"}, "description": "Local IP normalization with optional environment-only GeoIP JSON database."},
	{"id": "email_domain", "network": false, "accepts": []string{"email"}, "description": "Extract the normalized domain from an email address."},
	{"id": "username_normalize", "network": false, "accepts": []string{"username"}, "description": "Normalize a username for graph correlation."},
	{"id": "domain_normalize", "network": false, "accepts": []string{"domain", "subdomain"}, "description": "Normalize a domain identity without network access."},
	{"id": "url_host", "network": false, "accepts": []string{"url"}, "description": "Extract a host entity from an HTTP(S) URL."},
	{"id": "ghdb_links", "network": false, "accepts": []string{"domain", "subdomain"}, "description": "Generate categorized Google Hacking Database (GHDB) reconnaissance dorks for a domain without network traffic."},
	{"id": "ghdb_search", "network": true, "accepts": []string{"domain", "subdomain"}, "description": "Active GHDB search: queries search engines for reconnaissance dorks, detects CMS (WordPress, Joomla, Drupal) to apply targeted exploit-db dorks, and extracts live discovered URLs, leaked files, admin portals, and subdomains into the graph. Requires explicit network confirmation."},
	{"id": "reverse_dns", "network": true, "accepts": []string{"ip", "domain", "subdomain"}, "description": "Resolve PTR names for an IP; explicit confirmation required."},
	{"id": "dns_records", "network": true, "accepts": []string{"domain", "subdomain"}, "description": "Resolve A/AAAA records for a domain and read the public reputation of the domain and every address it resolves to; explicit confirmation required."},
	// The two transforms that resolve or probe many names in a loop declare the
	// `concurrency` capability, and the UI reads it from here. A dialog that
	// decided this by transform name would hide the control the moment the next
	// loop gained a pool, and nobody would be told.
	{"id": "subdomains", "network": true, "concurrency": true, "concurrency_default": bruteForceDefaultWorkers, "accepts": []string{"domain", "subdomain"}, "description": "Certificate transparency indexes, public page scans and DNS guessing; requires explicit network confirmation."},
	// The description is what the operator reads before confirming a network run,
	// so it has to name the three passes and the attribution rule. "Public GitHub
	// profile lookup" was true of the previous implementation and is not true of
	// this one: the profile is only the first of three passes, and a commit is
	// only reported when GitHub itself links it to the account.
	{"id": "github_recon", "network": true, "accepts": []string{"username"}, "description": "Public GitHub profile, event feed and commit scan for the account's own commit addresses; GitHub privacy addresses and other contributors' commits are not reported. Requires explicit network confirmation."},
	// The two secret scans. Both report a fingerprint and never the value, and
	// both are registered with `network: true` — which is what gates them: the
	// confirmation is read from this flag rather than from a hand-written list of
	// ids, so a transform is gated by being registered rather than by being
	// remembered in two places. A hand-written list was how both of these were
	// reachable without `confirm_network` on their first run.
	{"id": "git_secrets", "network": true, "accepts": []string{"username", "url"}, "description": "Scan the public commit diffs of a GitHub account or repository for committed credentials; reports a fingerprint, never the value. Requires explicit network confirmation."},
	{"id": "secret_scan", "network": true, "accepts": []string{"domain", "subdomain", "url"}, "description": "Fetch a fixed list of well-known paths from a host and report credential material published in them; reports a fingerprint, never the value. Requires explicit network confirmation."},
	// The one transform that returns the credential rather than a fingerprint,
	// and the description says so before the operator confirms the run. The two
	// scans above fingerprint because the value is a credential in *your own*
	// live system and the fingerprint is what a graph needs; here the value is
	// the finding — the question is what an address was reused as, and a
	// fingerprint would not answer it. The value is sent to three third-party
	// breach services, which is why this one is registered `network: true` and
	// gated on `confirm_network` like every other run that leaves the machine.
	// Breach Directory needs a key in `BREACHDIRECTORY_API_KEY` and is skipped,
	// with that stated in the run, when the key is absent; the other two run
	// either way.
	{"id": "breach_exposure", "network": true, "accepts": []string{"email", "username"}, "description": "Ask three public breach corpora (ProxyNova, BreachDirectory, weakpass) whether this email or username appears in a known compromise, and report the email, the plaintext password, the SHA-1 and the sources. Unlike the two secret scans above, this transform returns the credential value: the plaintext is the answer to the question, so it is reported rather than fingerprinted. Every request carries a timeout and is bounded by max_bytes. Requires explicit network confirmation, because the value is sent to third parties."},
	// The three identity services gosearch read as modules. Before this the engine
	// asked Gravatar and Keybase as bare HTML and judged them by status code, which
	// is a different question: both answer 200 for a page that holds nothing, so
	// the HTML read could not see a profile's linked accounts, its published
	// addresses or Keybase's verified proofs. The JSON endpoints answer those, and
	// HudsonRock has no equivalent here at all — `subdomains` reads a different
	// HudsonRock endpoint that yields hostnames, not a person's infostealer log.
	{"id": "identity_graph", "network": true, "accepts": []string{"email", "username"}, "description": "Ask Gravatar, Keybase and HudsonRock what they publish about this identity. Gravatar and Keybase return the profile, the addresses it publishes and the accounts it links, including Keybase's verified proofs; HudsonRock returns the infostealer log for the identity, with the machine name, the OS, the malware path and the passwords and logins the machine held. The three are keyed differently, and for an email each is asked the form it actually answers: Gravatar by the MD5 of the address (its documented key, and also by the address as typed, because that form answers nothing for a real profile), Keybase by the part of the address before @ — the only form of an address it accepts, and a candidate rather than a proof, which the finding says on its face — and HudsonRock by address, while a username is asked by name. The question each service was actually given is reported as asked_<service>, so 'nothing found' is never read without knowing what was asked. With check_domains it also probes 26 TLD candidates of <username><tld>; that pass is off by default and the setting is reported. With dump_file it writes the run to a report file. retries sets how many times HudsonRock is tried after a dropped connection (default 2 attempts, 0 means once, and the applied count is reported as hudsonrock_attempts). A service that did not answer, and an endpoint that is not served, are named in the run rather than reported as nothing found. Requires explicit network confirmation."},
	{"id": "wayback_urls", "network": true, "accepts": []string{"domain", "subdomain", "url"}, "description": "Query public archive indexes for URLs; explicit confirmation required."},
	{"id": "s3_buckets", "network": true, "concurrency": true, "concurrency_default": bucketCheckDefaultWorkers, "accepts": []string{"domain", "subdomain"}, "description": "Check a user-supplied bucket candidate list; explicit confirmation required."},
	// The three transforms for the kinds that used to accept none. Measured
	// 2026-10-02: `cidr`, `asn` and `technology` had an empty context menu, so
	// three of the nine kinds the graph stores could not be investigated at all.
	// Each one answers the question its kind is asked for, and each says what it
	// could not answer rather than reporting an empty success.
	{"id": "cidr_range", "network": true, "max_addresses_default": cidrRangeDefaultAddresses, "accepts": []string{"cidr"}, "description": "Ask the resolver about the addresses inside a range and record the names each one answers with, plus the addresses that answer with nothing. The run has an address budget, reported in the result and raised by the max_addresses option; a range larger than the budget says so instead of answering with a slice presented as the whole. Requires explicit network confirmation."},
	{"id": "asn_lookup", "network": true, "max_prefixes_default": asnLookupDefaultPrefixes, "accepts": []string{"asn"}, "description": "Ask the public network record and the public BGP record who announces an autonomous system, add the operator and the ranges it announces, and record the names those addresses answer with. Requires explicit network confirmation."},
	{"id": "technology_probe", "network": true, "accepts": []string{"technology"}, "description": "Fetch the host a technology was seen on and report whether that technology is still announced, naming the header, cookie or page marker the answer came from. A host that cannot be read is reported as unverified rather than as confirmed. Requires explicit network confirmation."},
	// httpx as a graph transform. The description is what the operator reads
	// before confirming a network run, so it names what is recorded and what is
	// not: the technologies and the addresses come back, the page title is not
	// claimed, and the run is routed through the same passive proxy as every
	// other tool so its exchanges reach Traffic.
	{"id": "http_probe", "network": true, "accepts": []string{"domain", "subdomain", "url"}, "description": "Probe a host with httpx and record what answered: the URLs that replied, their status codes, the addresses the host resolves to, the technologies it announces and the CDN in front of it. The probe follows redirects and reads the TLS certificate. It reports what answered at that moment and does not claim the host is up now. Requires explicit network confirmation."},
}

// The kinds a value can be recognised as without being told. A username, an ASN, a
// port, a technology and a bucket name are all opaque strings, and no classifier
// built on shape can separate them — so a transform whose `accepts` are all opaque
// keeps its own value validation, and a transform whose `accepts` are all
// recognisable can refuse a value it cannot recognise at all.
const (
	transformKindIP     = "ip"
	transformKindCIDR   = "cidr"
	transformKindURL    = "url"
	transformKindEmail  = "email"
	transformKindDomain = "domain"
)

var recognisableTransformKinds = map[string]bool{
	transformKindIP: true, transformKindCIDR: true, transformKindURL: true,
	transformKindEmail: true, transformKindDomain: true, "subdomain": true,
}

// All entity kinds the graph knows. A registry entry that names a kind outside this
// set would accept something the graph cannot store, so the test walks it.
var knownEntityKinds = map[string]bool{
	"domain": true, "subdomain": true, "ip": true, "cidr": true, "url": true,
	"email": true, "username": true, "asn": true, "certificate": true,
	"technology": true, "port": true, "cloud_asset": true, "profile": true,
}

func transformRegistryEntry(id string) map[string]interface{} {
	for _, item := range transformRegistry {
		if item["id"] == id {
			return item
		}
	}
	return nil
}

// transformAccepts reads the declared kinds off a registry entry. The registry is
// a []map[string]interface{} because it is serialised straight to the capability
// endpoint, so the value arrives as []interface{} from JSON and []string from the
// literal; both are read here rather than at every call site.
func transformAccepts(item map[string]interface{}) []string {
	switch kinds := item["accepts"].(type) {
	case []string:
		return kinds
	case []interface{}:
		list := make([]string, 0, len(kinds))
		for _, kind := range kinds {
			if text, ok := kind.(string); ok {
				list = append(list, text)
			}
		}
		return list
	default:
		return nil
	}
}

// classifyTransformValue reads the kind off the value itself. The order matters: a
// URL can carry an "@" in its userinfo, and a hostname is the last thing a value
// can be, so the specific shapes are tried first and only then is a name accepted.
func classifyTransformValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if net.ParseIP(value) != nil {
		return transformKindIP
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return transformKindCIDR
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil &&
			(parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" {
			return transformKindURL
		}
		return ""
	}
	if strings.Contains(value, "@") {
		local, host, _ := strings.Cut(value, "@")
		if local != "" && !strings.ContainsAny(local, " \t") {
			if _, err := normalizeDomainForTransform(host); err == nil {
				return transformKindEmail
			}
		}
		return ""
	}
	// A hostname is a domain here, dot and all. The dot is load-bearing: without it
	// `normalizeDomainForTransform` read `github` and `AS12389` as domains, which
	// refused the product's own username pairs and let `subdomains("443")` walk the
	// certificate indexes as though "443" were a name. What the zone actually is does
	// not matter to this reading — a reserved zone is a name too, and refusing it
	// would be the zone-based blocking this project does not do. Whether a dotted
	// value is a domain or a username is a different question, and it is answered by
	// the declared entity type.
	if strings.Contains(value, ".") {
		if _, err := normalizeDomainForTransform(value); err != nil {
			return ""
		}
		return transformKindDomain
	}
	return ""
}

// transformApplicabilityError reports why a transform cannot process this value, or
// "" and true when it can.
//
// The declared `entity_type` is the strong signal: a caller that says which entity it
// holds gets an exact answer, and nothing about guessing enters.
//
// When the caller declares nothing — which is every caller today, because the
// application does not send the type yet — the kind is read off the value, and that
// reading is only allowed to decide when every kind the transform accepts is one a
// classifier could recognise. The reason is the error the operator gets: for a
// username value the transform's own validation says "value is a domain name, not a
// username", which names the value; a kind mismatch would say "does not apply to
// domain", which names a type the caller never mentioned. Where every accepted kind
// is recognisable there is no such competition, and the check is what stopped the
// wasted traffic: `subdomains` on "443" is not a hostname, so no reading of "443"
// makes it one, and four certificate indexes plus a DNS pass are not a search for it.
// transformIsNetwork answers whether a registered transform reaches the network.
// It reads the registry rather than a list of ids so that registering a network
// transform is enough to have it gated, here and in the UI, by one declaration.
func transformIsNetwork(id string) bool {
	item := transformRegistryEntry(id)
	if item == nil {
		return false
	}
	declared, _ := item["network"].(bool)
	return declared
}

func transformApplicabilityError(input *osintTransformInput) (string, string, bool) {
	item := transformRegistryEntry(input.Transform)
	if item == nil {
		return "", "", true
	}
	accepts := transformAccepts(item)
	if len(accepts) == 0 {
		return "", "", true
	}
	if declared := strings.ToLower(strings.TrimSpace(input.EntityType)); declared != "" {
		for _, kind := range accepts {
			if kind == declared {
				return "", "", true
			}
		}
		return "TRANSFORM_NOT_APPLICABLE", fmt.Sprintf(
			"%s does not apply to a %s entity; it applies to %s",
			input.Transform, declared, strings.Join(accepts, ", ")), false
	}
	for _, kind := range accepts {
		if !recognisableTransformKinds[kind] {
			// An opaque kind — a username, an ASN, a technology — is exactly what
			// the classifier cannot recognise, so the transform's own validation
			// is the honest judge of this value.
			return "", "", true
		}
	}
	inferred := classifyTransformValue(input.Value)
	if inferred == "" {
		return "TRANSFORM_NOT_APPLICABLE", fmt.Sprintf(
			"%s needs %s, and %q is none of them",
			input.Transform, strings.Join(accepts, " or "), input.Value), false
	}
	for _, kind := range accepts {
		if kind == inferred {
			return "", "", true
		}
	}
	return "TRANSFORM_NOT_APPLICABLE", fmt.Sprintf(
		"%s does not apply to %s; it applies to %s",
		input.Transform, inferred, strings.Join(accepts, ", ")), false
}

func transformError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
}

func validateTransformValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, character := range value {
		if character < 32 && character != '\t' {
			return ""
		}
	}
	return value
}

func entity(transformType, identity string, properties, provenance map[string]interface{}) transformEntity {
	if properties == nil {
		properties = map[string]interface{}{}
	}
	if provenance == nil {
		provenance = map[string]interface{}{}
	}
	return transformEntity{Type: transformType, Identity: identity, Properties: properties, Provenance: provenance}
}

func entityWithDisplayAndRisk(transformType, identity, displayValue string, riskScore int, properties, provenance map[string]interface{}) transformEntity {
	if properties == nil {
		properties = map[string]interface{}{}
	}
	if provenance == nil {
		provenance = map[string]interface{}{}
	}
	return transformEntity{
		Type:         transformType,
		Identity:     identity,
		DisplayValue: displayValue,
		RiskScore:    riskScore,
		Properties:   properties,
		Provenance:   provenance,
	}
}

func (s *server) osintTransformRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": transformRegistry})
}

func (s *server) osintTransform(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input osintTransformInput
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OSINT_TRANSFORM", err)
		return
	}
	input.Transform = strings.ToLower(strings.TrimSpace(input.Transform))
	input.Value = validateTransformValue(input.Value)
	if input.Value == "" {
		writeError(w, http.StatusBadRequest, "INVALID_OSINT_TRANSFORM", transformError("INVALID_VALUE", "transform value is required"))
		return
	}
	if code, message, ok := validateTransformInput(&input); !ok {
		writeError(w, http.StatusBadRequest, code, transformError(code, message))
		return
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	runContext, err := s.bindToolRoute(routeContext, input.toolRunRoute)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", err)
		return
	}
	result, err := s.runOSINTTransform(runContext, input)
	if result.NetworkUsed {
		result.SourceIP = s.ensureSourceIP(routeContext)
	}
	if err != nil {
		// The reason is what a caller branches on, so the codes that answer a
		// question the caller asked have to reach it as a code and not only as prose
		// inside the message. `TRANSFORM_NOT_APPLICABLE` joins `NETWORK_CONFIRMATION_REQUIRED`
		// here for the same reason: an operator who asked for subdomains of "443" needs
		// the refusal to be recognisable, and a caller that cannot recognise it will
		// report it as an ordinary failure and offer a retry that cannot work.
		writeTransformError(w, http.StatusBadRequest, promotedTransformErrorCode(err.Error()), err, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// promotedTransformErrorCode decides which reason code a failed transform reports.
//
// The reason is what a caller branches on, so a code that answers a question the
// caller asked has to reach it as a code and not only as prose inside the message.
// `TRANSFORM_NOT_APPLICABLE` is promoted for the same reason `NETWORK_CONFIRMATION_REQUIRED`
// already was: an operator who asked for subdomains of "443" needs the refusal to be
// recognisable, and a caller that cannot recognise it reports an ordinary failure
// and offers a retry that cannot work. `INVALID_USERNAME` is promoted because that
// transform used to answer "completed" and write a domain into the graph as a
// username, so the operator had no signal at all; now the signal is a code.
//
// Anything else keeps the generic `OSINT_TRANSFORM_FAILED`: an unrecognised code
// passed through would let a caller act on a string it was never taught.
func promotedTransformErrorCode(message string) string {
	for _, promoted := range []string{"NETWORK_CONFIRMATION_REQUIRED", "TRANSFORM_NOT_APPLICABLE", "INVALID_USERNAME"} {
		if strings.HasPrefix(message, promoted+":") {
			return promoted
		}
	}
	return "OSINT_TRANSFORM_FAILED"
}

// writeTransformError answers a failed transform with everything the run
// observed, not only the failure.
//
// A transform that ends in an error has usually already learned something: four
// certificate indexes answered and a fifth refused, three archive indexes were
// consulted, a resolver returned nothing. Returning a bare error string threw
// that evidence away and made a partial run indistinguishable from a run that
// learned nothing at all. The keys `error` and `reason` are unchanged, so a
// caller that only reads the failure still sees exactly what it saw before.
func writeTransformError(w http.ResponseWriter, status int, reason string, err error, result osintTransformResult) {
	body := map[string]interface{}{
		"error":  err.Error(),
		"reason": reason,
	}
	// The collected rows are what makes the failure diagnosable, and a caller
	// reads one shape whether the run succeeded or not.
	body["warnings"] = result.Warnings
	body["entities"] = result.Entities
	body["relations"] = result.Relations
	if len(result.Metadata) > 0 {
		body["metadata"] = result.Metadata
	}
	if result.SourceIP != "" {
		body["source_ip"] = result.SourceIP
	}
	writeJSON(w, status, body)
}

// osintTransformJob starts one transform in the background so a long discovery
// reports live progress and can be paused or cancelled, instead of holding one
// blocking request open for the whole run.
func (s *server) osintTransformJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input osintTransformInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OSINT_TRANSFORM", err)
		return
	}
	if code, message, ok := validateTransformInput(&input); !ok {
		writeError(w, http.StatusBadRequest, code, transformError(code, message))
		return
	}
	// The job outlives this request, so it binds to the route generation rather
	// than to the request context. A route switch still cancels it.
	_, routeContext, release := s.bindBackgroundRouteContext(r.Context())
	s.ensureSourceIP(routeContext)
	runContext, routeErr := s.bindToolRoute(routeContext, input.toolRunRoute)
	if routeErr != nil {
		release()
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", routeErr)
		return
	}
	job := s.startOSINTJob(runContext, input, release)
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID, "state": osintJobQueued, "progress": job.Snapshot().Progress,
	})
}

// osintTransformJobStatus returns the live progress of a background transform
// and, once finished, its result. A trailing action segment controls the run:
// "/pause" suspends it, "/resume" continues it, "/cancel" stops it.
func (s *server) osintTransformJobStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/proxy/osint/transform/jobs/")
	for _, action := range []string{"/cancel", "/pause", "/resume"} {
		if strings.HasSuffix(id, action) {
			s.osintTransformJobAction(w, r, strings.TrimSuffix(id, action), strings.TrimPrefix(action, "/"))
			return
		}
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	snapshot, ok := osintJobSnapshotFor(id)
	if !ok {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("transform %q is unknown or already collected", id))
		return
	}
	writeJSON(w, http.StatusOK, osintJobPayload(snapshot))
}

// osintJobPayload renders one snapshot for the browser poll.
func osintJobPayload(snapshot osintJobSnapshot) map[string]interface{} {
	payload := map[string]interface{}{
		"job_id": snapshot.ID, "state": snapshot.State, "progress": snapshot.Progress,
	}
	if snapshot.Result != nil {
		payload["result"] = snapshot.Result
	}
	if snapshot.Error != "" {
		payload["error"] = snapshot.Error
	}
	if snapshot.Reason != "" {
		payload["reason"] = snapshot.Reason
	}
	return payload
}

// osintTransformJobAction applies one control action to a background transform.
func (s *server) osintTransformJobAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var err error
	switch action {
	case "cancel":
		if !cancelOSINTJob(id) {
			err = fmt.Errorf("transform %q is unknown or already finished", id)
		}
	case "pause":
		err = pauseOSINTJob(id)
	case "resume":
		err = resumeOSINTJob(id)
	default:
		err = fmt.Errorf("unknown transform action %q", action)
	}
	if err != nil {
		status, code := http.StatusBadRequest, "INVALID_JOB_STATE"
		if strings.Contains(err.Error(), "is unknown") {
			status, code = http.StatusNotFound, "UNKNOWN_JOB"
		}
		writeError(w, status, code, err)
		return
	}
	state := osintJobRunning
	switch action {
	case "cancel":
		state = osintJobCancelled
	case "pause":
		state = osintJobPaused
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job_id": id, "state": state})
}

// validateTransformInput rejects a transform that cannot run at all, so a bad
// request fails immediately instead of becoming a job that fails on a timer.
func validateTransformInput(input *osintTransformInput) (string, string, bool) {
	input.Transform = strings.ToLower(strings.TrimSpace(input.Transform))
	input.Value = validateTransformValue(input.Value)
	if input.Value == "" {
		return "INVALID_VALUE", "transform value is required", false
	}
	known := false
	for _, item := range transformRegistry {
		if item["id"] == input.Transform {
			known = true
			break
		}
	}
	if !known {
		return "UNKNOWN_TRANSFORM", "unsupported OSINT transform", false
	}
	if code, message, ok := transformApplicabilityError(input); !ok {
		return code, message, false
	}
	// The confirmation requirement is read from the registry's own `network`
	// flag rather than from a list written out here. That list was a second
	// copy of a fact the registry already states, and a second copy is a list
	// that goes stale: a network transform added to the registry without being
	// added here passed validation and was only stopped by its own internal
	// check. Reading the flag makes a transform correct by being registered, and
	// the page already reads the same flag to decide whether to offer it.
	if transformIsNetwork(input.Transform) && !input.ConfirmNetwork {
		return "NETWORK_CONFIRMATION_REQUIRED", "this transform performs a network request", false
	}
	return "", "", true
}

func (s *server) runOSINTTransform(ctx context.Context, input osintTransformInput) (osintTransformResult, error) {
	return s.runOSINTTransformWithCollector(ctx, input, nil)
}

// runOSINTTransformWithCollector runs one transform and reports its progress.
//
// The collector is what makes a long transform controllable: a background job
// passes one to get live counters and a pause point, while the synchronous
// endpoint passes nil and keeps the original single-shot behaviour. Nothing
// else about the transform changes between the two.
func (s *server) runOSINTTransformWithCollector(ctx context.Context, input osintTransformInput, collector *transformCollector) (osintTransformResult, error) {
	result := osintTransformResult{
		Transform:  input.Transform,
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		LocalOnly:  true,
		Entities:   []transformEntity{},
		Relations:  []transformRelation{},
		Warnings:   []string{},
	}
	// The full validation runs here as well as in the request handlers, so a direct
	// call, a background job and the synchronous endpoint all refuse the same
	// values. Running it before the switch is what keeps the refusal cheap: a
	// transform that would have walked four certificate indexes is turned away
	// before the first request, not after it.
	//
	// It is `validateTransformInput` and not `transformApplicabilityError`, and the
	// difference is the confirmation requirement. Applicability only asks whether a
	// value is the right kind; confirmation asks whether the operator agreed to the
	// requests. Checking only applicability here meant this entry point did not
	// enforce the second — every network transform's body was reachable from a
	// direct call, a test or a background job without the dialog, and the HTTP
	// handlers were the only thing holding the gate. `email_recon` is what made
	// that measurable: with its own in-body check removed, an unconfirmed call
	// reached the probe and sent the local-part to sixty platforms.
	if code, message, ok := validateTransformInput(&input); !ok {
		return result, transformError(code, message)
	}
	var err error
	switch input.Transform {
	case "email_recon":
		err = s.transformEmailRecon(ctx, &result, input)
	case "username_enum":
		err = runUsernameEnum(&result, input.Value)
	case "username_search":
		err = transformUsernameSearch(s, ctx, &result, input, collector)
	case "ip_geo":
		err = runIPGeo(&result, input.Value)
	case "email_domain":
		err = runEmailDomain(&result, input.Value)
	case "username_normalize":
		err = runUsernameEnum(&result, input.Value)
	case "domain_normalize":
		err = runDomainNormalize(&result, input.Value)
	case "url_host":
		err = runURLHost(&result, input.Value)
	case "ghdb_links":
		err = runGHDBLinks(&result, input.Value)
	case "ghdb_search":
		err = s.runGHDBSearchWithCollector(ctx, &result, input, collector)
	case "reverse_dns":
		err = s.runReverseDNS(ctx, &result, input)
	case "dns_records":
		err = s.runDNSRecords(ctx, &result, input)
	case subdomainTransform:
		err = s.runSubdomainTransformWithCollector(ctx, &result, input, collector)
	case "github_recon":
		err = transformGitHubRecon(s, ctx, &result, input, collector)
	case "git_secrets":
		err = transformGitSecrets(s, ctx, &result, input, collector)
	case "secret_scan":
		err = transformSecretScan(s, ctx, &result, input, collector)
	case "breach_exposure":
		err = transformBreachExposure(s, ctx, &result, input, collector)
	case "identity_graph":
		err = transformIdentityGraph(s, ctx, &result, input, collector)
	case "wayback_urls":
		err = s.runWaybackURLsWithCollector(ctx, &result, input, collector)
	case "s3_buckets":
		err = transformS3Buckets(s, ctx, &result, input, collector)
	case "cidr_range":
		err = s.runCIDRRange(ctx, &result, input, collector)
	case "asn_lookup":
		err = s.runASNLookup(ctx, &result, input, collector)
	case "technology_probe":
		err = s.runTechnologyProbe(ctx, &result, input, collector)
	case "http_probe":
		err = s.runHTTPProbe(ctx, &result, input, collector)
	default:
		return result, transformError("UNKNOWN_TRANSFORM", "unsupported OSINT transform")
	}

	return result, err
}

func runEmailDomain(result *osintTransformResult, value string) error {
	parsed, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || !strings.Contains(parsed.Address, "@") {
		return transformError("INVALID_EMAIL", "email must be a plain address")
	}
	domain := strings.ToLower(strings.SplitN(parsed.Address, "@", 2)[1])
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}))
	return nil
}

func (s *server) transformEmailRecon(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if input.Value == "" {
		return transformError("INVALID_EMAIL", "email must not be empty")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(input.Value))
	if err != nil || !strings.Contains(address.Address, "@") {
		return transformError("INVALID_EMAIL", "email must be a plain address")
	}
	localPart, domain := strings.TrimSpace(strings.SplitN(address.Address, "@", 2)[0]), strings.TrimSpace(strings.ToLower(strings.SplitN(address.Address, "@", 2)[1]))
	if localPart == "" || domain == "" {
		return transformError("INVALID_EMAIL", "email must include a local-part and domain")
	}
	result.Entities = append(result.Entities,
		entity("email", strings.ToLower(address.Address), map[string]interface{}{"local_part": localPart}, map[string]interface{}{"source": "local_transform"}),
		entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}),
	)
	result.Relations = append(result.Relations, transformRelation{Type: "contains", SourceType: "email", Source: strings.ToLower(address.Address), TargetType: "domain", Target: domain})
	// There is no "verification disabled" branch here any more, and adding one
	// back is what put this capability out of reach: the registry entry said
	// `network: false`, so no confirmation was ever requested, the page sent
	// `confirm_network: false`, and this function returned above the probe having
	// sent nothing while telling the operator the feature was switched off. The
	// gate now lives where every other network transform has it —
	// `transformApplicabilityError` refuses an unconfirmed run before this body is
	// entered — so a run that reaches this point has been confirmed and the probe
	// below is the work the operator agreed to.
	result.LocalOnly = false
	result.NetworkUsed = true
	profiles := []struct {
		name string
		path string
	}{
		{"GitHub", "https://github.com/%s"}, {"LinkedIn", "https://www.linkedin.com/in/%s"}, {"Twitter/X", "https://x.com/%s"}, {"Facebook", "https://www.facebook.com/%s"}, {"Instagram", "https://www.instagram.com/%s"},
		{"Mastodon", "https://mastodon.social/@%s"}, {"Reddit", "https://www.reddit.com/user/%s"}, {"TikTok", "https://www.tiktok.com/@%s"}, {"YouTube", "https://www.youtube.com/@%s"}, {"Pinterest", "https://www.pinterest.com/%s"},
		{"Tumblr", "https://%s.tumblr.com/"}, {"WordPress", "https://%s.wordpress.com/"}, {"Flickr", "https://www.flickr.com/people/%s/"}, {"Medium", "https://medium.com/@%s"}, {"Vimeo", "https://vimeo.com/%s"},
		{"Dribbble", "https://dribbble.com/%s"}, {"Behance", "https://www.behance.net/%s"}, {"GitLab", "https://gitlab.com/%s"}, {"Bitbucket", "https://bitbucket.org/%s"}, {"StackOverflow", "https://stackoverflow.com/users/%s"},
		{"Hacker News", "https://news.ycombinator.com/user?id=%s"}, {"Quora", "https://www.quora.com/profile/%s"}, {"Spotify", "https://open.spotify.com/user/%s"}, {"Steam", "https://steamcommunity.com/id/%s"}, {"VKontakte", "https://vk.com/%s"},
		{"Disqus", "https://disqus.com/by/%s/"}, {"GitHub Gist", "https://gist.github.com/%s"}, {"CodePen", "https://codepen.io/%s"}, {"Pastebin", "https://pastebin.com/u/%s"}, {"DeviantArt", "https://%s.deviantart.com/"},
		{"Amazon", "https://www.amazon.com/gp/profile/amzn1.account.%s"}, {"Etsy", "https://www.etsy.com/people/%s"}, {"Goodreads", "https://www.goodreads.com/user/show/%s"}, {"Foursquare", "https://foursquare.com/%s"}, {"MySpace", "https://myspace.com/%s"},
		{"SoundCloud", "https://soundcloud.com/%s"}, {"Mixcloud", "https://www.mixcloud.com/%s/"}, {"Last.fm", "https://www.last.fm/user/%s"}, {"Blogger", "https://%s.blogspot.com/"}, {"Strava", "https://www.strava.com/athletes/%s"},
		{"NPM", "https://www.npmjs.com/~%s"}, {"Slack", "https://%s.slack.com/"}, {"Discord", "https://discord.com/users/%s"}, {"Trustpilot", "https://www.trustpilot.com/users/%s"}, {"Capterra", "https://www.capterra.com/reviews/user/%s"},
		{"ProductHunt", "https://www.producthunt.com/@%s"}, {"Kaggle", "https://www.kaggle.com/%s"}, {"ResearchGate", "https://www.researchgate.net/profile/%s"}, {"Academia", "https://independent.academia.edu/%s"}, {"SlideShare", "https://www.slideshare.net/%s"},
		{"Gravatar", "https://en.gravatar.com/%s"}, {"Keybase", "https://keybase.io/%s"}, {"Patreon", "https://www.patreon.com/%s"}, {"Twitch", "https://www.twitch.tv/%s"}, {"Chess.com", "https://www.chess.com/member/%s"},
		{"GitHubSponsors", "https://github.com/sponsors/%s"}, {"HuggingFace", "https://huggingface.co/%s"}, {"Bsky", "https://bsky.app/profile/%s.bsky.social"}, {"Threads", "https://www.threads.net/@%s"}, {"Snapchat", "https://www.snapchat.com/add/%s"},
		{"Apple", "https://appleid.apple.com/account/%s"}, {"Mojang", "https://www.minecraft.net/en-us/profile/%s"},
	}
	// The client is the run's, so the index queries this transform makes are
	// recorded through the same proxy as a scan's requests.
	client := s.toolClient(ctx)
	seen := map[string]bool{}
	for _, profile := range profiles {
		candidate := profile.path
		candidate = strings.ReplaceAll(candidate, "%s", url.PathEscape(localPart))
		if strings.Contains(candidate, "%s") {
			candidate = strings.ReplaceAll(candidate, "%s", url.PathEscape(strings.Split(localPart, "+")[0]))
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate, nil)
		if err != nil {
			continue
		}
		request.Header.Set("User-Agent", RandomUserAgent())
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 400 || response.StatusCode == http.StatusForbidden {
			if !seen[profile.name] {
				seen[profile.name] = true
				result.Entities = append(result.Entities, entity("profile", profile.name+":"+localPart, map[string]interface{}{"platform": profile.name, "status": response.StatusCode, "profile_url": candidate}, map[string]interface{}{"source": "social_http_probe"}))
				result.Relations = append(result.Relations, transformRelation{Type: "accounts_for", SourceType: "email", Source: strings.ToLower(address.Address), TargetType: "profile", Target: profile.name + ":" + localPart, Properties: map[string]interface{}{"status": response.StatusCode}})
			}
		}
	}
	if len(seen) == 0 {
		result.Warnings = append(result.Warnings, "No public social accounts matched the supplied identity in the online check.")
	}
	return nil
}

// bucketProviderURLs maps a provider name onto the URL shape that answers for a
// bucket name. It is a function rather than a struct slice so the pool can carry
// names and this table stays the one place a provider is described.
var bucketProviderURLs = map[string]string{
	"aws_s3":      "https://%s.s3.amazonaws.com/",
	"gcp_storage": "https://storage.googleapis.com/%s/",
	"azure_blob":  "https://%s.blob.core.windows.net/",
}

// bucketProviderOrder is the order providers are asked in, so a report reads the
// same way on every run.
var bucketProviderOrder = []string{"aws_s3", "gcp_storage", "azure_blob"}

func providerURL(provider string) string {
	if shape, ok := bucketProviderURLs[provider]; ok {
		return shape
	}
	return ""
}

// candidateName reads the bucket name back out of the probed URL.
//
// The three providers put the name in different places, and the difference matters:
// AWS and Azure put it in the host as its first label, GCP puts it in the path.
// Cutting at the first dot returned `storage` for a GCP URL and an empty string
// for the other two, so the follow-up question was asked about a name that is not
// the one being probed.
func candidateName(probed string) string {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(probed, "https://"), "http://")
	host, path, hasPath := strings.Cut(trimmed, "/")
	if hasPath && strings.Trim(path, "/") != "" {
		return strings.Trim(path, "/")
	}
	// No usable path, so the name is the first label of the host. Splitting on the
	// dot keeps the label alone rather than the rest of the name.
	labels := strings.Split(host, ".")
	return labels[0]
}

// gcpBucketExists asks Google Storage about one bucket on its own domain.
//
// The shared endpoint answers 403 for every name, so it cannot tell a bucket that
// exists from one that does not. The per-bucket domain can: it answers 404 for a
// name Storage does not hold. Measured 2026-10-02 —
// `zzz-definitely-not-a-real-bucket-99887766` answers 403 on the shared endpoint
// and 404 on its own.
//
// The base is a parameter for the same reason every other adapter base is: a test
// must be able to point the probe at a local fixture, or it ends up asking Google's
// real DNS and failing on "no network in tests" instead of deciding the question.
func gcpBucketExists(ctx context.Context, client *http.Client, base, name string) (bool, error) {
	if strings.TrimSpace(name) == "" {
		return false, nil
	}
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		base = publicGCPBucketBase
	}
	target := base + "/" + urlQueryEscape(name) + "/"
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("User-Agent", archiveUserAgent())
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	response.Body.Close()
	// 404 is "no such bucket". Everything else that is not a success means the
	// question did not get answered, and a question that was not answered is not a
	// finding.
	return response.StatusCode == http.StatusOK ||
		response.StatusCode == http.StatusForbidden ||
		response.StatusCode == http.StatusMovedPermanently ||
		response.StatusCode == http.StatusFound, nil
}

// bucketAnswer is one probe that came back with a public endpoint.
type bucketAnswer struct {
	candidate string
	url       string
	provider  string
	status    int
}

// bucketCheckDefaultWorkers is how many bucket endpoints are probed at the same
// time when the caller names no value. Every candidate is still probed against
// every provider, so this is concurrency and not a cap on the work.
const bucketCheckDefaultWorkers = 8

// probeBucketEndpoint asks one provider whether one candidate name answers, and
// reports the URL and status when it does. It is a function so a test can drive
// the pool without a network.
type probeBucketEndpoint func(ctx context.Context, url, providerName string) (int, bool)

// checkBucketCandidates probes every candidate against every provider through a
// bounded pool and returns the answers in candidate-then-provider order.
//
// The order is the input order, not the completion order: a report that reordered
// its rows between two runs of the same wordlist could not be compared, and a
// pool is not a reason to lose that. Every candidate is a pause point, like the
// DNS phase, so a pause is observable between probes rather than after the last
// one.
func checkBucketCandidates(ctx context.Context, collector *transformCollector, candidates []string, providers []string, workers int, probe probeBucketEndpoint) ([]bucketAnswer, int) {
	type probeJob struct {
		candidate string
		provider  string
		url       string
	}
	jobs := make([]probeJob, 0, len(candidates)*len(providers))
	for _, candidate := range candidates {
		for _, provider := range providers {
			jobs = append(jobs, probeJob{candidate: candidate, provider: provider, url: fmt.Sprintf(providerURL(provider), candidate)})
		}
	}
	answers := make([]bucketAnswer, len(jobs))
	applied := workers
	if applied < 1 {
		applied = 1
	}
	if len(jobs) < applied {
		applied = len(jobs)
	}
	if applied < 1 {
		return nil, 0
	}
	queue := make(chan int)
	var wg sync.WaitGroup
	var done atomic.Int64
	for worker := 0; worker < applied; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range queue {
				if err := collector.checkpoint(ctx); err != nil {
					// A paused phase resumes from here and a cancelled one ends
					// with the job. Neither loses the answers already collected.
					continue
				}
				job := jobs[index]
				status, ok := probe(ctx, job.url, job.provider)
				done.Add(1)
				collector.label(ctx, fmt.Sprintf("bucket candidates %d/%d", done.Load(), len(jobs)))
				if ok {
					answers[index] = bucketAnswer{candidate: job.candidate, url: job.url, provider: job.provider, status: status}
				}
			}
		}()
	}
	go func() {
		defer close(queue)
		for index := range jobs {
			select {
			case <-ctx.Done():
				return
			case queue <- index:
			}
		}
	}()
	wg.Wait()
	collected := make([]bucketAnswer, 0, len(answers))
	for _, answer := range answers {
		if answer.url != "" {
			collected = append(collected, answer)
		}
	}
	return collected, applied
}

func transformS3Buckets(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "bucket checks perform network requests")
	}
	candidateNames := stringSliceOption(input.Options, "candidates")
	if len(candidateNames) == 0 {
		candidateNames = []string{strings.TrimSpace(input.Value)}
	}
	if len(candidateNames) == 0 {
		return transformError("INVALID_DOMAIN", "bucket source is required")
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	client := s.toolClient(ctx)
	var names []string
	seenNames := map[string]bool{}
	for _, name := range candidateNames {
		normalized := strings.ToLower(strings.TrimSpace(name))
		normalized = strings.TrimSuffix(normalized, ".")
		normalized = strings.TrimPrefix(normalized, "https://")
		normalized = strings.TrimPrefix(normalized, "http://")
		if normalized == "" || strings.ContainsAny(normalized, "/?#:@") || seenNames[normalized] {
			continue
		}
		seenNames[normalized] = true
		names = append(names, normalized)
	}
	if len(names) == 0 {
		names = []string{strings.Split(strings.Trim(strings.ToLower(input.Value), "."), ".")[0]}
	}
	// The probe is the one place the network is touched, so the pool stays
	// independent of it: what changes between a sequential run and a pooled one
	// is only how many requests are in flight, never which ones are asked.
	probe := func(ctx context.Context, url, providerName string) (int, bool) {
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			return 0, false
		}
		request.Header.Set("User-Agent", archiveUserAgent())
		response, err := client.Do(request)
		if err != nil {
			return 0, false
		}
		response.Body.Close()
		switch response.StatusCode {
		case http.StatusOK:
			// A readable bucket listing: the bucket exists and is open.
			return response.StatusCode, true
		case http.StatusForbidden:
			// `403` is where this got the answer wrong, and it is worth writing
			// down precisely. Measured 2026-10-02: Google Storage answers **403 for
			// every name**, including one that was never created
			// (`zzz-definitely-not-a-real-bucket-99887766`), because the refusal
			// says "no listing for you" and not "no such bucket". Treating 403 as
			// existence stored an invented name as a finding, so a run on any domain
			// produced a guaranteed false positive.
			//
			// AWS is the opposite: a name that does not exist answers **404**, so
			// there a 403 really is a bucket that exists and refuses the listing.
			if providerName == "gcp_storage" {
				// The bucket's own domain is the one that distinguishes the two:
				// storage.googleapis.com answers 403 for any path, while
				// <name>.storage.googleapis.com answers 404 for a name it does not
				// hold. That second question is what tells existence from refusal.
				exists, err := gcpBucketExists(ctx, client, s.gcpBucketBase, candidateName(url))
				if err != nil || !exists {
					return response.StatusCode, false
				}
			}
			return response.StatusCode, true
		case http.StatusMovedPermanently, http.StatusFound:
			// A redirect means the name resolves to an endpoint. A missing name
			// does not redirect.
			return response.StatusCode, true
		}
		return response.StatusCode, false
	}
	workers := concurrencyOption(input.Options, bucketCheckDefaultWorkers)
	answers, appliedWorkers := checkBucketCandidates(ctx, collector, names, bucketProviderOrder, workers, probe)
	// The applied bound is stated in the result rather than left to be guessed,
	// next to the other facts about how the transform was run.
	setTransformMetadata(result, "concurrency", appliedWorkers)
	for _, answer := range answers {
		provenance := map[string]interface{}{"source": "bucket_probe"}
		result.Entities = append(result.Entities, entity("cloud_asset", answer.url, map[string]interface{}{"provider": answer.provider, "status": answer.status}, provenance))
		result.Relations = append(result.Relations, transformRelation{Type: "hosted_on", SourceType: "cloud_asset", Source: answer.url, TargetType: "domain", Target: answer.candidate})
	}
	if len(result.Entities) == 0 {
		result.Warnings = append(result.Warnings, "No public bucket endpoints responded in the supplied candidate set.")
	}
	return nil
}

// The commit scan is bounded by three values, and every one of them is a default
// rather than a rule: `max_repos`, `max_commit_pages` and `commits_per_repo` are
// read from the caller's `options`, and `0` on any of them means "no bound".
// The applied values are written back into the result metadata, because a limit
// nobody can see is the kind this project does not accept.
//
// The defaults are sized for the unauthenticated GitHub budget rather than for
// convenience. An anonymous caller gets 60 requests per hour per IP
// (`X-RateLimit-Limit: 60`, measured), and the whole scan costs
// `1 + 1 + max_repos * max_commit_pages` requests plus a patch read for the
// rare commit whose API row carries no address. At the defaults that is 8
// requests, which leaves the rest of the hour to the operator.
const (
	githubDefaultMaxRepos       = 5
	githubDefaultMaxCommitPages = 1
	githubDefaultCommitsPerRepo = 3
)

// githubPatchPrefixLimit bounds a `.patch` read. The address is in the `From:`
// header of the first few hundred bytes, so a patch is truncated rather than
// refused: a 4 MB patch for a large commit must not cost 4 MB of memory, and
// nothing past the header is ever read. This is a resource bound, not a
// correctness one, which is why it truncates instead of failing the way
// readControlPlaneBody does.
const githubPatchPrefixLimit = 64 << 10

// githubRateLimitReset formats the moment the anonymous budget refills, so the
// message says when to come back rather than only that it ran out.
func githubRateLimitReset(response *http.Response) string {
	raw := strings.TrimSpace(response.Header.Get("X-RateLimit-Reset"))
	if raw == "" {
		return ""
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	wait := time.Until(time.Unix(seconds, 0))
	if wait <= 0 {
		return ""
	}
	return fmt.Sprintf(" The anonymous budget refills in about %s.", wait.Round(time.Second))
}

// githubRateLimited reports whether a rejection is the rate limiter rather than
// a refusal of this request. GitHub answers an exhausted budget with 403 and a
// remaining count of zero, and with 429 when it wants a retry instead; both mean
// "come back later", and both are reported as their own condition so the
// operator is not told the lookup failed.
func githubRateLimited(response *http.Response) bool {
	if response.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return response.StatusCode == http.StatusForbidden &&
		strings.TrimSpace(response.Header.Get("X-RateLimit-Remaining")) == "0"
}

// githubAPIGet performs one bounded GitHub API read and decodes it into target.
//
// It is the single place that knows the house rules for talking to GitHub: the
// `Accept` and API-version headers, the optional bearer token, the bounded body
// read, and the rate-limit condition. A caller that hand-rolled its own request
// is how the events read ended up unbounded, so the helpers below all go through
// here instead.
//
// The boolean it returns is the HTTP status; a non-2xx status is handed back to
// the caller rather than turned into an error, because 404 is an answer ("no
// such user", "no commits in this repository") and not a failure.
func githubAPIGet(ctx context.Context, client *http.Client, endpoint string, target interface{}) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", archiveUserAgent())
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// The token is read from the environment and never from the request body, so
	// it cannot arrive from a browser and cannot be persisted with a transform
	// configuration. It is deliberately absent from the result, from the warnings
	// and from every log line: the only fact reported about it is whether one was
	// configured, which is what an operator needs to understand a rate limit.
	if token := githubToken(); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if githubRateLimited(response) {
		return response.StatusCode, transformError("GITHUB_RATE_LIMITED",
			"GitHub refused further requests from this route: the hourly API budget is spent."+githubRateLimitReset(response))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, nil
	}
	// A nil target means the caller wants only the status. `204 No Content` has no
	// body, and decoding an empty body is an error — so the mutual-follower check
	// would have reported a parse failure for the one status that **is** the answer
	// it is looking for. This branch is what lets a status-only read exist without
	// the caller hand-rolling a second request builder.
	if target == nil {
		return response.StatusCode, nil
	}
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return response.StatusCode, transformError("GITHUB_RESPONSE_INVALID", "GitHub response could not be read")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return response.StatusCode, transformError("GITHUB_RESPONSE_INVALID", "GitHub response was not the expected JSON")
	}
	return response.StatusCode, nil
}

// githubToken is the optional personal access token. It is absent in most
// deployments and the transform is fully functional without it, so a missing
// token is never an error — it only changes the hourly budget.
func githubToken() string {
	return strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
}

// isGitHubPrivacyAddress reports whether an address is a GitHub privacy
// placeholder rather than a mailbox a person can be reached at.
//
// Measured over 300 commits of `nodejs/node`, `expressjs/express` and
// `github/gitignore`: every `github.com` address in them is the privacy form
// `<id>+<login>@users.noreply.github.com`, and bots appear as
// `dependabot[bot]@users.noreply.github.com`. Both are GitHub identifiers, and
// storing one as an `email` entity would put an address in the graph that
// delivers nothing and invites a phishing mail to a dead end.
//
// The reference implementation this follows filters every `*.github.com`
// address. That is broader than the problem: `security@github.com` is a real
// mailbox, and dropping it because a GitHub employee committed with it would
// discard a true positive. Only the measured privacy domain is filtered, and
// the `noreply.github.com` variant the reference names was not found in any of
// the commits measured, so it is not claimed here.
func isGitHubPrivacyAddress(address string) bool {
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return false
	}
	// A bot account is an automation, not a person, whichever domain it commits
	// from. `[bot]` is the name GitHub itself gives these accounts, so it holds
	// on its own and does not need the privacy domain to agree.
	if strings.Contains(strings.ToLower(address[:at]), "[bot]") {
		return true
	}
	return strings.EqualFold(strings.TrimSuffix(address[at+1:], "."), "users.noreply.github.com")
}

// githubAccount is the linked GitHub account a commit row carries. It is `null`
// for a commit whose address matches no account, which is exactly the case where
// an address cannot be attributed to anybody.
type githubAccount struct {
	Login string `json:"login"`
}

// gitHubCommit is one row of the commits API. Only the fields that decide
// whether an address belongs to the searched user are decoded.
type gitHubCommit struct {
	SHA       string          `json:"sha"`
	HTMLURL   string          `json:"html_url"`
	Author    *githubAccount  `json:"author"`
	Committer *githubAccount  `json:"committer"`
	Commit    gitHubCommitTag `json:"commit"`
}

// gitHubCommitTag is the commit object itself, which carries the addresses that
// the linked accounts above do not.
type gitHubCommitTag struct {
	Author struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"author"`
	Committer struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"committer"`
}

// commitBelongsToUser decides whether a commit row may speak for the searched
// user.
//
// This is the check the reference implementation does not make, and its absence
// produces a wrong answer rather than a thin one. Measured on `tj/commander.js`:
// the newest commits are authored by `abetomo` and `shadowspawn`, so a scan that
// reads the first `From:` header it sees reports `abe@enzou.tokyo` as the email
// of `tj` — the address of a contributor, attributed to somebody else.
//
// A commit counts as the user's when GitHub itself links it to their account,
// and a linked account is the only evidence strong enough to say whose address
// this is. The one addition is an unlinked commit whose address local part is
// the username itself, which is the same claim stated by the commit instead of
// by the API.
func commitBelongsToUser(commit *gitHubCommit, username string) bool {
	for _, linked := range []*githubAccount{commit.Author, commit.Committer} {
		if linked != nil && strings.EqualFold(linked.Login, username) {
			return true
		}
	}
	for _, address := range commitAddresses(commit) {
		at := strings.LastIndex(address, "@")
		if at > 0 && strings.EqualFold(address[:at], username) {
			return true
		}
	}
	return false
}

// commitAddresses returns the addresses a commit carries, author first.
func commitAddresses(commit *gitHubCommit) []string {
	addresses := make([]string, 0, 2)
	for _, raw := range []string{commit.Commit.Author.Email, commit.Commit.Committer.Email} {
		if address, ok := extractEmailCandidate(raw); ok && !isGitHubPrivacyAddress(address) {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// githubPatchAuthorEmail reads the `From:` header of a commit patch, which is
// the fallback for a commit whose API row carries no address at all.
func githubPatchAuthorEmail(ctx context.Context, client *http.Client, username, repository, sha string) string {
	endpoint := fmt.Sprintf("https://github.com/%s/%s/commit/%s.patch",
		url.PathEscape(username), url.PathEscape(repository), url.PathEscape(sha))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	request.Header.Set("User-Agent", archiveUserAgent())
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	head, err := io.ReadAll(io.LimitReader(response.Body, githubPatchPrefixLimit))
	if err != nil {
		return ""
	}
	// The mbox `From:` line names the patch author. Any other address in the
	// header block belongs to somebody mentioned in the diff, so the fallback
	// scan is not taken from the whole prefix: a `git format-patch` header
	// block ends before the first diff, and everything after it is payload.
	header := head
	if cut := indexOfPatchHeaderEnd(head); cut > 0 {
		header = head[:cut]
	}
	if match := patchAuthorPattern.FindSubmatch(header); match != nil {
		if address, ok := extractEmailCandidate(string(match[1])); ok && !isGitHubPrivacyAddress(address) {
			return address
		}
	}
	return ""
}

var patchAuthorPattern = regexp.MustCompile(`(?m)^From:[^\n]*<([^<>\n]+)>`)

func indexOfPatchHeaderEnd(head []byte) int {
	for _, marker := range [][]byte{[]byte("\n---\n"), []byte("\ndiff --git ")} {
		if index := bytes.Index(head, marker); index > 0 {
			return index
		}
	}
	return -1
}

// githubScanLimits reads the three bounds out of the caller's options.
//
// A value of 0 means "no bound", which is what makes these limits technical
// bounds rather than restrictions: the whole commit history of the whole account
// stays reachable, it is simply not the default. That is why the key's presence
// is what is read and not its value — an explicit `0` has to be told apart from
// an option that was never given, and a helper that returns a fallback for both
// would silently turn "unbounded" back into the default.
func githubScanLimits(options map[string]interface{}) (maxRepos, maxCommitPages, commitsPerRepo int) {
	bounded := func(key string, fallback int) int {
		raw, present := options[key]
		if !present {
			return fallback
		}
		switch typed := raw.(type) {
		case float64:
			if typed >= 0 {
				return int(typed)
			}
		case int:
			if typed >= 0 {
				return typed
			}
		case json.Number:
			if parsed, err := typed.Int64(); err == nil && parsed >= 0 {
				return int(parsed)
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil && parsed >= 0 {
				return parsed
			}
		}
		return fallback
	}
	return bounded("max_repos", githubDefaultMaxRepos),
		bounded("max_commit_pages", githubDefaultMaxCommitPages),
		bounded("commits_per_repo", githubDefaultCommitsPerRepo)
}

func transformGitHubRecon(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "GitHub lookup performs a public network request")
	}
	username := strings.TrimSpace(input.Value)
	if !githubUsernamePattern.MatchString(username) {
		return transformError("INVALID_GITHUB_USERNAME", "GitHub username is invalid")
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	client := s.toolClient(ctx)

	var profile struct {
		Login       string `json:"login"`
		HTMLURL     string `json:"html_url"`
		Name        string `json:"name"`
		PublicRepos int    `json:"public_repos"`
		Followers   int    `json:"followers"`
		Type        string `json:"type"`
	}
	// The profile read stays inline rather than moving into a helper: it is the
	// read that decides whether the account exists at all, so a 404 here is an
	// answer about the target rather than a condition any of the three passes
	// below could act on.
	status, err := githubAPIGet(ctx, client, githubAPIUsersBase+url.PathEscape(username), &profile)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		result.Warnings = append(result.Warnings, "GitHub profile was not found")
		return nil
	}
	if status < 200 || status >= 300 {
		return transformError("GITHUB_LOOKUP_FAILED", fmt.Sprintf("GitHub returned HTTP %d", status))
	}
	if profile.Login == "" {
		return transformError("GITHUB_RESPONSE_INVALID", "GitHub response did not contain a profile")
	}
	// The canonical login, not the typed value: GitHub folds case, and every
	// comparison below is made against the account GitHub named.
	username = profile.Login
	result.Entities = append(result.Entities, entity("username", profile.Login, map[string]interface{}{"html_url": profile.HTMLURL, "name": profile.Name, "public_repos": profile.PublicRepos, "followers": profile.Followers, "account_type": profile.Type}, map[string]interface{}{"source": "github_public_api"}))

	maxRepos, maxCommitPages, commitsPerRepo := githubScanLimits(input.Options)
	setTransformMetadata(result, "max_repos", maxRepos)
	setTransformMetadata(result, "max_commit_pages", maxCommitPages)
	setTransformMetadata(result, "commits_per_repo", commitsPerRepo)
	setTransformMetadata(result, "github_token_configured", githubToken() != "")

	seen := map[string]bool{}
	addAddress := func(address, repository, sha, sourceURL, source string) {
		if address == "" || seen[address] || isGitHubPrivacyAddress(address) {
			return
		}
		seen[address] = true
		properties := map[string]interface{}{"source": source}
		provenance := map[string]interface{}{"source": source}
		if repository != "" {
			properties["repository"] = repository
			provenance["repository"] = repository
		}
		if sha != "" {
			properties["commit"] = sha
			provenance["commit"] = sha
		}
		if sourceURL != "" {
			provenance["source_url"] = sourceURL
		}
		result.Entities = append(result.Entities, entity("email", address, properties, provenance))
		result.Relations = append(result.Relations, transformRelation{Type: "mentions_email", SourceType: "username", Source: username, TargetType: "email", Target: address})
	}

	// Pass one: the public event feed. It is one request and it is the only pass
	// that can find an account whose commits are not in its own repositories, so
	// it stays — but every address it offers is filtered the same way a scanned
	// commit is, because the feed mixes in every contributor to a repository the
	// user merely watched.
	eventsErr := githubScanEvents(ctx, client, username, addAddress)

	// Pass two: the repositories and their commits. This is the pass that reads
	// the address the account itself committed with, which the event feed cannot
	// always reach: it covers roughly the last 90 days and only PushEvent.
	//
	// An exhausted budget ends the transform here instead of being walked into.
	// Every request after a `403`/`429` fails the same way, so continuing would
	// spend the rest of the transform producing the same refusal — and, worse,
	// would report it as several separate warnings instead of the one condition
	// that actually stopped the scan.
	if eventsErr != nil {
		result.Warnings = append(result.Warnings, eventsErr.Error())
		if strings.Contains(eventsErr.Error(), "GITHUB_RATE_LIMITED") {
			setTransformMetadata(result, "commit_scan", "skipped: GitHub API budget exhausted")
			return nil
		}
	}
	githubScanCommits(ctx, client, result, username, maxRepos, maxCommitPages, commitsPerRepo, collector, addAddress)

	// The four key and graph passes, ported from `ibnaleem/gosearch` at `687f9ed`
	// (`ssh-keys.go`, `gpg-keys.go`, `social-accounts.go`, `mutual-followers.go`).
	// They live in `osint_github_keys.go`; this is the splice.
	//
	// They run **after** the address passes, not before, because a GPG key's
	// verified addresses and a social account's links are additions to an answer
	// the profile already opened — running them first would spend requests on an
	// account the profile read has since proved does not exist.
	maxFollowers := githubReconDefaultMaxFollowers
	if size := positiveIntOption(input.Options, "max_followers", 0); size > 0 {
		maxFollowers = size
	}
	maxChecks := githubReconDefaultFollowerChecks
	if size := positiveIntOption(input.Options, "max_follower_checks", 0); size > 0 {
		maxChecks = size
	}
	setTransformMetadata(result, "max_followers", maxFollowers)
	setTransformMetadata(result, "max_follower_checks", maxChecks)
	setTransformMetadata(result, "key_passes", githubReconKeyPasses)

	for index, pass := range githubReconKeyPasses {
		if err := collector.checkpoint(ctx); err != nil {
			return nil
		}
		if collector != nil {
			collector.indexPosition(ctx, pass, index, len(githubReconKeyPasses))
		}
		var (
			ran    bool
			status int
			err    error
		)
		switch pass {
		case "ssh_keys":
			status, ran, err = githubReconPassSSHKeys(ctx, client, username, result, collector)
		case "gpg_keys":
			status, ran, err = githubReconPassGPGKeys(ctx, client, username, result, collector)
		case "social_accounts":
			status, ran, err = githubReconPassSocialAccounts(ctx, client, username, result, collector)
		case "mutual_followers":
			status, err = githubReconPassMutualFollowers(ctx, client, username, result, collector, maxFollowers, maxChecks)
			ran = err == nil
		}
		if err != nil {
			// A pass that failed is named, and the run continues. The original
			// printed the error and moved on too, but its error came from
			// `log.Fatal` inside a goroutine in some paths and from a bare
			// `return` in others, so which passes had run at all was not
			// recoverable from its output.
			if strings.Contains(err.Error(), "GITHUB_RATE_LIMITED") {
				result.Warnings = append(result.Warnings,
					"The "+pass+" pass stopped when GitHub refused further requests from this route. "+
						"The keys, links and followers it did not read are absent from this result, and it says so.")
				setTransformMetadata(result, "key_passes_ran", githubReconKeyPasses[:index])
				return nil
			}
			result.Warnings = append(result.Warnings, "The "+pass+" pass did not complete: "+err.Error())
			continue
		}
		if !ran {
			// A non-2xx status is an answer, not a failure, and it is reported as
			// one: GitHub answers `404` for every pass on an account with nothing
			// published there, and `403` when the route is rate-limited.
			result.Warnings = append(result.Warnings,
				"GitHub answered HTTP "+strconv.Itoa(status)+" for the "+pass+" pass, so nothing is reported for it.")
			continue
		}
		setTransformMetadata(result, "key_passes_ran", append(keyPassesRan(result), pass))
	}

	// The check is on the **addresses**, not on the entity count. It used to be
	// `len(result.Entities) == 1`, which was correct while the profile was the only
	// other thing the transform wrote; with the key passes in place a GPG key or a
	// social link makes the count larger than 1 and the warning would have gone
	// silent exactly when it mattered — an account with keys and no address of its
	// own is the case the warning is for.
	if githubReconAddressCount(result) == 0 {
		result.Warnings = append(result.Warnings, "No public commit address was attributable to this account. Commit authors that GitHub does not link to it, and GitHub privacy addresses, are not reported as its email.")
	}
	return nil
}

// keyPassesRan reads back the passes recorded so far.
//
// It exists because `setTransformMetadata` writes an interface{} and the list is
// built up one pass at a time: reading it back through a single cast is what keeps
// the loop below from rebuilding a slice that a previous iteration already wrote,
// which would have left the earlier passes out of the published list.
func keyPassesRan(result *osintTransformResult) []string {
	existing, _ := result.Metadata["key_passes_ran"].([]string)
	return existing
}

// githubReconAddressCount counts the email entities the run produced.
//
// An `email` entity is only written by the address passes — the profile, the event
// feed, the commit scan and the GPG pass — and every one of them filters GitHub
// privacy placeholders out. So "0 addresses" is a statement about addresses and not
// about keys, links or followers.
func githubReconAddressCount(result *osintTransformResult) int {
	total := 0
	for _, item := range result.Entities {
		if item.Type == "email" {
			total++
		}
	}
	return total
}

// githubScanEvents reads the public event feed and offers every address it holds.
//
// The error is returned rather than swallowed. A pass that fails quietly leaves
// the caller with a result that looks complete and is not, and the operator has
// no way to tell that from an account with nothing to show.
func githubScanEvents(ctx context.Context, client *http.Client, username string, add func(address, repository, sha, sourceURL, source string)) error {
	var events []map[string]interface{}
	status, err := githubAPIGet(ctx, client,
		githubAPIUsersBase+url.PathEscape(username)+"/events/public", &events)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return transformError("GITHUB_EVENTS_UNAVAILABLE", fmt.Sprintf("GitHub returned HTTP %d for the public event feed", status))
	}
	for _, event := range events {
		if event["type"] != "PushEvent" {
			continue
		}
		payload, ok := event["payload"].(map[string]interface{})
		if !ok {
			continue
		}
		repository, _ := payload["repo"].(string)
		commits, ok := payload["commits"].([]interface{})
		if !ok {
			continue
		}
		for _, commit := range commits {
			commitMap, ok := commit.(map[string]interface{})
			if !ok {
				continue
			}
			sha, _ := commitMap["sha"].(string)
			for _, candidate := range []interface{}{commitMap["author"], commitMap["committer"], commitMap["email"], payload["head"], payload["head_commit"]} {
				add(normalizeGitHubEmail(candidate), repository, sha, "", "github_public_commit")
			}
		}
	}
	return nil
}

// githubScanCommits walks the account's own repositories and reports the
// addresses of the commits GitHub links to it.
//
// The commits are read oldest-first inside every page that was fetched. A newer
// commit is the more likely one to carry a privacy address, because that is what
// a user switches on over time, so a newest-first walk spends its budget on the
// commits least likely to answer. Reaching further back is a matter of raising
// `max_commit_pages`, which is why the walk is not capped at the first hit: this
// transform answers into a graph, and a partial answer is worse than a slow one.
func githubScanCommits(
	ctx context.Context,
	client *http.Client,
	result *osintTransformResult,
	username string,
	maxRepos, maxCommitPages, commitsPerRepo int,
	collector *transformCollector,
	add func(address, repository, sha, sourceURL, source string),
) {
	repositories, err := githubRepositories(ctx, client, username, maxRepos)
	if err != nil {
		// A budget that ran out part-way is reported rather than swallowed: the
		// profile and the event pass already produced a result, and saying
		// nothing would present that result as the whole answer.
		result.Warnings = append(result.Warnings, err.Error())
		return
	}
	if len(repositories) == 0 {
		return
	}
	setTransformMetadata(result, "repositories_scanned", len(repositories))
	if collector != nil {
		collector.setIndexTotal(ctx, len(repositories))
	}
	for index, repository := range repositories {
		if checkpointErr := collector.checkpoint(ctx); checkpointErr != nil {
			return
		}
		if collector != nil {
			collector.indexPosition(ctx, repository.Name, index, len(repositories))
		}
		githubScanRepository(ctx, client, result, username, repository, maxCommitPages, commitsPerRepo, collector, add)
	}
}

// githubRepository is one public repository of the searched account.
type githubRepository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Archived bool   `json:"archived"`
}

func githubRepositories(ctx context.Context, client *http.Client, username string, maxRepos int) ([]githubRepository, error) {
	// `type=owner` is what keeps a fork out of the scan: a fork's commit history
	// is somebody else's, and attributing it to this account is the mistake this
	// pass exists to avoid.
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=100&type=owner&sort=pushed",
		url.PathEscape(username))
	var repositories []githubRepository
	for page := 1; ; page++ {
		if err := collectorPause(ctx); err != nil {
			return repositories, err
		}
		var batch []githubRepository
		status, err := githubAPIGet(ctx, client, fmt.Sprintf("%s&page=%d", endpoint, page), &batch)
		if err != nil {
			return repositories, err
		}
		if status == http.StatusNotFound {
			return nil, nil
		}
		if status < 200 || status >= 300 {
			return repositories, nil
		}
		if len(batch) == 0 {
			break
		}
		repositories = append(repositories, batch...)
		if maxRepos > 0 && len(repositories) >= maxRepos {
			repositories = repositories[:maxRepos]
			break
		}
		if len(batch) < 100 {
			break
		}
	}
	return repositories, nil
}

// collectorPause is the pause point of a helper that has no collector in hand.
// A cancelled job stops between pages instead of finishing the account.
func collectorPause(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func githubScanRepository(
	ctx context.Context,
	client *http.Client,
	result *osintTransformResult,
	username string,
	repository githubRepository,
	maxCommitPages, commitsPerRepo int,
	collector *transformCollector,
	add func(address, repository, sha, sourceURL, source string),
) {
	name := repository.Name
	if name == "" {
		return
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?per_page=100",
		url.PathEscape(username), url.PathEscape(name))
	var scanned []gitHubCommit
	for page := 1; ; page++ {
		if err := collectorPause(ctx); err != nil {
			return
		}
		var batch []gitHubCommit
		status, err := githubAPIGet(ctx, client, fmt.Sprintf("%s&page=%d", endpoint, page), &batch)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
			return
		}
		// 409 is GitHub's answer for "this repository has no commits", which is
		// a fact about the repository and not a failure of the scan.
		if status == http.StatusConflict || status == http.StatusNotFound {
			return
		}
		if status < 200 || status >= 300 {
			return
		}
		if len(batch) == 0 {
			break
		}
		scanned = append(scanned, batch...)
		if maxCommitPages > 0 && page >= maxCommitPages {
			break
		}
		if len(batch) < 100 {
			break
		}
	}
	if len(scanned) == 0 {
		return
	}
	// Oldest first, bounded by `commits_per_repo`. `0` walks everything that was
	// fetched, which is the same "no bound" the other two options use.
	checked := 0
	for index := len(scanned) - 1; index >= 0; index-- {
		if commitsPerRepo > 0 && checked >= commitsPerRepo {
			break
		}
		commit := scanned[index]
		if commit.SHA == "" || !commitBelongsToUser(&commit, username) {
			continue
		}
		if err := collector.checkpoint(ctx); err != nil {
			return
		}
		checked++
		sourceURL := fmt.Sprintf("https://github.com/%s/%s/commit/%s", username, name, commit.SHA)
		addresses := commitAddresses(&commit)
		if len(addresses) == 0 {
			// A linked commit with no address in its API row is the one case the
			// patch is read for. The attribution is already established by the
			// link, so the header is read only after that, never before.
			if address := githubPatchAuthorEmail(ctx, client, username, name, commit.SHA); address != "" {
				addresses = []string{address}
			}
		}
		for _, address := range addresses {
			add(address, name, commit.SHA, sourceURL, "github_commit_patch")
		}
	}
}

func normalizeGitHubEmail(value interface{}) string {
	switch typed := value.(type) {
	case string:
		candidate := strings.TrimSpace(typed)
		if candidate == "" {
			return ""
		}
		if email, ok := extractEmailCandidate(candidate); ok {
			return email
		}
		return ""
	case map[string]interface{}:
		for _, key := range []string{"email", "value"} {
			if candidate := normalizeGitHubEmail(typed[key]); candidate != "" {
				return candidate
			}
		}
		if nested, ok := typed["author"].(map[string]interface{}); ok {
			if candidate := normalizeGitHubEmail(nested["email"]); candidate != "" {
				return candidate
			}
		}
		if nested, ok := typed["committer"].(map[string]interface{}); ok {
			if candidate := normalizeGitHubEmail(nested["email"]); candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func extractEmailCandidate(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	matches := regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`).FindStringSubmatch(strings.TrimSpace(value))
	if len(matches) == 0 {
		return "", false
	}
	return strings.ToLower(matches[0]), true
}

func runDomainNormalize(result *osintTransformResult, value string) error {
	domain, err := normalizeDomainForTransform(value)
	if err != nil {
		return err
	}
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}))
	return nil
}

func runURLHost(result *osintTransformResult, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (strings.ToLower(parsed.Scheme) != "http" && strings.ToLower(parsed.Scheme) != "https") || parsed.Hostname() == "" {
		return transformError("INVALID_URL", "URL must be absolute HTTP(S)")
	}
	host := strings.ToLower(parsed.Hostname())
	result.Entities = append(result.Entities, entity("url", parsed.String(), nil, map[string]interface{}{"source": "local_transform"}), entity("domain", host, nil, map[string]interface{}{"source": "local_transform"}))
	result.Relations = append(result.Relations, transformRelation{Type: "hosted_on", SourceType: "url", Source: parsed.String(), TargetType: "domain", Target: host})
	return nil
}

type ghdbDorkItem struct {
	category    string
	title       string
	description string
	riskScore   int
	query       string
}

func getGHDBDorks(apexDomain, domain, cms string) []ghdbDorkItem {
	dorks := []ghdbDorkItem{
		{
			category:    "public_secrets",
			title:       "Exposed Secrets & API Keys",
			description: "Finds exposed environment, config, or yaml files containing DB passwords, API tokens, or private keys",
			riskScore:   85,
			query:       fmt.Sprintf("site:%s (filetype:env OR filetype:yml OR filetype:yaml OR filetype:json OR filetype:ini OR filetype:toml) (\"DB_PASSWORD\" OR \"API_KEY\" OR \"BEGIN PRIVATE KEY\" OR \"SECRET_KEY\")", apexDomain),
		},
		{
			category:    "exposed_configs",
			title:       "Database Backups & Dumps",
			description: "Finds database dumps, SQL files, or archive backups left in public web roots",
			riskScore:   80,
			query:       fmt.Sprintf("site:%s (filetype:sql OR filetype:dump OR filetype:bak OR filetype:backup OR filetype:old OR filetype:swp)", apexDomain),
		},
		{
			category:    "git_exposure",
			title:       "Version Control & Source Exposure",
			description: "Detects exposed .git repositories, .svn directories, or Docker/CI configuration files",
			riskScore:   80,
			query:       fmt.Sprintf("site:%s (inurl:\"/.git\" OR inurl:\"/.env\" OR inurl:\"/wp-config.php\" OR inurl:\"/.svn\" OR inurl:\"/Dockerfile\")", apexDomain),
		},
		{
			category:    "admin_panels",
			title:       "Admin & Management Portals",
			description: "Discovers administrator login panels, dashboard interfaces, or hosting control portals",
			riskScore:   50,
			query:       fmt.Sprintf("site:%s (inurl:admin OR inurl:login OR inurl:dashboard OR inurl:cpanel OR inurl:webmin OR inurl:phpmyadmin)", apexDomain),
		},
		{
			category:    "directory_listing",
			title:       "Open Directory Listings",
			description: "Identifies web server directories with indexing enabled, exposing internal folder contents",
			riskScore:   45,
			query:       fmt.Sprintf("site:%s (intitle:\"index of /\" OR intitle:\"directory listing\" OR intitle:\"index.of /\")", apexDomain),
		},
		{
			category:    "debug_logs",
			title:       "Error Logs & Debug Information",
			description: "Finds application error logs, debug traces, and stack exceptions containing internal paths and queries",
			riskScore:   60,
			query:       fmt.Sprintf("site:%s (filetype:log OR inurl:log) (\"error\" OR \"PHP Fatal error\" OR \"stack trace\" OR \"SQL syntax\")", apexDomain),
		},
		{
			category:    "server_status",
			title:       "Server Status & Diagnostic Pages",
			description: "Detects diagnostic pages such as phpinfo() or server-status displaying environment and runtime details",
			riskScore:   45,
			query:       fmt.Sprintf("site:%s (inurl:phpinfo.php OR inurl:info.php OR intitle:\"Apache Status\" OR inurl:server-status OR inurl:elmah.axd)", apexDomain),
		},
		{
			category:    "exposed_documents",
			title:       "Confidential Documents",
			description: "Locates indexed office and PDF documents labeled confidential, internal, or restricted",
			riskScore:   40,
			query:       fmt.Sprintf("site:%s (filetype:doc OR filetype:docx OR filetype:pdf OR filetype:xls OR filetype:xlsx) (\"confidential\" OR \"internal use only\" OR \"not for public\")", apexDomain),
		},
		{
			category:    "subdomains_discovery",
			title:       "Subdomain Enumeration",
			description: "Discovers indexed subdomains by excluding the main site hostname",
			riskScore:   30,
			query:       fmt.Sprintf("site:*.%s -site:%s", apexDomain, domain),
		},
		{
			category:    "api_endpoints",
			title:       "API Documentation & Endpoints",
			description: "Finds interactive API specifications such as Swagger UI, OpenAPI, or GraphQL schemas",
			riskScore:   40,
			query:       fmt.Sprintf("site:%s (inurl:swagger OR inurl:api-docs OR inurl:graphql OR inurl:graphiql OR inurl:\"/api/v1\")", apexDomain),
		},
		{
			category:    "installers_setup",
			title:       "Unfinished Installers & Setup Pages",
			description: "Finds installation or upgrade scripts that may allow re-installation or takeover",
			riskScore:   70,
			query:       fmt.Sprintf("site:%s (inurl:install.php OR inurl:setup.php OR inurl:upgrade.php OR inurl:installer.php)", apexDomain),
		},
		{
			category:    "cloud_storage",
			title:       "Cloud Storage & S3 Buckets",
			description: "Finds publicly referenced AWS S3, Google Cloud Storage, or Azure Blob containers related to the target",
			riskScore:   50,
			query:       fmt.Sprintf("(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) \"%s\"", apexDomain),
		},
	}

	switch cms {
	case "wordpress":
		dorks = append(dorks,
			ghdbDorkItem{
				category:    "cms_wordpress",
				title:       "WordPress REST API User Enumeration",
				description: "Exploit-DB GHDB: Discovers publicly accessible WordPress REST API user endpoint exposing usernames and roles",
				riskScore:   65,
				query:       fmt.Sprintf("site:%s inurl:\"/wp-json/wp/v2/users\"", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_wordpress",
				title:       "WordPress wp-config Backup Exposure",
				description: "Exploit-DB GHDB: Finds backup copies of wp-config.php containing database credentials and salt keys",
				riskScore:   85,
				query:       fmt.Sprintf("site:%s (inurl:wp-config.php.bak OR inurl:wp-config.php~ OR inurl:wp-config.old)", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_wordpress",
				title:       "WordPress Plugin Readme Disclosure",
				description: "Exploit-DB GHDB: Discovers exposed plugin readme.txt files revealing exact installed plugin versions",
				riskScore:   55,
				query:       fmt.Sprintf("site:%s inurl:\"/wp-content/plugins/\" filetype:txt \"readme.txt\"", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_wordpress",
				title:       "WordPress Login & XML-RPC Interfaces",
				description: "Exploit-DB GHDB: Locates wp-login.php and XML-RPC endpoints vulnerable to brute force and pingback amplification",
				riskScore:   50,
				query:       fmt.Sprintf("site:%s (inurl:wp-login.php OR inurl:xmlrpc.php)", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_wordpress",
				title:       "WordPress Debug Logs Exposure",
				description: "Exploit-DB GHDB: Detects publicly exposed debug.log files containing application errors, stack traces, and database queries",
				riskScore:   75,
				query:       fmt.Sprintf("site:%s inurl:\"/wp-content/debug.log\"", apexDomain),
			},
		)
	case "joomla":
		dorks = append(dorks,
			ghdbDorkItem{
				category:    "cms_joomla",
				title:       "Joomla configuration.php Backup Exposure",
				description: "Exploit-DB GHDB: Finds configuration.php backups containing database credentials and secret key",
				riskScore:   85,
				query:       fmt.Sprintf("site:%s (inurl:\"configuration.php.bak\" OR inurl:\"configuration.php~\")", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_joomla",
				title:       "Joomla Administrator Portal",
				description: "Exploit-DB GHDB: Discovers Joomla backend administration login",
				riskScore:   50,
				query:       fmt.Sprintf("site:%s inurl:\"/administrator/index.php\"", apexDomain),
			},
		)
	case "drupal":
		dorks = append(dorks,
			ghdbDorkItem{
				category:    "cms_drupal",
				title:       "Drupal settings.php Backup Exposure",
				description: "Exploit-DB GHDB: Finds settings.php backups containing database credentials and hash salt",
				riskScore:   85,
				query:       fmt.Sprintf("site:%s inurl:\"/sites/default/settings.php.bak\"", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_drupal",
				title:       "Drupal User Login & Register",
				description: "Exploit-DB GHDB: Locates Drupal authentication endpoints",
				riskScore:   50,
				query:       fmt.Sprintf("site:%s (inurl:\"/user/login\" OR inurl:\"/user/register\")", apexDomain),
			},
		)
	case "bitrix":
		dorks = append(dorks,
			ghdbDorkItem{
				category:    "cms_bitrix",
				title:       "1C-Bitrix Admin Management Panel",
				description: "Exploit-DB GHDB: Discovers 1C-Bitrix admin interface",
				riskScore:   50,
				query:       fmt.Sprintf("site:%s inurl:\"/bitrix/admin/\"", apexDomain),
			},
			ghdbDorkItem{
				category:    "cms_bitrix",
				title:       "1C-Bitrix Database Configuration Exposure",
				description: "Exploit-DB GHDB: Finds dbconn.php or dbconn_error.php database settings",
				riskScore:   85,
				query:       fmt.Sprintf("site:%s (inurl:\"/bitrix/php_interface/dbconn.php\" OR inurl:\"/bitrix/php_interface/dbconn_error.php\")", apexDomain),
			},
		)
	}

	return dorks
}

func runGHDBLinks(result *osintTransformResult, value string) error {
	domain, err := normalizeDomainForTransform(value)
	if err != nil {
		return err
	}
	apexDomain := strings.TrimPrefix(domain, "www.")
	dorks := getGHDBDorks(apexDomain, domain, "")

	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}))
	if apexDomain != domain {
		result.Entities = append(result.Entities, entity("domain", apexDomain, nil, map[string]interface{}{"source": "local_transform"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "subdomain_of",
			SourceType: "domain",
			Source:     domain,
			TargetType: "domain",
			Target:     apexDomain,
			Provenance: map[string]interface{}{"source": "local_transform"},
		})
	}
	for _, dork := range dorks {
		searchURL := "https://www.google.com/search?q=" + url.QueryEscape(dork.query)
		ddgURL := "https://duckduckgo.com/?q=" + url.QueryEscape(dork.query)
		bingURL := "https://www.bing.com/search?q=" + url.QueryEscape(dork.query)
		displayVal := "GHDB: " + dork.title

		uEntity := entityWithDisplayAndRisk("url", searchURL, displayVal, dork.riskScore, map[string]interface{}{
			"category":      dork.category,
			"title":         dork.title,
			"description":   dork.description,
			"dork":          dork.query,
			"target_domain": domain,
			"google_url":    searchURL,
			"ddg_url":       ddgURL,
			"bing_url":      bingURL,
		}, map[string]interface{}{"source": "ghdb_transform"})
		result.Entities = append(result.Entities, uEntity)
		result.Relations = append(result.Relations, transformRelation{
			Type:       "recon_query",
			SourceType: "domain",
			Source:     domain,
			TargetType: "url",
			Target:     searchURL,
			Properties: map[string]interface{}{
				"category": dork.category,
				"title":    dork.title,
			},
			Provenance: map[string]interface{}{"source": "ghdb_transform"},
		})
	}
	return nil
}

var (
	htmlTagPattern    = regexp.MustCompile(`<[^>]+>`)
	ddgLinkPattern    = regexp.MustCompile(`(?i)<a[^>]*class=["'][^"']*result__a[^"']*["'][^>]*href=["'][^"']*uddg=([^&"'\s]+)[^"']*["'][^>]*>(.*?)</a>`)
	ddgSnippetPattern = regexp.MustCompile(`(?i)<a[^>]*class=["'][^"']*result__snippet[^"']*["'][^>]*>(.*?)</a>`)
)

func stripHTMLTags(s string) string {
	clean := htmlTagPattern.ReplaceAllString(s, "")
	return strings.TrimSpace(html.UnescapeString(clean))
}

type ddgSearchResult struct {
	URL     string
	Title   string
	Snippet string
}

func scrapeDuckDuckGo(ctx context.Context, client *http.Client, query string) ([]ddgSearchResult, error) {
	targetURL := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0")
	req.Header.Set("Referer", "https://duckduckgo.com/")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("duckduckgo returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)
	matches := ddgLinkPattern.FindAllStringSubmatch(bodyStr, -1)
	snippetMatches := ddgSnippetPattern.FindAllStringSubmatch(bodyStr, -1)

	var results []ddgSearchResult
	seen := make(map[string]bool)

	for i, m := range matches {
		if len(m) < 3 {
			continue
		}
		rawURL := m[1]
		decodedURL, err := url.QueryUnescape(rawURL)
		if err != nil {
			decodedURL = rawURL
		}
		decodedURL = strings.TrimSpace(decodedURL)
		if decodedURL == "" || seen[decodedURL] {
			continue
		}
		seen[decodedURL] = true

		title := stripHTMLTags(m[2])
		snippet := ""
		if i < len(snippetMatches) && len(snippetMatches[i]) >= 2 {
			snippet = stripHTMLTags(snippetMatches[i][1])
		}

		results = append(results, ddgSearchResult{
			URL:     decodedURL,
			Title:   title,
			Snippet: snippet,
		})
	}
	return results, nil
}

func (s *server) detectTargetCMS(ctx context.Context, client *http.Client, host string) (string, []string) {
	canonicalHost := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, scheme := range []string{"https", "http"} {
		target := scheme + "://" + canonicalHost
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		found, evidence := technologyEvidence(
			resp.Header.Get("Server"),
			resp.Header.Get("X-Powered-By"),
			resp.Header.Get("Set-Cookie"),
			body,
		)
		for _, cms := range []string{"wordpress", "joomla", "drupal", "bitrix", "moodle"} {
			if _, ok := found[cms]; ok {
				return cms, evidence
			}
		}
		lowered := strings.ToLower(string(body))
		if strings.Contains(lowered, "wp-content") || strings.Contains(lowered, "wp-includes") || strings.Contains(lowered, "wp-json") {
			return "wordpress", []string{"body:wp-content"}
		}
		if strings.Contains(lowered, "/components/com_") || strings.Contains(lowered, "option=com_") {
			return "joomla", []string{"body:joomla"}
		}
		if strings.Contains(lowered, "drupal-settings") || strings.Contains(lowered, "/sites/default/") {
			return "drupal", []string{"body:drupal"}
		}
		if strings.Contains(lowered, "/bitrix/") {
			return "bitrix", []string{"body:bitrix"}
		}
		if strings.Contains(lowered, "moodle") {
			return "moodle", []string{"body:moodle"}
		}
	}
	return "", nil
}

func (s *server) runGHDBSearchWithCollector(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "GHDB active search queries search engines and detects CMS over the network")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	apexDomain := strings.TrimPrefix(domain, "www.")
	result.LocalOnly, result.NetworkUsed = false, true

	// Domain entities and hierarchy
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "ghdb_search"}))
	if apexDomain != domain {
		result.Entities = append(result.Entities, entity("domain", apexDomain, nil, map[string]interface{}{"source": "ghdb_search"}))
		result.Relations = append(result.Relations, transformRelation{
			Type:       "subdomain_of",
			SourceType: "domain",
			Source:     domain,
			TargetType: "domain",
			Target:     apexDomain,
			Provenance: map[string]interface{}{"source": "ghdb_search"},
		})
	}

	client := s.toolClient(ctx)

	// Step 1: Detect CMS on target host
	cms, cmsEvidence := s.detectTargetCMS(ctx, client, domain)
	if cms == "" && apexDomain != domain {
		cms, cmsEvidence = s.detectTargetCMS(ctx, client, apexDomain)
	}

	if cms != "" {
		cmsEntity := entityWithDisplayAndRisk("technology", cms, "CMS: "+strings.ToUpper(cms[:1])+cms[1:], 10, map[string]interface{}{
			"category": "cms",
			"name":     cms,
			"evidence": cmsEvidence,
		}, map[string]interface{}{"source": "cms_detection"})
		result.Entities = append(result.Entities, cmsEntity)
		result.Relations = append(result.Relations, transformRelation{
			Type:       "uses",
			SourceType: "domain",
			Source:     domain,
			TargetType: "technology",
			Target:     cms,
			Provenance: map[string]interface{}{"source": "cms_detection"},
		})
		setTransformMetadata(result, "detected_cms", cms)
	}

	// Step 2: Retrieve dorks (general + CMS-specific)
	dorks := getGHDBDorks(apexDomain, domain, cms)

	// Add all GHDB dork query nodes for manual exploration / one-click queries
	for _, dork := range dorks {
		searchURL := "https://www.google.com/search?q=" + url.QueryEscape(dork.query)
		ddgURL := "https://duckduckgo.com/?q=" + url.QueryEscape(dork.query)
		bingURL := "https://www.bing.com/search?q=" + url.QueryEscape(dork.query)
		displayVal := "GHDB: " + dork.title

		uEntity := entityWithDisplayAndRisk("url", searchURL, displayVal, dork.riskScore, map[string]interface{}{
			"category":      dork.category,
			"title":         dork.title,
			"description":   dork.description,
			"dork":          dork.query,
			"target_domain": domain,
			"google_url":    searchURL,
			"ddg_url":       ddgURL,
			"bing_url":      bingURL,
		}, map[string]interface{}{"source": "ghdb_transform"})
		result.Entities = append(result.Entities, uEntity)
		result.Relations = append(result.Relations, transformRelation{
			Type:       "recon_query",
			SourceType: "domain",
			Source:     domain,
			TargetType: "url",
			Target:     searchURL,
			Properties: map[string]interface{}{
				"category": dork.category,
				"title":    dork.title,
			},
			Provenance: map[string]interface{}{"source": "ghdb_transform"},
		})
	}

	// Step 3: Active Dorking / Search Scraper via DuckDuckGo
	scrapeQueries := []struct {
		query    string
		category string
	}{
		{query: fmt.Sprintf("site:*.%s -site:%s", apexDomain, domain), category: "subdomains_discovery"},
		{query: fmt.Sprintf("site:%s (filetype:env OR filetype:sql OR filetype:log OR filetype:bak)", apexDomain), category: "exposed_configs"},
		{query: fmt.Sprintf("site:%s (inurl:admin OR inurl:login OR inurl:dashboard)", apexDomain), category: "admin_panels"},
	}

	if cms == "wordpress" {
		scrapeQueries = append(scrapeQueries,
			struct {
				query    string
				category string
			}{query: fmt.Sprintf("site:%s (inurl:wp-json OR inurl:wp-content OR inurl:wp-login)", apexDomain), category: "cms_wordpress"},
		)
	} else if cms != "" {
		for _, d := range dorks {
			if strings.HasPrefix(d.category, "cms_") {
				scrapeQueries = append(scrapeQueries, struct {
					query    string
					category string
				}{query: d.query, category: d.category})
				break
			}
		}
	} else {
		scrapeQueries = append(scrapeQueries,
			struct {
				query    string
				category string
			}{query: fmt.Sprintf("site:%s intitle:\"index of /\"", apexDomain), category: "directory_listing"},
		)
	}

	seenURLs := make(map[string]bool)
	seenSubdomains := make(map[string]bool)
	discoveredCount := 0

	for _, sq := range scrapeQueries {
		if collector != nil {
			if err := collector.checkpoint(ctx); err != nil {
				break
			}
		}
		searchResults, err := scrapeDuckDuckGo(ctx, client, sq.query)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("search scraper warning for query %q: %v", sq.query, err))
			continue
		}

		for _, item := range searchResults {
			targetParsed, parseErr := url.Parse(item.URL)
			if parseErr != nil {
				continue
			}
			targetHost := strings.ToLower(targetParsed.Hostname())
			if targetHost == "" {
				continue
			}

			// Ensure discovered URL belongs to target domain or its subdomains
			if targetHost != apexDomain && !strings.HasSuffix(targetHost, "."+apexDomain) {
				continue
			}

			// Add discovered subdomain if not seen
			if targetHost != domain && targetHost != apexDomain && !seenSubdomains[targetHost] {
				seenSubdomains[targetHost] = true
				result.Entities = append(result.Entities, entity("subdomain", targetHost, nil, map[string]interface{}{"source": "ghdb_search"}))
				result.Relations = append(result.Relations, transformRelation{
					Type:       "subdomain_of",
					SourceType: "subdomain",
					Source:     targetHost,
					TargetType: "domain",
					Target:     apexDomain,
					Provenance: map[string]interface{}{"source": "ghdb_search"},
				})
			}

			// Add discovered URL
			if !seenURLs[item.URL] {
				seenURLs[item.URL] = true
				discoveredCount++

				risk := 20
				loweredURL := strings.ToLower(item.URL)
				if strings.Contains(loweredURL, ".env") || strings.Contains(loweredURL, ".sql") || strings.Contains(loweredURL, ".bak") || strings.Contains(loweredURL, "wp-config") || strings.Contains(loweredURL, "dbconn") {
					risk = 85
				} else if strings.Contains(loweredURL, "admin") || strings.Contains(loweredURL, "login") || strings.Contains(loweredURL, "dashboard") || strings.Contains(loweredURL, "phpmyadmin") || strings.Contains(loweredURL, "install.php") {
					risk = 60
				} else if strings.Contains(loweredURL, "log") || strings.Contains(loweredURL, "wp-json/wp/v2/users") || strings.Contains(loweredURL, "xmlrpc.php") {
					risk = 50
				} else if strings.Contains(loweredURL, "wp-content") || strings.Contains(loweredURL, "mod/") || strings.Contains(loweredURL, "api") {
					risk = 30
				}

				displayVal := item.Title
				if displayVal == "" || strings.EqualFold(displayVal, targetHost) || strings.EqualFold(displayVal, "www."+targetHost) {
					displayVal = targetParsed.Path
					if targetParsed.RawQuery != "" {
						displayVal = targetParsed.Path + "?" + targetParsed.RawQuery
					}
					if displayVal == "" || displayVal == "/" {
						displayVal = item.URL
					}
				}
				if len(displayVal) > 75 {
					displayVal = displayVal[:72] + "..."
				}

				uEntity := entityWithDisplayAndRisk("url", item.URL, displayVal, risk, map[string]interface{}{
					"title":         item.Title,
					"snippet":       item.Snippet,
					"found_by_dork": sq.query,
					"category":      sq.category,
					"hostname":      targetHost,
				}, map[string]interface{}{
					"source":        "ghdb_search",
					"search_engine": "duckduckgo",
				})
				result.Entities = append(result.Entities, uEntity)

				hostType := "domain"
				if targetHost != domain && targetHost != apexDomain {
					hostType = "subdomain"
				}
				result.Relations = append(result.Relations, transformRelation{
					Type:       "exposes",
					SourceType: hostType,
					Source:     targetHost,
					TargetType: "url",
					Target:     item.URL,
					Properties: map[string]interface{}{
						"category": sq.category,
					},
					Provenance: map[string]interface{}{"source": "ghdb_search"},
				})
			}
		}
	}

	setTransformMetadata(result, "discovered_urls_count", discoveredCount)
	setTransformMetadata(result, "discovered_subdomains_count", len(seenSubdomains))

	return nil
}

func (s *server) runReverseDNS(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "reverse DNS performs a network lookup")
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return transformError("INVALID_IP", "IP address is invalid")
	}
	if strings.Contains(value, "/") {
		// A range is not a single address, and enumerating every address in it
		// would be a scan of the whole range rather than one reverse lookup.
		return transformError("INVALID_IP", "a CIDR range is not a single address; reverse DNS needs one specific address")
	}
	result.LocalOnly, result.NetworkUsed = false, true
	client := s.toolClient(ctx)
	routed := resolverForContext(ctx, client, s)
	addresses := []string{}
	host := ""
	if ip := net.ParseIP(value); ip != nil {
		addresses = append(addresses, ip.String())
	} else {
		// A hostname carries PTR information too, but only through its
		// addresses: the forward answer is stored so the graph keeps the
		// domain, its addresses and every name those addresses answer with.
		normalized, err := normalizeDomainForTransform(value)
		if err != nil {
			return err
		}
		host = normalized
		resolved, err := routed.lookupHost(ctx, normalized)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
		if len(resolved) == 0 {
			// A name that resolves nowhere is a failed lookup, not evidence. Adding
			// the host as an entity anyway would put an identity in the graph with
			// no address and no pointer behind it, and the result would read as a
			// successful lookup of something that does not exist.
			return nil
		}
		addresses = append(addresses, resolved...)
		result.Entities = append(result.Entities, entity("domain", normalized, nil, map[string]interface{}{"source": "reverse_dns"}))
	}
	if len(addresses) == 0 {
		return nil
	}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s is not an address that reverse DNS can ask about", address))
			continue
		}
		canonical := ip.String()
		names, err := routed.lookupHostReverse(ctx, canonical)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
		result.Entities = append(result.Entities, entity("ip", canonical, nil, map[string]interface{}{"source": "reverse_dns"}))
		if host != "" {
			result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: host, TargetType: "ip", Target: canonical})
		}
		for _, name := range names {
			name = strings.TrimSuffix(strings.ToLower(name), ".")
			result.Entities = append(result.Entities, entity("domain", name, nil, map[string]interface{}{"source": "reverse_dns"}))
			result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: name, TargetType: "ip", Target: canonical})
		}
		// Who else answers on this address. PTR says what the address is called;
		// this says who else is standing on it, which on a shared host is the
		// list of organisations an investigator actually wants.
		// The phase is asked and the answer is recorded whatever it is. A
		// neighbour list is the second half of what an address lookup is for,
		// and a result that silently omits it is indistinguishable from a result
		// where it found nothing.
		setTransformMetadata(result, "reverse_ip_asked", canonical)
		coHosted, note, neighbourErr := s.sharedHostNames(ctx, client, canonical)
		if neighbourErr != nil {
			setTransformMetadata(result, "reverse_ip_error", neighbourErr.Error())
			// A neighbour list that could not be read is a warning, not a failed
			// lookup: the PTR answer above is complete on its own and the result
			// must not be thrown away because a second index refused.
			result.Warnings = append(result.Warnings, "shared hosting names: "+neighbourErr.Error())
		} else {
			if note != "" {
				result.Warnings = append(result.Warnings, "shared hosting names: "+note)
			}
			added := 0
			for _, name := range coHosted {
				result.Entities = append(result.Entities, entity("domain", name, nil, map[string]interface{}{"source": "shared_hosting_index"}))
				result.Relations = append(result.Relations, transformRelation{Type: "hosted_on", SourceType: "domain", Source: name, TargetType: "ip", Target: canonical, Provenance: map[string]interface{}{"source": "shared_hosting_index"}})
				added++
			}
			setTransformMetadata(result, "reverse_ip_read", added)
			if added == 0 && note == "" {
				result.Warnings = append(result.Warnings, fmt.Sprintf("the shared-hosting index holds no other name for %s", canonical))
			}
		}
	}
	return nil
}

func (s *server) runDNSRecords(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "DNS lookup performs a network request")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly, result.NetworkUsed = false, true
	client := s.toolClient(ctx)
	// The resolver is chosen from the same route the request client was built
	// from, so a run over a SOCKS5 route cannot resolve a name one way and reach
	// it another. Over such a route the query itself is an HTTPS request, because
	// a Tor relay refuses to exit on port 53.
	routed := resolverForContext(ctx, client, s)

	// Check cancellation before issuing queries
	if err := ctx.Err(); err != nil {
		return err
	}

	dnsProps := map[string]interface{}{}
	dnsErrors := map[string]string{}

	// 1. A / AAAA queries via lookupHost
	ips, err := routed.lookupHost(ctx, domain)
	if err != nil {
		dnsErrors["A_AAAA"] = err.Error()
		result.Warnings = append(result.Warnings, "DNS A/AAAA: "+err.Error())
	} else if len(ips) > 0 {
		dnsProps["ips"] = ips
	}

	// 2. CNAME record
	if cname, cnameErr := routed.lookupCNAME(ctx, domain); cnameErr != nil {
		dnsErrors["CNAME"] = cnameErr.Error()
	} else if cname != "" {
		dnsProps["cname"] = cname
	}

	// 3. MX records
	if mx, mxErr := routed.lookupMX(ctx, domain); mxErr != nil {
		dnsErrors["MX"] = mxErr.Error()
	} else if len(mx) > 0 {
		dnsProps["mx"] = mx
	}

	// 4. NS records
	if ns, nsErr := routed.lookupNS(ctx, domain); nsErr != nil {
		dnsErrors["NS"] = nsErr.Error()
	} else if len(ns) > 0 {
		dnsProps["ns"] = ns
	}

	// 5. TXT records
	if txt, txtErr := routed.lookupTXT(ctx, domain); txtErr != nil {
		dnsErrors["TXT"] = txtErr.Error()
	} else if len(txt) > 0 {
		dnsProps["txt"] = txt
	}

	// 6. SOA record
	if soa, soaErr := routed.lookupSOA(ctx, domain); soaErr != nil {
		dnsErrors["SOA"] = soaErr.Error()
	} else if soa != "" {
		dnsProps["soa"] = soa
	}

	// 7. CAA records
	if caa, caaErr := routed.lookupCAA(ctx, domain); caaErr != nil {
		dnsErrors["CAA"] = caaErr.Error()
	} else if len(caa) > 0 {
		dnsProps["caa"] = caa
	}

	// Attach explicit DNS errors and records to properties
	domainProps := map[string]interface{}{"source": "dns_records"}
	for k, v := range dnsProps {
		domainProps["dns_"+k] = v
	}
	if len(dnsErrors) > 0 {
		domainProps["dns_errors"] = dnsErrors
	}

	result.Entities = append(result.Entities, entity("domain", domain, nil, domainProps))
	for _, ip := range ips {
		result.Entities = append(result.Entities, entity("ip", ip, nil, map[string]interface{}{"source": "dns_records"}))
		result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: domain, TargetType: "ip", Target: ip})
	}

	// Add relations for CNAME, MX and NS if present
	if cname, ok := dnsProps["cname"].(string); ok && cname != "" {
		result.Entities = append(result.Entities, entity("domain", cname, nil, map[string]interface{}{"source": "dns_cname"}))
		result.Relations = append(result.Relations, transformRelation{Type: "cname", SourceType: "domain", Source: domain, TargetType: "domain", Target: cname})
	}
	if mxList, ok := dnsProps["mx"].([]string); ok {
		for _, mxHost := range mxList {
			result.Entities = append(result.Entities, entity("domain", mxHost, nil, map[string]interface{}{"source": "dns_mx"}))
			result.Relations = append(result.Relations, transformRelation{Type: "mx", SourceType: "domain", Source: domain, TargetType: "domain", Target: mxHost})
		}
	}
	if nsList, ok := dnsProps["ns"].([]string); ok {
		for _, nsHost := range nsList {
			result.Entities = append(result.Entities, entity("domain", nsHost, nil, map[string]interface{}{"source": "dns_ns"}))
			result.Relations = append(result.Relations, transformRelation{Type: "ns", SourceType: "domain", Source: domain, TargetType: "domain", Target: nsHost})
		}
	}

	if len(ips) == 0 {
		// Nothing resolved, so there is nothing to have a reputation for. Saying
		// so is better than asking the index about a host the resolver could not
		// even name.
		result.Warnings = append(result.Warnings, "no address resolved, so no public reputation was requested")
		return nil
	}
	// The addresses a lookup just produced are exactly the identities a third
	// party has published something about, so the reputation is asked for them
	// here instead of as a separate tool the operator has to remember to run.
	// One request per kind, not one per address: the batch endpoint is what keeps
	// this from being a loop whose size the operator would have to guess.
	if domainVerdicts, verdictErr := s.filescanVerdicts(ctx, client, "domain", []string{domain}); verdictErr != nil {
		result.Warnings = append(result.Warnings, "public reputation for the domain: "+verdictErr.Error())
	} else {
		filescanReputation(result, domainVerdicts, "domains_marked")
	}
	if ipVerdicts, verdictErr := s.filescanVerdicts(ctx, client, "ip", ips); verdictErr != nil {
		result.Warnings = append(result.Warnings, "public reputation for the addresses: "+verdictErr.Error())
	} else {
		filescanReputation(result, ipVerdicts, "ips_marked")
	}
	// The registry's own record of the name: registrar, dates, nameservers. RDAP
	// is read before the reputation so a name the registry does not hold is
	// reported as such instead of being enriched from a third party's summary.
	registration, rdapErr := s.rdapDomain(ctx, client, domain)
	if rdapErr != nil {
		result.Warnings = append(result.Warnings, "registry record: "+rdapErr.Error())
	} else {
		markDomainRegistration(result, domain, registration)
	}
	// Who announces the addresses, read from a public network record. The
	// addresses came out of DNS a moment ago and the network behind them is the
	// next question, not a separate tool the operator has to remember.
	asns := map[string]bool{}
	for _, address := range ips {
		origins, originErr := originASNs(ctx, routed, address)
		if originErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("BGP origin of %s: %s", address, originErr.Error()))
		}
		for _, asn := range origins {
			asns[asn] = true
		}
	}
	for asn := range asns {
		operator, asnErr := s.asnOperator(ctx, client, asn)
		if asnErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("network record for %s: %s", asn, asnErr.Error()))
			continue
		}
		result.Entities = append(result.Entities, entity("asn", asn, map[string]interface{}{
			"operator":      operator.Name,
			"website":       operator.Website,
			"prefixes_v4":   operator.Prefixes4,
			"prefixes_v6":   operator.Prefixes6,
			"ix_count":      operator.IXCount,
			"policy_url":    operator.PolicyURL,
			"traffic_ratio": operator.TrafficRatio,
			"country":       operator.Country,
			"source":        "peeringdb_network_record",
		}, map[string]interface{}{"source": "peeringdb_network_record"}))
		setTransformMetadata(result, "asn_operators", len(asns))
	}
	return nil
}

// markDomainRegistration attaches the registry's own record to the domain the
// run already holds, and adds the nameservers it publishes.
func markDomainRegistration(result *osintTransformResult, domain string, registration domainRegistration) {
	properties := map[string]interface{}{"source": "rdap_registry"}
	if registration.Registrar != "" {
		properties["registrar"] = registration.Registrar
	}
	if registration.Handle != "" {
		properties["registry_handle"] = registration.Handle
	}
	if len(registration.Statuses) > 0 {
		properties["registry_status"] = registration.Statuses
	}
	for action, date := range registration.Events {
		properties["registered_"+strings.ReplaceAll(action, " ", "_")] = date
	}
	for index := range result.Entities {
		if result.Entities[index].Type == "domain" && result.Entities[index].Identity == domain {
			if result.Entities[index].Properties == nil {
				result.Entities[index].Properties = map[string]interface{}{}
			}
			for key, value := range properties {
				result.Entities[index].Properties[key] = value
			}
			result.Entities[index].Provenance["rdap_registry"] = true
		}
	}
	for _, nameserver := range registration.Nameservers {
		result.Entities = append(result.Entities, entity("domain", nameserver, map[string]interface{}{"source": "rdap_nameserver"}, map[string]interface{}{"source": "rdap_registry"}))
		result.Relations = append(result.Relations, transformRelation{Type: "nameserver_of", SourceType: "domain", Source: nameserver, TargetType: "domain", Target: domain, Provenance: map[string]interface{}{"source": "rdap_registry"}})
	}
	setTransformMetadata(result, "rdap_registrar", registration.Registrar)
	setTransformMetadata(result, "rdap_nameservers", len(registration.Nameservers))
}

// archiveEndpoint is one public archive index that answers the same question
// for a host: which URLs were archived. The endpoints differ in availability
// only, because an index rate limits or goes offline independently of the
// others. Falling back changes which backend answered, never the meaning of the
// rows it returns.
//
// The chain deliberately spans **more than one host**. Two indexes behind one
// hostname share that host's rate limit, so a chain built from a single host has
// no fallback at all for the one failure that actually happens: the host
// answering 429 to every client from one egress address. A second, independently
// operated archive is what makes the chain a chain.
type archiveEndpoint struct {
	name  string
	query string
	// layout selects the row decoder: archiveLayoutRows for the Internet Archive
	// array-of-arrays layouts, archiveLayoutObjects for a JSON Lines index of
	// objects.
	layout string
	// field is the object member that holds the archived URL, for
	// archiveLayoutObjects.
	field string
	// continueOnEmpty marks an index whose empty answer is not an answer. A crawl
	// collection that never visited the host says nothing about that host, so the
	// chain keeps looking; an archive index that holds no captures has answered,
	// and the result is "no archived URLs" rather than "ask someone else".
	continueOnEmpty bool
}

// Archive index row layouts.
const (
	archiveLayoutRows    = "rows"
	archiveLayoutObjects = "objects"
)

// publicArchiveIndex is the public Internet Archive index host.
const publicArchiveIndex = "https://web.archive.org"

// publicCrawlIndex publishes the current crawl collections and the query endpoint
// of each. It is a different organisation on a different host with its own rate
// limit, which is the whole reason the chain reaches for it.
const publicCrawlIndex = "https://index.commoncrawl.org"

// archiveUserAgent returns a realistic browser user-agent drawn from UserAgent.txt pool.
func archiveUserAgent() string {
	return RandomUserAgent()
}

// requestHTTPClient is the client every OSINT adapter uses so the active route
// and TLS configuration are shared by all of them.
func (s *server) requestHTTPClient() *http.Client {
	return s.toolClient(context.Background())
}

// archiveEndpoints returns the Internet Archive part of the chain for one
// domain. The CDX index collapses the archive to one row per URL; the timemap
// index keeps one row per capture, so it is only used when the collapsed index
// cannot answer.
// setTransformMetadata records one fact about how a transform was run.
//
// Metadata is created on demand: a caller may hand in a result that has no map
// yet, and a fact that cannot be recorded is a fact the operator never sees.
func setTransformMetadata(result *osintTransformResult, key string, value interface{}) {
	if result.Metadata == nil {
		result.Metadata = map[string]interface{}{}
	}
	result.Metadata[key] = value
}

// archiveQueryTarget turns a transform input into the prefix the archive
// indexes are asked about, and the host the result belongs to.
//
// The archives are URL-keyed, so a bare domain is asked as `host/*` and a URL is
// asked as `host/path/*`. Narrowing to the path is the point: an analyst who
// holds `https://example.test/api/v1/` wants what was archived under that path,
// not every URL the host ever served. The domain-only form stays exactly as it
// was, so nothing that worked before changes.
//
// Both forms resolve to the same host, so the returned URLs still hang off a
// domain entity and the relation contract the gateway validates is untouched.
func archiveQueryTarget(value string) (host, prefix string, err error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", "", transformError("INVALID_ARCHIVE_TARGET", "archive target is empty")
	}
	// A bare host is the historical input and is used as-is, with a numeric port
	// stripped: the archives are indexed by host, so the port is not part of the
	// question being asked. Anything carrying a scheme, path, query or fragment
	// is a URL and is read as one.
	if !strings.ContainsAny(trimmed, "/?#") {
		hostOnly := trimmed
		if name, port, found := strings.Cut(trimmed, ":"); found {
			if _, portErr := strconv.Atoi(port); portErr == nil {
				hostOnly = name
			}
		}
		if !strings.Contains(hostOnly, ":") {
			host, err = normalizeDomainForTransform(hostOnly)
			if err != nil {
				return "", "", err
			}
			return host, host + "/*", nil
		}
	}
	parsed, parseErr := url.Parse(trimmed)
	if parseErr != nil || parsed.Hostname() == "" {
		return "", "", transformError("INVALID_ARCHIVE_TARGET", "archive target is neither a domain nor a URL")
	}
	// The archives hold HTTP(S) captures, so a URL under another scheme is not a
	// question they can answer. Refusing it here says so, instead of asking and
	// returning a confidently empty result.
	if scheme := strings.ToLower(parsed.Scheme); scheme != "" && scheme != "http" && scheme != "https" {
		return "", "", transformError("INVALID_ARCHIVE_TARGET", "archive lookup covers http and https URLs only")
	}
	host, err = normalizeDomainForTransform(parsed.Hostname())
	if err != nil {
		return "", "", err
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	prefix = host + path + "/*"
	return host, prefix, nil
}

// archiveEndpoints builds the Wayback queries for one prefix. The parameter is
// the prefix rather than a bare host because a URL input narrows the query, and
// every index in the chain has to be asked the same question.
func archiveEndpoints(base, prefix string) []archiveEndpoint {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		base = publicArchiveIndex
	}
	escaped := url.QueryEscape(prefix)
	return []archiveEndpoint{
		{name: "cdx", query: base + "/cdx/search/cdx?url=" + escaped + "&output=json&fl=timestamp,original,filename,offset,length&collapse=urlkey", layout: archiveLayoutRows},
		{name: "timemap", query: base + "/web/timemap/json?url=" + escaped, layout: archiveLayoutRows},
	}
}

// archiveCapture is one archived URL as one index recorded it.
//
// The coordinates are kept because they are what turns a list of URLs into
// evidence. A URL says what a crawler asked for; `filename`, `offset` and
// `length` address the exact record inside the WARC file, so the response the
// crawler actually received can be fetched back instead of being guessed at
// from a URL that has since changed. They are empty for an index that answers
// with a timestamp and a URL and nothing else, which is a real answer from a
// real index and not a failure to parse.
type archiveCapture struct {
	url       string
	timestamp string
	filename  string
	offset    string
	length    string
}

// hasCoords reports whether this capture can be fetched back from the archive.
func (c archiveCapture) hasCoords() bool {
	return c.filename != "" && c.offset != "" && c.length != ""
}

// crawlCollection is one published crawl of the Common Crawl index.
type crawlCollection struct {
	ID  string `json:"id"`
	API string `json:"cdx-api"`
}

// crawlIndexEndpoints asks the crawl index which collections exist and returns
// one endpoint per collection, newest first as published.
//
// The collection id is not guessed: the index publishes the current one, and a
// hard-coded id rots into a collection that no longer exists. The answer is
// read once per transform run rather than cached for the process, because a
// cached id keeps being used after the index has rolled over, and a stale id is
// a lookup that answers 404 forever.
func (s *server) crawlIndexEndpoints(ctx context.Context, client *http.Client, prefix string) ([]archiveEndpoint, error) {
	return s.crawlIndexEndpointsWithBudget(ctx, client, prefix, archiveDiscoveryAttempts)
}

// crawlIndexEndpointsWithBudget reads the collection list and retries it within
// the given attempt budget.
func (s *server) crawlIndexEndpointsWithBudget(ctx context.Context, client *http.Client, prefix string, attempts int) ([]archiveEndpoint, error) {
	list := strings.TrimSuffix(strings.TrimSpace(s.crawlIndexBase), "/")
	if list == "" {
		list = publicCrawlIndex
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, list+"/collinfo.json", nil)
	if err != nil {
		return nil, fmt.Errorf("collection list request could not be built: %w", err)
	}
	request.Header.Set("User-Agent", archiveUserAgent())
	request.Header.Set("Accept", "application/json")
	// Reading the list is subject to exactly the conditions the queries it
	// enables are subject to, so it is asked the same way: a dropped connection
	// or a rate limit is asked again after the wait, a refusal is not. Measured on
	// the public index, five of twelve identical list requests were dropped, so
	// asking once meant losing the whole second archive to one reset connection.
	attempt := 0
	for {
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			err = archiveTransportError{err: err}
		} else if response.StatusCode < 200 || response.StatusCode >= 300 {
			err = archiveStatusError(response)
			response.Body.Close()
		} else {
			defer response.Body.Close()
			var collections []crawlCollection
			if decodeErr := json.NewDecoder(response.Body).Decode(&collections); decodeErr != nil {
				return nil, fmt.Errorf("collection list could not be decoded: %w", decodeErr)
			}
			return crawlCollectionEndpoints(collections, prefix), nil
		}
		attempt++
		wait, again := archiveRetryWait(err)
		if !again || attempt >= attempts {
			return nil, err
		}
		if waitErr := archiveBackoff(ctx, nil, wait); waitErr != nil {
			return nil, waitErr
		}
	}
}

// crawlCollectionEndpoints turns the published collection list into one index
// endpoint per collection, newest first as published.
func crawlCollectionEndpoints(collections []crawlCollection, prefix string) []archiveEndpoint {
	endpoints := make([]archiveEndpoint, 0, len(collections))
	for _, collection := range collections {
		base := strings.TrimSpace(collection.API)
		if base == "" || strings.TrimSpace(collection.ID) == "" {
			continue
		}
		endpoints = append(endpoints, archiveEndpoint{
			name:  "crawl " + collection.ID,
			query: base + "?url=" + url.QueryEscape(prefix) + "&output=json",
			// The crawl index writes one JSON object per line, each carrying the
			// captured URL under "url".
			layout:          archiveLayoutObjects,
			field:           "url",
			continueOnEmpty: true,
		})
	}
	return endpoints
}

// archiveChain returns the full ordered chain for one host: the Internet
// Archive first, because that is the archive the transform is named after, and
// then the crawl index collections.
//
// A crawl index that cannot be reached shortens the chain instead of removing
// it, so every index that did answer is still used and the analyst is told which
// part of the chain was unavailable.
func (s *server) archiveChain(ctx context.Context, client *http.Client, prefix string) ([]archiveEndpoint, string) {
	if s.archiveIndexList != nil {
		list, err := s.archiveIndexList(ctx, prefix)
		if err != nil {
			return nil, err.Error()
		}
		return list, ""
	}
	chain := archiveEndpoints(s.archiveIndexBase, prefix)
	crawl, err := s.crawlIndexEndpoints(ctx, client, prefix)
	if err != nil {
		if ctx.Err() != nil {
			return chain, ""
		}
		return chain, err.Error()
	}
	return append(chain, crawl...), ""
}

// archiveIndex reports what one streamed archive index actually delivered.
type archiveIndex struct {
	endpoint string
	rows     int
	urls     int
	complete bool
}

// truncated reports that the archive ended the index stream before the last
// row, which is a normal occurrence for a large host prefix.
func (index archiveIndex) truncated() bool {
	return index.rows > 0 && !index.complete
}

func (s *server) runWaybackURLsWithCollector(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "archive lookup performs a network request")
	}
	host, prefix, err := archiveQueryTarget(input.Value)
	if err != nil {
		return err
	}
	domain := host
	result.LocalOnly, result.NetworkUsed = false, true
	// The archived URLs are observed at this host, so the host is part of the
	// result: the gateway rejects a relation whose endpoint is not in the graph.
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "transform_input"}))
	// The query that was actually asked is stated, because a URL input narrows
	// the archive to a path prefix and a result read without that would claim
	// host-wide coverage it does not have.
	setTransformMetadata(result, "wayback_input", input.Value)
	setTransformMetadata(result, "wayback_host", domain)
	setTransformMetadata(result, "wayback_prefix", prefix)
	if prefix != domain+"/*" {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"the archive indexes are queried by URL, so %s was narrowed to the path prefix %s; the result covers that prefix and not the whole host",
			input.Value, prefix,
		))
	}
	client := s.toolClient(ctx)
	endpoints, chainNote := s.archiveChain(ctx, client, prefix)
	if chainNote != "" {
		// The chain is reported as it is built, because "the archive that usually
		// answers was not consulted" changes what a result is worth.
		result.Warnings = append(result.Warnings, "archive index chain: "+chainNote)
	}
	chainNotePrefix := ""
	if chainNote != "" {
		chainNotePrefix = "archive index chain: " + chainNote + "; "
	}
	// One identity per archived URL across the whole chain: the timemap index
	// repeats the same URL for every capture, so duplicates are dropped by
	// identity rather than by discarding part of the archive.
	seen := map[string]bool{}
	failures := make([]string, 0, len(endpoints))
	// skipped records the indexes the chain walked past, reported once the
	// answering index is known, so the coverage claim stays honest.
	skipped := make([]string, 0, len(endpoints))
	// The chain length is only known once the index has published its list, so
	// the total is published here rather than at job start. Until this line the
	// panel has no total, and it says so by showing none rather than a zero.
	collector.setIndexTotal(ctx, len(endpoints))
	for position, endpoint := range endpoints {
		collector.indexPosition(ctx, endpoint.name, position, len(endpoints))
		added := 0
		// collect turns one index response into graph rows. It is a function so
		// that a rate-limited index is asked again through exactly the same path
		// as the first attempt, and a retry cannot drift from it.
		collect := func(capture archiveCapture) {
			// The archive index is the longest part of a wayback transform and
			// regularly returns a partial view, so every row is both a pause
			// point and a progress tick.
			if collector != nil {
				if err := collector.checkpoint(ctx); err != nil {
					return
				}
			}
			target, ok := archiveURLTarget(capture.url)
			if !ok || seen[target] {
				return
			}
			seen[target] = true
			added++
			provenance := map[string]interface{}{"source": "wayback", "archive_index": endpoint.name}
			// The URL is linked to the host that actually served it, not to the
			// apex it was looked up under. `https://api.example.com/login` is an
			// observation about api.example.com, and attaching it to the apex
			// throws away the only host the record names — the same loss
			// AGENTS.md records for a substituted certificate zone, where the name
			// has to become a subdomain of the zone it really belongs to.
			observedHost, hostErr := archiveURLHost(target)
			if hostErr != nil {
				result.Warnings = append(result.Warnings, hostErr.Error())
				return
			}
			// The host is stored as the domain the transform already created when
			// it is that domain, and as a subdomain of it otherwise. Choosing this
			// here rather than in the reader is what stops the apex being linked to
			// itself through its own `subdomain_of`.
			hostType := "subdomain"
			if observedHost == domain {
				hostType = "domain"
			}
			properties := map[string]interface{}{}
			if capture.timestamp != "" {
				properties["captured_at"] = capture.timestamp
			}
			// The archive coordinates are written only when all three are
			// present, because a partial set is not a fetchable address: it
			// would read as an archive record and fail to resolve.
			if capture.hasCoords() {
				properties["archive_file"] = capture.filename
				properties["archive_offset"] = capture.offset
				properties["archive_length"] = capture.length
			}
			if hostType != "domain" {
				result.Entities = append(result.Entities, entity(hostType, observedHost, nil, provenance))
				result.Relations = append(result.Relations, transformRelation{
					Type: "subdomain_of", SourceType: "subdomain", Source: observedHost, TargetType: "domain", Target: domain, Provenance: provenance,
				})
			}
			result.Entities = append(result.Entities, entity("url", target, properties, provenance))
			result.Relations = append(result.Relations, transformRelation{
				Type: "observed_at", SourceType: "url", Source: target, TargetType: hostType, Target: observedHost, Provenance: provenance,
			})
		}
		index, streamErr := streamArchiveIndex(ctx, client, endpoint, collect)
		index.urls = added
		attempt := 1
		// Two failures are worth asking the same index about once more, because
		// neither of them is a refusal and both of them happen in normal
		// operation: a rate limit says "come back" and names when, and a broken
		// connection or a timed-out handshake is the state of a network rather
		// than an answer from the index. A refusal — 403, 404, an index that does
		// not exist — is the index's deliberate answer and is not retried. An index
		// that stays unusable is still reported afterwards, so a retry never hides
		// a failure.
		if wait, again := archiveRetryWait(streamErr); again && attempt < archiveQueryAttempts {
			collector.label(ctx, endpoint.name+" "+archiveRetryReason(streamErr)+", retrying in "+wait.String())
			if err := archiveBackoff(ctx, collector, wait); err != nil {
				failures = append(failures, fmt.Sprintf("%s index: %v", endpoint.name, streamErr))
				break
			}
			added = 0
			index, streamErr = streamArchiveIndex(ctx, client, endpoint, collect)
			index.urls = added
		}
		if streamErr != nil {
			refused := fmt.Sprintf("%s index: %v", endpoint.name, streamErr)
			if archiveIndexUnavailable(streamErr) {
				// A collection that cannot be served right now is a gap in the
				// coverage and is named as one. It is deliberately not a failure:
				// the coverage is still reported, and inflating the failure count
				// with a collection that is still being published would make a
				// healthy run look broken.
				unavailable := fmt.Sprintf("%s index: %v (this crawl is not being served yet)", endpoint.name, streamErr)
				result.Warnings = append(result.Warnings, unavailable)
				skipped = append(skipped, unavailable)
				if ctx.Err() != nil {
					break
				}
				continue
			}
			failures = append(failures, refused)
			skipped = append(skipped, refused)
			// A cancelled or replaced route must not walk the remaining chain.
			if ctx.Err() != nil {
				break
			}
			continue
		}
		result.Metadata = archiveIndexMetadata(result.Metadata, index)
		collector.indexDone(ctx, endpoint.name, position+1, added)
		if index.rows == 0 {
			empty := fmt.Sprintf("the %s archive index holds no captures for %s", endpoint.name, domain)
			result.Warnings = append(result.Warnings, empty)
			// A collection that never crawled this host is not an answer, so the
			// next collection is asked. An archive that genuinely holds no captures
			// has answered, and the result is "no archived URLs".
			if endpoint.continueOnEmpty {
				skipped = append(skipped, empty)
				continue
			}
		}
		if index.truncated() {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"the %s archive index stream ended early after %d rows; the collected URLs are a partial view",
				endpoint.name, index.rows,
			))
		}
		// A truncated index still carries real coverage, so the next endpoint is
		// only used when this one could not answer at all.
		if len(skipped) > 0 {
			// An index the chain walked past is part of what the result is worth. A
			// single crawl is a snapshot where the archive is a history, so a result
			// that quietly dropped the archive would overstate itself.
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%d archive index(es) answered nothing and the result comes from the %s index: %s",
					len(skipped), endpoint.name, strings.Join(skipped, "; ")))
		}
		return nil
	}
	// No index answered: report every attempt instead of a single opaque code.
	detail := chainNotePrefix + "no public archive index answered for " + domain
	if len(failures) > 0 {
		detail += ": " + strings.Join(failures, "; ")
	}
	return transformError("WAYBACK_LOOKUP_FAILED", detail)
}

// streamArchiveIndex decodes one archive index response row by row.
//
// The index for a large host is a very long stream that the archive regularly
// ends mid-array, and buffering it whole is neither useful nor safe, so rows
// are consumed as they arrive. A truncated tail is reported through the result
// instead of discarding every row that was already read, while a stream that
// never produced a usable row stays an error for the caller.
func streamArchiveIndex(ctx context.Context, client *http.Client, endpoint archiveEndpoint, sink func(archiveCapture)) (archiveIndex, error) {
	index := archiveIndex{endpoint: endpoint.name}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.query, nil)
	if err != nil {
		return index, fmt.Errorf("request could not be built: %w", err)
	}
	request.Header.Set("User-Agent", archiveUserAgent())
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		// The request never became an answer, so the index is not the one that
		// refused; the caller may ask it again.
		if ctx.Err() == nil {
			return index, archiveTransportError{err: err}
		}
		return index, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return index, archiveStatusError(response)
	}
	column := -1
	var indexes map[string]int
	var delivered int
	var streamErr error
	if endpoint.layout == archiveLayoutObjects {
		delivered, streamErr = streamJSONObjects(response.Body, endpoint.field, func(capture archiveCapture) {
			index.rows++
			sink(capture)
		})
	} else {
		streamErr = streamJSONArray(response.Body, func(element json.RawMessage) error {
			var row []string
			if err := json.Unmarshal(element, &row); err != nil {
				return err
			}
			if column < 0 {
				// Both array layouts start with a header row and name the archived
				// URL column "original", which the timemap layout places third.
				column = archiveURLColumn(row)
				if column < 0 {
					return errors.New("archive index header has no original URL column")
				}
				indexes = archiveColumnIndexes(row)
				return nil
			}
			index.rows++
			if column < len(row) {
				// The coordinate columns are read by name, and only when all three
				// are present: a partial address is not fetchable, and a capture
				// that cannot be fetched back is a list, not evidence. The timemap
				// layout publishes no such columns, so a capture from it simply
				// carries none rather than being filled with a guess.
				capture := archiveCapture{url: strings.TrimSpace(row[column])}
				if at, ok := indexes["timestamp"]; ok && at < len(row) {
					capture.timestamp = strings.TrimSpace(row[at])
				}
				if at, ok := indexes["filename"]; ok && at < len(row) {
					capture.filename = strings.TrimSpace(row[at])
				}
				if at, ok := indexes["offset"]; ok && at < len(row) {
					capture.offset = strings.TrimSpace(row[at])
				}
				if at, ok := indexes["length"]; ok && at < len(row) {
					capture.length = strings.TrimSpace(row[at])
				}
				sink(capture)
			}
			return nil
		})
	}
	if streamErr != nil && index.rows == 0 {
		return index, fmt.Errorf("archive index could not be decoded: %w", streamErr)
	}
	if index.rows == 0 && delivered > 0 {
		// Rows were delivered and none of them carried the archived URL. That is
		// an unusable answer rather than an empty one, and reporting it as "no
		// captures" would turn a changed index format into a silent empty result.
		return index, fmt.Errorf("%d archive index rows carry no %q field", delivered, endpoint.field)
	}
	index.complete = streamErr == nil
	return index, nil
}

// archiveStatusError turns a non-2xx index answer into an error that says which
// status came back, and marks a rate limit as retryable rather than as a
// refusal. A 429 is the index asking for a pause; reading it as a hard failure
// is what makes a transform that works fail on a busy host.
func archiveStatusError(response *http.Response) error {
	failure := fmt.Errorf("archive returned HTTP %d%s", response.StatusCode, retryAfterNote(response.Header))
	if response.StatusCode == http.StatusTooManyRequests {
		return archiveRateLimitError{
			failure:    archiveRefusal{status: response.StatusCode, err: failure},
			retryAfter: retryAfterSeconds(response.Header),
		}
	}
	return archiveRefusal{status: response.StatusCode, err: failure}
}

// archiveRateLimitError marks a rate-limited index answer as worth waiting out,
// and keeps the wait the index asked for so the retry honours it.
type archiveRateLimitError struct {
	failure    error
	retryAfter time.Duration
}

func (limited archiveRateLimitError) Error() string { return limited.failure.Error() }

func (limited archiveRateLimitError) Unwrap() error { return limited.failure }

// Attempt budgets for a retryable archive request.
//
// The two requests are not the same kind of thing. Reading the collection list is
// a single request whose loss removes the entire second archive, and it is cheap,
// so it is asked a few times. A query is one of many against a host that may
// simply be busy, so one repeat is enough and more would only make a run slow
// without making it more likely to succeed.
const (
	archiveDiscoveryAttempts = 3
	archiveQueryAttempts     = 2
)

// archiveRetryWait reports how long to wait before asking an index again, and
// whether asking again is worth it.
//
// A rate limit waits as long as the index asked. A transport failure waits the
// short default: nothing named a duration, and the point is to ride out a
// connection that was closed rather than to honour a schedule.
func archiveRetryWait(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	if wait, limited := archiveRateLimitWait(err); limited {
		return wait, true
	}
	if archiveStatusOf(err) != 0 {
		// A status is the index's own answer. Retrying it would ask a question
		// that has already been answered.
		return 0, false
	}
	if !archiveTransportFailure(err) {
		return 0, false
	}
	return archiveRateLimitPause, true
}

// archiveIndexUnavailable reports whether a status means the index cannot serve
// this crawl at the moment, rather than that the crawl has nothing.
//
// Measured on the public crawl index: the newest published collection answers
// HTTP 504 until its query path is serving, while older ones answer normally.
// That is a statement about the collection, in the same family as a collection
// that holds no captures, and it is counted as a skipped index with a reason —
// not as a failure, because a chain of 128 collections where the first one is
// still being built is a normal chain, and reporting it as a failure tells the
// operator their run is broken when it is not.
//
// Only 504 is here. 502 was not measured, and 503 deliberately stays a reported
// failure: an existing regression test holds that a 503 is an answer the
// operator must see. Widening this without measuring it would change a
// deliberate contract on a guess.
func archiveIndexUnavailable(err error) bool {
	return archiveStatusOf(err) == http.StatusGatewayTimeout
}

// archiveRetryReason names the cause in the progress line, so a paused or slow
// run says why it is waiting instead of only that it is.
func archiveRetryReason(err error) string {
	if _, limited := archiveRateLimitWait(err); limited {
		return "rate limited"
	}
	return "unreachable"
}

// archiveRefusal keeps the status an index answered with, so a deliberate answer
// can be told apart from a connection that never happened.
type archiveRefusal struct {
	status int
	err    error
}

func (refused archiveRefusal) Error() string { return refused.err.Error() }

func (refused archiveRefusal) Unwrap() error { return refused.err }

// archiveStatusOf returns the HTTP status an index answered with, or zero when
// the index never answered at all.
func archiveStatusOf(err error) int {
	var refused archiveRefusal
	if !errors.As(err, &refused) {
		return 0
	}
	return refused.status
}

// archiveTransportError is a request that never produced an answer: a refused
// connection, a closed connection, a handshake that timed out.
//
// It is tagged where it happens rather than guessed from the absence of a status,
// because "no status" also covers a body that decoded into nothing usable, and
// repeating that request cannot change what the index chose to send.
type archiveTransportError struct {
	err error
}

func (broken archiveTransportError) Error() string { return broken.err.Error() }

func (broken archiveTransportError) Unwrap() error { return broken.err }

// archiveTransportFailure reports whether an error is the network refusing to
// carry the request rather than an answer arriving.
func archiveTransportFailure(err error) bool {
	var broken archiveTransportError
	return errors.As(err, &broken)
}

// archiveRateLimitWait reports how long to wait before asking a rate-limited
// index again, and whether the failure was a rate limit at all.
//
// The archive's own `Retry-After` wins. A host that refuses without naming a
// wait is given a short fixed pause, because the alternative is to abandon a
// host that may simply be busy, and the pause is bounded so one busy index
// cannot hold a running transform longer than the rest of its work.
func archiveRateLimitWait(err error) (time.Duration, bool) {
	var limited archiveRateLimitError
	if !errors.As(err, &limited) {
		return 0, false
	}
	wait := limited.retryAfter
	if wait <= 0 {
		wait = archiveRateLimitPause
	}
	if wait > archiveRateLimitWaitCap {
		wait = archiveRateLimitWaitCap
	}
	return wait, true
}

// retryAfterSeconds reads the numeric `Retry-After` an index sent. A date, an
// empty value or a malformed one yields zero, which makes the caller fall back
// to its own short pause rather than waiting for a time it could not read.
func retryAfterSeconds(header http.Header) time.Duration {
	values := header.Values("Retry-After")
	if len(values) == 0 {
		return 0
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(values[0]))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// The bounds of an index rate-limit pause.
const (
	// archiveRateLimitPause is the wait for an index that refused without naming
	// one.
	archiveRateLimitPause = 2 * time.Second
	// archiveRateLimitWaitCap keeps a long `Retry-After` from turning into a
	// transform that appears hung. A host that asks for longer than this is
	// treated as unavailable, and the chain moves on instead of waiting.
	archiveRateLimitWaitCap = 20 * time.Second
)

// archiveBackoff waits out a rate limit without becoming uncancellable.
//
// The wait is a pause point like every other step of a transform, so pausing the
// job suspends here instead of sitting out the delay, and cancelling or
// replacing the route returns immediately rather than after the full pause.
func archiveBackoff(ctx context.Context, collector *transformCollector, wait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		// A pause suspends the wait rather than being spent inside a timer the
		// job cannot interrupt, so pausing here holds the transform at the same
		// place as every other checkpoint.
		if collector != nil && collector.job.gate.isPaused() {
			if err := collector.checkpoint(ctx); err != nil {
				return err
			}
			continue
		}
		slice := remaining
		if slice > archiveBackoffSlice {
			slice = archiveBackoffSlice
		}
		timer := time.NewTimer(slice)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-collectorStop(collector):
			timer.Stop()
			return context.Canceled
		case <-timer.C:
		}
	}
}

// archiveBackoffSlice is how finely a rate-limit wait is sliced so cancellation
// is noticed promptly instead of after the whole pause.
const archiveBackoffSlice = 250 * time.Millisecond

// collectorStop returns the channel that closes when a job is asked to stop.
// A synchronous run has no job and therefore nothing to interrupt it.
func collectorStop(collector *transformCollector) <-chan struct{} {
	if collector == nil {
		return nil
	}
	return collector.stop
}

// retryAfterNote reports how long the archive asked a client to wait, so a
// rate-limited answer explains itself instead of looking like a hard failure.
// The archive documents `Retry-After` on 429 as the client's cue to back off.
func retryAfterNote(header http.Header) string {
	values := header.Values("Retry-After")
	if len(values) == 0 {
		return ""
	}
	wait := strings.TrimSpace(values[0])
	if wait == "" {
		return ""
	}
	if seconds, err := strconv.Atoi(wait); err == nil {
		if seconds < 0 {
			return ""
		}
		return fmt.Sprintf(" (retry after %ds)", seconds)
	}
	// A date is passed through as written rather than reinterpreted here.
	return " (retry after " + wait + ")"
}

// archiveURLColumn returns the position of the archived URL inside an index
// header row, or -1 when the row does not describe one.
// archiveEndpointFields returns which fields a query asks the index for.
//
// It exists so that a test can assert on the fields rather than on the exact
// query text: widening the field list is a normal change, and a test pinned to
// the literal string would then fail on a query that is still correct.
func archiveEndpointFields(query string) map[string]bool {
	fields := map[string]bool{}
	for _, part := range strings.Split(query, "&") {
		if !strings.HasPrefix(part, "fl=") {
			continue
		}
		for _, name := range strings.Split(strings.TrimPrefix(part, "fl="), ",") {
			fields[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	return fields
}

// archiveColumnIndexes maps the published header names to their positions, so
// the coordinate columns are read by name rather than by position. An index that
// reorders or extends its row keeps its URL, which a positional read would lose.
func archiveColumnIndexes(header []string) map[string]int {
	indexes := make(map[string]int, len(header))
	for position, name := range header {
		indexes[strings.ToLower(strings.TrimSpace(name))] = position
	}
	return indexes
}

func archiveURLColumn(header []string) int {
	for position, name := range header {
		if strings.EqualFold(strings.TrimSpace(name), "original") {
			return position
		}
	}
	return -1
}

// archiveURLTarget canonicalizes one archived URL and reports whether it is a
// usable absolute HTTP(S) identity.
//
// The public archive is attacker-controllable input: it stores captured
// credential URLs such as https://user@yandex.ru/ and fragment-only variants.
// The canonical form therefore drops userinfo, query and fragment, and rejects
// hosts the graph identity rules cannot store, so one poisoned archive row
// cannot fail the whole transform and no captured credential becomes an
// identity.
func archiveURLTarget(candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host, ok := canonicalURLHost(parsed.Hostname())
	if !ok {
		return "", false
	}
	port := parsed.Port()
	if !validURLPort(port) {
		return "", false
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	netloc := host
	if strings.Contains(host, ":") {
		netloc = "[" + host + "]"
	}
	if port != "" {
		netloc += ":" + port
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if hasDotSegment(path) {
		return "", false
	}
	return scheme + "://" + netloc + path, true
}

// hasDotSegment reports whether a path still carries a "." or ".." segment.
// Such a row is a traversal attempt in attacker-controllable archive data
// rather than a captured resource, so it is dropped instead of stored.
func hasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// canonicalURLHost normalizes one URL host to the ASCII form the graph stores
// and reports whether the host is storable. The rules match the graph identity
// validation so a URL the engine accepts is always a URL the gateway keeps.
func canonicalURLHost(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, " \\/?#@") {
		return "", false
	}
	if address := net.ParseIP(host); address != nil {
		return address.String(), true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", false
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || !isASCIIAlnum(label[0]) || !isASCIIAlnum(label[len(label)-1]) {
			return "", false
		}
		for index := 0; index < len(label); index++ {
			if character := label[index]; !isASCIIAlnum(character) && character != '-' {
				return "", false
			}
		}
	}
	return ascii, true
}

func isASCIIAlnum(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
}

// validURLPort reports whether a port is absent or a real TCP port. The graph
// identity rules reject anything else, so such a row is dropped here.
func validURLPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 {
		return false
	}
	number := 0
	for index := 0; index < len(port); index++ {
		character := port[index]
		if character < '0' || character > '9' {
			return false
		}
		number = number*10 + int(character-'0')
	}
	return number > 0 && number <= 65535
}

// archiveIndexMetadata records which index answered and how much it delivered,
// so a partial archive view stays visible in the graph metadata.
func archiveIndexMetadata(metadata map[string]interface{}, index archiveIndex) map[string]interface{} {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["archive_index"] = index.endpoint
	metadata["archive_rows"] = index.rows
	metadata["archive_urls"] = index.urls
	metadata["archive_stream_complete"] = index.complete
	return metadata
}

// validateUsernameValue refuses a value that is not a username.
//
// The character pattern alone let a domain through: `pravda.ru` matches
// `^[A-Za-z0-9][A-Za-z0-9._-]*$`, so the transform answered "completed" and wrote a
// `username` entity whose identity was the domain the graph already held — a second
// copy of the same thing under the wrong type, with a relation to nothing. A dotted
// username is real (`john.doe` on several platforms), so the dot is not the test;
// being a well-formed domain name is, and a name without a zone in it is not one. The check reuses the domain normalizer rather
// than carrying its own top-level-domain list, so the two can never disagree about
// what a name is.
// looksLikePublicDomainName reports whether a value is a name under a zone the DNS
// root actually delegates.
//
// It exists for one caller — deciding whether a value offered as a username is a
// domain — and the scope is deliberate. "Is this a domain, or a username with a dot
// in it?" cannot be answered by shape: `john.doe` and `example.com` are the same
// shape, and a rule that refuses both takes away a real username (`john.doe` and
// `ivan.petrov` exist on several platforms) to fix a mistake an operator makes by
// pasting a domain into the wrong field. The Public Suffix List answers it instead of
// guessing: `pravda.ru` sits under `ru`, which ICANN delegates, while `john.doe` sits
// under `doe`, which nobody delegated. That is a published technical standard read
// from the module cache, not a list of allowed or denied targets, and it is not used
// to decide whether a target may be touched — only whether a string is a name.
//
// The delegated-zone requirement is why this is not used by the value classifier:
// reserved zones such as `.test`, `.local` and `.example` are real names for a lab
// and must keep classifying as domains, and a classifier that refused them would be
// the zone-based blocking this project does not do. The cost of that choice is
// stated where it is paid: a value like `example.test` offered as a username is
// accepted as one, and the exact answer for that case is the declared entity type.
func looksLikePublicDomainName(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if !strings.Contains(value, ".") {
		return false
	}
	if _, err := normalizeDomainForTransform(value); err != nil {
		return false
	}
	// The list is keyed in lower case, so `Yandex.RU` has to be folded before it is
	// asked; the archive tests use that exact casing and it answered "not a name".
	_, icann := publicsuffix.PublicSuffix(value)
	return icann
}

func validateUsernameValue(value string) (string, error) {
	username := strings.TrimSpace(value)
	if !usernamePattern.MatchString(username) {
		return "", transformError("INVALID_USERNAME", "username contains unsupported characters")
	}
	// An address and a range are shapes a username can never be, and unlike a dotted
	// label they need no zone list to say so. `94.137.92.20` matches the character
	// pattern, and the domain normalizer refuses it for being an address, so without
	// this the value would have fallen through every check and become a username.
	if net.ParseIP(username) != nil {
		return "", transformError("INVALID_USERNAME", "value is an IP address, not a username")
	}
	if _, _, err := net.ParseCIDR(username); err == nil {
		return "", transformError("INVALID_USERNAME", "value is a CIDR range, not a username")
	}
	if looksLikePublicDomainName(username) {
		return "", transformError("INVALID_USERNAME", "value is a domain name, not a username")
	}
	return username, nil
}

func runUsernameEnum(result *osintTransformResult, value string) error {
	username, err := validateUsernameValue(value)
	if err != nil {
		return err
	}
	result.Entities = append(result.Entities, entity("username", username, map[string]interface{}{"canonical": strings.ToLower(username)}, map[string]interface{}{"source": "local_transform"}))
	// This used to append the warning "External platform enumeration is
	// intentionally disabled; use a separately reviewed provider adapter." The
	// statement was false by the time it was read, and it was false twice over:
	// it named a capability this project does have, and it reported a *missing
	// feature* as the outcome of a run that had done everything it was asked to.
	//
	// `username_search` has answered that question since 2026-09-30: it is the
	// network counterpart of this transform, it queries the merged Sherlock and
	// Maigret catalogue through the same route generation and provenance as every
	// other network transform, and it requires the explicit confirmation the
	// registry's `network: true` already gates. There is no provider adapter left
	// to write, and nothing to be separately reviewed.
	//
	// A warning is this project's word for "this run could not answer part of the
	// question" — the GeoIP database that is not configured, the platform behind a
	// bot wall that gave no usable answer. A local normalizer that produced its
	// canonical entity has no such gap, so it warns about nothing. Where the
	// pointer to `username_search` belongs is the registry description the
	// operator reads *before* choosing a transform, not a warning printed after a
	// successful run.
	return nil
}

func runIPGeo(result *osintTransformResult, value string) error {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return transformError("INVALID_IP", "IP address is invalid")
	}
	properties := map[string]interface{}{"geo_source": "unavailable"}
	warnings := []string{"GeoIP database is not configured; no database download or network lookup was performed."}
	if geo, ok := lookupLocalGeoIP(ip.String()); ok {
		properties = geo
		properties["geo_source"] = "local_json"
		warnings = []string{}
	}
	result.Entities = append(result.Entities, entity("ip", ip.String(), properties, map[string]interface{}{"source": "local_transform"}))
	result.Warnings = append(result.Warnings, warnings...)
	return nil
}

func lookupLocalGeoIP(ip string) (map[string]interface{}, bool) {
	path := strings.TrimSpace(os.Getenv("OSINT_GEOIP_JSON"))
	if path == "" {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var entries map[string]map[string]interface{}
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, false
	}
	bestBits := -1
	var best map[string]interface{}
	for prefix, value := range entries {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil || !network.Contains(parsedIP) {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones > bestBits {
			bestBits = ones
			best = value
		}
	}
	return best, best != nil
}

func normalizeDomainForTransform(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(value))
	if domain == "" || net.ParseIP(domain) != nil {
		return "", transformError("INVALID_DOMAIN", "domain is invalid")
	}
	parsed, err := url.Parse("https://" + domain)
	if err != nil || parsed.Hostname() == "" || strings.ContainsAny(domain, "/?#@\\") {
		return "", transformError("INVALID_DOMAIN", "domain is invalid")
	}
	return strings.TrimSuffix(parsed.Hostname(), "."), nil
}

// runSubdomainTransformWithCollector discovers subdomains and reports what the
// certificate indexes have collected so far. The collector is the pause and
// progress point; a nil collector runs the phase without one.
//
// certificateIndexChain returns the certificate transparency indexes to query.
// Production uses the public chain; a test points it at a local fixture.
func (s *server) certificateIndexChain(domain string) []certificateSource {
	if s.certificateIndexList != nil {
		return s.certificateIndexList(domain)
	}
	return certificateSources(domain)
}

func (s *server) runSubdomainTransformWithCollector(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "subdomain discovery performs DNS and certificate transparency requests")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "transform_input"}))
	found := map[string]bool{}
	client := s.toolClient(ctx)
	evidence := certificateTransparencyNames(ctx, client, domain, collector, s.certificateIndexChain)
	result.Warnings = append(result.Warnings, evidence.warnings...)
	for name := range evidence.names {
		found[name] = true
	}
	// The indexes are keyed by zone, so a host input is answered by the zone the
	// host belongs to. The names are certified under that zone, so the zone is
	// what the relations and the DNS candidates are resolved against, and the
	// substitution is stated instead of being applied silently.
	zone := evidence.zone
	if zone == "" {
		zone = domain
	}
	if zone != domain {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"the certificate indexes are keyed by zone, and %s produced no names of its own, so the indexes and the DNS candidates were resolved against the zone %s that it belongs to; %s stays in the graph as its own domain entity",
			domain, zone, domain,
		))
		result.Entities = append(result.Entities, entity("domain", zone,
			map[string]interface{}{"role": "certificate_zone"},
			map[string]interface{}{"source": "certificate_transparency"}))
	}
	result.Metadata = certificateIndexMetadata(result.Metadata, evidence.counts, len(evidence.names))
	result.Metadata["cert_input"] = domain
	result.Metadata["cert_zone"] = zone
	result.Metadata["cert_zones_queried"] = evidence.queried
	// The public page-scan index is a third source of names for the same zone,
	// and it is asked after the certificate chain rather than inside it: the
	// chain walks zones and retries indexes, while this index is keyed by the
	// zone that was actually resolved. A source that fails is a warning and the
	// discovery continues, exactly as one dead certificate index does.
	scanSize, sizeErr := urlscanOptionSize(input.Options)
	if sizeErr != nil {
		return sizeErr
	}
	scans, scanErr := s.urlscanNames(ctx, client, zone, scanSize)
	if scanErr != nil {
		// A source that did not answer is named, not swallowed: a subdomain
		// discovery that silently lost one of its sources reads as a complete
		// answer for a zone it is not.
		result.Warnings = append(result.Warnings, "public page scans: "+scanErr.Error())
	} else {
		for name := range scans.names {
			found[name] = true
		}
		result.Metadata = urlscanEvidenceMetadata(result.Metadata, scans)
		if scans.foreign > 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"the public page-scan index answered %d hits outside %s, and they are not in the graph: its domain field is a substring match, so a name is only taken when the index published an apex it really sits under",
				scans.foreign, zone,
			))
		}
	}
	// The passive-DNS index is asked here, after the certificate chain and the
	// page scans, for the same reason urlscan is: it is a fourth source about the
	// same zone, it fails independently, and a source that did not answer is
	// named rather than folded into a complete-looking result.
	//
	// It is what closed the measured gap against subfinder on `pravda.ru`:
	// certificate indexes, page scans and DNS guessing between them produced 148
	// names and missed `ns1`/`ns2`/`mx`, while this index returned all three —
	// they are historical MX and NS records, the kind no live index publishes.
	pdns, pdnsErr := s.robtexForwardNames(ctx, client, zone)
	if pdnsErr != nil {
		result.Warnings = append(result.Warnings, "passive DNS: "+pdnsErr.Error())
	} else {
		for name := range pdns.names {
			found[name] = true
		}
		result.Metadata = robtexEvidenceMetadata(result.Metadata, pdns)
		if pdns.foreign > 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"the passive-DNS index answered %d names outside %s, and they are not in the graph: an index keyed by an exact name must not add another zone's hosts",
				pdns.foreign, zone,
			))
		}
	}
	// The threat-intelligence indexes are asked next, and they are the reason the
	// comparison with subfinder is now closed rather than merely measured.
	//
	// Its JSON output names the source of every finding, and the ten names it
	// found that nothing here found came from three indexes, not from a
	// certificate: `thc` (a threat feed's own DNS sightings), (sitedossier was here
	// until 2026-10-03, when it stopped answering)
	// crawl of the parent domain) and `hudsonrock` (hostnames of machines caught
	// by infostealers). Measured on `pravda.ru`: `thc` 60 names, 3 new to us;
	// `hudsonrock` 17 URLs, 5 names, 1 new.
	//
	// They answer for a class nothing else can: a host that only ever appeared in
	// an infostealer log has no certificate, no page scan and no live DNS record.
	intel, intelCounts, intelNotes := s.passiveIntelNames(ctx, client, zone)
	for name := range intel {
		found[name] = true
	}
	if len(intel) > 0 {
		result.Metadata["intel_names"] = len(intel)
		for source, count := range intelCounts {
			result.Metadata["intel_"+source+"_names"] = count
		}
	}
	for _, note := range intelNotes {
		result.Warnings = append(result.Warnings, "threat intelligence index: "+note)
	}
	words := stringSliceOption(input.Options, "words")
	if len(words) == 0 {
		words = defaultSubdomainWords()
	}
	// resolved holds the names the DNS phase already answered for, so the
	// pointer phase below asks only about the ones nothing else knows.
	resolved := map[string]bool{}
	routed := resolverForContext(ctx, client, s)
	lookup := func(lookupCtx context.Context, candidate string) ([]string, error) {
		return routed.lookupHost(lookupCtx, candidate)
	}
	if sample, wildcard := detectWildcardDNS(ctx, collector, lookup, zone); wildcard {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"wildcard DNS detected: %s resolves, so DNS brute-force names were skipped as unreliable; certificate transparency results are kept",
			sample,
		))
	} else {
		// Concurrency is an explicit option with a documented default, so the
		// operator can widen or narrow the phase instead of guessing. It bounds
		// how many names resolve at once, never how many are tried.
		dnsConcurrency := concurrencyOption(input.Options, bruteForceDefaultWorkers)
		guesses, appliedWorkers := bruteForceSubdomains(ctx, collector, lookup, zone, words, found, dnsConcurrency)
		// Reported so the applied bound is visible in the result, next to the
		// certificate zone and the indexes that were queried, instead of being
		// an internal detail the operator has to guess.
		setTransformMetadata(result, "dns_concurrency", appliedWorkers)
		for _, foundName := range guesses {
			found[foundName.name] = true
			// A name the brute-force phase already resolved is not asked about
			// again by the pointer phase: its address and its PTR are both known.
			resolved[foundName.name] = true
			for _, address := range foundName.ips {
				result.Entities = append(result.Entities, entity("ip", address, nil, map[string]interface{}{"source": "dns_guess"}))
				result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "subdomain", Source: foundName.name, TargetType: "ip", Target: address, Provenance: map[string]interface{}{"source": "dns_guess"}})
			}
		}
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// A name that resolved through DNS guessing is weaker evidence than
		// one an index actually holds, so the origin stays distinguishable. The
		// page-scan index is a real index too, so its names are marked as its
		// own rather than folded into the certificate provenance: an analyst
		// reading the graph has to be able to tell which source saw what.
		origin := map[string]interface{}{"source": "certificate_transparency"}
		switch {
		case !evidence.names[name] && scans.names[name]:
			origin = map[string]interface{}{"source": "urlscan_public_search"}
		case !evidence.names[name]:
			origin = map[string]interface{}{"source": "dns_guess"}
		}
		result.Entities = append(result.Entities, entity("subdomain", name, nil, origin))
		result.Relations = append(result.Relations, transformRelation{Type: "subdomain_of", SourceType: "subdomain", Source: name, TargetType: "domain", Target: zone, Provenance: origin})
	}
	// The pointer each certified name answers with. A certificate says a name
	// was issued; the PTR record says which address actually serves it, and the
	// two rarely match one to one — several names behind one address is the
	// shared-hosting case an investigator reads for. The names that are already
	// resolved are skipped, so this asks only about the ones nothing else knows.
	pointered := 0
	for _, name := range names {
		if resolved[name] {
			continue
		}
		addresses, lookupErr := routed.lookupHost(ctx, name)
		if lookupErr != nil {
			// One unresolvable certified name is not a reason to abandon the rest,
			// and it is not a warning either: a certificate is issued for names
			// that were never pointed anywhere, and that is the normal case.
			continue
		}
		for _, address := range addresses {
			canonical := net.ParseIP(address)
			if canonical == nil {
				continue
			}
			ip := canonical.String()
			pointer, ptrErr := routed.lookupHostReverse(ctx, ip)
			if ptrErr != nil {
				continue
			}
			pointerProvenance := map[string]interface{}{"source": "certificate_pointer", "name": name}
			result.Entities = append(result.Entities, entity("ip", ip, map[string]interface{}{"source": "certificate_pointer"}, pointerProvenance))
			result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "subdomain", Source: name, TargetType: "ip", Target: ip, Provenance: pointerProvenance})
			pointered++
			for _, record := range pointer {
				record = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record)), ".")
				if !storableHostname(record) {
					continue
				}
				result.Entities = append(result.Entities, entity("domain", record, nil, pointerProvenance))
				result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: record, TargetType: "ip", Target: ip, Provenance: pointerProvenance})
			}
		}
	}
	if pointered > 0 {
		setTransformMetadata(result, "cert_pointer_names", pointered)
	}
	return nil
}

// certificateIndexMetadata records which certificate transparency indexes
// answered and how many names each contributed, so the operator can see the
// coverage behind a result without repeating the query.
func certificateIndexMetadata(metadata map[string]interface{}, counts map[string]int, total int) map[string]interface{} {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	perIndex := map[string]interface{}{}
	for name, count := range counts {
		perIndex[name] = count
	}
	metadata["cert_indexes"] = perIndex
	metadata["cert_names"] = total
	return metadata
}

// certificateQueryZones returns the zones to ask the certificate indexes about,
// nearest first, for one host.
//
// The indexes are keyed by zone, not by host. An index that validates its input
// refuses a host that is not a zone — crt.name answers `invalid apex: not an
// apex (eTLD+1 is ...)` — and an index that accepts a host answers with the host
// itself, which is what the caller already knows and no subdomain at all. So a
// host input is resolved to the zone the indexes actually hold, one parent at a
// time, and the walk stops before a single label so a public suffix is never
// asked for the certificate list of the whole registry.
//
// A candidate that is not a storable host never enters the chain: an empty label
// such as the `..` of a malformed value is not a zone any index can answer.
func certificateQueryZones(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	zones := []string{}
	for zone := host; storableHostname(zone) && strings.Contains(zone, "."); zone = parentCertificateZone(zone) {
		zones = append(zones, zone)
	}
	return zones
}

// parentCertificateZone returns the zone one label up, or an empty string when
// the host is already a single label.
func parentCertificateZone(host string) string {
	if index := strings.Index(host, "."); index >= 0 {
		return host[index+1:]
	}
	return ""
}

// certificateEvidence is what the certificate indexes returned for one host.
type certificateEvidence struct {
	// names is the union of the names every index held.
	names map[string]bool
	// warnings names every index that could not answer and every index that
	// stopped short, so a thin result is never mistaken for a complete one.
	warnings []string
	// counts holds the names each answering index contributed.
	counts map[string]int
	// zone is the queried zone that produced names. It is the zone the names
	// are certified under, which for a host input is the zone the host belongs
	// to rather than the host itself.
	zone string
	// queried lists the zones that were asked, nearest first.
	queried []string
}

// certificateIndexOutcome accumulates what one index delivered across every zone
// it was asked about, so an index that cannot answer one zone is still credited
// with the zones it did answer.
type certificateIndexOutcome struct {
	source string
	names  map[string]bool
	// note describes how much of the index was read, such as where its own
	// public allowance stopped a paginated walk. It is not a failure.
	note string
	// firstFailure is the answer for the nearest zone, so an index that could
	// not answer the requested host is reported against that host rather than
	// against a parent zone that was tried on its behalf.
	firstFailure string
	// exhausted is set when the index said its own public allowance is spent,
	// which stops the walk from spending further requests on it.
	exhausted bool
	queried   int
	answered  bool
	zone      string
}

// certificateTransparencyNames resolves one host against the certificate
// indexes and returns the union of the names they returned, the warning for
// every index that did not answer, and the per-index counts.
//
// The chain builds the index queries for one zone, so every zone of the walk is
// asked about itself rather than about the host that started the walk. The walk
// stops at the first zone that holds a name the transform did not already have,
// so a host input is answered by the zone it belongs to while an apex input
// costs exactly one round of queries. Inside one zone the indexes run at the
// same time, so the whole transform costs the slowest index instead of the sum,
// and a dead index never delays the ones that work.
func certificateTransparencyNames(ctx context.Context, client *http.Client, host string, collector *transformCollector, chain func(string) []certificateSource) certificateEvidence {
	evidence := certificateEvidence{names: map[string]bool{}, counts: map[string]int{}}
	evidence.queried = certificateQueryZones(host)
	outcomes := map[string]*certificateIndexOutcome{}
	order := []string{}
	if len(evidence.queried) > 0 && chain != nil {
		// The index set is the same for every zone, so the accumulator order is
		// taken once from the first zone that is asked.
		for _, source := range chain(evidence.queried[0]) {
			if _, seen := outcomes[source.name]; seen {
				continue
			}
			outcomes[source.name] = &certificateIndexOutcome{source: source.name, names: map[string]bool{}}
			order = append(order, source.name)
		}
	}
	if len(order) == 0 {
		evidence.warnings = append(evidence.warnings, fmt.Sprintf("no public certificate index answered for %s", host))
		return evidence
	}
	for _, zone := range evidence.queried {
		sources := chain(zone)
		zoneNames, answering := queryCertificateZone(ctx, client, zone, collector, sources, outcomes, order)
		discovered := 0
		for name := range zoneNames {
			if name != host {
				discovered++
			}
			evidence.names[name] = true
		}
		// One checkpoint per zone, so the panel names the zone being read and
		// the indexes that answered instead of showing a frozen counter.
		collector.indexDone(ctx, certificateZoneProgress(zone, host, answeredIndexes(outcomes, order)), answering, collector.nameCount())
		if discovered > 0 || ctx.Err() != nil {
			evidence.zone = zone
			break
		}
	}
	for _, name := range order {
		outcome := outcomes[name]
		if !outcome.answered {
			if outcome.firstFailure != "" {
				evidence.warnings = append(evidence.warnings, outcome.firstFailure)
			}
			continue
		}
		evidence.counts[name] = len(outcome.names)
		if outcome.note != "" {
			evidence.warnings = append(evidence.warnings, fmt.Sprintf("the %s certificate index %s", name, outcome.note))
		}
		if len(outcome.names) == 0 {
			evidence.warnings = append(evidence.warnings, fmt.Sprintf("the %s certificate index holds no names for %s", name, outcome.zone))
		}
	}
	if len(evidence.counts) == 0 && ctx.Err() == nil {
		evidence.warnings = append(evidence.warnings, fmt.Sprintf("no public certificate index answered for %s", host))
	}
	return evidence
}

// queryCertificateZone asks every index about one zone at the same time and
// merges what they answered into the per-index accumulators. It reports the
// names the zone produced and the indexes that answered it.
func queryCertificateZone(ctx context.Context, client *http.Client, zone string, collector *transformCollector, sources []certificateSource, outcomes map[string]*certificateIndexOutcome, order []string) (map[string]bool, int) {
	pending := make([]certificateSource, 0, len(sources))
	for _, source := range sources {
		// An index that reported its allowance as spent is not asked again for
		// the next zone: it would answer with the same refusal it just gave.
		if outcomes[source.name].exhausted {
			continue
		}
		pending = append(pending, source)
	}
	indexes := make([]certificateIndex, len(pending))
	var wg sync.WaitGroup
	for position, source := range pending {
		wg.Add(1)
		go func(slot int, current certificateSource) {
			defer wg.Done()
			// Each index streams its names into the shared collector, so the
			// progress panel moves while the indexes are still answering
			// rather than only when they are all done.
			index := &streamingCollector{collector: collector, source: current.name}
			names, note, exhausted, failure := queryCertificateSource(ctx, client, current, zone, index)
			indexes[slot] = certificateIndex{source: current.name, names: names, note: note, exhausted: exhausted, failure: failure}
		}(position, source)
	}
	wg.Wait()

	zoneNames := map[string]bool{}
	answered := 0
	for _, index := range indexes {
		outcome, known := outcomes[index.source]
		if !known {
			// The chain for this zone carries an index the first zone did not,
			// so it is accounted for from the zone that introduced it.
			outcome = &certificateIndexOutcome{source: index.source, names: map[string]bool{}}
			outcomes[index.source] = outcome
			order = append(order, index.source)
		}
		outcome.queried++
		if index.failure != "" {
			if outcome.firstFailure == "" {
				outcome.firstFailure = index.failure
			}
			continue
		}
		outcome.answered = true
		outcome.zone = zone
		answered++
		if index.note != "" && outcome.note == "" {
			outcome.note = index.note
		}
		if index.exhausted {
			outcome.exhausted = true
		}
		for name := range index.names {
			zoneNames[name] = true
			outcome.names[name] = true
		}
	}
	return zoneNames, answered
}

// answeredIndexes lists the certificate indexes that have answered so far, in the
// order the chain declares them, so the progress panel names real sources rather
// than an opaque counter.
func answeredIndexes(outcomes map[string]*certificateIndexOutcome, order []string) []string {
	answered := []string{}
	for _, name := range order {
		if outcomes[name].answered {
			answered = append(answered, certificateIndexName(name))
		}
	}
	return answered
}

// certificateZoneProgress describes the zone being read for the progress panel.
func certificateZoneProgress(zone, host string, answered []string) string {
	if zone == host {
		return strings.Join(answered, ", ")
	}
	if len(answered) == 0 {
		return "zone " + zone
	}
	return "zone " + zone + ": " + strings.Join(answered, ", ")
}

// positiveIntOption reads an explicit numeric option from a transform request.
//
// It exists so concurrency and other operational numbers arrive from a field the
// caller can read and change, never from a constant buried in a loop. A missing
// or unusable value returns the documented default, and the default is reported
// back in the visible progress label so the applied value is never a surprise.
func positiveIntOption(options map[string]interface{}, key string, fallback int) int {
	switch raw := options[key].(type) {
	case float64:
		if raw >= 1 {
			return int(raw)
		}
	case int:
		if raw >= 1 {
			return raw
		}
	case json.Number:
		if parsed, err := raw.Int64(); err == nil && parsed >= 1 {
			return int(parsed)
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && parsed >= 1 {
			return parsed
		}
	}
	return fallback
}

func stringSliceOption(options map[string]interface{}, key string) []string {
	values, ok := options[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

// dnsGuess is one resolved brute-force candidate with deterministic ordering.
type dnsGuess struct {
	name string
	ips  []string
}

// defaultSubdomainWords is the embedded sublist3r-style wordlist used when
// the caller supplies no explicit words. Entries are short alphanumeric
// labels; the option cap still applies through stringSliceOption bounds.
func defaultSubdomainWords() []string {
	words := []string{
		"www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "admin",
		"blog", "shop", "api", "dev", "test", "stage", "staging", "prod",
		"portal", "vpn", "remote", "secure", "login", "sso", "auth",
		"cdn", "static", "assets", "img", "images", "media", "video",
		"ns1", "ns2", "dns", "mx", "web", "site", "sites", "app", "apps",
		"mobile", "m", "beta", "demo", "docs", "support", "help", "status",
		"git", "gitlab", "jenkins", "jira", "wiki", "crm", "erp", "hr",
		"pay", "billing", "store", "news", "forum", "community", "chat",
		"files", "drive", "cloud", "backup", "db", "sql", "monitor",
		"grafana", "kibana", "prometheus", "ldap", "proxy", "gateway",
		"internal", "intranet", "extranet", "partner", "client",
		"new", "old", "legacy", "v1", "v2", "api-v1", "api-v2", "sandbox",
	}
	return words
}

// crtLookupAttempts is how often one certificate transparency query is sent
// before the outage is reported. The public crt.sh mirror answers 502 and 503
// for a single large query often enough that one attempt reports an outage a
// later attempt resolves, so the retry is part of the adapter instead of a
// policy choice by the caller.
const crtLookupAttempts = 3

// certspotterPageSize is the number of issuances one certspotter page carries.
// A short page is the whole answer, a full one has a successor.
const certspotterPageSize = 100

// certificateTransparencyQuery is the public crt.sh certificate transparency
// query for one domain.
func certificateTransparencyQuery(domain string) string {
	return "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
}

// certificateSource is one public Certificate Transparency index. Every source
// answers the same question from the same public CT logs — which names were
// certified under a host — and they fail independently of each other, so the
// union of their answers is evidence and a failed source only removes coverage.
type certificateSource struct {
	name  string
	query string
	// accept is the media type this index actually serves.
	accept string
	// keyEnv names the optional operator key for indexes that meter access.
	keyEnv string
	// page extracts the certified names from one answer and the token that
	// fetches the next page, which is empty for an index that answered in
	// full. Pagination therefore follows the index's own cursor. The stream
	// reports the names as they arrive and is the pause point; it is nil for
	// the synchronous endpoint.
	page func(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error)
}

// certificateSources returns the index set for one zone.
//
// crt.sh is the public front end, but it runs on a shared PostgreSQL cluster
// with a measured uptime in the low double digits and answers 502 for a single
// large zone query. The rest are independent indexes of the same public logs,
// each with its own answer format: crt.name serves one name per line,
// certspotter serves paginated issuances, Shodan CTL serves a hostname array,
// and ctlogs.dev serves one row per hostname. Querying them together is what
// makes subdomain discovery survive crt.sh being down, so the set is merged
// rather than walked.
//
// Every index is asked about a zone, never about a bare host: crt.name refuses
// a host that is not an apex, and the others answer a host with the host
// itself. The zone chain in certificateQueryZones supplies the zone.
func certificateSources(domain string) []certificateSource {
	return []certificateSource{
		{
			name:   "crt.sh",
			query:  "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json",
			accept: "application/json",
			page:   readCrtShNames,
		},
		{
			name:   "crt.name",
			query:  "https://crt.name/v1/search?apex=" + url.QueryEscape(domain),
			accept: "text/plain",
			page:   readLineNames,
		},
		{
			// Anonymous certspotter access is metered at ten requests, so this
			// index is read page by page and stops where the server says its
			// own allowance ran out.
			name:   "certspotter",
			query:  "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names",
			accept: "application/json",
			keyEnv: "CERTSPOTTER_API_TOKEN",
			page:   readCertspotterNames,
		},
		{
			// НЕ ключ без ключа. Попередня правка додала `keyEnv: "SHODAN_API_KEY"`
			// і механізм «не питати індекс без ключа», щоб прибрати 403.
			//
			// Відкочено 2026-10-03 тому, що доказ був недобрий: 403 містить
			// Cloudflare-інтерстиціал, а **весь контроль ішов з Tor-exit**
			// (міряно `api.ipify.org` = 185.220.101.3 / .9 — це вузли Tor).
			// Tor-exit регулярно отримує 403, тож «Shodan закрив доступ без
			// ключа» з такого вимірювання **не йде**. А наслідок був незворотний:
			// індекс назавжди випадав зі звіту з формулюванням «пропущено: ключ не
			// заданий», тобто причина записувалась як факт про мертве джерело.
			// Прибрати джерело можна лише після контролю без Tor.
			name:   "shodan-ctl",
			query:  "https://ctl.shodan.io/api/v1/domain/" + url.QueryEscape(domain) + "/hostnames",
			accept: "application/json",
			page:   readStringArrayNames,
		},
		{
			// The hostname list is one row per name and needs no wildcard
			// syntax, so it also answers for a subdomain the apex-only
			// indexes reject. Paging it needs a key; the first page is the
			// whole anonymous answer.
			name:   "ctlogs.dev",
			query:  "https://api.ctlogs.dev/v1/hosts/" + url.QueryEscape(domain),
			accept: "application/json",
			keyEnv: "CTLOGS_API_KEY",
			page:   readCTLogsHosts,
		},
	}
}

// certificateIndex is the outcome of querying one index about one zone.
type certificateIndex struct {
	source string
	names  map[string]bool
	// note describes how much of the index was read, such as where its own
	// public allowance stopped a paginated walk. It is not a failure.
	note string
	// exhausted is set when the index reported its own public allowance as
	// spent, so a further zone does not spend another request on it.
	exhausted bool
	// failure is set only when the index could not answer at all.
	failure string
}

// streamingCollector reports the names one certificate index has produced so
// far, and holds the pause point for that index. A nil one keeps the index
// reading at full speed, which is what the synchronous endpoint does.
type streamingCollector struct {
	collector *transformCollector
	source    string
}

// addName reports one name this index contributed, so the panel counts distinct
// names instead of one row per index.
func (stream *streamingCollector) addName(ctx context.Context, name string) {
	if stream == nil || stream.collector == nil {
		return
	}
	stream.collector.distinct(ctx, name)
}

// flush publishes the counters after a finished page.
func (stream *streamingCollector) flush(ctx context.Context) {
	if stream == nil || stream.collector == nil {
		return
	}
	stream.collector.flush(ctx)
}

// context returns the context of the job this stream belongs to, or the
// background context when it runs without a job.
func (stream *streamingCollector) context() context.Context {
	if stream == nil || stream.collector == nil || stream.collector.job == nil {
		return context.Background()
	}
	return stream.collector.jobContext()
}

// certificateStatusError is one index answer that could not be used. Its status
// decides whether another attempt is worth making: a rate limit, a timeout or a
// server error is the index being briefly unavailable, while a rejected or
// missing query is the index saying it will never answer that query, and
// repeating it only spends the run's time.
type certificateStatusError struct {
	status int
	reason string
}

func (failure *certificateStatusError) Error() string {
	return failure.reason
}

// retryable reports whether the same query may answer on a later attempt.
func (failure *certificateStatusError) retryable() bool {
	switch failure.status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// queryCertificateSource queries one index, retrying while the index is merely
// unavailable and returning as soon as it has answered. The note describes how
// much of the index was read; the failure is set only when it could not answer.
func queryCertificateSource(ctx context.Context, client *http.Client, source certificateSource, domain string, stream *streamingCollector) (map[string]bool, string, bool, string) {
	found := map[string]bool{}
	note := ""
	failure := ""
	for attempt := 1; attempt <= crtLookupAttempts; attempt++ {
		if attempt > 1 {
			// Wait between attempts without ignoring a cancelled route.
			select {
			case <-ctx.Done():
				return found, note, false, fmt.Sprintf("the %s index was cancelled after %d of %d attempts", source.name, attempt-1, crtLookupAttempts)
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		names, pageNote, exhausted, err := readCertificateIndex(ctx, client, source, domain, stream)
		for name := range names {
			found[name] = true
		}
		if err == nil {
			return found, pageNote, exhausted, ""
		}
		// A query the index has rejected is reported once and the walk moves on
		// to the next zone instead of spending attempts on a refusal.
		var status *certificateStatusError
		if errors.As(err, &status) && !status.retryable() {
			return map[string]bool{}, "", false, fmt.Sprintf("the %s index %s", source.name, status.reason)
		}
		// A retry that follows a partial read starts the walk from the top so
		// the reported page count describes one coherent run.
		found = map[string]bool{}
		note = ""
		failure = fmt.Sprintf("the %s index %s", source.name, err.Error())
	}
	return found, note, false, fmt.Sprintf("%s after %d attempts", failure, crtLookupAttempts)
}

// readCertificateIndex follows one index to the end of what it is willing to
// serve, and reports the names together with a note when the index itself
// stopped the walk.
//
// The walk ends where the index's own cursor or its own remaining allowance
// ends, never at a page count invented here, so a metered public index is
// read exactly as far as it allows and the operator is told where it stopped.
func readCertificateIndex(ctx context.Context, client *http.Client, source certificateSource, domain string, stream *streamingCollector) (map[string]bool, string, bool, error) {
	found := map[string]bool{}
	query := source.query
	pages := 0
	for {
		names, cursor, allowance, err := fetchCertificatePage(ctx, client, source, query, domain, stream)
		if err != nil {
			if pages == 0 {
				return found, "", false, err
			}
			// A later page failing does not discard the pages already read.
			return found, fmt.Sprintf("was read for %d page(s) before the index %s", pages, err.Error()), false, nil
		}
		for name := range names {
			found[name] = true
		}
		// The page is reported as a whole as well: the per-name counter is exact,
		// but a short answer must not wait for the report threshold to tick.
		stream.flush(ctx)
		pages++
		switch {
		case allowance != "":
			return found, fmt.Sprintf("was read for %d page(s); %s", pages, allowance), true, nil
		case cursor == "":
			if pages > 1 {
				return found, fmt.Sprintf("was read for %d page(s)", pages), false, nil
			}
			return found, "", false, nil
		}
		query = nextCertificatePage(source.query, cursor)
	}
}

// fetchCertificatePage performs one index request and reports the names, the
// cursor of the next page, and what the index says is left of its allowance.
func fetchCertificatePage(ctx context.Context, client *http.Client, source certificateSource, queryURL, domain string, stream *streamingCollector) (map[string]bool, string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	request.Header.Set("User-Agent", RandomUserAgent())
	request.Header.Set("Accept", source.accept)
	// The key is read from the environment only; no index credential is
	// hardcoded, and an index without a key still answers anonymously.
	if key := strings.TrimSpace(os.Getenv(source.keyEnv)); source.keyEnv != "" && key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// An unavailable index answers a 429/502/503 HTML page, so the body
		// is not worth reading: the status already explains the failure.
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return nil, "", "", &certificateStatusError{status: response.StatusCode, reason: fmt.Sprintf("returned an unusable response (status=%d)", response.StatusCode)}
		}
		// A rejected query is the index refusing this exact question, which is
		// what an index does for a host that is not a zone.
		return nil, "", "", &certificateStatusError{status: response.StatusCode, reason: fmt.Sprintf("rejected the query (status=%d)", response.StatusCode)}
	}
	names, cursor, readErr := source.page(response.Body, domain, stream)
	if readErr != nil {
		return nil, "", "", fmt.Errorf("returned an unusable response (%v)", readErr)
	}
	return names, cursor, exhaustedAllowance(response.Header), nil
}

// nextCertificatePage adds the cursor of the following page to an index query.
func nextCertificatePage(query, cursor string) string {
	separator := "?"
	if strings.Contains(query, "?") {
		separator = "&"
	}
	return query + separator + "after=" + url.QueryEscape(cursor)
}

// exhaustedAllowance reports whether an index says its public budget is spent,
// so the walk stops exactly where the index says it must.
func exhaustedAllowance(header http.Header) string {
	limit, hasLimit := headerValue(header, "X-RateLimit-Limit")
	remaining, hasRemaining := headerValue(header, "X-RateLimit-Remaining")
	if hasRemaining && remaining == "0" {
		if hasLimit {
			return fmt.Sprintf("stopped where the index reported %s of %s requests left", remaining, limit)
		}
		return "stopped where the index reported no requests left"
	}
	if hourly, ok := headerValue(header, "X-Hourly-Remaining"); ok && hourly == "0" {
		return "stopped where the index reported no requests left this hour"
	}
	return ""
}

func headerValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.TrimSpace(values[0]), true
}

// readCertspotterNames reads one certspotter page of issuances and returns the
// issuance id of the last row, which is the `after` cursor of the next page.
func readCertspotterNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	decoder := json.NewDecoder(body)
	var issuances []struct {
		ID       string   `json:"id"`
		DNSNames []string `json:"dns_names"`
	}
	if err := decoder.Decode(&issuances); err != nil {
		return names, "", fmt.Errorf("certificate index could not be decoded: %w", err)
	}
	for _, issuance := range issuances {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		for _, name := range issuance.DNSNames {
			if addCertificateName(names, name, domain) {
				stream.addName(stream.context(), name)
			}
		}
	}
	// A short page is the whole answer; a full one has a successor.
	if len(issuances) < certspotterPageSize {
		return names, "", nil
	}
	return names, issuances[len(issuances)-1].ID, nil
}

// readStringArrayNames reads an index that answers with a flat JSON array of
// host names, such as the Shodan CTL hostname list.
func readStringArrayNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	decoder := json.NewDecoder(body)
	var values []string
	if err := decoder.Decode(&values); err != nil {
		return names, "", fmt.Errorf("certificate index could not be decoded: %w", err)
	}
	for _, value := range values {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		if addCertificateName(names, value, domain) {
			stream.addName(stream.context(), value)
		}
	}
	return names, "", nil
}

// addCertificateName keeps one certified name when it belongs to the requested
// zone, and reports whether the name was kept, so the caller can count the names
// the answer really holds. The apex itself is the transform input and is not
// repeated.
//
// An index answer is attacker-controllable: a certificate can name an empty
// label such as `..example.test` or a name carrying a separator. Those are
// dropped here rather than stored, and every label is checked with the same
// rules the graph identity validation uses.
func addCertificateName(names map[string]bool, candidate, domain string) bool {
	name := strings.ToLower(strings.TrimSpace(candidate))
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" || name == domain {
		return false
	}
	if !strings.HasSuffix(name, "."+domain) {
		return false
	}
	if strings.ContainsAny(name, " /:@\\\t\r\n\"'") {
		return false
	}
	if !storableHostname(name) {
		return false
	}
	names[name] = true
	return true
}

// storableHostname reports whether every label of a host is one the graph can
// store: non-empty, alphanumeric or hyphen, and not starting or ending with a
// hyphen. This mirrors the gateway identity rules exactly.
func storableHostname(host string) bool {
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if !isASCIIAlnum(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

// readCrtShNames reads a crt.sh answer: one very large JSON array of
// certificates, consumed element by element, where each row carries every
// certificate name in a single newline separated value. The endpoint answers
// the whole query in one document, so there is no next page.
//
// Each row is a pause point and reports its own names, which is what keeps a
// multi-hundred-thousand name answer controllable instead of one long block.
func readCrtShNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	err := streamJSONArray(body, func(element json.RawMessage) error {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return err
			}
		}
		var row struct {
			NameValue string `json:"name_value"`
		}
		if json.Unmarshal(element, &row) != nil {
			// One malformed certificate row must not discard the whole log.
			return nil
		}
		for _, name := range strings.Split(row.NameValue, "\n") {
			if addCertificateName(names, name, domain) {
				stream.addName(stream.context(), name)
			}
		}
		return nil
	})
	return names, "", err
}

// readLineNames reads a crt.name answer: one certified name per line. The line
// reader is bounded per line and streams, because the answer for a large zone
// is megabytes long.
func readLineNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		// A line index answers tens of thousands of names, so the pause point
		// is every line rather than once at the end.
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		if addCertificateName(names, scanner.Text(), domain) {
			stream.addName(stream.context(), scanner.Text())
		}
	}
	return names, "", scanner.Err()
}

// readCTLogsHosts reads a ctlogs.dev answer: an envelope with one row per
// certified hostname rather than one row per certificate. The envelope names
// the cursor of the next page, but that walk needs a key, so an anonymous
// query stops at the page the index chose to serve.
func readCTLogsHosts(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	decoder := json.NewDecoder(body)
	var envelope struct {
		Hosts []struct {
			Host string `json:"host"`
		} `json:"hosts"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return names, "", fmt.Errorf("certificate index could not be decoded: %w", err)
	}
	for _, row := range envelope.Hosts {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		if addCertificateName(names, row.Host, domain) {
			stream.addName(stream.context(), row.Host)
		}
	}
	return names, "", nil
}

// streamJSONArray decodes a JSON array element by element and calls visit for
// every element. Public datasets answer with one very large array, so the
// response body is never buffered as a whole and an element that arrives
// incomplete is reported as an error instead of being silently dropped.
// streamJSONObjects reads a JSON Lines index: one object per line, each holding
// the captured URL under one member.
//
// The crawl index answers this way rather than with an array, and it holds one
// row per capture, so the stream is consumed as it arrives for the same reason
// the array layouts are: a host with a long capture history produces a very long
// response. A line that is not an object is skipped rather than ending the read,
// because one malformed row must not cost the rows that follow it.
func streamJSONObjects(reader io.Reader, field string, visit func(archiveCapture)) (int, error) {
	scanner := bufio.NewScanner(reader)
	// A crawl row carries a digest, offsets and a WARC filename, so a line is far
	// wider than the scanner default allows.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	// delivered counts every object the index sent, including the ones that carry
	// no usable URL. Rows that arrive without the field are what tells "this index
	// changed its format" apart from "this host has no captures", so the number
	// cannot be inferred from the accepted rows.
	delivered := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		delivered++
		raw, ok := row[field]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			// The coordinate columns are read by name, so an index that publishes
			// them under a different spelling keeps its URL rather than losing the
			// whole row. A crawl that publishes all three is the only thing that
			// can be fetched back, so a partial set is not written as a partial
			// address that would read as a broken one.
			capture := archiveCapture{url: value}
			capture.timestamp = archiveRowString(row, "timestamp")
			capture.filename = archiveRowString(row, "filename")
			capture.offset = archiveRowString(row, "offset")
			capture.length = archiveRowString(row, "length")
			visit(capture)
		}
	}
	return delivered, scanner.Err()
}

// archiveRowString reads one column of a published row by name.
//
// The crawl index writes its numbers as JSON strings, but a column that carried
// a bare number would be a row this reader cannot use, and dropping the row over
// one unreadable column would throw away a URL that was read perfectly. A column
// that is not a string is therefore an empty value, not a failed row.
func archiveRowString(row map[string]json.RawMessage, field string) string {
	raw, ok := row[field]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

// archiveURLHost returns the host a recorded URL was served by, and the entity
// type that host is stored as.
//
// A host equal to the queried one is the apex and is stored as the domain the
// transform already created. Any other host under it is a subdomain, and it is
// stored as one so that the name is never claimed to be the apex and so that a
// later transform that already found the name links to the same identity rather
// than adding a second copy of it.
func archiveURLHost(target string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("recorded URL %q could not be read", target)
	}
	host, ok := canonicalURLHost(parsed.Hostname())
	if !ok {
		return "", fmt.Errorf("recorded URL %q names no usable host", target)
	}
	return host, nil
}

func streamJSONArray(reader io.Reader, visit func(json.RawMessage) error) error {
	decoder := json.NewDecoder(reader)
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return errors.New("response is not a JSON array")
	}
	for decoder.More() {
		var element json.RawMessage
		if err := decoder.Decode(&element); err != nil {
			return err
		}
		if err := visit(element); err != nil {
			return err
		}
	}
	// Read the closing bracket so an array that stops early is reported.
	_, err = decoder.Token()
	return err
}

// detectWildcardDNS probes random labels; any resolution means the zone
// answers every name and brute-force names would be false positives. The
// resolving probe is returned so the warning can be verified by the analyst.
//
// The probes are pause points like every other step of the transform, so a
// paused job suspends here instead of waiting out the resolver.
func detectWildcardDNS(ctx context.Context, collector *transformCollector, lookup func(context.Context, string) ([]string, error), domain string) (string, bool) {
	for _, label := range []string{"rr-nowild-01", "rr-nowild-02"} {
		if err := collector.checkpoint(ctx); err != nil {
			return "", false
		}
		collector.label(ctx, "wildcard dns probe "+label)
		name := label + "." + domain
		ips, err := lookup(ctx, name)
		if err != nil || len(ips) == 0 {
			continue
		}
		return name + " -> " + strings.Join(ips, ", "), true
	}
	return "", false
}

// concurrencyOption reads the explicit pool size for a transform phase.
//
// `concurrency` is the name every transform reads, so the operator is not asked
// to learn a different key per tool. `dns_concurrency` stays accepted because it
// is the key the DNS phase was already driven with; dropping it would silently
// reset a saved configuration to the default.
func concurrencyOption(options map[string]interface{}, fallback int) int {
	if size := positiveIntOption(options, "concurrency", 0); size > 0 {
		return size
	}
	return positiveIntOption(options, "dns_concurrency", fallback)
}

// bruteForceDefaultWorkers is how many candidates the DNS phase resolves at the
// same time when the caller names no value. The whole wordlist is still
// resolved — this is concurrency, not a cap on the work — and a bounded pool is
// what makes the phase a real pause point: with one goroutine per candidate the
// whole wordlist would already be in flight before a pause could be observed.
//
// It is a default, not a rule: the caller overrides it with the explicit
// `dns_concurrency` option, and the applied value is stated in the progress
// label so the operator sees which one is in use.
const bruteForceDefaultWorkers = 8

// bruteForceSubdomains resolves every supplied candidate and returns hits
// sorted by name for deterministic entity output.
//
// Every candidate is a pause point and reports itself, because this is the part
// of the transform that produces no names for long stretches: without the
// checkpoint a paused job would keep resolving candidates to the end of the
// wordlist, and without the label the panel would look frozen while it works.
func bruteForceSubdomains(ctx context.Context, collector *transformCollector, lookup func(context.Context, string) ([]string, error), domain string, words []string, found map[string]bool, workers int) ([]dnsGuess, int) {
	applied := workers
	if applied < 1 {
		applied = 1
	}
	candidates := make([]string, 0, len(words))
	for _, word := range words {
		candidate := strings.ToLower(strings.TrimSpace(word))
		if candidate == "" || strings.ContainsAny(candidate, " /:@") || found[candidate+"."+domain] {
			continue
		}
		candidates = append(candidates, candidate+"."+domain)
	}
	queue := make(chan string)
	results := make(chan dnsGuess)
	var tried atomic.Int64
	var wg sync.WaitGroup
	if len(candidates) < applied {
		applied = len(candidates)
	}
	for worker := 0; worker < applied; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range queue {
				if err := collector.checkpoint(ctx); err != nil {
					// A paused phase resumes from here; a cancelled one ends
					// with the job. Neither loses the names already resolved.
					continue
				}
				ips, err := lookup(ctx, candidate)
				done := tried.Add(1)
				collector.label(ctx, fmt.Sprintf("dns candidates %d/%d", done, len(candidates)))
				if err != nil || len(ips) == 0 {
					continue
				}
				collector.distinct(ctx, candidate)
				select {
				case <-ctx.Done():
				case results <- dnsGuess{name: candidate, ips: append([]string{}, ips...)}:
				}
			}
		}()
	}
	go func() {
		defer close(results)
		wg.Wait()
	}()
	go func() {
		defer close(queue)
		for _, candidate := range candidates {
			select {
			case <-ctx.Done():
				return
			case queue <- candidate:
			}
		}
	}()
	hits := []dnsGuess{}
	seen := map[string]bool{}
	for guess := range results {
		if seen[guess.name] {
			continue
		}
		seen[guess.name] = true
		hits = append(hits, guess)
	}
	sort.Slice(hits, func(left, right int) bool { return hits[left].name < hits[right].name })
	// The applied pool size travels with the result. The per-candidate progress
	// label is overwritten by the counter, so reporting the number here is what
	// makes the bound visible instead of an unstated internal detail.
	return hits, applied
}

// The two public-index transforms below read observations a third party already
// collected. They are here because the analyst is holding an identity and wants
// what the public record says about it — which host it was seen on, which network
// answered for it, whether anyone has flagged it — and answering that from a
// public index is faster and cheaper than reproducing the collection.
//
// Both are one query per run against a public endpoint that answers an anonymous
// client. Neither declares a pool: there is no loop to size, and inventing one
// would only give the index a second reason to throttle us.

// publicUrlscanSearch is the urlscan.io search API. It answers an anonymous
// client for public scans; a key read from the environment raises the rate
// limit but is not required, so the transform is useful on a fresh install.
const publicUrlscanSearch = "https://urlscan.io"

// publicFilescan is the filescan.io API host.
//
// The vendor also publishes `api.filescan.io`, and that host does not answer:
// the connection is closed before any status arrives. The API this transform
// reads is served from the apex host, which is what the vendor's own OpenAPI
// document is published on. Naming the working host is the whole reason this
// constant exists — the other one looks correct and is not.
const publicFilescan = "https://www.filescan.io"

// indexUserAgent returns a realistic browser user-agent drawn from UserAgent.txt pool.
func indexUserAgent() string {
	return RandomUserAgent()
}

// urlscanSearchMaxResults is the number of scans one run reads.
//
// The index answers `total` for the whole match, so this is not a limit on what
// the analyst can see: it is one page. A larger page is available on request
// through the `size` option, and the value that was really used travels with the
// result in `urlscan_size`, because a bound the operator cannot see and cannot
// change is the kind this project does not ship.
const urlscanSearchMaxResults = 100

// urlscanOptionSize reads the requested page size from the transform options.
func urlscanOptionSize(options map[string]interface{}) (int, error) {
	raw, ok := options["size"]
	if !ok {
		return urlscanSearchMaxResults, nil
	}
	switch typed := raw.(type) {
	case float64:
		return int(typed), nil
	case int:
		return typed, nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, transformError("INVALID_URLSCAN_OPTION", "size must be a whole number")
		}
		return parsed, nil
	case nil:
		return urlscanSearchMaxResults, nil
	default:
		return 0, transformError("INVALID_URLSCAN_OPTION", "size must be a whole number")
	}
}

// urlscanSearchResult is one public page scan as the search index publishes it.
//
// The struct holds the fields the graph can store. The index publishes more per
// scan — the request list, the technologies, the cookies, the screenshot — and
// that is deliberately not read here: the result of a search is a set of
// identities and the network that answered for them, and a search that fetched
// every detail of every scan would be a different and much heavier tool.
type urlscanSearchResult struct {
	Task struct {
		URL        string `json:"url"`
		Domain     string `json:"domain"`
		Time       string `json:"time"`
		UUID       string `json:"uuid"`
		Visibility string `json:"visibility"`
	} `json:"task"`
	Page struct {
		URL             string      `json:"url"`
		Domain          string      `json:"domain"`
		IP              string      `json:"ip"`
		ASN             string      `json:"asn"`
		ASNName         string      `json:"asnname"`
		Server          string      `json:"server"`
		TLSIssuer       string      `json:"tlsIssuer"`
		TLSValidFrom    string      `json:"tlsValidFrom"`
		TLSValidDays    interface{} `json:"tlsValidDays"`
		DomainAgeDays   interface{} `json:"domainAgeDays"`
		Country         string      `json:"country"`
		Language        string      `json:"language"`
		MIMEType        string      `json:"mimeType"`
		Status          interface{} `json:"status"`
		Title           string      `json:"title"`
		PTR             string      `json:"ptr"`
		APEXDomain      string      `json:"apexDomain"`
		APEXDomainAge   interface{} `json:"apexDomainAgeDays"`
		UmbrellaRankRaw interface{} `json:"umbrellaRank"`
	} `json:"page"`
	Stats struct {
		UniqIPs       interface{} `json:"uniqIPs"`
		UniqCountries interface{} `json:"uniqCountries"`
		Requests      interface{} `json:"requests"`
		DataLength    interface{} `json:"dataLength"`
	} `json:"stats"`
	Result string `json:"result"`
}

// urlscanNames is what the public urlscan.io index contributes to a subdomain
// discovery: the hosts it has actually seen a page scanned on.
//
// It is deliberately a **name source and nothing else**. urlscan publishes far
// more per scan — the request list, the technologies, the cookies, the
// screenshot — and none of that belongs in a name discovery: the operator asked
// "which names exist under this zone", and a source that answered with a
// screenshot would be answering a different question.
//
// The zone filter is the whole point of this function. `domain:` on urlscan is
// a **substring match**, not an exact one: a query for `domain:example.com`
// comes back with `newsdig.tbs.co.jp` and `kbmfa.vip` among the hits. Accepting
// those would invent a hierarchy between unrelated organisations, so a name is
// only taken when the index itself published an apex and the name really sits
// under the queried zone. The rest is reported as a count, never silently
// dropped and never silently accepted.
type urlscanEvidence struct {
	names map[string]bool
	total int
	read  int
	// foreign counts the hits the zone filter rejected, so the operator can see
	// that the index answered and that the filter, not an empty index, is why
	// some of it is not in the graph.
	foreign int
}

// urlscanNames asks the public index which hosts it has scanned under a zone.
func (s *server) urlscanNames(ctx context.Context, client *http.Client, zone string, size int) (urlscanEvidence, error) {
	evidence := urlscanEvidence{names: map[string]bool{}}
	base := strings.TrimSuffix(strings.TrimSpace(s.urlscanBase), "/")
	if base == "" {
		base = publicUrlscanSearch
	}
	scans, total, err := s.urlscanSearch(ctx, client, base, "domain", zone, size)
	if err != nil {
		return evidence, err
	}
	evidence.total, evidence.read = total, len(scans)
	for index := range scans {
		host := normalizeGraphHostname(scans[index].Page.Domain)
		if host == "" {
			continue
		}
		apex := normalizeGraphHostname(scans[index].Page.APEXDomain)
		if host == zone {
			// The zone itself is what the operator already holds and what the
			// result already contains; a name source that returned it would make
			// a domain look like its own subdomain.
			continue
		}
		if apex == "" || !strings.HasSuffix(host, "."+zone) {
			evidence.foreign++
			continue
		}
		evidence.names[host] = true
	}
	return evidence, nil
}

// urlscanEvidenceMetadata records what the index answered and how much of it the
// run read, so a result is not read as the index's complete record.
// The three threat-intelligence indexes below were added 2026-10-01 after the
// comparison with subfinder named them: its JSON output records which source
// produced each name, and the names it found and we did not came from exactly
// these three, not from any certificate index.
//
//	thc           ip.thc.org        POST, 3 names we had none of
//	(sitedossier was here: 6 names we had none of — прибрано 2026-10-03, джерело мертве)
//	hudsonrock    hudsonrock.com    GET,  1 name  we had none of
//
// They are a different class from what was already in the chain: not
// certificates, not passive DNS, not public page scans, but records of
// infrastructure these organisations have *seen* — a threat feed's own DNS
// sightings, a dossier's crawl of the parent domain, and the hostnames of
// machines caught by infostealers. That is why they answer for names nothing
// else can: a host that only ever appeared in an infostealer log has no
// certificate, no scan and no DNS record today.
//
// The subfinder contract was read from its source, not guessed:
// `pkg/subscraping/sources/thc/thc.go` posts `{domain, page_state, limit}` and
// reads `domains[].domain` with `next_page_state`; `hudsonrock.go` GETs
// `urls-by-domain?domain=` and reads `data.employees_urls` / `data.clients_urls`
// as full URLs, so the host has to be parsed out of them; the removed `sitedossier` GETs
// `/parentdomain/<domain>` and extracts hostnames from the page.

// passiveNameSource is one such index. They are the same shape — a request, a
// body, and a way to read hostnames out of it — so they are one type and one
// loop rather than three near-identical functions, which is the difference
// between a pattern and a pile.
type passiveNameSource struct {
	name string
	// post selects the HTTP method.
	post bool
	// build renders the request for one query.
	build func(base, zone string) (method, endpoint string, body string)
	// parse reads hostnames out of the answer, using the same name for every
	// index so the zone filter and the counters stay in one place.
	parse func(body []byte) (names []string, more bool, err error)
}

// passiveIntelSources is the measured set. Each entry is a name, a request and a
// parser, and the loop below asks them all, counts what each answered, and names
// the ones that did not.
var passiveIntelSources = []passiveNameSource{
	{
		name: "thc",
		post: true,
		build: func(base, zone string) (string, string, string) {
			payload, _ := json.Marshal(map[string]interface{}{
				"domain": zone, "page_state": "", "limit": 1000,
			})
			return http.MethodPost, base + "/api/v1/lookup/subdomains", string(payload)
		},
		parse: func(body []byte) ([]string, bool, error) {
			var document struct {
				Domains []struct {
					Domain string `json:"domain"`
				} `json:"domains"`
				NextPageState string `json:"next_page_state"`
			}
			if err := json.Unmarshal(body, &document); err != nil {
				return nil, false, fmt.Errorf("the answer was not the documented shape")
			}
			names := make([]string, 0, len(document.Domains))
			for _, entry := range document.Domains {
				if entry.Domain != "" {
					names = append(names, entry.Domain)
				}
			}
			return names, document.NextPageState != "", nil
		},
	},
	// sitedossier прибрано 2026-10-03.
	//
	// Замірено того дня, і саме тому це ендпоінт, а не сервіс: сервер
	// живий і відповідає, але саме цей шлях більше не існує.
	//
	//   UA curl/8        -> 404, 2367 байт HTML-сторінки «not found»
	//   UA Mozilla/5.0   -> 403, 11 байт «Forbidden.»
	//   без UA           -> 302, 0 байт
	//   DNS              -> 192.95.19.76 (резолвиться)
	//
	// Тобто запит до `/parentdomain/<zone>` не повертає імені за жодного
	// клієнта, а сам домен обслуговується. Джерело виключено з банді, бо воно
	// тягнуло по одному запиту на зону й додавало до звіту збій, який не про
	// цю зону.
	{
		name: "hudsonrock",
		post: false,
		build: func(base, zone string) (string, string, string) {
			return http.MethodGet,
				base + "/api/json/v2/osint-tools/urls-by-domain?domain=" + url.QueryEscape(zone), ""
		},
		parse: func(body []byte) ([]string, bool, error) {
			var document struct {
				Data struct {
					Employees []struct {
						URL string `json:"url"`
					} `json:"employees_urls"`
					Clients []struct {
						URL string `json:"url"`
					} `json:"clients_urls"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &document); err != nil {
				return nil, false, fmt.Errorf("the answer was not the documented shape")
			}
			names := []string{}
			for _, record := range append(document.Data.Employees, document.Data.Clients...) {
				parsed, err := url.Parse(record.URL)
				if err != nil {
					continue
				}
				if host := parsed.Hostname(); host != "" {
					names = append(names, host)
				}
			}
			return names, false, nil
		},
	},
}

// passiveHostnameInText finds hostnames in a plain page. It is deliberately the
// same shape the upstream source uses, and deliberately narrow: letters, digits,
// dots and dashes, so it cannot match a sentence.
var passiveHostnameInText = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}`)

// passiveIntelAgent прибрано разом із sitedossier 2026-10-03: він існував
// лише тому, що одне джерело відрізнялося від решти своїм клієнтом.

// passiveIntelEvidence is what one threat-intelligence index answered.
type passiveIntelEvidence struct {
	names map[string]bool
	read  int
	// foreign counts the names the zone filter rejected, so a source that
	// answers about somebody else's host is visible rather than silent.
	foreign int
}

// passiveIntelNames asks every threat-intelligence index about one zone.
//
// They are asked concurrently and independently: one index being down must not
// cost the others, and a source that did not answer is named in the report rather
// than folded into a result that looks complete.
func (s *server) passiveIntelNames(ctx context.Context, client *http.Client, zone string) (
	map[string]bool, map[string]int, []string) {
	found := map[string]bool{}
	counts := map[string]int{}
	notes := make([]string, 0, len(passiveIntelSources))

	var wait sync.WaitGroup
	var mutex sync.Mutex
	for _, source := range passiveIntelSources {
		wait.Add(1)
		go func(source passiveNameSource) {
			defer wait.Done()
			evidence, err := s.askPassiveIntel(ctx, client, source, zone)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				notes = append(notes, source.name+": "+err.Error())
				counts[source.name] = 0
				return
			}
			counts[source.name] = len(evidence.names)
			for name := range evidence.names {
				found[name] = true
			}
		}(source)
	}
	wait.Wait()
	sort.Strings(notes)
	return found, counts, notes
}

// askPassiveIntel queries one index and applies the zone filter to its answer.
func (s *server) askPassiveIntel(ctx context.Context, client *http.Client,
	source passiveNameSource, zone string) (passiveIntelEvidence, error) {
	evidence := passiveIntelEvidence{names: map[string]bool{}}
	// Three indexes, three organisations, three hosts. One override field would
	// be a lie about two of them, so the field is a **per source** map and the
	// test points every source at the same fixture.
	base := strings.TrimSuffix(strings.TrimSpace(s.passiveIntelBase[source.name]), "/")
	if base == "" {
		base = publicPassiveIntelBases[source.name]
	}
	method, endpoint, payload := source.build(base, zone)
	var reader io.Reader
	if payload != "" {
		reader = strings.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return evidence, fmt.Errorf("the request could not be built")
	}
	if payload != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	// sitedossier прибрано 2026-10-03 (див. список нижче): його більше не має
	// власного user agent, бо більше не є джерелом.
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
	response, err := client.Do(request)
	if err != nil {
		return evidence, fmt.Errorf("the index could not be asked: %s", identityErrorSummary(err))
	}
	defer response.Body.Close()
	body, readErr := readControlPlaneBody(response.Body)
	if readErr != nil {
		return evidence, fmt.Errorf("the answer could not be read")
	}
	if response.StatusCode == http.StatusTooManyRequests {
		return evidence, fmt.Errorf("the index refused the request, so its share of the result is " +
			"missing rather than empty")
	}
	if response.StatusCode != http.StatusOK {
		return evidence, errors.New("the index answered HTTP " + strconv.Itoa(response.StatusCode))
	}
	names, _, parseErr := source.parse(body)
	if parseErr != nil {
		return evidence, parseErr
	}
	evidence.read = len(names)
	for _, candidate := range names {
		host := normalizeGraphHostname(candidate)
		if host == "" || host == zone {
			continue
		}
		if !strings.HasSuffix(host, "."+zone) {
			evidence.foreign++
			continue
		}
		evidence.names[host] = true
	}
	return evidence, nil
}

// publicPassiveIntelBases is the measured host per source: three indexes, three
// organisations, three domains. One shared base would be a lie about two of them.
var publicPassiveIntelBases = map[string]string{
	"thc":        "https://ip.thc.org",
	"hudsonrock": "https://cavalier.hudsonrock.com",
}

// It answers `pdns_forward?domain=` with every record it has observed for a name
// — active **and** historical — which is why it is a subdomain source and not
// only a DNS one: for `pravda.ru` it returned `ns1.pravda.ru`, `ns2.pravda.ru`
// and `mx.pravda.ru`, and the first two were exactly the names the certificate
// indexes, the public page scans and DNS guessing all missed while subfinder
// found them. Historical names are the whole point: a decommissioned host leaves
// its MX and NS records behind, and those are still resolvable attack surface.
//
// The limit is real and is not hidden: the free tier is **ten requests per hour
// per IP**. A subdomain run asks this index once per zone, so a run fits, but a
// loop over zones does not — and a `429` is reported as a named warning with the
// limit, never as an empty answer.
const publicRobtex = "https://freeapi.robtex.com"

// robtexRateLimit is what the free tier allows, and what a `429` message has to
// say so the operator knows a refused request is a limit and not a finding.
const robtexRateLimit = "10 requests per hour per IP"

// robtexEvidence is what one passive-DNS query returned.
type robtexEvidence struct {
	names map[string]bool
	// historical counts the names the index reports as no longer active. They are
	// kept in the graph — a stale MX or NS host is still a hostname an operator
	// has to look at — but counted, so "found" and "still resolves" stay apart.
	historical int
	read       int
	foreign    int
}

// robtexForwardNames asks the passive-DNS index about one zone.
//
// Only names that really sit under the zone are taken. The index is keyed by an
// exact name, so unlike a substring-matching page-scan index it cannot answer
// about another zone — but its `rrname` values are lower-cased and carry a
// trailing dot on some record types, and a name that is not under the zone would
// be a claim about somebody else's host.
func (s *server) robtexForwardNames(ctx context.Context, client *http.Client, zone string) (robtexEvidence, error) {
	evidence := robtexEvidence{names: map[string]bool{}}
	base := strings.TrimSuffix(strings.TrimSpace(s.robtexBase), "/")
	if base == "" {
		base = publicRobtex
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/pdns_forward?domain="+url.QueryEscape(zone), nil)
	if err != nil {
		return evidence, transformError("ROBTEX_REQUEST_FAILED", err.Error())
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return evidence, transformError("ROBTEX_REQUEST_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return evidence, transformError("ROBTEX_RESPONSE_INVALID", "the passive-DNS response could not be read")
	}
	// The limit is a first-class answer, not an error to swallow: the run must
	// say "this source did not answer because the free tier is exhausted", which
	// is a different claim from "this source found nothing".
	if response.StatusCode == http.StatusTooManyRequests {
		return evidence, transformError("ROBTEX_RATE_LIMITED",
			"the free passive-DNS index allows "+robtexRateLimit+", and this run has used them; "+
				"the source was not read, so its share of the result is missing rather than empty")
	}
	if response.StatusCode != http.StatusOK {
		return evidence, transformError("ROBTEX_STATUS", fmt.Sprintf("the passive-DNS index answered HTTP %d", response.StatusCode))
	}
	var document struct {
		Status  string `json:"status"`
		Records []struct {
			Name    string `json:"rrname"`
			Type    string `json:"rrtype"`
			Data    string `json:"rrdata"`
			Last    int64  `json:"time_last"`
			Present bool   `json:"active"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return evidence, transformError("ROBTEX_RESPONSE_INVALID", "the passive-DNS response was not the documented shape")
	}
	evidence.read = len(document.Records)
	for _, record := range document.Records {
		// A passive-DNS answer carries the host in **two** places, and reading only
		// one of them is why the first run found nothing.
		//
		// `rrname` is the name the record is about — usually the zone itself when
		// the zone is queried, so it repeats the input. `rrdata` is where the
		// *value* lives, and for NS, MX and CNAME that value is a hostname. Those
		// are the names this source is for: on `pravda.ru` the index answered
		// `ns1.pravda.ru`, `ns2.pravda.ru`, `mail.pravda.ru` and `mx.pravda.ru`,
		// and the first two are exactly the ones the certificate indexes, the
		// public page scans and DNS guessing all missed while subfinder found
		// them — they are historical NS records, and no live index publishes what
		// is no longer assigned.
		//
		// A, AAAA and TXT records carry an address or a free-text value, so their
		// `rrdata` is not a name and is not read as one.
		for _, candidate := range robtexHostCandidates(record) {
			host := normalizeGraphHostname(candidate)
			if host == "" || host == zone {
				// The zone itself is what the operator already holds, and a name
				// source that returned it would make a domain look like its own
				// subdomain.
				continue
			}
			if !strings.HasSuffix(host, "."+zone) {
				evidence.foreign++
				continue
			}
			evidence.names[host] = true
		}
	}
	return evidence, nil
}

// robtexHostCandidates returns the hostnames one record contributes: the name it
// is about, plus — for the record types whose value is a host — the value.
//
// A and AAAA are excluded on purpose: their value is an address, and an address
// in the subdomain set is a type confusion rather than a discovery. PTR is
// excluded for the same reason in the other direction: its value is a name that
// lives somewhere else, and the zone filter would reject it anyway.
func robtexHostCandidates(record struct {
	Name    string `json:"rrname"`
	Type    string `json:"rrtype"`
	Data    string `json:"rrdata"`
	Last    int64  `json:"time_last"`
	Present bool   `json:"active"`
}) []string {
	candidates := []string{record.Name}
	switch strings.ToUpper(record.Type) {
	case "NS", "MX", "CNAME", "DNAME":
		// An MX value is `10 mail.example.com`; only the host is a name.
		if host := strings.TrimSpace(record.Data); host != "" {
			if fields := strings.Fields(host); len(fields) > 1 {
				candidates = append(candidates, fields[len(fields)-1])
			} else {
				candidates = append(candidates, host)
			}
		}
	}
	return candidates
}

// robtexEvidenceMetadata records what the passive-DNS index answered, so a run
// that got a thin result can say whether the source was thin or was refused.
func robtexEvidenceMetadata(metadata map[string]interface{}, evidence robtexEvidence) map[string]interface{} {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["robtex_names"] = len(evidence.names)
	metadata["robtex_records"] = evidence.read
	if evidence.foreign > 0 {
		metadata["robtex_outside_zone"] = evidence.foreign
	}
	return metadata
}

func urlscanEvidenceMetadata(metadata map[string]interface{}, evidence urlscanEvidence) map[string]interface{} {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["urlscan_names"] = len(evidence.names)
	metadata["urlscan_total"] = evidence.total
	metadata["urlscan_read"] = evidence.read
	if evidence.foreign > 0 {
		metadata["urlscan_outside_zone"] = evidence.foreign
	}
	return metadata
}

// urlscanSearch performs one page request against the public search API.
//
// The key is read from the environment when one is set and omitted when it is
// not: the endpoint answers an anonymous client, so demanding a key would make
// discovery useless on a fresh install for no gain.
func (s *server) urlscanSearch(ctx context.Context, client *http.Client, base, kind, target string, size int) ([]urlscanSearchResult, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/search/?"+url.Values{
		"q":    []string{kind + ":" + target},
		"size": []string{strconv.Itoa(size)},
	}.Encode(), nil)
	if err != nil {
		return nil, 0, transformError("URLSCAN_SEARCH_FAILED", err.Error())
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/json")
	if key := strings.TrimSpace(os.Getenv("URLSCAN_API_KEY")); key != "" {
		request.Header.Set("API-Key", key)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, transformError("URLSCAN_SEARCH_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, 0, transformError("URLSCAN_RESPONSE_INVALID", "the urlscan response could not be read")
	}
	if response.StatusCode == http.StatusTooManyRequests {
		// A rate limit is a request to come back, and it is reported as its own
		// condition because retrying it immediately is what turns one limit into a
		// refusal.
		return nil, 0, transformError("URLSCAN_RATE_LIMITED", "the public urlscan index is rate limiting this client")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, 0, transformError("URLSCAN_SEARCH_FAILED", fmt.Sprintf("urlscan returned HTTP %d", response.StatusCode))
	}
	var payload struct {
		Results []urlscanSearchResult `json:"results"`
		Total   int                   `json:"total"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return nil, 0, transformError("URLSCAN_RESPONSE_INVALID", "the urlscan response did not contain a search result")
	}
	return payload.Results, payload.Total, nil
}

// filescanVerdict is the public verdict one identity carries.
//
// `flagged` is the index's own word, not a conclusion of this transform. Measured
// 2026-09-28 on the live index: 8.8.8.8 answers `no_threat` with 207 reports
// marked `malicious`, and 1.1.1.1 answers `likely_malicious` with 436 of 500
// reports marked `likely_malicious`. So `overall_verdict` is the index's own
// aggregate and the report tally is a separate count, and a boolean derived from
// the counts would read as a contradiction next to the vendor's verdict.
type filescanVerdict struct {
	IOCType    string
	IOCValue   string
	Overall    string
	ScanTime   string
	Detected   *int
	Malicious  int
	Suspicious int
	Reports    int
}

func (v filescanVerdict) flagged() bool {
	switch strings.ToLower(v.Overall) {
	case "malicious", "likely_malicious", "suspicious":
		return true
	}
	return false
}

// properties renders the verdict as entity properties.
//
// A verdict is a claim about a host, not an observation of it, so it is stored on
// the identity and never turned into an edge: the graph stores observations, and
// this is somebody else's conclusion.
func (v filescanVerdict) properties() map[string]interface{} {
	return map[string]interface{}{
		"filescan_verdict":    v.Overall,
		"filescan_flagged":    v.flagged(),
		"filescan_reports":    v.Reports,
		"filescan_malicious":  v.Malicious,
		"filescan_suspicious": v.Suspicious,
		"filescan_scan_time":  v.ScanTime,
		"filescan_source":     "filescan_public_reputation",
	}
}

// filescanVerdicts reads the public reputation of a batch of identities in ONE
// request.
//
// The bulk endpoint is what makes this affordable and is also why no pool is
// needed: a domain that resolves to a dozen addresses is a dozen verdicts, and
// asking one by one would be a loop the operator has no way to size. The batch
// endpoint answers an anonymous client, verified live: `POST
// /api/reputation/<kind>` with a JSON list returns the same shape as the single
// lookup, one element per requested identity.
func (s *server) filescanVerdicts(ctx context.Context, client *http.Client, kind string, values []string) (map[string]filescanVerdict, error) {
	verdicts := map[string]filescanVerdict{}
	if len(values) == 0 {
		return verdicts, nil
	}
	base := strings.TrimSuffix(strings.TrimSpace(s.filescanBase), "/")
	if base == "" {
		base = publicFilescan
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/reputation/"+url.PathEscape(kind), strings.NewReader(mustJSON(values)))
	if err != nil {
		return verdicts, transformError("FILESCAN_LOOKUP_FAILED", err.Error())
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	// The vendor names its credential X-Api-Key. Sending it as the urlscan
	// header would look like it worked and be ignored.
	if key := strings.TrimSpace(os.Getenv("FILESCAN_API_KEY")); key != "" {
		request.Header.Set("X-Api-Key", key)
	}
	response, err := client.Do(request)
	if err != nil {
		return verdicts, transformError("FILESCAN_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return verdicts, transformError("FILESCAN_RESPONSE_INVALID", "the filescan response could not be read")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return verdicts, transformError("FILESCAN_LOOKUP_FAILED", fmt.Sprintf("filescan returned HTTP %d", response.StatusCode))
	}
	var payload []struct {
		IOCType  string `json:"ioc_type"`
		IOCValue string `json:"ioc_value"`
		Overall  string `json:"overall_verdict"`
		MDCloud  *struct {
			ScanTime string `json:"scan_time"`
			Detected *int   `json:"detected"`
		} `json:"mdcloud"`
		Reports []struct {
			Verdict string `json:"verdict"`
		} `json:"filescan_reports"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return verdicts, transformError("FILESCAN_RESPONSE_INVALID", "the filescan response did not contain reputation records")
	}
	for _, record := range payload {
		verdict := filescanVerdict{
			IOCType:  strings.TrimSpace(record.IOCType),
			IOCValue: strings.TrimSpace(record.IOCValue),
			Overall:  strings.TrimSpace(record.Overall),
			Reports:  len(record.Reports),
		}
		if record.MDCloud != nil {
			verdict.ScanTime = strings.TrimSpace(record.MDCloud.ScanTime)
			verdict.Detected = record.MDCloud.Detected
		}
		for _, report := range record.Reports {
			switch strings.ToLower(strings.TrimSpace(report.Verdict)) {
			case "malicious":
				verdict.Malicious++
			case "suspicious":
				verdict.Suspicious++
			}
		}
		verdicts[verdict.IOCValue] = verdict
	}
	return verdicts, nil
}

// mustJSON renders a value that cannot fail to encode: the batch body is a list
// of strings and nothing else.
func mustJSON(values []string) string {
	encoded, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// filescanReputation attaches the public verdicts to identities the run already
// produced, in place.
//
// The entities are not appended and the graph gains no new edge: the point is
// that an address a DNS lookup just produced also carries what a third party has
// published about it. An identity the index holds nothing for is left exactly as
// it was, because "no public record" and "not asked" must not look alike.
func filescanReputation(result *osintTransformResult, verdicts map[string]filescanVerdict, source string) int {
	if len(verdicts) == 0 {
		return 0
	}
	marked := 0
	for index := range result.Entities {
		item := &result.Entities[index]
		verdict, ok := verdicts[item.Identity]
		if !ok || verdict.Overall == "" {
			continue
		}
		if item.Properties == nil {
			item.Properties = map[string]interface{}{}
		}
		for key, value := range verdict.properties() {
			item.Properties[key] = value
		}
		if item.Provenance == nil {
			item.Provenance = map[string]interface{}{}
		}
		item.Provenance["filescan_ioc_type"] = verdict.IOCType
		marked++
	}
	if marked > 0 {
		setTransformMetadata(result, "filescan_"+source, marked)
	}
	return marked
}

// normalizeGraphHostname lowercases a host and drops a trailing root dot, so two
// spellings of the same name are one identity.
func normalizeGraphHostname(value string) string {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, "/ \t") {
		return ""
	}
	return host
}
