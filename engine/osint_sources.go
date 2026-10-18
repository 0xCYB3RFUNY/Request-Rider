package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Four public sources added to the transforms that already ask the same
// question. None of them is a new tool: each answers a question the graph
// already asks, from a different place, so it is read as a phase of the
// transform that owns the identity rather than as something an operator has to
// remember to run.
//
// All four answer an anonymous client. A key raises a rate limit on some of
// them, and where the environment supplies one it is sent; none of them is
// required, so a fresh install gets the same coverage.

// publicHackerTarget is the shared-hosting index. It answers with a plain list
// of names, one per line, with no envelope: that is its whole contract.
const publicHackerTarget = "https://api.hackertarget.com"

// publicPeeringDB publishes network records by ASN. It is a different
// organisation from the RIRs and from the route collectors, which is why its
// view of a network is worth having next to the address itself.
const publicPeeringDB = "https://www.peeringdb.com"

// publicAnnouncedPrefixes publishes the ranges an autonomous system announces.
// PeeringDB reports how many a network has and not which ones, and a count is
// not something a graph can pivot on, so the ranges come from the public BGP
// statistics service instead — a different organisation from both PeeringDB and
// the RIR, which is the reason its view is worth reading next to the operator.
const publicAnnouncedPrefixes = "https://stat.ripe.net"

// publicGCPBucketBase is the per-bucket Google Storage host `s3_buckets` asks when
// a 403 has to be told apart from "no such bucket". It is asked separately from the
// shared `storage.googleapis.com` endpoint because only this one can answer whether
// a name exists: the shared endpoint answers 403 for every name, measured 2026-10-02
// on `zzz-definitely-not-a-real-bucket-99887766`.
const publicGCPBucketBase = "https://storage.googleapis.com"

// publicRDAP is the bootstrap: it answers which registry serves a TLD and
// redirects there. Going through the bootstrap instead of hard-coding a
// registry per TLD is what keeps this correct for every TLD rather than the
// handful a table would have listed.
const publicRDAP = "https://rdap.org"

// coHostedNames is the number of names read from the shared-hosting index.
//
// It is one page of a newline list, so the bound is on the **response**, not on
// how many names exist: the index holds thousands for a busy address and every
// one of them is a real host. The value that was really read is reported as
// `reverse_ip_read`, and a truncated answer says so, because "this address
// hosts exactly these" and "these are the first N" are different claims.
const coHostedNames = 500

// sharedHostNames returns the names a public index has seen on one address.
//
// The question is "what else is on this address", and it is the strongest
// pivot a graph has against a shared host: a hundred names on one address is a
// hundred organisations, and the ones sharing infrastructure with a target are
// the ones worth reading. The answer is a neighbour list, not a proof of
// ownership, so every name is stored as its own identity and linked with
// `hosted_on` rather than claimed to belong to the queried host.
func (s *server) sharedHostNames(ctx context.Context, client *http.Client, address string) ([]string, string, error) {
	base := strings.TrimSuffix(strings.TrimSpace(s.sharedHostBase), "/")
	if base == "" {
		base = publicHackerTarget
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/reverseiplookup/?q="+urlQueryEscape(address), nil)
	if err != nil {
		return nil, "", transformError("REVERSE_IP_FAILED", err.Error())
	}
	request.Header.Set("User-Agent", indexUserAgent)
	if key := strings.TrimSpace(os.Getenv("HACKERTARGET_API_KEY")); key != "" {
		// The index reads its credential as an X-Api-Key and treats an
		// unrecognised one as anonymous, so sending nothing is also correct.
		request.Header.Set("X-Api-Key", key)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", transformError("REVERSE_IP_FAILED", err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", transformError("REVERSE_IP_FAILED", fmt.Sprintf("the shared-hosting index returned HTTP %d", response.StatusCode))
	}
	body, err := readBoundedTextBody(response.Body, coHostedNames*64)
	if err != nil {
		return nil, "", transformError("REVERSE_IP_RESPONSE_INVALID", "the shared-hosting answer could not be read")
	}
	names := make([]string, 0, 16)
	seen := map[string]bool{}
	truncated := false
	for _, line := range strings.Split(body, "\n") {
		candidate := strings.ToLower(strings.TrimSpace(strings.TrimRight(line, "\r")))
		if candidate == "" {
			continue
		}
		// The index answers a query it cannot serve with a sentence in the same
		// field the names use. Reading it as a hostname would put a sentence in
		// the graph, so anything that is not a storable host is refused.
		if !storableHostname(candidate) {
			if strings.Contains(candidate, " ") || strings.Contains(candidate, "api count") {
				// A quota note is a warning about the answer, not a failure of
				// the lookup, and it is stated so the operator knows the list is
				// short because the index stopped, not because the address is.
				return names, strings.TrimSpace(candidate), nil
			}
			continue
		}
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		names = append(names, candidate)
		if len(names) >= coHostedNames {
			truncated = true
			break
		}
	}
	if truncated {
		return names, fmt.Sprintf("read %d names; the address may host more", len(names)), nil
	}
	return names, "", nil
}

// domainRegistration is what a registry publishes about one domain.
//
// RDAP is the registry's own machine-readable answer, so this is a primary
// source: the registrar, the dates and the nameservers come from whoever holds
// the domain, not from somebody's summary of them.
type domainRegistration struct {
	Registrar   string
	Events      map[string]string
	Statuses    []string
	Nameservers []string
	Handle      string
}

// rdapDomain asks the bootstrap where a domain is registered and reads the
// registry's own answer.
func (s *server) rdapDomain(ctx context.Context, client *http.Client, domain string) (domainRegistration, error) {
	registration := domainRegistration{Events: map[string]string{}}
	// The bootstrap answers a redirect, and the client must not follow it with
	// POST semantics or a body; a plain GET is what it is given.
	bootstrap := strings.TrimSuffix(strings.TrimSpace(s.rdapBase), "/")
	if bootstrap == "" {
		bootstrap = publicRDAP
	}
	endpoint := bootstrap + "/domain/" + urlQueryEscape(domain)
	hops := 0
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return registration, transformError("RDAP_FAILED", err.Error())
		}
		request.Header.Set("User-Agent", indexUserAgent)
		request.Header.Set("Accept", "application/rdap+json, application/json")
		response, err := client.Do(request)
		if err != nil {
			return registration, transformError("RDAP_FAILED", err.Error())
		}
		if isRedirect(response.StatusCode) {
			location := response.Header.Get("Location")
			response.Body.Close()
			hops++
			// A redirect chain longer than this is a loop, not a bootstrap, and
			// following it further would keep the connection busy.
			if location == "" || hops > 4 {
				return registration, transformError("RDAP_FAILED", "the RDAP bootstrap did not reach a registry")
			}
			endpoint = location
			continue
		}
		defer response.Body.Close()
		body, err := readControlPlaneBody(response.Body)
		if err != nil {
			return registration, transformError("RDAP_RESPONSE_INVALID", "the registry answer could not be read")
		}
		if response.StatusCode == http.StatusNotFound {
			// A 404 from the **bootstrap** and a 404 from the **registry** are
			// different facts, and reading them as one produced a false claim.
			// Measured 2026-10-03: `rdap.org/domain/mail.ru` answers
			// `{"errorCode":404,"title":"No RDAP service is available for this
			// resource"}` — `.ru` simply has no RDAP service (the IANA bootstrap
			// registry lists none for `.ru`, `.io` or `.de`), and that answer is
			// permanent. It was reported as `RDAP_NOT_REGISTERED`, i.e. "the
			// registry holds no record of this domain", which is a statement about
			// the domain and is false: nobody asked a registry at all.
			//
			// So the first hop is the bootstrap and its 404 names the missing
			// service; every later hop is a registry and its 404 names the domain.
			if hops == 0 {
				return registration, transformError(
					"RDAP_UNSUPPORTED_TLD",
					"no RDAP service is published for this top-level domain, so there is no registration to read")
			}
			// The registry says it holds no such domain. That is an answer about
			// the name, and it is reported as an error only so the caller can say
			// it out loud rather than store a domain with no registration.
			return registration, transformError("RDAP_NOT_REGISTERED", "the registry holds no record of this domain")
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return registration, transformError("RDAP_FAILED", fmt.Sprintf("the registry returned HTTP %d", response.StatusCode))
		}
		var payload struct {
			Handle      string   `json:"handle"`
			Status      []string `json:"status"`
			Nameservers []struct {
				Host string `json:"ldhName"`
			} `json:"nameservers"`
			Events []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
			Entities []struct {
				Roles []string        `json:"roles"`
				Card  json.RawMessage `json:"vcardArray"`
			} `json:"entities"`
		}
		if decodeErr := json.Unmarshal(body, &payload); decodeErr != nil {
			return registration, transformError("RDAP_RESPONSE_INVALID", "the registry answer could not be read: "+decodeErr.Error())
		}
		registration.Handle = strings.TrimSpace(payload.Handle)
		registration.Statuses = payload.Status
		for _, event := range payload.Events {
			if event.Action != "" && event.Date != "" {
				registration.Events[event.Action] = event.Date
			}
		}
		for _, nameserver := range payload.Nameservers {
			if host := normalizeGraphHostname(nameserver.Host); host != "" {
				registration.Nameservers = append(registration.Nameservers, host)
			}
		}
		registration.Registrar = rdapEntityName(payload.Entities)
		return registration, nil
	}
}

// isRedirect reports whether a status is one a bootstrap legitimately uses.
func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound ||
		status == http.StatusSeeOther || status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect
}

// rdapEntityName picks the registrar out of the entities a registry publishes.
//
// The name lives inside `vcardArray`, a JSON array holding an object under
// `vcard` whose `fn` is the human name. Reading the whole array as a string is
// what a first version of this does, and it fails on the very first domain.
func rdapEntityName(entities []struct {
	Roles []string        `json:"roles"`
	Card  json.RawMessage `json:"vcardArray"`
}) string {
	for _, entity := range entities {
		isRegistrar := false
		for _, role := range entity.Roles {
			if strings.EqualFold(strings.TrimSpace(role), "registrar") {
				isRegistrar = true
			}
		}
		if !isRegistrar {
			continue
		}
		if name := vcardName(entity.Card); name != "" {
			return name
		}
	}
	return ""
}

// vcardName extracts `fn` from a jCard array as RDAP carries it.
//
// The field is a JSON **array**, not a string: declaring it as a string makes
// the whole answer fail to decode, which is what the first version did, and the
// error named nothing useful.
func vcardName(card json.RawMessage) string {
	if len(card) == 0 {
		return ""
	}
	var array []json.RawMessage
	if json.Unmarshal(card, &array) != nil || len(array) < 2 {
		return ""
	}
	// The jCard RDAP carries is `["vcard", [ [field...], ... ]]`: the second
	// element is the field list **itself**, not an object wrapping it. Decoding
	// it as an object finds no fields and reports an empty registrar for every
	// domain in the world.
	// A jCard field is `[name, parameters, type, value]`, and the parameters slot
	// holds `{}` — an **object**. A `[][]string` decoder therefore refuses the
	// whole answer, and a decoder that skips that slot by type finds no name.
	var fields [][]interface{}
	if json.Unmarshal(array[1], &fields) != nil {
		// Some registries wrap the list in an object instead; both are read, and
		// neither makes the whole answer fail.
		var wrapped struct {
			Fields [][]interface{} `json:"vcard"`
		}
		if json.Unmarshal(array[1], &wrapped) != nil {
			return ""
		}
		fields = wrapped.Fields
	}
	for _, field := range fields {
		if len(field) < 4 {
			continue
		}
		name, nameOK := field[0].(string)
		value, valueOK := field[3].(string)
		if nameOK && valueOK && strings.EqualFold(name, "fn") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// networkOperator is what a public network record says about an ASN.
type networkOperator struct {
	Name         string
	Website      string
	Prefixes4    int
	Prefixes6    int
	IXCount      int
	PolicyURL    string
	TrafficRatio string
	Country      string
}

func asnNumber(value string) string {
	trimmed := strings.ToUpper(strings.TrimSpace(value))
	trimmed = strings.TrimPrefix(trimmed, "AS")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return ""
	}
	number, err := strconv.Atoi(trimmed)
	if err != nil || number <= 0 {
		return ""
	}
	return "AS" + strconv.Itoa(number)
}

// asnOperator asks the public network record for who announces an ASN.
func (s *server) asnOperator(ctx context.Context, client *http.Client, asn string) (networkOperator, error) {
	operator := networkOperator{}
	normalized := asnNumber(asn)
	if normalized == "" {
		return operator, transformError("INVALID_ASN", "the autonomous system number is not a number")
	}
	base := strings.TrimSuffix(strings.TrimSpace(s.networkRecordBase), "/")
	if base == "" {
		base = publicPeeringDB
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/net?asn="+urlQueryEscape(strings.TrimPrefix(normalized, "AS")), nil)
	if err != nil {
		return operator, transformError("ASN_LOOKUP_FAILED", err.Error())
	}
	request.Header.Set("User-Agent", indexUserAgent)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return operator, transformError("ASN_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return operator, transformError("ASN_LOOKUP_FAILED", fmt.Sprintf("the network record returned HTTP %d", response.StatusCode))
	}
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return operator, transformError("ASN_RESPONSE_INVALID", "the network record could not be read")
	}
	var payload struct {
		Data []struct {
			Name         string `json:"name"`
			Website      string `json:"website"`
			Prefixes4    int    `json:"info_prefixes4"`
			Prefixes6    int    `json:"info_prefixes6"`
			IXCount      int    `json:"ix_count"`
			PolicyURL    string `json:"policy_url"`
			TrafficRatio string `json:"info_traffic"`
			Country      string `json:"info_country"`
			Whois        string `json:"whois"`
		} `json:"data"`
	}
	// This endpoint answers a bare list, not an envelope, so a decoder that
	// expects `data` reads an empty record and reports "no operator" for a
	// network that has one.
	if json.Unmarshal(body, &payload) != nil || len(payload.Data) == 0 {
		var records []struct {
			Name         string `json:"name"`
			Website      string `json:"website"`
			Prefixes4    int    `json:"info_prefixes4"`
			Prefixes6    int    `json:"info_prefixes6"`
			IXCount      int    `json:"ix_count"`
			PolicyURL    string `json:"policy_url"`
			TrafficRatio string `json:"info_traffic"`
			Country      string `json:"info_country"`
		}
		if json.Unmarshal(body, &records) != nil || len(records) == 0 {
			return operator, transformError("ASN_RESPONSE_INVALID", "the network record did not contain a network")
		}
		operator = networkOperator{
			Name: records[0].Name, Website: records[0].Website,
			Prefixes4: records[0].Prefixes4, Prefixes6: records[0].Prefixes6,
			IXCount: records[0].IXCount, PolicyURL: records[0].PolicyURL,
			TrafficRatio: records[0].TrafficRatio, Country: records[0].Country,
		}
		return operator, nil
	}
	record := payload.Data[0]
	operator = networkOperator{
		Name: record.Name, Website: record.Website,
		Prefixes4: record.Prefixes4, Prefixes6: record.Prefixes6,
		IXCount: record.IXCount, PolicyURL: record.PolicyURL,
		TrafficRatio: record.TrafficRatio, Country: record.Country,
	}
	return operator, nil
}

// readBoundedTextBody reads a text answer up to a limit and reports when the
// limit was reached, so a caller can say the answer was short instead of
// pretending it was complete.
//
// The control-plane bound is deliberately not reused here: a shared-hosting
// index answers a newline list measured in tens of kilobytes for a busy
// address, and a bound sized for a JSON API object would cut it in half.
func readBoundedTextBody(body io.Reader, limit int) (string, error) {
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return "", err
	}
	if len(data) > limit {
		return "", fmt.Errorf("the answer is longer than the %d byte bound", limit)
	}
	return string(data), nil
}

// originASNs returns the autonomous systems that originate an address.
//
// The BGP origin is published as a text record by Team Cymru under
// `<reversed-address>.origin.asn.cymru.com`, and the reply is one line:
// `15169 | 8.8.8.0/24 | US | arin | 1992-12-01`. It is asked as a DNS question
// on purpose: a routed run cannot open an arbitrary HTTP connection to a
// third-party whois service, because a relay refuses port 53 but allows 443,
// and a whois-over-HTTP service is not what this is. A name the database has
// never heard of answers NXDOMAIN, which is a fact about the address and not a
// failure, so the empty answer is silent and only a real error is reported.
func originASNs(ctx context.Context, resolver routeResolver, address string) ([]string, error) {
	parsed := net.ParseIP(strings.TrimSpace(address))
	if parsed == nil {
		return nil, nil
	}
	labels := reverseDomainName(parsed.String())
	if labels == "" {
		return nil, nil
	}
	base := strings.TrimSuffix(labels, ".in-addr.arpa")
	if base == labels {
		base = strings.TrimSuffix(labels, ".ip6.arpa")
	}
	records, err := resolver.lookupTXT(ctx, base+".origin.asn.cymru.com")
	if err != nil {
		return nil, err
	}
	asns := make([]string, 0, len(records))
	for _, record := range records {
		// The first field is the origin ASN. The rest describes the prefix, and
		// reading field three as the ASN would attribute a country to a network.
		fields := strings.Split(record, "|")
		if len(fields) == 0 {
			continue
		}
		if asn := asnNumber(fields[0]); asn != "" {
			asns = append(asns, asn)
		}
	}
	return asns, nil
}
