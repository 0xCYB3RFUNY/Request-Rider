package main

// Three transforms for the entity kinds that had none.
//
// Measured 2026-10-02: `cidr`, `asn` and `technology` accepted zero transforms,
// so three of the nine kinds the graph can store had an empty context menu and the
// operator was told so in the add-entity dialog. That was a real gap, and it was
// reported as an open question for the owner rather than filled in, because
// inventing a transform is a decision about what the tool means. The owner closed
// it by asking for the gap to be closed, and this file is the answer.
//
// Each transform does the thing the kind is actually for, and nothing else:
//
//   - `cidr_range` enumerates the addresses of a range and asks each one for its
//     PTR names, which is what a range is asked for. It refuses to enumerate an
//     unbounded prefix by asking the operator for an explicit address budget, so
//     the cost of the run is a stated number rather than a surprise.
//   - `asn_lookup` asks the public network record for an autonomous system and
//     adds the operator, the prefixes it announces and the addresses inside the
//     prefixes that resolve. The record reader already existed, used by
//     `dns_records`; this makes it reachable from an ASN node, which is where an
//     operator reads it from.
//   - `technology_probe` fetches a host the technology was seen on and reports
//     whether that technology is still announced by the server, so a stack entry
//     from a month ago is either confirmed against the live host or marked stale.
//
// The rules that apply to every transform in this project are kept literally: no
// hidden cap, a limit only where the operator can see and raise it, a partial
// result kept with warnings rather than discarded, and an empty answer that names
// what was asked instead of reading as success.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// cidrRangeDefaultAddresses is the address budget a range enumeration runs with
// when the operator names none. It is a default with a name and a reportable
// field, not a ceiling: `max_addresses` in the request overrides it, and the
// panel shows what was asked for.
const cidrRangeDefaultAddresses = 256

// asnLookupDefaultPrefixes is how many announced prefixes one ASN run walks when
// the operator names no budget.
//
// It exists because the run is otherwise unbounded, which is not a slow tool but an
// unstoppable one: `AS12389` announces 3307 prefixes, and each is walked up to
// `cidrRangeDefaultAddresses` reverse lookups, so a single click could queue up to
// 845 792 of them with no field to stop it and nothing in the result saying the run
// stopped early. The budget is a default the operator can raise through
// `max_prefixes`, and the truncation is reported, so it is a number they chose
// rather than a limit that happened to them.
const asnLookupDefaultPrefixes = 24

// cidrRangeHardCeiling exists so a mistyped /8 cannot start an unbounded walk on
// one keystroke. It is far above the default and it is reported when it bites,
// so the operator sees that the answer is a slice of the range rather than a
// silent truncation.
const cidrRangeHardCeiling = 65536

// runCIDRRange reports the addresses inside a range and the names they answer
// with. A range is the one kind whose useful answer is a set rather than a single
// identity, so this is the only transform that can return many rows of one kind.
func (s *server) runCIDRRange(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "a range lookup performs reverse DNS queries")
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(input.Value))
	if err != nil {
		return transformError("INVALID_CIDR", "the value is not a CIDR range")
	}
	result.LocalOnly, result.NetworkUsed = false, true
	canonical := network.String()
	result.Entities = append(result.Entities, entity("cidr", canonical, map[string]interface{}{
		"prefix_length":   prefixLength(network),
		"total_addresses": addressTotal(network),
	}, map[string]interface{}{"source": "transform_input"}))

	budget := cidrRangeDefaultAddresses
	if requested := intOption(input.Options, "max_addresses"); requested > 0 {
		budget = requested
	}
	if budget > cidrRangeHardCeiling {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"the requested budget of %d addresses was reduced to %d for this run; the range itself holds %d",
			budget, cidrRangeHardCeiling, addressTotal(network)))
		budget = cidrRangeHardCeiling
	}

	total := addressTotal(network)
	if total > int64(budget) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s holds %d addresses and this run asked the resolver about the first %d; raise max_addresses to cover the rest",
			canonical, total, budget))
	}

	client := s.toolClient(ctx)
	routed := resolverForContext(ctx, client, s)
	asked, named := 0, 0
	// The first and last address of a range are that range's own network and
	// broadcast addresses: a PTR lookup on either asks about the prefix, not about a
	// host, and a range of eight that answers with eight rows overstates what was
	// checked. /31 and /32 are the exception and have no such pair — RFC 3021 gives
	// /31 two usable addresses and /32 one — so nothing is skipped there.
	skipEdges := prefixLength(network) < 31
	last := rangeLastAddress(network)
	for address := network.IP.Mask(network.Mask); asked < budget; address = nextAddress(address, network) {
		if !network.Contains(address) {
			break
		}
		if skipEdges && (address.Equal(network.IP.Mask(network.Mask)) || address.Equal(last)) {
			continue
		}
		// Every address is a pause point and a progress tick: a range is the
		// longest loop in the tool, and a paused job has to be able to stop.
		if collector != nil {
			if err := collector.checkpoint(ctx); err != nil {
				return err
			}
		}
		asked++
		canonicalAddress := address.String()
		names, err := routed.lookupHostReverse(ctx, canonicalAddress)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("reverse DNS of %s: %s", canonicalAddress, err.Error()))
			continue
		}
		if len(names) == 0 {
			// No PTR is itself the answer: the address exists and answers, and
			// nothing claims it. It is recorded, and the absence is stated once
			// rather than dropped, because a dropped row reads as "not asked".
			result.Entities = append(result.Entities, entity("ip", canonicalAddress,
				map[string]interface{}{"ptr_names": 0},
				map[string]interface{}{"source": "cidr_range"}))
			result.Relations = append(result.Relations, transformRelation{
				Type: "contains", SourceType: "cidr", Source: canonical,
				TargetType: "ip", Target: canonicalAddress,
				Provenance: map[string]interface{}{"source": "cidr_range"},
			})
			continue
		}
		result.Entities = append(result.Entities, entity("ip", canonicalAddress,
			map[string]interface{}{"ptr_names": len(names)},
			map[string]interface{}{"source": "cidr_range"}))
		result.Relations = append(result.Relations, transformRelation{
			Type: "contains", SourceType: "cidr", Source: canonical,
			TargetType: "ip", Target: canonicalAddress,
			Provenance: map[string]interface{}{"source": "cidr_range"},
		})
		for _, name := range names {
			host := strings.TrimSuffix(strings.ToLower(name), ".")
			if host == "" {
				continue
			}
			result.Entities = append(result.Entities, entity("domain", host,
				map[string]interface{}{"from_ptr_of": canonicalAddress},
				map[string]interface{}{"source": "cidr_range"}))
			result.Relations = append(result.Relations, transformRelation{
				Type: "resolves_to", SourceType: "domain", Source: host,
				TargetType: "ip", Target: canonicalAddress,
				Provenance: map[string]interface{}{"source": "cidr_range"},
			})
			named++
		}
	}
	setTransformMetadata(result, "cidr_addresses_asked", asked)
	setTransformMetadata(result, "cidr_addresses_total", total)
	setTransformMetadata(result, "cidr_names_found", named)
	setTransformMetadata(result, "cidr_budget", budget)
	return nil
}

// rangeLastAddress returns the last address of a range: the base with every bit
// the mask leaves free set.
//
// The earlier form walked backwards from the candidate and asked whether the
// previous address was still inside the range, which answers a different question
// and let the broadcast address itself through. Setting the host bits is the
// definition, and it stays correct for IPv6, where the arithmetic that adds one
// overflows a machine word.
func rangeLastAddress(network *net.IPNet) net.IP {
	last := make(net.IP, len(network.IP))
	for index := range network.IP {
		last[index] = network.IP[index] | ^network.Mask[index]
	}
	return last
}

// prefixLength reports how many bits of the address the mask fixes.
func prefixLength(network *net.IPNet) int {
	ones, _ := network.Mask.Size()
	return ones
}

// addressTotal reports how many addresses the range holds, which is what the
// operator compares the budget against.
func addressTotal(network *net.IPNet) int64 {
	ones, bits := network.Mask.Size()
	if ones < 0 {
		return 0
	}
	return int64(1) << uint(bits-ones)
}

// nextAddress returns the address one above the given one, staying inside the
// range's family. It returns the input unchanged when the family is exhausted,
// which the caller's containment check turns into the end of the walk.
func nextAddress(address net.IP, _ *net.IPNet) net.IP {
	next := make(net.IP, len(address))
	copy(next, address)
	for index := len(next) - 1; index >= 0; index-- {
		next[index]++
		if next[index] != 0 {
			break
		}
	}
	return next
}

// intOption reads one integer option, answering zero when it is absent or not a
// number. Both numeric shapes are accepted on purpose: a value that arrived as
// JSON is a float64, while a value passed in-process is an int. Reading only one
// of them makes the budget a default that silently ignores whatever the caller
// asked for — which is exactly the hidden cap this project's rules forbid.
func intOption(options map[string]interface{}, key string) int {
	switch value := options[key].(type) {
	case float64:
		if value > 0 {
			return int(value)
		}
	case float32:
		if value > 0 {
			return int(value)
		}
	case int:
		if value > 0 {
			return value
		}
	case int64:
		if value > 0 {
			return int(value)
		}
	case json.Number:
		if parsed, err := value.Int64(); err == nil && parsed > 0 {
			return int(parsed)
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && parsed > 0 {
			return parsed
		}
	}
	return 0
}

// runASNLookup answers an autonomous system with its public network record: who
// announces it, what they announce, and which of those addresses resolve.
//
// The reader already existed for `dns_records`, which reaches an ASN only after
// resolving a domain first. An ASN node is a place an operator arrives from a
// routing table or a leaked config, so the same reader is exposed here rather
// than asked to be reached through a domain.
func (s *server) runASNLookup(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "an autonomous system lookup queries a public network record")
	}
	normalized := asnNumber(strings.TrimSpace(input.Value))
	if normalized == "" {
		return transformError("INVALID_ASN", "the autonomous system number is not a number")
	}
	result.LocalOnly, result.NetworkUsed = false, true
	client := s.toolClient(ctx)

	operator, err := s.asnOperator(ctx, client, normalized)
	if err != nil {
		// The record refused. The autonomous system itself is still a real
		// identity, so it stays in the graph with the refusal named, instead of
		// a run that ends with nothing at all.
		result.Warnings = append(result.Warnings, err.Error())
		result.Entities = append(result.Entities, entity("asn", normalized,
			map[string]interface{}{"record": "unavailable"},
			map[string]interface{}{"source": "peeringdb_network_record"}))
		return nil
	}
	properties := map[string]interface{}{"source": "peeringdb_network_record"}
	if operator.Name != "" {
		properties["operator"] = operator.Name
	}
	if operator.Website != "" {
		properties["website"] = operator.Website
	}
	if operator.Country != "" {
		properties["country"] = operator.Country
	}
	if operator.PolicyURL != "" {
		properties["policy_url"] = operator.PolicyURL
	}
	if operator.IXCount > 0 {
		properties["ix_count"] = operator.IXCount
	}
	result.Entities = append(result.Entities, entity("asn", normalized, properties,
		map[string]interface{}{"source": "peeringdb_network_record"}))

	// PeeringDB publishes how many prefixes a network announces, not which
	// ones, so the ranges come from the public BGP record that does list them.
	// A count without the list would leave the ASN node with a number the
	// operator cannot pivot on.
	prefixes, prefixErr := s.asnAnnouncedPrefixes(ctx, client, normalized)
	if prefixErr != nil {
		result.Warnings = append(result.Warnings, "announced prefixes: "+prefixErr.Error())
	}
	setTransformMetadata(result, "asn_prefixes_declared", operator.Prefixes4+operator.Prefixes6)
	if len(prefixes) == 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"the public BGP record lists no prefix for %s, so the node carries the operator and no range", normalized))
		setTransformMetadata(result, "asn_prefixes", 0)
		return nil
	}
	routed := resolverForContext(ctx, client, s)
	// One budget for the whole run, not one per prefix. A budget that restarts for
	// every prefix is a budget that does not bound anything: it is multiplied by the
	// prefix count, and the operator's number is no longer the number that applies.
	prefixBudget := asnLookupDefaultPrefixes
	if requested := intOption(input.Options, "max_prefixes"); requested > 0 {
		prefixBudget = requested
	}
	walked := prefixes
	if len(walked) > prefixBudget {
		walked = walked[:prefixBudget]
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s announces %d prefixes and this run walked the first %d; raise max_prefixes to cover the rest",
			normalized, len(prefixes), prefixBudget))
	}
	for _, prefix := range walked {
		if err := s.collectASNPrefix(ctx, result, routed, normalized, prefix, collector, input.Options); err != nil {
			return err
		}
	}
	setTransformMetadata(result, "asn_prefixes", len(walked))
	setTransformMetadata(result, "asn_prefixes_available", len(prefixes))
	setTransformMetadata(result, "asn_prefix_budget", prefixBudget)
	return nil
}

// asnAnnouncedPrefixes reads the ranges an autonomous system announces from the
// public BGP statistics service, which publishes them as a list rather than a
// count.
func (s *server) asnAnnouncedPrefixes(ctx context.Context, client *http.Client, asn string) ([]string, error) {
	base := strings.TrimSuffix(strings.TrimSpace(s.announcedPrefixBase), "/")
	if base == "" {
		base = publicAnnouncedPrefixes
	}
	resource := strings.TrimPrefix(asnNumber(asn), "AS")
	target := base + "/data/announced-prefixes/data.json?resource=AS" + urlQueryEscape(resource)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, transformError("ASN_PREFIX_LOOKUP_FAILED", err.Error())
	}
	request.Header.Set("User-Agent", indexUserAgent)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, transformError("ASN_PREFIX_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, transformError("ASN_PREFIX_LOOKUP_FAILED",
			fmt.Sprintf("the BGP record returned HTTP %d", response.StatusCode))
	}
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, transformError("ASN_RESPONSE_INVALID", "the BGP record could not be read")
	}
	var payload struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return nil, transformError("ASN_RESPONSE_INVALID", "the BGP record did not carry a prefix list")
	}
	prefixes := make([]string, 0, len(payload.Data.Prefixes))
	seen := map[string]bool{}
	for _, entry := range payload.Data.Prefixes {
		canonical := strings.TrimSpace(entry.Prefix)
		if canonical == "" || seen[canonical] {
			continue
		}
		seen[canonical] = true
		prefixes = append(prefixes, canonical)
	}
	sort.Strings(prefixes)
	return prefixes, nil
}

// collectASNPrefix adds one announced prefix and the addresses inside it that
// resolve, so the ASN node carries the range rather than a number.
func (s *server) collectASNPrefix(ctx context.Context, result *osintTransformResult, routed routeResolver, asn, prefix string, collector *transformCollector, options map[string]interface{}) error {
	_, network, err := net.ParseCIDR(strings.TrimSpace(prefix))
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("the network record lists %q, which is not a CIDR range", prefix))
		return nil
	}
	canonical := network.String()
	result.Entities = append(result.Entities, entity("cidr", canonical,
		map[string]interface{}{"announced_by": asn, "prefix_length": prefixLength(network)},
		map[string]interface{}{"source": "peeringdb_network_record"}))
	result.Relations = append(result.Relations, transformRelation{
		Type: "contains", SourceType: "asn", Source: asn,
		TargetType: "cidr", Target: canonical,
		Provenance: map[string]interface{}{"source": "peeringdb_network_record"},
	})

	// A /24 is asked; a /16 is not walked address by address. The budget is the
	// same one the range transform uses and is reported, and a prefix larger than
	// the budget is recorded with its addresses unknown rather than partially
	// filled with whichever addresses happened to come first.
	budget := cidrRangeDefaultAddresses
	if requested := intOption(options, "max_addresses"); requested > 0 {
		budget = requested
	}
	total := addressTotal(network)
	asked := 0
	for address := network.IP.Mask(network.Mask); asked < budget; address = nextAddress(address, network) {
		if !network.Contains(address) {
			break
		}
		if collector != nil {
			if err := collector.checkpoint(ctx); err != nil {
				return err
			}
		}
		asked++
		canonicalAddress := address.String()
		names, err := routed.lookupHostReverse(ctx, canonicalAddress)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("reverse DNS of %s: %s", canonicalAddress, err.Error()))
			continue
		}
		if len(names) == 0 {
			continue
		}
		result.Entities = append(result.Entities, entity("ip", canonicalAddress,
			map[string]interface{}{"ptr_names": len(names), "announced_by": asn},
			map[string]interface{}{"source": "peeringdb_network_record"}))
		for _, name := range names {
			host := strings.TrimSuffix(strings.ToLower(name), ".")
			if host == "" {
				continue
			}
			result.Entities = append(result.Entities, entity("domain", host,
				map[string]interface{}{"from_ptr_of": canonicalAddress},
				map[string]interface{}{"source": "peeringdb_network_record"}))
			result.Relations = append(result.Relations, transformRelation{
				Type: "resolves_to", SourceType: "domain", Source: host,
				TargetType: "ip", Target: canonicalAddress,
				Provenance: map[string]interface{}{"source": "peeringdb_network_record"},
			})
		}
	}
	if total > int64(asked) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s holds %d addresses and this run asked the resolver about %d of them; raise max_addresses to cover the rest",
			canonical, total, asked))
	}
	return nil
}

// technologySignature is one technology the page admits to, and where the
// admission came from. The source is kept because "the server said so in a
// header" and "a file on the page was named this" are different strengths of
// evidence, and a graph that flattens them cannot answer which one a finding rests on.
type technologySignature struct {
	name   string
	source string
}

// technologyHeaderSignatures are the headers that name a technology outright.
// The values are prefixes of what the products send, matched case-insensitively,
// because the versions change and the product name does not.
var technologyHeaderSignatures = []technologySignature{
	{name: "nginx", source: "header:server"},
	{name: "apache", source: "header:server"},
	{name: "caddy", source: "header:server"},
	{name: "cloudflare", source: "header:server"},
	{name: "microsoft-iis", source: "header:server"},
	{name: "litespeed", source: "header:server"},
	{name: "jetty", source: "header:server"},
	{name: "gunicorn", source: "header:server"},
	{name: "openresty", source: "header:server"},
}

// technologyCookieSignatures are cookies whose name only a specific product sets.
// A cookie is a strong admission: the server chose to send it.
var technologyCookieSignatures = []technologySignature{
	{name: "phpsessid", source: "cookie"},
	{name: "wordpress_logged_in", source: "cookie"},
	{name: "joomla_user_state", source: "cookie"},
	{name: "csrfmiddlewaretoken", source: "cookie"},
	{name: "laravel_session", source: "cookie"},
	{name: "asp.net_sessionid", source: "cookie"},
	{name: "jsessionid", source: "cookie"},
}

// runTechnologyProbe re-checks a technology against the host it was seen on.
//
// A stack entry is a claim about a host at a moment in time, and hosts change.
// Fetching the host again and reporting what the live answer says is the
// difference between a graph that holds a record and one that holds a fact: the
// transform either confirms the technology, reports that it is no longer
// announced, or reports that the host could not be read — and it never reports
// success for a question it did not ask.
func (s *server) runTechnologyProbe(ctx context.Context, result *osintTransformResult, input osintTransformInput, _ *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "a technology probe fetches the host")
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return transformError("INVALID_TECHNOLOGY", "the technology and its host are required")
	}
	host, name, err := splitTechnologyProbe(value)
	if err != nil {
		return err
	}
	result.LocalOnly, result.NetworkUsed = false, true

	// The host has to be a host, not whatever the operator typed into a field
	// labelled as a technology. A technology with no host cannot be probed, and
	// the operator is told to run the stack probe from a host node instead.
	if strings.ContainsAny(host, " /?#@") || net.ParseIP(host) == nil && !strings.Contains(host, ".") {
		return transformError("INVALID_TECHNOLOGY", "the probe needs a host and a technology, for example nginx and www.example.test")
	}
	canonicalHost := strings.ToLower(strings.TrimSuffix(host, "."))

	client := s.toolClient(ctx)
	for _, scheme := range []string{"https", "http"} {
		target := scheme + "://" + canonicalHost
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		request.Header.Set("User-Agent", indexUserAgent)
		request.Header.Set("Accept", "text/html,application/xhtml+xml")
		// A redirect to another host would answer a different question than the
		// one the operator asked, so the probe does not follow one.
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		response, err := client.Do(request)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s over %s: %s", canonicalHost, scheme, err.Error()))
			continue
		}
		body, readErr := readControlPlaneBody(response.Body)
		response.Body.Close()
		if readErr != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s over %s answered with a body that could not be read: %s", canonicalHost, scheme, readErr.Error()))
			continue
		}
		found, evidence := technologyEvidence(
			response.Header.Get("Server"),
			response.Header.Get("X-Powered-By"),
			response.Header.Get("Set-Cookie"),
			body,
		)
		setTransformMetadata(result, "technology_probe_status", response.StatusCode)
		if _, announced := found[name]; !announced {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"%s answered over %s and no longer announces %s", canonicalHost, scheme, name))
			result.Entities = append(result.Entities, entity("technology", name,
				map[string]interface{}{"status": "not_announced", "host": canonicalHost, "scheme": scheme},
				map[string]interface{}{"source": "host_probe"}))
			result.Relations = append(result.Relations, transformRelation{
				Type: "uses", SourceType: "domain", Source: canonicalHost,
				TargetType: "technology", Target: name,
				Provenance: map[string]interface{}{"source": "host_probe"},
			})
			return nil
		}
		result.Entities = append(result.Entities, entity("technology", name,
			map[string]interface{}{"status": "announced", "host": canonicalHost, "scheme": scheme,
				"evidence": strings.Join(evidence, ", "), "evidence_count": len(evidence)},
			map[string]interface{}{"source": "host_probe"}))
		result.Entities = append(result.Entities, entity("domain", canonicalHost, nil,
			map[string]interface{}{"source": "host_probe"}))
		result.Relations = append(result.Relations, transformRelation{
			Type: "uses", SourceType: "domain", Source: canonicalHost,
			TargetType: "technology", Target: name,
			Provenance: map[string]interface{}{"source": "host_probe"},
		})
		setTransformMetadata(result, "technology_evidence", strings.Join(evidence, ", "))
		setTransformMetadata(result, "technology_status", "announced")
		return nil
	}
	result.Warnings = append(result.Warnings, fmt.Sprintf(
		"%s could not be read on either scheme, so the technology was not checked", canonicalHost))
	result.Entities = append(result.Entities, entity("technology", name,
		map[string]interface{}{"status": "unverified", "host": canonicalHost},
		map[string]interface{}{"source": "host_probe"}))
	return nil
}

// splitTechnologyProbe reads the "technology on host" value. Both orders are
// accepted because the operator writes it the way it reads in their head, and
// guessing wrong would probe the technology name as a host.
func splitTechnologyProbe(value string) (string, string, error) {
	if index := strings.Index(value, "@"); index > 0 {
		return value[index+1:], strings.ToLower(value[:index]), nil
	}
	if index := strings.Index(value, "/"); index > 0 {
		return value[:index], strings.ToLower(value[index+1:]), nil
	}
	parts := strings.Fields(value)
	if len(parts) == 2 {
		return strings.ToLower(parts[1]), strings.ToLower(parts[0]), nil
	}
	return "", "", transformError("INVALID_TECHNOLOGY", "the probe needs a host and a technology, for example nginx@www.example.test")
}

// technologyEvidence reports which technologies the live answer admits to, and
// for each one where the admission came from. The headers and the body are
// passed as the values the response actually carried, because a header a server
// does not send must not read as an empty match rather than as no admission.
func technologyEvidence(server, poweredBy, cookies string, body []byte) (map[string]string, []string) {
	found := map[string]string{}
	evidence := []string{}
	record := func(signature technologySignature) {
		if _, seen := found[signature.name]; seen {
			return
		}
		found[signature.name] = signature.source
		evidence = append(evidence, signature.source)
	}
	serverHeader := strings.ToLower(server)
	for _, signature := range technologyHeaderSignatures {
		if strings.Contains(serverHeader, signature.name) {
			record(signature)
		}
	}
	loweredPoweredBy := strings.ToLower(poweredBy)
	if loweredPoweredBy != "" {
		for _, signature := range technologyHeaderSignatures {
			if strings.Contains(loweredPoweredBy, signature.name) {
				record(technologySignature{name: signature.name, source: "header:x-powered-by"})
			}
		}
	}
	loweredCookies := strings.ToLower(cookies)
	for _, signature := range technologyCookieSignatures {
		if strings.Contains(loweredCookies, signature.name) {
			record(signature)
		}
	}
	lowered := strings.ToLower(string(body))
	for _, signature := range []technologySignature{
		{name: "wordpress", source: "wp-content"},
		{name: "joomla", source: "/components/com_"},
		{name: "react", source: "data-reactroot"},
		{name: "vue", source: "data-v-"},
		{name: "next.js", source: "__next_data__"},
		{name: "drupal", source: "drupal-settings-json"},
	} {
		if strings.Contains(lowered, signature.source) {
			record(technologySignature{name: signature.name, source: "body:" + signature.source})
		}
	}
	return found, evidence
}
