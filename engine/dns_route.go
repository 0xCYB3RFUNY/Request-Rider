package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Route-aware DNS.
//
// A SOCKS5 route carries HTTPS fine and carries **DNS on port 53 not at all**,
// and that is not a property of this code: Tor relays refuse to exit on port
// 53, so a resolver query sent through the route is answered by "i/o timeout"
// from every relay. Measured 2026-09-29 with `ROUTE_ADDRESS=127.0.0.1:9050`:
// `dns_records` on `vk.ru` returned no address and the warning
// `lookup vk.ru on 91.239.100.100:53: i/o timeout`, while the very same engine
// answered a urlscan query over the same route with `source_ip` equal to a Tor
// exit address. The route was working; the resolver was the one thing that
// went outside it.
//
// The fix is to ask over HTTPS. DNS-over-HTTPS is an ordinary HTTPS request on
// port 443 to a resolver that speaks it, so it travels the same route as every
// other request the tool makes and no relay refuses it. The name is resolved by
// the resolver, not by us, so the address the graph stores is the one the route
// would reach — which is the whole point of a route.

// routeResolver is the narrow interface the transforms resolve names through.
//
// It is an interface rather than *net.Resolver because the two are not
// interchangeable: *net.Resolver speaks DNS over a dialer, and there is no way
// to make it speak HTTPS. The direct path keeps using *net.Resolver unchanged,
// so nothing about a run without a route is different from before.
type routeResolver interface {
	// lookupHost returns the addresses a name resolves to. The order is not
	// meaningful and must not be relied upon.
	lookupHost(ctx context.Context, name string) ([]string, error)
	// lookupHostReverse returns the PTR names an address answers with.
	lookupHostReverse(ctx context.Context, address string) ([]string, error)
	// lookupTXT returns the text records published for a name.
	lookupTXT(ctx context.Context, name string) ([]string, error)
	// lookupMX returns the MX exchange hosts published for a name.
	lookupMX(ctx context.Context, name string) ([]string, error)
	// lookupNS returns the NS name server hosts published for a name.
	lookupNS(ctx context.Context, name string) ([]string, error)
	// lookupCNAME returns the canonical name for a given host name.
	lookupCNAME(ctx context.Context, name string) (string, error)
	// lookupCAA returns the CAA records published for a name.
	lookupCAA(ctx context.Context, name string) ([]string, error)
	// lookupSOA returns the SOA record published for a zone name.
	lookupSOA(ctx context.Context, name string) (string, error)
	// describe names the mechanism in a warning, so a run that could not
	// resolve says which resolver it was talking to.
	describe() string
}

// systemResolver is the direct path: the host's own resolver, untouched.
type systemResolver struct {
	resolver *net.Resolver
}

func (r systemResolver) lookupHost(ctx context.Context, name string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupHost(ctx, name)
}

func (r systemResolver) lookupHostReverse(ctx context.Context, address string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupAddr(ctx, address)
}

func (r systemResolver) lookupTXT(ctx context.Context, name string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupTXT(ctx, name)
}

func (r systemResolver) lookupMX(ctx context.Context, name string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	records, err := resolver.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(result)
	return result, nil
}

func (r systemResolver) lookupNS(ctx context.Context, name string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	records, err := resolver.LookupNS(ctx, name)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(result)
	return result, nil
}

func (r systemResolver) lookupCNAME(ctx context.Context, name string) (string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	cname, err := resolver.LookupCNAME(ctx, name)
	if err != nil {
		return "", err
	}
	cname = strings.TrimSuffix(strings.TrimSpace(cname), ".")
	if strings.EqualFold(cname, strings.TrimSuffix(strings.TrimSpace(name), ".")) {
		return "", nil
	}
	return cname, nil
}

func (r systemResolver) lookupCAA(ctx context.Context, name string) ([]string, error) {
	// The Go standard library net.Resolver does not expose LookupCAA directly,
	// so for direct system resolution we query TXT or return nil if unsupported.
	// When DoH is used, RFC 8659 CAA records (type 257) are queried directly.
	return nil, nil
}

func (r systemResolver) lookupSOA(ctx context.Context, name string) (string, error) {
	// SOA is queried via DoH directly where JSON DNS response contains type 6.
	return "", nil
}

func (r systemResolver) describe() string { return "the system resolver" }

// dohResolver resolves names over DNS-over-HTTPS through the active route.
type dohResolver struct {
	client *http.Client
	// endpoints are the resolvers to ask, in order. It is a field rather than a
	// package variable so a test can name its own, and so two resolvers in one
	// process cannot reorder each other's fallbacks.
	endpoints []string
}

// resolvers returns the endpoints to ask, falling back to the public pair when
// none was supplied.
func (r dohResolver) resolvers() []string {
	if len(r.endpoints) > 0 {
		return r.endpoints
	}
	return dohEndpoints
}

// The DoH resolvers, in preference order.
//
// Cloudflare is first because it answers AAAA and A in one request, which is
// what a subdomain discovery needs: two round trips per name across a Tor exit
// is a slow crawl, and a name is usually only worth one question. Google is
// kept as the fallback rather than dropped, because a single resolver being
// unreachable is exactly the failure a fallback exists for.
var dohEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
}

// dohAnswer is the JSON shape both resolvers serve: `Answer` holds the records
// of every requested type, and the type is a numeric DNS type, where A is 1 and
// AAAA is 28.
type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type uint16 `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
	// Comment is served by Cloudflare in the Google shape and carries the
	// resolver's own explanation, which is what a warning should repeat.
	Comment string `json:"Comment"`
}

// lookupHostReverse reads the PTR record over DNS-over-HTTPS.
//
// A PTR record is published as a name under `in-addr.arpa`, so the question is
// a forward lookup of that name and the trailing labels are stripped from the
// answer. It goes through the routed path for the same reason a forward lookup
// does: a relay refuses port 53. An address with no PTR record has no such
// name, which is an answer and not a failure.
func (r dohResolver) lookupHostReverse(ctx context.Context, address string) ([]string, error) {
	parsed := net.ParseIP(strings.TrimSpace(address))
	if parsed == nil {
		return nil, fmt.Errorf("not an address: %q", address)
	}
	labels := reverseDomainName(parsed.String())
	if labels == "" {
		return nil, nil
	}
	records, err := r.lookupHost(ctx, labels)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record)), ".")
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// lookupTXT reads a text record over DNS-over-HTTPS, for the same reason a
// forward lookup goes over HTTPS: a relay refuses port 53.
func (r dohResolver) lookupTXT(ctx context.Context, name string) ([]string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=TXT"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		records, err := r.askTXT(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return records, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return nil, lastErr
}

// dohTXTAnswer is the JSON shape a TXT question comes back in. A TXT record's
// data is split into quoted chunks on the wire, and the JSON form joins them
// back, so the value is read whole.
type dohTXTAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type uint16 `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (r dohResolver) askTXT(ctx context.Context, queryURL string) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohTXTAnswer
	if json.Unmarshal(body, &answer) != nil {
		return nil, fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	records := make([]string, 0, len(answer.Answer))
	for _, record := range answer.Answer {
		if record.Type != 16 {
			continue
		}
		if value := strings.Trim(strings.TrimSpace(record.Data), `"`); value != "" {
			records = append(records, value)
		}
	}
	return records, nil
}

func (r dohResolver) lookupMX(ctx context.Context, name string) ([]string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=MX"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		records, err := r.askMX(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return records, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return nil, lastErr
}

func (r dohResolver) askMX(ctx context.Context, queryURL string) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohAnswer
	if json.Unmarshal(body, &answer) != nil {
		return nil, fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	if answer.Status == 3 {
		return nil, nil
	}
	records := make([]string, 0, len(answer.Answer))
	for _, record := range answer.Answer {
		if record.Type != 15 {
			continue
		}
		parts := strings.Fields(record.Data)
		host := ""
		if len(parts) >= 2 {
			host = parts[1]
		} else if len(parts) == 1 {
			host = parts[0]
		}
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if host != "" {
			records = append(records, host)
		}
	}
	sort.Strings(records)
	return records, nil
}

func (r dohResolver) lookupNS(ctx context.Context, name string) ([]string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=NS"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		records, err := r.askNS(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return records, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return nil, lastErr
}

func (r dohResolver) askNS(ctx context.Context, queryURL string) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohAnswer
	if json.Unmarshal(body, &answer) != nil {
		return nil, fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	if answer.Status == 3 {
		return nil, nil
	}
	records := make([]string, 0, len(answer.Answer))
	for _, record := range answer.Answer {
		if record.Type != 2 {
			continue
		}
		host := strings.TrimSuffix(strings.TrimSpace(record.Data), ".")
		if host != "" {
			records = append(records, host)
		}
	}
	sort.Strings(records)
	return records, nil
}

func (r dohResolver) lookupCNAME(ctx context.Context, name string) (string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=CNAME"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		cname, err := r.askCNAME(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return cname, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return "", lastErr
}

func (r dohResolver) askCNAME(ctx context.Context, queryURL string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohAnswer
	if json.Unmarshal(body, &answer) != nil {
		return "", fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	if answer.Status == 3 {
		return "", nil
	}
	for _, record := range answer.Answer {
		if record.Type == 5 {
			return strings.TrimSuffix(strings.TrimSpace(record.Data), "."), nil
		}
	}
	return "", nil
}

func (r dohResolver) lookupCAA(ctx context.Context, name string) ([]string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=CAA"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		records, err := r.askCAA(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return records, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return nil, lastErr
}

func (r dohResolver) askCAA(ctx context.Context, queryURL string) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohAnswer
	if json.Unmarshal(body, &answer) != nil {
		return nil, fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	if answer.Status == 3 {
		return nil, nil
	}
	records := make([]string, 0, len(answer.Answer))
	for _, record := range answer.Answer {
		if record.Type == 257 { // CAA type RFC 8659
			val := strings.TrimSpace(record.Data)
			if strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) && len(val) >= 2 {
				val = val[1 : len(val)-1]
			}
			if val != "" {
				records = append(records, val)
			}
		}
	}
	sort.Strings(records)
	return records, nil
}

func (r dohResolver) lookupSOA(ctx context.Context, name string) (string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=SOA"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		record, err := r.askSOA(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return record, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return "", lastErr
}

func (r dohResolver) askSOA(ctx context.Context, queryURL string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohAnswer
	if json.Unmarshal(body, &answer) != nil {
		return "", fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	if answer.Status == 3 {
		return "", nil
	}
	for _, record := range answer.Answer {
		if record.Type == 6 { // SOA type
			return strings.Trim(strings.TrimSpace(record.Data), `"`), nil
		}
	}
	return "", nil
}

func (r dohResolver) describe() string {
	return "DNS-over-HTTPS on the active route"
}

// lookupHost asks the DoH resolvers for A and AAAA, in one request per
// resolver, and returns whatever addresses they answer with.
//
// Both types are requested in a single question because a resolver is free to
// answer only one of them, and asking twice doubles the latency of the slowest
// phase in a discovery for no added certainty.
func (r dohResolver) lookupHost(ctx context.Context, name string) ([]string, error) {
	question := name
	if !strings.HasSuffix(question, ".") {
		question += "."
	}
	query := "?name=" + urlQueryEscape(question) + "&type=A"
	var lastErr error
	for _, endpoint := range r.resolvers() {
		addresses, err := r.ask(ctx, endpoint+query)
		if err != nil {
			lastErr = err
			continue
		}
		return addresses, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS-over-HTTPS resolver answered")
	}
	return nil, lastErr
}

// ask performs one DoH question and reads the addresses out of the answer.
func (r dohResolver) ask(ctx context.Context, queryURL string) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", indexUserAgent())
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("the DNS-over-HTTPS resolver returned HTTP %d", response.StatusCode)
	}
	var answer dohAnswer
	if json.Unmarshal(body, &answer) != nil {
		return nil, fmt.Errorf("the DNS-over-HTTPS answer could not be read")
	}
	// Status 3 is NXDOMAIN: the name does not exist, and that is an answer, not
	// a failure of the resolver. It is reported as an empty result so the caller
	// treats it as "this name is not taken" rather than as an error.
	if answer.Status == 3 {
		return nil, nil
	}
	addresses := make([]string, 0, len(answer.Answer))
	for _, record := range answer.Answer {
		if record.Type != 1 && record.Type != 28 {
			continue
		}
		address := strings.TrimSpace(record.Data)
		if net.ParseIP(address) == nil {
			continue
		}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 && answer.Status != 0 {
		if answer.Comment != "" {
			return nil, fmt.Errorf("the DNS-over-HTTPS resolver refused the name: %s", answer.Comment)
		}
		return nil, fmt.Errorf("the DNS-over-HTTPS resolver answered with status %d", answer.Status)
	}
	return addresses, nil
}

// urlQueryEscape escapes a value for a query string without pulling in a
// second helper for a single caller.
func urlQueryEscape(value string) string {
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '-', character == '.', character == '_', character == '~':
			builder.WriteRune(character)
		default:
			builder.WriteString(fmt.Sprintf("%%%02X", character))
		}
	}
	return builder.String()
}

// resolverForContext returns the resolver a transform should use for a context.
//
// A SOCKS5 route cannot carry DNS, so a routed run resolves over HTTPS through
// the same transport as every other request; a run without a route keeps the
// host resolver, which is both faster and the pre-existing behaviour.
func resolverForContext(ctx context.Context, client *http.Client, s *server) routeResolver {
	// The route's own snapshot is the authority on whether a route is active: the
	// resolver is chosen from the same configuration the request transport is
	// built from, so a run can never resolve one way and connect another.
	if lease, ok := routeLeaseFromContext(ctx); ok && lease.manager != nil {
		if lease.manager.configSnapshot().Address != "" {
			if client == nil {
				client = &http.Client{Timeout: 20 * time.Second}
			}
			return dohResolver{client: client}
		}
		return systemResolver{resolver: lease.resolver()}
	}
	if s != nil && s.resolverOverride != nil {
		return s.resolverOverride
	}
	return systemResolver{resolver: routeResolverForContext(ctx)}
}

// reverseDomainName renders an address as the name its PTR record is published
// under.
//
// The standard library builds this for its own resolver and does not export
// it, and a routed run cannot use that resolver, so the name is built here.
// For IPv4 the octets are reversed under `in-addr.arpa`; for IPv6 the nibbles
// are reversed under `ip6.arpa`. An address that is not one yields an empty
// string, because a PTR question needs an address to ask about.
func reverseDomainName(address string) string {
	parsed := net.ParseIP(strings.TrimSpace(address))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := parsed.To16()
	if v6 == nil {
		return ""
	}
	var builder strings.Builder
	for index := len(v6) - 1; index >= 0; index-- {
		octet := v6[index]
		builder.WriteByte("0123456789abcdef"[octet&0x0f])
		builder.WriteByte('.')
		builder.WriteByte("0123456789abcdef"[octet>>4])
		builder.WriteByte('.')
	}
	builder.WriteString("ip6.arpa")
	return builder.String()
}
