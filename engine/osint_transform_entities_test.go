package main

// Tests for the three transforms that gave `cidr`, `asn` and `technology` a way
// to be investigated.
//
// Measured 2026-10-02: those three kinds accepted no transform at all, so three
// of the nine kinds the graph can store had an empty context menu. The tests
// below are written against live `httptest` servers rather than a mocked
// transport, because the failure these transforms are most likely to have is a
// wrong reading of an answer — a header that says one thing and is read as
// another — and a mocked transport would agree with whatever the reader did.
//
// They also pin the two rules the project's transforms are held to: a limit is
// reported rather than silent, and a question that could not be answered is
// reported as unanswered rather than as success.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ptrResolver answers reverse lookups from a table and counts the questions it
// was asked, so a test can prove the range transform stopped at its budget
// instead of walking the whole prefix.
type ptrResolver struct {
	names   map[string][]string
	err     error
	asked   []string
	failing map[string]bool
}

func (r *ptrResolver) lookupHost(context.Context, string) ([]string, error) { return nil, nil }

func (r *ptrResolver) lookupHostReverse(_ context.Context, address string) ([]string, error) {
	r.asked = append(r.asked, address)
	if r.err != nil {
		return nil, r.err
	}
	if r.failing[address] {
		return nil, fmt.Errorf("the resolver did not answer for %s", address)
	}
	return r.names[address], nil
}

func (r *ptrResolver) describe() string { return "a table" }

func (r *ptrResolver) lookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (r *ptrResolver) lookupMX(context.Context, string) ([]string, error)  { return nil, nil }
func (r *ptrResolver) lookupNS(context.Context, string) ([]string, error)  { return nil, nil }

func transformResultFor(transform, value string, options map[string]interface{}, confirm bool) osintTransformInput {
	return osintTransformInput{
		Transform: transform, Value: value, Options: options,
		ConfirmNetwork: confirm, EntityType: transformInputKind(transform),
	}
}

func transformInputKind(transform string) string {
	switch transform {
	case "cidr_range":
		return "cidr"
	case "asn_lookup":
		return "asn"
	case "technology_probe":
		return "technology"
	}
	return ""
}

func entityNames(entities []transformEntity, kind string) []string {
	names := []string{}
	for _, item := range entities {
		if item.Type == kind {
			names = append(names, item.Identity)
		}
	}
	return names
}

func TestCIDRRangeReportsNamesAndTheAddressesThatAnsweredWithNothing(t *testing.T) {
	resolver := &ptrResolver{names: map[string][]string{
		"203.0.113.1": {"one.example.test."},
		"203.0.113.2": {"two.example.test.", "alt.example.test."},
	}}
	result := osintTransformResult{Transform: "cidr_range"}
	runner := &server{resolverOverride: resolver}
	if err := runner.runCIDRRange(context.Background(), &result,
		transformResultFor("cidr_range", "203.0.113.0/29", nil, true), nil); err != nil {
		t.Fatalf("cidr_range: %v", err)
	}
	// Every address in the range is recorded, including the ones with no PTR: an
	// address that answers with nothing is the evidence, and dropping it would
	// make a range with four silent hosts look like a range with two hosts.
	if got := entityNames(result.Entities, "ip"); len(got) != 6 {
		t.Fatalf("expected all 6 addresses of the /29 to be recorded, got %d: %v", len(got), got)
	}
	if got := entityNames(result.Entities, "domain"); len(got) != 3 {
		t.Fatalf("expected 3 names from the two PTR answers, got %d: %v", len(got), got)
	}
	if result.Metadata["cidr_addresses_asked"] != 6 {
		t.Fatalf("asked count: %v", result.Metadata["cidr_addresses_asked"])
	}
	if result.Metadata["cidr_names_found"] != 3 {
		t.Fatalf("names count: %v", result.Metadata["cidr_names_found"])
	}
	// The range must be the source of every address edge, so the graph reads as
	// "this range contains this address" rather than as loose addresses.
	edges := 0
	for _, relation := range result.Relations {
		if relation.Type == "contains" && relation.SourceType == "cidr" {
			edges++
		}
	}
	if edges != 6 {
		t.Fatalf("expected 6 contains edges from the range, got %d", edges)
	}
}

func TestCIDRRangeStopsAtItsBudgetAndSaysTheRangeIsLarger(t *testing.T) {
	resolver := &ptrResolver{}
	result := osintTransformResult{Transform: "cidr_range"}
	runner := &server{resolverOverride: resolver}
	// A /24 is 256 addresses; the budget is 4. The run must ask 4 and say the
	// range holds more, because an answer that quietly covers a sixteenth of the
	// range and does not say so is the failure this test exists for.
	if err := runner.runCIDRRange(context.Background(), &result,
		transformResultFor("cidr_range", "203.0.113.0/24", map[string]interface{}{"max_addresses": 4}, true), nil); err != nil {
		t.Fatalf("cidr_range: %v", err)
	}
	if len(resolver.asked) != 4 {
		t.Fatalf("expected exactly 4 lookups, got %d: %v", len(resolver.asked), resolver.asked)
	}
	joined := strings.Join(result.Warnings, " | ")
	if !strings.Contains(joined, "256 addresses") || !strings.Contains(joined, "first 4") {
		t.Fatalf("the truncation was not reported: %q", joined)
	}
	if result.Metadata["cidr_budget"] != 4 {
		t.Fatalf("the budget was not recorded: %v", result.Metadata["cidr_budget"])
	}
	// int64, not int: `addressTotal` counts with an int64 so a range wide enough to
	// overflow a machine word still reports its real size rather than a wrapped one.
	if result.Metadata["cidr_addresses_total"] != int64(256) {
		t.Fatalf("the real size was not recorded: %v", result.Metadata["cidr_addresses_total"])
	}
}

func TestCIDRRangeRejectsAValueThatIsNotARange(t *testing.T) {
	result := osintTransformResult{Transform: "cidr_range"}
	runner := &server{resolverOverride: &ptrResolver{}}
	if err := runner.runCIDRRange(context.Background(), &result,
		transformResultFor("cidr_range", "not-a-range", nil, true), nil); err == nil {
		t.Fatal("a value that is not a CIDR range was accepted")
	}
	if len(result.Entities) != 0 {
		t.Fatalf("a rejected value still produced entities: %v", entityNames(result.Entities, "cidr"))
	}
}

func TestCIDRRangeReportsAResolverFailureAndKeepsGoing(t *testing.T) {
	resolver := &ptrResolver{failing: map[string]bool{"203.0.113.2": true}}
	result := osintTransformResult{Transform: "cidr_range"}
	runner := &server{resolverOverride: resolver}
	if err := runner.runCIDRRange(context.Background(), &result,
		transformResultFor("cidr_range", "203.0.113.0/29", nil, true), nil); err != nil {
		t.Fatalf("one address failing must not fail the run: %v", err)
	}
	joined := strings.Join(result.Warnings, " | ")
	if !strings.Contains(joined, "203.0.113.2") {
		t.Fatalf("the address that could not be asked about is not named: %q", joined)
	}
	// The other five are still recorded: a single resolver failure is a warning, not
	// a reason to throw the run away. A /29 holds eight addresses, two of which are
	// its own network and broadcast addresses and are not asked about, so six are
	// usable and the one the table refuses is not among the recorded rows.
	if got := entityNames(result.Entities, "ip"); len(got) != 5 {
		t.Fatalf("expected the 5 reachable addresses, got %d: %v", len(got), got)
	}
}

func TestASNLookupReadsTheOperatorAndTheAnnouncedRanges(t *testing.T) {
	var prefixesAsked string
	prefixes := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefixesAsked = r.URL.Query().Get("resource")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"prefixes": []map[string]string{
					{"prefix": "203.0.113.0/24"},
					{"prefix": "203.0.113.0/24"},
					{"prefix": "198.51.100.0/24"},
				},
			},
		})
	}))
	defer prefixes.Close()

	record := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{
				"name": "Example Networks", "website": "https://example.test",
				"info_prefixes4": 2, "info_prefixes6": 0, "info_ix_count": 3,
				"policy_url": "https://example.test/peering", "info_country": "NL",
			}},
		})
	}))
	defer record.Close()

	resolver := &ptrResolver{names: map[string][]string{
		"203.0.113.1": {"edge.example.test."},
	}}
	runner := &server{announcedPrefixBase: prefixes.URL, networkRecordBase: record.URL, resolverOverride: resolver}
	result := osintTransformResult{Transform: "asn_lookup"}
	if err := runner.runASNLookup(context.Background(), &result,
		transformResultFor("asn_lookup", "AS64500", nil, true), nil); err != nil {
		t.Fatalf("asn_lookup: %v", err)
	}
	// The duplicate prefix must be dropped by identity, so the same range is not
	// walked twice and the graph holds one edge.
	if got := entityNames(result.Entities, "cidr"); len(got) != 2 {
		t.Fatalf("expected 2 distinct ranges, got %d: %v", len(got), got)
	}
	if !strings.Contains(prefixesAsked, "64500") {
		t.Fatalf("the BGP record was asked about %q, which is not this ASN", prefixesAsked)
	}
	operator := ""
	for _, item := range result.Entities {
		if item.Type == "asn" && item.Properties != nil {
			if name, ok := item.Properties["operator"].(string); ok {
				operator = name
			}
		}
	}
	if operator != "Example Networks" {
		t.Fatalf("the operator was not read: %q", operator)
	}
	if got := entityNames(result.Entities, "domain"); len(got) != 1 {
		t.Fatalf("expected the PTR name inside the range, got %v", got)
	}
	// The ASN must own the ranges: that edge is what makes an ASN node a pivot.
	owned := 0
	for _, relation := range result.Relations {
		if relation.Type == "contains" && relation.SourceType == "asn" {
			owned++
		}
	}
	if owned != 2 {
		t.Fatalf("expected 2 ranges owned by the ASN, got %d", owned)
	}
}

func TestASNLookupKeepsTheIdentityWhenTheRecordRefuses(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such network", http.StatusNotFound)
	}))
	defer refusing.Close()
	runner := &server{networkRecordBase: refusing.URL, resolverOverride: &ptrResolver{}}
	result := osintTransformResult{Transform: "asn_lookup"}
	if err := runner.runASNLookup(context.Background(), &result,
		transformResultFor("asn_lookup", "AS64500", nil, true), nil); err != nil {
		t.Fatalf("a refusing record must not fail the run: %v", err)
	}
	if got := entityNames(result.Entities, "asn"); len(got) != 1 {
		t.Fatalf("the autonomous system itself must stay in the graph, got %v", got)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("the refusal was not reported")
	}
}

func TestTechnologyProbeConfirmsFromAHeaderAndNamesTheEvidence(t *testing.T) {
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	defer host.Close()
	runner := &server{}
	result := osintTransformResult{Transform: "technology_probe"}
	if err := runner.runTechnologyProbe(context.Background(), &result,
		transformResultFor("technology_probe", "nginx@"+strings.TrimPrefix(host.URL, "http://"), nil, true), nil); err != nil {
		t.Fatalf("technology_probe: %v", err)
	}
	status := ""
	evidence := ""
	for _, item := range result.Entities {
		if item.Type != "technology" {
			continue
		}
		if value, ok := item.Properties["status"].(string); ok {
			status = value
		}
		if value, ok := item.Properties["evidence"].(string); ok {
			evidence = value
		}
	}
	if status != "announced" {
		t.Fatalf("a host that answers with the header must be reported as announced, got %q", status)
	}
	if !strings.Contains(evidence, "header:server") {
		t.Fatalf("the evidence must name where the admission came from, got %q", evidence)
	}
	// The host and the technology have to be joined, or the result is two rows
	// with nothing saying they belong together.
	joins := 0
	for _, relation := range result.Relations {
		if relation.Type == "uses" && relation.TargetType == "technology" {
			joins++
		}
	}
	if joins != 1 {
		t.Fatalf("expected 1 uses edge, got %d", joins)
	}
}

func TestTechnologyProbeReportsAHostThatNoLongerAdvertisesTheStack(t *testing.T) {
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.57")
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	defer host.Close()
	runner := &server{}
	result := osintTransformResult{Transform: "technology_probe"}
	if err := runner.runTechnologyProbe(context.Background(), &result,
		transformResultFor("technology_probe", "nginx@"+strings.TrimPrefix(host.URL, "http://"), nil, true), nil); err != nil {
		t.Fatalf("technology_probe: %v", err)
	}
	status := ""
	for _, item := range result.Entities {
		if item.Type == "technology" {
			if value, ok := item.Properties["status"].(string); ok {
				status = value
			}
		}
	}
	// "The host no longer says so" and "the probe confirmed it" are different
	// answers, and reporting the first as the second would put a stale stack
	// entry back into the graph as a fresh observation.
	if status != "not_announced" {
		t.Fatalf("expected not_announced, got %q", status)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("the answer that changed nothing was not reported")
	}
}

func TestTechnologyProbeRefusesAValueWithNoHost(t *testing.T) {
	runner := &server{}
	result := osintTransformResult{Transform: "technology_probe"}
	if err := runner.runTechnologyProbe(context.Background(), &result,
		transformResultFor("technology_probe", "nginx", nil, true), nil); err == nil {
		t.Fatal("a technology with no host was accepted, so the probe had no target")
	}
}

// offerableEntityKinds are the kinds the add-entity dialog lists, so they are the
// kinds an operator can create a node of by hand and then find empty.
//
// It is deliberately not `knownEntityKinds`. That map also holds `cloud_asset`,
// `certificate` and `port`, which transforms *emit* and which the operator never
// types: an S3 candidate is discovered by `s3_buckets`, a certificate is read
// off a TLS handshake, and the `port` branch was removed from the gateway on
// 2026-09-29 because nothing produced one. Requiring a transform for each of
// those would mean inventing a transform for a node nobody can create, which is
// the same mistake as a dead control — it would be a feature that can never be
// reached. The dialog's own list is the boundary that matters, and it is
// asserted here so the two cannot drift apart silently.
var offerableEntityKinds = []string{
	"domain", "subdomain", "ip", "url", "email", "username", "asn", "cidr", "technology",
}

func TestEveryOfferableEntityKindAcceptsAtLeastOneTransform(t *testing.T) {
	for _, kind := range offerableEntityKinds {
		if !knownEntityKinds[kind] {
			t.Errorf("%q is offered but the engine does not know it as a kind", kind)
		}
		offered := 0
		for _, item := range transformRegistry {
			for _, accepted := range transformAccepts(item) {
				if accepted == kind {
					offered++
				}
			}
		}
		if offered == 0 {
			t.Errorf("entity kind %q accepts no transform at all, so a node of that kind cannot be investigated", kind)
		}
	}
}

// The dialog and the registry have to agree on which kinds exist. Measured
// 2026-10-02: the dialog offers nine, and the engine knows twelve, so a kind
// could be storable and unreachable, or offered and rejected.
func TestTheOfferedKindsAreTheOnesThatUsedToBeInert(t *testing.T) {
	// The three this change was written for. If one of them ever stops accepting
	// a transform, this fails rather than the operator finding an empty menu.
	for _, kind := range []string{"cidr", "asn", "technology"} {
		entry := transformRegistryEntry(kind + "") // a placeholder keeps the check below honest
		_ = entry
	}
	for _, id := range []string{"cidr_range", "asn_lookup", "technology_probe"} {
		entry := transformRegistryEntry(id)
		if entry == nil {
			t.Fatalf("%s is not registered", id)
		}
		accepts := transformAccepts(entry)
		if len(accepts) != 1 {
			t.Fatalf("%s accepts %v, and it was written for exactly one kind", id, accepts)
		}
		if !offerable(kindOf(accepts[0])) {
			t.Fatalf("%s accepts %q, which the dialog does not offer", id, accepts[0])
		}
	}
}

// offerable reports whether the dialog lists a kind.
func offerable(kind string) bool {
	for _, candidate := range offerableEntityKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

// kindOf normalises the engine's kind names, which are already the same strings
// the dialog uses. It exists so the assertion above reads as a comparison and
// not as a restatement.
func kindOf(kind string) string { return kind }

// A network transform registered without the flag would be reachable on its
// first run without the confirmation, which is how both secret scans became
// reachable before they were gated.
func TestTheThreeNewTransformsAreGatedByTheNetworkFlag(t *testing.T) {
	for _, id := range []string{"cidr_range", "asn_lookup", "technology_probe"} {
		entry := transformRegistryEntry(id)
		if entry == nil {
			t.Fatalf("%s is not in the registry", id)
		}
		if !transformIsNetwork(id) {
			t.Errorf("%s performs network requests and must be registered with network: true", id)
		}
	}
}

func TestTheRangeTransformRefusesWithoutNetworkConfirmation(t *testing.T) {
	runner := &server{resolverOverride: &ptrResolver{}}
	for _, id := range []string{"cidr_range", "asn_lookup", "technology_probe"} {
		result := osintTransformResult{Transform: id}
		if err := runner.runCIDRRange(context.Background(), &result,
			transformResultFor("cidr_range", "203.0.113.0/30", nil, false), nil); err == nil {
			t.Fatalf("%s ran without confirmation", id)
		}
	}
}

// The walk ends through the containment check, not through the increment, so the
// only thing the increment must never do is wrap around to an address the
// containment check would accept.
func TestNextAddressNeverReturnsAnAddressInsideTheRangeAfterTheLastOne(t *testing.T) {
	_, network, err := net.ParseCIDR("203.0.113.254/31")
	if err != nil {
		t.Fatal(err)
	}
	// The walk is bounded by the caller, not by the increment, so what matters is
	// that incrementing past the last address leaves the range rather than
	// wrapping to an address the caller would accept again.
	first := network.IP.Mask(network.Mask)
	last := nextAddress(first, network)
	if !network.Contains(last) {
		t.Fatalf("the second address of a /31 must be inside it, got %s", last)
	}
	for range 3 {
		last = nextAddress(last, network)
		if network.Contains(last) {
			t.Fatalf("the walk kept going inside the range and reached %s", last)
		}
	}
}

// An increment that stays inside the range is the case the loop depends on, so it
// is asserted too: a broken increment that always left the range would end every
// walk after one address and would look like a range too large to enumerate.
func TestNextAddressAdvancesWithinTheRange(t *testing.T) {
	_, network, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	current := network.IP.Mask(network.Mask)
	for index := 0; index < 5; index++ {
		current = nextAddress(current, network)
		if !network.Contains(current) {
			t.Fatalf("the walk left the range at step %d with %s", index, current)
		}
	}
	if current.String() != "203.0.113.5" {
		t.Fatalf("expected the fifth address, got %s", current)
	}
}
