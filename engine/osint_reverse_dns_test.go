package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// dnsStub is a minimal UDP DNS responder for the reverse_dns tests.
//
// The transform asks a real resolver two questions — the addresses of a host
// and the pointer names of those addresses — so the test needs an answer for
// both. A stub listener keeps the test deterministic and offline: the wire
// format is small enough to build by hand, and nothing about the transform is
// stubbed, only the network beneath it.
type dnsStub struct {
	address  string
	address4 net.IP
	pointer  []byte
}

// startDNSStub answers every A query with address4, every PTR query with
// pointer, and every other query with an empty NOERROR answer. An empty
// NOERROR for AAAA matters: a NXDOMAIN there would tell the resolver that the
// whole name does not exist and it would never look at the A answer.
func startDNSStub(t *testing.T, address4 string, pointer string) *dnsStub {
	t.Helper()
	return startStub(t, net.ParseIP(address4), dnsEncodeName(pointer))
}

// dnsStubAddress is the UDP address of the DNS stub the tests resolve through,
// or the empty string when no stub is running. It is an atomic value rather than
// a package variable because the resolver reads it from whatever goroutine
// happens to be resolving, including a background OAST poller left over from an
// earlier test.
var dnsStubAddress atomic.Value // string

// startStub is startDNSStub with the address and pointer left optional: a nil
// address answers every A query with nothing, and an empty pointer answers every
// PTR query with nothing. Both are answers a real resolver returns for a name
// that does not exist and for an address nothing points back at.
func startStub(t *testing.T, address4 net.IP, pointer []byte) *dnsStub {
	t.Helper()
	stub := &dnsStub{address4: address4, pointer: pointer}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns stub: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	stub.address = conn.LocalAddr().String()
	go func() {
		buffer := make([]byte, 1500)
		for {
			read, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			answer, err := stub.answer(buffer[:read])
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(answer, peer)
		}
	}()
	// The stub is published through dnsStubAddress, which the resolver installed
	// once in TestMain reads. Writing `net.DefaultResolver` here and restoring it
	// from `t.Cleanup` was a data race, and the detector named both sides: the
	// cleanup's write against a live OAST poller that was still dialing through
	// the global (`oast.go` -> `http.Transport.dial` -> `net.Dialer`). A
	// process-wide setting can only be used safely when nothing writes it while
	// a test runs, so the write happens exactly once — in TestMain — and a test
	// only publishes an address.
	dnsStubAddress.Store(stub.address)
	t.Cleanup(func() { dnsStubAddress.Store("") })
	return stub
}

// answer builds the response for one query packet.
func (s *dnsStub) answer(query []byte) ([]byte, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errStubQuery
	}
	question, qtype, err := dnsSplitQuestion(query)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 12)
	copy(header, query[:4])
	// QR, AA and RA set, RCODE 0; RD copied so the resolver treats the answer
	// as an answer to its own recursive query.
	binary.BigEndian.PutUint16(header[2:6], 0x8580|(binary.BigEndian.Uint16(query[2:4])&0x0100))
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], 1)
	response := append(header, question...)
	switch qtype {
	case 1: // A
		if s.address4 == nil {
			// An empty NOERROR is how a name that does not exist is answered.
			return response, nil
		}
		record := make([]byte, 0, 16)
		record = append(record, 0xc0, 0x0c) // pointer to the question name
		record = binary.BigEndian.AppendUint16(record, 1)
		record = binary.BigEndian.AppendUint16(record, 1)
		record = binary.BigEndian.AppendUint32(record, 60)
		address := s.address4.To4()
		record = binary.BigEndian.AppendUint16(record, uint16(len(address)))
		response = append(response, append(record, address...)...)
	case 12: // PTR
		if len(s.pointer) == 0 {
			// An address nothing points back at is answered the same way.
			return response, nil
		}
		record := make([]byte, 0, 32)
		record = append(record, 0xc0, 0x0c)
		record = binary.BigEndian.AppendUint16(record, 12)
		record = binary.BigEndian.AppendUint16(record, 1)
		record = binary.BigEndian.AppendUint32(record, 60)
		record = binary.BigEndian.AppendUint16(record, uint16(len(s.pointer)))
		response = append(response, append(record, s.pointer...)...)
	}
	return response, nil
}

var errStubQuery = &stubError{"query packet is not a single-question DNS message"}

type stubError struct{ text string }

func (e *stubError) Error() string { return e.text }

// dnsSplitQuestion returns the question section verbatim and its question type.
func dnsSplitQuestion(query []byte) ([]byte, uint16, error) {
	name := 12
	for name < len(query) && query[name] != 0 {
		name += int(query[name]) + 1
	}
	end := name + 5
	if end > len(query) {
		return nil, 0, errStubQuery
	}
	return query[12:end], binary.BigEndian.Uint16(query[name+1 : name+3]), nil
}

// dnsEncodeName encodes a domain name in DNS wire format.
func dnsEncodeName(name string) []byte {
	encoded := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0)
}

// transformEntityIDs returns the identities stored by a transform, keyed by type.
func transformEntityIDs(result *osintTransformResult) map[string][]string {
	ids := map[string][]string{}
	for _, item := range result.Entities {
		ids[item.Type] = append(ids[item.Type], item.Identity)
	}
	return ids
}

// transformRelationPairs returns the "source>type>target" form of every relation.
func transformRelationPairs(result *osintTransformResult) []string {
	pairs := make([]string, 0, len(result.Relations))
	for _, relation := range result.Relations {
		pairs = append(pairs, relation.Source+">"+relation.Type+">"+relation.Target)
	}
	return pairs
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestReverseDNSResolvesHostnameBeforeAskingForPointerNames(t *testing.T) {
	startDNSStub(t, "203.0.113.7", "ptr.example.test.")
	shared := startSharedHostFixture(t, "neighbour-one.test\nneighbour-two.test\n")
	engine := &server{sharedHostBase: shared}
	result := &osintTransformResult{}
	if err := engine.runReverseDNS(context.Background(), result, osintTransformInput{
		Transform: "reverse_dns", Value: "host.example.test", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("reverse_dns for a hostname: %v", err)
	}
	ids := transformEntityIDs(result)
	// The forward answer is kept, not only the pointer name: without the host
	// entity and its resolves_to relation the graph would lose which name the
	// address belongs to.
	for _, want := range []string{"host.example.test", "ptr.example.test"} {
		if !containsValue(ids["domain"], want) {
			t.Fatalf("domain %q missing from %#v", want, ids)
		}
	}
	if !containsValue(ids["ip"], "203.0.113.7") {
		t.Fatalf("the resolved address is missing: %#v", ids)
	}
	pairs := transformRelationPairs(result)
	for _, want := range []string{
		"host.example.test>resolves_to>203.0.113.7",
		"ptr.example.test>resolves_to>203.0.113.7",
	} {
		if !containsValue(pairs, want) {
			t.Fatalf("relation %q missing from %v", want, pairs)
		}
	}
	// The neighbour list is the point of asking an address at all: a name that
	// answers on the same address is another organisation on shared hosting, and
	// it must be linked as hosted_on rather than as a resolves_to the queried
	// host does not have.
	for _, want := range []string{"neighbour-one.test", "neighbour-two.test"} {
		if !containsValue(ids["domain"], want) {
			t.Fatalf("shared-hosting name %q missing from %#v", want, ids)
		}
	}
	for _, want := range []string{
		"neighbour-one.test>hosted_on>203.0.113.7",
		"neighbour-two.test>hosted_on>203.0.113.7",
	} {
		if !containsValue(pairs, want) {
			t.Fatalf("shared-hosting relation %q missing from %v", want, pairs)
		}
	}
	if result.Metadata["reverse_ip_read"] != 2 {
		t.Fatalf("reverse_ip_read = %v, want the number of names actually stored", result.Metadata["reverse_ip_read"])
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}
	if result.LocalOnly || !result.NetworkUsed {
		t.Fatalf("network flags = localOnly:%v networkUsed:%v", result.LocalOnly, result.NetworkUsed)
	}
}

// startSharedHostFixture serves the newline list the shared-hosting index
// answers with, so the neighbour phase is asserted without a third party.
func startSharedHostFixture(t *testing.T, body string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/reverseiplookup/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// A quota note arrives in the same field as the names, so it must be read as a
// note about the answer and never stored as a hostname.
func TestSharedHostIndexRefusesToStoreItsOwnMessages(t *testing.T) {
	shared := startSharedHostFixture(t, "error:You have exceeded the daily api count\nreal-neighbour.test\n")
	engine := &server{sharedHostBase: shared}
	names, note, err := engine.sharedHostNames(context.Background(), &http.Client{}, "203.0.113.7")
	if err != nil {
		t.Fatalf("shared-hosting lookup: %v", err)
	}
	if note == "" {
		t.Fatalf("a quota message was swallowed: names=%#v note=%q", names, note)
	}
	if len(names) != 0 {
		t.Fatalf("an index message was stored as a name: %#v", names)
	}
}

func TestReverseDNSAcceptsLiteralAddress(t *testing.T) {
	startDNSStub(t, "203.0.113.7", "ptr.example.test.")

	engine := &server{}
	result := &osintTransformResult{}
	if err := engine.runReverseDNS(context.Background(), result, osintTransformInput{
		Transform: "reverse_dns", Value: "203.0.113.7", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("reverse_dns for an address: %v", err)
	}
	ids := transformEntityIDs(result)
	if !containsValue(ids["ip"], "203.0.113.7") {
		t.Fatalf("address entity missing: %#v", ids)
	}
	// A literal address is asked about directly, so no forward relation for a
	// host is invented.
	if len(ids["domain"]) != 1 || !containsValue(ids["domain"], "ptr.example.test") {
		t.Fatalf("pointer names = %#v, want exactly the stub pointer", ids["domain"])
	}
	if !containsValue(transformRelationPairs(result), "ptr.example.test>resolves_to>203.0.113.7") {
		t.Fatalf("pointer relation missing: %v", transformRelationPairs(result))
	}
}

func TestReverseDNSRejectsRangeAndEmptyValue(t *testing.T) {
	engine := &server{}
	for value, want := range map[string]string{
		"203.0.113.0/24": "a CIDR range is not a single address",
		"":               "IP address is invalid",
	} {
		err := engine.runReverseDNS(context.Background(), &osintTransformResult{}, osintTransformInput{
			Transform: "reverse_dns", Value: value, ConfirmNetwork: true,
		})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("reverse_dns for %q error = %v, want %q", value, err, want)
		}
	}
}

func TestReverseDNSStillRequiresNetworkConfirmation(t *testing.T) {
	engine := &server{}
	err := engine.runReverseDNS(context.Background(), &osintTransformResult{}, osintTransformInput{
		Transform: "reverse_dns", Value: "host.example.test",
	})
	if err == nil || !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Fatalf("reverse_dns without confirmation error = %v", err)
	}
}

// TestReverseDNSDoesNotStoreANameThatResolvesNowhere proves a failed lookup is
// reported as a failed lookup.
//
// The transform accepts a hostname as well as an address, so a name that
// resolves nowhere used to be stored as a domain entity with no address and no
// pointer behind it. The result then read as a successful lookup of a host that
// does not exist: one entity, zero relations, no error. A name is only an
// identity once the resolver has confirmed it exists.
func TestReverseDNSDoesNotStoreANameThatResolvesNowhere(t *testing.T) {
	// An empty NOERROR for both A and AAAA is what a name that does not resolve
	// looks like, so the stub answers with no addresses at all.
	startDNSStubWithoutAddresses(t)

	engine := &server{}
	result := &osintTransformResult{}
	if err := engine.runReverseDNS(context.Background(), result, osintTransformInput{
		Transform: "reverse_dns", Value: "nxdomain.example.test", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("reverse_dns for an unresolvable name: %v", err)
	}
	ids := transformEntityIDs(result)
	if len(ids["domain"]) != 0 || len(ids["ip"]) != 0 {
		t.Fatalf("a name that resolves nowhere was stored: %#v", ids)
	}
	if len(result.Relations) != 0 {
		t.Fatalf("relations invented for a name that resolves nowhere: %v", transformRelationPairs(result))
	}
	// The refusal itself is still visible: an empty answer is evidence that the
	// name does not resolve, and saying so is the point of the warning.
	if len(result.Warnings) == 0 {
		t.Fatal("an unresolvable name was reported without a word about it")
	}
}

// TestReverseDNSKeepsAnAddressWhosePointerIsMissing proves the opposite case: an
// address with no PTR is real evidence and is kept, because the interesting fact
// is that the address does not resolve back.
func TestReverseDNSKeepsAnAddressWhosePointerIsMissing(t *testing.T) {
	// The stub answers A with an address and PTR with an empty NOERROR, so the
	// address exists and nothing points back at it.
	startDNSStubWithoutPointers(t)

	engine := &server{}
	result := &osintTransformResult{}
	if err := engine.runReverseDNS(context.Background(), result, osintTransformInput{
		Transform: "reverse_dns", Value: "203.0.113.7", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("reverse_dns: %v", err)
	}
	ids := transformEntityIDs(result)
	if !containsValue(ids["ip"], "203.0.113.7") {
		t.Fatalf("an address with no pointer was dropped: %#v", ids)
	}
	if len(ids["domain"]) != 0 {
		t.Fatalf("a pointer name was invented: %#v", ids["domain"])
	}
	if len(result.Relations) != 0 {
		t.Fatalf("a relation was invented without a pointer: %v", transformRelationPairs(result))
	}
}

// startDNSStubWithoutAddresses answers every question with an empty NOERROR, so
// a name the resolver asks about simply does not exist.
func startDNSStubWithoutAddresses(t *testing.T) *dnsStub {
	t.Helper()
	return startStub(t, nil, nil)
}

// startDNSStubWithoutPointers answers A with an address and PTR with nothing, so
// the address exists and no name points back at it.
func startDNSStubWithoutPointers(t *testing.T) *dnsStub {
	t.Helper()
	return startStub(t, net.ParseIP("203.0.113.7"), nil)
}
