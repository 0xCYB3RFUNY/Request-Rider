package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
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
	stub := &dnsStub{address4: net.ParseIP(address4), pointer: dnsEncodeName(pointer)}
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
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", stub.address)
		},
	}
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
		record := make([]byte, 0, 16)
		record = append(record, 0xc0, 0x0c) // pointer to the question name
		record = binary.BigEndian.AppendUint16(record, 1)
		record = binary.BigEndian.AppendUint16(record, 1)
		record = binary.BigEndian.AppendUint32(record, 60)
		address := s.address4.To4()
		record = binary.BigEndian.AppendUint16(record, uint16(len(address)))
		response = append(response, append(record, address...)...)
	case 12: // PTR
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

	engine := &server{}
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
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}
	if result.LocalOnly || !result.NetworkUsed {
		t.Fatalf("network flags = localOnly:%v networkUsed:%v", result.LocalOnly, result.NetworkUsed)
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
