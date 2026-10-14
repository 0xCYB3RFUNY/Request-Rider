package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The three new sources answer the graph, so the tests assert the shape of the
// answer and, more importantly, what the transform refuses to store: a registry
// message is not a nameserver, and an unknown verdict vocabulary is not a
// classification.

func jsonFixture(t *testing.T, body string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestRdapReadsRegistrarDatesAndNameservers(t *testing.T) {
	// The registrar name lives inside a jCard array, not in a plain field, so a
	// decoder that reads `vcardArray` as a string finds nothing here.
	body := `{
	  "handle":"EXAMPLE.COM",
	  "ldhName":"EXAMPLE.COM",
	  "status":["client delete prohibited","client transfer prohibited"],
	  "events":[
	    {"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
	    {"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"},
	    {"eventAction":"last changed","eventDate":"2026-08-14T07:01:38Z"}
	  ],
	  "nameservers":[
	    {"ldhName":"A.IANA-SERVERS.NET"},
	    {"ldhName":"B.IANA-SERVERS.NET"}
	  ],
	  "entities":[{
	    "roles":["registrar"],
	    "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]
	  }]
	}`
	engine := &server{rdapBase: jsonFixture(t, body)}

	registration, err := engine.rdapDomain(context.Background(), &http.Client{}, "example.com")
	if err != nil {
		t.Fatalf("rdap lookup: %v", err)
	}
	if registration.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Fatalf("registrar = %q, the jCard name was not read", registration.Registrar)
	}
	if registration.Events["registration"] != "1995-08-14T04:00:00Z" {
		t.Fatalf("registration date = %q", registration.Events["registration"])
	}
	if len(registration.Nameservers) != 2 || registration.Nameservers[0] != "a.iana-servers.net" {
		t.Fatalf("nameservers = %#v", registration.Nameservers)
	}
	if len(registration.Statuses) != 2 {
		t.Fatalf("statuses = %#v", registration.Statuses)
	}
}

func TestRdapFollowsTheBootstrapRedirect(t *testing.T) {
	// The bootstrap answers a redirect, and the registry answers the second
	// request. A client that does not follow it reports "no record" for every
	// domain in the world.
	registry := jsonFixture(t, `{"handle":"X","entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Fixture Registrar"]]]}]}`)
	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, registry+"/domain/x.test", http.StatusFound)
	}))
	t.Cleanup(bootstrap.Close)

	engine := &server{rdapBase: bootstrap.URL}
	registration, err := engine.rdapDomain(context.Background(), &http.Client{}, "example.com")
	if err != nil {
		t.Fatalf("rdap lookup through the bootstrap: %v", err)
	}
	if registration.Registrar != "Fixture Registrar" {
		t.Fatalf("registrar = %q", registration.Registrar)
	}
}

func TestRdapRefusesARedirectLoop(t *testing.T) {
	// A registry that keeps redirecting is a loop, and following it forever
	// would hold the connection open instead of reporting the failure.
	var looping *httptest.Server
	looping = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, looping.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(looping.Close)

	engine := &server{rdapBase: looping.URL}
	if _, err := engine.rdapDomain(context.Background(), &http.Client{}, "example.com"); err == nil {
		t.Fatal("a redirect loop was followed instead of reported")
	}
}

func TestAsnOperatorReadsThePublicNetworkRecord(t *testing.T) {
	// This endpoint answers a bare list, not an envelope. A decoder written for
	// the envelope reads an empty record and reports "no operator" for a network
	// that plainly has one.
	body := `[{"asn":15169,"name":"Fixture Networks","website":"https://example.test",
	  "info_prefixes4":15000,"info_prefixes6":10000,"ix_count":175,
	  "policy_url":"https://example.test/peering","info_traffic":"Mostly Outbound","info_country":"US"}]`
	engine := &server{networkRecordBase: jsonFixture(t, body)}

	operator, err := engine.asnOperator(context.Background(), &http.Client{}, "AS15169")
	if err != nil {
		t.Fatalf("network record: %v", err)
	}
	if operator.Name != "Fixture Networks" || operator.IXCount != 175 || operator.PolicyURL == "" {
		t.Fatalf("operator = %#v", operator)
	}
}

func TestAsnNumberNormalisesEverySpelling(t *testing.T) {
	for _, value := range []string{"AS15169", "as15169", "15169", " 15169 ", "AS 15169"} {
		if got := asnNumber(value); got != "AS15169" {
			t.Fatalf("%q -> %q", value, got)
		}
	}
	// A value that is not a number has no answer, and inventing one would attach
	// an operator to an identity that does not exist.
	for _, value := range []string{"", "AS", "ASN15169", "AS0", "abc"} {
		if got := asnNumber(value); got != "" {
			t.Fatalf("%q -> %q, want no ASN", value, got)
		}
	}
}

func TestOriginASNsReadsTheBgpOriginFieldOnly(t *testing.T) {
	// The reply is `asn | prefix | country | rir | allocated`. Reading the
	// country as the ASN would attribute a country to a network.
	resolver := txtResolver{records: map[string][]string{
		"7.113.0.203.origin.asn.cymru.com": {"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"},
		"nothing.origin.asn.cymru.com":     {"64496 | 192.0.0.0/12 | US | arin | 2010-07-13"},
	}}
	asns, err := originASNs(context.Background(), resolver, "203.0.113.7")
	if err != nil {
		t.Fatalf("bgp origin: %v", err)
	}
	if len(asns) != 1 || asns[0] != "AS15169" {
		t.Fatalf("asns = %#v, want the first field only", asns)
	}
	// A name the database has never heard of is a fact about the address, so it
	// is silent rather than a warning on every address in a run.
	none, err := originASNs(context.Background(), txtResolver{}, "198.51.100.9")
	if err != nil || len(none) != 0 {
		t.Fatalf("an unknown address produced %#v / %v", none, err)
	}
}

// txtResolver is a resolver that answers from a table, so the BGP origin logic
// is asserted without a DNS server.
type txtResolver struct{ records map[string][]string }

func (r txtResolver) lookupHost(context.Context, string) ([]string, error) { return nil, nil }
func (r txtResolver) lookupHostReverse(context.Context, string) ([]string, error) {
	return nil, nil
}
func (r txtResolver) describe() string { return "a table" }
func (r txtResolver) lookupTXT(_ context.Context, name string) ([]string, error) {
	return r.records[strings.ToLower(name)], nil
}
func (r txtResolver) lookupMX(context.Context, string) ([]string, error) { return nil, nil }
func (r txtResolver) lookupNS(context.Context, string) ([]string, error) { return nil, nil }
func (r txtResolver) lookupCNAME(context.Context, string) (string, error) { return "", nil }
func (r txtResolver) lookupCAA(context.Context, string) ([]string, error) { return nil, nil }
func (r txtResolver) lookupSOA(context.Context, string) (string, error) { return "", nil }

func TestSharedHostNamesStopsAtItsOwnBoundAndSaysSo(t *testing.T) {
	var many []string
	for index := 0; index < coHostedNames+50; index++ {
		many = append(many, fmt.Sprintf("host-%d.test", index))
	}
	engine := &server{sharedHostBase: jsonFixture(t, strings.Join(many, "\n"))}
	names, note, err := engine.sharedHostNames(context.Background(), &http.Client{}, "203.0.113.7")
	if err != nil {
		t.Fatalf("shared-hosting lookup: %v", err)
	}
	if len(names) > coHostedNames {
		t.Fatalf("read %d names, above the bound %d", len(names), coHostedNames)
	}
	// A short answer must say it is short: "this address hosts exactly these"
	// and "these are the first N" are different claims.
	if note == "" {
		t.Fatalf("a bounded answer was not reported as bounded: %d names", len(names))
	}
}
