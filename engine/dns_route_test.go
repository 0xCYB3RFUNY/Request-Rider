package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A SOCKS5 route cannot carry DNS: Tor relays refuse to exit on port 53, so a
// resolver query sent through the route comes back as a timeout. Measured
// 2026-09-29 with a live Tor route: `dns_records` on `vk.ru` resolved nothing
// and warned `lookup vk.ru on 91.239.100.100:53: i/o timeout`, while the same
// engine answered an HTTPS query over the same route. The fix is to ask over
// HTTPS, and these tests hold that the routed path really asks over HTTPS and
// the direct path really does not.
func dohFixture(t *testing.T, body string, status int) (*httptest.Server, *[]string) {
	t.Helper()
	asked := &[]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*asked = append(*asked, r.URL.String())
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server, asked
}

func TestRouteResolverUsesTheSystemResolverWithoutARoute(t *testing.T) {
	resolver := resolverForContext(context.Background(), &http.Client{}, &server{})
	if _, ok := resolver.(systemResolver); !ok {
		t.Fatalf("an unrouted run resolved through %T, want the system resolver", resolver)
	}
	if got := resolver.describe(); !strings.Contains(got, "system resolver") {
		t.Fatalf("describe = %q", got)
	}
}

func TestDohResolverReadsBothAddressFamilies(t *testing.T) {
	// One question returns A and AAAA; a CNAME and a TXT are not addresses and
	// must not be read as such.
	body := `{"Status":0,"Answer":[
	  {"type":5,"data":"edge.example.test."},
	  {"type":1,"data":"93.184.216.34"},
	  {"type":28,"data":"2606:2800:220:1:248:1893:25c8:1946"},
	  {"type":16,"data":"v=spf1 -all"}
	]}`
	server, asked := dohFixture(t, body, 0)
	resolver := dohResolver{client: server.Client(), endpoints: []string{server.URL + "/dns-query"}}

	addresses, err := resolver.lookupHost(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("doh lookup: %v", err)
	}
	if len(addresses) != 2 || addresses[0] != "93.184.216.34" || addresses[1] != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Fatalf("addresses = %#v, want the A and the AAAA and nothing else", addresses)
	}
	if len(*asked) != 1 {
		t.Fatalf("the name took %d questions, want one: %#v", len(*asked), *asked)
	}
	// A resolver is a question, not a decision: the requested name and type have
	// to be on the wire, or the answer is about something else.
	if !strings.Contains((*asked)[0], "name=example.test.") || !strings.Contains((*asked)[0], "type=A") {
		t.Fatalf("the question is not the one asked: %q", (*asked)[0])
	}
}

func TestDohResolverTreatsNXDOMAINAsAnAnswer(t *testing.T) {
	server, _ := dohFixture(t, `{"Status":3}`, 0)
	resolver := dohResolver{client: server.Client(), endpoints: []string{server.URL + "/dns-query"}}
	// A name that does not exist is a fact about the name, not a broken
	// resolver: reporting it as an error would fail a whole discovery phase on
	// one free subdomain.
	addresses, err := resolver.lookupHost(context.Background(), "no-such-name.test")
	if err != nil {
		t.Fatalf("NXDOMAIN must be an answer, not a failure: %v", err)
	}
	if len(addresses) != 0 {
		t.Fatalf("NXDOMAIN returned addresses: %#v", addresses)
	}
}

func TestDohResolverFallsBackToTheSecondResolver(t *testing.T) {
	// The first endpoint refuses, the second answers. Dropping a resolver because
	// it is briefly unreachable is how a routed run loses its names entirely.
	good, _ := dohFixture(t, `{"Status":0,"Answer":[{"type":1,"data":"203.0.113.7"}]}`, 0)
	refused, _ := dohFixture(t, `upstream is down`, http.StatusServiceUnavailable)

	resolver := dohResolver{client: good.Client(), endpoints: []string{refused.URL + "/dns-query", good.URL + "/dns-query"}}
	addresses, err := resolver.lookupHost(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("doh lookup: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "203.0.113.7" {
		t.Fatalf("addresses = %#v", addresses)
	}
}

func TestDohResolverReportsAnUnusableAnswerInsteadOfPretending(t *testing.T) {
	server, _ := dohFixture(t, `{"Status":2,"Comment":"servfail at upstream"}`, 0)
	resolver := dohResolver{client: server.Client(), endpoints: []string{server.URL + "/dns-query"}}
	if _, err := resolver.lookupHost(context.Background(), "example.test"); err == nil {
		t.Fatal("a servfail was reported as a successful lookup")
	} else if !strings.Contains(err.Error(), "servfail") {
		t.Fatalf("the resolver's own explanation was dropped: %v", err)
	}
}

func TestDohResolverNamesTheMechanismItUses(t *testing.T) {
	resolver := dohResolver{client: &http.Client{}}
	if got := resolver.describe(); !strings.Contains(got, "DNS-over-HTTPS") {
		t.Fatalf("describe = %q, a warning must say which resolver failed", got)
	}
}

func TestDohResolverReadsCNAMECNAAAndSOA(t *testing.T) {
	cnameBody := `{"Status":0,"Answer":[{"type":5,"data":"target.example.test."}]}`
	cnameSrv, _ := dohFixture(t, cnameBody, 0)
	cnameResolver := dohResolver{client: cnameSrv.Client(), endpoints: []string{cnameSrv.URL + "/dns-query"}}
	cname, err := cnameResolver.lookupCNAME(context.Background(), "alias.example.test")
	if err != nil {
		t.Fatalf("lookupCNAME failed: %v", err)
	}
	if cname != "target.example.test" {
		t.Fatalf("cname = %q, want target.example.test", cname)
	}

	caaBody := `{"Status":0,"Answer":[{"type":257,"data":"0 issue \"letsencrypt.org\""}]}`
	caaSrv, _ := dohFixture(t, caaBody, 0)
	caaResolver := dohResolver{client: caaSrv.Client(), endpoints: []string{caaSrv.URL + "/dns-query"}}
	caa, err := caaResolver.lookupCAA(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("lookupCAA failed: %v", err)
	}
	if len(caa) != 1 || caa[0] != `0 issue "letsencrypt.org"` {
		t.Fatalf("caa = %#v", caa)
	}

	soaBody := `{"Status":0,"Answer":[{"type":6,"data":"ns1.example.test. hostmaster.example.test. 2026101201 7200 3600 1209600 3600"}]}`
	soaSrv, _ := dohFixture(t, soaBody, 0)
	soaResolver := dohResolver{client: soaSrv.Client(), endpoints: []string{soaSrv.URL + "/dns-query"}}
	soa, err := soaResolver.lookupSOA(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("lookupSOA failed: %v", err)
	}
	if !strings.Contains(soa, "ns1.example.test") {
		t.Fatalf("soa = %q", soa)
	}
}
