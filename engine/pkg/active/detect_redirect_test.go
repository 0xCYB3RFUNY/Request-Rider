package active

// Tests for the open redirect detector.
//
// The decisive test is TestRedirectDoesNotAcceptAHostThatMerelyEndsWithThe
// Marker. The upstream implementation compares hosts with a suffix test, so
// `notrd.example.invalid` and `rd.example.invalid.attacker.test` both pass — two
// hosts that end with the operator's name and resolve wherever their owner wants,
// which is the opposite of what the finding claims.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testMarker = "rr-redirect-probe.invalid"

// newRedirectFixture serves a parameter and decides the response for a value.
func newRedirectFixture(t *testing.T, respond func(value string) (int, http.Header, string)) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, header, text := respond(r.URL.Query().Get("next"))
		for name, values := range header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "next",
		Values: url.Values{"next": {"/home"}},
	}
}

func (m Redirect) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return m.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

// A Location header naming the operator's own host is proof: the application
// sent a browser where the attacker asked.
func TestRedirectReportsAHeaderRedirectToTheMarker(t *testing.T) {
	transport, point := newRedirectFixture(t, func(value string) (int, http.Header, string) {
		if strings.Contains(value, testMarker) {
			return http.StatusFound, http.Header{"Location": {"https://" + testMarker + "/landed"}}, ""
		}
		return http.StatusOK, nil, "<html><body>home</body></html>"
	})
	findings := (Redirect{MarkerHost: testMarker}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: the Location header is the evidence", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Evidence, testMarker) {
		t.Errorf("evidence = %q, want the header quoted", finding.Evidence)
	}
	if finding.PoCCurl == "" {
		t.Error("no reproduction attached")
	}
}

// The decisive case. These hosts all end with the operator's name and none of
// them is the operator's host.
func TestRedirectDoesNotAcceptAHostThatMerelyEndsWithTheMarker(t *testing.T) {
	cases := []string{
		"https://notrr-redirect-probe.invalid/",
		"https://attacker-rr-redirect-probe.invalid/",
		"https://rr-redirect-probe.invalid.attacker.test/",
		"https://evil.test/rr-redirect-probe.invalid",
	}
	for _, location := range cases {
		if redirectsOffSite(location, testMarker) {
			t.Errorf("redirectsOffSite(%q) = true; a suffix match is not a host match", location)
		}
	}
	if !redirectsOffSite("https://"+testMarker+"/landed", testMarker) {
		t.Error("the marker's own host was not recognised")
	}
	// A port is part of where a request goes, not part of the host's name.
	if !redirectsOffSite("https://"+testMarker+":8443/landed", testMarker) {
		t.Error("a marker host on an explicit port was not recognised")
	}
	// A relative Location is the server redirecting within itself.
	if redirectsOffSite("/login/next", testMarker) {
		t.Error("a relative Location was treated as an off-site redirect")
	}
}

// A redirect within the same site is ordinary navigation.
func TestRedirectIgnoresOnSiteNavigation(t *testing.T) {
	transport, point := newRedirectFixture(t, func(value string) (int, http.Header, string) {
		return http.StatusFound, http.Header{"Location": {"/account/settings"}}, ""
	})
	if findings := (Redirect{MarkerHost: testMarker}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none for a redirect within the site", len(findings))
	}
}

// The client-side case needs both halves: a reflected destination and a
// navigation primitive. A page with only a primitive is ordinary navigation; a
// page that reflects without acting on it is a reflection, and the XSS detector
// owns that.
func TestRedirectNeedsReflectionAndAPrimitiveTogether(t *testing.T) {
	withBoth := "<html><body>redirecting to " + testMarker + "...<script>window.location=\"go\"</script></body></html>"
	primitiveOnly := "<html><body><script>window.location=\"/home\"</script></body></html>"
	reflectOnly := "<html><body>you asked for " + testMarker + "</body></html>"

	if !reflectClientRedirect(withBoth, testMarker) {
		t.Error("a page with both a reflection and a primitive was not recognised")
	}
	if reflectClientRedirect(primitiveOnly, testMarker) {
		t.Error("a page with a primitive but no reflection was accepted")
	}
	if reflectClientRedirect(reflectOnly, testMarker) {
		t.Error("a page with a reflection but no primitive was accepted")
	}
}

// Without a marker the detector cannot tell an off-site redirect from ordinary
// navigation, so it must say nothing rather than report every redirect a site
// does.
// The same rule as above, exercised through the scan rather than through the
// helper: a page carrying a navigation primitive and no reflection of the
// destination is ordinary navigation, and the detector has to stay silent on it.
func TestRedirectScanIgnoresAPageWithAPrimitiveButNoReflection(t *testing.T) {
	transport, point := newRedirectFixture(t, func(value string) (int, http.Header, string) {
		if strings.Contains(value, testMarker) {
			return http.StatusOK, nil, `<html><body><script>window.location="/home"</script></body></html>`
		}
		return http.StatusOK, nil, `<html><body><script>window.location="/home"</script></body></html>`
	})
	if findings := (Redirect{MarkerHost: testMarker}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none: a navigation primitive with no reflected destination", len(findings))
	}
}

func TestRedirectReportsNothingWithoutAMarker(t *testing.T) {
	transport, point := newRedirectFixture(t, func(value string) (int, http.Header, string) {
		return http.StatusFound, http.Header{"Location": {"https://anywhere.example/"}}, ""
	})
	if findings := (Redirect{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none with no marker configured", len(findings))
	}
}

// A parameter that redirects nowhere is not a finding.
func TestRedirectReportsNothingWhenTheParameterIsNotARedirect(t *testing.T) {
	transport, point := newRedirectFixture(t, func(value string) (int, http.Header, string) {
		return http.StatusOK, nil, "<html><body>results for " + value + "</body></html>"
	})
	if findings := (Redirect{MarkerHost: testMarker}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none", len(findings))
	}
}

func TestRedirectReportsNothingOnCancellation(t *testing.T) {
	transport, point := newRedirectFixture(t, func(value string) (int, http.Header, string) {
		return http.StatusFound, http.Header{"Location": {"https://" + testMarker}}, ""
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (Redirect{MarkerHost: testMarker}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

// Every vector has to actually carry the marker, and each has to be a different
// string — a duplicate in the table costs a request and proves nothing the first
// one did not.
func TestRedirectVectorsAreDistinctAndCarryTheMarker(t *testing.T) {
	if len(redirectVectors) == 0 {
		t.Fatal("no vectors configured")
	}
	seen := map[string]string{}
	for _, vector := range redirectVectors {
		payload := vector.build(testMarker)
		if !strings.Contains(payload, testMarker) {
			t.Errorf("vector %q built %q, which does not name the marker", vector.name, payload)
		}
		if previous, clash := seen[payload]; clash {
			t.Errorf("vectors %q and %q build the same payload %q", previous, vector.name, payload)
		}
		seen[payload] = vector.name
	}
}

// The userinfo vector is the one that separates the host a browser displays from
// the host it connects to, and it is the reason an exact host comparison matters.
func TestRedirectUserinfoVectorPutsTheRealDestinationLast(t *testing.T) {
	payload := "https://trusted.test@" + testMarker
	parsed, err := url.Parse(payload)
	if err != nil {
		t.Fatalf("payload %q does not parse: %v", payload, err)
	}
	if parsed.Hostname() != testMarker {
		t.Fatalf("hostname = %q, want %q; a browser connects to the last @", parsed.Hostname(), testMarker)
	}
	if parsed.User == nil {
		t.Fatal("userinfo is not parsed; the vector does not test what it claims")
	}
	if !redirectsOffSite(payload, testMarker) {
		t.Error("the userinfo payload was not recognised as pointing at the marker")
	}
}
