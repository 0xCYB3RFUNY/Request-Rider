package active

// Tests for the SSRF detector.
//
// The decisive test is TestSSRFReportsLoopbackFetch. The upstream detector's
// `reflectOnly` default branch returns `strings.Contains(body, payload)` after a
// guard that has already established it, so it is always true — which means every
// loopback and IPv6-loopback probe is dismissed as "the page echoed it". SSRF to
// localhost is never reported, silently, and a scan that cannot see it looks
// exactly like a scan that found nothing.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newSSRFFixture serves a parameter and decides what a value produces.
func newSSRFFixture(t *testing.T, respond func(value string) (int, string)) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, text := respond(r.URL.Query().Get("url"))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "url",
		Values: url.Values{"url": {"/local"}},
	}
}

func (SSRF) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return SSRF{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

const internalPage = "<html><head><title>Internal Admin</title></head><body>internal service</body></html>"

// The decisive case: a parameter that makes the server fetch its own loopback
// and returns what it found. The upstream implementation reports this never.
func TestSSRFReportsLoopbackFetch(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		if strings.HasPrefix(value, "http://127.0.0.1") || strings.HasPrefix(value, "http://localhost") {
			return 200, internalPage
		}
		return 200, "<html><body>normal page</body></html>"
	})
	findings := (SSRF{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: a loopback fetch is the cheapest proof there is", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Payload, "127.0.0.1") {
		t.Errorf("payload = %q, want the loopback URL", finding.Payload)
	}
	if !strings.Contains(finding.Evidence, "does not contain the requested URL") {
		t.Errorf("evidence = %q, want the reflection test stated", finding.Evidence)
	}
}

// A page that reflects the payload is not a fetch, whatever else it contains.
//
// The fixture is built so the echo check is actually reached. An earlier version
// of this test returned a page whose HTML tags were also in the baseline, so the
// freshness check rejected it first and the echo check was never executed — the
// test passed for a reason that had nothing to do with what it claimed to test.
// Here the response is genuinely different from the baseline *and* carries the
// payload, which is the ambiguous case: the server fetched, and also echoed.
func TestSSRFDoesNotReportAPageThatEchoedThePayload(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		if value == "/local" {
			// The baseline carries no head tag at all.
			return 200, "normal page"
		}
		// The response carries an internal page's markup *and* echoes what it was
		// asked to fetch. Both fingerprints are new, and the payload is present.
		return 200, "<html><head><title>fetched</title></head><body>you asked for " + value + "</body></html>"
	})
	findings := (SSRF{}).probe(t, transport, point)
	for _, finding := range findings {
		t.Fatalf("reported %q for a response that echoed the payload it was asked to fetch", finding.Title)
	}
}

// A fingerprint that was already on the page proves nothing about a fetch.
func TestSSRFDoesNotReportAFingerprintAlreadyOnThePage(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		return 200, "<html><body>This proxy returns <head> for errors. " + value + "</body></html>"
	})
	findings := (SSRF{}).probe(t, transport, point)
	for _, finding := range findings {
		t.Fatalf("reported %q for a fingerprint the page already carried", finding.Title)
	}
}

// Cloud metadata is a different severity from loopback and the report has to say
// which one it found.
func TestSSRFReportsCloudMetadataAsCritical(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		if strings.Contains(value, "169.254.169.254") {
			return 200, "ami-id\ni-0123456789abcdef\nlocal-ipv4\n"
		}
		return 200, "<html><body>normal</body></html>"
	})
	findings := (SSRF{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical for instance metadata", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "metadata") {
		t.Errorf("title = %q, want the resource named", findings[0].Title)
	}
}

// Loopback is tried before cloud metadata: it is the same proof for a quieter
// request, and a scanner that reaches for a metadata service before a loopback
// connection has the priorities backwards.
func TestSSRFTriesLoopbackBeforeCloudMetadata(t *testing.T) {
	loopback := -1
	for i, target := range ssrfTargets {
		if strings.HasPrefix(target.payload, "http://127.0.0.1") {
			loopback = i
		}
		if strings.Contains(target.payload, "169.254.169.254") && loopback >= 0 && i < loopback {
			t.Errorf("cloud metadata is at index %d, before loopback at %d", i, loopback)
		}
	}
	if loopback < 0 {
		t.Fatal("no loopback target configured")
	}
}

// Every target has to carry evidence. A target with no fingerprint can never
// report, so probing it is a request that buys nothing.
func TestSSRFTargetsAllCarryEvidence(t *testing.T) {
	if len(ssrfTargets) == 0 {
		t.Fatal("no targets configured")
	}
	seen := map[string]bool{}
	for i, target := range ssrfTargets {
		if target.name == "" {
			t.Errorf("target %d has no name", i)
		}
		if seen[target.name] {
			t.Errorf("target %q is listed twice", target.name)
		}
		seen[target.name] = true
		if target.payload == "" {
			t.Errorf("target %d has no payload", i)
		}
		if len(target.fingerprints) == 0 {
			t.Errorf("target %q has no fingerprint, so it can never report", target.name)
		}
		if target.claimed.Rank() < SeverityHigh.Rank() {
			t.Errorf("target %q claims %q; an internal fetch is at least high", target.name, target.claimed)
		}
		// The payload has to be a URL the parameter could accept.
		if !strings.HasPrefix(target.payload, "http://") {
			t.Errorf("target %q payload %q is not an http URL", target.name, target.payload)
		}
	}
}

// A target whose fingerprint is absent from the response produces nothing, and
// the probe stops at the first target that does produce something rather than
// sending the whole list.
func TestSSRFStopsAtTheFirstTargetThatAnswers(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		if strings.HasPrefix(value, "http://127.0.0.1") {
			return 200, internalPage
		}
		return 200, "<html><body>normal</body></html>"
	})
	findings := (SSRF{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "127.0.0.1") {
		t.Errorf("payload = %q, want the first target", findings[0].Payload)
	}
}

func TestSSRFReportsNothingWhenNothingIsFetched(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		return 200, "<html><body>nothing happened</body></html>"
	})
	if findings := (SSRF{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none", len(findings))
	}
}

func TestSSRFReportsNothingOnCancellation(t *testing.T) {
	transport, point := newSSRFFixture(t, func(value string) (int, string) {
		return 200, internalPage
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (SSRF{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

// judge is the whole contract of the module, asserted directly so a change to it
// cannot hide behind a scan.
func TestJudgeSeparatesFetchFromReflection(t *testing.T) {
	loopback := ssrfTargets[0]
	baseline := body("<html><body>normal page</body></html>")

	// Fetched: fingerprint new, payload absent.
	if judge(baseline, body(internalPage), loopback, testPoint()) == nil {
		t.Error("a fetch that returned the internal page was not judged a fetch")
	}
	// Echoed: payload present.
	if judge(baseline, body("<html><body>you asked for "+loopback.payload+"</body></html>"), loopback, testPoint()) != nil {
		t.Error("a page that echoed the payload was judged a fetch")
	}
	// Already present: fingerprint not new.
	if judge(body(internalPage), body(internalPage), loopback, testPoint()) != nil {
		t.Error("a fingerprint that was already on the page was judged a fetch")
	}
	// No baseline at all: "already there" cannot be ruled out.
	if judge(nil, body(internalPage), loopback, testPoint()) != nil {
		t.Error("judged a fetch with no baseline to compare against")
	}
	// No response at all.
	if judge(baseline, nil, loopback, testPoint()) != nil {
		t.Error("judged a fetch with no response")
	}
}
