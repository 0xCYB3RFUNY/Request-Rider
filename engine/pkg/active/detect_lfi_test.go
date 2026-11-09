package active

// Tests for the local file inclusion detector.
//
// The defect this module was written to correct has exactly one test, and it is
// the first one here: a page that already shows a passwd file's contents must
// not be reported as a file read. The upstream module has no baseline check at
// all, so it reports that page, and reporting it is how a scanner teaches an
// operator to stop reading its rows.

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// lfiFixture serves one parameter, with a page template the test controls.
type lfiFixture struct {
	render func(value string) string
	served map[string]bool
}

func newLFFixture(t *testing.T, render func(string) string) (*Transport, Point, *lfiFixture) {
	t.Helper()
	fixture := &lfiFixture{render: render, served: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("file")
		fixture.served[value] = true
		_, _ = io.WriteString(w, fixture.render(value))
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "file",
		Values: url.Values{"file": {"index.html"}},
	}, fixture
}

func (LFI) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return LFI{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

const realPasswd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

// A file that was served because of the injected path is proof, not a pattern.
func TestLFIReportsAFileActuallyServed(t *testing.T) {
	transport, point, _ := newLFFixture(t, func(value string) string {
		if value != "index.html" {
			return realPasswd
		}
		return "<html><body>Index page</body></html>"
	})
	findings := (LFI{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: the file content came back", finding.Tier, TierVerified)
	}
	if finding.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", finding.Severity)
	}
	if !strings.Contains(finding.Payload, "etc/passwd") {
		t.Errorf("payload = %q, want the path that was requested", finding.Payload)
	}
	if !strings.Contains(finding.Evidence, "root:x:0:0:") {
		t.Errorf("evidence = %q, want the served line quoted", finding.Evidence)
	}
}

// The decisive test. The page already displays the contents of a passwd file,
// on every request, injection or not. A baseline-free detector reports
// arbitrary file read on this page for every parameter it has.
func TestLFIIgnoresAFingerprintAlreadyOnThePage(t *testing.T) {
	transport, point, _ := newLFFixture(t, func(value string) string {
		// A documentation page that shows an example file listing.
		return `<html><body><h1>Example /etc/passwd</h1><pre>` + realPasswd + `</pre></body></html>`
	})
	findings := (LFI{}).probe(t, transport, point)
	if len(findings) != 0 {
		t.Fatalf("findings = %d (%s), want none: the fingerprint was on the page before the injection",
			len(findings), findings[0].Title)
	}
}

// A page that already quotes *a* passwd-shaped line is not thereby immune. The
// check is for the fingerprint, not for the shape: a documentation page showing
// `root:x:1000:1000:` still fails the test, and a served root account still
// passes it.
func TestLFIReportsWhenOnlyTheInjectedResponseHasTheFingerprint(t *testing.T) {
	transport, point, _ := newLFFixture(t, func(value string) string {
		if value != "index.html" {
			return realPasswd
		}
		return `<html><body><p>example: root:x:1000:1000:app:/srv:/sbin/nologin</p></body></html>`
	})
	findings := (LFI{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the full fingerprint is new even though a fragment was present",
			len(findings))
	}
}

// The base64 wrapper returns the file encoded, so a plain-text search finds
// nothing. Matching the encoded form is what makes the technique work, and the
// evidence quotes the decoded text the operator can actually read.
func TestLFIDetectsTheBase64Wrapper(t *testing.T) {
	// A real wrapper returns the whole file encoded, so the fixture encodes the
	// whole file rather than a hand-picked prefix: base64 of a prefix is not a
	// prefix of the base64 of the file, and a test that got that wrong would be
	// testing its own encoding rather than the technique.
	encoded := base64.StdEncoding.EncodeToString([]byte(realPasswd))
	transport, point, _ := newLFFixture(t, func(value string) string {
		if value != "index.html" {
			return encoded
		}
		return "<html><body>Index</body></html>"
	})
	findings := (LFI{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 for a base64-encoded file read", len(findings))
	}
	if !strings.Contains(findings[0].Title, "php filter") {
		t.Errorf("title = %q, want the wrapper named", findings[0].Title)
	}
	if strings.Contains(findings[0].Evidence, "cm9vdDp4") {
		t.Errorf("evidence = %q, want the decoded text rather than the matched base64", findings[0].Evidence)
	}
	if !strings.Contains(findings[0].Evidence, "root:x:0:0:") {
		t.Errorf("evidence = %q, want the decoded first line of the file", findings[0].Evidence)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical: a wrapper discloses source without traversal", findings[0].Severity)
	}
}

// The shadow file is a different severity from passwd, and the fingerprint has
// to be its own — a response that leaks passwd does not leak shadow.
func TestLFISeparatesShadowFromPasswd(t *testing.T) {
	transport, point, _ := newLFFixture(t, func(value string) string {
		if value == "index.html" {
			return "<html><body>Index</body></html>"
		}
		return "root:$1$abc$def:19000:0:99999:7:::\n"
	})
	findings := (LFI{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical for a shadow read", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Payload, "etc/shadow") {
		t.Errorf("payload = %q, want the shadow path", findings[0].Payload)
	}
}

// A parameter that has already proven it will serve files does not get six
// more requests to prove it again.
func TestLFIStopsAtTheFirstTechniqueThatAnswers(t *testing.T) {
	transport, point, fixture := newLFFixture(t, func(value string) string {
		if value != "index.html" {
			return realPasswd
		}
		return "<html><body>Index</body></html>"
	})
	(LFI{}).probe(t, transport, point)
	probes := 0
	for value := range fixture.served {
		if value != "index.html" {
			probes++
		}
	}
	if probes != 1 {
		t.Fatalf("sent %d probes after the first one answered, want 1", probes)
	}
}

// A parameter that serves nothing gets every technique tried, and reports
// nothing.
func TestLFIReportsNothingWhenNoFileIsServed(t *testing.T) {
	transport, point, _ := newLFFixture(t, func(value string) string {
		return `<html><body>Not found: ` + xssUnescape(value) + `</body></html>`
	})
	if findings := (LFI{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none for a parameter that serves no file", len(findings))
	}
}

func TestLFIReportsNothingOnCancellation(t *testing.T) {
	transport, point, _ := newLFFixture(t, func(value string) string { return realPasswd })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (LFI{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

// Every technique must carry at least one fingerprint, or it can never produce
// evidence and is a request that buys nothing.
func TestLFITechniquesAllCarryProof(t *testing.T) {
	if len(lfiTechniques) == 0 {
		t.Fatal("no techniques configured")
	}
	seen := map[string]bool{}
	for i, technique := range lfiTechniques {
		if technique.name == "" {
			t.Errorf("technique %d has no name", i)
		}
		if seen[technique.name] {
			t.Errorf("technique %q is listed twice; a duplicate sends the same request twice", technique.name)
		}
		seen[technique.name] = true
		if len(technique.fingerprints) == 0 {
			t.Errorf("technique %q has no fingerprint, so it can never report", technique.name)
		}
		for _, fingerprint := range technique.fingerprints {
			if strings.TrimSpace(fingerprint) == "" {
				t.Errorf("technique %q has an empty fingerprint, which every body contains", technique.name)
			}
		}
		if technique.payload == "" {
			t.Errorf("technique %q has no payload", technique.name)
		}
		if technique.description == "" {
			t.Errorf("technique %q has no description", technique.name)
		}
		if technique.claimed.Rank() < SeverityHigh.Rank() {
			t.Errorf("technique %q claims %q; a file read is at least high", technique.name, technique.claimed)
		}
	}
}

// A technique whose payload does not name the file its fingerprint belongs to
// would report a file it never asked for.
func TestLFIFingerprintsBelongToTheRequestedFile(t *testing.T) {
	for _, technique := range lfiTechniques {
		payload := strings.ToLower(technique.payload)
		switch {
		case strings.Contains(payload, "passwd"):
			if !strings.Contains(strings.Join(technique.fingerprints, "|"), "cm9vdDp4OjA6") &&
				!strings.Contains(strings.Join(technique.fingerprints, "|"), passwdFingerprint[:9]) {
				t.Errorf("technique %q requests passwd but has no passwd fingerprint", technique.name)
			}
		case strings.Contains(payload, "shadow"):
			if !strings.Contains(strings.Join(technique.fingerprints, "|"), "root:$") {
				t.Errorf("technique %q requests shadow but has no shadow fingerprint", technique.name)
			}
		}
	}
}
