package active

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The .NET fixture answers all three shapes: the trace endpoint, a debug-mode
// configuration, and a page whose ViewState is not encrypted.
func aspNetFixtureServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	viewState := base64.StdEncoding.EncodeToString(append([]byte{0x01},
		[]byte("/wEPDwUKLTE2NzM0NzYxNzlkZGQ=")...))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form action="/" method="post">` +
			`<input type="hidden" name="__VIEWSTATE" value="` + viewState + `">` +
			`</form></body></html>`))
	})
	mux.HandleFunc("/trace.axd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Application Trace</title></head><body>` +
			`<h1>Application Trace</h1><table id="tracedetails"><tr><th>Request Details</th></tr>` +
			`</table></body></html>`))
	})
	mux.HandleFunc("/web.config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<?xml version="1.0"?><configuration><system.web>` +
			`<compilation debug="true" targetFramework="4.8">` +
			`<customErrors mode="Off"></customErrors></system.web></configuration>`))
	})
	server := httptest.NewServer(mux)
	return server, viewState
}

func TestASPDotNetReportsAllThreeDisclosures(t *testing.T) {
	server, viewState := aspNetFixtureServer(t)
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: `<html><body><form action="/" method="post">` +
			`<input type="hidden" name="__VIEWSTATE" value="` + viewState + `">` +
			`</form></body></html>`}

	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	findings := (ASPDotNet{}).Scan(context.Background(), transport,
		Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3 (trace, debugging, unencrypted ViewState)", len(findings))
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.Title] = true
	}
	for _, want := range []string{
		"ASP.NET Tracing Enabled",
		"ASP.NET Debugging Enabled",
		"ASP.NET ViewState Carries an Unencrypted Payload",
	} {
		if !seen[want] {
			t.Errorf("missing %q; got %v", want, seen)
		}
	}
}

// The MAC is not claimable without the machine key, and the row must say so.
// A test that let the description assert the signature was missing would let a
// claim the detector cannot make into the report.
func TestASPDotNetViewStateRowDoesNotClaimTheMAC(t *testing.T) {
	server, viewState := aspNetFixtureServer(t)
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: `<html><body><input type="hidden" name="__VIEWSTATE" value="` + viewState + `">` +
			`</body></html>`}

	findings := aspViewState(Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	if findings == nil {
		t.Fatal("no ViewState row")
	}
	if strings.Contains(strings.ToLower(findings.Description), "not claim") == false {
		// The row must state the limit explicitly rather than leave it implied.
		if !strings.Contains(findings.Description, "does **not** claim") {
			t.Errorf("the row does not name the limit it is under: %s", findings.Description)
		}
	}
	if findings.Tier != TierPotential {
		t.Errorf("tier = %q, want potential", findings.Tier)
	}
}

// An encrypted ViewState (`0xFF`) is opaque and this run has nothing to read, so
// the module must be silent rather than reporting the byte it did not understand.
func TestASPDotNetIgnoresAnEncryptedViewState(t *testing.T) {
	encrypted := base64.StdEncoding.EncodeToString(append([]byte{0xFF, 0x01, 0x00, 0x00},
		[]byte("opaque-payload")...))
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: `<html><body><input type="hidden" name="__VIEWSTATE" value="` + encrypted + `">` +
			`</body></html>`}
	if findings := aspViewState(Point{URL: "https://example.com/", Method: http.MethodGet}, baseline); findings != nil {
		t.Fatalf("reported %q against an encrypted payload", findings.Title)
	}
}
