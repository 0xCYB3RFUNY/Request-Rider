package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// An encoded echo is not an injection.
//
// This file exists because a live run found the opposite, and it is the clearest
// case in the package of a green fixture proving nothing. The fixture that
// exercises every detector reflects parameters **raw**, so it exercised the echo
// stripping and never the case the stripping missed. A run against a real news
// site reported NoSQL, LDAP and XPath rows whose entire stated basis was that the
// probe answer and the decoy answer differed by about one character — the length
// of the submitted value. That site reflected the value into an `href` and into a
// script variable, percent-encoded. `stripEcho` matched the raw submission, found
// nothing, and the echo survived into the measurement; the three detectors read
// the escaping as a result set, and XPath reported it at `TierVerified`, the
// strongest claim this tool makes.
//
// The fixture below runs no database and evaluates nothing. It reflects the value,
// encoded, and that is all. Any differential-injection row it produces is a false
// positive by construction, so the assertion is the only one this test needs.
func TestAnEncodedEchoIsNotAnInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		// The two shapes a real site reflects a value in: a link, and a script
		// variable. Both are percent-encoded; neither is the raw submission.
		_, _ = w.Write([]byte(`<html><body><a href="/news?id=` +
			url.QueryEscape(value) + `">next</a>` +
			`<script>var id="` + url.QueryEscape(value) + `";</script>` +
			`<p>news</p></body></html>`))
	}))
	defer server.Close()

	start, _ := url.Parse(server.URL)
	start.Path = "/news"

	report, err := NewScan(ScanRequest{
		URL: start.String(), MaxPages: 2, MaxDepth: 1, Concurrency: 1,
		Timeout: 20 * time.Second, RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, f := range report.Findings {
		switch f.Module {
		case "nosql", "ldap", "xpath":
			t.Errorf("false positive: %s reported tier=%s on a page that only echoes the value: %s",
				f.Module, f.Tier, f.Title)
		}
	}
	t.Logf("points=%d findings=%d", len(report.Points), len(report.Findings))
}

// TestEchoVariantsCoverTheEncodedForms is the narrow guard for the half of the fix
// that is a data change rather than a control: `echoVariants` has to produce the
// percent-encoded shapes, because a variant list that forgets them is exactly the
// defect above wearing a different name.
func TestEchoVariantsCoverTheEncodedForms(t *testing.T) {
	const payload = `' OR 1=1 -- `

	want := map[string]bool{
		payload:                    true, // raw
		`&#39; OR 1=1 -- `:         true, // html.EscapeString
		`%27+OR+1%3D1+--+`:         true, // url.QueryEscape
		`%27%20OR%201%3D1%20--%20`: true, // encodeURIComponent's spaces
	}

	got := map[string]bool{}
	for _, v := range echoVariants(payload) {
		got[v] = true
	}

	for form := range want {
		if !got[form] {
			t.Errorf("echoVariants does not produce %q, so a page reflecting the value in that form keeps its echo", form)
		}
	}
}
