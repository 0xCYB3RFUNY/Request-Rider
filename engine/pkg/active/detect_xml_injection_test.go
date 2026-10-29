package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func xmlTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport
}

func xmlFixtureServer(t *testing.T, raw bool) (*httptest.Server, *Response) {
	t.Helper()
	baselineBody := `<?xml version="1.0" encoding="UTF-8"?><result>abc</result>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if raw {
			// The defect: the value goes into the document unescaped.
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><result>` +
				r.URL.Query().Get("payload") + `</result>`))
			return
		}
		// The control: the value is encoded, so every metacharacter becomes
		// text rather than markup. A server that escaped *around* the value
		// but echoed the value itself raw would be the defect, not the
		// control, and the test says so by escaping the payload.
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><result>` +
			escapeXMLText(r.URL.Query().Get("payload")) + `</result>`))
	}))
	baseline := &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/xml"}},
		Body:       baselineBody,
	}
	return server, baseline
}

// escapeXMLText is the control server's own encoding, and it is what an
// application that treats the value as data does.
func escapeXMLText(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}

func xmlPoint(server *httptest.Server) Point {
	return Point{
		URL:    server.URL + "/xml",
		Method: http.MethodGet,
		Param:  "payload",
		Values: url.Values{"payload": {"abc"}},
	}
}

// The signal is that the injected metacharacters arrived as markup: the same
// bytes that were sent are in the document the server answered with.
func TestXMLInjectionReportsMarkupThatArrivedUnescaped(t *testing.T) {
	server, baseline := xmlFixtureServer(t, true)
	defer server.Close()

	findings := (XMLInjection{}).Scan(context.Background(), xmlTransport(t), xmlPoint(server), baseline)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: a raw echo of the sequence is the whole signal", len(findings))
	}
	if !strings.Contains(findings[0].Title, "XML Injection") {
		t.Errorf("title = %q", findings[0].Title)
	}
}

// The control is an application that encodes what it puts in the document. The
// sequence then reaches the response as text (`]]&gt;`), which is the same bytes
// read differently, and reporting it would be reporting escaping as a defect.
func TestXMLInjectionIsSilentOnAnEscapedResponse(t *testing.T) {
	server, baseline := xmlFixtureServer(t, false)
	defer server.Close()

	findings := (XMLInjection{}).Scan(context.Background(), xmlTransport(t), xmlPoint(server), baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 against a server that encodes", len(findings))
	}
}

// An HTML endpoint is out of scope: injecting XML markup into a page that is
// parsed as HTML is the XSS family's question, and a module that asked it again
// would spend requests to re-report another detector's finding.
func TestXMLInjectionSkipsAResponseThatIsNotXML(t *testing.T) {
	baseline := &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       "<html><body>abc</body></html>",
	}
	findings := (XMLInjection{}).Scan(context.Background(), xmlTransport(t),
		Point{URL: "http://example.com/", Method: http.MethodGet}, baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
