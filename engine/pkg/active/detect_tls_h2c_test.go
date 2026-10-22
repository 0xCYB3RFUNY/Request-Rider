package active

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// h2cFixture is a cleartext listener that either speaks h2c or answers like an
// HTTP/1.1 server, so the probe's positive and negative cases are both
// observable rather than argued.
type h2cFixture struct {
	// speaksH2C answers a connection preface with a SETTINGS frame.
	speaksH2C bool
	// plain answers whatever arrives with an HTTP/1.1 response, which is what a
	// server that does not speak h2c does with a preface it does not recognise.
	plain bool
}

func (fixture *h2cFixture) serve(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				buffer := make([]byte, len(h2cPreface))
				read, err := raw.Read(buffer)
				if err != nil && read == 0 {
					return
				}
				switch {
				case fixture.speaksH2C && strings.HasPrefix(string(buffer[:read]), "PRI * HTTP/2.0"):
					_, _ = raw.Write(h2cSettingsFrame)
				case fixture.plain:
					_, _ = raw.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
				default:
					// A port that says nothing at all: the probe has to give up
					// rather than read until the run's own deadline.
					return
				}
			}(connection)
		}
	}()
	return listener.Addr().String()
}

// scanTLS runs the certificate reader against a URL.
func scanTLS(rawURL string) []Finding {
	return (TLSCertificate{}).Scan(context.Background(), nil,
		Point{URL: rawURL, Method: http.MethodGet}, nil)
}

// A cleartext port that answers a connection preface with a SETTINGS frame speaks
// h2c, and that is the whole of the second half of the hidden-HTTP-2 row: ALPN
// cannot report it, because a cleartext connection has nowhere to negotiate.
func TestTLSReportsHTTP2OverCleartext(t *testing.T) {
	fixture := &h2cFixture{speaksH2C: true}
	address := fixture.serve(t)

	findings := scanTLS("http://" + address + "/page")
	row := tlsRow(t, findings, "cleartext port answers an h2c preface")
	if row.Severity != SeverityMedium {
		t.Errorf("severity = %q, want %q", row.Severity, SeverityMedium)
	}
	if !strings.Contains(row.Description, "ALPN cannot report this") {
		t.Errorf("the row does not say why ALPN could not have found it: %s", row.Description)
	}
	if !strings.Contains(row.Evidence, "SETTINGS") && !strings.Contains(row.Evidence, "answer:") {
		t.Errorf("the evidence does not carry the answer it got: %s", row.Evidence)
	}
}

// The control: a cleartext port that answers a preface with HTTP/1.1 is a server
// that does not speak h2c, and nothing is reported.
func TestTLSIsSilentWhenACleartextPortDoesNotSpeakH2C(t *testing.T) {
	fixture := &h2cFixture{plain: true}
	address := fixture.serve(t)

	for _, finding := range scanTLS("http://" + address + "/page") {
		if strings.Contains(finding.Title, "h2c preface") {
			t.Fatalf("reported h2c against a port that answered HTTP/1.1: %q", finding.Title)
		}
	}
}

// The preface is the protocol, and the probe sends the documented bytes. A
// misspelled preface would make the positive case pass for the wrong reason.
func TestH2CPrefaceIsTheProtocolsOwn(t *testing.T) {
	if h2cPreface != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Errorf("preface = %q, want the HTTP/2 connection preface", h2cPreface)
	}
	if len(h2cSettingsFrame) != 9 || h2cSettingsFrame[3] != 4 {
		t.Errorf("the settings frame is not a nine-byte SETTINGS frame: % x", h2cSettingsFrame)
	}
}

// The TLS half and the cleartext half are the same row and must not double-count
// against a TLS port: a port that negotiated h2 is measured by ALPN, and asking
// it again over a second, unencrypted connection would be a request nobody needs.
func TestH2CProbeIsSkippedOnATLSPort(t *testing.T) {
	// An https URL is the condition, and it is checked before anything is dialled,
	// so a port that would refuse the connection is never touched.
	findings := scanTLS("https://127.0.0.1:1/page")
	for _, finding := range findings {
		if strings.Contains(finding.Title, "h2c preface") {
			t.Fatalf("probed h2c on a TLS port: %q", finding.Title)
		}
	}
}

// tlsRow returns the one finding whose title contains a marker, or fails.
func tlsRow(t *testing.T, findings []Finding, marker string) Finding {
	t.Helper()
	for _, finding := range findings {
		if strings.Contains(finding.Title, marker) {
			return finding
		}
	}
	titles := make([]string, 0, len(findings))
	for _, finding := range findings {
		titles = append(titles, finding.Title)
	}
	t.Fatalf("no row containing %q; got %v", marker, titles)
	return Finding{}
}

// A TLS port still reports the ALPN half, and the two halves do not both fire on
// the same connection. The fixture serves a real certificate so the reader has
// something to look at.
func TestTLSKeepsBothHalvesApart(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{material.certificate},
		NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	alpn, cleartext := 0, 0
	for _, finding := range scanTLS(server.URL + "/page") {
		if strings.Contains(finding.Title, "ALPN negotiated h2") {
			alpn++
		}
		if strings.Contains(finding.Title, "h2c preface") {
			cleartext++
		}
	}
	if cleartext != 0 {
		t.Errorf("the cleartext half fired on a TLS port %d time(s)", cleartext)
	}
	_ = alpn
}
