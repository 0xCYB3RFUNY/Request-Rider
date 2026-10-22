package active

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsMaterial is a certificate this test controls, so the properties a detector
// reads — the names it covers, the dates it is valid for, the algorithm that
// signed it — are chosen here rather than hoped for.
//
// A test that used a generated certificate and asserted on whatever it happened
// to get would pass for the wrong reason: "a certificate row was produced" would
// be satisfied by any defect the generator happened to introduce.
type tlsMaterial struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
}

// makeCertificate builds a leaf certificate with exactly the properties the
// caller names.
//
// `addresses` is separate from `names` on purpose: a certificate that lists an
// IP address covers the host reached over loopback, and a test that wanted a
// hostname mismatch would trip over its own fixture rather than over the code.
func makeCertificate(t *testing.T, commonName string, notBefore, notAfter time.Time,
	names []string, addresses []net.IP) tlsMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(20261015),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Request-Rider fixture"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              names,
		IPAddresses:           addresses,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tlsMaterial{certificate: tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}, leaf: leaf}
}

// loopbackAddress is what a fixture listening on 127.0.0.1 is reached as.
func loopbackAddress() net.IP { return net.ParseIP("127.0.0.1") }

// tlsServer starts an HTTPS server presenting the given certificate.
func tlsServer(t *testing.T, material tlsMaterial, nextProtos []string) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{material.certificate},
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// runTLS reads the certificate the host at the URL presents, through the
// detector's own probe, which is the only vantage point that can see a
// certificate the run's client would have refused.
func runTLS(t *testing.T, rawURL string) []Finding {
	t.Helper()
	findings := (TLSCertificate{}).Scan(context.Background(), nil,
		Point{URL: rawURL, Method: http.MethodGet}, nil)
	return findings
}

// An in-date certificate for its own host has nothing wrong with it, and a
// detector that cannot stay silent on that case is a detector that will report
// noise on every site.
func TestTLSCertificateIsSilentOnAValidCertificate(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	server := tlsServer(t, material, []string{"http/1.1"})

	findings := runTLS(t, server.URL)
	for _, finding := range findings {
		if finding.Severity != SeverityInfo {
			t.Errorf("a valid certificate produced %q", finding.Title)
		}
	}
}

// The whole reason this module opens its own connection: a certificate the run's
// client would have refused is exactly the certificate worth reporting, and a
// detector reading the run's own handshake could never see it.
func TestTLSCertificateReportsAnExpiredCertificate(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(-72*time.Hour), time.Now().Add(-time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	server := tlsServer(t, material, []string{"http/1.1"})

	row := findRow(t, runTLS(t, server.URL), "expired")
	if !strings.Contains(row.Description, "expired on") {
		t.Errorf("the row does not name the date it expired: %s", row.Description)
	}
	if !strings.Contains(row.Evidence, "serial:") || !strings.Contains(row.Evidence, "valid:") {
		t.Errorf("the evidence does not carry the certificate's own facts: %s", row.Evidence)
	}
	if !strings.Contains(row.Title, "0x01000100") {
		t.Errorf("title = %q, want the original's identifier in it", row.Title)
	}
	if row.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: the certificate was read, not inferred", row.Tier, TierVerified)
	}
}

// A certificate for a name the client did not ask for is the mismatch, and it is
// what a client that skips name verification silently accepts.
func TestTLSCertificateReportsAHostnameMismatch(t *testing.T) {
	material := makeCertificate(t, "other.example", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
		[]string{"other.example"}, nil)
	server := tlsServer(t, material, []string{"http/1.1"})

	row := findRow(t, runTLS(t, server.URL), "hostname mismatch")
	if !strings.Contains(row.Description, "other.example") {
		t.Errorf("the row does not name what the certificate covers: %s", row.Description)
	}
}

// A certificate that is not yet valid is the other half of the same clock
// problem, and reporting only one of them would leave a badly-skewed host half
// described.
func TestTLSCertificateReportsACertificateThatIsNotYetValid(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(72*time.Hour), time.Now().Add(96*time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	server := tlsServer(t, material, []string{"http/1.1"})

	findRow(t, runTLS(t, server.URL), "not yet valid")
}

// The recording-CA row exists because a run whose transport records never sees
// the target's chain, and a report that stayed silent there would leave the
// reader assuming a chain it never looked at.
func TestTLSCertificateSaysWhenItIsLookingAtTheRecordingProxy(t *testing.T) {
	material := makeCertificate(t, "Request-Rider recording CA", time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour), []string{"localhost"}, []net.IP{loopbackAddress()})
	server := tlsServer(t, material, []string{"http/1.1"})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: material.leaf.Raw}), 0o600); err != nil {
		t.Fatalf("write the recording CA: %v", err)
	}
	t.Setenv("CA_CERT", certPath)

	row := findRow(t, runTLS(t, server.URL), "Not Observed")
	if row.Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q: an absent observation is not a defect in the target",
			row.Severity, SeverityInfo)
	}
	if !strings.Contains(row.Description, "was **not** observed") {
		t.Errorf("the row does not say the target's chain was not seen: %s", row.Description)
	}
}

// With the recording CA in the path, the module must not also issue a verdict
// about the proxy's certificate: that verdict is a claim about the wrong host,
// and the row above is already the honest account of what happened.
func TestTLSCertificateDoesNotJudgeTheProxyCertificate(t *testing.T) {
	// Expired, and issued by what the recording-CA file names — two defects, both
	// of them about a certificate that is not the target's.
	material := makeCertificate(t, "Request-Rider recording CA", time.Now().Add(-72*time.Hour),
		time.Now().Add(-time.Hour), []string{"localhost"}, []net.IP{loopbackAddress()})
	server := tlsServer(t, material, []string{"http/1.1"})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: material.leaf.Raw}), 0o600); err != nil {
		t.Fatalf("write the recording CA: %v", err)
	}
	t.Setenv("CA_CERT", certPath)

	for _, finding := range runTLS(t, server.URL) {
		if strings.Contains(finding.Title, "expired") {
			t.Fatalf("issued a verdict about the proxy's own certificate: %q", finding.Title)
		}
	}
}

// Hidden HTTP 2 is the disagreement: the connection negotiates h2 and the host
// answers 1.1 text. The fixture below is exactly that server, and the control is
// the same server answering in binary frames instead.
// TestTLSCertificateReportsHiddenHTTP2OnAConnectionThatNegotiatedH2 is the
// positive case: the host offers `h2`, the handshake settles on it, and the
// answer to an HTTP/1.1 request comes back as HTTP/1.1 text.
func TestTLSCertificateReportsHiddenHTTP2OnANegotiatedH2Connection(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	address := deceptiveTLSServer(t, material, []string{"h2"}, true)

	row := findRow(t, runTLS(t, "https://"+address), "Hidden HTTP 2")
	if !strings.Contains(row.Evidence, "negotiated protocol: h2") {
		t.Errorf("the evidence does not name the negotiated protocol: %s", row.Evidence)
	}
	if !strings.Contains(row.Payload, "HTTP/1.1 200") {
		t.Errorf("payload = %q, want the status line the host actually sent", row.Payload)
	}
	if !strings.Contains(row.Title, "0x01000500") {
		t.Errorf("title = %q, want the original's identifier in it", row.Title)
	}
}

// The control: the same negotiation, answered in binary frames. Nothing is being
// hidden when the host speaks the protocol it agreed to, so the detector has to
// be silent — and this is what proves the positive case above is not simply
// "ALPN said h2".
func TestTLSCertificateIsSilentWhenTheHostSpeaksTheProtocolItNegotiated(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	address := deceptiveTLSServer(t, material, []string{"h2"}, false)

	for _, finding := range runTLS(t, "https://"+address) {
		if strings.Contains(finding.Title, "Hidden HTTP 2") {
			t.Fatalf("fired against a host that answered in its negotiated protocol: %q", finding.Title)
		}
	}
}

// deceptiveTLSServer is a TLS listener that settles on the protocols it is told
// to offer and then answers with whatever the test wants it to answer with.
//
// It exists because the shape under test cannot be produced by `httptest`: a
// server that negotiates `h2` through httptest answers in HTTP/2, which is
// precisely the control case.
func deceptiveTLSServer(t *testing.T, material tlsMaterial, alpn []string, answerHTTP11Text bool) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{material.certificate},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS12,
	})
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
			go func(secure net.Conn) {
				defer secure.Close()
				_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(secure)
				// Consume the request head so the answer lands after it.
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				if answerHTTP11Text {
					_, _ = secure.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
					return
				}
				// An HTTP/2 connection preface followed by a SETTINGS frame: the
				// bytes a client parsing HTTP/1.1 would see instead of a status line.
				_, _ = secure.Write([]byte{'P', 'R', 'I', 'E', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', 0, 0, 0, 4, 0, 0, 0, 0})
			}(connection)
		}
	}()
	return listener.Addr().String()
}

// The pure readings are checked against values rather than against a handshake
// that would have to be built to produce them.
func TestWeakSignatureAndDeprecatedVersionReadTheLeaf(t *testing.T) {
	material := makeCertificate(t, "loopback", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
		[]string{"localhost"}, []net.IP{loopbackAddress()})
	if got := weakSignatureDescription(material.leaf); got != "" {
		t.Errorf("a P-256 certificate was called %q", got)
	}
	for name, version := range map[string]uint16{
		"TLS 1.0": tls.VersionTLS10,
		"TLS 1.1": tls.VersionTLS11,
		"SSL 3.0": tls.VersionSSL30,
	} {
		if got := deprecatedTLSVersion(version); got != name {
			t.Errorf("deprecatedTLSVersion(%s) = %q, want %q", name, got, name)
		}
	}
	if got := deprecatedTLSVersion(tls.VersionTLS13); got != "" {
		t.Errorf("TLS 1.3 was called %q", got)
	}
	if got := tlsVersionName(tls.VersionTLS13); got != "TLS 1.3" {
		t.Errorf("tlsVersionName(1.3) = %q", got)
	}
}

// A host that is not there produces no row rather than an error-shaped one: the
// run already reports unreachable hosts elsewhere, and a certificate row about a
// host that answered nothing would be a second, weaker account of the same fact.
func TestTLSCertificateIsSilentForAHostThatDoesNotAnswer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	if findings := runTLS(t, "https://"+address); len(findings) != 0 {
		t.Fatalf("findings = %d for a host that does not answer", len(findings))
	}
}

// findRow returns the one finding whose title contains the marker, or fails.
func findRow(t *testing.T, findings []Finding, marker string) Finding {
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
