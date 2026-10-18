package active

// TLSCertificate reads the certificate and the negotiated parameters of a TLS
// connection, over a connection it opens itself.
//
// Burp files two checks here: `0x01000100` TLS certificate and `0x01000500`
// hidden HTTP 2. They are the only two rows in the register whose evidence is
// not in the message — one is about the certificate the client was *shown*, the
// other about the protocol the connection *negotiated* — and the run's own
// transport could not supply either.
//
// # Why this opens its own connection instead of reading the run's
//
// A certificate checker that uses the run's own connection can only ever see a
// certificate the run's client **accepted**, and the interesting ones are the
// ones it rejects. This was measured rather than assumed: an expired fixture
// certificate makes Go's verifier abort the handshake, `Response.TLS` is then
// nil, and a detector reading it reports nothing — and the report's silence
// would read as "this site's certificate is fine". So the module dials the host
// itself, with verification off, and reads what was presented. That is what a
// certificate viewer does and it is the only vantage point from which "expired",
// "for another host" and "SHA-1" are observable at all.
//
// The verification-off dial is used for the *certificate read only*. It carries
// no application data, sends nothing the operator did not ask for beyond the
// handshake, and never writes the run's traffic through it: the recording
// transport, the cookie jar and the route generation all stay on the run's own
// connection.
//
// # What is claimed, and what the observation channel costs
//
// Every row is a fact about **the certificate this client was presented**. When
// the run's transport is the recording proxy, the target's chain was never on
// the wire to this client either — the proxy terminated it — so the detector
// reads the issuer, compares it with the run's own recording CA, and when they
// match it says exactly that: the target's certificate was not observed.
//
// That is the only honest form of the check from inside a client, and it is what
// makes the module's value real rather than decorative: a reader knows whether
// the row is about the target or about the vantage point.
//
// # Why a raw HTTP/1.1 request is written onto an h2 connection
//
// "Hidden HTTP 2" is a server whose negotiated protocol and whose messages
// disagree: the connection carries HTTP/2 while everything on the wire is 1.1
// text, so anything in front of it that keys on framing reasons about a protocol
// the connection is not using. `tls.Dial` gives the negotiated protocol and a
// raw socket; writing `GET / HTTP/1.1` onto it and reading the first line back
// shows whether the server answers in 1.1 text or in binary frames. Only the
// first is the finding, and the second is the control that proves the detector
// distinguishes them.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TLSCertificate is the connection-level reader.
type TLSCertificate struct{}

// Name implements Module.
func (TLSCertificate) Name() string { return "tls-certificate" }

// Level implements Module.
//
// Host level, and the reason is that a certificate is a property of a
// **connection**, not of a URL: the same endpoint answers on the same certificate
// for every path, so an endpoint-level module would emit the same rows once per
// page. One row per distinct defect per origin is what a reader wants.
func (TLSCertificate) Level() Level { return LevelHost }

// tlsProbeTimeout bounds the certificate read.
//
// It is a bound and not a ceiling: a host that accepts a TCP connection and then
// never completes a handshake would otherwise hold the run for as long as the
// transport's own deadline, and the operator would see a run stuck with nothing
// to act on. Every probe passes the operator's own context, so a cancelled run
// cancels this too.
const tlsProbeTimeout = 20 * time.Second

// Scan reads the certificate the host presents and reports what is wrong with it.
func (TLSCertificate) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	host, port, err := tlsHostOf(p.URL)
	if err != nil {
		return nil
	}
	// A cleartext host has no certificate to read. Saying so is not a row:
	// "this site has no TLS" is the absence of the precondition, and the
	// transport-security rows are the ones that report it.
	if baseline != nil && baseline.TLS == nil && !strings.HasPrefix(strings.ToLower(p.URL), "https://") {
		return nil
	}

	var out []Finding
	// The TLS half runs only where there is TLS to read. A cleartext URL used to
	// fall through to the certificate probe, which then failed the handshake and
	// returned nothing — taking the h2c half with it, because the h2c port is by
	// definition the one where there is no certificate. That is why the two halves
	// are now separate branches rather than one probe with a second check after
	// it.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.URL)), "https://") {
		probe, err := tlsProbe(ctx, host, port)
		// One handshake and one request reached the target whether or not they
		// proved anything, and the run's request count has to say so.
		t.CountExternalRequests(1)
		if err == nil {
			recorded := probe.recordedRecordingCA
			if recorded {
				out = append(out, tlsRecordingCARow(p, probe))
			}
			if finding, ok := tlsHiddenHTTP2Row(p, probe); ok {
				out = append(out, finding)
			}
			out = append(out, tlsDefectRows(p, probe, host, recorded)...)
		}
	}

	// The second half of the row, and it is a different mechanism: a server can
	// speak HTTP/2 over cleartext — `h2c` — and a client that only reads ALPN never
	// sees it, because ALPN is a TLS extension and a cleartext connection has
	// nowhere to negotiate.
	if finding, ok := h2cHiddenRow(ctx, t, host, port, p); ok {
		out = append(out, finding)
	}
	return out
}

// tlsObservation is everything one handshake and one raw exchange showed.
type tlsObservation struct {
	// host and port are what was dialled.
	host, port string
	// leaf is the certificate the host presented, nil if it presented none.
	leaf *x509.Certificate
	// chain is the whole presented chain, for the evidence line.
	chain []*x509.Certificate
	// negotiated is the ALPN protocol, empty when none was settled.
	negotiated string
	// tlsVersion is the negotiated version.
	tlsVersion uint16
	// cipherSuite is the negotiated suite.
	cipherSuite uint16
	// statusLine is the first line the host answered with after an HTTP/1.1
	// request, empty when it answered with something that is not 1.1 text.
	statusLine string
	// recordedRecordingCA is whether the presented leaf was issued by the run's
	// own recording CA, which means the run saw the proxy and not the target.
	recordedRecordingCA bool
}

// tlsProbe opens one connection, reads the certificate, and asks the host an
// HTTP/1.1 question on it.
//
// The three steps are in this order because each one narrows the next: the
// handshake gives the certificate and the negotiated protocol, and only then is
// it worth asking whether the host's answer to 1.1 text agrees with what it
// negotiated.
func tlsProbe(ctx context.Context, host, port string) (tlsObservation, error) {
	probeContext, cancel := context.WithTimeout(ctx, tlsProbeTimeout)
	defer cancel()

	// The dialling and the handshake are separate steps so that the run's own
	// cancellation reaches both: `tls.DialWithDialer` takes a dialer but no
	// context, and a probe that ignored a cancelled run would be one more thing
	// holding a cancelled scan open.
	raw, err := (&net.Dialer{}).DialContext(probeContext, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return tlsObservation{}, fmt.Errorf("tls probe %s:%s: %w", host, port, err)
	}
	// `InsecureSkipVerify` is deliberate and is the whole point of this
	// connection: the certificate is the *subject* of the check, so a client that
	// rejects an unacceptable one can never report it. Nothing is sent but the
	// handshake and a HEAD.
	connection := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the certificate is what is being read, not trusted
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS10,
	})
	if err := connection.HandshakeContext(probeContext); err != nil {
		_ = raw.Close()
		return tlsObservation{}, fmt.Errorf("tls handshake %s:%s: %w", host, port, err)
	}
	defer connection.Close()

	deadline := time.Now().Add(tlsProbeTimeout)
	_ = connection.SetDeadline(deadline)
	state := connection.ConnectionState()
	observation := tlsObservation{
		host:                host,
		port:                port,
		chain:               state.PeerCertificates,
		negotiated:          state.NegotiatedProtocol,
		tlsVersion:          state.Version,
		cipherSuite:         state.CipherSuite,
		recordedRecordingCA: presentedByRecordingCA(&state),
	}
	if len(state.PeerCertificates) > 0 {
		observation.leaf = state.PeerCertificates[0]
	}
	observation.statusLine = tlsRawStatusLine(connection, host)
	return observation, nil
}

// tlsRawStatusLine asks the connection an HTTP/1.1 question and reads the first
// line back.
//
// It writes 1.1 text on purpose even when the connection negotiated h2: the whole
// question is whether the host answers in 1.1 text, so asking in 2.0 framing
// would answer a different one. A host that answers with binary frames — the
// first byte is the frame length, not `H` — returns an empty string, and that
// empty string is the control this detector's positive case needs.
func tlsRawStatusLine(connection *tls.Conn, host string) string {
	request := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Request-Rider\r\n" +
		"Connection: close\r\nAccept: */*\r\n\r\n"
	if _, err := connection.Write([]byte(request)); err != nil {
		return ""
	}
	buffer := make([]byte, 256)
	read, err := connection.Read(buffer)
	if err != nil && read == 0 {
		return ""
	}
	line := string(buffer[:read])
	if index := strings.IndexAny(line, "\r\n"); index >= 0 {
		line = line[:index]
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "HTTP/1.") {
		return ""
	}
	return line
}

// tlsDefectRows reports the properties of the presented certificate that are
// defects in their own right, whatever produced the certificate.
func tlsDefectRows(p Point, probe tlsObservation, host string, recorded bool) []Finding {
	leaf := probe.leaf
	if leaf == nil {
		return nil
	}
	var out []Finding
	now := time.Now()

	if now.After(leaf.NotAfter) {
		out = append(out, tlsCertificateRow(p, leaf, len(probe.chain), "expired",
			"The certificate presented for "+host+" expired on "+
				leaf.NotAfter.UTC().Format(time.RFC3339)+". A client that enforces validity refuses "+
				"the connection outright, and a client that was taught to click past that warning "+
				"is taught to click past the ones that matter.",
			"Renew the certificate, and have the client stack treat an expired certificate as a "+
				"hard failure rather than something to click past."))
	} else if now.Before(leaf.NotBefore) {
		out = append(out, tlsCertificateRow(p, leaf, len(probe.chain), "not yet valid",
			"The certificate presented for "+host+" only becomes valid on "+
				leaf.NotBefore.UTC().Format(time.RFC3339)+", which is in the future from now. A "+
				"clock this far out of step makes every other certificate decision unreliable, "+
				"including the expiry one above.",
			"Correct the host clock, and have the issuer stamp a validity window that is not "+
				"behind the server that serves it."))
	}

	if weak := weakSignatureDescription(leaf); weak != "" {
		out = append(out, tlsCertificateRow(p, leaf, len(probe.chain), "weak key or signature",
			"The certificate presented for "+host+" is signed with "+weak+". A signature that "+
				"weak has published collisions, so a forger can produce a certificate that "+
				"verifies without ever holding the issuer's key.",
			"Reissue with SHA-256 or better and an RSA key of at least 2048 bits, or move to "+
				"ECDSA."))
	}

	if err := leaf.VerifyHostname(host); err != nil {
		out = append(out, tlsCertificateRow(p, leaf, len(probe.chain), "hostname mismatch",
			"The certificate presented for "+host+" does not cover that name. It covers "+
				describeCertificateNames(leaf)+", and the verifier says: "+err.Error()+
				". A client that checks the name refuses the connection, and one that does not "+
				"is trusting a certificate the issuer issued for somebody else.",
			"Reissue with every name the service answers on in its subject alternative names, or "+
				"terminate the name the clients actually use."))
	}

	// A withdrawn protocol is a property of the same handshake, so it belongs to
	// the certificate row's family rather than to a row of its own that the
	// original does not have.
	if version := deprecatedTLSVersion(probe.tlsVersion); version != "" {
		out = append(out, tlsCertificateRow(p, leaf, len(probe.chain), "deprecated protocol version",
			"The connection for "+host+" negotiated "+version+", which is withdrawn from every "+
				"current browser and has attacks that remove its guarantees entirely.",
			"Disable TLS 1.0 and 1.1 and require TLS 1.2 at minimum, preferably 1.3."))
	}

	// With the recording CA in the path, the verdict on *that* chain would be a
	// verdict about the proxy — which is the false claim this module exists not to
	// make.
	if recorded {
		return nil
	}
	return out
}

// describeCertificateNames renders what a certificate actually covers.
//
// The verifier's own wording is quoted in the row as well, but it is not the
// whole answer: "doesn't contain any IP SANs" tells an operator what the check
// looked for, and not which names the certificate will pass for — which is the
// half they have to go and fix.
func describeCertificateNames(leaf *x509.Certificate) string {
	var names []string
	for _, name := range leaf.DNSNames {
		names = append(names, name)
	}
	for _, address := range leaf.IPAddresses {
		names = append(names, address.String())
	}
	if leaf.Subject.CommonName != "" {
		names = append(names, leaf.Subject.CommonName+" (common name)")
	}
	if len(names) == 0 {
		return "no name at all"
	}
	return strings.Join(names, ", ")
}

// tlsCertificateRow renders one certificate defect.
func tlsCertificateRow(p Point, leaf *x509.Certificate, chainLength int,
	defect, description, remediation string) Finding {
	finding, _ := NewFinding(Spec{
		Module:  "tls-certificate",
		Title:   "TLS Certificate (" + defect + "): 0x01000100",
		Claimed: SeverityMedium,
		Tier:    TierVerified,
		Point:   p,
		Payload: leaf.Subject.String(),
		Evidence: "subject: " + leaf.Subject.String() +
			"\nissuer:  " + leaf.Issuer.String() +
			"\nvalid:   " + leaf.NotBefore.UTC().Format(time.RFC3339) + " → " +
			leaf.NotAfter.UTC().Format(time.RFC3339) +
			"\nserial:  " + leaf.SerialNumber.String() +
			"\nchain:   " + strconv.Itoa(chainLength) + " certificate(s) presented",
		Description: description,
		Remediation: remediation,
	})
	return finding
}

// tlsRecordingCARow says what the run could not see, and names why.
//
// This row is the opposite of a finding: it is the honest report of an absent
// observation, and it exists so a reader is not left to explain a silence. It is
// `info` because nothing is wrong with the target — something is wrong with the
// vantage point.
func tlsRecordingCARow(p Point, probe tlsObservation) Finding {
	subject, issuer := "", ""
	if probe.leaf != nil {
		subject, issuer = probe.leaf.Subject.String(), probe.leaf.Issuer.String()
	}
	finding, _ := NewFinding(Spec{
		Module:  "tls-certificate",
		Title:   "Target Certificate Not Observed (recording proxy in the path): 0x01000100",
		Claimed: SeverityInfo,
		Tier:    TierVerified,
		Point:   p,
		Payload: subject,
		Evidence: "observed subject: " + firstNonBlank(subject, "(no certificate)") +
			"\nobserved issuer:  " + firstNonBlank(issuer, "(no certificate)") +
			"\nnegotiated:       " + tlsVersionName(probe.tlsVersion) +
			" / " + tls.CipherSuiteName(probe.cipherSuite),
		Description: "This run's transport goes through the recording proxy, so the certificate " +
			"that was on the wire to this client is the proxy's own. The target's chain — its " +
			"issuer, its validity, its key — was **not** observed, and no row about it is " +
			"reported either way. To read the target's certificate, run with a direct transport " +
			"rather than one that records.",
		Remediation: "Not a defect in the target. Run the scan with a direct RoundTripper when " +
			"the certificate itself is what is under review.",
	})
	return finding
}

// tlsHiddenHTTP2Row reports a connection whose negotiated protocol and whose
// messages disagree.
//
// Both halves are needed and neither is enough alone: the negotiation proves the
// connection carries HTTP/2, and the 1.1 status line proves the host answered in
// 1.1 framing. A host that answers in binary frames is not hiding anything, and
// this row is silent for it — that silence is the control, not an absence.
func tlsHiddenHTTP2Row(p Point, probe tlsObservation) (Finding, bool) {
	if probe.negotiated != "h2" && probe.negotiated != "http/2" {
		return Finding{}, false
	}
	if probe.statusLine == "" {
		return Finding{}, false
	}
	finding, _ := NewFinding(Spec{
		Module:  "tls-certificate",
		Title:   "Hidden HTTP 2 (ALPN negotiated h2, host answered HTTP/1.1 text): 0x01000500",
		Claimed: SeverityLow,
		Tier:    TierVerified,
		Point:   p,
		Payload: "ALPN: " + probe.negotiated + " / answer: " + probe.statusLine,
		Evidence: "negotiated protocol: " + probe.negotiated +
			"\nstatus line:        " + probe.statusLine +
			"\ntls version:        " + tlsVersionName(probe.tlsVersion) +
			"\ncipher suite:       " + tls.CipherSuiteName(probe.cipherSuite),
		Description: "The connection negotiated HTTP/2 through ALPN and the host answered an " +
			"HTTP/1.1 request with an HTTP/1.1 status line. Anything in front of this service " +
			"that keys on framing — a cache, a WAF, a reverse proxy configured for 1.1 — is " +
			"reasoning about a protocol the connection is not using, and the request-smuggling " +
			"and desynchronisation classes all begin from exactly that disagreement.",
		Remediation: "Serve the protocol you negotiate: either terminate HTTP/2 and answer in " +
			"HTTP/2 framing, or stop offering `h2` in ALPN. Set the front end's hop-by-hop " +
			"handling to match the origin's framing.",
	})
	return finding, true
}

// tlsHostOf reduces a URL to a host and a TLS port.
//
// A `null` result is not an error to report: a URL that names no host is not a
// target, and a row about it would be noise.
func tlsHostOf(raw string) (host, port string, err error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", "", errors.New("no host")
	}
	port = parsed.Port()
	if port == "" {
		port = "443"
	}
	return parsed.Hostname(), port, nil
}

// leafOf returns the certificate the client was shown, which for a resumed
// session may be nil and is then not a thing to report on.
func leafOf(state *tls.ConnectionState) *x509.Certificate {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

// weakSignatureDescription names a signature or key that has published
// collisions, and returns an empty string for one that has not.
func weakSignatureDescription(leaf *x509.Certificate) string {
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1 or weaker"
	}
	if leaf.PublicKeyAlgorithm == x509.RSA {
		if key, ok := leaf.PublicKey.(interface{ Size() int }); ok && key.Size()*8 < 2048 {
			return "an RSA key of " + strconv.Itoa(key.Size()*8) + " bits"
		}
	}
	return ""
}

// deprecatedTLSVersion names a withdrawn protocol version, and returns an empty
// string for one still in use.
func deprecatedTLSVersion(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	}
	return ""
}

// tlsVersionName renders a version for the evidence line.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionSSL30:
		return "SSL 3.0"
	}
	return "unknown"
}

// presentedByRecordingCA reports whether the certificate the client saw was
// issued by the run's own recording CA — which is what every HTTPS connection a
// recording run makes looks like.
//
// The recording CA is found the way the engine finds it: `CA_CERT` names the
// file, or `CA_DIR` names the directory holding `ca.crt`. A run that cannot find
// it answers false, and that answer is safe in one direction only: it means the
// certificate is treated as the target's, which is what a direct transport
// deserves. That is why the missing file degrades towards more rows rather than
// fewer — the recording-CA row is the one that gets lost.
func presentedByRecordingCA(state *tls.ConnectionState) bool {
	leaf := leafOf(state)
	if leaf == nil {
		return false
	}
	ca := recordingCA()
	if ca == nil {
		return false
	}
	return bytesEqual(ca.RawSubject, leaf.RawIssuer)
}

// recordingCA reads the run's own certificate authority, or nil.
func recordingCA() *x509.Certificate {
	path := strings.TrimSpace(os.Getenv("CA_CERT"))
	if path == "" {
		if dir := strings.TrimSpace(os.Getenv("CA_DIR")); dir != "" {
			path = filepath.Join(dir, "ca.crt")
		}
	}
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return parsed
}

// bytesEqual compares two byte slices without pulling in a second import for a
// comparison used once per connection.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// h2cPreface is the connection preface an HTTP/2 client sends, and the only thing
// that distinguishes a server speaking h2c from one answering a garbled request.
//
// The preface is not negotiable in HTTP/2 — it is the first bytes of every
// connection — so a server that answers one and then a SETTINGS frame is speaking
// HTTP/2 without TLS, which is the condition this probe looks for.
const h2cPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// h2cSettingsFrame is the frame a server answers the preface with: a SETTINGS
// frame with no identifiers, which is the shortest legal answer.
var h2cSettingsFrame = []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}

// h2cProbeTimeout bounds the cleartext probe. It matches the TLS probe's bound and
// for the same reason: a host that accepts a connection and then says nothing
// would otherwise hold the run.
const h2cProbeTimeout = tlsProbeTimeout

// h2cProbe speaks h2c to a cleartext port and reports whether the port answered.
func h2cProbe(ctx context.Context, host, port string) (bool, string, error) {
	probeContext, cancel := context.WithTimeout(ctx, h2cProbeTimeout)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(probeContext, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false, "", err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(h2cProbeTimeout))

	if _, err := raw.Write([]byte(h2cPreface)); err != nil {
		return false, "", err
	}
	buffer := make([]byte, 64)
	read, err := raw.Read(buffer)
	if err != nil && read == 0 {
		return false, "", err
	}
	return bytes.HasPrefix(buffer[:read], h2cSettingsFrame), fmt.Sprintf(
		"%x", buffer[:min(read, 16)]), nil
}

// h2cHiddenRow reports a cleartext port that speaks HTTP/2.
//
// The row is `verified` from the frame alone, because the frame is the protocol:
// there is no reading of a SETTINGS answer to a connection preface other than "this
// port speaks h2c". What the row does **not** claim is that anything is wrong
// with that — h2c is a choice, and the finding is that a client which frames
// HTTP/1.1 on this connection will be talking past it.
func h2cHiddenRow(ctx context.Context, t *Transport, host, port string, p Point) (Finding, bool) {
	// The probe is only meaningful on a cleartext port: a TLS port that answers an
	// h2c preface has already been measured by the ALPN half of the row, and
	// opening a second, unencrypted connection to it to ask again would be a
	// request the operator's target does not need.
	if strings.EqualFold(strings.ToLower(pageURL(p.URL).Scheme), "https") {
		return Finding{}, false
	}
	supported, frame, err := h2cProbe(ctx, host, port)
	t.CountExternalRequests(1)
	if err != nil || !supported {
		return Finding{}, false
	}
	finding, _ := NewFinding(Spec{
		Module:  "tls-certificate",
		Title:   "Hidden HTTP 2 (cleartext port answers an h2c preface): 0x01000500",
		Claimed: SeverityMedium,
		Tier:    TierVerified,
		Point:   p,
		Payload: h2cPreface,
		Evidence: "port:      " + host + ":" + port +
			"\npreface:  sent\nanswer:   " + frame,
		Description: "This port speaks HTTP/2 in the clear. A connection preface is the first " +
			"bytes of every HTTP/2 connection and the port answered one with a SETTINGS frame, " +
			"so it is HTTP/2 without TLS on a connection anyone may open.\n\n" +
			"The finding is not that h2c exists — it is that a client which frames HTTP/1.1 " +
			"on this connection is talking past the server, and every hop between here and " +
			"there has to agree about which one is in use. ALPN cannot report this at all, " +
			"because a cleartext connection has nowhere to negotiate.",
		Remediation: "Either terminate HTTP/2 on TLS and leave the cleartext port HTTP/1.1, " +
			"or declare h2c deliberately and make every hop in front of it parse the same " +
			"framing. Do not let the two protocols share a port without that agreement.",
	})
	return finding, true
}
