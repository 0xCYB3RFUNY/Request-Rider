package passive

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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// The pool has to pay off on the path the scanner actually uses: nuclei talks to
// this proxy and opens a CONNECT tunnel per template, so several tunnels to the
// same host arrive in sequence on separate client connections.
//
// `TestPoolServesASecondTunnelFromTheReleasedSocket` proves the pool itself; this
// proves it is reachable from the MITM handler, which is the part that can
// silently not run — goproxy has more than one path for an upstream socket.

func TestMitmTunnelsReuseOneUpstreamSocket(t *testing.T) {
	target, stop := keepAliveTLSTarget(t)
	defer stop()

	var mutex sync.Mutex
	dials := 0
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mutex.Lock()
		dials++
		mutex.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	transport := &http.Transport{
		DialContext: dial,
		// The stand-in target serves a self-signed certificate. Skipping
		// verification is what lets the tunnel reach it, and it is confined to
		// this test: the engine's own transport keeps full verification.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: false,
	}
	defer transport.CloseIdleConnections()

	proxy := NewProxy(NewStore(), transport)
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	// A fresh transport per request forces a fresh CONNECT per request, which is
	// the pattern a scanner produces. Reusing one client transport would reuse
	// the tunnel and never reach the pool.
	const rounds = 4
	for i := 0; i < rounds; i++ {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			},
			Timeout: 20 * time.Second,
		}
		response, err := client.Get(target + "/probe")
		if err != nil {
			t.Fatalf("request %d through the MITM proxy failed: %v", i, err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		client.CloseIdleConnections()
		if response.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("request %d returned %d %q; the tunnel did not reach the target", i, response.StatusCode, body)
		}
	}

	mutex.Lock()
	got := dials
	mutex.Unlock()
	if got != 1 {
		t.Fatalf("%d separate CONNECT tunnels produced %d upstream sockets; a scan pays a TCP connect and a TLS handshake per template (pool idle=%d)", rounds, got, proxy.upstream.idleCount())
	}
}

// keepAliveTLSTarget serves TLS on loopback and holds each socket open after the
// response, which is what a real HTTPS target does. A target that closes
// (`Connection: close`) cannot demonstrate reuse, because there is nothing left
// to reuse.
func keepAliveTLSTarget(t *testing.T) (string, func()) {
	t.Helper()
	certificate := selfSignedCertificate(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveKeepAlive(conn)
		}
	}()
	return "https://" + listener.Addr().String(), func() { listener.Close() }
}

func serveKeepAlive(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		// Drain the rest of the header block.
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")); err != nil {
			return
		}
	}
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		func() []byte {
			der, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatalf("marshal key: %v", err)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}(),
	)
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}
	return certificate
}
