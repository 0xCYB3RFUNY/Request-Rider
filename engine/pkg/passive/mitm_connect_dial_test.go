package passive

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// A MITM'd CONNECT does NOT go through `proxy.Tr`.
//
// goproxy's `connectDial` (https.go:168) prefers `ConnectDialWithReq`, then
// `ConnectDial`, and when neither is set it opens the upstream socket with a bare
// `net.Dialer{}` (https.go:162-165). A project that sets only `Tr` therefore gets
// a fresh TCP connect and a fresh TLS handshake per HTTPS request, on a socket
// that never passed through its own dialer.
//
// Measured 2026-10-10 on `http/misconfiguration` against
// `https://www.kommersant.ru`, same binary, same target, each way twice:
//
//	nuclei direct, no proxy      17.8 s  221 requests  138 errors
//	nuclei through this proxy   86.0 s  376 requests  298 errors
//	nuclei direct again         17.5 s  223 requests  138 errors
//
//	[INF] HTTP connections: 208 total, 208 new, 0 reused (0.0%)
//
// so the test asserts the dialer, not the timing: a scan's speed is a property of
// a target, and the dialer is a property of this code.

// countingDialer records every socket opened through it, so the test can say
// which dialer produced the connection a MITM tunnel ran over.
type countingDialer struct {
	dials atomic.Int64
}

func (c *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c.dials.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

func TestMitmConnectDialsThroughTheProjectTransport(t *testing.T) {
	// A TLS server standing in for the target, so the client's request really is
	// a CONNECT that has to be MITM'd.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Who", "target")
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	dialer := &countingDialer{}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		// The stand-in target serves a self-signed certificate. Skipping
		// verification is what lets the tunnel reach it, and it is confined to
		// this test: the engine's own transport keeps full verification.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: false,
	}
	defer transport.CloseIdleConnections()

	proxyServer := httptest.NewServer(NewProxy(NewStore(), transport).Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
		Timeout: 20 * time.Second,
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(target.URL + "/probe")
	if err != nil {
		t.Fatalf("request through the MITM proxy failed: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("proxied exchange returned %d %q; the tunnel did not reach the target", response.StatusCode, body)
	}
	if got := dialer.dials.Load(); got == 0 {
		t.Fatal("the MITM tunnel was dialled by goproxy's own dialer, not by this project's transport: " +
			"every exchange pays a new TCP connect and a new TLS handshake, and bypasses the route dialer and its bounds")
	}
}
