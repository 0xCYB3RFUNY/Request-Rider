package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"intruder/engine/pkg/passive"
)

// The route dialer may connect a loopback destination without the SOCKS5 proxy,
// because no proxy can reach the local host. It must do nothing else: every
// other destination still has to travel through the proxy the analyst chose, or
// Tor silently stops being Tor. These two tests are the guard for that.
func TestRouteDialerBypassesProxyForLoopbackOnly(t *testing.T) {
	// A SOCKS5 proxy address with nothing listening. If the dialer ever fell
	// back to a direct connection, the dial below would succeed and the test
	// would fail.
	deadProxy := closedLocalAddress(t)
	dialer, err := buildRouteDialer(deadProxy)
	if err != nil {
		t.Fatalf("buildRouteDialer() error = %v", err)
	}

	// A loopback listener the direct dial is expected to reach.
	local := startAcceptListener(t)

	t.Run("loopback connects without the proxy", func(t *testing.T) {
		conn, err := dialer(context.Background(), "tcp", local)
		if err != nil {
			t.Fatalf("loopback dial through a dead proxy failed: %v", err)
		}
		conn.Close()
	})

	t.Run("IPv6 loopback connects without the proxy", func(t *testing.T) {
		conn, err := dialer(context.Background(), "tcp", "[::1]:1")
		if conn != nil {
			conn.Close()
		}
		// Port 1 on loopback is closed, so a direct dial is expected to be
		// refused rather than proxied. Either way it must not be a hang.
		if err == nil {
			t.Fatal("closed loopback port reported success")
		}
	})

	t.Run("localhost by name connects without the proxy", func(t *testing.T) {
		_, port, err := net.SplitHostPort(local)
		if err != nil {
			t.Fatalf("split local address: %v", err)
		}
		conn, err := dialer(context.Background(), "tcp", net.JoinHostPort("localhost", port))
		if err != nil {
			t.Fatalf("localhost dial through a dead proxy failed: %v", err)
		}
		conn.Close()
	})
}

// A destination that is not loopback must not reach the network when the proxy
// is down. This is the confidentiality half of the contract: Tor is the
// operator's privacy boundary, and a silent direct dial would remove it.
func TestRouteDialerNeverFallsBackToDirectForRoutableTargets(t *testing.T) {
	dialer, err := buildRouteDialer(closedLocalAddress(t))
	if err != nil {
		t.Fatalf("buildRouteDialer() error = %v", err)
	}

	for _, target := range []string{
		"198.51.100.7:80",   // TEST-NET-2
		"203.0.113.9:443",   // TEST-NET-3
		"10.0.0.5:80",       // RFC1918
		"172.16.0.9:80",     // RFC1918
		"192.168.1.1:443",   // RFC1918
		"[2001:db8::1]:443", // documentation range
		"example.com:80",    // by name
	} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := dialer(ctx, "tcp", target)
			if conn != nil {
				conn.Close()
			}
			// The proxy address has nothing listening, so every one of these must
			// fail. A success would mean the dial left the route, which is
			// exactly the leak this test exists to catch.
			if err == nil {
				t.Fatalf("target %q connected while the SOCKS5 route was down", target)
			}
		})
	}
}

// A loopback dial must still be cancellable. The bypass picks a dialer, not an
// exemption: work admitted under a route generation has to be cancelled by the
// next route switch exactly like traffic that went through the proxy.
func TestRouteDialerLoopbackBypassStaysCancellable(t *testing.T) {
	dialer, err := buildRouteDialer(closedLocalAddress(t))
	if err != nil {
		t.Fatalf("buildRouteDialer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 1)
	go func() {
		for {
			conn, err := dialer(ctx, "tcp", "127.0.0.1:1")
			if conn != nil {
				conn.Close()
			}
			if err != nil {
				results <- err
				return
			}
			select {
			case <-ctx.Done():
				results <- ctx.Err()
				return
			default:
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-results:
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "refused") {
			t.Fatalf("cancelled loopback dial error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling the context did not stop a loopback dial")
	}
}

// The kill switch must still reach a request that took the loopback bypass.
// This is the whole reason the bypass is safe: it chooses a dialer, it does not
// exempt the operation from the generation gate. A slow loopback server stands
// in for an in-flight crawl, the route is switched underneath it, and the
// request has to come back cancelled exactly like proxied work does.
func TestLoopbackBypassedRequestIsCancelledByRouteSwitch(t *testing.T) {
	manager, err := newRouteManager()
	if err != nil {
		t.Fatalf("newRouteManager() error = %v", err)
	}
	// A SOCKS5 route that is installed and points nowhere: a loopback dial
	// still works because it bypasses the proxy, which is what puts the request
	// in flight in the first place.
	if err := manager.set(routeConfig{Address: closedLocalAddress(t)}); err != nil {
		t.Fatalf("route set error = %v", err)
	}

	target, accepted, release := startSlowServer(t)
	defer release()

	engine := &server{
		routes:            manager,
		store:             passive.NewStore(),
		sourceIPTransport: &sourceIPRoundTripper{},
	}
	recorder := httptest.NewRecorder()
	body := strings.NewReader(`{"method":"GET","url":"` + target + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/proxy/request", body)
	request.Header.Set("Content-Type", "application/json")

	done := make(chan struct{})
	go func() {
		engine.request(recorder, request)
		close(done)
	}()

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("loopback request never reached the server, so the bypass did not run")
	}

	if err := manager.set(routeConfig{}); err != nil {
		t.Fatalf("route switch error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("route switch did not cancel a loopback-bypassed request")
	}
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("route-cancelled loopback status = %d, want 502; body=%s",
			recorder.Code, recorder.Body.String())
	}
}

func TestIsLoopbackTargetClassification(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:80":           true,
		"127.5.5.5:80":           true,
		"[::1]:443":              true,
		"localhost:8080":         true,
		"LOCALHOST:8080":         true,
		"198.51.100.7:80":        false,
		"10.0.0.5:80":            false,
		"192.168.1.1:443":        false,
		"[2001:db8::1]:443":      false,
		"example.com:80":         false,
		"":                       false,
		"no-port-at-all":         false,
		"127.0.0.1.evil.test:80": false,
	}
	for target, want := range cases {
		if got := isLoopbackTarget(target); got != want {
			t.Errorf("isLoopbackTarget(%q) = %v, want %v", target, got, want)
		}
	}
}

// startSlowServer serves a loopback HTTP endpoint that accepts the request and
// then never answers, so a test can hold a request in flight on purpose.
func startSlowServer(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	accepted := make(chan struct{})
	var once sync.Once
	held := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start slow loopback server: %v", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(accepted) })
			select {
			case <-held:
			case <-r.Context().Done():
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go server.Serve(listener)
	return "http://" + listener.Addr().String() + "/", accepted, func() {
		close(held)
		server.Close()
		listener.Close()
	}
}

// closedLocalAddress returns a host:port on loopback with nothing listening, so
// a dial through it fails immediately instead of hanging.
func closedLocalAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return address
}

// startAcceptListener starts a loopback listener that accepts and immediately
// closes, so a direct dial to it succeeds and can be told apart from a proxied
// one.
func startAcceptListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start loopback listener: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return listener.Addr().String()
}
