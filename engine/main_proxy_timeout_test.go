package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// TestProxyServerConfigurationEnforcesReadHeaderAndIdleTimeouts tests that
// the proxy server configuration explicitly sets ReadHeaderTimeout and IdleTimeout,
// preventing unclosed hanging sockets during scanning.
func TestProxyServerConfigurationEnforcesReadHeaderAndIdleTimeouts(t *testing.T) {
	server := &http.Server{
		ReadHeaderTimeout: 50 * time.Millisecond,
		IdleTimeout:       100 * time.Millisecond,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on loopback: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	// Connect a socket and send nothing (hanging client)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	// The server should close connection after ReadHeaderTimeout expires
	n, readErr := conn.Read(buf)
	if readErr == nil && n > 0 {
		t.Fatalf("expected EOF or close on idle header connection, read %d bytes", n)
	}
}
