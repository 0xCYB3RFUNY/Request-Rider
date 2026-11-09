package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The engine's own HTTP surface had no authentication and no Host check: a web
// page in the analyst's browser could drive it directly, bypassing the gateway.
// withInternalAccess closes the Host half, and /health stays open on purpose
// (start.sh probes it with a bare curl).
//
// THE SERVICE KEY IS GONE. `RR_INTERNAL_API_KEY` and `X-RequestRider-Internal-Key`
// were removed end to end. `TestTheServiceKeyCheckIsReallyGone` asserts that,
// because a suite written only for the surviving `Host` check would pass a
// regression that brought the key back — and the key's own history is why that
// matters: it was compared against the value read at boot, so two processes from
// one checkout agreed only when booted from the same environment, and a leftover
// engine on the port answered 403 to every call while `start.sh` reported UP.

func hostRequest(t *testing.T, host, path string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Host = host
	return request
}

func serveThroughGate(t *testing.T, request *http.Request) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	withInternalAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(recorder, request)
	return recorder.Code
}

func TestLoopbackHostsPassTheGate(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1:8081", "localhost:8081", "127.0.0.1", "localhost",
		"[::1]:8081", "127.0.0.2:8081",
	} {
		if code := serveThroughGate(t, hostRequest(t, host, "/proxy/request")); code != http.StatusTeapot {
			t.Errorf("host %q: got %d, want the inner handler", host, code)
		}
	}
}

func TestReboundHostIsRefused(t *testing.T) {
	for _, host := range []string{"evil.example", "evil.example:8081", "10.0.0.5:8081", "192.168.1.50"} {
		if code := serveThroughGate(t, hostRequest(t, host, "/proxy/request")); code != http.StatusForbidden {
			t.Errorf("host %q: got %d, want 403", host, code)
		}
	}
}

func TestHealthIsOpen(t *testing.T) {
	if code := serveThroughGate(t, hostRequest(t, "127.0.0.1:8081", "/health")); code != http.StatusTeapot {
		t.Errorf("health: got %d, want the inner handler", code)
	}
}

// A key in the environment must change nothing: the reader is gone, so the gate
// neither consults nor requires it. The variable is set on purpose — a reader
// that came back would find it.
func TestTheServiceKeyCheckIsReallyGone(t *testing.T) {
	t.Setenv("RR_INTERNAL_API_KEY", "abababababababababababababababababababababababababababababababab")
	if code := serveThroughGate(t, hostRequest(t, "127.0.0.1:8081", "/proxy/request")); code != http.StatusTeapot {
		t.Errorf("with a key in the environment: got %d, want the inner handler — "+
			"the mechanism is removed and must not come back", code)
	}
	request := hostRequest(t, "127.0.0.1:8081", "/proxy/request")
	request.Header.Set("X-RequestRider-Internal-Key", "anything")
	if code := serveThroughGate(t, request); code != http.StatusTeapot {
		t.Errorf("with a key header: got %d, want the inner handler — "+
			"the header is now just a header", code)
	}
}

func TestIsLoopbackHostShapes(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1:8081": true,
		"localhost:8081": true,
		"[::1]:8081":     true,
		"127.0.0.2:8081": true,
		"evil.example":   false,
		"10.0.0.5":       false,
		"":               false,
		"127.0.0.1:9000": true, // the port is the mux's business, not the gate's
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}