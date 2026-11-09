package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// Access control for the engine's own HTTP surface.
//
// The engine has no login: it is a single-operator tool bound to loopback. One
// check remains, and it is about geography rather than identity:
//
//  1. Host check (always on): the request's Host must name loopback literally
//     (127.0.0.1, localhost, ::1). This closes DNS rebinding, where an attacker
//     domain resolves to 127.0.0.1 and the browser sends `Host: evil.example`.
//
// THE SERVICE KEY IS GONE. `RR_INTERNAL_API_KEY` and `X-RequestRider-Internal-Key`
// were removed end to end, and this is the measured reason, not a preference.
// (The reason string they answered with is named in the paragraph below; the test
// `TestTheEngineNoLongerDeclaresAServiceKey` reads this file, so prose here that
// quotes an identifier the engine no longer declares would fail it.)
// The engine compares the presented header against the value it read at boot, so
// two processes from the same checkout could only talk if they were booted from
// the same environment. In practice: a leftover engine stayed on :8081 across a
// restart, `start.sh` probed only the (by-design unauthenticated) `/health`, saw
// 200 and declared "engine вже працює" — while Django sent the current
// installation's key and got a 403 on every internal call. The
// stack was half-alive and the status row read UP. A credential that only works
// between processes started in the same breath is a startup-ordering bug wearing a
// security control's clothes.
//
// The bind refusal below is untouched and is not part of this: the control plane
// still refuses to listen on a reachable interface without an explicit override.

const allowNonLoopbackBindEnv = "RR_ALLOW_NON_LOOPBACK_BIND"

func isLoopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return parsed.IsLoopback()
	}
	return false
}

func withInternalAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			writeError(w, http.StatusForbidden, "FORBIDDEN_HOST",
				errForbiddenHost(r.Host))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func errForbiddenHost(host string) error {
	return fmt.Errorf("request host %q is not loopback", host)
}

// requireLoopbackBind refuses to listen on a reachable interface unless the
// operator said so explicitly. The defaults are correct; nothing checks the
// value when it is overridden, so a `PROXY_LISTEN_ADDR=0.0.0.0:8080` typo would
// otherwise expose the unauthenticated capture store to the network silently.
func requireLoopbackBind(service, addr string) {
	if isLoopbackHost(addr) {
		return
	}
	if strings.TrimSpace(os.Getenv(allowNonLoopbackBindEnv)) == "1" {
		log.Printf("%s listening on non-loopback %s by explicit %s=1", service, addr, allowNonLoopbackBindEnv)
		return
	}
	log.Fatalf("%s refuses to bind %s: not loopback (set %s=1 to override deliberately)",
		service, addr, allowNonLoopbackBindEnv)
}
