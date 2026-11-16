package main

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Transport bounds are the deadlines that protect a connection from being left
// half-open. They are not a budget for the work: an operator who needs a target
// to take longer raises the bound, and no value is capped.
//
// The four stages that can hang without any progress are distinct, so they get
// distinct bounds:
//
//   - dial: a SYN to an address that never answers keeps a goroutine and a
//     socket for the OS connect timeout, which is minutes on Linux. A hostile or
//     merely broken target must not hold a worker that way.
//   - TLS handshake: a peer that accepts TCP and then stops speaking TLS holds
//     the connection the same way. This is the classic silent hang of a scanner.
//   - response header: a server that answers 200 OK's socket and never sends a
//     header line keeps the body read blocked with nothing to report.
//   - idle connection: a pooled connection kept open after use leaks a socket
//     per target until the process runs out of them.
//
// Every one of them is overridable from the environment, and the values actually
// in force are reported by the health endpoint, because a bound nobody can read
// is a bound nobody can reason about.
const (
	// defaultDialTimeout covers establishing the connection, not the request.
	defaultDialTimeout = 30 * time.Second
	// defaultTLSHandshakeTimeout is shorter than the dial bound on purpose: a
	// handshake that outlives the connect is not a slow network, it is a peer
	// that stopped answering.
	defaultTLSHandshakeTimeout = 15 * time.Second
	// defaultResponseHeaderTimeout bounds the wait for the status line and
	// headers. It is generous because a slow application may legitimately take
	// that long to produce its first byte, and short because a header that never
	// arrives is indistinguishable from a dead socket.
	defaultResponseHeaderTimeout = 60 * time.Second
	// defaultIdleConnTimeout releases a pooled connection that a target is no
	// longer using. A passive proxy holds thousands of them, so leaving them to
	// the operating system is how the process runs out of sockets.
	defaultIdleConnTimeout = 90 * time.Second
	// defaultDNSQueryTimeout bounds ONE query to one nameserver.
	//
	// It exists because of a measured environment, not a guess. On the machine
	// this was found on, `/etc/resolv.conf` lists two servers:
	//
	//	nameserver 10.0.2.3                          # answers in 20 ms
	//	nameserver fd17:625c:f037:2::3                # network unreachable
	//
	// Go's resolver walks that list itself and its own per-query budget is
	// seconds, so every single resolve paid that whole budget before falling
	// through to the working server. `data/logs/engine.log` recorded **82** of
	//
	//	lookup yandex.ru on [fd17:625c:f037:2::3]:53: read udp …: i/o timeout
	//
	// during a single scan, and a scan that has to resolve a hostname per request
	// turns that into the dominant cost of the run.
	//
	// This does not fix a broken `/etc/resolv.conf` and does not pretend to: an
	// unreachable server still fails. It makes the failure cheap, so the resolver
	// reaches the working one instead of waiting out a budget sized for a server
	// that is merely slow. Overridable like every other bound here.
	defaultDNSQueryTimeout = 2 * time.Second
)

// transportBounds are the connection-level deadlines applied to every outbound
// transport this engine builds.
type transportBounds struct {
	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	DNSQueryTimeout       time.Duration
}

var (
	transportBoundsOnce     sync.Once
	transportBoundsResolved transportBounds
)

// positiveDurationEnv reads an operator override in milliseconds.
//
// A missing, unparseable or non-positive value falls back to the documented
// default. That is the same rule the gateway uses for its own deadlines: a
// typo must not silently remove a bound, because a removed bound looks exactly
// like a slow target until the process wedges.
func positiveDurationEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	if value, err := strconv.Atoi(raw); err == nil && value > 0 {
		return time.Duration(value) * time.Millisecond
	}
	return fallback
}

// loadTransportBounds resolves the bounds once per process. The environment does
// not change under a running engine, and re-reading it per request would make the
// reported values disagree with the applied ones.
func loadTransportBounds() transportBounds {
	transportBoundsOnce.Do(func() {
		transportBoundsResolved = transportBounds{
			DialTimeout:           positiveDurationEnv("RR_DIAL_TIMEOUT_MS", defaultDialTimeout),
			TLSHandshakeTimeout:   positiveDurationEnv("RR_TLS_HANDSHAKE_TIMEOUT_MS", defaultTLSHandshakeTimeout),
			ResponseHeaderTimeout: positiveDurationEnv("RR_RESPONSE_HEADER_TIMEOUT_MS", defaultResponseHeaderTimeout),
			IdleConnTimeout:       positiveDurationEnv("RR_IDLE_CONN_TIMEOUT_MS", defaultIdleConnTimeout),
			DNSQueryTimeout:       positiveDurationEnv("RR_DNS_QUERY_TIMEOUT_MS", defaultDNSQueryTimeout),
		}
	})
	return transportBoundsResolved
}

// apply sets the bounds on one transport. Every transport this engine builds goes
// through here, so a new transport cannot forget the protection.
func (bounds transportBounds) apply(transport *http.Transport) {
	if transport == nil {
		return
	}
	transport.TLSHandshakeTimeout = bounds.TLSHandshakeTimeout
	transport.ResponseHeaderTimeout = bounds.ResponseHeaderTimeout
	transport.IdleConnTimeout = bounds.IdleConnTimeout
	if transport.MaxIdleConnsPerHost <= 0 {
		maxPerHost := 64
		if val, err := strconv.Atoi(os.Getenv("RR_MAX_IDLE_CONNS_PER_HOST")); err == nil && val > 0 {
			maxPerHost = val
		}
		transport.MaxIdleConnsPerHost = maxPerHost
	}
	if transport.MaxIdleConns <= 0 {
		maxTotal := 256
		if val, err := strconv.Atoi(os.Getenv("RR_MAX_IDLE_CONNS")); err == nil && val > 0 {
			maxTotal = val
		}
		transport.MaxIdleConns = maxTotal
	}
}


// dialer returns a dialer carrying the dial bound and TCP keepalive.
//
// KeepAlive is a deadline in the other direction — it detects a connection that
// died silently, which is exactly the failure the response-header bound cannot
// see because no data ever arrives to time out.
func (bounds transportBounds) dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   bounds.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
}

// describe reports the values in force, in milliseconds, so the operator reads
// the number the engine actually applied rather than the one it assumes.
func (bounds transportBounds) describe() map[string]interface{} {
	return map[string]interface{}{
		"dial_timeout_ms":                bounds.DialTimeout.Milliseconds(),
		"tls_handshake_timeout_ms":       bounds.TLSHandshakeTimeout.Milliseconds(),
		"response_header_timeout_ms":     bounds.ResponseHeaderTimeout.Milliseconds(),
		"idle_conn_timeout_ms":           bounds.IdleConnTimeout.Milliseconds(),
		"dns_query_timeout_ms":           bounds.DNSQueryTimeout.Milliseconds(),
		"control_plane_body_limit_bytes": controlPlaneBodyLimit(),
		"finished_job_retention_minutes": int64(finishedJobRetention() / time.Minute),
		"source_ip_lookup_concurrency":   sourceIPLookupConcurrency(),
		"overrides": []string{
			"RR_DIAL_TIMEOUT_MS",
			"RR_TLS_HANDSHAKE_TIMEOUT_MS",
			"RR_RESPONSE_HEADER_TIMEOUT_MS",
			"RR_IDLE_CONN_TIMEOUT_MS",
			"RR_DNS_QUERY_TIMEOUT_MS",
			"RR_CONTROL_PLANE_BODY_LIMIT_BYTES",
			"RR_FINISHED_JOB_RETENTION_MINUTES",
			"RR_SOURCE_IP_LOOKUP_CONCURRENCY",
		},
	}
}

// defaultControlPlaneBodyLimit bounds how much of a response the engine reads
// for itself.
//
// The distinction is evidentiary, not technical. A target's answer — Repeater,
// Intruder, Repeater Burst, Last-Byte Sync — is the thing the operator is here to
// read, so it is read whole: a truncated exchange is a lost finding. What the
// engine fetches for its own bookkeeping is not evidence anyone asked for: the
// external-IP courtesy lookup, an OAST provider's JSON, a public profile. Those
// are single small documents, and a response far larger than that is a broken or
// hostile endpoint rather than a result. Reading it whole would trade a small
// amount of memory for a process that can be pushed over by one reply.
const defaultControlPlaneBodyLimit = 1 << 20 // 1 MiB

// controlPlaneBodyLimit is the applied bound, overridable so a provider that
// genuinely answers with more is not second-guessed.
func controlPlaneBodyLimit() int64 {
	raw := strings.TrimSpace(os.Getenv("RR_CONTROL_PLANE_BODY_LIMIT_BYTES"))
	if raw != "" {
		// The one byte read past the limit is what proves the answer was too
		// large, so `limit+1` must stay a positive number. An operator who typed
		// the largest int64 would otherwise overflow it to a negative limit, and
		// io.LimitReader with a negative count reads nothing at all — which would
		// turn every control-plane read into a silent failure.
		if value, err := strconv.ParseInt(raw, 10, 64); err == nil && value > 0 && value < math.MaxInt64 {
			return value
		}
	}
	return defaultControlPlaneBodyLimit
}

// readControlPlaneBody reads a bounded prefix of a service response.
//
// A body past the bound is an error, not a quiet truncation: a truncated JSON
// document fails to parse for a reason that has nothing to do with the real
// problem, and the operator would be reading a parse error instead of being told
// the endpoint answered with more than the limit.
func readControlPlaneBody(body io.Reader) ([]byte, error) {
	limit := controlPlaneBodyLimit()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeded the %d byte control-plane limit", limit)
	}
	return data, nil
}
