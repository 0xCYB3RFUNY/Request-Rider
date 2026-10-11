package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// A scan through the passive proxy resolves a hostname per request, and Go's
// own per-query budget is measured in seconds. On the machine this was found on,
// `/etc/resolv.conf` lists two nameservers:
//
//	nameserver 10.0.2.3                 # answers in 20 ms
//	nameserver fd17:625c:f037:2::3       # network unreachable
//
// so every resolve walked to the second server and waited out that budget before
// falling through to the working one — 82 recorded `i/o timeout` lines for
// `lookup yandex.ru` during a single scan of the `http` corpus.
//
// The bound does not make an unreachable server reachable. It makes the failure
// cheap enough that the resolver reaches the working server.

func TestTheDNSQueryBoundIsReportedAsAnOverridableBound(t *testing.T) {
	// A bound nobody can read is a bound nobody can reason about, and every other
	// bound in this file is reported by the health endpoint. This one has to be
	// there too, or an operator who hit the seconds-long default would have no
	// way to see that a different value is in force.
	described := loadTransportBounds().describe()
	got, ok := described["dns_query_timeout_ms"]
	if !ok {
		t.Fatal("the DNS query bound is not reported by describe(); an operator cannot see the value in force")
	}
	if got != loadTransportBounds().DNSQueryTimeout.Milliseconds() {
		t.Fatalf("describe() reports %v, but the applied bound is %v", got, loadTransportBounds().DNSQueryTimeout)
	}
	overrides, _ := described["overrides"].([]string)
	found := false
	for _, name := range overrides {
		if name == "RR_DNS_QUERY_TIMEOUT_MS" {
			found = true
		}
	}
	if !found {
		t.Fatal("RR_DNS_QUERY_TIMEOUT_MS is not listed among the overrides")
	}
}

func TestTheDefaultDNSQueryBoundIsShortEnoughToMatter(t *testing.T) {
	// The whole point is that it beats Go's own per-query budget. A default of
	// 30 s would be a bound that documents the problem without fixing it, so this
	// asserts the value rather than trusting that someone picked a sensible one.
	if defaultDNSQueryTimeout <= 0 {
		t.Fatalf("the default DNS query bound is %v; it must be positive to bound anything", defaultDNSQueryTimeout)
	}
	if defaultDNSQueryTimeout > 5*time.Second {
		t.Fatalf("the default DNS query bound is %v; an unreachable nameserver would still dominate a scan", defaultDNSQueryTimeout)
	}
}

func TestTheDNSQueryBoundIsOverridable(t *testing.T) {
	t.Setenv("RR_DNS_QUERY_TIMEOUT_MS", "750")
	if got := positiveDurationEnv("RR_DNS_QUERY_TIMEOUT_MS", defaultDNSQueryTimeout); got != 750*time.Millisecond {
		t.Fatalf("RR_DNS_QUERY_TIMEOUT_MS=750 gave %v, want 750ms", got)
	}
	// A typo must not silently remove the bound, the same rule every other
	// override in this file follows.
	t.Setenv("RR_DNS_QUERY_TIMEOUT_MS", "abc")
	if got := positiveDurationEnv("RR_DNS_QUERY_TIMEOUT_MS", defaultDNSQueryTimeout); got != defaultDNSQueryTimeout {
		t.Fatalf("an unparsable value gave %v, want the %v default", got, defaultDNSQueryTimeout)
	}
}

// The bound is useless unless it actually lands on the socket. This is the check
// that would fail if the deadline were set on the dial instead of on the
// returned connection, since a dial deadline bounds establishing the connection
// and says nothing about waiting for the answer.
func TestTheBoundLandsOnTheSocketCarryingTheQuery(t *testing.T) {
	// A connection whose peer never answers: the read blocks, so only a deadline
	// on the connection can end it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		// Hold the connection open and send nothing. This is the shape of an
		// unreachable nameserver that blackholes rather than refuses.
		time.Sleep(3 * time.Second)
		_ = conn.Close()
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	conn, err := boundDNSConn(context.Background(), client, nil)
	if err != nil {
		t.Fatalf("boundDNSConn returned an error for a good connection: %v", err)
	}
	if conn != client {
		t.Fatal("boundDNSConn replaced the connection; it is meant to bound the one it is given")
	}

	started := time.Now()
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("a read from a silent peer succeeded; nothing bounded it")
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("the read failed with %v, want a timeout — so the bound did not reach the socket", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("the read blocked for %v, which is longer than the bound and longer than the peer held the connection", elapsed)
	}
}

// A failed dial passes straight through. Wrapping it would turn a refused
// connection into something a caller has to unwrap, and `net.Resolver` treats
// the error as "this server failed, try the next one".
func TestAFailedDialIsPassedThroughUntouched(t *testing.T) {
	conn, err := boundDNSConn(context.Background(), nil, net.ErrClosed)
	if err != net.ErrClosed {
		t.Fatalf("boundDNSConn reported %v, want the original error", err)
	}
	if conn != nil {
		t.Fatalf("boundDNSConn returned a connection %v alongside an error", conn)
	}
}

// A context that already has a shorter deadline wins. A cancelled route switch
// must not be turned back into a wait by a bound this function added.
func TestAShorterContextDeadlineWins(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		time.Sleep(3 * time.Second)
		_ = conn.Close()
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	conn, err := boundDNSConn(ctx, client, nil)
	if err != nil {
		t.Fatalf("boundDNSConn: %v", err)
	}

	started := time.Now()
	_, err = conn.Read(make([]byte, 1))
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("a read from a silent peer succeeded")
	}
	// The context bound is 150 ms and the DNS bound is seconds, so anything
	// close to the context value proves the shorter one was applied.
	if elapsed > time.Second {
		t.Fatalf("the read blocked for %v; the 150ms context deadline did not win over the DNS bound", elapsed)
	}
}

// The engine's health endpoint is how an operator reads a bound, so the value
// has to survive a round trip through `describe()` as a number and not as a
// string.
func TestTheReportedDNSBoundIsANumber(t *testing.T) {
	described := loadTransportBounds().describe()
	value, ok := described["dns_query_timeout_ms"]
	if !ok {
		t.Fatal("dns_query_timeout_ms is missing from describe()")
	}
	if _, isInt := value.(int64); !isInt {
		t.Fatalf("dns_query_timeout_ms is %T (%v), want int64 like every other millisecond bound", value, value)
	}
}

// Nothing here may depend on the machine's resolver: a test that only passes on
// a host with working IPv6 would not be a test. This one asserts the opposite
// direction — that the engine's default does not come from the environment at
// all unless the operator set it.
func TestTheBoundHasADefaultWhenTheEnvironmentIsSilent(t *testing.T) {
	if _, present := os.LookupEnv("RR_DNS_QUERY_TIMEOUT_MS"); present {
		t.Skip("the operator has set RR_DNS_QUERY_TIMEOUT_MS; the default path is not what is running")
	}
	if got := positiveDurationEnv("RR_DNS_QUERY_TIMEOUT_MS", defaultDNSQueryTimeout); got != defaultDNSQueryTimeout {
		t.Fatalf("a silent environment gave %v, want the %v default", got, defaultDNSQueryTimeout)
	}
}
