package passive

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// A scan through the proxy opens one CONNECT tunnel per template, and each tunnel
// owns an upstream socket that goproxy closes when the tunnel ends. Without
// `upstreamPool` the proxy therefore pays a TCP connect and a TLS handshake per
// template, which is what made a scan through this proxy 4.3x slower and twice as
// error-prone than the same binary running directly (measurement and numbers are
// in `upstream_pool.go`).
//
// These tests assert the two properties the pool has to hold, both of which cost
// correctness if broken: a released socket is handed to the next tunnel, and a
// socket that is not really finished — or that belongs to a route that is gone —
// is closed rather than reused.

func newPoolForTest() *upstreamPool {
	pool := newUpstreamPool()
	pool.ttl = time.Minute
	return pool
}

// countingDial records how many sockets were dialled.
type countingDial struct {
	mutex sync.Mutex
	calls int
}

func (d *countingDial) dial(_ context.Context, network, addr string) (net.Conn, error) {
	d.mutex.Lock()
	d.calls++
	d.mutex.Unlock()
	return net.Dial(network, addr)
}

func (d *countingDial) count() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.calls
}

// echoListener answers every connection with a line and then holds the socket
// open, so a released socket is idle rather than half-closed.
func echoListener(t *testing.T) (addr string, closeAll func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mutex sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			conns = append(conns, conn)
			mutex.Unlock()
			go func(c net.Conn) {
				buf := make([]byte, 4)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().String(), func() {
		listener.Close()
		mutex.Lock()
		for _, conn := range conns {
			conn.Close()
		}
		mutex.Unlock()
	}
}

func TestPoolServesASecondTunnelFromTheReleasedSocket(t *testing.T) {
	addr, stop := echoListener(t)
	defer stop()

	pool := newPoolForTest()
	dial := &countingDial{}

	first, err := pool.take(context.Background(), "tcp", addr, dial.dial)
	if err != nil {
		t.Fatalf("first take: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("release first socket: %v", err)
	}
	if got := pool.idleCount(); got != 1 {
		t.Fatalf("after releasing one tunnel the pool holds %d sockets; a released upstream socket is not being reused", got)
	}

	second, err := pool.take(context.Background(), "tcp", addr, dial.dial)
	if err != nil {
		t.Fatalf("second take: %v", err)
	}
	defer second.Close()
	if got := dial.count(); got != 1 {
		t.Fatalf("the second tunnel dialled a new socket (%d dials in total); the released one was dropped instead of reused", got)
	}
	if second == first {
		t.Fatal("the pool handed back the same wrapper it already handed out; a released socket must leave the pool first")
	}
}

func TestPoolDoesNotReuseASocketFromAPreviousRoute(t *testing.T) {
	addr, stop := echoListener(t)
	defer stop()

	pool := newPoolForTest()
	dial := &countingDial{}

	held, err := pool.take(context.Background(), "tcp", addr, dial.dial)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	// The route is swapped while the tunnel is still open, which is exactly when
	// `Apply route` runs and every in-flight exchange is drained.
	pool.flush()
	if got := pool.idleCount(); got != 0 {
		t.Fatalf("flush left %d sockets idle; they belong to the route that was just replaced", got)
	}

	if err := held.Close(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := pool.idleCount(); got != 0 {
		t.Fatalf("a socket dialled under the previous route was kept for reuse (%d idle); the next request would leave by the old exit", got)
	}
	if got := dial.count(); got != 1 {
		t.Fatalf("unexpected extra dial: %d", got)
	}

	// The pool must still serve traffic after a flush: a route change stops
	// reuse, it does not stop the proxy.
	fresh, err := pool.take(context.Background(), "tcp", addr, dial.dial)
	if err != nil {
		t.Fatalf("take after flush: %v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("release after flush: %v", err)
	}
	if got := pool.idleCount(); got != 1 {
		t.Fatalf("the pool does not reuse sockets opened after the flush (%d idle); a route change disabled reuse for good", got)
	}
	if got := dial.count(); got != 2 {
		t.Fatalf("expected the post-flush tunnel to dial (%d dials), reuse of the old generation must not count", got)
	}
}

func TestPoolClosesAnExpiredSocket(t *testing.T) {
	addr, stop := echoListener(t)
	defer stop()

	pool := newPoolForTest()
	pool.ttl = time.Millisecond
	dial := &countingDial{}

	held, err := pool.take(context.Background(), "tcp", addr, dial.dial)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if err := held.Close(); err != nil {
		t.Fatalf("release: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	next, err := pool.take(context.Background(), "tcp", addr, dial.dial)
	if err != nil {
		t.Fatalf("take after expiry: %v", err)
	}
	defer next.Close()
	if got := dial.count(); got != 2 {
		t.Fatalf("expired socket was handed out (%d dials); a stale upstream socket may be pointing at a different connection state", got)
	}
}

func TestPoolHoldsOnlyItsPerHostLimit(t *testing.T) {
	addr, stop := echoListener(t)
	defer stop()

	pool := newPoolForTest()
	pool.perHost = 2
	dial := &countingDial{}

	for i := 0; i < 5; i++ {
		held, err := pool.take(context.Background(), "tcp", addr, dial.dial)
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if err := held.Close(); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if got := pool.idleCount(); got > 2 {
		t.Fatalf("pool holds %d idle sockets with a per-host limit of 2; file descriptors for a scan's idle targets accumulate without bound", got)
	}
}

func TestPoolDoesNotReuseASocketWithDataStillPending(t *testing.T) {
	// A listener that writes a byte the client never read: the socket has an
	// unfinished exchange on it, and the next request writing on it would read
	// the previous reply.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("x"))
		select {}
	}()

	pool := newPoolForTest()
	dial := &countingDial{}
	held, err := pool.take(context.Background(), "tcp", listener.Addr().String(), dial.dial)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	// Give the listener's write time to land so the peeking read sees it.
	time.Sleep(100 * time.Millisecond)
	if err := held.Close(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := pool.idleCount(); got != 0 {
		t.Fatalf("a socket with an unread reply was kept for reuse (%d idle); the next request would answer the previous one", got)
	}
}
