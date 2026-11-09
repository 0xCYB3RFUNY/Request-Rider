package passive

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// upstreamPool hands MITM tunnels idle upstream sockets instead of making every
// tunnel pay a fresh TCP connect and TLS handshake.
//
// WHY IT EXISTS, measured 2026-10-10 on `http/misconfiguration` (986 templates)
// against `https://www.kommersant.ru`, same nuclei binary, same target, each way
// twice to rule out target drift:
//
//	nuclei direct, no proxy      17.8 s  221 requests  138 errors
//	nuclei through this proxy   86.0 s  376 requests  298 errors
//	nuclei direct again         17.5 s  223 requests  138 errors
//
//	[INF] HTTP connections: 208 total, 208 new, 0 reused (0.0%)
//
// Direct, nuclei keeps one connection for the whole scan and handshakes once.
// Through a proxy it opens a CONNECT tunnel per template, and each tunnel owns an
// upstream socket that goproxy closes when the tunnel ends — so without a pool the
// proxy handshakes once per tunnel. `data/logs/engine.log` fills with
// `Cannot read response from mitm'd server net/http: TLS handshake timeout`; 377
// of them were recorded during that measurement, and each one held its worker for
// the full handshake bound.
//
// `http.Transport` cannot do this for us. Its pool is driven by `RoundTrip`, not
// by `DialContext`, and goproxy calls the dialer directly — so wiring
// `ConnectDialWithReq` to the transport (which this project does, so MITM traffic
// follows the route and its bounds) dials through the right route but still
// creates a socket per tunnel.
//
// SAFETY. A socket goes back to the pool only if it still looks unused: the
// wrapper peeks for a pending byte before offering it, because an exchange that
// left unread data behind is not a connection the next request may start writing
// on. Anything unreadable, expired, or over the per-host limit is closed instead.
// The pool is flushed whenever the route generation changes, because a socket
// belongs to the route that opened it.

const upstreamIdleTTL = 90 * time.Second

// upstreamPerHostIdle matches the shared transport's own idle budget
// (`MaxIdleConnsPerHost`). More idle sockets than the transport would keep is
// memory and file descriptors for nothing.
const upstreamPerHostIdle = 32

// idleSocket is a released upstream socket together with the moment it was
// released, so expiry is read from the pool's own bookkeeping rather than from
// socket timestamps.
type idleSocket struct {
	conn      net.Conn
	idleSince time.Time
}

type upstreamPool struct {
	mutex   sync.Mutex
	idle    map[string][]idleSocket
	ttl     time.Duration
	perHost int
	// generation rises on every flush. A socket carries the generation it was
	// dialled under, and one from an older generation is closed rather than
	// reused — otherwise a route change would leave the pre-change sockets
	// eligible, which is exactly the socket the new route must not use.
	generation uint64
	now        func() time.Time
}

func newUpstreamPool() *upstreamPool {
	return &upstreamPool{
		idle:    map[string][]idleSocket{},
		ttl:     upstreamIdleTTL,
		perHost: upstreamPerHostIdle,
		now:     time.Now,
	}
}

func upstreamKey(network, addr string) string { return network + "|" + addr }

// take returns an idle socket for the address, or dials a new one. The socket it
// returns is a `*pooledConn`, so the caller closing it offers it back here rather
// than losing it.
func (p *upstreamPool) take(ctx context.Context, network, addr string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	key := upstreamKey(network, addr)

	p.mutex.Lock()
	queue := p.idle[key]
	for len(queue) > 0 {
		last := len(queue) - 1
		socket := queue[last]
		queue = queue[:last]
		if socket.conn != nil && p.now().Sub(socket.idleSince) <= p.ttl {
			p.idle[key] = queue
			p.mutex.Unlock()
			return &pooledConn{Conn: socket.conn, pool: p, key: key}, nil
		}
		if socket.conn != nil {
			socket.conn.Close()
		}
	}
	p.idle[key] = queue
	generation := p.generation
	p.mutex.Unlock()

	conn, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &pooledConn{Conn: conn, pool: p, key: key, generation: generation}, nil
}

// give takes back a socket a tunnel has finished with.
func (p *upstreamPool) give(key string, generation uint64, conn net.Conn) {
	if conn == nil {
		return
	}
	p.mutex.Lock()
	// The route changed while this tunnel was running: its socket belongs to the
	// generation that is gone.
	if generation != p.generation {
		p.mutex.Unlock()
		conn.Close()
		return
	}
	p.mutex.Unlock()

	// A socket with anything still unread belongs to an unfinished exchange, and
	// the next request writing on it would read the previous reply.
	if !socketIsIdle(conn) {
		conn.Close()
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()
	if generation != p.generation {
		conn.Close()
		return
	}
	now := p.now()
	queue := p.idle[key]
	live := queue[:0]
	for _, held := range queue {
		if held.conn == nil {
			continue
		}
		if now.Sub(held.idleSince) > p.ttl {
			held.conn.Close()
			continue
		}
		live = append(live, held)
	}
	if len(live) >= p.perHost {
		p.idle[key] = live
		conn.Close()
		return
	}
	p.idle[key] = append(live, idleSocket{conn: conn, idleSince: now})
}

// flush closes every idle socket and opens a new generation, so sockets dialled
// under the old one are closed when their tunnels end instead of being reused.
// A route change calls it: a socket belongs to the route that opened it.
func (p *upstreamPool) flush() {
	p.mutex.Lock()
	p.generation++
	held := p.idle
	p.idle = map[string][]idleSocket{}
	p.mutex.Unlock()
	for _, queue := range held {
		for _, socket := range queue {
			if socket.conn != nil {
				socket.conn.Close()
			}
		}
	}
}

// idleCount reports how many sockets the pool is currently holding, for the
// handler's own accounting and for tests.
func (p *upstreamPool) idleCount() int {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	total := 0
	for _, queue := range p.idle {
		total += len(queue)
	}
	return total
}

// socketIdleProbeWindow is how long the reuse check waits for a pending byte.
//
// It cannot be zero. `net.Conn` checks an expired read deadline BEFORE reading,
// so a deadline of `time.Now()` reports "idle" even when the socket has an
// unread reply waiting — which is the exact case the check exists to catch. A
// short positive window lets a buffered record be returned, and costs a finished
// exchange at most this long.
const socketIdleProbeWindow = 2 * time.Millisecond

// socketIsIdle reports whether the socket has nothing pending. A read with a
// short deadline answers almost at once: data means the exchange finished early
// and the socket is not safe to reuse, a timeout means the socket is waiting for
// the next request.
func socketIsIdle(conn net.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(socketIdleProbeWindow)); err != nil {
		return false
	}
	defer conn.SetReadDeadline(time.Time{})
	var probe [1]byte
	_, err := conn.Read(probe[:])
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// pooledConn is the socket goproxy believes it owns. Closing it is what normally
// ends an upstream socket; here Close offers it back to the pool instead, and the
// pool decides whether it may be reused.
type pooledConn struct {
	net.Conn
	pool       *upstreamPool
	key        string
	generation uint64
	mutex      sync.Mutex
	closed     bool
}

func (c *pooledConn) Close() error {
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return nil
	}
	c.closed = true
	c.mutex.Unlock()
	c.pool.give(c.key, c.generation, c.Conn)
	return nil
}
