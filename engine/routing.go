package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

var errRouteChanged = errors.New("route changed")

type routeConfig struct {
	Address    string `json:"address"`
	Generation uint64 `json:"generation"`
}

type routeManager struct {
	// changeMu serializes complete drain-and-swap route applications.
	changeMu sync.Mutex
	mu       sync.RWMutex
	config   routeConfig
	dialer   func(context.Context, string, string) (net.Conn, error)
	current  *http.Transport
	shared   *http.Transport
	// lookup carries the external-IP check. It is pooled so repeated lookups do
	// not each pay DNS, TCP and TLS, and it is replaced by `install` on every
	// route swap so a socket from the previous exit is never reused.
	lookup *http.Transport
	// generation identifies the current route and its cancellation scope.
	generation    uint64
	generationCtx context.Context
	generationEnd context.CancelCauseFunc
	// changeHooks run after a route has been swapped. A component that keeps its
	// own sockets — the passive proxy's MITM upstream pool, for one — needs to
	// drop them here, because a socket that came up through the previous route
	// belongs to a different exit.
	changeHooksMu sync.Mutex
	changeHooks   []func()
}

// onRouteChange registers a hook to run after every route swap. It returns
// immediately for the current route; the hook first runs at the next swap.
func (m *routeManager) onRouteChange(hook func()) {
	if hook == nil {
		return
	}
	m.changeHooksMu.Lock()
	defer m.changeHooksMu.Unlock()
	m.changeHooks = append(m.changeHooks, hook)
}

func (m *routeManager) runRouteChangeHooks() {
	m.changeHooksMu.Lock()
	hooks := make([]func(), len(m.changeHooks))
	copy(hooks, m.changeHooks)
	m.changeHooksMu.Unlock()
	for _, hook := range hooks {
		hook()
	}
}

// routeLease freezes one route generation for one logical outbound operation.
// An old lease can never silently start using the newly installed dialer.
type routeLease struct {
	manager    *routeManager
	generation uint64
	context    context.Context
	dialer     func(context.Context, string, string) (net.Conn, error)
	transport  *http.Transport
	shared     *http.Transport
}

type routeBinding struct {
	lease  *routeLease
	shared bool
}

type routeBindingKey struct{}
type expectedRouteGenerationKey struct{}

const routeGenerationHeader = "X-RequestRider-Route-Generation"

func newRouteManager() (*routeManager, error) {
	return newRouteManagerWithRoute(routeConfig{})
}

func newRouteManagerWithRoute(config routeConfig) (*routeManager, error) {
	manager := &routeManager{}
	if err := manager.setInitial(config); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *routeManager) setInitial(config routeConfig) error {
	return m.install(config, true)
}

func (m *routeManager) set(config routeConfig) error {
	return m.install(config, false)
}

func (m *routeManager) install(config routeConfig, initial bool) error {
	address := strings.TrimSpace(config.Address)
	dial, err := buildRouteDialer(address)
	if err != nil {
		return err
	}

	m.changeMu.Lock()
	defer m.changeMu.Unlock()

	m.mu.Lock()
	oldTransport := m.current
	oldShared := m.shared
	oldLookup := m.lookup
	oldCancel := m.generationEnd
	m.config = routeConfig{Address: address}
	m.dialer = dial
	if initial {
		m.generation = 0
	} else {
		m.generation++
	}
	m.generationCtx, m.generationEnd = context.WithCancelCause(context.Background())
	m.current = m.newTransportLocked()
	if m.shared == nil {
		m.shared = m.newSharedTransportLocked()
	}
	// The pooled lookup transport belongs to the route that opened it: its socket
	// went up through that route's dialer and came back with that route's exit
	// address, so it is dropped on every swap rather than kept warm across one.
	m.lookup = m.newLookupTransportLocked()
	m.mu.Unlock()

	if oldCancel != nil {
		oldCancel(errRouteChanged)
	}
	if oldTransport != nil {
		oldTransport.CloseIdleConnections()
	}
	if oldShared != nil {
		oldShared.CloseIdleConnections()
	}
	if oldLookup != nil {
		oldLookup.CloseIdleConnections()
	}
	// Outside the lock and after the generation has already moved on: a hook
	// that dropped sockets may take real work, and nothing about it is allowed to
	// hold up the next route application.
	m.runRouteChangeHooks()
	return nil
}

func buildRouteDialer(address string) (func(context.Context, string, string) (net.Conn, error), error) {
	bounds := loadTransportBounds()
	if address == "" {
		return bounds.dialer().DialContext, nil
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("SOCKS5 route must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("SOCKS5 route port is invalid")
	}
	socksDialer, err := xproxy.SOCKS5("tcp", address, nil, bounds.dialer())
	if err != nil {
		return nil, fmt.Errorf("configure SOCKS5 route %s: %w", address, err)
	}
	direct := bounds.dialer()
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		// A SOCKS5 route cannot carry a loopback destination: the proxy dials
		// the address from its own host, where 127.0.0.1 is the proxy itself, so
		// every request to a local service fails the moment Tor is enabled. The
		// local QA path in AGENTS.md crawls exactly such targets, so the dialer
		// resolves them itself.
		//
		// This is a transport capability, not a policy: no destination is
		// refused here. A loopback address is not routable anywhere else, so
		// there is nothing to leak by connecting to it directly, and a route
		// that could reach it would not be this route.
		if isLoopbackTarget(target) {
			return direct.DialContext(ctx, network, target)
		}
		type result struct {
			conn net.Conn
			err  error
		}
		results := make(chan result)
		go func() {
			conn, err := socksDialer.Dial(network, target)
			select {
			case results <- result{conn: conn, err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case dialed := <-results:
			return dialed.conn, dialed.err
		}
	}, nil
}

// isLoopbackTarget reports whether a dial target names the local host.
//
// It resolves the host rather than testing the string, because "localhost",
// "127.0.0.1" and "[::1]" are three spellings of the same destination and a
// string check would let one of them through the route.
func isLoopbackTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// A target without a port cannot be dialled, so it is not a local
		// service either; leave it to the route.
		return false
	}
	if strings.EqualFold(strings.Trim(host, "[]"), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (m *routeManager) configSnapshot() routeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	config := m.config
	config.Generation = m.generation
	return config
}

func (m *routeManager) generationSnapshot() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}

func (m *routeManager) proxyServer() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config.Address == "" {
		return ""
	}
	return "socks5://" + m.config.Address
}

func (m *routeManager) ensureGenerationContextLocked() {
	if m.generationCtx != nil {
		return
	}
	m.generationCtx, m.generationEnd = context.WithCancelCause(context.Background())
}

// acquire binds parent to the currently installed route generation.
func (m *routeManager) acquire(parent context.Context) (*routeLease, context.Context, context.CancelFunc) {
	return m.acquireWithTransport(parent, false)
}

// acquireShared binds a passive-proxy exchange to the current generation and its
// shared transport.
func (m *routeManager) acquireShared(parent context.Context) (*routeLease, context.Context, context.CancelFunc) {
	return m.acquireWithTransport(parent, true)
}

// acquireBackground binds a long-running job to the current generation. Unlike
// acquire it deliberately does not inherit the HTTP request context, because
// the job must outlive the request that started it, while a route switch still
// has to cancel it.
func (m *routeManager) acquireBackground(expected *uint64) (*routeLease, context.Context, context.CancelFunc) {
	return m.acquireWithExpected(context.Background(), false, expected, true)
}

// acquireExpectedBackground is the generation-checked form of acquireBackground.
func (m *routeManager) acquireExpectedBackground(expected uint64) (*routeLease, context.Context, context.CancelFunc) {
	return m.acquireWithExpected(context.Background(), false, &expected, true)
}

func (m *routeManager) acquireWithTransport(parent context.Context, shared bool) (*routeLease, context.Context, context.CancelFunc) {
	return m.acquireWithExpected(parent, shared, nil, false)
}

func (m *routeManager) acquireExpected(parent context.Context, expected uint64) (*routeLease, context.Context, context.CancelFunc) {
	return m.acquireWithExpected(parent, false, &expected, false)
}

func (m *routeManager) acquireWithExpected(parent context.Context, shared bool, expected *uint64, detached bool) (*routeLease, context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	m.mu.Lock()
	if expected != nil && m.generation != *expected {
		m.mu.Unlock()
		cancelled, cancel := context.WithCancelCause(parent)
		cancel(errRouteChanged)
		return nil, cancelled, func() { cancel(context.Canceled) }
	}
	m.ensureGenerationContextLocked()
	lease := &routeLease{
		manager:    m,
		generation: m.generation,
		context:    m.generationCtx,
		dialer:     m.dialer,
		transport:  m.current,
	}
	if shared {
		lease.shared = m.shared
	}
	generationContext := m.generationCtx
	m.mu.Unlock()
	if detached {
		// A background job keeps only the generation signal: the request that
		// started it may finish immediately, and that must not kill the job.
		parent = context.Background()
	}

	merged, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(generationContext, func() {
		cancel(errRouteChanged)
	})
	if generationContext.Err() != nil {
		cancel(errRouteChanged)
	}
	boundContext := context.WithValue(merged, routeBindingKey{}, routeBinding{lease: lease, shared: shared})
	release := func() {
		stop()
		cancel(context.Canceled)
	}
	return lease, boundContext, release
}

func (m *routeManager) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var conn net.Conn
			var err error
			if lease, ok := routeLeaseFromContext(ctx); ok {
				conn, err = lease.dialContext(ctx, network, address)
			} else {
				if m.configSnapshot().Address != "" {
					network = "tcp"
				}
				conn, err = m.dialContext(ctx, network, address)
			}
			return boundDNSConn(ctx, conn, err)
		},
	}
}

// boundDNSConn puts the DNS query bound on the socket that carries it.
//
// The deadline is the whole fix, and it has to be on the connection rather than
// on the dial: `Dial` here is called once per nameserver per query, so setting a
// deadline on the returned socket is what bounds the wait for the ANSWER. Without
// it Go applies its own per-query budget, measured in seconds, and a scan that
// resolves a hostname per request pays that on every single one — 82 such waits
// were recorded on one scan of the `http` corpus because the machine's
// `/etc/resolv.conf` lists an IPv6 nameserver that is not reachable.
//
// A context that already carries an earlier deadline wins, so a cancelled route
// switch is not turned back into a 2-second wait by this bound.
func boundDNSConn(ctx context.Context, conn net.Conn, err error) (net.Conn, error) {
	if err != nil || conn == nil {
		return conn, err
	}
	bound := loadTransportBounds().DNSQueryTimeout
	if existing, ok := ctx.Deadline(); ok && time.Until(existing) < bound {
		bound = time.Until(existing)
	}
	if bound > 0 {
		_ = conn.SetDeadline(time.Now().Add(bound))
	}
	return conn, nil
}

func (m *routeManager) dialContext(ctx context.Context, network, target string) (net.Conn, error) {
	m.mu.RLock()
	dial := m.dialer
	m.mu.RUnlock()
	if dial == nil {
		return nil, fmt.Errorf("route is not configured")
	}
	return dial(ctx, network, target)
}

func (m *routeManager) ephemeralTransport() *http.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if lease, ok := routeLeaseFromContext(ctx); ok {
				return lease.dialContext(ctx, network, address)
			}
			return m.dialContext(ctx, network, address)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	// A transport without keep-alive still needs the dial, handshake and header
	// bounds: it is used for one-shot calls, which are exactly the calls that
	// leave nothing to time them out from the pool side.
	loadTransportBounds().apply(transport)
	return transport
}

func (m *routeManager) transport() *http.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// currentGeneration is the identity of the route currently installed. Two
// exchanges that read the same value are talking through the same exit, which is
// what lets an in-flight external-IP lookup be shared between them.
func (m *routeManager) currentGeneration() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}

func (m *routeManager) sharedTransport() *http.Transport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shared == nil {
		m.shared = m.newSharedTransportLocked()
	}
	return m.shared
}

// lookupTransport returns the transport the external-IP lookup travels on, and it
// is a pooled one on purpose.
//
// MEASURED 2026-10-10 from this machine, every sample a full HTTPS GET to
// check.torproject.org/api/ip:
//
//	dns=0.86s  connect=0.54s  tls=0.84s  ttfb=0.79s  total=3.03s
//	the same request over an already-warm connection:  0.62s
//
// Two and a quarter of those three seconds are DNS, TCP and TLS — work that has
// nothing to do with how fast the endpoint answers, and that `ephemeralTransport`
// throws away after every single lookup by setting `DisableKeepAlives: true` and
// being closed by its own caller's `closeIdle`. At three seconds per lookup, a
// semaFOR of eight slots sustains 2.2 lookups a second, and a burst of 1500
// exchanges inside 112ms could never be covered by it.
//
// This transport keeps the connection, so a lookup costs one round trip instead
// of a fresh handshake, and it is per-route: `install` replaces and closes it on
// every swap, so a pooled socket opened through one exit is never reused after
// the route moves to another. That is the whole freshness argument, and it is a
// property of the socket rather than of a cached answer — the value is still
// fetched fresh, every time, by whoever asks.
func (m *routeManager) lookupTransport() *http.Transport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lookup == nil {
		m.lookup = m.newLookupTransportLocked()
	}
	return m.lookup
}

func (m *routeManager) newLookupTransportLocked() *http.Transport {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if lease, ok := routeLeaseFromContext(ctx); ok {
				return lease.dialContext(ctx, network, address)
			}
			return m.dialContext(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: false,
		// The lookup host is one host, so the pool ceiling *is* the number of
		// concurrent lookups. It matches the semaFOR on purpose: a slot exists to
		// open a request, and there is no reason for the pool to hold fewer idle
		// sockets than there are slots able to use them.
		MaxIdleConnsPerHost: sourceIPLookupConcurrency(),
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
	loadTransportBounds().apply(transport)
	return transport
}

func (m *routeManager) newSharedTransportLocked() *http.Transport {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if lease, ok := routeLeaseFromContext(ctx); ok {
				return lease.dialContext(ctx, network, address)
			}
			return m.dialContext(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
		// THE PASSIVE PROXY REUSES CONNECTIONS, AND THAT IS THE POINT OF THIS
		// TRANSPORT.
		//
		// It used to set `DisableKeepAlives: true`, so every captured exchange
		// cost a fresh TCP connect **and** a fresh TLS handshake to the target —
		// and the proxy already terminates one of each on the client side, so a
		// recorded scan paid two handshakes per request where the binary in a
		// terminal pays one. Measured 2026-10-07 on `http/miscellaneous` against
		// `https://ria.ru`, the same folder and the same nuclei binary:
		//
		//	nuclei in a terminal, no proxy       304.5 s   56 records   0 errors
		//	through the browser, via the proxy  1077.8 s
		//
		// and `data/logs/engine.log` counted **328**
		// `Cannot read response from mitm'd server net/http: TLS handshake timeout`
		// during that one run. The engine's handshake bound is 15 s
		// (`defaultTLSHandshakeTimeout`), so each of those exchanges held its
		// worker for a quarter of a minute as well — which is where the time went,
		// and where the operator's `errors 30` and a request count frozen at
		// `334 / 442` came from: nuclei's own `-mhe` default of 30 then stops
		// sending to a host that has failed that often.
		//
		// Reuse is safe here because the pool is flushed on every route change:
		// `install` calls `CloseIdleConnections()` on the shared transport it is
		// replacing, and every new dial reads the currently installed dialer. A
		// connection already in flight finishes under its own lease, which
		// `routeLease.validate` rejects once the generation has moved.
		DisableKeepAlives: false,
		// Go's default is 2, which is a pool for a browser and not for a scanner:
		// under the binary's own default concurrency (25 templates × 25 hosts)
		// everything past the second connection is closed again on use and the
		// handshake comes straight back. This is a socket budget rather than a
		// ceiling on anything the operator asked for; `IdleConnTimeout` (90 s by
		// default, `RR_IDLE_CONN_TIMEOUT_MS`) is what returns a connection the
		// target stopped using.
		MaxIdleConnsPerHost: 64,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
	loadTransportBounds().apply(transport)
	return transport
}

func (m *routeManager) newTransportLocked() *http.Transport {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if lease, ok := routeLeaseFromContext(ctx); ok {
				return lease.dialContext(ctx, network, address)
			}
			return m.dialContext(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}
	loadTransportBounds().apply(transport)
	return transport
}

func (m *routeManager) roundTripper() http.RoundTripper {
	return routeRoundTripper{manager: m}
}

type routeRoundTripper struct {
	manager *routeManager
	shared  bool
}

func (r routeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if binding, ok := req.Context().Value(routeBindingKey{}).(routeBinding); ok && binding.lease != nil {
		if err := binding.lease.validate(); err != nil {
			return nil, err
		}
		transport := binding.lease.transport
		if binding.shared {
			transport = binding.lease.shared
		}
		if transport == nil {
			return nil, fmt.Errorf("route transport is not configured")
		}
		return transport.RoundTrip(req)
	}
	if r.shared {
		transport := r.manager.sharedTransport()
		if transport == nil {
			return nil, fmt.Errorf("route transport is not configured")
		}
		return transport.RoundTrip(req)
	}
	transport := r.manager.transport()
	if transport == nil {
		return nil, fmt.Errorf("route transport is not configured")
	}
	return transport.RoundTrip(req)
}

func (lease *routeLease) validate() error {
	select {
	case <-lease.context.Done():
		return errRouteChanged
	default:
	}
	lease.manager.mu.RLock()
	current := lease.manager.generation == lease.generation
	lease.manager.mu.RUnlock()
	if !current {
		return errRouteChanged
	}
	return nil
}

func (lease *routeLease) dialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if err := lease.validate(); err != nil {
		return nil, err
	}
	if lease.dialer == nil {
		return nil, fmt.Errorf("route is not configured")
	}
	return lease.dialer(ctx, network, target)
}

func (lease *routeLease) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if lease.manager.configSnapshot().Address != "" {
				network = "tcp"
			}
			// The same DNS query bound the shared resolver applies. This one is
			// the per-generation resolver, so without it a routed request would
			// keep paying the seconds-long per-query budget that the bound exists
			// to remove — the route would change the timing of a lookup rather
			// than only where it goes.
			conn, err := lease.dialContext(ctx, network, address)
			return boundDNSConn(ctx, conn, err)
		},
	}
}

func routeLeaseFromContext(ctx context.Context) (*routeLease, bool) {
	binding, ok := ctx.Value(routeBindingKey{}).(routeBinding)
	if !ok || binding.lease == nil {
		return nil, false
	}
	return binding.lease, true
}

func withExpectedRouteGeneration(ctx context.Context, generation uint64) context.Context {
	return context.WithValue(ctx, expectedRouteGenerationKey{}, generation)
}

func expectedRouteGeneration(ctx context.Context) (uint64, bool) {
	generation, ok := ctx.Value(expectedRouteGenerationKey{}).(uint64)
	return generation, ok
}

func canceledExpectedRouteContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancelCause(parent)
	cancel(errRouteChanged)
	return ctx, func() { cancel(context.Canceled) }
}
