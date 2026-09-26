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
	// generation identifies the current route and its cancellation scope.
	generation    uint64
	generationCtx context.Context
	generationEnd context.CancelCauseFunc
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
	return nil
}

func buildRouteDialer(address string) (func(context.Context, string, string) (net.Conn, error), error) {
	if address == "" {
		directDialer := &net.Dialer{}
		return directDialer.DialContext, nil
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("SOCKS5 route must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("SOCKS5 route port is invalid")
	}
	socksDialer, err := xproxy.SOCKS5("tcp", address, nil, &net.Dialer{})
	if err != nil {
		return nil, fmt.Errorf("configure SOCKS5 route %s: %w", address, err)
	}
	return func(ctx context.Context, network, target string) (net.Conn, error) {
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

// acquireShared binds a passive-proxy exchange to the current generation and
// its no-keepalive shared transport.
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
			if lease, ok := routeLeaseFromContext(ctx); ok {
				return lease.dialContext(ctx, network, address)
			}
			if m.configSnapshot().Address != "" {
				network = "tcp"
			}
			return m.dialContext(ctx, network, address)
		},
	}
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
	return &http.Transport{
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
}

func (m *routeManager) transport() *http.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *routeManager) sharedTransport() *http.Transport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shared == nil {
		m.shared = m.newSharedTransportLocked()
	}
	return m.shared
}

func (m *routeManager) newSharedTransportLocked() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if lease, ok := routeLeaseFromContext(ctx); ok {
				return lease.dialContext(ctx, network, address)
			}
			return m.dialContext(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func (m *routeManager) newTransportLocked() *http.Transport {
	return &http.Transport{
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
}

func (m *routeManager) roundTripper() http.RoundTripper {
	return routeRoundTripper{manager: m}
}

func (m *routeManager) sharedRoundTripper() http.RoundTripper {
	return routeRoundTripper{manager: m, shared: true}
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
			return lease.dialContext(ctx, network, address)
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
