package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

var (
	routeDialTimeout           = envLimit("RR_DIAL_TIMEOUT_MS", 10000)
	routeKeepAlive             = envLimit("RR_TCP_KEEPALIVE_SEC", 30)
	routeMaxIdleConns          = envLimit("RR_MAX_IDLE_CONNS", 100)
	routeIdleConnTimeout       = envLimit("RR_IDLE_CONN_TIMEOUT_SEC", 90)
	routeTLSHandshakeTimeout   = envLimit("RR_TLS_HANDSHAKE_TIMEOUT_MS", 10000)
	routeResponseHeaderTimeout = envLimit("RR_RESPONSE_HEADER_TIMEOUT_MS", 30000)
	routeExpectContinueTimeout = envLimit("RR_EXPECT_CONTINUE_TIMEOUT_MS", 1000)
)

type routeConfig struct {
	Address string `json:"address"`
}

type routeManager struct {
	mu         sync.RWMutex
	config     routeConfig
	dialer     func(context.Context, string, string) (net.Conn, error)
	current    *http.Transport
	generation uint64
}

func newRouteManager() (*routeManager, error) {
	manager := &routeManager{}
	if err := manager.set(routeConfig{}); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *routeManager) set(config routeConfig) error {
	address := strings.TrimSpace(config.Address)
	if address == "" {
		directDialer := &net.Dialer{
			Timeout:   time.Duration(routeDialTimeout) * time.Millisecond,
			KeepAlive: time.Duration(routeKeepAlive) * time.Second,
		}
		dial := directDialer.DialContext
		m.mu.Lock()
		old := m.current
		m.config = routeConfig{}
		m.dialer = dial
		m.generation++
		m.current = m.newTransportLocked()
		m.mu.Unlock()
		if old != nil {
			old.CloseIdleConnections()
		}
		return nil
	}

	socksDialer, err := xproxy.SOCKS5("tcp", address, nil, &net.Dialer{
		Timeout:   time.Duration(routeDialTimeout) * time.Millisecond,
		KeepAlive: time.Duration(routeKeepAlive) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("configure SOCKS5 route %s: %w", address, err)
	}
	dial := func(ctx context.Context, network, target string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		results := make(chan result, 1)
		go func() {
			conn, err := socksDialer.Dial(network, target)
			results <- result{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			return result.conn, result.err
		}
	}

	m.mu.Lock()
	old := m.current
	m.config = routeConfig{Address: address}
	m.dialer = dial
	m.generation++
	m.current = m.newTransportLocked()
	m.mu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
	return nil
}

func (m *routeManager) configSnapshot() routeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *routeManager) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
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

func (m *routeManager) transport() *http.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *routeManager) newTransportLocked() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           m.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          routeMaxIdleConns,
		IdleConnTimeout:       time.Duration(routeIdleConnTimeout) * time.Second,
		TLSHandshakeTimeout:   time.Duration(routeTLSHandshakeTimeout) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(routeResponseHeaderTimeout) * time.Millisecond,
		ExpectContinueTimeout: time.Duration(routeExpectContinueTimeout) * time.Millisecond,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func (m *routeManager) roundTripper() http.RoundTripper {
	return routeRoundTripper{manager: m}
}

type routeRoundTripper struct{ manager *routeManager }

func (r routeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := r.manager.transport()
	if transport == nil {
		return nil, fmt.Errorf("route is not configured")
	}
	return transport.RoundTrip(req)
}
