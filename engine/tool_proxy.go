package main

// Tool traffic recording without changing its route.
//
// Go-based tools keep the same selected route as Repeater. When the gateway
// supplies a capture context, their RoundTripper records lifecycle events in the
// shared Store without routing target TLS through a second MITM handshake.
// Binaries that only accept an HTTP proxy continue to use the passive proxy.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"intruder/engine/pkg/passive"
)

// toolTransportKey carries the transport one tool run must use through the
// context, so the shared OSINT adapters reach it without every call site growing
// a parameter. It is a transport, not a recorder: the proxy does the recording.
type toolTransportKey struct{}

// withToolTransport binds the transport of one tool run to its context.
func withToolTransport(ctx context.Context, transport http.RoundTripper) context.Context {
	if transport == nil {
		return ctx
	}
	return context.WithValue(ctx, toolTransportKey{}, transport)
}

// toolTransportFromContext returns the transport bound to this run, if any.
//
// It is the interface rather than a concrete type because a recording transport
// may be the bare `*http.Transport` or the header-stamping wrapper around it,
// and a run must not depend on which of the two the gateway's request produced.
func toolTransportFromContext(ctx context.Context) http.RoundTripper {
	if ctx == nil {
		return nil
	}
	transport, _ := ctx.Value(toolTransportKey{}).(http.RoundTripper)
	return transport
}

// toolRunRoute is what the gateway sends with every recording tool run: the
// local proxy to route through, and the correlation token its exchanges are
// filed under.
type toolRunRoute struct {
	Proxy          string `json:"proxy"`
	CaptureContext string `json:"capture_context"`
}

func (route toolRunRoute) validateProxy() error {
	address := strings.TrimSpace(route.Proxy)
	if address == "" {
		return nil
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("tool proxy must be an absolute http or https URL, got %q", address)
	}
	return nil
}

// proxyForRun is the proxy the nuclei binary sends through.
//
// A recorded run goes through the local passive proxy, which is what puts every
// template request into History in the order the binary sent it. An unrecorded
// run keeps the direct route proxy it has always had, so nothing about a scan
// changes when nobody asked to watch it.
func (route toolRunRoute) proxyForRun(routes *routeManager) string {
	if address := strings.TrimSpace(route.Proxy); address != "" {
		return address
	}
	if routes == nil {
		return ""
	}
	return routes.proxyServer()
}

// captureHeaders is the header set one run sends on every request. Today that is
// the correlation token and nothing else; the map exists so a second internal
// header does not mean a second mechanism.
func (route toolRunRoute) captureHeaders() map[string]string {
	token := strings.TrimSpace(route.CaptureContext)
	if token == "" {
		return nil
	}
	return map[string]string{passive.CaptureContextHeader: token}
}

// s.toolRouteTransport preserves the route transport and records the run
// directly, avoiding a second TLS hop through the passive proxy.
func (s *server) toolRouteTransport(route toolRunRoute) (http.RoundTripper, error) {
	if err := route.validateProxy(); err != nil {
		return nil, err
	}
	transport := s.requestTransport()
	if strings.TrimSpace(route.Proxy) == "" && strings.TrimSpace(route.CaptureContext) == "" {
		return transport, nil
	}
	// The resolver is handed to the recorder, not read once here: every tool's
	// exchanges reach Traffic through this transport, so this is the one place
	// where they all pick up the exit address. Resolving it here alone left the
	// run's own answer filled in and every recorded row empty.
	return passive.NewCaptureTransport(transport, s.store, route.CaptureContext, s.ensureSourceIP), nil
}

// bindToolRoute attaches the recording transport of a run to its context.
func (s *server) bindToolRoute(ctx context.Context, route toolRunRoute) (context.Context, error) {
	transport, err := s.toolRouteTransport(route)
	if err != nil {
		return ctx, err
	}
	if transport == nil {
		return ctx, nil
	}
	return withToolTransport(ctx, transport), nil
}

// s.toolClient is the client every OSINT adapter uses during a recorded run.
func (s *server) toolClient(ctx context.Context) *http.Client {
	transport := toolTransportFromContext(ctx)
	if transport == nil {
		transport = s.requestTransport()
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
