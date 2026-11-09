package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"intruder/engine/pkg/passive"
)

func TestRecordedToolTransportKeepsTheRouteAndCapturesHTTPS(t *testing.T) {
	var targetHeader string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHeader = r.Header.Get(passive.CaptureContextHeader)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "captured response")
	}))
	defer target.Close()

	store := passive.NewStore()
	engine := &server{
		store:     store,
		transport: target.Client().Transport.(*http.Transport),
	}
	transport, err := engine.toolRouteTransport(toolRunRoute{
		// A closed proxy address proves this request uses the selected route
		// directly rather than adding a second, failure-prone TLS hop.
		Proxy:          "http://127.0.0.1:1",
		CaptureContext: "run-token-1",
	})
	if err != nil {
		t.Fatalf("build tool transport: %v", err)
	}
	response, err := (&http.Client{Transport: transport}).Get(target.URL + "/page")
	if err != nil {
		t.Fatalf("tool request: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read tool response: %v", err)
	}
	if string(body) != "captured response" {
		t.Fatalf("response body = %q", body)
	}
	if targetHeader != "" {
		t.Fatalf("capture context leaked to the target: %q", targetHeader)
	}

	events := store.List()
	if len(events) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(events))
	}
	event := events[0]
	if event.Source != "tool" || event.CaptureContext != "run-token-1" {
		t.Fatalf("event attribution = source %q, context %q", event.Source, event.CaptureContext)
	}
	if event.URL != target.URL+"/page" || event.Status != http.StatusOK {
		t.Fatalf("captured exchange = %+v", event)
	}
	if event.ResponseBody != "captured response" || event.ResponseSize != len("captured response") {
		t.Fatalf("captured response evidence = %+v", event)
	}
	if _, leaked := event.RequestHeader[passive.CaptureContextHeader]; leaked {
		t.Fatal("the internal capture token must not be stored as a request header")
	}
}

func TestRecordedToolTransportCapturesNetworkErrors(t *testing.T) {
	store := passive.NewStore()
	engine := &server{
		store: store,
		transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("fixture connection refused")
		}},
	}
	transport, err := engine.toolRouteTransport(toolRunRoute{
		Proxy:          "http://127.0.0.1:8080",
		CaptureContext: "failed-run",
	})
	if err != nil {
		t.Fatalf("build tool transport: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://target.test/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("the fixture transport should fail")
	}
	events := store.List()
	if len(events) != 1 || events[0].Error != "fixture connection refused" {
		t.Fatalf("network failure was not captured: %+v", events)
	}
}

func TestRecordedToolTransportMarksCompleteAndPartialBodyClosesCorrectly(t *testing.T) {
	for _, test := range []struct {
		name          string
		contentLength int64
		readBytes     int
		wantBody      string
		wantReadError string
	}{
		{
			name:          "complete content-length body",
			contentLength: 4,
			readBytes:     4,
			wantBody:      "body",
		},
		{
			name:          "incomplete content-length body",
			contentLength: 8,
			readBytes:     2,
			wantBody:      "bo",
			wantReadError: io.ErrUnexpectedEOF.Error(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.FormatInt(test.contentLength, 10))
				_, _ = io.WriteString(w, "body")
			}))
			defer target.Close()

			store := passive.NewStore()
			engine := &server{
				store:     store,
				transport: target.Client().Transport.(*http.Transport),
			}
			transport, err := engine.toolRouteTransport(toolRunRoute{
				Proxy:          "http://127.0.0.1:8080",
				CaptureContext: "body-run",
			})
			if err != nil {
				t.Fatalf("build tool transport: %v", err)
			}
			request, err := http.NewRequest(http.MethodGet, target.URL, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatalf("tool request: %v", err)
			}
			buffer := make([]byte, test.readBytes)
			if _, err := io.ReadFull(response.Body, buffer); err != nil {
				t.Fatalf("read response: %v", err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatalf("close response: %v", err)
			}
			if got := string(buffer); got != test.wantBody {
				t.Fatalf("response body = %q, want %q", got, test.wantBody)
			}
			events := store.List()
			if len(events) != 1 {
				t.Fatalf("recorded %d exchanges, want 1", len(events))
			}
			if events[0].Error != test.wantReadError {
				t.Fatalf("recorded error = %q, want %q", events[0].Error, test.wantReadError)
			}
			if events[0].ResponseBody != test.wantBody {
				t.Fatalf("recorded response body = %q, want %q", events[0].ResponseBody, test.wantBody)
			}
		})
	}
}

func TestAToolRunWithoutARecordingProxyKeepsTheDirectRoute(t *testing.T) {
	engine := &server{}
	transport, err := engine.toolRouteTransport(toolRunRoute{})
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	if transport != engine.requestTransport() {
		t.Fatal("an unrecorded run must use the direct route transport")
	}
	if got := (toolRunRoute{}).proxyForRun(nil); got != "" {
		t.Fatalf("proxyForRun without a proxy or a route = %q, want empty", got)
	}
}

func TestAToolRunWithACaptureContextButNoProxyIsRecorded(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "captured")
	}))
	defer target.Close()

	store := passive.NewStore()
	engine := &server{
		store:     store,
		transport: target.Client().Transport.(*http.Transport),
	}
	transport, err := engine.toolRouteTransport(toolRunRoute{CaptureContext: "context-only"})
	if err != nil {
		t.Fatalf("build tool transport: %v", err)
	}
	response, err := (&http.Client{Transport: transport}).Get(target.URL)
	if err != nil {
		t.Fatalf("tool request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()

	events := store.List()
	if len(events) != 1 || events[0].CaptureContext != "context-only" {
		t.Fatalf("tool request without an explicit proxy was not recorded: %+v", events)
	}
}

func TestAnUnparsableToolProxyIsAnErrorRatherThanASilentFallback(t *testing.T) {
	engine := &server{}
	if _, err := engine.toolRouteTransport(toolRunRoute{Proxy: "not-a-url"}); err == nil {
		t.Fatal("an unparsable proxy address must be reported, not ignored")
	}
	if _, err := engine.toolRouteTransport(toolRunRoute{Proxy: "ftp://127.0.0.1:8080"}); err == nil {
		t.Fatal("a non-HTTP proxy scheme must be reported, not ignored")
	}
}

func TestAnUnrecordedNucleiRunKeepsTheRouteProxy(t *testing.T) {
	routes, err := newRouteManagerWithRoute(routeConfig{Address: "127.0.0.1:9050"})
	if err != nil {
		t.Fatalf("route manager: %v", err)
	}
	if got := (toolRunRoute{}).proxyForRun(routes); got != "socks5://127.0.0.1:9050" {
		t.Fatalf("unrecorded proxy = %q, want the route's own", got)
	}
	recorded := toolRunRoute{Proxy: "http://127.0.0.1:8080"}
	if got := recorded.proxyForRun(routes); got != "http://127.0.0.1:8080" {
		t.Fatalf("recorded proxy = %q, want the local recording proxy", got)
	}
}

func TestAnUnrecordedNucleiRunSendsNoCaptureHeader(t *testing.T) {
	if headers := (toolRunRoute{}).captureHeaders(); headers != nil {
		t.Fatalf("an unrecorded run would send %v", headers)
	}
	headers := (toolRunRoute{CaptureContext: "tok"}).captureHeaders()
	if headers[passive.CaptureContextHeader] != "tok" {
		t.Fatalf("capture headers = %v, want the correlation token", headers)
	}
}

func TestActiveScanRecordsHTTPSRequestsOnItsDirectRoute(t *testing.T) {
	target := activeScanTarget(t)
	store := passive.NewStore()
	engine := &server{
		store:             store,
		transport:         http.DefaultTransport.(*http.Transport),
		sourceIPTransport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("disabled") }),
	}
	job, err := engine.startActiveScanJob(context.Background(), activeScanInput{
		URL:      target.URL,
		MaxPages: 1,
		MaxDepth: 0,
		toolRunRoute: toolRunRoute{
			Proxy:          "http://127.0.0.1:1",
			CaptureContext: "active-run",
		},
	})
	if err != nil {
		t.Fatalf("start active scan: %v", err)
	}
	snapshot := waitForActiveScan(t, engine, job.id)
	if snapshot.State != activeJobCompleted {
		t.Fatalf("active scan state = %q, error = %q", snapshot.State, snapshot.Error)
	}
	events := store.List()
	if len(events) == 0 {
		t.Fatal("active scan made no recorded requests")
	}
	for _, event := range events {
		if event.Source != "tool" || event.CaptureContext != "active-run" {
			t.Fatalf("active scan event was not attributed: %+v", event)
		}
	}
	if !strings.HasPrefix(events[0].URL, target.URL) {
		t.Fatalf("captured URL = %q, want target %q", events[0].URL, target.URL)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
