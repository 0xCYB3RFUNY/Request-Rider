package passive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
)

func TestReadAndRestorePreservesBody(t *testing.T) {
	body := io.NopCloser(strings.NewReader("0123456789"))
	captured, err := readAndRestore(&body)
	if err != nil {
		t.Fatalf("readAndRestore() error = %v", err)
	}
	if string(captured) != "0123456789" {
		t.Fatalf("captured body = %q, want original body", captured)
	}
	restored, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(restored) != "0123456789" {
		t.Fatalf("restored body = %q, want original body", restored)
	}
}

func TestStoreKeepsMostRecentEvents(t *testing.T) {
	store := NewStore()
	for index := int64(1); index <= 3; index++ {
		store.Add(Event{Session: index})
	}

	events := store.List()
	if len(events) != 3 || events[0].Session != 1 || events[2].Session != 3 {
		t.Fatalf("stored events = %#v, want all sessions", events)
	}
}

func TestStoreClearRemovesSnapshotAndReplay(t *testing.T) {
	store := NewStore()
	store.Add(Event{Method: "GET"})
	store.Clear()
	if events := store.List(); len(events) != 0 {
		t.Fatalf("snapshot after clear = %#v", events)
	}
	if events := store.ListSince(0); len(events) != 0 {
		t.Fatalf("replay after clear = %#v", events)
	}
}

func TestStoreCanPauseAndResumeCapture(t *testing.T) {
	store := NewStore()
	if !store.Recording() {
		t.Fatal("store should record by default")
	}
	if !store.Pause() {
		t.Fatal("pause should succeed when capture is active")
	}
	if store.Recording() {
		t.Fatal("store should stop recording while paused")
	}
	if store.Add(Event{Method: "GET", URL: "https://example.test/paused"}) != 0 {
		t.Fatal("paused store should ignore new record additions")
	}
	if !store.Resume() {
		t.Fatal("resume should succeed when capture is paused")
	}
	if store.Add(Event{Method: "GET", URL: "https://example.test/resumed"}) == 0 {
		t.Fatal("resumed store should accept new record additions")
	}
}

func TestStorePublishesRequestAndResponseUpdates(t *testing.T) {
	store := NewStore()
	events, unsubscribe := store.Subscribe()
	defer unsubscribe()

	id := store.Add(Event{Method: "GET", URL: "https://example.test/path"})
	requestEvent := <-events
	if requestEvent.ID != id || requestEvent.URL == "" || requestEvent.Status != 0 {
		t.Fatalf("request event = %#v", requestEvent)
	}

	store.Update(id, func(event *Event) {
		event.Status = http.StatusNoContent
		event.Latency = 12
	})
	responseEvent := <-events
	if responseEvent.ID != id || responseEvent.Status != http.StatusNoContent || responseEvent.Latency != 12 {
		t.Fatalf("response event = %#v", responseEvent)
	}

}

func TestNormalizeCaptureContext(t *testing.T) {
	if got := normalizeCaptureContext("  abc_123-xyz  "); got != "abc_123-xyz" {
		t.Fatalf("normalized capture context = %q", got)
	}
	for _, value := range []string{"", "bad value", "bad/value"} {
		if got := normalizeCaptureContext(value); got != "" {
			t.Fatalf("normalizeCaptureContext(%q) = %q, want empty", value, got)
		}
	}
}

func TestCaptureRequestStoresContextButRemovesHeaderBeforeUpstream(t *testing.T) {
	store := NewStore()
	proxy := &Proxy{Store: store}
	request := httptest.NewRequest(http.MethodGet, "https://example.test/path", strings.NewReader(""))
	request.Header.Set(CaptureContextHeader, "capture_123")
	ctx := &goproxy.ProxyCtx{Session: 9}

	returned, response := proxy.captureRequest(request, ctx)
	if response != nil || returned != request {
		t.Fatalf("captureRequest() = (%#v, %#v)", returned, response)
	}
	if request.Header.Get(CaptureContextHeader) != "" {
		t.Fatal("capture context header leaked upstream")
	}
	events := store.List()
	if len(events) != 1 || events[0].CaptureContext != "capture_123" {
		t.Fatalf("captured events = %#v", events)
	}
	if _, ok := events[0].RequestHeader[CaptureContextHeader]; ok {
		t.Fatal("capture context header leaked into captured request metadata")
	}
}

func TestCaptureRequestPublishesPendingBeforeSourceLookup(t *testing.T) {
	store := NewStore()
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	lookupFinished := make(chan struct{})
	proxy := &Proxy{
		Store: store,
		SourceIP: func(context.Context) string {
			close(lookupStarted)
			<-releaseLookup
			close(lookupFinished)
			return "198.51.100.77"
		},
	}
	request := httptest.NewRequest(http.MethodGet, "http://fixture.test/slow", nil)
	proxyCtx := &goproxy.ProxyCtx{Session: 77}
	done := make(chan struct{})
	go func() {
		proxy.captureRequest(request, proxyCtx)
		close(done)
	}()
	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("source lookup did not start")
	}
	events := store.List()
	if len(events) != 1 || events[0].Status != 0 || events[0].SourceIP != "" {
		t.Fatalf("pending event = %#v", events)
	}
	close(releaseLookup)
	select {
	case <-lookupFinished:
	case <-time.After(time.Second):
		t.Fatal("source lookup did not finish")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture did not finish after source lookup")
	}
	events = store.List()
	if len(events) != 1 || events[0].SourceIP != "198.51.100.77" {
		t.Fatalf("source IP event = %#v", events)
	}
}

func TestProxyHandlerPropagatesContextWithoutSendingHeaderUpstream(t *testing.T) {
	upstreamHeader := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamHeader <- request.Header.Get(CaptureContextHeader)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	store := NewStore()
	proxyServer := httptest.NewServer((&Proxy{Store: store}).Handler())
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}}
	request, err := http.NewRequest(http.MethodGet, target.URL+"/capture", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(CaptureContextHeader, "proxy_capture_123")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("proxy status = %d", response.StatusCode)
	}
	if header := <-upstreamHeader; header != "" {
		t.Fatalf("upstream received internal header %q", header)
	}
	events := store.List()
	if len(events) != 1 || events[0].CaptureContext != "proxy_capture_123" {
		t.Fatalf("proxy events = %#v", events)
	}
}

type switchableDialer struct {
	mu   sync.RWMutex
	fail bool
}

func (d *switchableDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.RLock()
	fail := d.fail
	d.mu.RUnlock()
	if fail {
		return nil, errors.New("route switched")
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *switchableDialer) setFail(value bool) {
	d.mu.Lock()
	d.fail = value
	d.mu.Unlock()
}

func TestProxyUsesDynamicRouteTransportAfterSwitch(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	dialer := &switchableDialer{}
	dynamic := &http.Transport{DialContext: dialer.dial, DisableKeepAlives: true}
	store := NewStore()
	proxy := &Proxy{Store: store, Transport: dynamic}
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}}

	request, err := http.NewRequest(http.MethodGet, target.URL+"/before", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("initial proxy request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("initial status = %d", response.StatusCode)
	}

	dialer.setFail(true)
	request, err = http.NewRequest(http.MethodGet, target.URL+"/after", nil)
	if err != nil {
		t.Fatalf("new switched request: %v", err)
	}
	switchedResponse, err := client.Do(request)
	if err != nil {
		if !strings.Contains(err.Error(), "route switched") {
			t.Fatalf("switched proxy error = %v, want route switched", err)
		}
	} else {
		switchedResponse.Body.Close()
		if switchedResponse.StatusCode == http.StatusNoContent {
			t.Fatal("switched proxy request unexpectedly reused the previous route")
		}
	}
	events := store.List()
	if len(events) < 2 || !strings.Contains(fmt.Sprint(events[len(events)-1].Error), "route switched") {
		t.Fatalf("switched proxy event = %#v, want route switched error", events)
	}
}

func TestRouteCancellationInterruptsPassiveExchange(t *testing.T) {
	started := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	defer upstream.Close()

	store := NewStore()
	proxy := &Proxy{
		Store:     store,
		Transport: &http.Transport{DisableKeepAlives: true},
		SourceIP: func(context.Context) string {
			return "198.51.100.25"
		},
	}
	routeCancel := make(chan context.CancelFunc, 1)
	proxy.RouteContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		routeCancel <- cancel
		return ctx, cancel
	}
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}}
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/slow", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		response, requestErr := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		result <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("passive upstream did not start")
	}
	cancel := <-routeCancel
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("passive request did not stop after route cancellation")
	}
	events := store.List()
	if len(events) != 1 || events[0].SourceIP != "198.51.100.25" || events[0].Error == "" {
		t.Fatalf("cancelled passive event = %#v", events)
	}
}

func TestEventKeepsZeroResponseSizeInJSON(t *testing.T) {
	payload, err := json.Marshal(Event{
		Status:       http.StatusNoContent,
		ResponseSize: 0,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(payload), `"response_size":0`) {
		t.Fatalf("event JSON = %s, want explicit zero response_size", payload)
	}
}

func TestStoreReplaysUpdatesAfterCursor(t *testing.T) {
	store := NewStore()
	id := store.Add(Event{Method: "GET"})
	initial := store.ListSince(0)
	if len(initial) != 1 || initial[0].ID != id {
		t.Fatalf("initial replay = %#v", initial)
	}

	store.Update(id, func(event *Event) { event.Status = http.StatusOK })
	replayed := store.ListSince(initial[0].Cursor)
	if len(replayed) != 1 || replayed[0].ID != id || replayed[0].Status != http.StatusOK {
		t.Fatalf("updated replay = %#v", replayed)
	}

}

func TestStoreResetsCursorAfterEngineRestartEpoch(t *testing.T) {
	store := NewStore()
	store.Add(Event{Method: "GET"})
	events := store.ListSince(100)
	if len(events) != 1 {
		t.Fatalf("restart reconciliation = %#v, want current snapshot", events)
	}
}

func TestFlattenHeaders(t *testing.T) {
	headers := flattenHeaders(http.Header{"X-Test": {"one", "two"}})
	if headers["X-Test"] != "one, two" {
		t.Fatalf("flattened header = %q", headers["X-Test"])
	}
}

func TestListSummaryKeepsEveryFieldExceptThePayload(t *testing.T) {
	store := NewStore()
	store.Add(Event{
		ID:                  1,
		Method:              "GET",
		URL:                 "http://target.local/big",
		Host:                "target.local",
		Status:              200,
		ResponseSize:        524288,
		Latency:             12,
		RequestHeader:       map[string]string{"Host": "target.local"},
		RequestBody:         "request-payload",
		ResponseHeader:      map[string]string{"Content-Type": "application/octet-stream"},
		ResponseBody:        "response-payload",
		Tags:                []string{"kept"},
		Notes:               "kept too",
		ResponseContentType: "application/octet-stream",
	})

	summary := store.ListSummary()
	if len(summary) != 1 {
		t.Fatalf("summary length = %d, want 1", len(summary))
	}
	row := summary[0]
	// The payload is what a table row does not show.
	if row.RequestBody != "" || row.ResponseBody != "" {
		t.Fatalf("summary kept a body: request=%q response=%q", row.RequestBody, row.ResponseBody)
	}
	if row.RequestHeader != nil || row.ResponseHeader != nil {
		t.Fatalf("summary kept headers: request=%#v response=%#v", row.RequestHeader, row.ResponseHeader)
	}
	// Everything the row actually displays, and the annotations, stay.
	if row.ID != 1 || row.Method != "GET" || row.URL != "http://target.local/big" ||
		row.Host != "target.local" || row.Status != 200 || row.Latency != 12 {
		t.Fatalf("summary lost row columns: %#v", row)
	}
	if row.ResponseSize != 524288 {
		t.Fatalf("summary response_size = %d, want the recorded size", row.ResponseSize)
	}
	if len(row.Tags) != 1 || row.Notes != "kept too" {
		t.Fatalf("summary lost annotations: tags=%#v notes=%q", row.Tags, row.Notes)
	}

	// The Store still holds the payload: nothing was dropped.
	full, ok := store.Get(1)
	if !ok {
		t.Fatal("store.Get(1) reported the event as missing")
	}
	if full.RequestBody != "request-payload" || full.ResponseBody != "response-payload" {
		t.Fatalf("stored payload changed: request=%q response=%q", full.RequestBody, full.ResponseBody)
	}
	if full.RequestHeader["Host"] != "target.local" ||
		full.ResponseHeader["Content-Type"] != "application/octet-stream" {
		t.Fatalf("stored headers changed: %#v %#v", full.RequestHeader, full.ResponseHeader)
	}
	if events := store.List(); len(events) != 1 || events[0].ResponseBody != "response-payload" {
		t.Fatalf("full listing lost the payload: %#v", events)
	}
}

func TestListSummaryOfAnEmptyStoreIsEmptyNotNil(t *testing.T) {
	store := NewStore()
	if summary := store.ListSummary(); summary == nil || len(summary) != 0 {
		t.Fatalf("empty summary = %#v, want an empty slice", summary)
	}
}

func TestGetReportsAMissingEvent(t *testing.T) {
	store := NewStore()
	// The Store assigns ids itself, so the test reads back the one it was given
	// instead of assuming which id the event received.
	id := store.Add(Event{ResponseBody: "kept"})
	if id == 0 {
		t.Fatal("store.Add did not assign an id")
	}
	event, ok := store.Get(id)
	if !ok {
		t.Fatalf("store.Get(%d) did not find a stored event", id)
	}
	if event.ResponseBody != "kept" {
		t.Fatalf("store.Get(%d) body = %q, want the stored payload", id, event.ResponseBody)
	}
	if _, ok := store.Get(id + 1); ok {
		t.Fatalf("store.Get(%d) invented an event", id+1)
	}
}

func TestListSummaryDoesNotMutateTheStoredEvents(t *testing.T) {
	store := NewStore()
	store.Add(Event{
		Method:         "GET",
		URL:            "http://target.local/kept",
		ResponseBody:   "payload",
		ResponseHeader: map[string]string{"A": "b"},
		Tags:           []string{"original"},
	})
	first := store.ListSummary()
	if len(first) != 1 {
		t.Fatalf("summary length = %d, want 1", len(first))
	}
	// A summary is a copy: writing to it must not reach the Store. The tag slice
	// is the one shared reference that survives a field-by-field copy, so it is
	// what proves the copy is real rather than a set of pointers.
	first[0].ResponseBody = "tampered"
	first[0].URL = "tampered"
	first[0].Method = "tampered"
	first[0].Tags[0] = "tampered"

	second := store.List()
	if second[0].ResponseBody != "payload" {
		t.Fatalf("stored body was mutated through a summary: %q", second[0].ResponseBody)
	}
	if second[0].URL != "http://target.local/kept" {
		t.Fatalf("stored URL was mutated through a summary: %q", second[0].URL)
	}
	if second[0].Method != "GET" {
		t.Fatalf("stored method was mutated through a summary: %q", second[0].Method)
	}
	if second[0].ResponseHeader["A"] != "b" {
		t.Fatalf("stored header was mutated through a summary: %#v", second[0].ResponseHeader)
	}
	if second[0].Tags[0] != "original" {
		t.Fatalf("stored tag was mutated through a summary: %#v", second[0].Tags)
	}
}
