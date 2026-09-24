package passive

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
	for _, value := range []string{"", "bad value", "bad/value", strings.Repeat("a", 65)} {
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
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
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
