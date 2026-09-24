// Package passive implements Traffic capture for the local MITM proxy.
package passive

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"intruder/engine/pkg/ca"

	"github.com/elazarl/goproxy"
)

// CaptureContextHeader carries an opaque local correlation token to the proxy.
// The proxy removes it before forwarding the request upstream.
const CaptureContextHeader = "X-RequestRider-Capture-Context"

// Event is the JSON contract shared by the proxy, SSE stream and UI.
type Event struct {
	ID                   uint64            `json:"id"`
	Cursor               uint64            `json:"-"`
	Session              int64             `json:"session"`
	CaptureContext       string            `json:"capture_context,omitempty"`
	Timestamp            time.Time         `json:"timestamp"`
	Source               string            `json:"source,omitempty"`
	Method               string            `json:"method"`
	URL                  string            `json:"url"`
	Host                 string            `json:"host"`
	SourceIP             string            `json:"source_ip,omitempty"`
	RequestHeader        map[string]string `json:"request_headers"`
	RequestBody          string            `json:"request_body"`
	RequestBodyEncoding  string            `json:"request_body_encoding,omitempty"`
	RequestBodyBase64    string            `json:"request_body_base64,omitempty"`
	Status               int               `json:"status,omitempty"`
	ResponseHeader       map[string]string `json:"response_headers,omitempty"`
	ResponseBody         string            `json:"response_body,omitempty"`
	ResponseBodyEncoding string            `json:"response_body_encoding,omitempty"`
	ResponseBodyBase64   string            `json:"response_body_base64,omitempty"`
	ResponseContentType  string            `json:"response_content_type,omitempty"`
	ResponseSize         int               `json:"response_size"`
	Latency              int64             `json:"latency_ms,omitempty"`
	Error                string            `json:"error,omitempty"`
	Tags                 []string          `json:"tags,omitempty"`
	Notes                string            `json:"notes,omitempty"`
}

// Store keeps recent events and subscribers in process memory.
type Store struct {
	mu          sync.RWMutex
	events      []Event
	subscribers map[chan Event]struct{}
	nextID      uint64
	nextCursor  uint64
	replay      []Event
	paused      bool
}

// Store keeps the in-memory Traffic view and broadcasts request lifecycle updates.
func NewStore() *Store {
	// Start with an initialized subscriber map so Add can broadcast safely.
	return &Store{subscribers: make(map[chan Event]struct{})}
}

func (s *Store) Pause() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused {
		return false
	}
	s.paused = true
	return true
}

func (s *Store) Resume() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.paused {
		return false
	}
	s.paused = false
	return true
}

func (s *Store) Recording() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.paused
}

func (s *Store) Add(event Event) uint64 {
	// Add assigns a stable ID before publishing the pending event.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused {
		return 0
	}
	s.nextID++
	event.ID = s.nextID
	s.nextCursor++
	event.Cursor = s.nextCursor
	s.events = append(s.events, event)
	s.replay = append(s.replay, event)
	s.broadcastLocked(event)
	return event.ID
}

func (s *Store) List() []Event {
	// Return a copy so callers cannot mutate Store state without its lock.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.events) == 0 {
		return []Event{}
	}

	return append([]Event(nil), s.events...)
}

// Clear removes the current Traffic snapshot and replay backlog.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
	s.replay = nil
}

// ListSince returns every event update after a cursor.
func (s *Store) ListSince(cursor uint64) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cursor > s.nextCursor {
		cursor = 0
	}
	result := make([]Event, 0)
	for _, event := range s.replay {
		if event.Cursor > cursor {
			result = append(result, event)
		}
	}
	return result
}

// SubscribeSince atomically snapshots missed events and subscribes the caller.
func (s *Store) SubscribeSince(cursor uint64) ([]Event, <-chan Event, func()) {
	channel := make(chan Event, 32)
	s.mu.Lock()
	if cursor > s.nextCursor {
		// A restarted engine begins a fresh cursor epoch; reconcile from the
		// current snapshot instead of waiting forever for an impossible ID.
		cursor = 0
	}
	backlog := make([]Event, 0)
	for _, event := range s.replay {
		if event.Cursor > cursor {
			backlog = append(backlog, event)
		}
	}
	s.subscribers[channel] = struct{}{}
	s.mu.Unlock()
	return backlog, channel, func() {
		s.mu.Lock()
		if _, ok := s.subscribers[channel]; ok {
			delete(s.subscribers, channel)
			close(channel)
		}
		s.mu.Unlock()
	}
}

func (s *Store) Update(id uint64, update func(*Event)) {
	// Locate one event, apply its response update and broadcast the new state.
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.events {
		if s.events[index].ID == id {
			update(&s.events[index])
			s.nextCursor++
			s.events[index].Cursor = s.nextCursor
			s.replay = append(s.replay, s.events[index])
			s.broadcastLocked(s.events[index])
			return
		}
	}
}

func (s *Store) Annotate(id uint64, tags []string, notes string) bool {
	updated := false
	s.Update(id, func(event *Event) {
		event.Tags = tags
		event.Notes = notes
		updated = true
	})
	return updated
}

// Subscribe is intentionally non-blocking: a slow UI must not stop the proxy.
func (s *Store) Subscribe() (<-chan Event, func()) {
	// Buffered channels absorb short UI delays without blocking the proxy.
	channel := make(chan Event, 16)
	s.mu.Lock()
	s.subscribers[channel] = struct{}{}
	s.mu.Unlock()
	return channel, func() {
		s.mu.Lock()
		if _, ok := s.subscribers[channel]; ok {
			delete(s.subscribers, channel)
			close(channel)
		}
		s.mu.Unlock()
	}
}

func (s *Store) broadcastLocked(event Event) {
	// The caller must hold the Store write lock while iterating subscribers.
	for channel := range s.subscribers {
		select {
		case channel <- event:
		default:
			// A slow UI must not block proxy traffic.
		}
	}
}

type Proxy struct {
	// Store receives request and response lifecycle events.
	Store *Store
	// Transport is shared with active engine requests so route changes apply
	// consistently to MITM upstream traffic and tool requests.
	Transport *http.Transport
	// SourceIP resolves the public source IP used by the shared route.
	SourceIP func(context.Context) string
}

func NewProxy(store *Store, transport *http.Transport, sourceIP ...func(context.Context) string) *Proxy {
	// Bind the proxy to the shared event store.
	proxy := &Proxy{Store: store, Transport: transport}
	if len(sourceIP) > 0 {
		proxy.SourceIP = sourceIP[0]
	}
	return proxy
}

func (p *Proxy) Handler() http.Handler {
	// Configure GoProxy for HTTPS MITM and lifecycle callbacks.
	proxy := goproxy.NewProxyHttpServer()
	if p.Transport != nil {
		proxy.Tr = p.Transport
	}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(p.captureRequest)
	proxy.OnResponse().DoFunc(p.captureResponse)

	// Wrap GoProxy in a standard net/http handler for ListenAndServe.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
}

func normalizeCaptureContext(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return ""
		}
	}
	return value
}

// captureRequest publishes a pending event before the upstream response exists.
func (p *Proxy) captureRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Read the internal correlation header, then remove it before upstream forwarding.
	captureContext := normalizeCaptureContext(r.Header.Get(CaptureContextHeader))
	r.Header.Del(CaptureContextHeader)
	// Read and restore the body so capture does not consume the upstream request.
	body, err := readAndRestore(&r.Body)
	requestBody, requestEncoding, requestBase64 := encodeBody(body)
	// Publish the request immediately, before the upstream response arrives.
	event := Event{
		Source:              "proxy",
		Session:             ctx.Session,
		CaptureContext:      captureContext,
		Timestamp:           time.Now().UTC(),
		Method:              r.Method,
		URL:                 r.URL.String(),
		Host:                requestHost(r),
		RequestHeader:       flattenHeaders(r.Header),
		RequestBody:         requestBody,
		RequestBodyEncoding: requestEncoding,
		RequestBodyBase64:   requestBase64,
	}
	if p.SourceIP != nil {
		event.SourceIP = p.SourceIP(r.Context())
	}
	if err != nil {
		event.Error = err.Error()
	}
	// Keep the event ID and start time in the per-request proxy context.
	eventID := p.Store.Add(event)
	ctx.UserData = &captureState{eventID: eventID, started: time.Now()}
	return r, nil
}

// captureResponse completes the same event with response data and timing.
func (p *Proxy) captureResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// Complete the pending event when GoProxy receives the upstream response.
	state, ok := ctx.UserData.(*captureState)
	if !ok {
		state = &captureState{eventID: p.Store.Add(Event{Session: ctx.Session, Timestamp: time.Now().UTC()})}
	}
	// Preserve proxy errors even when no HTTP response exists.
	var eventError string
	if ctx.Error != nil {
		eventError = ctx.Error.Error()
	}
	var status int
	var responseHeaders map[string]string
	var responseBody string
	var responseSize int
	// A nil response represents a transport or TLS failure.
	if resp != nil {
		body, err := readAndRestore(&resp.Body)
		status = resp.StatusCode
		responseHeaders = flattenHeaders(resp.Header)
		responseBody, responseEncoding, responseBase64 := encodeBody(body)
		responseSize = len(body)
		contentType := resp.Header.Get("Content-Type")
		if err != nil && eventError == "" {
			eventError = err.Error()
		}
		p.Store.Update(state.eventID, func(event *Event) {
			event.Status = status
			event.ResponseHeader = responseHeaders
			event.ResponseBody = responseBody
			event.ResponseBodyEncoding = responseEncoding
			event.ResponseBodyBase64 = responseBase64
			event.ResponseContentType = contentType
			event.ResponseSize = responseSize
			event.Latency = time.Since(state.started).Milliseconds()
			event.Error = eventError
		})
		log.Printf("[PASSIVE %d] request completed in %dms -> %d", state.eventID, time.Since(state.started).Milliseconds(), status)
		return resp
	}
	// Measure from request capture until response processing completes.
	latency := time.Since(state.started).Milliseconds()
	p.Store.Update(state.eventID, func(event *Event) {
		event.Status = status
		event.ResponseHeader = responseHeaders
		event.ResponseBody = responseBody
		event.ResponseSize = responseSize
		event.Latency = latency
		event.Error = eventError
	})
	log.Printf("[PASSIVE %d] request completed in %dms -> %d", state.eventID, latency, status)
	return resp
}

func encodeBody(body []byte) (string, string, string) {
	if utf8.Valid(body) {
		return string(body), "utf8", ""
	}
	return "", "base64", base64.StdEncoding.EncodeToString(body)
}

type captureState struct {
	eventID uint64
	started time.Time
}

func requestHost(r *http.Request) string {
	// Prefer the URL host because proxy requests may use absolute-form URLs.
	if r.URL != nil && r.URL.Host != "" {
		if parsed, err := url.Parse(r.URL.String()); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}
	return r.Host
}

func readAndRestore(body *io.ReadCloser) ([]byte, error) {
	// Capture the complete body and replace it with a fresh readable stream.
	if body == nil || *body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(*body)
	_ = (*body).Close()
	*body = io.NopCloser(bytes.NewReader(data))
	return data, err
}

// Header values are flattened for the JSON/UI contract.
func flattenHeaders(headers http.Header) map[string]string {
	// Convert net/http's multi-value headers to the UI's flat JSON shape.
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = joinHeaderValues(values)
	}
	return result
}

func joinHeaderValues(values []string) string {
	// Preserve multiple values in one readable header string.
	result := ""
	for index, value := range values {
		if index > 0 {
			result += ", "
		}
		result += value
	}
	return result
}

func ConfigureCA() error {
	// Load the explicitly configured certificate or create the project CA.
	certPath, keyPath := os.Getenv("CA_CERT"), os.Getenv("CA_KEY")
	// CA_DIR is the preferred configuration because it derives both file paths.
	dir := os.Getenv("CA_DIR")
	if dir == "" && certPath == "" && keyPath == "" {
		// Keep local `go run .` self-contained from either the repository root
		// or the engine directory.
		for _, candidate := range []string{"data/ca", "../data/ca"} {
			if _, err := os.Stat(filepath.Dir(candidate)); err == nil {
				dir = candidate
				break
			}
		}
		if dir == "" {
			return os.ErrNotExist
		}
		_ = os.Setenv("CA_DIR", dir)
	}
	if dir != "" {
		manager, err := ca.NewCAManager(dir)
		if err != nil {
			return err
		}
		certPath, keyPath = manager.CertPath, manager.KeyPath
		_ = os.Setenv("CA_CERT", certPath)
		_ = os.Setenv("CA_KEY", keyPath)
	}
	// Explicit certificate/key configuration remains supported.
	if certPath == "" && keyPath == "" {
		return nil
	}
	if certPath == "" || keyPath == "" {
		return os.ErrInvalid
	}
	// Clean paths before loading to avoid accidental path formatting issues.
	cert, err := tls.LoadX509KeyPair(filepath.Clean(certPath), filepath.Clean(keyPath))
	if err != nil {
		return err
	}
	goproxy.GoproxyCa = cert
	return nil
}
