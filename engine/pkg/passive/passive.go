// Package passive implements Traffic capture for the local MITM proxy.
package passive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

type eventSubscriber struct {
	mu       sync.Mutex
	cond     *sync.Cond
	queue    []Event
	closed   bool
	output   chan Event
	stop     chan struct{}
	finished chan struct{}
	stopOnce sync.Once
}

func newEventSubscriber() *eventSubscriber {
	subscriber := &eventSubscriber{
		output:   make(chan Event),
		stop:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	subscriber.cond = sync.NewCond(&subscriber.mu)
	go subscriber.forward()
	return subscriber
}

func (subscriber *eventSubscriber) forward() {
	defer close(subscriber.output)
	defer close(subscriber.finished)
	for {
		subscriber.mu.Lock()
		for len(subscriber.queue) == 0 && !subscriber.closed {
			subscriber.cond.Wait()
		}
		if len(subscriber.queue) == 0 {
			subscriber.mu.Unlock()
			return
		}
		event := subscriber.queue[0]
		subscriber.queue = subscriber.queue[1:]
		subscriber.mu.Unlock()
		select {
		case subscriber.output <- event:
		case <-subscriber.stop:
			return
		}
	}
}

func (subscriber *eventSubscriber) push(event Event) {
	subscriber.mu.Lock()
	if !subscriber.closed {
		subscriber.queue = append(subscriber.queue, event)
		subscriber.cond.Signal()
	}
	subscriber.mu.Unlock()
}

func (subscriber *eventSubscriber) close() {
	subscriber.stopOnce.Do(func() {
		subscriber.mu.Lock()
		subscriber.closed = true
		subscriber.cond.Broadcast()
		subscriber.mu.Unlock()
		close(subscriber.stop)
	})
	<-subscriber.finished
}

// Store keeps recent events and subscribers in process memory.
type Store struct {
	mu          sync.RWMutex
	events      []Event
	subscribers map[*eventSubscriber]struct{}
	nextID      uint64
	nextCursor  uint64
	replay      []Event
	paused      bool
}

// Store keeps the in-memory Traffic view and broadcasts request lifecycle updates.
func NewStore() *Store {
	// Start with an initialized subscriber map so Add can broadcast safely.
	return &Store{subscribers: make(map[*eventSubscriber]struct{})}
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

// ListSummary returns the snapshot with the captured payload left out.
//
// A Traffic row shows host, method, URL, status, size and time, so listing the
// payload of every stored event made one snapshot cost the size of every
// captured body: a few hundred exchanges of a large transfer were tens of
// megabytes and the tab stopped responding. The payload is not discarded — it
// stays in the Store and `Get` returns it in full for the event that is opened.
// Every other field, including the recorded sizes, is unchanged, so a summary
// row still shows that there is something to read.
func (s *Store) ListSummary() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.events) == 0 {
		return []Event{}
	}

	summary := make([]Event, len(s.events))
	for i, event := range s.events {
		summary[i] = event
		summary[i].RequestHeader = nil
		summary[i].RequestBody = ""
		summary[i].RequestBodyBase64 = ""
		summary[i].ResponseHeader = nil
		summary[i].ResponseBody = ""
		summary[i].ResponseBodyBase64 = ""
		// Tags is the one reference a struct copy shares, so the summary gets its
		// own slice. Otherwise a caller that edited a returned summary would edit
		// the stored event, and the next read would show the change.
		summary[i].Tags = append([]string(nil), event.Tags...)
	}
	return summary
}

// Get returns one complete event, payload included.
func (s *Store) Get(id uint64) (Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, event := range s.events {
		if event.ID == id {
			return event, true
		}
	}
	return Event{}, false
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
	subscriber := newEventSubscriber()
	s.mu.Lock()
	if cursor > s.nextCursor {
		cursor = 0
	}
	backlog := make([]Event, 0)
	for _, event := range s.replay {
		if event.Cursor > cursor {
			backlog = append(backlog, event)
		}
	}
	s.subscribers[subscriber] = struct{}{}
	s.mu.Unlock()
	return backlog, subscriber.output, func() {
		s.mu.Lock()
		delete(s.subscribers, subscriber)
		s.mu.Unlock()
		subscriber.close()
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

// Subscribe creates an unbounded per-consumer event queue.
func (s *Store) Subscribe() (<-chan Event, func()) {
	subscriber := newEventSubscriber()
	s.mu.Lock()
	s.subscribers[subscriber] = struct{}{}
	s.mu.Unlock()
	return subscriber.output, func() {
		s.mu.Lock()
		delete(s.subscribers, subscriber)
		s.mu.Unlock()
		subscriber.close()
	}
}

func (s *Store) broadcastLocked(event Event) {
	// The caller must hold the Store write lock while iterating subscribers.
	for subscriber := range s.subscribers {
		subscriber.push(event)
	}
}

type Proxy struct {
	// Store receives request and response lifecycle events.
	Store *Store
	// Transport is shared with active engine requests so route changes apply
	// consistently to MITM upstream traffic and tool requests.
	Transport http.RoundTripper
	// RouteContext binds one proxy exchange to the installed route generation.
	RouteContext func(context.Context) (context.Context, context.CancelFunc)
	// SourceIP resolves the public source IP used by the shared route.
	SourceIP func(context.Context) string
}

func NewProxy(store *Store, transport http.RoundTripper, sourceIP ...func(context.Context) string) *Proxy {
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
	if transport, ok := p.Transport.(*http.Transport); ok && transport != nil {
		proxy.Tr = transport
	}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(p.captureRequest)
	proxy.OnResponse().DoFunc(p.captureResponse)

	// Wrap GoProxy in a standard net/http handler for ListenAndServe.
	//
	// `hijackBoundedConns` is what keeps a MITM tunnel from living forever, and it
	// has to sit HERE rather than on the `http.Server`: `HandleConnect(AlwaysMitm)`
	// resolves to goproxy's `ConnectMitm`, and that path calls `Hijack()`
	// (`https.go:271`). A hijacked connection leaves the server's own machinery
	// immediately, so `ReadHeaderTimeout`, `IdleTimeout` and `WriteTimeout` stop
	// applying to it — the engine API sets all three (`main.go:678`) and none of
	// them would ever reach a tunnel. After the 200 confirmation goproxy only
	// `io.Copy`s between the two sockets, with no deadline on either.
	//
	// Measured on the full `http` corpus through this proxy, against
	// `https://yandex.ru`: 82 tunnels ESTAB with the request counter frozen at
	// 6395/20675 and nuclei down to a single thread at 0% CPU, while the same
	// corpus in a terminal finished in 189 s. Nothing closed those 82 connections:
	// each one waited for the other side forever.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(&hijackBoundedResponseWriter{ResponseWriter: w}, r)
	})
}

// defaultMITMIdleTimeout bounds how long a hijacked tunnel may carry no bytes
// when RR_MITM_IDLE_TIMEOUT_SEC says nothing.
//
// The value is measured, not chosen for tidiness. Three settings were each run
// over the full `http` corpus (11 660 templates, 20 675 requests) against
// `https://yandex.ru` through this proxy, and the outcome differs in kind, not
// in degree:
//
//	90 s (the old "no bound" behaviour)  never finished — the request counter
//	                                    froze at 6 395/20 675 and nuclei sat at
//	                                    one thread and 0% CPU
//	 2 s                                  finished in 468 s, 11 788 matches
//	10 s                                  finished in 846 s, 11 788 matches
//
// 90 s is the reason the default is not "generous". Below that, the number that
// decides the choice is the client's own patience: nuclei's default per-request
// timeout is 10 s, so a bound longer than that lets this proxy hold a response
// the scanner has already stopped waiting for — the exact state the 90 s run
// froze in. A bound of 10 s therefore never cuts a response the scanner would
// still have read, which is why it is the default, and why the faster 2 s
// setting is left to an operator who wants the churn.
//
// The two completing settings produced the SAME 11 788 matches, so the bound
// changes how long a scan takes and not what it finds.
const defaultMITMIdleTimeout = 10 * time.Second

// idleTimeoutFromEnv reads the tunnel bound, falling back to the default for
// anything it cannot use.
//
// A zero or unparsable value falls back rather than being honoured: read as a
// literal, `0` would expire every tunnel on its next read, and that reads like
// "close idle connections" while actually closing all of them. Turning the bound
// off is done in code by setting `MITMIdleTimeout`, which an operator's
// environment cannot reach.
func idleTimeoutFromEnv() time.Duration {
	seconds, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv("RR_MITM_IDLE_TIMEOUT_SEC")), 64)
	if err != nil || seconds <= 0 {
		return defaultMITMIdleTimeout
	}
	return time.Duration(seconds * float64(time.Second))
}

// MITMIdleTimeout bounds how long a hijacked tunnel may carry no bytes at all.
//
// It is an idle bound, not a lifetime: every read or write that actually moves
// data resets it, so a long scan over one connection is untouched. What it
// removes is the connection that stopped talking and stayed counted — one
// socket, one goroutine each way, and one of the analyzer's own concurrency
// slots held open for the rest of the run.
var MITMIdleTimeout = idleTimeoutFromEnv()

// deadlineConn applies MITMIdleTimeout to every read and write on a hijacked
// connection.
//
// The deadline is set before each operation and cleared after it succeeds, so
// the bound is on idleness rather than on total time. A connection transferring
// data continuously — which is what a scan through this proxy does — never sees
// it fire.
type deadlineConn struct {
	net.Conn
	idle time.Duration
}

// Read bounds one read by the idle timeout and lifts the deadline afterwards.
func (c *deadlineConn) Read(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	n, err := c.Conn.Read(b)
	if n > 0 || err == nil {
		_ = c.Conn.SetReadDeadline(time.Time{})
	}
	return n, err
}

// Write bounds one write the same way. The error is passed through untouched:
// a partial write must not be reported as success, and the caller decides what
// a deadline means for its own exchange.
func (c *deadlineConn) Write(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	n, err := c.Conn.Write(b)
	if n > 0 || err == nil {
		_ = c.Conn.SetWriteDeadline(time.Time{})
	}
	return n, err
}

// hijackBoundedResponseWriter hands goproxy a connection that expires when it
// goes idle.
//
// goproxy needs `http.Hijacker` and type-asserts for it, so the wrapper has to
// implement the interface rather than just wrap it. The other optional
// interfaces goproxy looks for are preserved by delegation, because dropping one
// would silently change the path goproxy takes.
type hijackBoundedResponseWriter struct {
	http.ResponseWriter
}

// Hijack is the whole point: the connection goproxy takes over from here is
// wrapped once, and every later read and write on it is bounded.
func (w *hijackBoundedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		// Reporting this rather than pretending: goproxy turns a missing
		// Hijacker into an HTTP/2-only path, and the operator would see requests
		// fail without being told why.
		return nil, nil, errNoHijacker
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return conn, buffered, err
	}
	if MITMIdleTimeout > 0 {
		conn = &deadlineConn{Conn: conn, idle: MITMIdleTimeout}
	}
	return conn, buffered, nil
}

// Flush keeps the streaming path available to goproxy; without it a wrapped
// response writer that goproxy can flush through would turn every flush into a
// no-op and buffer the whole exchange.
func (w *hijackBoundedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

var errNoHijacker = errors.New("passive proxy: response writer does not support hijacking")

func normalizeCaptureContext(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
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
	cancelRoute := func() {}
	if p.RouteContext != nil {
		routeContext, cancel := p.RouteContext(r.Context())
		*r = *r.WithContext(routeContext)
		cancelRoute = cancel
	}
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
	// Publish the pending event before the synchronous source-IP lookup. The
	// lookup still belongs to this logical exchange, but observers must be able
	// to see the event while the external endpoint is being queried.
	eventID := p.Store.Add(event)
	ctx.UserData = &captureState{eventID: eventID, started: time.Now(), cancel: cancelRoute}
	if p.SourceIP != nil {
		// Start one fresh lookup for this exchange without blocking the target
		// request on a slow external IP endpoint. The lookup retains the route
		// generation binding, while WithoutCancel prevents a browser's normal
		// post-response disconnect from discarding the metadata update.
		sourceContext := context.WithoutCancel(r.Context())
		go func() {
			sourceIP := p.SourceIP(sourceContext)
			p.Store.Update(eventID, func(stored *Event) {
				stored.SourceIP = sourceIP
			})
		}()
	}
	if err != nil {
		p.Store.Update(eventID, func(stored *Event) {
			stored.Error = err.Error()
		})
	}
	return r, nil
}

// captureResponse completes the same event with response data and timing.
func (p *Proxy) captureResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// Complete the pending event when GoProxy receives the upstream response.
	state, ok := ctx.UserData.(*captureState)
	if !ok {
		state = &captureState{eventID: p.Store.Add(Event{Session: ctx.Session, Timestamp: time.Now().UTC()})}
	}
	if state.cancel != nil {
		defer state.cancel()
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

// encodeBody decides between a text body and a base64 one.
//
// The two questions are "can this be decoded as UTF-8" and "can this be stored in a
// text column", and `utf8.Valid` only answers the first: U+0000 is a well-formed
// UTF-8 code point, so a body holding a NUL byte passes it. PostgreSQL refuses NUL
// in a text column, so publishing such a body as text made every durable write of
// that exchange fail with `DataError` — and because the durable write happens on the
// transform poll, the transform result existed and was unreachable.
//
// Measured 2026-10-02 on real captures during `username_search`: three live
// responses, one from a `.ru` blog and two from a Japanese profile page, each
// `text/html` with valid UTF-8 and exactly one NUL byte.
func encodeBody(body []byte) (string, string, string) {
	if utf8.Valid(body) && !bytes.Contains(body, []byte{0}) {
		return string(body), "utf8", ""
	}
	return "", "base64", base64.StdEncoding.EncodeToString(body)
}

type captureState struct {
	eventID uint64
	started time.Time
	cancel  context.CancelFunc
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
