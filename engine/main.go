// Package main starts the HTTP execution engine and passive MITM proxy.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"intruder/engine/pkg/intruder"
	"intruder/engine/pkg/passive"
)

// server owns process-wide state shared by the HTTP handlers.
type server struct {
	// attackSequence provides a readable identifier for each Intruder run.
	attackSequence    uint64
	attacks           map[uint64]*attack
	attacksMu         sync.RWMutex
	store             *passive.Store
	targetMaps        map[uint64]*targetMap
	targetMapsMu      sync.RWMutex
	oastListeners     map[uint64]*oastListener
	oastListenersMu   sync.RWMutex
	oastSequence      uint64
	bursts            map[uint64]*repeaterBurst
	burstsMu          sync.RWMutex
	burstSequence     uint64
	burstSlots        chan struct{}
	burstJobSlots     chan struct{}
	burstSlotsMu      sync.Mutex
	lastByteJobs      map[uint64]*lastByteJob
	lastByteJobsMu    sync.RWMutex
	lastByteSequence  uint64
	lastByteSlots     chan struct{}
	lastByteJobSlots  chan struct{}
	lastByteSlotsMu   sync.Mutex
	routes            *routeManager
	transport         *http.Transport
	sourceIPTransport http.RoundTripper
}

type targetMap struct {
	mu       sync.RWMutex
	cancel   context.CancelFunc
	status   string
	startURL string
	maxPages int
	visited  int
	pages    []map[string]interface{}
}

type targetMapInput struct {
	URL        string `json:"url"`
	MaxPages   int    `json:"max_pages"`
	MaxDepth   int    `json:"max_depth"`
	DelayMS    int    `json:"delay_ms"`
	SameOrigin bool   `json:"same_origin"`
}

type osintInput struct {
	URL      string `json:"url"`
	WAFCheck bool   `json:"waf_check"`
}

type scannerInput struct {
	URL     string `json:"url"`
	Profile string `json:"profile"`
}

type routeCheckInput struct {
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
}

var (
	maxTargetPages = envLimit("RR_TARGET_MAX_PAGES", 10000)
	maxTargetDepth = envLimit("RR_TARGET_MAX_DEPTH", 50)
)

var mapURLPattern = regexp.MustCompile(`(?i)(?:["'(\s]|^)((?:https?://|/)[^"'()\s<>]+)`)

var osintHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type attack struct {
	mu        sync.RWMutex
	cancel    context.CancelFunc
	resumeCh  chan struct{}
	paused    bool
	status    string
	total     int
	completed int
	failed    int
	results   []map[string]interface{}
}

type suppressRequestLogsKey struct{}

var maxAnalysisBodyBytes = envLimit("RR_ANALYSIS_MAX_BODY_BYTES", 2<<20)

const sourceIPCheckURL = "https://check.torproject.org/api/ip"

func readAnalysisBody(body io.Reader) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, int64(maxAnalysisBodyBytes)+1))
	if err != nil {
		return nil, false, err
	}
	truncated := len(data) > maxAnalysisBodyBytes
	if truncated {
		data = data[:maxAnalysisBodyBytes]
	}
	return data, truncated, nil
}

// requestInput is the common wire format for Repeater and generated jobs.
type requestInput struct {
	// Method is the HTTP verb sent to the target.
	Method string `json:"method"`
	// URL is the absolute target URL.
	URL string `json:"url"`
	// Headers contains request header names and values.
	Headers map[string]string `json:"headers"`
	// Body contains the request payload as text.
	Body string `json:"body"`
}

// intruderInput describes one complete Intruder attack submitted by Django.
type intruderInput struct {
	// BaseRequest is copied and modified for every generated job.
	BaseRequest requestInput `json:"base_request"`
	// Mode selects the payload-combination algorithm.
	Mode intruder.AttackMode `json:"mode"`
	// Payloads is the positional fallback representation used by the UI.
	Payloads [][]string `json:"payloads"`
	// Dictionaries optionally maps marker names or indexes to payload lists.
	Dictionaries map[string][]string `json:"dictionaries"`
	// Transforms are applied to payloads before request generation.
	Transforms []intruder.Transform `json:"transformations"`
	// DelayMS spaces sequential requests by this many milliseconds.
	DelayMS int `json:"delay_ms"`
	// Concurrency controls the number of concurrent workers. Zero selects the
	// engine default for ordinary UI requests.
	Concurrency int `json:"concurrency"`
}

func main() {
	// Discover the project CA before the proxy starts intercepting HTTPS.
	configureDefaultCAPath()
	if err := passive.ConfigureCA(); err != nil {
		log.Fatalf("configure passive proxy CA: %v", err)
	}
	log.Printf("passive MITM CA active cert=%s key=%s", os.Getenv("CA_CERT"), os.Getenv("CA_KEY"))
	routes, err := newRouteManager()
	if err != nil {
		log.Fatalf("configure route manager: %v", err)
	}
	if address := strings.TrimSpace(os.Getenv("ROUTE_ADDRESS")); address != "" {
		if err := routes.set(routeConfig{Address: address}); err != nil {
			log.Fatalf("configure initial route: %v", err)
		}
	}
	transport := routes.transport()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	osintHTTPClient.Transport = routes.roundTripper()

	// Store is shared by the proxy snapshot endpoint and the SSE stream.
	store := passive.NewStore()
	// Create the shared HTTP server state.
	// Include a process epoch so persisted attack IDs remain unique after
	// engine restarts and cannot collide with older History rows.
	s := &server{
		attackSequence:   uint64(time.Now().Unix()) << 20,
		attacks:          make(map[uint64]*attack),
		store:            store,
		targetMaps:       make(map[uint64]*targetMap),
		oastListeners:    make(map[uint64]*oastListener),
		oastSequence:     uint64(time.Now().Unix()) << 20,
		bursts:           make(map[uint64]*repeaterBurst),
		burstSequence:    uint64(time.Now().Unix()) << 20,
		burstSlots:       make(chan struct{}, maxBurstActiveRequests),
		burstJobSlots:    make(chan struct{}, maxBurstActiveJobs),
		lastByteJobs:     make(map[uint64]*lastByteJob),
		lastByteSequence: uint64(time.Now().Unix()) << 20,
		lastByteSlots:    make(chan struct{}, maxLastByteActiveRequests),
		lastByteJobSlots: make(chan struct{}, maxLastByteActiveJobs),
		routes:           routes,
		transport:        transport,
	}
	// Register engine endpoints on a private mux instead of using global handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/proxy/request", s.request)
	mux.HandleFunc("/proxy/intruder", s.intruder)
	mux.HandleFunc("/proxy/intruder/", s.intruderStatus)
	mux.HandleFunc("/proxy/target-map", s.targetMapStart)
	mux.HandleFunc("/proxy/target-map/", s.targetMapStatus)
	mux.HandleFunc("/proxy/oast", s.oastStart)
	mux.HandleFunc("/proxy/oast/", s.oastStatus)
	mux.HandleFunc("/proxy/repeater-burst", s.repeaterBurstStart)
	mux.HandleFunc("/proxy/repeater-burst/", s.repeaterBurstStatus)
	mux.HandleFunc("/proxy/last-byte", s.lastByteStart)
	mux.HandleFunc("/proxy/last-byte/", s.lastByteStatus)
	mux.HandleFunc("/proxy/osint", s.osint)
	mux.HandleFunc("/proxy/osint/transforms", s.osintTransformRegistry)
	mux.HandleFunc("/proxy/osint/transform", s.osintTransform)
	mux.HandleFunc("/proxy/scanner", s.scanner)
	mux.HandleFunc("/route", s.route)
	mux.HandleFunc("/route/check", s.routeCheck)
	// The snapshot endpoint hydrates the Traffic table before SSE starts.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			store.Clear()
			writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
			return
		}
		if r.Method == http.MethodPost {
			var input struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || strings.TrimSpace(input.Action) == "" {
				input.Action = strings.TrimSpace(r.URL.Query().Get("action"))
			}
			switch strings.ToLower(strings.TrimSpace(input.Action)) {
			case "pause":
				store.Pause()
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recording": false})
				return
			case "resume":
				store.Resume()
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recording": true})
				return
			case "status":
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recording": store.Recording()})
				return
			default:
				writeError(w, http.StatusBadRequest, "INVALID_TRAFFIC_ACTION", fmt.Errorf("action must be pause, resume or status"))
				return
			}
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
			return
		}
		writeJSON(w, http.StatusOK, store.List())
	})
	mux.HandleFunc("/events/annotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
			return
		}
		var input struct {
			ID    uint64   `json:"id"`
			Tags  []string `json:"tags"`
			Notes string   `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ID == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_ANNOTATION", fmt.Errorf("id and valid JSON are required"))
			return
		}
		if !store.Annotate(input.ID, input.Tags, input.Notes) {
			writeError(w, http.StatusNotFound, "EVENT_NOT_FOUND", fmt.Errorf("event %d not found", input.ID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	})
	// SSE publishes both the pending request and its later response update.
	mux.HandleFunc("/events/stream", func(w http.ResponseWriter, r *http.Request) {
		// The response must support flushing so events reach the browser immediately.
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "STREAM_UNSUPPORTED", fmt.Errorf("streaming is not supported"))
			return
		}

		// These headers disable intermediary buffering for the live stream.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		cursor := parseEventCursor(r)
		backlog, events, unsubscribe := store.SubscribeSince(cursor)
		defer unsubscribe()
		send := func(event passive.Event) {
			data, err := json.Marshal(event)
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(w, "id: %d\nevent: traffic\ndata: %s\n\n", event.Cursor, data)
			flusher.Flush()
		}
		for _, event := range backlog {
			send(event)
		}
		for {
			select {
			// Stop listening when the browser closes the connection.
			case <-r.Context().Done():
				return
			case event := <-events:
				send(event)
			}
		}
	})
	// The proxy writes its lifecycle events into the same Store.
	proxy := passive.NewProxy(store, transport, func(ctx context.Context) string {
		return s.ensureSourceIP(ctx)
	})

	// The proxy and engine API use separate listeners in one process.
	go func() {
		proxyAddr := envOrDefault("PROXY_LISTEN_ADDR", "127.0.0.1:8080")
		log.Printf("passive MITM proxy listening on %s", proxyAddr)
		if err := http.ListenAndServe(proxyAddr, proxy.Handler()); err != nil {
			log.Fatalf("passive proxy: %v", err)
		}
	}()

	engineAddr := envOrDefault("ENGINE_LISTEN_ADDR", "127.0.0.1:8081")
	log.Printf("engine listening on %s", engineAddr)
	log.Fatal(http.ListenAndServe(engineAddr, mux))
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.routes.configSnapshot())
	case http.MethodPut, http.MethodPost:
		var config routeConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_ROUTE", err)
			return
		}
		if err := s.routes.set(config); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_ROUTE", err)
			return
		}
		writeJSON(w, http.StatusOK, s.routes.configSnapshot())
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
	}
}

func (s *server) routeCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input routeCheckInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ROUTE_CHECK", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_ROUTE_CHECK", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	timeout := 15 * time.Second
	if input.TimeoutMS > 0 {
		timeout = time.Duration(input.TimeoutMS) * time.Millisecond
	}
	if timeout < time.Second {
		timeout = time.Second
	}
	route := s.routes.configSnapshot()
	result := map[string]interface{}{
		"route":      route,
		"target_url": target,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	}
	client := &http.Client{
		Transport: s.requestTransport(),
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetStarted := time.Now()
	targetResponse, targetErr := client.Get(target)
	targetLatency := time.Since(targetStarted).Milliseconds()
	targetResult := map[string]interface{}{"latency_ms": targetLatency}
	var targetTrafficID uint64
	if targetErr != nil {
		targetResult["status"] = "error"
		targetResult["error"] = targetErr.Error()
		targetTrafficID = s.publishRouteCheckTraffic(target, targetStarted, nil, targetErr)
	} else {
		targetResult["status"] = "ok"
		targetResult["status_code"] = targetResponse.StatusCode
		targetResult["status_text"] = targetResponse.Status
		targetBody, _ := io.ReadAll(io.LimitReader(targetResponse.Body, 4096))
		_ = targetResponse.Body.Close()
		targetTrafficID = s.publishRouteCheckTraffic(target, targetStarted, &routeCheckResponse{
			status:  targetResponse.StatusCode,
			header:  flattenHeaders(targetResponse.Header),
			body:    targetBody,
			content: targetResponse.Header.Get("Content-Type"),
		}, nil)
	}
	result["target"] = targetResult

	ipResult := map[string]interface{}{"status": "unavailable"}
	ipStarted := time.Now()
	ipResponse, ipErr := client.Get(sourceIPCheckURL)
	ipLatency := time.Since(ipStarted).Milliseconds()
	ipResult["latency_ms"] = ipLatency
	if ipErr != nil {
		ipResult["status"] = "error"
		ipResult["error"] = ipErr.Error()
		s.publishRouteCheckTraffic(sourceIPCheckURL, ipStarted, nil, ipErr)
	} else {
		var ipTrafficID uint64
		ipBody, _ := io.ReadAll(io.LimitReader(ipResponse.Body, 4096))
		_ = ipResponse.Body.Close()
		var payload struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(ipBody, &payload); err != nil || payload.IP == "" {
			ipResult["status"] = "error"
			ipResult["error"] = "external IP response did not contain an IP"
		} else {
			ipResult["status"] = "ok"
			ipResult["ip"] = payload.IP
			if targetTrafficID != 0 {
				s.store.Update(targetTrafficID, func(event *passive.Event) {
					event.SourceIP = payload.IP
				})
			}
		}
		ipResult["status_code"] = ipResponse.StatusCode
		ipTrafficID = s.publishRouteCheckTraffic(sourceIPCheckURL, ipStarted, &routeCheckResponse{
			status:  ipResponse.StatusCode,
			header:  flattenHeaders(ipResponse.Header),
			body:    ipBody,
			content: ipResponse.Header.Get("Content-Type"),
		}, nil)
		if payload.IP != "" {
			s.store.Update(ipTrafficID, func(event *passive.Event) {
				event.SourceIP = payload.IP
			})
		}
	}
	result["external_ip"] = ipResult
	if targetErr != nil {
		result["status"] = "error"
	} else {
		result["status"] = "ok"
	}
	writeJSON(w, http.StatusOK, result)
}

type routeCheckResponse struct {
	status  int
	header  map[string]string
	body    []byte
	content string
}

func (s *server) publishRouteCheckTraffic(rawURL string, started time.Time, response *routeCheckResponse, requestErr error) uint64 {
	if s.store == nil {
		return 0
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	event := passive.Event{
		Source:        "route-check",
		Timestamp:     started.UTC(),
		Method:        http.MethodGet,
		URL:           rawURL,
		Host:          parsed.Host,
		RequestHeader: map[string]string{"User-Agent": "RequestRider-RouteCheck/1.0"},
		Latency:       time.Since(started).Milliseconds(),
	}
	if requestErr != nil {
		event.Error = requestErr.Error()
	} else {
		event.Status = response.status
		event.ResponseHeader = response.header
		event.ResponseBody = string(response.body)
		event.ResponseContentType = response.content
		event.ResponseSize = len(response.body)
	}
	return s.store.Add(event)
}

func (s *server) ensureSourceIP(ctx context.Context) string {
	if s.transport == nil && s.routes == nil {
		return ""
	}
	checkContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(checkContext, http.MethodGet, sourceIPCheckURL, nil)
	if err != nil {
		return ""
	}
	transport := s.requestTransport()
	if s.sourceIPTransport != nil {
		transport = s.sourceIPTransport
	}
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return ""
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	ip := strings.TrimSpace(payload.IP)
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func configureDefaultCAPath() {
	// Respect an explicit CA_DIR supplied by the caller or Docker.
	if os.Getenv("CA_DIR") != "" || os.Getenv("CA_CERT") != "" || os.Getenv("CA_KEY") != "" {
		return
	}
	// ConfigureCA resolves and creates the project default from the current
	// working directory, so no environment variable is required locally.
}

func envOrDefault(key, fallback string) string {
	// Environment variables configure Docker and local development addresses.
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	// Health is intentionally cheap so it can be used by smoke tests.
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *server) request(w http.ResponseWriter, r *http.Request) {
	// Decode the Repeater request submitted by Django.
	var input requestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	eventID := s.addRequestTraffic(input, s.ensureSourceIP(r.Context()))
	// Reuse the same execution path used by Intruder jobs.
	result, err := s.executeContext(r.Context(), input)
	if err != nil {
		s.completeRequestTraffic(eventID, nil, err)
		writeError(w, http.StatusBadGateway, "REQUEST_FAILED", err)
		return
	}
	s.completeRequestTraffic(eventID, result, nil)
	writeJSON(w, http.StatusOK, result)
}

// execute is shared by Repeater and every generated Intruder job.
func (s *server) execute(r *http.Request, input requestInput) (map[string]interface{}, error) {
	return s.executeContext(r.Context(), input)
}

func (s *server) executeContext(ctx context.Context, input requestInput) (map[string]interface{}, error) {
	sourceIP := s.ensureSourceIP(ctx)
	// Default an omitted method to the standard HTTP GET verb.
	method := input.Method
	if method == "" {
		method = http.MethodGet
	}
	// requestStart measures failures occurring before a response exists.
	requestStart := time.Now()
	logRequests := !requestLogsSuppressed(ctx)
	if logRequests {
		log.Printf("[REQUEST] start method=%s host=%s path=%s", method, requestHost(input.URL), requestPath(input.URL))
	}
	// Bind the outbound request to the inbound request context.
	req, err := http.NewRequestWithContext(ctx, method, input.URL, strings.NewReader(input.Body))
	if err != nil {
		if logRequests {
			log.Printf("[REQUEST] build_error method=%s host=%s error=%v", method, requestHost(input.URL), err)
		}
		return nil, err
	}
	// Copy caller-supplied headers without exposing them in diagnostic logs.
	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	// start measures only the outbound request/response round trip.
	start := time.Now()
	resp, err := (&http.Client{
		Transport:     s.requestTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		if logRequests {
			log.Printf("[REQUEST] error method=%s host=%s duration_ms=%d error=%v", method, requestHost(input.URL), time.Since(requestStart).Milliseconds(), err)
		}
		return nil, err
	}
	// Always release the response body, including read failures.
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if logRequests {
			log.Printf("[REQUEST] read_error method=%s host=%s status=%d duration_ms=%d error=%v", method, requestHost(input.URL), resp.StatusCode, time.Since(requestStart).Milliseconds(), err)
		}
		return nil, err
	}
	// Flatten multi-value response headers for the JSON contract.
	headers := map[string]string{}
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	duration := time.Since(start).Milliseconds()
	if logRequests {
		log.Printf("[REQUEST] complete method=%s host=%s status=%d duration_ms=%d response_bytes=%d", method, requestHost(input.URL), resp.StatusCode, duration, len(body))
	}
	result := map[string]interface{}{
		"status":      resp.StatusCode,
		"status_text": resp.Status,
		"time":        duration,
		"size":        len(body),
		"headers":     headers,
		"source_ip":   sourceIP,
	}
	if utf8.Valid(body) {
		result["body"] = string(body)
		result["body_encoding"] = "utf8"
	} else {
		result["body"] = ""
		result["body_encoding"] = "base64"
		result["body_base64"] = base64.StdEncoding.EncodeToString(body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		result["body_content_type"] = contentType
	}
	return result, nil
}

func (s *server) requestTransport() http.RoundTripper {
	if s.routes != nil {
		return s.routes.roundTripper()
	}
	if s.transport != nil {
		return s.transport
	}
	return http.DefaultTransport
}

func (s *server) targetMapStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input targetMapInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	start, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || start.Scheme == "" || start.Host == "" || (start.Scheme != "http" && start.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if input.MaxPages <= 0 || input.MaxPages > maxTargetPages {
		writeError(w, http.StatusBadRequest, "INVALID_MAX_PAGES", fmt.Errorf("max_pages must be between 1 and %d", maxTargetPages))
		return
	}
	if input.MaxDepth < 0 || input.MaxDepth > maxTargetDepth {
		writeError(w, http.StatusBadRequest, "INVALID_MAX_DEPTH", fmt.Errorf("max_depth must be between 0 and %d", maxTargetDepth))
		return
	}
	if input.DelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_DELAY", fmt.Errorf("delay_ms must not be negative"))
		return
	}
	id := atomic.AddUint64(&s.attackSequence, 1)
	ctx, cancel := context.WithCancel(context.Background())
	job := &targetMap{
		cancel: cancel, status: "running", startURL: normalizeMapURL(start),
		maxPages: input.MaxPages, pages: make([]map[string]interface{}, 0, input.MaxPages),
	}
	s.targetMapsMu.Lock()
	s.targetMaps[id] = job
	s.targetMapsMu.Unlock()
	writeJSON(w, http.StatusAccepted, targetMapSnapshot(id, job))
	go s.runTargetMap(id, job, ctx, input)
}

func (s *server) osint(w http.ResponseWriter, r *http.Request) {
	// OSINT is intentionally passive: the endpoint gathers public metadata and
	// never sends exploit payloads or attempts to bypass a real WAF.
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input osintInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	result, err := runOSINTWithResolver(parsed, input.WAFCheck, s.routes.resolver(), s.requestTransport())
	if err != nil {
		writeError(w, http.StatusBadGateway, "OSINT_CHECK_FAILED", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) scanner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input scannerInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	profile := strings.TrimSpace(input.Profile)
	if profile == "" {
		profile = "generic_web"
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	result, err := runSafeScanner(parsed)
	if err != nil {
		writeError(w, http.StatusBadGateway, "SCANNER_CHECK_FAILED", err)
		return
	}
	result["profile"] = profile
	writeJSON(w, http.StatusOK, result)
}

func runOSINT(target *url.URL, wafCheck bool) (map[string]interface{}, error) {
	return runOSINTWithResolver(target, wafCheck, net.DefaultResolver, osintHTTPClient.Transport)
}

func runOSINTWithResolver(target *url.URL, wafCheck bool, resolver *net.Resolver, transport http.RoundTripper) (map[string]interface{}, error) {
	// Each section is collected independently so a DNS, TLS, or HTTP failure
	// can be reported as partial results instead of hiding all available data.
	hostname := target.Hostname()
	result := map[string]interface{}{
		"url":        target.String(),
		"host":       target.Host,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"errors":     []string{},
	}

	ips, dnsErr := lookupHostWithRetryWithResolver(hostname, resolver)
	sort.Strings(ips)
	result["dns"] = map[string]interface{}{
		"host": ips,
		"mx":   lookupMXWithResolver(hostname, resolver),
		"ns":   lookupNSWithResolver(hostname, resolver),
		"txt":  lookupTXTWithResolver(hostname, resolver),
	}
	if dnsErr != nil {
		result["errors"] = append(result["errors"].([]string), fmt.Sprintf("DNS lookup: %v", dnsErr))
	}

	response, chain, err := fetchOSINTPageWithTransport(target, transport)
	if err != nil {
		result["http"] = map[string]interface{}{"error": err.Error()}
		result["redirect_chain"] = chain
		result["technologies"] = []string{}
		result["security_headers"] = map[string]interface{}{}
		result["cookies"] = []map[string]interface{}{}
		result["discovery"] = discoverOSINTResources(target, map[string]interface{}{})
		result["waf"] = map[string]interface{}{
			"detected": false, "vendors": []string{}, "confidence": "none",
			"confidence_percent": 0, "evidence": []string{},
		}
		result["errors"] = append(result["errors"].([]string), err.Error())
		return result, nil
	}
	result["http"] = response
	result["redirect_chain"] = chain
	result["technologies"] = detectTechnologies(response, target)
	result["security_headers"] = securityHeaderChecks(response["headers"].(map[string]string))
	result["cookies"] = response["cookies"]
	result["discovery"] = discoverOSINTResources(target, response)
	result["waf"] = detectWAF(response)
	if wafCheck {
		result["waf_check"] = runWAFCanary(target, response)
	}
	return result, nil
}

func lookupHostWithRetry(hostname string) ([]string, error) {
	return lookupHostWithRetryWithResolver(hostname, net.DefaultResolver)
}

func lookupHostWithRetryWithResolver(hostname string, resolver *net.Resolver) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := resolver.LookupHost(ctx, hostname)
		cancel()
		if err == nil {
			return ips, nil
		}
		lastErr = err
		if attempt == 0 {
			time.Sleep(250 * time.Millisecond)
		}
	}
	return []string{}, lastErr
}

func fetchOSINTPage(target *url.URL) (map[string]interface{}, []string, error) {
	return fetchOSINTPageWithTransport(target, osintHTTPClient.Transport)
}

func fetchOSINTPageWithTransport(target *url.URL, transport http.RoundTripper) (map[string]interface{}, []string, error) {
	// Redirects are followed manually to preserve every hop for the UI and to
	// keep the final request within the same bounded transport policy.
	current := target.String()
	chain := []string{current}
	var response *http.Response
	var lastErr error
	for step := 0; step < 8; step++ {
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			req, requestErr := http.NewRequest(http.MethodGet, current, nil)
			if requestErr != nil {
				return nil, nil, requestErr
			}
			req.Header.Set("User-Agent", "RequestRider-OSINT/1.0")
			client := *osintHTTPClient
			client.Transport = transport
			response, err = client.Do(req)
			if err == nil {
				break
			}
			lastErr = err
			if response != nil {
				response.Body.Close()
				response = nil
			}
			if strings.Contains(strings.ToLower(err.Error()), "lookup") {
				break
			}
			if attempt == 0 {
				time.Sleep(250 * time.Millisecond)
			}
		}
		if err != nil {
			return nil, chain, fmt.Errorf("GET %s failed after 2 attempts: %w", current, lastErr)
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			break
		}
		location := response.Header.Get("Location")
		response.Body.Close()
		if location == "" {
			break
		}
		next, err := target.Parse(location)
		if err != nil {
			break
		}
		current = next.String()
		chain = append(chain, current)
	}
	if response == nil {
		return nil, nil, fmt.Errorf("target returned no response")
	}
	defer response.Body.Close()
	body, truncated, err := readAnalysisBody(response.Body)
	if err != nil {
		return nil, nil, err
	}
	headers := flattenHeaders(response.Header)
	cookies := make([]map[string]interface{}, 0)
	for _, cookie := range response.Cookies() {
		cookies = append(cookies, map[string]interface{}{
			"name": cookie.Name, "secure": cookie.Secure, "http_only": cookie.HttpOnly,
			"same_site": fmt.Sprint(cookie.SameSite), "domain": cookie.Domain, "path": cookie.Path,
		})
	}
	page := map[string]interface{}{
		"status": response.StatusCode, "status_text": response.Status,
		"headers": headers, "content_type": response.Header.Get("Content-Type"),
		"size": len(body), "body_truncated": truncated, "cookies": cookies,
	}
	tlsInfo := map[string]interface{}{"enabled": response.TLS != nil}
	if response.TLS != nil {
		tlsInfo["version"] = tlsVersionName(response.TLS.Version)
		tlsInfo["cipher"] = tls.CipherSuiteName(response.TLS.CipherSuite)
		tlsInfo["negotiated_protocol"] = response.TLS.NegotiatedProtocol
	}
	page["tls"] = tlsInfo
	if utf8.Valid(body) {
		page["body"] = string(body)
	} else {
		page["body"] = ""
	}
	return page, chain, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func flattenHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func lookupMX(hostname string) []string {
	return lookupMXWithResolver(hostname, net.DefaultResolver)
}

func lookupMXWithResolver(hostname string, resolver *net.Resolver) []string {
	records, err := resolver.LookupMX(context.Background(), hostname)
	if err != nil {
		return []string{}
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(result)
	return result
}

func lookupNS(hostname string) []string {
	return lookupNSWithResolver(hostname, net.DefaultResolver)
}

func lookupNSWithResolver(hostname string, resolver *net.Resolver) []string {
	records, err := resolver.LookupNS(context.Background(), hostname)
	if err != nil {
		return []string{}
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(result)
	return result
}

func lookupTXT(hostname string) []string {
	return lookupTXTWithResolver(hostname, net.DefaultResolver)
}

func lookupTXTWithResolver(hostname string, resolver *net.Resolver) []string {
	records, err := resolver.LookupTXT(context.Background(), hostname)
	if err != nil {
		return []string{}
	}
	sort.Strings(records)
	return records
}

func securityHeaderChecks(headers map[string]string) map[string]interface{} {
	// These checks describe observable browser-facing protections; they do not
	// claim that a missing header alone proves a vulnerability.
	checks := map[string]interface{}{}
	for name, description := range map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Content-Type-Options":    "NoSniff",
		"X-Frame-Options":           "Clickjacking protection",
		"Referrer-Policy":           "Referrer policy",
		"Permissions-Policy":        "Permissions policy",
	} {
		value := ""
		for key, candidate := range headers {
			if strings.EqualFold(key, name) {
				value = candidate
				break
			}
		}
		checks[description] = map[string]interface{}{"present": value != "", "value": value}
	}
	return checks
}

func detectTechnologies(response map[string]interface{}, target *url.URL) []string {
	// Fingerprinting is based on static HTML, headers, cookies, and asset URLs.
	// Runtime-only frameworks require a browser/Wappalyzer worker and are not
	// inferred from speculation.
	headers := response["headers"].(map[string]string)
	body, _ := response["body"].(string)
	text := strings.ToLower(body)
	technologies := []string{}
	add := func(name, evidence string) {
		if evidence == "" {
			technologies = append(technologies, name)
			return
		}
		technologies = append(technologies, name+" · "+evidence)
	}
	for key, value := range headers {
		if strings.EqualFold(key, "server") && value != "" {
			add("Web server", "Server: "+value)
		}
		if strings.EqualFold(key, "x-powered-by") && value != "" {
			add("Runtime", "X-Powered-By: "+value)
		}
	}
	for marker, name := range map[string]string{
		"wp-content": "WordPress", "wp-includes": "WordPress",
		"woocommerce": "WooCommerce", "drupal-settings-json": "Drupal",
		"/sites/default/": "Drupal", "joomla": "Joomla", "shopify": "Shopify",
		"cdn.shopify.com": "Shopify", "wixstatic.com": "Wix",
		"squarespace.com": "Squarespace", "webflow.css": "Webflow",
		"ghost.org": "Ghost", "__next_data__": "Next.js",
		"_next/static": "Next.js", "__nuxt": "Nuxt.js", "webpack": "Webpack",
		"react": "React", "vue": "Vue.js", "ng-version": "Angular",
		"ng-app": "Angular", "svelte": "Svelte", "jquery": "jQuery",
		"bootstrap": "Bootstrap", "tailwind": "Tailwind CSS",
		"googletagmanager.com": "Google Tag Manager",
		"google-analytics.com": "Google Analytics", "gtag(": "Google Analytics",
		"laravel": "Laravel", "django": "Django", "rails": "Ruby on Rails",
		"magento": "Magento", "asp.net": "ASP.NET", "express": "Express",
	} {
		if strings.Contains(text, marker) {
			add(name, "HTML/script marker: "+marker)
		}
	}
	for key, value := range headers {
		lower := strings.ToLower(key + ": " + value)
		for marker, name := range map[string]string{
			"cf-ray": "Cloudflare", "x-vercel-id": "Vercel",
			"x-nf-request-id": "Netlify", "x-shopify-stage": "Shopify",
			"x-drupal-cache": "Drupal", "x-generator": "CMS generator",
		} {
			if strings.Contains(lower, marker) {
				add(name, "Header: "+key)
			}
		}
	}
	for _, cookie := range response["cookies"].([]map[string]interface{}) {
		name, _ := cookie["name"].(string)
		lower := strings.ToLower(name)
		for marker, technology := range map[string]string{
			"wordpress": "WordPress", "wp-settings": "WordPress",
			"laravel_session": "Laravel", "django": "Django",
			"phpsessid": "PHP", "asp.net": "ASP.NET",
		} {
			if strings.Contains(lower, marker) {
				add(technology, "Cookie: "+name)
			}
		}
	}
	for _, match := range regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`).FindAllStringSubmatch(body, -1) {
		add("Generator", strings.TrimSpace(match[1]))
	}
	if regexp.MustCompile(`(?is)<meta[^>]+(?:property|name)=["']og:`).MatchString(body) {
		add("Open Graph", "Meta tags: og:*")
	}
	if regexp.MustCompile(`(?is)<link[^>]+rel=["'][^"']*\bmanifest\b`).MatchString(body) ||
		strings.Contains(text, "serviceworker.register") {
		add("PWA", "Web app manifest or service worker")
	}
	if regexp.MustCompile(`(?is)<link[^>]+type=["']application/(?:rss|atom)\+xml["']`).MatchString(body) ||
		regexp.MustCompile(`(?is)<link[^>]+rel=["'][^"']*\balternate\b[^"']*["'][^>]+type=["']application/(?:rss|atom)\+xml["']`).MatchString(body) {
		add("RSS", "Alternate feed link")
	}
	reactVersion := regexp.MustCompile(`(?i)\breact(?:js)?[\/@ -]+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	if match := reactVersion.FindStringSubmatch(body); len(match) > 1 {
		add("JavaScript frameworks", "React "+match[1])
	} else if strings.Contains(text, "data-reactroot") ||
		strings.Contains(text, "__react_devtools_global_hook__") ||
		strings.Contains(text, "react.createelement") ||
		strings.Contains(text, "reactdom") {
		add("JavaScript frameworks", "React")
	}
	for _, match := range regexp.MustCompile(`(?is)<(?:script|link)[^>]+(?:src|href)=["']([^"']+)["']`).FindAllStringSubmatch(body, -1) {
		asset := strings.ToLower(match[1])
		for marker, name := range map[string]string{
			"cdn.jsdelivr.net": "jsDelivr", "unpkg.com": "unpkg",
			"cdnjs.cloudflare.com": "cdnjs", "fonts.googleapis.com": "Google Fonts",
			"recaptcha": "Google reCAPTCHA", "turnstile": "Cloudflare Turnstile",
		} {
			if strings.Contains(asset, marker) {
				add(name, "Asset URL: "+match[1])
			}
		}
	}
	if target.Scheme == "https" {
		add("HTTPS", "")
	}
	return uniqueStrings(technologies)
}

func detectWAF(response map[string]interface{}) map[string]interface{} {
	// Vendor scores combine independent clues so the report includes both a
	// confidence estimate and the evidence that produced it.
	headers := response["headers"].(map[string]string)
	body, _ := response["body"].(string)
	type signal struct {
		vendor   string
		evidence string
		score    int
	}
	signals := []signal{}
	for key, value := range headers {
		lower := strings.ToLower(key + " " + value)
		for marker, vendor := range map[string]string{
			"cloudflare": "Cloudflare", "cf-ray": "Cloudflare", "akamai": "Akamai",
			"imperva": "Imperva", "incap_ses": "Imperva", "sucuri": "Sucuri",
			"bunkerweb": "BunkerWeb", "mod_security": "ModSecurity",
		} {
			if strings.Contains(lower, marker) {
				signals = append(signals, signal{vendor, "Header: " + key, 30})
			}
		}
	}
	lowerBody := strings.ToLower(body)
	for marker, vendor := range map[string]string{
		"attention required": "Cloudflare", "access denied": "Generic WAF",
		"request rejected": "Generic WAF", "imperva incident": "Imperva",
	} {
		if strings.Contains(lowerBody, marker) {
			signals = append(signals, signal{vendor, "Body marker: " + marker, 25})
		}
	}
	scores := map[string]int{}
	evidence := map[string][]string{}
	for _, item := range signals {
		scores[item.vendor] += item.score
		evidence[item.vendor] = append(evidence[item.vendor], item.evidence)
	}
	vendors := []string{}
	bestScore := 0
	for vendor, score := range scores {
		vendors = append(vendors, vendor)
		if score > bestScore {
			bestScore = score
		}
	}
	sort.Strings(vendors)
	confidence := "none"
	if bestScore >= 50 {
		confidence = "high"
	} else if bestScore > 0 {
		confidence = "low"
	}
	return map[string]interface{}{
		"detected": len(vendors) > 0, "vendors": vendors, "confidence": confidence,
		"confidence_percent": minInt(bestScore, 100), "evidence": evidence,
	}
}

func minInt(value, maximum int) int {
	if value > maximum {
		return maximum
	}
	return value
}

func runWAFCanary(target *url.URL, baseline map[string]interface{}) map[string]interface{} {
	// The canary changes only a harmless query parameter and compares the
	// response with the baseline; it is not a bypass or evasion test.
	clone := *target
	query := clone.Query()
	query.Set("rr_waf_canary", "requestrider-benign-check")
	clone.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, clone.String(), nil)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	req.Header.Set("User-Agent", "RequestRider-OSINT/1.0")
	response, err := osintHTTPClient.Do(req)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	defer response.Body.Close()
	return map[string]interface{}{
		"status": "completed", "request_url": clone.String(), "http_status": response.StatusCode,
		"baseline_status": baseline["status"], "changed_status": response.StatusCode != osintIntValue(baseline["status"]),
		"note": "Benign canary only; this is not an exploit or bypass audit.",
	}
}

func osintIntValue(value interface{}) int {
	number, _ := value.(int)
	return number
}

func discoverOSINTResources(target *url.URL, response map[string]interface{}) map[string]interface{} {
	body, _ := response["body"].(string)
	return map[string]interface{}{
		"robots":      target.ResolveReference(&url.URL{Path: "/robots.txt"}).String(),
		"sitemap":     target.ResolveReference(&url.URL{Path: "/sitemap.xml"}).String(),
		"links_found": len(mapURLPattern.FindAllString(body, -1)),
	}
}

func runSafeScanner(target *url.URL) (map[string]interface{}, error) {
	base, err := runOSINT(target, true)
	if err != nil {
		return nil, err
	}
	findings := []map[string]interface{}{}
	statusCode := 0
	if httpSection, ok := base["http"].(map[string]interface{}); ok {
		if value, ok := httpSection["status"].(int); ok {
			statusCode = value
		}
	}
	securityHeaders, _ := base["security_headers"].(map[string]interface{})
	httpSection, _ := base["http"].(map[string]interface{})
	technologies := []string{}
	if items, ok := base["technologies"].([]string); ok {
		technologies = items
	}
	baselineFingerprint := responseFingerprint(httpSection)
	missing := []string{}
	if security, ok := securityHeaders["Strict-Transport-Security"].(map[string]interface{}); ok && !security["present"].(bool) {
		missing = append(missing, "Strict-Transport-Security")
	}
	if security, ok := securityHeaders["Content-Security-Policy"].(map[string]interface{}); ok && !security["present"].(bool) {
		missing = append(missing, "Content-Security-Policy")
	}
	if security, ok := securityHeaders["X-Frame-Options"].(map[string]interface{}); ok && !security["present"].(bool) {
		missing = append(missing, "X-Frame-Options")
	}
	if statusCode == 0 {
		findings = append(findings, map[string]interface{}{
			"severity":       "HIGH",
			"title":          "Target unreachable",
			"evidence":       "The target did not return a valid HTTP response during the passive scan.",
			"recommendation": "Verify the URL, ensure the service is running, and rerun the scan against an authorized target.",
		})
	} else {
		if statusCode >= 200 && statusCode < 400 {
			findings = append(findings, map[string]interface{}{
				"severity":       "INFO",
				"title":          "Public HTTP service reachable",
				"evidence":       fmt.Sprintf("HTTP %d response received from %s.", statusCode, target.String()),
				"recommendation": "Use the response as a baseline and verify access control, headers, and public surfaces.",
			})
		}
		if len(technologies) > 0 {
			findings = append(findings, map[string]interface{}{
				"severity":       "INFO",
				"title":          "Technology fingerprint detected",
				"evidence":       strings.Join(technologies[:min(len(technologies), 5)], ", "),
				"recommendation": "Confirm the technology stack in the app inventory and review framework-specific security settings.",
			})
		}
		if len(missing) > 0 {
			findings = append(findings, map[string]interface{}{
				"severity":       "MEDIUM",
				"title":          "Security headers missing",
				"evidence":       strings.Join(missing, ", "),
				"recommendation": "Add HSTS, CSP, and framing protections to reduce browser-side attack surface.",
			})
		}
		if tlsInfo, ok := httpSection["tls"].(map[string]interface{}); ok {
			if version, _ := tlsInfo["version"].(string); version == "TLS 1.0" || version == "TLS 1.1" {
				findings = append(findings, map[string]interface{}{
					"severity":       "MEDIUM",
					"title":          "Outdated TLS protocol negotiated",
					"evidence":       fmt.Sprintf("The target negotiated %s.", version),
					"recommendation": "Disable TLS 1.0 and TLS 1.1 and require TLS 1.2 or newer.",
				})
			}
		}
		if cookies, ok := httpSection["cookies"].([]map[string]interface{}); ok {
			for _, cookie := range cookies {
				name, _ := cookie["name"].(string)
				secure, _ := cookie["secure"].(bool)
				httpOnly, _ := cookie["http_only"].(bool)
				sameSite := fmt.Sprint(cookie["same_site"])
				if target.Scheme == "https" && !secure {
					findings = append(findings, map[string]interface{}{
						"severity":       "MEDIUM",
						"title":          "HTTPS cookie missing Secure flag",
						"evidence":       fmt.Sprintf("Cookie %q was set without Secure.", name),
						"recommendation": "Set Secure on cookies that are sent over HTTPS.",
					})
				}
				if !httpOnly {
					findings = append(findings, map[string]interface{}{
						"severity":       "LOW",
						"title":          "Cookie missing HttpOnly flag",
						"evidence":       fmt.Sprintf("Cookie %q was set without HttpOnly.", name),
						"recommendation": "Use HttpOnly for session and other non-client-readable cookies.",
					})
				}
				if sameSite == "0" || sameSite == "SameSiteDefaultMode" {
					findings = append(findings, map[string]interface{}{
						"severity":       "LOW",
						"title":          "Cookie SameSite policy is not explicit",
						"evidence":       fmt.Sprintf("Cookie %q did not advertise an explicit SameSite policy.", name),
						"recommendation": "Set SameSite=Lax or Strict where cross-site use is not required.",
					})
				}
			}
		}
		if waf, ok := base["waf"].(map[string]interface{}); ok && waf["detected"] == true {
			vendors, _ := waf["vendors"].([]string)
			findings = append(findings, map[string]interface{}{
				"severity":       "INFO",
				"title":          "WAF or edge protection signal detected",
				"evidence":       fmt.Sprintf("WAF vendors: %s", strings.Join(vendors, ", ")),
				"recommendation": "Keep the network edge in the approved inventory and review platform-specific protections.",
			})
		}
	}

	commonPaths := []struct {
		path     string
		name     string
		category string
	}{
		{path: "/wp-admin/", name: "WordPress admin surface", category: "cms"},
		{path: "/wp-login.php", name: "WordPress login surface", category: "cms"},
		{path: "/wp-json/", name: "WordPress JSON API", category: "cms"},
		{path: "/xmlrpc.php", name: "XML-RPC endpoint", category: "cms"},
		{path: "/administrator/", name: "Joomla admin surface", category: "cms"},
		{path: "/api/", name: "Public API path", category: "api"},
		{path: "/admin/", name: "Admin panel path", category: "admin"},
		{path: "/phpmyadmin/", name: "phpMyAdmin exposure", category: "admin"},
		{path: "/.env", name: "Environment file exposure", category: "misconfiguration"},
		{path: "/.git/HEAD", name: "Git metadata exposure", category: "misconfiguration"},
		{path: "/backup.zip", name: "Backup archive exposure", category: "misconfiguration"},
		{path: "/db.sql", name: "Database dump exposure", category: "misconfiguration"},
		{path: "/server-status", name: "Server status exposure", category: "debug"},
		{path: "/debug/", name: "Debug endpoint", category: "debug"},
	}
	probes := []map[string]interface{}{}
	for _, candidate := range commonPaths {
		probeURL := target.ResolveReference(&url.URL{Path: candidate.path}).String()
		response, err := probeScannerPath(probeURL)
		if err != nil {
			continue
		}
		probeBody, probeTruncated, _ := readAnalysisBody(response.Body)
		response.Body.Close()
		probeFingerprint := fingerprintResponse(response, probeBody)
		isFallback := baselineFingerprint != "" && probeFingerprint == baselineFingerprint
		probes = append(probes, map[string]interface{}{
			"path": candidate.path, "category": candidate.category, "status": response.StatusCode,
			"content_type": response.Header.Get("Content-Type"), "fingerprint": probeFingerprint,
			"same_as_baseline": isFallback, "body_truncated": probeTruncated,
		})
		if response.StatusCode >= 200 && response.StatusCode < 400 && !isFallback {
			severity := "LOW"
			if response.StatusCode == http.StatusOK {
				severity = "MEDIUM"
			}
			if candidate.category == "misconfiguration" && response.StatusCode == http.StatusOK {
				severity = "HIGH"
			}
			findings = append(findings, map[string]interface{}{
				"severity":       severity,
				"title":          candidate.name,
				"category":       candidate.category,
				"evidence":       fmt.Sprintf("%s returned HTTP %d (read-only probe; content was not retained).", probeURL, response.StatusCode),
				"recommendation": "Review whether this endpoint is intentionally exposed; if not, restrict access and validate the deployment configuration.",
			})
		}
	}
	allow, optionsErr := scannerOptions(target)
	if optionsErr == nil && allow != "" {
		findings = append(findings, map[string]interface{}{
			"severity":       "INFO",
			"title":          "HTTP methods advertised",
			"category":       "http",
			"evidence":       fmt.Sprintf("Allow header: %s", allow),
			"recommendation": "Disable methods that are not required by the application and verify write methods require authorization.",
		})
	}
	if len(findings) == 0 {
		findings = append(findings, map[string]interface{}{
			"severity":       "INFO",
			"title":          "No passive findings",
			"evidence":       "The target did not surface obvious public exposures during the read-only scan.",
			"recommendation": "Continue with a controlled, authorized review of the application and network configuration.",
		})
	}
	summary := map[string]interface{}{
		"target":           target.String(),
		"status_code":      statusCode,
		"findings_count":   len(findings),
		"highest_severity": "INFO",
	}
	severityRank := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
	for _, item := range findings {
		severity := strings.ToUpper(item["severity"].(string))
		current := summary["highest_severity"].(string)
		if severityRank[severity] > severityRank[current] {
			summary["highest_severity"] = severity
		}
	}
	return map[string]interface{}{
		"url":      target.String(),
		"status":   "completed",
		"summary":  summary,
		"findings": findings,
		"details": map[string]interface{}{
			"dns":              base["dns"],
			"http":             base["http"],
			"security_headers": base["security_headers"],
			"technologies":     base["technologies"],
			"waf":              base["waf"],
			"probes":           probes,
		},
	}, nil
}

func responseFingerprint(httpSection map[string]interface{}) string {
	body, _ := httpSection["body"].(string)
	if body == "" {
		return ""
	}
	return fingerprintBytes([]byte(body))
}

func fingerprintResponse(response *http.Response, body []byte) string {
	if response == nil || len(body) == 0 {
		return ""
	}
	return fingerprintBytes(body)
}

func fingerprintBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}

func probeScannerPath(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RequestRider-Scanner/1.0")
	return osintHTTPClient.Do(req)
}

func scannerOptions(target *url.URL) (string, error) {
	req, err := http.NewRequest(http.MethodOptions, target.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "RequestRider-Scanner/1.0")
	response, err := osintHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	return response.Header.Get("Allow"), nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func (s *server) targetMapStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/proxy/target-map/"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_MAP_ID", err)
		return
	}
	s.targetMapsMu.RLock()
	job, ok := s.targetMaps[id]
	s.targetMapsMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "TARGET_MAP_NOT_FOUND", fmt.Errorf("target map %d not found", id))
		return
	}
	if r.Method == http.MethodDelete {
		job.mu.Lock()
		job.cancel()
		job.status = "cancelling"
		job.mu.Unlock()
		writeJSON(w, http.StatusAccepted, targetMapSnapshot(id, job))
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, targetMapSnapshot(id, job))
}

func (s *server) runTargetMap(id uint64, job *targetMap, ctx context.Context, input targetMapInput) {
	// The crawler uses a bounded breadth-first queue. Keeping depth, origin,
	// page count, and body size constrained makes progress predictable.
	start, _ := url.Parse(job.startURL)
	origin := start.Scheme + "://" + start.Host
	queue := []struct {
		rawURL string
		depth  int
		kind   string
	}{{job.startURL, 0, "page"}}
	seen := map[string]bool{job.startURL: true}
	for _, suffix := range []string{"/robots.txt", "/sitemap.xml"} {
		resource := normalizeMapURL(mustResolveURL(start, suffix))
		if !seen[resource] {
			seen[resource] = true
			queue = append(queue, struct {
				rawURL string
				depth  int
				kind   string
			}{resource, 0, strings.TrimPrefix(suffix, "/")})
		}
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: s.requestTransport(), CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.rawURL, nil)
		if err != nil {
			continue
		}
		requestStart := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, bodyTruncated, readErr := readAnalysisBody(resp.Body)
		resp.Body.Close()
		page := map[string]interface{}{
			"url": item.rawURL, "depth": item.depth, "status": resp.StatusCode, "kind": item.kind,
			"content_type": resp.Header.Get("Content-Type"), "time": time.Since(requestStart).Milliseconds(),
			"body_truncated": bodyTruncated,
		}
		// Publish each page before discovering its links so polling clients can
		// render incremental progress while the crawl is still running.
		if readErr != nil {
			page["error"] = readErr.Error()
		}
		job.mu.Lock()
		job.pages = append(job.pages, page)
		job.visited = len(job.pages)
		job.mu.Unlock()
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if item.depth < input.MaxDepth || item.kind != "page" {
			links := extractMapLinks(string(body), contentType)
			if item.kind == "robots.txt" || strings.Contains(contentType, "xml") {
				links = append(links, extractSitemapReferences(string(body))...)
			}
			for _, link := range links {
				next, err := start.Parse(link)
				if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
					continue
				}
				next.Fragment = ""
				nextURL := normalizeMapURL(next)
				if input.SameOrigin && next.Scheme+"://"+next.Host != origin {
					continue
				}
				if !seen[nextURL] && len(seen) < input.MaxPages {
					seen[nextURL] = true
					queue = append(queue, struct {
						rawURL string
						depth  int
						kind   string
					}{nextURL, item.depth + 1, classifyMapURL(nextURL)})
				}
			}
		}
		if input.DelayMS > 0 && len(queue) > 0 && !waitForDelay(ctx, time.Duration(input.DelayMS)*time.Millisecond) {
			break
		}
	}
	job.mu.Lock()
	if ctx.Err() != nil {
		job.status = "cancelled"
	} else {
		job.status = "completed"
	}
	job.mu.Unlock()
	log.Printf("[TARGET-MAP %d] %s pages=%d", id, job.status, job.visited)
}

func targetMapSnapshot(id uint64, job *targetMap) map[string]interface{} {
	job.mu.RLock()
	defer job.mu.RUnlock()
	return map[string]interface{}{
		"map_id": id, "status": job.status, "start_url": job.startURL,
		"total": job.maxPages, "visited": job.visited,
		"pages": append([]map[string]interface{}{}, job.pages...),
	}
}

func normalizeMapURL(value *url.URL) string {
	value.Path = strings.ReplaceAll(value.Path, "//", "/")
	if value.Path == "" {
		value.Path = "/"
	}
	return value.String()
}

func extractMapLinks(body, contentType string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	var links []string
	if err == nil && strings.Contains(contentType, "html") {
		var walk func(*html.Node)
		walk = func(node *html.Node) {
			if node.Type == html.ElementNode {
				for _, attr := range node.Attr {
					if (node.Data == "a" && attr.Key == "href") ||
						(node.Data == "form" && attr.Key == "action") ||
						(node.Data == "script" && attr.Key == "src") ||
						(node.Data == "link" && attr.Key == "href") {
						if attr.Val != "" {
							links = append(links, strings.TrimSpace(attr.Val))
						}
					}
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				walk(child)
			}
		}
		walk(doc)
	}
	if strings.Contains(contentType, "css") {
		for _, match := range mapURLPattern.FindAllStringSubmatch(body, -1) {
			if validMapReference(match[1]) {
				links = append(links, match[1])
			}
		}
	}
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
		for _, match := range mapURLPattern.FindAllStringSubmatch(body, -1) {
			if validMapReference(match[1]) {
				links = append(links, match[1])
			}
		}
	}
	return links
}

func validMapReference(reference string) bool {
	reference = strings.TrimSpace(reference)
	if reference == "" || len(reference) > 2048 {
		return false
	}
	if strings.ContainsAny(reference, `\{}[]|*^$`) {
		return false
	}
	if strings.Contains(reference, "://") && !strings.HasPrefix(strings.ToLower(reference), "http://") &&
		!strings.HasPrefix(strings.ToLower(reference), "https://") {
		return false
	}
	if strings.HasPrefix(reference, "/") {
		return !strings.ContainsAny(reference, `"',();<>`)
	}
	return strings.HasPrefix(strings.ToLower(reference), "http://") ||
		strings.HasPrefix(strings.ToLower(reference), "https://")
}

func extractSitemapReferences(body string) []string {
	var links []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			links = append(links, strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Sitemap:"), "sitemap:")))
		}
	}
	for _, match := range regexp.MustCompile(`(?i)<loc>\s*([^<]+)\s*</loc>`).FindAllStringSubmatch(body, -1) {
		links = append(links, strings.TrimSpace(match[1]))
	}
	return links
}

func mustResolveURL(base *url.URL, reference string) *url.URL {
	resolved, err := base.Parse(reference)
	if err != nil {
		return &url.URL{Scheme: base.Scheme, Host: base.Host, Path: reference}
	}
	return resolved
}

func classifyMapURL(rawURL string) string {
	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasSuffix(lower, ".js"):
		return "javascript"
	case strings.HasSuffix(lower, ".css"):
		return "stylesheet"
	case strings.HasSuffix(lower, ".xml"):
		return "sitemap"
	case strings.HasSuffix(lower, "/robots.txt"):
		return "robots.txt"
	default:
		return "page"
	}
}

func (s *server) intruder(w http.ResponseWriter, r *http.Request) {
	// Every attack gets an ID so concurrent logs can be correlated.
	attackID := atomic.AddUint64(&s.attackSequence, 1)
	var input intruderInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("[INTRUDER %d] invalid_json error=%v", attackID, err)
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}

	normalizeIntruderMarkers(&input.BaseRequest)
	if input.DelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_DELAY", fmt.Errorf("delay_ms must not be negative"))
		return
	}
	// Resolve payload lists in marker order so replacement is deterministic.
	// Markers are discovered in URL, sorted headers, then body order.
	markers := requestPositions(input.BaseRequest)
	log.Printf("[INTRUDER %d] start mode=%s host=%s markers=%d dictionaries=%d transformations=%d", attackID, input.Mode, requestHost(input.BaseRequest.URL), len(markers), len(input.Payloads), len(input.Transforms))
	payloadSets := make([][]string, len(markers))
	// Resolve and transform one payload list for every marker position.
	for setIndex := range payloadSets {
		set := []string(nil)
		if values, ok := input.Dictionaries[markers[setIndex]]; ok {
			set = values
		} else if values, ok := input.Dictionaries[strconv.Itoa(setIndex)]; ok {
			set = values
		} else if len(input.Payloads) > 0 {
			payloadIndex := setIndex
			if payloadIndex >= len(input.Payloads) {
				payloadIndex = len(input.Payloads) - 1
			}

			set = input.Payloads[payloadIndex]
		}
		payloadSets[setIndex] = make([]string, len(set))
		for valueIndex, value := range set {
			transformed, transformErr := intruder.TransformPayload(value, input.Transforms)
			if transformErr != nil {
				log.Printf("[INTRUDER %d] transformation_error marker=%d payload_index=%d error=%v", attackID, setIndex, valueIndex, transformErr)
				writeError(w, http.StatusBadRequest, "INVALID_TRANSFORMATION", transformErr)
				return
			}
			payloadSets[setIndex][valueIndex] = transformed
		}
	}
	// Generate the complete job list before starting concurrent requests.
	jobs, err := intruder.Generate(input.Mode, len(markers), payloadSets)
	if err != nil {
		log.Printf("[INTRUDER %d] generation_error mode=%s error=%v", attackID, input.Mode, err)
		writeError(w, http.StatusBadRequest, "INVALID_INTRUDER", err)
		return
	}
	log.Printf("[INTRUDER %d] generated_jobs=%d payload_sizes=%v", attackID, len(jobs), payloadSizes(payloadSets))
	// Start the attack after the request returns so the browser can observe and cancel it.
	ctx, cancel := context.WithCancel(context.Background())
	job := &attack{cancel: cancel, resumeCh: make(chan struct{}), status: "running", total: len(jobs), results: make([]map[string]interface{}, 0, len(jobs))}
	s.attacksMu.Lock()
	s.attacks[attackID] = job
	s.attacksMu.Unlock()
	writeJSON(w, http.StatusAccepted, s.attackSnapshot(attackID, job, 0, 500))
	go s.runAttack(attackID, job, ctx, input.BaseRequest, jobs, input.DelayMS, input.Concurrency)
}

func normalizeIntruderMarkers(input *requestInput) {
	// Preserve section markers when a browser or gateway URL-encodes the UTF-8
	// representation of § before the request reaches the engine.
	restore := func(value string) string {
		value = strings.ReplaceAll(value, "%25C2%25A7", "§")
		return strings.ReplaceAll(value, "%C2%A7", "§")
	}
	input.URL = restore(input.URL)
	input.Body = restore(input.Body)
	for key, value := range input.Headers {
		input.Headers[key] = restore(value)
	}
}

func (s *server) runAttack(attackID uint64, attackJob *attack, ctx context.Context, base requestInput, jobs []intruder.Job, delayMS, concurrency int) {
	ctx = context.WithValue(ctx, suppressRequestLogsKey{}, true)
	workers := concurrency
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
		if workers < 4 {
			workers = 4
		}
		if workers > 32 {
			workers = 32
		}
	}
	if delayMS > 0 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	var wg sync.WaitGroup
	jobIndexes := make(chan int)
	var lastRequest time.Time
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobIndexes {
				job := jobs[index]
				if !waitForAttack(ctx, attackJob) {
					return
				}
				if delayMS > 0 && !lastRequest.IsZero() {
					if !waitForDelay(ctx, time.Until(lastRequest.Add(time.Duration(delayMS)*time.Millisecond))) {
						return
					}
				}
				// Clone prevents one goroutine from mutating another job's headers.
				req := cloneRequest(base)
				// position tracks markers across URL, headers and body as one stream.
				position := 0
				req.URL, position = intruder.ReplaceAt(req.URL, job.Values, position)
				for _, key := range sortedHeaderKeys(req.Headers) {
					req.Headers[key], position = intruder.ReplaceAt(req.Headers[key], job.Values, position)
				}
				req.Body, _ = intruder.ReplaceAt(req.Body, job.Values, position)
				result, execErr := s.executeContext(ctx, req)
				if delayMS > 0 {
					lastRequest = time.Now()
				}
				if execErr != nil {
					if ctx.Err() != nil {
						return
					}

					result = map[string]interface{}{"error": execErr.Error(), "payloads": job.Values}
				} else {
					result["payloads"] = job.Values
				}
				result["request"] = map[string]interface{}{
					"method":  req.Method,
					"url":     req.URL,
					"headers": req.Headers,
					"body":    req.Body,
				}
				s.publishIntruderTraffic(attackID, req, result, execErr)
				attackJob.mu.Lock()
				attackJob.results = append(attackJob.results, result)
				attackJob.completed++
				if execErr != nil {
					attackJob.failed++
				}
				attackJob.mu.Unlock()
			}
		}()
	}
dispatch:
	for index := range jobs {
		select {
		case jobIndexes <- index:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobIndexes)
	wg.Wait()
	attackJob.mu.Lock()
	if ctx.Err() != nil {
		attackJob.status = "cancelled"
	} else {
		attackJob.status = "completed"
	}
	attackJob.mu.Unlock()
	attackJob.mu.RLock()
	status := attackJob.status
	attackJob.mu.RUnlock()
	log.Printf("[INTRUDER %d] %s jobs=%d", attackID, status, len(jobs))
}

func waitForDelay(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func requestLogsSuppressed(ctx context.Context) bool {
	return ctx.Value(suppressRequestLogsKey{}) == true
}

func (s *server) publishIntruderTraffic(attackID uint64, req requestInput, result map[string]interface{}, execErr error) {
	// Intruder uses the active engine directly, so publish its completed
	// exchanges explicitly for the same Traffic stream as passive proxy events.
	if s.store == nil {
		return
	}
	sourceIP := stringValue(result["source_ip"])
	event := passive.Event{
		Source:        "intruder",
		Session:       int64(attackID),
		Timestamp:     time.Now().UTC(),
		Method:        req.Method,
		URL:           req.URL,
		Host:          requestHost(req.URL),
		RequestHeader: req.Headers,
		RequestBody:   req.Body,
		SourceIP:      sourceIP,
	}
	if execErr != nil {
		event.Error = execErr.Error()
	} else {
		event.Status = intValue(result["status"])
		event.ResponseHeader = stringMapValue(result["headers"])
		event.ResponseBody = stringValue(result["body"])
		event.ResponseBodyEncoding = stringValue(result["body_encoding"])
		event.ResponseBodyBase64 = stringValue(result["body_base64"])
		event.ResponseContentType = stringValue(result["body_content_type"])
		event.ResponseSize = intValue(result["size"])
		event.Latency = int64Value(result["time"])
	}
	s.store.Add(event)
}

func (s *server) addRequestTraffic(req requestInput, sourceIP string) uint64 {
	// Publish the Repeater request immediately, then complete the same event
	// after the outbound response arrives.
	if s.store == nil {
		return 0
	}
	event := passive.Event{
		Source:        "repeater",
		Timestamp:     time.Now().UTC(),
		Method:        req.Method,
		URL:           req.URL,
		Host:          requestHost(req.URL),
		RequestHeader: req.Headers,
		RequestBody:   req.Body,
		SourceIP:      sourceIP,
	}
	return s.store.Add(event)
}

func (s *server) completeRequestTraffic(eventID uint64, result map[string]interface{}, execErr error) {
	if s.store == nil || eventID == 0 {
		return
	}
	if execErr != nil {
		s.store.Update(eventID, func(event *passive.Event) {
			event.Error = execErr.Error()
		})
		return
	}
	s.store.Update(eventID, func(event *passive.Event) {
		event.Status = intValue(result["status"])
		event.ResponseHeader = stringMapValue(result["headers"])
		event.ResponseBody = stringValue(result["body"])
		event.ResponseBodyEncoding = stringValue(result["body_encoding"])
		event.ResponseBodyBase64 = stringValue(result["body_base64"])
		event.ResponseContentType = stringValue(result["body_content_type"])
		event.ResponseSize = intValue(result["size"])
		event.Latency = int64Value(result["time"])
	})
}

func intValue(value interface{}) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func int64Value(value interface{}) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func stringValue(value interface{}) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func stringMapValue(value interface{}) map[string]string {
	if typed, ok := value.(map[string]string); ok {
		return typed
	}
	if typed, ok := value.(map[string]interface{}); ok {
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			if text, ok := item.(string); ok {
				result[key] = text
			}
		}
		return result
	}
	return nil
}

func (s *server) intruderStatus(w http.ResponseWriter, r *http.Request) {
	idText := strings.TrimPrefix(r.URL.Path, "/proxy/intruder/")
	attackID, err := strconv.ParseUint(idText, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ATTACK_ID", err)
		return
	}
	s.attacksMu.RLock()
	attackJob, ok := s.attacks[attackID]
	s.attacksMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "ATTACK_NOT_FOUND", fmt.Errorf("attack %d not found", attackID))
		return
	}
	if r.Method == http.MethodDelete {
		attackJob.mu.Lock()
		if attackJob.status == "pending" || attackJob.status == "running" {
			attackJob.cancel()
			if attackJob.paused {
				close(attackJob.resumeCh)
			}
			attackJob.status = "cancelled"
		}
		attackJob.mu.Unlock()
		writeJSON(w, http.StatusAccepted, s.attackSnapshot(attackID, attackJob, 0, 500))
		return
	}
	if r.Method == http.MethodPost {
		var command struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&command)
		switch strings.ToLower(command.Action) {
		case "pause":
			attackJob.mu.Lock()
			if attackJob.status == "running" {
				attackJob.paused = true
				attackJob.status = "paused"
				attackJob.resumeCh = make(chan struct{})
			}
			attackJob.mu.Unlock()
		case "resume":
			attackJob.mu.Lock()
			if attackJob.status == "paused" {
				close(attackJob.resumeCh)
				attackJob.paused = false
				attackJob.status = "running"
				attackJob.resumeCh = make(chan struct{})
				close(attackJob.resumeCh)
			}
			attackJob.mu.Unlock()
		default:
			writeError(w, http.StatusBadRequest, "INVALID_ATTACK_ACTION", fmt.Errorf("action must be pause or resume"))
			return
		}
		writeJSON(w, http.StatusAccepted, s.attackSnapshot(attackID, attackJob, 0, 500))
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}

	since, _ := strconv.Atoi(r.URL.Query().Get("since"))
	if since < 0 {
		since = 0
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	writeJSON(w, http.StatusOK, s.attackSnapshot(attackID, attackJob, since, limit))
}

func waitForAttack(ctx context.Context, job *attack) bool {
	for {
		job.mu.RLock()
		paused := job.paused
		resumeCh := job.resumeCh
		job.mu.RUnlock()
		if !paused {
			select {
			case <-ctx.Done():
				return false
			default:
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-resumeCh:
		}
	}
}

func parseEventCursor(r *http.Request) uint64 {
	value := r.Header.Get("Last-Event-ID")
	if value == "" {
		value = r.URL.Query().Get("last_event_id")
	}
	cursor, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	return cursor
}

func (s *server) attackSnapshot(id uint64, attackJob *attack, since int, limit int) map[string]interface{} {
	attackJob.mu.RLock()
	defer attackJob.mu.RUnlock()
	results := attackJob.results
	if results == nil {
		results = []map[string]interface{}{}
	}
	if since > len(results) {
		since = len(results)
	}
	end := since + limit
	if end > len(results) {
		end = len(results)
	}
	return map[string]interface{}{
		"attack_id":     id,
		"status":        attackJob.status,
		"total":         attackJob.total,
		"completed":     attackJob.completed,
		"failed":        attackJob.failed,
		"result_offset": since,
		"results":       append([]map[string]interface{}{}, results[since:end]...),
	}
}

func requestHost(rawURL string) string {
	// Logs use only the parsed host, not request bodies or credentials.
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "-"
	}
	return parsed.Host
}

func requestPath(rawURL string) string {
	// Keep logs useful without printing query values.
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

func payloadSizes(payloadSets [][]string) []int {
	// Report dictionary sizes without logging their actual values.
	sizes := make([]int, len(payloadSets))
	for index, payloads := range payloadSets {
		sizes[index] = len(payloads)
	}
	return sizes
}

func requestPositions(input requestInput) []string {
	// Use the same ordering for discovery and replacement.
	values := intruder.Positions(input.URL)
	keys := sortedHeaderKeys(input.Headers)
	for _, key := range keys {
		values = append(values, intruder.Positions(input.Headers[key])...)
	}
	values = append(values, intruder.Positions(input.Body)...)
	return values
}

func sortedHeaderKeys(headers map[string]string) []string {
	// Map iteration is random; sorting makes marker order reproducible.
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneRequest(input requestInput) requestInput {
	// Copy the header map because maps are reference types in Go.
	headers := make(map[string]string, len(input.Headers))
	for key, value := range input.Headers {
		headers[key] = value
	}
	input.Headers = headers
	return input
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	// Keep all successful and error responses JSON encoded consistently.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, reason string, err error) {
	// Expose a machine-readable reason together with the human-readable error.
	writeJSON(w, status, map[string]string{"error": err.Error(), "reason": reason})
}
