package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var (
	maxBurstURLBytes            = envLimit("RR_BURST_MAX_URL_BYTES", 2048)
	maxBurstResponseBytes       = envLimit("RR_BURST_MAX_RESPONSE_BYTES", 1<<20)
	maxBurstResultBytes         = envLimit("RR_BURST_MAX_RESULT_BYTES", 8<<20)
	maxBurstResponseHeaderBytes = envLimit("RR_BURST_MAX_RESPONSE_HEADER_BYTES", 64<<10)
	maxBurstResponseHeaders     = envLimit("RR_BURST_MAX_RESPONSE_HEADERS", 100)
	maxBurstIterations          = envLimit("RR_BURST_MAX_ITERATIONS", 20)
	maxBurstConcurrency         = envLimit("RR_BURST_MAX_CONCURRENCY", 4)
	maxBurstDelayMS             = envLimit("RR_BURST_MAX_DELAY_MS", 5000)
	maxBurstTimeoutMS           = envLimit("RR_BURST_MAX_TIMEOUT_MS", 15000)
	maxBurstRequestHeaders      = envLimit("RR_BURST_MAX_REQUEST_HEADERS", 50)
	maxBurstHeaderNameBytes     = envLimit("RR_BURST_MAX_HEADER_NAME_BYTES", 128)
	maxBurstHeaderValueBytes    = envLimit("RR_BURST_MAX_HEADER_VALUE_BYTES", 4096)
	maxBurstActiveJobs          = envLimit("RR_BURST_MAX_ACTIVE_JOBS", 4)
	maxBurstActiveRequests      = envLimit("RR_BURST_MAX_ACTIVE_REQUESTS", 16)
)

var burstRetention = time.Duration(envLimit("RR_BURST_RETENTION_SEC", 600)) * time.Second

type repeaterBurstInput struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Iterations  int               `json:"iterations"`
	Concurrency int               `json:"concurrency"`
	DelayMS     int               `json:"delay_ms"`
	TimeoutMS   int               `json:"timeout_ms"`
}

type repeaterBurst struct {
	mu          sync.RWMutex
	cancel      context.CancelFunc
	resumeCh    chan struct{}
	status      string
	input       repeaterBurstInput
	results     []map[string]interface{}
	attempted   int
	completed   int
	failed      int
	resultBytes int
	startedAt   time.Time
	finishedAt  time.Time
}

func (s *server) repeaterBurstStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input repeaterBurstInput
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", fmt.Errorf("request body must contain one JSON object"))
		return
	}
	if err := validateBurstInput(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BURST_INPUT", err)
		return
	}
	s.burstSlotsMu.Lock()
	if s.burstSlots == nil {
		s.burstSlots = make(chan struct{}, maxBurstActiveRequests)
	}
	if s.burstJobSlots == nil {
		s.burstJobSlots = make(chan struct{}, maxBurstActiveJobs)
	}
	slots := s.burstSlots
	jobSlots := s.burstJobSlots
	s.burstSlotsMu.Unlock()
	select {
	case jobSlots <- struct{}{}:
	default:
		writeError(w, http.StatusTooManyRequests, "BURST_LIMIT_REACHED", fmt.Errorf("too many active repeater bursts"))
		return
	}
	id := atomic.AddUint64(&s.burstSequence, 1)
	ctx, cancel := context.WithCancel(context.Background())
	job := &repeaterBurst{
		cancel: cancel, resumeCh: make(chan struct{}), status: "running",
		input: input, startedAt: time.Now().UTC(),
	}
	s.burstsMu.Lock()
	if s.bursts == nil {
		s.bursts = make(map[uint64]*repeaterBurst)
	}
	s.bursts[id] = job
	s.burstsMu.Unlock()
	writeJSON(w, http.StatusAccepted, repeaterBurstSnapshot(id, job))
	go s.runRepeaterBurst(id, job, ctx, slots, jobSlots)
}

func (s *server) repeaterBurstStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseBurstID(r.URL.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BURST_ID", err)
		return
	}
	s.burstsMu.RLock()
	job, ok := s.bursts[id]
	s.burstsMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "BURST_NOT_FOUND", fmt.Errorf("burst %d not found", id))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, repeaterBurstSnapshot(id, job))
	case http.MethodDelete:
		job.mu.Lock()
		if !isBurstTerminal(job.status) {
			job.status = "cancelling"
			job.cancel()
		}
		job.mu.Unlock()
		writeJSON(w, http.StatusAccepted, repeaterBurstSnapshot(id, job))
	case http.MethodPost:
		var action struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&action); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
			return
		}
		job.mu.Lock()
		switch strings.ToLower(strings.TrimSpace(action.Action)) {
		case "pause":
			if !isBurstTerminal(job.status) && job.status != "paused" {
				job.status = "paused"
			}
		case "resume":
			if job.status == "paused" {
				job.status = "running"
				close(job.resumeCh)
				job.resumeCh = make(chan struct{})
			}
		default:
			job.mu.Unlock()
			writeError(w, http.StatusBadRequest, "INVALID_BURST_ACTION", fmt.Errorf("action must be pause or resume"))
			return
		}
		job.mu.Unlock()
		writeJSON(w, http.StatusOK, repeaterBurstSnapshot(id, job))
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
	}
}

func (s *server) runRepeaterBurst(id uint64, job *repeaterBurst, ctx context.Context, slots chan struct{}, jobSlots chan struct{}) {
	defer job.cancel()
	defer func() { <-jobSlots }()
	defer s.scheduleBurstCleanup(id, job)
	defer func() {
		snapshot := repeaterBurstSnapshot(id, job)
		log.Printf("[REPEATER-BURST %d] %s requested=%d completed=%d failed=%d", id, snapshot["status"], snapshot["total"], snapshot["completed"], snapshot["failed"])
	}()
	for start := 0; start < job.input.Iterations; start += job.input.Concurrency {
		if !waitBurstReady(job, ctx) {
			markBurstCancelled(job)
			return
		}
		end := start + job.input.Concurrency
		if end > job.input.Iterations {
			end = job.input.Iterations
		}
		results := make(chan map[string]interface{}, end-start)
		var wg sync.WaitGroup
		for index := start; index < end; index++ {
			wg.Add(1)
			go func(iteration int) {
				defer wg.Done()
				if ctx.Err() != nil {
					results <- map[string]interface{}{"iteration": iteration, "error": "burst cancelled"}
					return
				}
				select {
				case slots <- struct{}{}:
					defer func() { <-slots }()
				case <-ctx.Done():
					results <- map[string]interface{}{"iteration": iteration, "error": "burst cancelled"}
					return
				}
				results <- s.executeBurstRequest(ctx, job.input, iteration)
			}(index)
		}
		wg.Wait()
		close(results)
		for result := range results {
			job.mu.Lock()
			resultSize := burstResultSize(result)
			if job.resultBytes+resultSize > maxBurstResultBytes {
				delete(result, "body")
				delete(result, "body_base64")
				result["body_truncated"] = true
				result["aggregate_truncated"] = true
				resultSize = burstResultSize(result)
			}
			job.resultBytes += resultSize
			job.results = append(job.results, result)
			job.attempted++
			if result["error"] != nil {
				job.failed++
			} else {
				job.completed++
			}
			job.mu.Unlock()
		}
		if end < job.input.Iterations && job.input.DelayMS > 0 {
			if !waitBurstDelay(ctx, time.Duration(job.input.DelayMS)*time.Millisecond) {
				markBurstCancelled(job)
				return
			}
		}
	}
	job.mu.Lock()
	if ctx.Err() != nil {
		job.status = "cancelled"
	} else {
		job.status = "completed"
	}
	job.finishedAt = time.Now().UTC()
	job.mu.Unlock()
}

func (s *server) executeBurstRequest(ctx context.Context, input repeaterBurstInput, iteration int) map[string]interface{} {
	request := requestInput{Method: input.Method, URL: input.URL, Headers: cloneStringMap(input.Headers), Body: input.Body}
	eventID := s.addRequestTraffic(request, "")
	requestContext, cancel := context.WithTimeout(ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, input.Method, input.URL, strings.NewReader(input.Body))
	result := map[string]interface{}{"iteration": iteration}
	if err != nil {
		s.completeRequestTraffic(eventID, nil, err)
		result["error"] = err.Error()
		return result
	}
	for key, value := range input.Headers {
		if isManagedBurstHeader(key) {
			continue
		}
		req.Header.Set(key, value)
	}
	// Do not reuse a connection: net/http may replay idempotent requests after
	// a stale reused connection, which would violate the explicit iteration count.
	req.Close = true
	started := time.Now()
	resp, err := (&http.Client{
		Transport:     s.requestTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		s.completeRequestTraffic(eventID, nil, err)
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		return result
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxBurstResponseBytes)+1))
	truncated := len(body) > maxBurstResponseBytes
	if truncated {
		body = body[:maxBurstResponseBytes]
	}
	if readErr != nil {
		s.completeRequestTraffic(eventID, nil, readErr)
		result["error"] = readErr.Error()
		return result
	}
	headers := map[string]string{}
	headerBytes := 0
	headersTruncated := false
	for key, values := range resp.Header {
		joined := strings.Join(values, ", ")
		if len(headers) >= maxBurstResponseHeaders || headerBytes+len(key)+len(joined) > maxBurstResponseHeaderBytes {
			headersTruncated = true
			break
		}
		headers[key] = joined
		headerBytes += len(key) + len(joined)
	}
	result["status"] = resp.StatusCode
	result["status_text"] = resp.Status
	result["time"] = time.Since(started).Milliseconds()
	result["size"] = len(body)
	result["headers"] = headers
	result["headers_truncated"] = headersTruncated
	result["body_truncated"] = truncated
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
	s.completeRequestTraffic(eventID, result, nil)
	return result
}

func isManagedBurstHeader(key string) bool {
	switch strings.ToLower(key) {
	case "host", "content-length", "transfer-encoding", "connection", "expect":
		return true
	default:
		return false
	}
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for _, character := range method {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func validateBurstInput(input *repeaterBurstInput) error {
	input.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	if input.Method == "" {
		input.Method = http.MethodGet
	}
	if !validHTTPMethod(input.Method) {
		return fmt.Errorf("method must be a valid HTTP token")
	}
	rawURL := strings.TrimSpace(input.URL)
	if len(rawURL) > maxBurstURLBytes {
		return fmt.Errorf("url is too long")
	}
	if strings.ContainsAny(rawURL, "\r\n") || strings.IndexFunc(rawURL, func(value rune) bool { return value < 0x20 || value == 0x7f }) >= 0 {
		return fmt.Errorf("url contains control characters")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("url must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("url must not contain userinfo or fragment")
	}
	// Burst accepts arbitrary caller-supplied methods and bodies. HTTP
	// framing headers remain executor-owned below rather than a policy gate.
	if input.Iterations < 1 || input.Iterations > maxBurstIterations {
		return fmt.Errorf("iterations must be between 1 and %d", maxBurstIterations)
	}
	if input.Concurrency < 1 || input.Concurrency > maxBurstConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d", maxBurstConcurrency)
	}
	if input.DelayMS < 0 || input.DelayMS > maxBurstDelayMS {
		return fmt.Errorf("delay_ms must be between 0 and %d", maxBurstDelayMS)
	}
	if input.TimeoutMS < 1 || input.TimeoutMS > maxBurstTimeoutMS {
		return fmt.Errorf("timeout_ms must be between 1 and %d", maxBurstTimeoutMS)
	}
	if len(input.Headers) > maxBurstRequestHeaders {
		return fmt.Errorf("burst supports at most %d headers", maxBurstRequestHeaders)
	}
	for key, value := range input.Headers {
		if key == "" || len(key) > maxBurstHeaderNameBytes || len(value) > maxBurstHeaderValueBytes || strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("burst headers contain invalid characters or are too large")
		}
	}
	return nil
}

func waitBurstReady(job *repeaterBurst, ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		job.mu.RLock()
		status := job.status
		paused := status == "paused"
		resume := job.resumeCh
		job.mu.RUnlock()
		if status == "cancelling" || isBurstTerminal(status) {
			return false
		}
		if !paused {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-resume:
		}
	}
}

func waitBurstDelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func markBurstCancelled(job *repeaterBurst) {
	job.mu.Lock()
	job.status = "cancelled"
	job.finishedAt = time.Now().UTC()
	job.mu.Unlock()
}

func isBurstTerminal(status string) bool {
	return status == "completed" || status == "cancelled" || status == "failed"
}

func parseBurstID(path string) (uint64, error) {
	value := strings.TrimPrefix(path, "/proxy/repeater-burst/")
	if value == "" || strings.Contains(value, "/") {
		return 0, fmt.Errorf("invalid burst id")
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid burst id")
	}
	return id, nil
}

func (s *server) scheduleBurstCleanup(id uint64, job *repeaterBurst) {
	time.AfterFunc(burstRetention, func() {
		s.burstsMu.Lock()
		defer s.burstsMu.Unlock()
		if current, ok := s.bursts[id]; ok && current == job {
			delete(s.bursts, id)
		}
	})
}

func repeaterBurstSnapshot(id uint64, job *repeaterBurst) map[string]interface{} {
	job.mu.RLock()
	defer job.mu.RUnlock()
	results := append([]map[string]interface{}(nil), job.results...)
	sort.Slice(results, func(left, right int) bool {
		return intValue(results[left]["iteration"]) < intValue(results[right]["iteration"])
	})
	return map[string]interface{}{
		"burst_id": id, "status": job.status, "mode": "bounded_parallel",
		"total": job.input.Iterations, "total_sent": job.attempted, "count": len(results),
		"attempted": job.attempted, "completed": job.completed, "failed": job.failed,
		"results": results, "started_at": job.startedAt, "finished_at": job.finishedAt,
	}
}

func burstResultSize(result map[string]interface{}) int {
	size := 0
	if body, ok := result["body"].(string); ok {
		size += len(body)
	}
	if body, ok := result["body_base64"].(string); ok {
		size += len(body)
	}
	return size
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
