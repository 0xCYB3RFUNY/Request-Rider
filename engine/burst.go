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
	mu         sync.RWMutex
	cancel     context.CancelFunc
	resumeCh   chan struct{}
	status     string
	input      repeaterBurstInput
	results    []map[string]interface{}
	attempted  int
	completed  int
	failed     int
	startedAt  time.Time
	finishedAt time.Time
}

func (s *server) repeaterBurstStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input repeaterBurstInput
	decoder := json.NewDecoder(r.Body)
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
	id := atomic.AddUint64(&s.burstSequence, 1)
	_, routeContext, releaseRoute := s.bindRouteContext(context.WithoutCancel(r.Context()))
	ctx, cancel := context.WithCancel(routeContext)
	job := &repeaterBurst{
		cancel: func() { cancel(); releaseRoute() }, resumeCh: make(chan struct{}), status: "running",
		input: input, startedAt: time.Now().UTC(),
	}
	s.burstsMu.Lock()
	if s.bursts == nil {
		s.bursts = make(map[uint64]*repeaterBurst)
	}
	s.bursts[id] = job
	s.burstsMu.Unlock()
	writeJSON(w, http.StatusAccepted, repeaterBurstSnapshot(id, job))
	go s.runRepeaterBurst(id, job, ctx)
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
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
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

func (s *server) runRepeaterBurst(id uint64, job *repeaterBurst, ctx context.Context) {
	defer job.cancel()
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
				results <- s.executeBurstRequest(ctx, job.input, iteration)
			}(index)
		}
		wg.Wait()
		close(results)
		for result := range results {
			job.mu.Lock()
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
	requestContext := ctx
	cancel := func() {}
	if input.TimeoutMS > 0 {
		requestContext, cancel = context.WithTimeout(ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
	}
	defer cancel()
	lookup := s.startSourceIPLookup(ctx)
	eventID := s.addRequestTraffic(request, "")
	req, err := http.NewRequestWithContext(requestContext, input.Method, input.URL, strings.NewReader(input.Body))
	result := map[string]interface{}{"iteration": iteration, "source_ip": "", "traffic_event_id": eventID}
	defer func() {
		if ip, ready := sourceIPIfReady(lookup); ready {
			result["source_ip"] = ip
			s.setTrafficSourceIP(eventID, ip)
		} else {
			result["source_ip_pending"] = true
			s.updateTrafficSourceIP(eventID, lookup)
		}
	}()
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
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		s.completeRequestTraffic(eventID, nil, readErr)
		result["error"] = readErr.Error()
		return result
	}
	headers := map[string]string{}
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	result["status"] = resp.StatusCode
	result["status_text"] = resp.Status
	result["time"] = time.Since(started).Milliseconds()
	result["size"] = len(body)
	result["headers"] = headers
	result["headers_truncated"] = false
	result["body_truncated"] = false
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
	if input.Iterations < 1 {
		return fmt.Errorf("iterations must be positive")
	}
	if input.Concurrency < 1 {
		return fmt.Errorf("concurrency must be positive")
	}
	if input.DelayMS < 0 {
		return fmt.Errorf("delay_ms must not be negative")
	}
	if input.TimeoutMS < 0 {
		return fmt.Errorf("timeout_ms must not be negative")
	}
	for key, value := range input.Headers {
		if key == "" || strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("burst headers contain invalid characters")
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

func repeaterBurstSnapshot(id uint64, job *repeaterBurst) map[string]interface{} {
	job.mu.RLock()
	defer job.mu.RUnlock()
	results := append([]map[string]interface{}(nil), job.results...)
	sort.Slice(results, func(left, right int) bool {
		return intValue(results[left]["iteration"]) < intValue(results[right]["iteration"])
	})
	return map[string]interface{}{
		"burst_id": id, "status": job.status, "mode": "parallel",
		"total": job.input.Iterations, "total_sent": job.attempted, "count": len(results),
		"attempted": job.attempted, "completed": job.completed, "failed": job.failed,
		"results": results, "started_at": job.startedAt, "finished_at": job.finishedAt,
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
