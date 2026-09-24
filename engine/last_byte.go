package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"intruder/engine/pkg/passive"
)

var (
	maxLastByteURLBytes         = envLimit("RR_LAST_BYTE_MAX_URL_BYTES", 2048)
	maxLastByteBodyBytes        = envLimit("RR_LAST_BYTE_MAX_BODY_BYTES", 32<<10)
	maxLastByteRequestBytes     = envLimit("RR_LAST_BYTE_MAX_REQUEST_BYTES", 64<<10)
	maxLastByteResponseBytes    = envLimit("RR_LAST_BYTE_MAX_RESPONSE_BYTES", 1<<20)
	maxLastByteResponseRaw      = maxLastByteResponseBytes + envLimit("RR_LAST_BYTE_MAX_RAW_RESPONSE_BYTES", 64<<10)
	maxLastByteAggregateBytes   = envLimit("RR_LAST_BYTE_MAX_AGGREGATE_BYTES", 8<<20)
	maxLastByteHeaderBytes      = envLimit("RR_LAST_BYTE_MAX_HEADER_BYTES", 64<<10)
	maxLastByteHeaders          = envLimit("RR_LAST_BYTE_MAX_RESPONSE_HEADERS", 100)
	maxLastByteIterations       = envLimit("RR_LAST_BYTE_MAX_ITERATIONS", 20)
	maxLastByteConcurrency      = envLimit("RR_LAST_BYTE_MAX_CONCURRENCY", 4)
	maxLastByteHoldMS           = envLimit("RR_LAST_BYTE_MAX_HOLD_MS", 2000)
	maxLastByteDelayMS          = envLimit("RR_LAST_BYTE_MAX_DELAY_MS", 5000)
	maxLastByteTimeoutMS        = envLimit("RR_LAST_BYTE_MAX_TIMEOUT_MS", 30000)
	maxLastByteRequestHeaders   = envLimit("RR_LAST_BYTE_MAX_REQUEST_HEADERS", 50)
	maxLastByteHeaderNameBytes  = envLimit("RR_LAST_BYTE_MAX_HEADER_NAME_BYTES", 128)
	maxLastByteHeaderValueBytes = envLimit("RR_LAST_BYTE_MAX_HEADER_VALUE_BYTES", 4096)
	maxLastByteActiveJobs       = envLimit("RR_LAST_BYTE_MAX_ACTIVE_JOBS", 4)
	maxLastByteActiveRequests   = envLimit("RR_LAST_BYTE_MAX_ACTIVE_REQUESTS", 16)
)

var lastByteRetention = time.Duration(envLimit("RR_LAST_BYTE_RETENTION_SEC", 600)) * time.Second

const (
	lastByteProtocolHTTP       = "HTTP/1.1"
	lastByteALPNProtocol       = "http/1.1"
	lastByteDefaultHoldMS      = 50
	lastByteDefaultTimeoutMS   = 5000
	lastByteDefaultIterations  = 1
	lastByteDefaultConcurrency = 1
)

type lastByteInput struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Iterations  int               `json:"iterations"`
	Concurrency int               `json:"concurrency"`
	DelayMS     int               `json:"delay_ms"`
	HoldMS      int               `json:"hold_ms"`
	TimeoutMS   int               `json:"timeout_ms"`
}

type lastByteJob struct {
	mu          sync.RWMutex
	cancel      context.CancelFunc
	resumeCh    chan struct{}
	status      string
	input       lastByteInput
	results     []map[string]interface{}
	attempted   int
	completed   int
	failed      int
	resultBytes int
	startedAt   time.Time
	finishedAt  time.Time
}

func (s *server) lastByteStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input lastByteInput
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
	if err := validateLastByteInput(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_LAST_BYTE_INPUT", err)
		return
	}

	s.lastByteSlotsMu.Lock()
	if s.lastByteSlots == nil {
		s.lastByteSlots = make(chan struct{}, maxLastByteActiveRequests)
	}
	if s.lastByteJobSlots == nil {
		s.lastByteJobSlots = make(chan struct{}, maxLastByteActiveJobs)
	}
	slots := s.lastByteSlots
	jobSlots := s.lastByteJobSlots
	s.lastByteSlotsMu.Unlock()

	select {
	case jobSlots <- struct{}{}:
	default:
		writeError(w, http.StatusTooManyRequests, "LAST_BYTE_LIMIT_REACHED", fmt.Errorf("too many active last-byte jobs"))
		return
	}

	id := atomic.AddUint64(&s.lastByteSequence, 1)
	ctx, cancel := context.WithCancel(context.Background())
	job := &lastByteJob{
		cancel: cancel, resumeCh: make(chan struct{}), status: "running",
		input: input, startedAt: time.Now().UTC(),
	}
	s.lastByteJobsMu.Lock()
	if s.lastByteJobs == nil {
		s.lastByteJobs = make(map[uint64]*lastByteJob)
	}
	s.lastByteJobs[id] = job
	s.lastByteJobsMu.Unlock()

	writeJSON(w, http.StatusAccepted, lastByteSnapshot(id, job))
	go s.runLastByte(id, job, ctx, slots, jobSlots)
}

func (s *server) lastByteStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseLastByteID(r.URL.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_LAST_BYTE_ID", err)
		return
	}
	s.lastByteJobsMu.RLock()
	job, ok := s.lastByteJobs[id]
	s.lastByteJobsMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "LAST_BYTE_NOT_FOUND", fmt.Errorf("last-byte job %d not found", id))
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, lastByteSnapshot(id, job))
	case http.MethodDelete:
		job.mu.Lock()
		if !isLastByteTerminal(job.status) {
			job.status = "cancelling"
			job.cancel()
		}
		job.mu.Unlock()
		writeJSON(w, http.StatusAccepted, lastByteSnapshot(id, job))
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
			if !isLastByteTerminal(job.status) && job.status != "paused" {
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
			writeError(w, http.StatusBadRequest, "INVALID_LAST_BYTE_ACTION", fmt.Errorf("action must be pause or resume"))
			return
		}
		job.mu.Unlock()
		writeJSON(w, http.StatusOK, lastByteSnapshot(id, job))
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
	}
}

func (s *server) runLastByte(id uint64, job *lastByteJob, ctx context.Context, slots chan struct{}, jobSlots chan struct{}) {
	defer job.cancel()
	defer func() { <-jobSlots }()
	defer s.scheduleLastByteCleanup(id, job)
	defer func() {
		snapshot := lastByteSnapshot(id, job)
		log.Printf("[LAST-BYTE %d] %s requested=%d completed=%d failed=%d", id, snapshot["status"], snapshot["total"], snapshot["completed"], snapshot["failed"])
	}()

	for start := 0; start < job.input.Iterations; start += job.input.Concurrency {
		if !waitLastByteReady(job, ctx) {
			markLastByteCancelled(job)
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
					results <- map[string]interface{}{"iteration": iteration, "error": "last-byte job cancelled"}
					return
				}
				select {
				case slots <- struct{}{}:
					defer func() { <-slots }()
				case <-ctx.Done():
					results <- map[string]interface{}{"iteration": iteration, "error": "last-byte job cancelled"}
					return
				}
				results <- s.executeLastByteRequest(ctx, job.input, iteration)
			}(index)
		}
		wg.Wait()
		close(results)
		for result := range results {
			job.mu.Lock()
			resultSize := lastByteResultSize(result)
			if job.resultBytes+resultSize > maxLastByteAggregateBytes {
				delete(result, "body")
				delete(result, "body_base64")
				result["body_truncated"] = true
				result["aggregate_truncated"] = true
				resultSize = lastByteResultSize(result)
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
			if !waitLastByteDelay(ctx, time.Duration(job.input.DelayMS)*time.Millisecond) {
				markLastByteCancelled(job)
				return
			}
		}
	}

	job.mu.Lock()
	if ctx.Err() != nil {
		job.status = "cancelled"
	} else if job.completed == 0 && job.failed > 0 {
		job.status = "failed"
	} else {
		job.status = "completed"
	}
	job.finishedAt = time.Now().UTC()
	job.mu.Unlock()
}

func (s *server) executeLastByteRequest(ctx context.Context, input lastByteInput, iteration int) map[string]interface{} {
	result := map[string]interface{}{"iteration": iteration, "url": input.URL, "mode": "raw_last_byte"}
	eventID := s.addLastByteTraffic(requestInput{Method: input.Method, URL: input.URL, Headers: cloneStringMap(input.Headers), Body: input.Body}, "")
	requestContext, cancel := context.WithTimeout(ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
	defer cancel()

	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil {
		result["error"] = err.Error()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	wireRequest, err := buildLastByteRequest(input, parsed)
	if err != nil {
		result["error"] = err.Error()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	result["request_bytes"] = len(wireRequest)
	result["hold_ms"] = input.HoldMS
	result["tls"] = "not_used"
	if parsed.Scheme == "https" {
		result["tls"] = "verified"
	}

	address, err := lastByteAddress(parsed)
	if err != nil {
		result["error"] = err.Error()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	started := time.Now()
	var conn net.Conn
	if parsed.Scheme == "https" {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: time.Duration(input.TimeoutMS) * time.Millisecond},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: parsed.Hostname(),
				NextProtos: []string{lastByteALPNProtocol},
			},
		}
		conn, err = dialer.DialContext(requestContext, "tcp", address)
	} else {
		dialer := &net.Dialer{Timeout: time.Duration(input.TimeoutMS) * time.Millisecond}
		conn, err = dialer.DialContext(requestContext, "tcp", address)
	}
	if err != nil {
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	defer conn.Close()
	stopClose := make(chan struct{})
	go func() {
		select {
		case <-requestContext.Done():
			_ = conn.Close()
		case <-stopClose:
		}
	}()
	defer close(stopClose)
	_ = conn.SetDeadline(time.Now().Add(time.Duration(input.TimeoutMS) * time.Millisecond))

	if len(wireRequest) < 2 {
		err = fmt.Errorf("request must contain a body with a final byte")
		result["error"] = err.Error()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	if err = writeAll(conn, wireRequest[:len(wireRequest)-1]); err != nil {
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	if !waitLastByteHold(requestContext, time.Duration(input.HoldMS)*time.Millisecond) {
		err = requestContext.Err()
		if err == nil {
			err = context.Canceled
		}
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	if err = writeAll(conn, wireRequest[len(wireRequest)-1:]); err != nil {
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}

	rawResponse, readErr := io.ReadAll(io.LimitReader(conn, int64(maxLastByteResponseRaw)+1))
	if readErr != nil {
		result["error"] = readErr.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, readErr)
		return result
	}
	if len(rawResponse) > maxLastByteResponseRaw {
		err = fmt.Errorf("response exceeds %d bytes", maxLastByteResponseRaw)
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rawResponse)), &http.Request{Method: input.Method, URL: parsed})
	if err != nil {
		result["error"] = err.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, err)
		return result
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maxLastByteResponseBytes)+1))
	if readErr != nil {
		result["error"] = readErr.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, readErr)
		return result
	}
	truncated := len(body) > maxLastByteResponseBytes
	if truncated {
		body = body[:maxLastByteResponseBytes]
	}
	headers := make(map[string]string)
	headerBytes := 0
	headersTruncated := false
	for key, values := range response.Header {
		joined := strings.Join(values, ", ")
		if len(headers) >= maxLastByteHeaders || headerBytes+len(key)+len(joined) > maxLastByteHeaderBytes {
			headersTruncated = true
			break
		}
		headers[key] = joined
		headerBytes += len(key) + len(joined)
	}
	result["status"] = response.StatusCode
	result["status_text"] = response.Status
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
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		result["body_content_type"] = contentType
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		result["tls"] = "verified"
		result["tls_version"] = tlsVersionName(state.Version)
		result["tls_verified"] = len(state.VerifiedChains) > 0
	}
	s.completeLastByteTraffic(eventID, result, nil)
	return result
}

func validateLastByteInput(input *lastByteInput) error {
	input.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	if input.Method == "" {
		input.Method = http.MethodPost
	}
	if !validHTTPMethod(input.Method) {
		return fmt.Errorf("method must be a valid HTTP token")
	}
	input.URL = strings.TrimSpace(input.URL)
	if len(input.URL) == 0 || len(input.URL) > maxLastByteURLBytes {
		return fmt.Errorf("url is required and must be at most %d bytes", maxLastByteURLBytes)
	}
	if strings.ContainsAny(input.URL, "\r\n") || strings.IndexFunc(input.URL, func(value rune) bool { return value < 0x20 || value == 0x7f }) >= 0 {
		return fmt.Errorf("url contains control characters")
	}
	parsed, err := url.Parse(input.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("url must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("url must not contain userinfo or fragment")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("url host is required")
	}
	for _, value := range parsed.Host {
		if value > 0x7f || value < 0x20 || value == 0x7f {
			return fmt.Errorf("url host contains invalid characters")
		}
	}
	if port := parsed.Port(); port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return fmt.Errorf("url port is invalid")
		}
	}
	if input.Body == "" {
		return fmt.Errorf("last-byte requires a non-empty request body")
	}
	if len(input.Body) > maxLastByteBodyBytes {
		return fmt.Errorf("body must be at most %d bytes", maxLastByteBodyBytes)
	}
	if input.Iterations == 0 {
		input.Iterations = lastByteDefaultIterations
	}
	if input.Concurrency == 0 {
		input.Concurrency = lastByteDefaultConcurrency
	}
	if input.HoldMS == 0 {
		input.HoldMS = lastByteDefaultHoldMS
	}
	if input.TimeoutMS == 0 {
		input.TimeoutMS = lastByteDefaultTimeoutMS
	}
	if input.Iterations < 1 || input.Iterations > maxLastByteIterations {
		return fmt.Errorf("iterations must be between 1 and %d", maxLastByteIterations)
	}
	if input.Concurrency < 1 || input.Concurrency > maxLastByteConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d", maxLastByteConcurrency)
	}
	if input.DelayMS < 0 || input.DelayMS > maxLastByteDelayMS {
		return fmt.Errorf("delay_ms must be between 0 and %d", maxLastByteDelayMS)
	}
	if input.HoldMS < 0 || input.HoldMS > maxLastByteHoldMS {
		return fmt.Errorf("hold_ms must be between 0 and %d", maxLastByteHoldMS)
	}
	if input.TimeoutMS < 1 || input.TimeoutMS > maxLastByteTimeoutMS {
		return fmt.Errorf("timeout_ms must be between 1 and %d", maxLastByteTimeoutMS)
	}
	if len(input.Headers) > maxLastByteRequestHeaders {
		return fmt.Errorf("last-byte supports at most %d headers", maxLastByteRequestHeaders)
	}
	for key, value := range input.Headers {
		if !validLastByteHeaderName(key) || len(key) > maxLastByteHeaderNameBytes || len(value) > maxLastByteHeaderValueBytes || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("last-byte headers contain invalid characters or are too large")
		}
	}
	if len(buildLastByteRequestBytes(*input, parsed)) > maxLastByteRequestBytes {
		return fmt.Errorf("request exceeds %d bytes", maxLastByteRequestBytes)
	}
	return nil
}

func buildLastByteRequest(input lastByteInput, parsed *url.URL) ([]byte, error) {
	data := buildLastByteRequestBytes(input, parsed)
	if len(data) == 0 {
		return nil, fmt.Errorf("request is empty")
	}
	return data, nil
}

func isManagedLastByteHeader(key string) bool {
	switch strings.ToLower(key) {
	case "host", "content-length", "transfer-encoding", "connection", "expect", "upgrade":
		return true
	default:
		return false
	}
}

func buildLastByteRequestBytes(input lastByteInput, parsed *url.URL) []byte {
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	lines := []string{input.Method + " " + path + " " + lastByteProtocolHTTP, "Host: " + parsed.Host}
	keys := make([]string, 0, len(input.Headers))
	for key := range input.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if isManagedLastByteHeader(key) {
			continue
		}
		lines = append(lines, key+": "+input.Headers[key])
	}
	lines = append(lines, "Content-Length: "+strconv.Itoa(len(input.Body)), "Connection: close", "", input.Body)
	return []byte(strings.Join(lines, "\r\n"))
}

func lastByteAddress(parsed *url.URL) (string, error) {
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), nil
}

func validLastByteHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		value := name[index]
		if value <= 0x20 || value >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}\t", rune(value)) {
			return false
		}
	}
	return true
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func waitLastByteHold(ctx context.Context, hold time.Duration) bool {
	if hold <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(hold)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func waitLastByteReady(job *lastByteJob, ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		job.mu.RLock()
		status := job.status
		resume := job.resumeCh
		job.mu.RUnlock()
		if status == "cancelling" || isLastByteTerminal(status) {
			return false
		}
		if status != "paused" {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-resume:
		}
	}
}

func waitLastByteDelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func markLastByteCancelled(job *lastByteJob) {
	job.mu.Lock()
	job.status = "cancelled"
	job.finishedAt = time.Now().UTC()
	job.mu.Unlock()
}

func isLastByteTerminal(status string) bool {
	return status == "completed" || status == "cancelled" || status == "failed"
}

func parseLastByteID(path string) (uint64, error) {
	value := strings.TrimPrefix(path, "/proxy/last-byte/")
	if value == "" || strings.Contains(value, "/") {
		return 0, fmt.Errorf("invalid last-byte id")
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid last-byte id")
	}
	return id, nil
}

func (s *server) scheduleLastByteCleanup(id uint64, job *lastByteJob) {
	time.AfterFunc(lastByteRetention, func() {
		s.lastByteJobsMu.Lock()
		defer s.lastByteJobsMu.Unlock()
		if current, ok := s.lastByteJobs[id]; ok && current == job {
			delete(s.lastByteJobs, id)
		}
	})
}

func lastByteSnapshot(id uint64, job *lastByteJob) map[string]interface{} {
	job.mu.RLock()
	defer job.mu.RUnlock()
	results := append([]map[string]interface{}(nil), job.results...)
	sort.Slice(results, func(left, right int) bool {
		return intValue(results[left]["iteration"]) < intValue(results[right]["iteration"])
	})
	snapshot := map[string]interface{}{
		"last_byte_id": id, "status": job.status, "mode": "raw_last_byte",
		"total": job.input.Iterations, "total_sent": job.attempted, "count": len(results),
		"attempted": job.attempted, "completed": job.completed, "failed": job.failed,
		"hold_ms": job.input.HoldMS, "results": results,
		"started_at": job.startedAt, "finished_at": job.finishedAt,
	}
	if job.status == "failed" {
		snapshot["error"] = "all last-byte requests failed"
	}
	return snapshot
}

func lastByteResultSize(result map[string]interface{}) int {
	size := 0
	if body, ok := result["body"].(string); ok {
		size += len(body)
	}
	if body, ok := result["body_base64"].(string); ok {
		size += len(body)
	}
	return size
}

func (s *server) addLastByteTraffic(request requestInput, sourceIP string) uint64 {
	if s.store == nil {
		return 0
	}
	return s.store.Add(passive.Event{
		Source: "last_byte", Timestamp: time.Now().UTC(), Method: request.Method,
		URL: request.URL, Host: requestHost(request.URL), RequestHeader: request.Headers,
		RequestBody: request.Body, SourceIP: sourceIP,
	})
}

func (s *server) completeLastByteTraffic(eventID uint64, result map[string]interface{}, execErr error) {
	if s.store == nil || eventID == 0 {
		return
	}
	if execErr != nil {
		s.store.Update(eventID, func(event *passive.Event) { event.Error = execErr.Error() })
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
