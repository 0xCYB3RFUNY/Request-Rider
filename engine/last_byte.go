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

const (
	lastByteProtocolHTTP = "HTTP/1.1"
	lastByteALPNProtocol = "http/1.1"
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
	mu         sync.RWMutex
	cancel     context.CancelFunc
	resumeCh   chan struct{}
	status     string
	input      lastByteInput
	results    []map[string]interface{}
	attempted  int
	completed  int
	failed     int
	startedAt  time.Time
	finishedAt time.Time
}

func (s *server) lastByteStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input lastByteInput
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
	if err := validateLastByteInput(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_LAST_BYTE_INPUT", err)
		return
	}

	id := atomic.AddUint64(&s.lastByteSequence, 1)
	_, routeContext, releaseRoute := s.bindRouteContext(context.WithoutCancel(r.Context()))
	ctx, cancel := context.WithCancel(routeContext)
	job := &lastByteJob{
		cancel: func() { cancel(); releaseRoute() }, resumeCh: make(chan struct{}), status: "running",
		input: input, startedAt: time.Now().UTC(),
	}
	s.lastByteJobsMu.Lock()
	if s.lastByteJobs == nil {
		s.lastByteJobs = make(map[uint64]*lastByteJob)
	}
	s.lastByteJobs[id] = job
	s.lastByteJobsMu.Unlock()

	writeJSON(w, http.StatusAccepted, lastByteSnapshot(id, job))
	go s.runLastByte(id, job, ctx)
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
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
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

func (s *server) runLastByte(id uint64, job *lastByteJob, ctx context.Context) {
	defer job.cancel()
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
				results <- s.executeLastByteRequest(ctx, job.input, iteration)
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
	requestContext := ctx
	cancel := func() {}
	if input.TimeoutMS > 0 {
		requestContext, cancel = context.WithTimeout(ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
	}
	defer cancel()
	lookup := s.startSourceIPLookup(ctx)
	result := map[string]interface{}{"iteration": iteration, "url": input.URL, "mode": "raw_last_byte", "source_ip": ""}
	eventID := s.addLastByteTraffic(requestInput{Method: input.Method, URL: input.URL, Headers: cloneStringMap(input.Headers), Body: input.Body}, "")
	result["traffic_event_id"] = eventID
	defer func() {
		if ip, ready := sourceIPIfReady(lookup); ready {
			result["source_ip"] = ip
			s.setTrafficSourceIP(eventID, ip)
		} else {
			result["source_ip_pending"] = true
			s.updateTrafficSourceIP(eventID, lookup)
		}
	}()

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
	if lease, ok := routeLeaseFromContext(requestContext); ok {
		conn, err = lease.dialContext(requestContext, "tcp", address)
	} else {
		dialer := &net.Dialer{}
		if input.TimeoutMS > 0 {
			dialer.Timeout = time.Duration(input.TimeoutMS) * time.Millisecond
		}
		conn, err = dialer.DialContext(requestContext, "tcp", address)
	}
	if err == nil && parsed.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: parsed.Hostname(),
			NextProtos: []string{lastByteALPNProtocol},
		})
		if err = tlsConn.HandshakeContext(requestContext); err != nil {
			_ = tlsConn.Close()
			conn = nil
		} else {
			conn = tlsConn
		}
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
	if input.TimeoutMS > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(input.TimeoutMS) * time.Millisecond))
	}

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

	rawResponse, readErr := io.ReadAll(conn)
	if readErr != nil {
		result["error"] = readErr.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, readErr)
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
	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		result["error"] = readErr.Error()
		result["time"] = time.Since(started).Milliseconds()
		s.completeLastByteTraffic(eventID, result, readErr)
		return result
	}
	headers := make(map[string]string)
	for key, values := range response.Header {
		headers[key] = strings.Join(values, ", ")
	}
	result["status"] = response.StatusCode
	result["status_text"] = response.Status
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

func (s *server) SendH2SinglePacket(conn net.Conn, frames ...[]byte) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}
	if len(frames) == 0 {
		return nil
	}
	// Go cannot control raw TCP segmentation at the socket layer, so the strongest
	// correct equivalent is to emit the entire HTTP/2 burst in a single user-space
	// write while clearing END_STREAM from each frame header. This preserves frame
	// ordering and avoids claiming deterministic one-packet delivery on the wire.
	var payload []byte
	for _, frame := range frames {
		if len(frame) == 0 {
			continue
		}
		if len(frame) < 9 {
			return fmt.Errorf("http2 frame must be at least 9 bytes")
		}
		frameCopy := append([]byte(nil), frame...)
		frameCopy[4] &^= 0x01
		payload = append(payload, frameCopy...)
	}
	if len(payload) == 0 {
		return nil
	}
	written, err := conn.Write(payload)
	if err != nil {
		return err
	}
	if written < len(payload) {
		return writeAll(conn, payload[written:])
	}
	return nil
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
	if len(input.URL) == 0 {
		return fmt.Errorf("url is required")
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

	if input.Iterations == 0 {
		input.Iterations = 1
	}
	if input.Concurrency == 0 {
		input.Concurrency = 1
	}
	if input.Iterations < 1 {
		return fmt.Errorf("iterations must be positive")
	}
	if input.Concurrency < 1 {
		return fmt.Errorf("concurrency must be positive")
	}
	if input.DelayMS < 0 {
		return fmt.Errorf("delay_ms must not be negative")
	}
	if input.HoldMS < 0 {
		return fmt.Errorf("hold_ms must not be negative")
	}
	if input.TimeoutMS < 0 {
		return fmt.Errorf("timeout_ms must not be negative")
	}
	for key, value := range input.Headers {
		if !validLastByteHeaderName(key) || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("last-byte headers contain invalid characters")
		}
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
