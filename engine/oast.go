package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	maxOASTEvents       = envLimit("RR_OAST_MAX_EVENTS", 100)
	maxOASTEventRunes   = envLimit("RR_OAST_MAX_EVENT_RUNES", 2048)
	maxOASTProviderBody = envLimit("RR_OAST_MAX_PROVIDER_BODY_BYTES", 1<<20)
	maxOASTPollInterval = envLimit("RR_OAST_MAX_POLL_INTERVAL_SEC", 60)
	maxOASTTimeoutSec   = envLimit("RR_OAST_MAX_TIMEOUT_SEC", 300)
	maxOASTListenerID   = envLimit("RR_OAST_MAX_LISTENER_ID_BYTES", 120)
)

type oastStartInput struct {
	ServerURL        string   `json:"server_url"`
	ListenerID       string   `json:"listener_id"`
	PollIntervalSec  int      `json:"poll_interval_sec"`
	TimeoutSec       int      `json:"timeout_sec"`
	CaptureProtocols []string `json:"capture_protocols"`
}

type oastListener struct {
	mu           sync.RWMutex
	cleanupOnce  sync.Once
	cancel       context.CancelFunc
	status       string
	providerID   string
	providerURL  string
	payloadURL   string
	domain       string
	protocols    []string
	events       []map[string]interface{}
	lastError    string
	pollFailures int
	timedOut     bool
	startedAt    time.Time
	finishedAt   time.Time
}

func (s *server) oastStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input oastStartInput
	if err := json.NewDecoder(io.LimitReader(r.Body, int64(maxOASTProviderBody))).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	providerURL := strings.TrimRight(strings.TrimSpace(input.ServerURL), "/")
	if _, err := validateOASTProviderURL(providerURL); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OAST_SERVER", err)
		return
	}
	pollInterval := input.PollIntervalSec
	if pollInterval <= 0 {
		pollInterval = 3
	}
	if pollInterval > maxOASTPollInterval {
		writeError(w, http.StatusBadRequest, "INVALID_POLL_INTERVAL", fmt.Errorf("poll_interval_sec must be between 1 and %d", maxOASTPollInterval))
		return
	}
	timeout := input.TimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > maxOASTTimeoutSec {
		writeError(w, http.StatusBadRequest, "INVALID_TIMEOUT", fmt.Errorf("timeout_sec must be between 1 and %d", maxOASTTimeoutSec))
		return
	}
	protocols, err := normalizeOASTProtocols(input.CaptureProtocols)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OAST_PROTOCOL", err)
		return
	}
	listenerID := atomic.AddUint64(&s.oastSequence, 1)
	providerID := strings.TrimSpace(input.ListenerID)
	if providerID == "" {
		providerID = fmt.Sprintf("rr-%d", listenerID)
	} else if len(providerID) > maxOASTListenerID || strings.ContainsAny(providerID, "/?#\r\n") {
		writeError(w, http.StatusBadRequest, "INVALID_LISTENER_ID", fmt.Errorf("listener_id contains unsupported characters"))
		return
	}
	payloadURL, domain, err := s.registerOAST(r.Context(), providerURL, providerID, protocols)
	if err != nil {
		writeError(w, http.StatusBadGateway, "OAST_REGISTER_FAILED", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &oastListener{
		cancel: cancel, status: "listening", providerID: providerID,
		providerURL: providerURL, payloadURL: payloadURL, domain: domain,
		protocols: protocols, startedAt: time.Now().UTC(),
	}
	s.oastListenersMu.Lock()
	s.oastListeners[listenerID] = job
	s.oastListenersMu.Unlock()
	writeJSON(w, http.StatusAccepted, oastSnapshot(listenerID, job))
	go s.runOASTListener(job, ctx, time.Duration(pollInterval)*time.Second, time.Duration(timeout)*time.Second)
}

func (s *server) oastStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/proxy/oast/"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OAST_ID", err)
		return
	}
	s.oastListenersMu.RLock()
	job, ok := s.oastListeners[id]
	s.oastListenersMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "OAST_LISTENER_NOT_FOUND", fmt.Errorf("OAST listener %d not found", id))
		return
	}
	if r.Method == http.MethodDelete {
		job.mu.Lock()
		terminal := isOASTTerminal(job.status)
		if !terminal {
			job.status = "cancelling"
			job.cancel()
		}
		job.mu.Unlock()
		job.cleanup(s)
		writeJSON(w, http.StatusAccepted, oastSnapshot(id, job))
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, oastSnapshot(id, job))
}

func (s *server) runOASTListener(job *oastListener, ctx context.Context, interval, timeout time.Duration) {
	defer job.cancel()
	defer job.cleanup(s)
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	poll := func() bool {
		events, err := s.pollOAST(ctx, job)
		job.mu.Lock()
		defer job.mu.Unlock()
		if err != nil {
			job.pollFailures++
			job.lastError = err.Error()
			if job.pollFailures >= 3 {
				job.status = "failed"
				job.finishedAt = time.Now().UTC()
				return true
			}
			return false
		}
		job.pollFailures = 0
		job.lastError = ""
		seen := make(map[string]bool, len(job.events))
		for _, event := range job.events {
			if eventID, ok := event["event_id"].(string); ok {
				seen[eventID] = true
			}
		}
		added := false
		for _, event := range events {
			eventID, _ := event["event_id"].(string)
			if eventID == "" || seen[eventID] {
				continue
			}
			seen[eventID] = true
			if len(job.events) < maxOASTEvents {
				job.events = append(job.events, sanitizeOASTEvent(event))
				added = true
			}
		}
		if added {
			job.status = "completed"
			job.finishedAt = time.Now().UTC()
			return true
		}
		return false
	}

	if poll() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			job.mu.Lock()
			if !isOASTTerminal(job.status) {
				job.status = "cancelled"
				job.finishedAt = time.Now().UTC()
			}
			job.mu.Unlock()
			return
		case <-ticker.C:
			if poll() {
				return
			}
			if time.Now().After(deadline) {
				job.mu.Lock()
				if !isOASTTerminal(job.status) {
					job.status = "completed"
					job.timedOut = true
					job.finishedAt = time.Now().UTC()
				}
				job.mu.Unlock()
				return
			}
		}
	}
}

func (s *server) registerOAST(ctx context.Context, baseURL, listenerID string, protocols []string) (string, string, error) {
	payload := map[string]interface{}{"listener_id": listenerID, "protocols": protocols}
	var response map[string]interface{}
	if err := s.oastJSON(ctx, http.MethodPost, baseURL+"/register", payload, os.Getenv("OAST_AUTH_TOKEN"), &response); err != nil {
		return "", "", err
	}
	payloadURL, _ := response["payload_url"].(string)
	domain, _ := response["domain"].(string)
	if payloadURL == "" {
		return "", "", fmt.Errorf("OAST provider did not return payload_url")
	}
	callback, err := url.Parse(payloadURL)
	if err != nil || callback.Scheme == "" || callback.Host == "" {
		return "", "", fmt.Errorf("OAST provider returned an invalid payload_url")
	}
	return payloadURL, domain, nil
}

func (s *server) pollOAST(ctx context.Context, job *oastListener) ([]map[string]interface{}, error) {
	endpoint := job.providerURL + "/poll?listener_id=" + url.QueryEscape(job.providerID)
	var response struct {
		Events []map[string]interface{} `json:"events"`
	}
	if err := s.oastJSON(ctx, http.MethodGet, endpoint, nil, os.Getenv("OAST_AUTH_TOKEN"), &response); err != nil {
		return nil, err
	}
	filtered := make([]map[string]interface{}, 0, len(response.Events))
	for _, event := range response.Events {
		if protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(event["protocol"]))); protocol == "" || protocol == "http" {
			filtered = append(filtered, event)
		}
	}
	return filtered, nil
}

func (s *server) deleteOAST(job *oastListener) error {
	endpoint := job.providerURL + "/listener/" + url.PathEscape(job.providerID)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.oastJSON(ctx, http.MethodDelete, endpoint, nil, os.Getenv("OAST_AUTH_TOKEN"), &struct{}{})
}

func (s *server) oastJSON(ctx context.Context, method, endpoint string, payload interface{}, token string, output interface{}) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(token) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: s.requestTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(maxOASTProviderBody)))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("OAST provider returned HTTP %d", response.StatusCode)
	}
	if output == nil {
		return nil
	}
	return json.Unmarshal(data, output)
}

func oastSnapshot(id uint64, job *oastListener) map[string]interface{} {
	job.mu.RLock()
	defer job.mu.RUnlock()
	return map[string]interface{}{
		"listener_id": id, "status": job.status, "provider_listener_id": job.providerID,
		"payload_url": job.payloadURL, "full_http_url": job.payloadURL, "domain": job.domain,
		"protocols": append([]string{}, job.protocols...), "triggered": len(job.events) > 0,
		"events": append([]map[string]interface{}{}, job.events...), "events_count": len(job.events),
		"error": job.lastError, "timed_out": job.timedOut, "started_at": job.startedAt, "finished_at": job.finishedAt,
	}
}

func (job *oastListener) cleanup(s *server) {
	job.cleanupOnce.Do(func() { _ = s.deleteOAST(job) })
}

func isOASTTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}

func normalizeOASTProtocols(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{"http"}, nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		protocol := strings.ToLower(strings.TrimSpace(value))
		if protocol != "http" {
			return nil, fmt.Errorf("only the local http protocol is supported in this slice")
		}
		result = append(result, protocol)
	}
	return result, nil
}

func sanitizeOASTEvent(event map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(event))
	for key, value := range event {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") {
			result[key] = "[redacted]"
			continue
		}
		result[key] = sanitizeOASTValue(value)
	}
	return result
}

func sanitizeOASTValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case string:
		runes := []rune(typed)
		if len(runes) > maxOASTEventRunes {
			return string(runes[:maxOASTEventRunes]) + "…"
		}
		return typed
	case []interface{}:
		result := make([]interface{}, 0, minInt(len(typed), 50))
		for _, item := range typed[:minInt(len(typed), 50)] {
			result = append(result, sanitizeOASTValue(item))
		}
		return result
	case map[string]interface{}:
		return sanitizeOASTEvent(typed)
	default:
		return value
	}
}

func validateOASTProviderURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("server_url must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("server_url must not contain userinfo, query, or fragment")
	}
	return parsed, nil
}
