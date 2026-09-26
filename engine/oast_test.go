package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOASTStartAndPollLocalProvider(t *testing.T) {
	var polls atomic.Int32
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"listener_id": "fixture-listener",
				"domain":      "fixture-listener.fixture.local",
				"base_url":    provider.URL,
				"payload_url": provider.URL + "/hit/fixture-listener",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/poll":
			if polls.Add(1) == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": []map[string]interface{}{{"event_id": "evt-1", "protocol": "http"}, {"event_id": "evt-1", "protocol": "http"}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": []map[string]interface{}{}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/listener/"):
			_, _ = w.Write([]byte(`{"deleted":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	s := &server{oastListeners: make(map[uint64]*oastListener)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/oast", strings.NewReader(`{"server_url":"`+provider.URL+`","poll_interval_sec":1,"timeout_sec":2,"capture_protocols":["http"]}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.oastStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("oast start status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	listenerID := int(started["listener_id"].(float64))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.oastListenersMu.RLock()
		job := s.oastListeners[uint64(listenerID)]
		s.oastListenersMu.RUnlock()
		if job != nil {
			job.mu.RLock()
			triggered := len(job.events) > 0
			job.mu.RUnlock()
			if triggered {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	snapshotRecorder := httptest.NewRecorder()
	s.oastStatus(snapshotRecorder, httptest.NewRequest(http.MethodGet, "/proxy/oast/"+strconv.Itoa(listenerID), nil))
	if snapshotRecorder.Code != http.StatusOK {
		t.Fatalf("oast status = %d, body = %s", snapshotRecorder.Code, snapshotRecorder.Body.String())
	}
	var snapshot map[string]interface{}
	if err := json.Unmarshal(snapshotRecorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot["triggered"] != true || int(snapshot["events_count"].(float64)) != 1 {
		t.Fatalf("snapshot = %#v, want one triggered event", snapshot)
	}
}

func TestOASTProviderURLAllowsExternalProviders(t *testing.T) {
	if _, err := validateOASTProviderURL("https://oast.example"); err != nil {
		t.Fatalf("external provider was rejected: %v", err)
	}
}

func TestOASTProtocolsAreHTTPOnlyInLocalSlice(t *testing.T) {
	if protocols, err := normalizeOASTProtocols(nil); err != nil || len(protocols) != 1 || protocols[0] != "http" {
		t.Fatalf("default protocols = %#v, error = %v", protocols, err)
	}
	if _, err := normalizeOASTProtocols([]string{"dns"}); err == nil {
		t.Fatal("unsupported DNS protocol was accepted")
	}
}

func TestOASTAcceptsForeignCallbackOrigin(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			_ = json.NewEncoder(w).Encode(map[string]string{"payload_url": "http://foreign.example/hit/id"})
			return
		}
		http.NotFound(w, r)
	}))
	defer provider.Close()
	s := &server{oastListeners: make(map[uint64]*oastListener)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/oast", strings.NewReader(`{"server_url":"`+provider.URL+`","capture_protocols":["http"]}`))
	recorder := httptest.NewRecorder()
	s.oastStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("foreign callback response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestOASTTimeoutCompletesWithoutCallback(t *testing.T) {
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			_ = json.NewEncoder(w).Encode(map[string]string{"payload_url": provider.URL + "/hit/id"})
		case r.Method == http.MethodGet && r.URL.Path == "/poll":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}})
		case r.Method == http.MethodDelete:
			_, _ = w.Write([]byte(`{"deleted":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	s := &server{oastListeners: make(map[uint64]*oastListener)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/oast", strings.NewReader(`{"server_url":"`+provider.URL+`","poll_interval_sec":1,"timeout_sec":1,"capture_protocols":["http"]}`))
	recorder := httptest.NewRecorder()
	s.oastStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("start = %d %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &started)
	listenerID := uint64(started["listener_id"].(float64))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job := s.oastListeners[listenerID]
		if job != nil {
			job.mu.RLock()
			status := job.status
			timedOut := job.timedOut
			job.mu.RUnlock()
			if status == "completed" {
				if !timedOut {
					t.Fatal("timeout completed without timed_out marker")
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("OAST timeout did not complete")
}
