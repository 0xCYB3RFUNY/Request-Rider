package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRepeaterBurstRunsBoundedParallelRequests(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	var received atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		received.Add(1)
		time.Sleep(15 * time.Millisecond)
		active.Add(-1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer provider.Close()

	s := &server{bursts: make(map[uint64]*repeaterBurst), burstSlots: make(chan struct{}, 16)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(`{"method":"GET","url":"`+provider.URL+`","iterations":4,"concurrency":2,"delay_ms":0,"timeout_ms":1000}`))
	recorder := httptest.NewRecorder()
	s.repeaterBurstStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("burst start = %d %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	burstID := uint64(started["burst_id"].(float64))
	final := waitRepeaterBurst(t, s, burstID, "completed")
	if received.Load() != 4 || int(final["completed"].(float64)) != 4 {
		t.Fatalf("burst result = received=%d snapshot=%#v", received.Load(), final)
	}
	if maximum.Load() > 2 {
		t.Fatalf("max active = %d, want bounded concurrency 2", maximum.Load())
	}
}

func TestRepeaterBurstSupportsPauseResume(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		_, _ = w.Write([]byte("ok"))
	}))
	defer provider.Close()

	s := &server{bursts: make(map[uint64]*repeaterBurst), burstSlots: make(chan struct{}, 16)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(`{"method":"GET","url":"`+provider.URL+`","iterations":1,"concurrency":1,"timeout_ms":2000}`))
	recorder := httptest.NewRecorder()
	s.repeaterBurstStart(recorder, request)
	var snapshot map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	id := uint64(snapshot["burst_id"].(float64))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("burst request did not start")
	}
	pause := httptest.NewRecorder()
	s.repeaterBurstStatus(pause, httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst/"+strconv.FormatUint(id, 10), strings.NewReader(`{"action":"pause"}`)))
	if pause.Code != http.StatusOK || !strings.Contains(pause.Body.String(), `"status":"paused"`) {
		t.Fatalf("burst pause = %d %s", pause.Code, pause.Body.String())
	}
	resume := httptest.NewRecorder()
	s.repeaterBurstStatus(resume, httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst/"+strconv.FormatUint(id, 10), strings.NewReader(`{"action":"resume"}`)))
	if resume.Code != http.StatusOK {
		t.Fatalf("burst resume = %d %s", resume.Code, resume.Body.String())
	}
	close(release)
	final := waitRepeaterBurst(t, s, id, "completed")
	if int(final["completed"].(float64)) != 1 {
		t.Fatalf("paused burst result = %#v", final)
	}
}

func TestRepeaterBurstCancelsInFlightWork(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("late"))
	}))
	defer provider.Close()

	s := &server{bursts: make(map[uint64]*repeaterBurst), burstSlots: make(chan struct{}, 16)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(`{"method":"GET","url":"`+provider.URL+`","iterations":8,"concurrency":2,"timeout_ms":1000}`))
	recorder := httptest.NewRecorder()
	s.repeaterBurstStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("burst start = %d %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	id := uint64(started["burst_id"].(float64))
	cancelRecorder := httptest.NewRecorder()
	s.repeaterBurstStatus(cancelRecorder, httptest.NewRequest(http.MethodDelete, "/proxy/repeater-burst/"+strconv.FormatUint(id, 10), nil))
	if cancelRecorder.Code != http.StatusAccepted {
		t.Fatalf("burst cancel = %d %s", cancelRecorder.Code, cancelRecorder.Body.String())
	}
	final := waitRepeaterBurst(t, s, id, "cancelled")
	if int(final["completed"].(float64)) > 0 {
		t.Fatalf("cancelled burst completed requests: %#v", final)
	}
}

func TestRepeaterBurstCapsResponseAndAggregateEvidence(t *testing.T) {
	payload := strings.Repeat("x", maxBurstResponseBytes+32)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer provider.Close()

	s := &server{bursts: make(map[uint64]*repeaterBurst), burstSlots: make(chan struct{}, 16)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(`{"method":"GET","url":"`+provider.URL+`","iterations":1,"concurrency":1,"timeout_ms":2000}`))
	recorder := httptest.NewRecorder()
	s.repeaterBurstStart(recorder, request)
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	final := waitRepeaterBurst(t, s, uint64(started["burst_id"].(float64)), "completed")
	result := final["results"].([]interface{})[0].(map[string]interface{})
	if result["body_truncated"] != true || len(result["body"].(string)) != maxBurstResponseBytes {
		t.Fatalf("response cap result = %#v", result)
	}
}

func TestRepeaterBurstKeepsTLSVerification(t *testing.T) {
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer provider.Close()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	s := &server{
		bursts:     make(map[uint64]*repeaterBurst),
		burstSlots: make(chan struct{}, 16),
		transport:  transport,
	}
	request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(`{"method":"GET","url":"`+provider.URL+`","iterations":1,"concurrency":1,"timeout_ms":1000}`))
	recorder := httptest.NewRecorder()
	s.repeaterBurstStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("burst start = %d %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	final := waitRepeaterBurst(t, s, uint64(started["burst_id"].(float64)), "completed")
	if int(final["failed"].(float64)) != 1 || int(final["completed"].(float64)) != 0 {
		t.Fatalf("untrusted TLS result = %#v", final)
	}
}

func TestRepeaterBurstRejectsWhenGlobalJobBudgetIsFull(t *testing.T) {
	jobSlots := make(chan struct{}, 1)
	jobSlots <- struct{}{}
	s := &server{bursts: make(map[uint64]*repeaterBurst), burstSlots: make(chan struct{}, 16), burstJobSlots: jobSlots}
	request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(`{"method":"GET","url":"http://127.0.0.1/","iterations":1,"concurrency":1,"timeout_ms":1000}`))
	recorder := httptest.NewRecorder()
	s.repeaterBurstStart(recorder, request)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("burst budget response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestRepeaterBurstRejectsInvalidProtocolInput(t *testing.T) {
	s := &server{bursts: make(map[uint64]*repeaterBurst), burstSlots: make(chan struct{}, 16)}
	cases := []string{
		`{"method":"GET","url":"http://127.0.0.1/","iterations":21,"concurrency":1,"timeout_ms":1000}`,
		`{"method":"GET","url":"http://127.0.0.1/","iterations":1,"concurrency":5,"timeout_ms":1000}`,
		`{"method":"GET","url":"http://127.0.0.1/\r\nX-Test: yes","iterations":1,"concurrency":1,"timeout_ms":1000}`,
		`{"method":"GET","url":"http://127.0.0.1/","iterations":1,"concurrency":1,"timeout_ms":1000,"headers":{"X-Test":"bad\r\nvalue"}}`,
	}
	for _, body := range cases {
		request := httptest.NewRequest(http.MethodPost, "/proxy/repeater-burst", strings.NewReader(body))
		recorder := httptest.NewRecorder()
		s.repeaterBurstStart(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid burst input = %d %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestRepeaterBurstAcceptsArbitraryMethodAndBody(t *testing.T) {
	input := &repeaterBurstInput{Method: "DELETE", URL: "http://127.0.0.1/", Body: "state=1", Iterations: 1, Concurrency: 1, TimeoutMS: 1000}
	if err := validateBurstInput(input); err != nil {
		t.Fatalf("arbitrary method/body rejected: %v", err)
	}
}

func waitRepeaterBurst(t *testing.T, s *server, id uint64, status string) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job := s.bursts[id]
		if job != nil {
			recorder := httptest.NewRecorder()
			s.repeaterBurstStatus(recorder, httptest.NewRequest(http.MethodGet, "/proxy/repeater-burst/"+strconv.FormatUint(id, 10), nil))
			var snapshot map[string]interface{}
			_ = json.Unmarshal(recorder.Body.Bytes(), &snapshot)
			if snapshot["status"] == status {
				return snapshot
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("burst did not reach %s", status)
	return nil
}
