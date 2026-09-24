package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lastByteFixture struct {
	listener  net.Listener
	observed  chan time.Duration
	waitGroup sync.WaitGroup
}

func newLastByteFixture(t *testing.T) *lastByteFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &lastByteFixture{listener: listener, observed: make(chan time.Duration, 32)}
	fixture.waitGroup.Add(1)
	go func() {
		defer fixture.waitGroup.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fixture.waitGroup.Add(1)
			go func() {
				defer fixture.waitGroup.Done()
				defer conn.Close()
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				started := time.Now()
				body, err := io.ReadAll(request.Body)
				if err != nil || len(body) == 0 {
					return
				}
				_ = request.Body.Close()
				fixture.observed <- time.Since(started)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nok")
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		fixture.waitGroup.Wait()
	})
	return fixture
}

func TestLastByteSyncSendsFinalBodyByteAfterHold(t *testing.T) {
	fixture := newLastByteFixture(t)
	s := &server{lastByteJobs: make(map[uint64]*lastByteJob), lastByteSlots: make(chan struct{}, 16)}
	body := `{"method":"POST","url":"http://` + fixture.listener.Addr().String() + `/sync","body":"canary","iterations":2,"concurrency":1,"hold_ms":40,"timeout_ms":2000}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/last-byte", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	s.lastByteStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("last-byte start = %d %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	final := waitLastByte(t, s, uint64(started["last_byte_id"].(float64)), "completed")
	if int(final["completed"].(float64)) != 2 || int(final["failed"].(float64)) != 0 {
		t.Fatalf("last-byte result = %#v", final)
	}
	results := final["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("results = %#v", results)
	}
	for index := range results {
		result := results[index].(map[string]interface{})
		if int(result["status"].(float64)) != http.StatusOK || result["body"] != "ok" {
			t.Fatalf("result %d = %#v", index, result)
		}
		if int(result["hold_ms"].(float64)) != 40 {
			t.Fatalf("hold evidence = %#v", result)
		}
	}
	for index := 0; index < 2; index++ {
		select {
		case observed := <-fixture.observed:
			if observed < 30*time.Millisecond {
				t.Fatalf("fixture observed hold = %s, want at least 30ms", observed)
			}
		case <-time.After(time.Second):
			t.Fatal("fixture did not observe both requests")
		}
	}
}

func TestLastByteSyncAcceptsExternalAndPrivateTargetsWithoutPolicyGate(t *testing.T) {
	for _, target := range []string{"https://example.com/", "http://10.0.0.1/"} {
		input := &lastByteInput{Method: "DELETE", URL: target, Body: "canary", Iterations: 1, Concurrency: 1, HoldMS: 10, TimeoutMS: 1000}
		if err := validateLastByteInput(input); err != nil {
			t.Fatalf("target %s was rejected: %v", target, err)
		}
	}
}

func TestLastByteSyncKeepsTLSVerification(t *testing.T) {
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer provider.Close()
	s := &server{lastByteJobs: make(map[uint64]*lastByteJob), lastByteSlots: make(chan struct{}, 16)}
	request := httptest.NewRequest(http.MethodPost, "/proxy/last-byte", strings.NewReader(`{"method":"POST","url":"`+provider.URL+`/sync","body":"canary","iterations":1,"concurrency":1,"hold_ms":10,"timeout_ms":1000}`))
	recorder := httptest.NewRecorder()
	s.lastByteStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("TLS start = %d %s", recorder.Code, recorder.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	final := waitLastByte(t, s, uint64(started["last_byte_id"].(float64)), "failed")
	if int(final["failed"].(float64)) != 1 || int(final["completed"].(float64)) != 0 {
		t.Fatalf("untrusted TLS result = %#v", final)
	}
	result := final["results"].([]interface{})[0].(map[string]interface{})
	if !strings.Contains(strings.ToLower(stringValue(result["error"])), "certificate") {
		t.Fatalf("TLS error = %#v", result)
	}
}

func TestLastByteSyncCancelsInFlightConnection(t *testing.T) {
	fixture := newLastByteFixture(t)
	s := &server{lastByteJobs: make(map[uint64]*lastByteJob), lastByteSlots: make(chan struct{}, 16)}
	body := `{"method":"POST","url":"http://` + fixture.listener.Addr().String() + `/sync","body":"canary","iterations":8,"concurrency":1,"hold_ms":1000,"timeout_ms":3000}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/last-byte", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	s.lastByteStart(recorder, request)
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	id := uint64(started["last_byte_id"].(float64))
	time.Sleep(30 * time.Millisecond)
	cancel := httptest.NewRecorder()
	s.lastByteStatus(cancel, httptest.NewRequest(http.MethodDelete, "/proxy/last-byte/"+strconv.FormatUint(id, 10), nil))
	if cancel.Code != http.StatusAccepted {
		t.Fatalf("cancel = %d %s", cancel.Code, cancel.Body.String())
	}
	final := waitLastByte(t, s, id, "cancelled")
	if int(final["completed"].(float64)) > 1 {
		t.Fatalf("cancelled job completed too much work: %#v", final)
	}
}

func TestLastByteSyncRejectsInvalidProtocolInput(t *testing.T) {
	s := &server{lastByteJobs: make(map[uint64]*lastByteJob), lastByteSlots: make(chan struct{}, 16)}
	cases := []string{
		`{"method":"POST","url":"http://127.0.0.1/","body":"","iterations":1,"concurrency":1,"timeout_ms":1000}`,
		`{"method":"POST","url":"http://127.0.0.1/","body":"canary","iterations":21,"concurrency":1,"timeout_ms":1000}`,
		`{"method":"POST","url":"http://127.0.0.1/","body":"canary","iterations":1,"concurrency":5,"timeout_ms":1000}`,
		`{"method":"POST","url":"http://127.0.0.1/","body":"canary","iterations":1,"concurrency":1,"timeout_ms":1000,"headers":{"X-Test":"bad\r\nvalue"}}`,
	}
	for _, body := range cases {
		request := httptest.NewRequest(http.MethodPost, "/proxy/last-byte", strings.NewReader(body))
		recorder := httptest.NewRecorder()
		s.lastByteStart(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid last-byte input = %d %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestLastByteSyncAcceptsArbitraryMethod(t *testing.T) {
	input := &lastByteInput{Method: "DELETE", URL: "http://127.0.0.1/", Body: "canary", Iterations: 1, Concurrency: 1, HoldMS: 1, TimeoutMS: 1000}
	if err := validateLastByteInput(input); err != nil {
		t.Fatalf("arbitrary method rejected: %v", err)
	}
}

func TestLastByteSyncBoundsConcurrency(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer conn.Close()
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				_, _ = io.ReadAll(request.Body)
				_ = request.Body.Close()
				current := active.Add(1)
				for {
					old := maximum.Load()
					if current <= old || maximum.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(30 * time.Millisecond)
				active.Add(-1)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}()
		}
	}()
	s := &server{lastByteJobs: make(map[uint64]*lastByteJob), lastByteSlots: make(chan struct{}, 16)}
	body := fmt.Sprintf(`{"method":"POST","url":"http://%s/sync","body":"canary","iterations":6,"concurrency":2,"hold_ms":1,"timeout_ms":2000}`, listener.Addr().String())
	request := httptest.NewRequest(http.MethodPost, "/proxy/last-byte", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	s.lastByteStart(recorder, request)
	var started map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	final := waitLastByte(t, s, uint64(started["last_byte_id"].(float64)), "completed")
	if int(final["completed"].(float64)) != 6 || maximum.Load() > 2 {
		t.Fatalf("bounded last-byte result = %#v max=%d", final, maximum.Load())
	}
	_ = listener.Close()
	waitGroup.Wait()
}

func waitLastByte(t *testing.T, s *server, id uint64, status string) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job := s.lastByteJobs[id]
		if job != nil {
			recorder := httptest.NewRecorder()
			s.lastByteStatus(recorder, httptest.NewRequest(http.MethodGet, "/proxy/last-byte/"+strconv.FormatUint(id, 10), nil))
			var snapshot map[string]interface{}
			_ = json.Unmarshal(recorder.Body.Bytes(), &snapshot)
			if snapshot["status"] == status {
				return snapshot
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("last-byte job did not reach %s", status)
	return nil
}
