package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"intruder/engine/pkg/passive"
)

func TestCancelAllJobsStopsActiveToolsAndClosesConnections(t *testing.T) {
	store := passive.NewStore()
	routes, err := newRouteManager()
	if err != nil {
		t.Fatalf("newRouteManager: %v", err)
	}
	srv := &server{
		attacks:       map[uint64]*attack{},
		corpusJobs:    map[string]*corpusJob{},
		store:         store,
		targetMaps:    map[uint64]*targetMap{},
		oastListeners: map[uint64]*oastListener{},
		bursts:        map[uint64]*repeaterBurst{},
		lastByteJobs:  map[uint64]*lastByteJob{},
		activeScans:   map[string]*activeScanJob{},
		routes:        routes,
		transport:     &http.Transport{},
	}
	srv.passiveProxy = passive.NewProxy(store, srv.routes.sharedTransport())

	var mu sync.Mutex
	var cancelledTools []string
	mark := func(name string) {
		mu.Lock()
		cancelledTools = append(cancelledTools, name)
		mu.Unlock()
	}

	_, attackCancel := context.WithCancel(context.Background())
	srv.attacks[1] = &attack{
		status: "running",
		cancel: func() { mark("intruder"); attackCancel() },
	}
	_, corpusCancel := context.WithCancel(context.Background())
	srv.corpusJobs["c1"] = &corpusJob{
		state:  "running",
		cancel: func() { mark("corpus"); corpusCancel() },
	}
	_, mapCancel := context.WithCancel(context.Background())
	srv.targetMaps[1] = &targetMap{
		status: "running",
		cancel: func() { mark("target_map"); mapCancel() },
	}
	_, burstCancel := context.WithCancel(context.Background())
	srv.bursts[1] = &repeaterBurst{
		status: "running",
		cancel: func() { mark("burst"); burstCancel() },
	}
	_, lbCancel := context.WithCancel(context.Background())
	srv.lastByteJobs[1] = &lastByteJob{
		status: "running",
		cancel: func() { mark("last_byte"); lbCancel() },
	}

	req := httptest.NewRequest(http.MethodPost, "/proxy/jobs/cancel-all", nil)
	rec := httptest.NewRecorder()
	srv.cancelAllJobsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		OK        bool           `json:"ok"`
		Cancelled map[string]int `json:"cancelled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK {
		t.Fatalf("expected ok=true")
	}
	for _, key := range []string{"intruder", "corpus", "target_map", "burst", "last_byte"} {
		if body.Cancelled[key] != 1 {
			t.Fatalf("expected cancelled[%s]=1, got %d (all=%v)", key, body.Cancelled[key], body.Cancelled)
		}
	}
	mu.Lock()
	gotCount := len(cancelledTools)
	mu.Unlock()
	if gotCount != 5 {
		t.Fatalf("expected 5 cancel callbacks invoked, got %d (%v)", gotCount, cancelledTools)
	}
}

func TestListNucleiJobsAndCaptureContextCancelEndpoints(t *testing.T) {
	store := passive.NewStore()
	routes, err := newRouteManager()
	if err != nil {
		t.Fatalf("newRouteManager: %v", err)
	}
	srv := &server{
		routes:    routes,
		transport: &http.Transport{},
	}
	srv.passiveProxy = passive.NewProxy(store, srv.routes.sharedTransport())

	// GET /proxy/scanner/nuclei/jobs should return 200 with a jobs array.
	req := httptest.NewRequest(http.MethodGet, "/proxy/scanner/nuclei/jobs", nil)
	rec := httptest.NewRecorder()
	srv.scannerNucleiJob(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /proxy/scanner/nuclei/jobs, got %d: %s", rec.Code, rec.Body.String())
	}
	var jobsResp struct {
		Jobs []json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &jobsResp); err != nil {
		t.Fatalf("decode jobs response: %v", err)
	}

	// POST /proxy/traffic/capture-contexts/cancel should accept token and return ok=true.
	payload := []byte(`{"token":"test-token-123"}`)
	cancelReq := httptest.NewRequest(http.MethodPost, "/proxy/traffic/capture-contexts/cancel", bytes.NewReader(payload))
	cancelRec := httptest.NewRecorder()
	srv.captureContextCancelHandler(cancelRec, cancelReq)
	if cancelRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from captureContextCancelHandler, got %d: %s", cancelRec.Code, cancelRec.Body.String())
	}
	var cancelResp map[string]interface{}
	if err := json.Unmarshal(cancelRec.Body.Bytes(), &cancelResp); err != nil {
		t.Fatalf("decode cancel response: %v", err)
	}
	if cancelResp["ok"] != true || cancelResp["token"] != "test-token-123" {
		t.Fatalf("unexpected cancel response: %v", cancelResp)
	}
	_ = time.Second
}
