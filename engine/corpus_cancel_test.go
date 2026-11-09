package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// `Cancel` existed on the server and did nothing. `run` replaced the job's
// canceller with a no-op as its first statement, so by the time an operator
// pressed the button the job held an empty function and the run continued to its
// end — measured 2026-10-10: a job cancelled 25 s into a 2500-check run was still
// `running` at every poll afterwards, and the button the operator could see was
// the only thing that had been missing.
//
// These tests hold the run to the two things an operator needs from it: stopping
// actually stops, and a cancelled run reports itself as cancelled rather than
// vanishing.

func waitForCorpusState(t *testing.T, engine *server, jobID string, want string, within time.Duration) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(within)
	var last map[string]interface{}
	for time.Now().Before(deadline) {
		job := engine.corpusJob(jobID)
		if job != nil {
			last = job.snapshot()
			if last["state"] == want {
				return last
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job did not reach %q within %s; last state was %v", want, within, last["state"])
	return nil
}

func TestCancellingACorpusRunStopsIt(t *testing.T) {
	// A target that never answers keeps the run in flight long enough for the
	// cancel to land on a running job rather than on one that already finished.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(30 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer target.Close()

	engine := &server{transport: target.Client().Transport.(*http.Transport)}
	body := `{"url":"` + target.URL + `","max_checks":50,"concurrency":4}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/corpus/jobs", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	engine.scannerCorpusJobs(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("start answered %d: %s", recorder.Code, recorder.Body.String())
	}
	var started struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode job id: %v", err)
	}
	jobID := started.JobID

	// Cancel through the same endpoint the button uses, not by reaching into the
	// job: the endpoint is what the operator's request goes through.
	cancel := httptest.NewRequest(http.MethodDelete, "/proxy/scanner/corpus/jobs/"+jobID, nil)
	cancelRecorder := httptest.NewRecorder()
	engine.scannerCorpusJobs(cancelRecorder, cancel)
	if cancelRecorder.Code != http.StatusOK {
		t.Fatalf("cancel answered %d: %s", cancelRecorder.Code, cancelRecorder.Body.String())
	}

	report := waitForCorpusState(t, engine, jobID, "cancelled", 15*time.Second)
	if report["state"] != "cancelled" {
		t.Fatalf("state is %v after an explicit cancel", report["state"])
	}
}

func TestCancellingAFinishedRunIsReportedNotSilentlyAccepted(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	engine := &server{transport: target.Client().Transport.(*http.Transport)}
	body := `{"url":"` + target.URL + `","max_checks":1}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/corpus/jobs", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	engine.scannerCorpusJobs(recorder, request)
	var started struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode job id: %v", err)
	}
	jobID := started.JobID
	waitForCorpusState(t, engine, jobID, "completed", 30*time.Second)

	cancel := httptest.NewRequest(http.MethodDelete, "/proxy/scanner/corpus/jobs/"+jobID, nil)
	cancelRecorder := httptest.NewRecorder()
	engine.scannerCorpusJobs(cancelRecorder, cancel)
	if cancelRecorder.Code != http.StatusOK {
		t.Fatalf("cancel of a finished run answered %d", cancelRecorder.Code)
	}
	var report map[string]interface{}
	if err := json.Unmarshal(cancelRecorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode cancel answer: %v", err)
	}
	if report["state"] != "completed" {
		t.Fatalf("cancelling a finished run reported %v; a run that already ended must not be rewritten as cancelled", report["state"])
	}
}

func TestCancellingAJobThatIsGoneAnswers404(t *testing.T) {
	engine := &server{corpusJobs: map[string]*corpusJob{}}
	cancel := httptest.NewRequest(http.MethodDelete, "/proxy/scanner/corpus/jobs/gone", nil)
	recorder := httptest.NewRecorder()
	engine.scannerCorpusJobs(recorder, cancel)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("cancel of an unknown job answered %d; the browser would report a transport failure instead of 'the run is gone'", recorder.Code)
	}
}

// The run's own context is the thing a cancel must reach, so this pins the
// property directly: cancelling the job cancels the enumeration's context.
func TestTheJobsCancellerIsTheRunsOwnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	job := &corpusJob{cancel: cancel}
	job.cancel()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the job's canceller did not cancel the run's context")
	}
}
