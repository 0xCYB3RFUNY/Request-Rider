package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"intruder/engine/pkg/scanner"
)

// quietBinary reports one template so the job reaches the running phase, then
// goes silent for a while before exiting. That is what a paused scan looks like
// on the wire: a live job with no events to send.
func quietBinary(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-quiet.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"f=$(find \"$templates\" -name '*.yaml' | sort | head -1)\n" +
		"id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"printf '%s\\n' '{\"template-id\":\"'\"$id\"'\",\"template-path\":\"'\"$f\"'\",\"host\":\"http://target.test/\",\"matcher-status\":false}' >> \"$out\"\n" +
		"sleep 2\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

// A stream that only writes on real events looks dead to every hop in between.
// A paused scan writes nothing at all, so without a heartbeat the connection is
// reaped while the job is still running and the browser reports a transport
// failure for a job it can no longer pause, resume or cancel.
func TestScannerNucleiJobStreamHeartbeatsWhileTheRunIsQuiet(t *testing.T) {
	quietBinary(t)
	// The job is started through the same two endpoints the browser uses, so the
	// test covers staging, the background run and the stream in one path.
	stageBody := `{"url":"http://target.test/","files":[` + nucleiUpload("quiet.yaml", "", nucleiValidTemplate) + `]}`
	stageRequest := httptest.NewRequest(http.MethodPost, "/proxy/scanner/nuclei/stage", strings.NewReader(stageBody))
	stageRecorder := httptest.NewRecorder()
	(&server{}).scannerNucleiStage(stageRecorder, stageRequest)
	if stageRecorder.Code != http.StatusOK {
		t.Fatalf("nuclei stage endpoint = %d %s", stageRecorder.Code, stageRecorder.Body.String())
	}
	var staged struct {
		UploadID string `json:"upload_id"`
	}
	if err := json.Unmarshal(stageRecorder.Body.Bytes(), &staged); err != nil {
		t.Fatal(err)
	}
	if staged.UploadID == "" {
		t.Fatalf("no upload id was returned: %s", stageRecorder.Body.String())
	}
	startRequest := httptest.NewRequest(http.MethodPost, "/proxy/scanner/nuclei/jobs",
		strings.NewReader(`{"url":"http://target.test/","upload_id":"`+staged.UploadID+`"}`))
	recorder := httptest.NewRecorder()
	(&server{}).scannerNucleiJob(recorder, startRequest)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("nuclei job endpoint = %d %s", recorder.Code, recorder.Body.String())
	}
	var started struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	job, ok := scanner.NucleiJobStream(started.JobID)
	if !ok {
		t.Fatalf("job %q is not streamable", started.JobID)
	}
	defer job.Wait()

	// Shorten the interval so the assertion does not depend on wall-clock timing.
	previous := scannerStreamHeartbeat
	scannerStreamHeartbeat = 50 * time.Millisecond
	defer func() { scannerStreamHeartbeat = previous }()

	streamRequest := httptest.NewRequest(http.MethodGet, "/proxy/scanner/nuclei/jobs/"+job.ID+"/stream", nil)
	streamRecorder := httptest.NewRecorder()
	handler := &server{}
	streamed := make(chan struct{})
	go func() {
		handler.scannerNucleiJobStream(streamRecorder, streamRequest)
		close(streamed)
	}()

	deadline := time.After(15 * time.Second)
	for {
		if strings.Contains(streamRecorder.Body.String(), ": keepalive") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("no keepalive was written while the run was quiet: %q", streamRecorder.Body.String())
		case <-streamed:
			t.Fatalf("the stream ended before a keepalive was written: %q", streamRecorder.Body.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A comment frame is not an event: it carries no id, so it cannot be mistaken
	// for a result and it does not move the event cursor.
	for _, frame := range strings.Split(streamRecorder.Body.String(), "\n\n") {
		frame = strings.TrimSpace(frame)
		if frame == "" {
			continue
		}
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "id:") {
				t.Fatalf("a keepalive frame carried an event id: %q", frame)
			}
		}
	}

	select {
	case <-streamed:
	case <-time.After(15 * time.Second):
		t.Fatal("the stream did not end after the run finished")
	}
	if !strings.Contains(streamRecorder.Body.String(), "event: done") {
		t.Fatalf("the terminal report was not streamed: %q", streamRecorder.Body.String())
	}
}
