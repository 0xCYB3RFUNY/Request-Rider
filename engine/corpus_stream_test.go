package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A corpus run is thousands of requests, and with polling alone nothing appeared
// on screen until the last one answered — which reads exactly like a hung scan.
// The stream is what makes the run watchable, so its three properties are what
// these tests hold it to: a listener sees progress and findings as they happen,
// the terminal frame is the authoritative report, and a listener that arrives
// late or reconnects starts from the truth rather than from the next event.

type sseFrame struct {
	id      string
	event   string
	payload map[string]interface{}
}

// readSSE reads frames until `stop` says one is the last one, or the deadline
// passes. A blank line terminates a frame; forwarding without it is a bug this
// reader would report as "no events at all".
func readSSE(t *testing.T, response *http.Response, stop func(sseFrame) bool, within time.Duration) []sseFrame {
	t.Helper()
	reader := bufio.NewReader(response.Body)
	frames := []sseFrame{}
	deadline := time.Now().Add(within)
	var current sseFrame
	var data strings.Builder
	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "id: "):
			current.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			current.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data.WriteString(strings.TrimPrefix(line, "data: "))
		case line == "" && current.event != "":
			_ = json.Unmarshal([]byte(data.String()), &current.payload)
			frames = append(frames, current)
			if stop(current) {
				return frames
			}
			current = sseFrame{}
			data.Reset()
		}
	}
	return frames
}

func newTestCorpusJob(state string) *corpusJob {
	job := &corpusJob{ID: "corpus-test-1", Target: "https://example.test/", Started: time.Now(), state: state}
	job.progress.Total = 100
	job.progress.Done = 40
	job.progress.Percent = -1
	return job
}

func TestCorpusStreamOpensWithTheJobAsItStands(t *testing.T) {
	job := newTestCorpusJob("running")
	server := &server{corpusJobs: map[string]*corpusJob{job.ID: job}}

	httpServer := httptest.NewServer(http.HandlerFunc(server.scannerCorpusJobs))
	defer httpServer.Close()

	response, err := httpServer.Client().Get(httpServer.URL + "/proxy/scanner/corpus/jobs/corpus-test-1/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type %q; the browser dispatches nothing else", got)
	}

	frames := readSSE(t, response, func(frame sseFrame) bool { return frame.event == "snapshot" }, 5*time.Second)
	if len(frames) == 0 || frames[0].event != "snapshot" {
		t.Fatalf("first frame is %+v; a listener that connects late must start from the job's state, not from the next event", frames)
	}
	progress, ok := frames[0].payload["progress"].(map[string]interface{})
	if !ok {
		t.Fatalf("snapshot carries no progress object: %v", frames[0].payload)
	}
	if progress["requests_done"] != float64(40) {
		t.Fatalf("snapshot reports %v requests done; the job had 40", progress["requests_done"])
	}
	if frames[0].id == "" {
		t.Fatal("snapshot frame has no id; `Last-Event-ID` on reconnect would be empty")
	}
}

func TestCorpusStreamPushesFindingsBeforeTheRunEnds(t *testing.T) {
	job := newTestCorpusJob("running")
	server := &server{corpusJobs: map[string]*corpusJob{job.ID: job}}
	httpServer := httptest.NewServer(http.HandlerFunc(server.scannerCorpusJobs))
	defer httpServer.Close()

	response, err := httpServer.Client().Get(httpServer.URL + "/proxy/scanner/corpus/jobs/corpus-test-1/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer response.Body.Close()

	// Give the listener a moment to attach, then publish from a goroutine the
	// way a real run does — from inside the enumeration.
	time.Sleep(150 * time.Millisecond)
	go func() {
		job.publish("progress", job.progressPayload())
		job.publish("finding", map[string]interface{}{"method": "GET", "path": "/.env", "status": 200})
		job.publish("progress", job.progressPayload())
	}()

	frames := readSSE(t, response, func(frame sseFrame) bool { return frame.event == "finding" }, 10*time.Second)
	kinds := make([]string, 0, len(frames))
	for _, frame := range frames {
		kinds = append(kinds, frame.event)
	}
	if len(kinds) < 2 {
		t.Fatalf("frames seen: %v; a live run must reach the browser before it ends", kinds)
	}
	var finding map[string]interface{}
	for _, frame := range frames {
		if frame.event == "finding" {
			finding = frame.payload
		}
	}
	if finding == nil || finding["path"] != "/.env" {
		t.Fatalf("finding frame payload is %v; the row that proves the run is producing evidence never arrived", finding)
	}
	if finding["status"] != float64(200) {
		t.Fatalf("finding frame lost its status: %v", finding)
	}
}

func TestCorpusStreamEndsWithTheAuthoritativeReport(t *testing.T) {
	job := newTestCorpusJob("completed")
	job.progress.Total = 100
	job.progress.Done = 100
	job.progress.Percent = 100
	server := &server{corpusJobs: map[string]*corpusJob{job.ID: job}}
	httpServer := httptest.NewServer(http.HandlerFunc(server.scannerCorpusJobs))
	defer httpServer.Close()

	response, err := httpServer.Client().Get(httpServer.URL + "/proxy/scanner/corpus/jobs/corpus-test-1/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer response.Body.Close()

	frames := readSSE(t, response, func(frame sseFrame) bool { return frame.event == "done" }, 10*time.Second)
	if len(frames) == 0 {
		t.Fatal("a finished run produced no terminal frame; the browser would wait forever")
	}
	last := frames[len(frames)-1]
	if last.event != "done" {
		t.Fatalf("last frame is %q; the run ended without a verdict", last.event)
	}
	if last.payload["state"] != "completed" {
		t.Fatalf("terminal frame state is %v", last.payload["state"])
	}
}

func TestCorpusStreamAnswers404ForAJobThatIsGone(t *testing.T) {
	server := &server{corpusJobs: map[string]*corpusJob{}}
	httpServer := httptest.NewServer(http.HandlerFunc(server.scannerCorpusJobs))
	defer httpServer.Close()

	response, err := httpServer.Client().Get(httpServer.URL + "/proxy/scanner/corpus/jobs/gone/stream")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("stream for an unknown job answered %d; the browser would show a transport failure instead of 'the run is gone'", response.StatusCode)
	}
}

// A cancelled run must still reach the browser as a verdict, not as a dropped
// connection: cancelling is an operator action and it has an outcome to show.
func TestCorpusStreamReportsCancellationAsAVerdict(t *testing.T) {
	job := newTestCorpusJob("cancelled")
	server := &server{corpusJobs: map[string]*corpusJob{job.ID: job}}
	httpServer := httptest.NewServer(http.HandlerFunc(server.scannerCorpusJobs))
	defer httpServer.Close()

	response, err := httpServer.Client().Get(httpServer.URL + "/proxy/scanner/corpus/jobs/corpus-test-1/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer response.Body.Close()

	frames := readSSE(t, response, func(frame sseFrame) bool { return frame.event == "done" }, 10*time.Second)
	if len(frames) == 0 || frames[len(frames)-1].event != "done" {
		t.Fatalf("cancelled run produced %+v; the operator pressed stop and got nothing", frames)
	}
	if frames[len(frames)-1].payload["state"] != "cancelled" {
		t.Fatalf("terminal state is %v", frames[len(frames)-1].payload["state"])
	}
}

// The publish fan-out must not let one unreadable listener stall a run.
func TestCorpusPublishDoesNotBlockOnAFullListener(t *testing.T) {
	job := newTestCorpusJob("running")
	events, detach := job.subscribe()
	defer detach()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			job.publish("progress", job.progressPayload())
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("publish blocked on a listener that never reads; a browser tab in the background would stall the whole scan")
	}
	// The backlog stays bounded without throwing frames away: progress is a
	// snapshot, so only the newest one is ever pending.
	if len(events) > 64 {
		t.Fatalf("listener backlog is %d frames; the buffer is supposed to be bounded", len(events))
	}
}

// A finding must survive a listener that is not reading yet.
//
// This is the defect the operator reported: the header counted five findings while
// the table held one row. The count comes from `j.progress.Findings`, which is
// maintained by the scan, and the rows come from the frames — so a frame thrown
// away by the fan-out shows up as exactly that disagreement, and nothing repairs
// it because the terminal frame that carries the full list went through the same
// fan-out.
func TestAFindingSurvivesAListenerThatIsNotReadingYet(t *testing.T) {
	job := newTestCorpusJob("running")
	events, detach := job.subscribe()
	defer detach()

	// A long run emits progress after every request; these frames are what filled
	// the old fixed buffer before the finding arrived.
	for i := 0; i < 5000; i++ {
		job.publish("progress", job.progressPayload())
	}
	job.publish("finding", map[string]interface{}{
		"CheckID": "9999", "Method": "GET", "Path": "/admin", "StatusCode": 200,
	})

	deadline := time.After(10 * time.Second)
	for {
		select {
		case event, open := <-events:
			if !open {
				t.Fatal("listener channel closed before the finding arrived")
			}
			if event.Kind == "finding" {
				if event.Payload["CheckID"] != "9999" {
					t.Fatalf("finding frame carries %v; the row would render another check", event.Payload["CheckID"])
				}
				return
			}
		case <-deadline:
			t.Fatal("the finding never arrived; a dropped frame leaves the table short of the counter and nothing repairs it")
		}
	}
}

// Every finding of a run reaches the listener, not the first one to fit.
func TestEveryFindingReachesTheListener(t *testing.T) {
	job := newTestCorpusJob("running")
	events, detach := job.subscribe()
	defer detach()

	const total = 400
	go func() {
		for i := 0; i < total; i++ {
			job.publish("progress", job.progressPayload())
			job.publish("finding", map[string]interface{}{
				"CheckID": i, "Method": "GET", "Path": "/p", "StatusCode": 200,
			})
		}
		job.publish("done", map[string]interface{}{"state": "completed"})
	}()

	seen := 0
	done := false
	deadline := time.After(20 * time.Second)
	for !done {
		select {
		case event, open := <-events:
			if !open {
				t.Fatalf("listener closed after %d of %d findings", seen, total)
			}
			switch event.Kind {
			case "finding":
				seen++
			case "done":
				done = true
			}
		case <-deadline:
			t.Fatalf("only %d of %d findings arrived before the terminal frame", seen, total)
		}
	}
	if seen != total {
		t.Fatalf("%d of %d findings reached the listener; a run's evidence is not a disposable frame", seen, total)
	}
}

// The terminal frame carries the whole report, so losing it loses the run.
func TestTheTerminalFrameSurvivesAFloodOfProgress(t *testing.T) {
	job := newTestCorpusJob("running")
	events, detach := job.subscribe()
	defer detach()

	for i := 0; i < 5000; i++ {
		job.publish("progress", job.progressPayload())
	}
	report := map[string]interface{}{"state": "completed", "finding_count": 5}
	job.publish("done", report)

	deadline := time.After(10 * time.Second)
	for {
		select {
		case event, open := <-events:
			if !open {
				t.Fatal("listener channel closed before the terminal frame arrived")
			}
			if event.Kind == "done" {
				if event.Payload["finding_count"] != 5 {
					t.Fatalf("terminal frame carries %v findings; the report the browser rebuilds from it is incomplete", event.Payload["finding_count"])
				}
				return
			}
		case <-deadline:
			t.Fatal("the terminal frame never arrived; the browser keeps the truncated live view for good")
		}
	}
}

// Coalescing, not discarding: a backlog of progress frames is one frame wide.
func TestProgressFramesCoalesceInsteadOfQueueing(t *testing.T) {
	subscriber := newCorpusSubscriber()
	defer subscriber.close()

	// Nothing reads this subscriber, so everything published is still queued.
	for i := 0; i < 5000; i++ {
		subscriber.enqueue(corpusEvent{ID: i, Kind: "progress"})
	}
	if queued := subscriber.queued(); queued != 1 {
		t.Fatalf("%d progress frames are queued; a snapshot only needs the newest one, and an unbounded backlog is what the dropped version replaced with a loss", queued)
	}

	// A finding behind the backlog is not squeezed out by it.
	subscriber.enqueue(corpusEvent{ID: 9000, Kind: "finding"})
	subscriber.enqueue(corpusEvent{ID: 9001, Kind: "progress"})
	if queued := subscriber.queued(); queued != 2 {
		t.Fatalf("%d frames are queued after one finding; progress is coalesced, findings are not", queued)
	}
}

// A detached listener stops receiving and its channel closes. Publishing after a
// detach used to be the panic the old comment warned about; with a queue it is a
// no-op, and this is the test that says so.
func TestPublishingAfterDetachIsNotAPanic(t *testing.T) {
	job := newTestCorpusJob("running")
	events, detach := job.subscribe()
	detach()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			job.publish("finding", map[string]interface{}{"CheckID": i})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("publish blocked on a listener that detached")
	}
	for range events {
	}
}
