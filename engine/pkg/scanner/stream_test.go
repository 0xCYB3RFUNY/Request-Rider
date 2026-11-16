package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// streamingBinary writes one JSONL record per template, sleeping between them,
// so a test can observe the report while the binary is still running.
func streamingBinary(t *testing.T, stagedCount int) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-stream.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\nvalidate=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  if [ \"$arg\" = '-validate' ]; then validate='yes'; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		// Validation is a separate invocation with no -o. This binary accepts every
		// document, so it answers at once; the streaming the test watches has to be
		// the scan itself, not a validation pass that slept between records.
		"if [ -n \"$validate\" ]; then exit 0; fi\n" +
		"n=0\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  n=$((n+1))\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  printf '%s\\n' '{\"template-id\":\"'\"$id\"'\",\"template-path\":\"'\"$f\"'\",\"host\":\"http://target.test/\",\"matched-at\":\"http://target.test/p\",\"matcher-status\":false}' >> \"$out\"\n" +
		"  sleep 0.3\n" +
		"done\n" +
		"exit 0\n"
	_ = stagedCount
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

func collectUntil(t *testing.T, job *NucleiJob, want int, timeout time.Duration) []TemplateEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events := job.EventsSince(0)
		if len(events) >= want {
			return events
		}
		if job.IsFinished() {
			return job.EventsSince(0)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return job.EventsSince(0)
}

func TestNucleiJobStreamsTemplateResultsBeforeItFinishes(t *testing.T) {
	streamingBinary(t, 6)
	upload, _, _, err := StageNucleiUpload("", []UploadFile{
		{Name: "one.yaml", Content: idTemplate("stream-one")},
		{Name: "two.yaml", Content: idTemplate("stream-two")},
		{Name: "three.yaml", Content: idTemplate("stream-three")},
		{Name: "four.yaml", Content: idTemplate("stream-four")},
		{Name: "five.yaml", Content: idTemplate("stream-five")},
		{Name: "six.yaml", Content: idTemplate("stream-six")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), upload, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Three of six templates have reported, and the binary is still running.
	early := collectUntil(t, job, 3, 5*time.Second)
	if len(early) < 3 {
		t.Fatalf("only %d events before the run finished: %#v", len(early), early)
	}
	if job.IsFinished() {
		t.Fatal("the whole report arrived at once instead of streaming")
	}
	templates := 0
	for _, event := range early {
		if event.Kind != EventTemplate {
			continue
		}
		templates++
		if event.Name == "" || event.Status == "" {
			t.Fatalf("streamed row is incomplete: %#v", event)
		}
		if event.TemplateID == "" {
			t.Fatalf("streamed row lost its template id: %#v", event)
		}
	}
	if templates < 3 {
		t.Fatalf("streamed %d template rows before the run finished", templates)
	}

	job.Wait()
	all := job.EventsSince(0)
	final := all[len(all)-1]
	if final.Kind != EventDiagnostic {
		t.Fatalf("last event = %q, want %q", final.Kind, EventDiagnostic)
	}
	if final.State != JobCompleted {
		t.Fatalf("final state = %q", final.State)
	}
	if final.Result == nil {
		t.Fatal("the final event carries no report")
	}
	if templates, ok := final.Result["templates"].([]TemplateResult); !ok || len(templates) != 6 {
		t.Fatalf("final report templates = %#v, want all six files", final.Result["templates"])
	}
}

func TestNucleiJobStreamsFindingDetailsWithMatchedTemplate(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "nuclei-matched-stream.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"file=$(find \"$templates\" -name '*.yaml' | head -1)\n" +
		"printf '%s\\n' '{\"template-id\":\"live-match\",\"template-path\":\"'\"$file\"'\",\"info\":{\"name\":\"Live Match\",\"severity\":\"high\"},\"type\":\"http\",\"host\":\"http://target.test/\",\"matched-at\":\"http://target.test/probe\",\"matcher-name\":\"status\",\"matcher-status\":true}' > \"$out\"\n" +
		"sleep 0.7\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
	upload, _, _, err := StageNucleiUpload("", []UploadFile{
		{Name: "matched.yaml", Content: idTemplate("live-match")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), upload, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var matched *TemplateEvent
	for time.Now().Before(deadline) {
		for _, event := range job.EventsSince(0) {
			if event.Kind == EventTemplate && event.Status == TemplateMatched {
				matched = &event
				break
			}
		}
		if matched != nil || job.IsFinished() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	job.Wait()
	if matched == nil {
		t.Fatalf("no matched template event was streamed: %#v", job.EventsSince(0))
	}
	if len(matched.Findings) != 1 || matched.Findings[0]["template_id"] != "live-match" {
		t.Fatalf("live finding details = %#v, want the matched finding", matched.Findings)
	}
	if matched.Findings[0]["matched_at"] != "http://target.test/probe" {
		t.Fatalf("live finding lost matched_at: %#v", matched.Findings[0])
	}
	payload, err := json.Marshal(matched)
	if err != nil {
		t.Fatalf("marshal matched event: %v", err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatalf("decode matched event: %v", err)
	}
	findings, ok := wire["findings"].([]interface{})
	if !ok || len(findings) != 1 {
		t.Fatalf("SSE event findings = %#v, want one finding", wire["findings"])
	}
}

func TestNucleiJobStreamReplaysFromACursor(t *testing.T) {
	streamingBinary(t, 3)
	upload, _, _, err := StageNucleiUpload("", []UploadFile{
		{Name: "a.yaml", Content: idTemplate("cursor-a")},
		{Name: "b.yaml", Content: idTemplate("cursor-b")},
		{Name: "c.yaml", Content: idTemplate("cursor-c")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), upload, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	job.Wait()
	all := job.EventsSince(0)
	if len(all) < 2 {
		t.Fatalf("events = %d, want several", len(all))
	}
	// A browser that reconnects with Last-Event-ID only gets what it missed.
	missed := job.EventsSince(all[0].Cursor)
	if len(missed) != len(all)-1 {
		t.Fatalf("replay from cursor %d returned %d events, want %d", all[0].Cursor, len(missed), len(all)-1)
	}
	backlog, _, unsubscribe := job.SubscribeSince(all[0].Cursor)
	defer unsubscribe()
	if len(backlog) != len(all)-1 {
		t.Fatalf("backlog = %d, want %d", len(backlog), len(all)-1)
	}
}

func TestNucleiJobStreamWakesSubscribers(t *testing.T) {
	streamingBinary(t, 2)
	upload, _, _, err := StageNucleiUpload("", []UploadFile{
		{Name: "a.yaml", Content: idTemplate("wake-a")},
		{Name: "b.yaml", Content: idTemplate("wake-b")},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), upload, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	_, updates, unsubscribe := job.SubscribeSince(0)
	defer unsubscribe()
	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("a subscriber was never woken by a streamed result")
	}
	job.Wait()
}
