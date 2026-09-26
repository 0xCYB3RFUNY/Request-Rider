package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TemplateEvent kinds carried by the scan stream.
const (
	EventProgress   = "progress"
	EventTemplate   = "template"
	EventDiagnostic = "done"
)

// TemplateEvent is one live update of a running scan. The browser renders a row
// straight from it, so a folder scan shows results while nuclei is still
// working instead of dumping the whole report at the end.
type TemplateEvent struct {
	Cursor     int                    `json:"cursor"`
	Kind       string                 `json:"kind"`
	Name       string                 `json:"name,omitempty"`
	Path       string                 `json:"path,omitempty"`
	TemplateID string                 `json:"template_id,omitempty"`
	Title      string                 `json:"title,omitempty"`
	Severity   string                 `json:"severity,omitempty"`
	Status     string                 `json:"status,omitempty"`
	Reason     string                 `json:"reason,omitempty"`
	CVE        []string               `json:"cve,omitempty"`
	CWE        []string               `json:"cwe,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
	Author     []string               `json:"author,omitempty"`
	Matches    int                    `json:"matches,omitempty"`
	Evidence   string                 `json:"evidence,omitempty"`
	MatchedAt  string                 `json:"matched_at,omitempty"`
	Progress   *NucleiProgress        `json:"progress,omitempty"`
	State      string                 `json:"state,omitempty"`
	Result     map[string]interface{} `json:"result,omitempty"`
}

// appendEvent records one event and wakes every subscriber.
func (j *NucleiJob) appendEvent(event TemplateEvent) {
	j.eventsMutex.Lock()
	j.eventCursor++
	event.Cursor = j.eventCursor
	j.events = append(j.events, event)
	waiters := make([]chan struct{}, 0, len(j.waiters))
	for waiter := range j.waiters {
		waiters = append(waiters, waiter)
	}
	j.eventsMutex.Unlock()
	for _, waiter := range waiters {
		// A subscriber that is already gone is skipped rather than blocking the
		// scan, so one closed browser tab cannot stall the report.
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
}

// SubscribeSince returns the events a client has not seen and a channel that is
// signalled whenever new ones arrive.
func (j *NucleiJob) SubscribeSince(cursor int) ([]TemplateEvent, chan struct{}, func()) {
	waiter := make(chan struct{}, 1)
	j.eventsMutex.Lock()
	backlog := []TemplateEvent{}
	for _, event := range j.events {
		if event.Cursor > cursor {
			backlog = append(backlog, event)
		}
	}
	j.waiters[waiter] = struct{}{}
	j.eventsMutex.Unlock()
	unsubscribe := func() {
		j.eventsMutex.Lock()
		delete(j.waiters, waiter)
		j.eventsMutex.Unlock()
	}
	return backlog, waiter, unsubscribe
}

// EventsSince returns the events a client has not seen yet.
func (j *NucleiJob) EventsSince(cursor int) []TemplateEvent {
	j.eventsMutex.Lock()
	defer j.eventsMutex.Unlock()
	missing := []TemplateEvent{}
	for _, event := range j.events {
		if event.Cursor > cursor {
			missing = append(missing, event)
		}
	}
	return missing
}

// IsFinished reports whether the scan has reached a terminal state.
func (j *NucleiJob) IsFinished() bool {
	select {
	case <-j.done:
		return true
	default:
		return false
	}
}

// NucleiJobStream returns a job for live streaming.
func NucleiJobStream(id string) (*NucleiJob, bool) {
	return nucleiJobs.get(strings.TrimSpace(id))
}

// watchOutput tails the JSONL report the binary writes while it runs. Nuclei
// appends a record as soon as a template finishes, so tailing the file is what
// turns the report into a live stream without changing how nuclei executes.
func (j *NucleiJob) watchOutput(path string) {
	byPath := map[string]StagedFile{}
	for _, file := range j.staged {
		byPath[filepath.Clean(file.StagedPath)] = file
	}
	reported := map[string]bool{}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	handle, err := os.Open(path)
	if err != nil {
		return
	}
	defer handle.Close()
	reader := bufio.NewReader(handle)
	for {
		<-ticker.C
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				// A partially written line stays in the buffered reader for the
				// next tick, so a half-written record is never parsed.
				break
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			var hit nucleiFinding
			if json.Unmarshal([]byte(trimmed), &hit) != nil || hit.TemplateID == "" {
				continue
			}
			clean := filepath.Clean(strings.TrimSpace(hit.TemplatePath))
			file, known := byPath[clean]
			if !known {
				// A template resolved from outside the staged directory is still
				// real evidence, so it is streamed under its own name.
				file = StagedFile{UploadName: filepath.Base(clean)}
			}
			if reported[clean] {
				// A template is streamed once; the final report carries the full
				// match count and every finding.
				continue
			}
			reported[clean] = true
			if hit.isFinding() {
				event := j.templateEvent(file, TemplateMatched, "")
				event.Evidence = hit.evidenceText()
				event.MatchedAt = oneLine(hit.MatchedAt)
				event.Matches = 1
				j.appendEvent(event)
				continue
			}
			// The streamed row says the same thing the final report will, so the
			// operator is not told a `code` or `file` template checked the target
			// while the run is still going.
			if file.Meta != nil && requestLessProtocols[file.Meta.Protocol] {
				j.appendEvent(j.templateEvent(file, TemplateNoRequest, fmt.Sprintf(
					"Ran, but checked no URL: this is a %q template, so it ran a local engine or read local files "+
						"and issued no request to the target. It cannot match or miss against a target host.",
					file.Meta.Protocol)))
				continue
			}
			j.appendEvent(j.templateEvent(file, TemplateNotMatched, ""))
		}
	}
}

// templateEvent builds the streamed row of one staged file.
func (j *NucleiJob) templateEvent(file StagedFile, status, reason string) TemplateEvent {
	event := TemplateEvent{Kind: EventTemplate, Name: file.UploadName, Status: status, Reason: reason}
	// The folder path travels with the row so the browser can file a streamed
	// result under its folder while the run is still working.
	event.Path = displayRelativePath(file.RelativePath, file.UploadName)
	if file.Meta != nil {
		event.TemplateID = file.Meta.TemplateID
		event.Title = file.Meta.Name
		event.Severity = file.Meta.Severity
		event.CVE = file.Meta.CVE
		event.CWE = file.Meta.CWE
		event.Tags = file.Meta.Tags
		event.Author = file.Meta.Author
	}
	return event
}
