package main

// Tests for pausing and resuming a Target crawl.
//
// The crawler is the second of the two long loops that could only be killed. It
// matters for the same reason: a crawl that walks into a host which has stopped
// answering keeps spending requests and pages, and the analyst gets no way to
// stop it at the moment it broke or to return there afterwards.
//
// These drive the real handler against live `httptest` targets, for the same
// reason the rest of this package does.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// crawlTarget answers with a small site: enough links for the crawl to have a
// frontier worth pausing in the middle of.
func crawlTarget(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>`+
			`<a href="/one">1</a><a href="/two">2</a><a href="/three">3</a>`+
			`<a href="/four">4</a><a href="/five">5</a><a href="/six">6</a>`+
			`<a href="/seven">7</a><a href="/eight">8</a>`+
			`</body></html>`)
	}))
	t.Cleanup(server.Close)
	return server
}

// slowCrawlTarget answers, but only after a delay long enough that a pause lands
// while a request is genuinely in flight.
func slowCrawlTarget(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/one">1</a><a href="/two">2</a></body></html>`)
	}))
	t.Cleanup(server.Close)
	return server
}

// crawlServer is the smallest server a crawl needs: a job registry to put the
// crawl in and a route transport to leave through.
func crawlServer() *server {
	return &server{targetMaps: map[uint64]*targetMap{}}
}

// startCrawl posts a crawl the way the gateway does and returns the map id.
func startCrawl(t *testing.T, s *server, body string) uint64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/proxy/target-map", strings.NewReader(body))
	s.targetMapStart(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("target-map start returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var started struct {
		MapID uint64 `json:"map_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatalf("the start answer is not JSON: %v (%s)", err, recorder.Body.String())
	}
	t.Cleanup(func() { stopCrawl(t, s, started.MapID) })
	return started.MapID
}

// crawlAction posts an action against a running crawl.
func crawlAction(t *testing.T, s *server, id uint64, action string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/proxy/target-map/%d/%s", id, action), strings.NewReader(""))
	s.targetMapStatus(recorder, request)
	return recorder
}

// crawlSnapshot reads a crawl the way the gateway polls it.
func crawlSnapshot(t *testing.T, s *server, id uint64) map[string]interface{} {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/proxy/target-map/%d", id), nil)
	s.targetMapStatus(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("target-map poll returned %d", recorder.Code)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("the poll answer is not JSON: %v", err)
	}
	return out
}

func TestACrawlCanBePausedAndResumedWithoutLosingItsFrontier(t *testing.T) {
	target := slowCrawlTarget(t, 400*time.Millisecond)
	s := crawlServer()
	id := startCrawl(t, s, fmt.Sprintf(`{"url":%q,"max_depth":2,"same_origin":true}`, target.URL))

	// Wait until the crawl has fetched something, so the resume can be shown to
	// continue rather than restart.
	waitFor(t, func() bool { return crawlVisited(t, s, id) > 0 })

	if recorder := crawlAction(t, s, id, "pause"); recorder.Code != http.StatusOK {
		t.Fatalf("pause returned %d: %s", recorder.Code, recorder.Body.String())
	}
	snapshot := crawlSnapshot(t, s, id)
	if snapshot["status"] != "paused" {
		t.Fatalf("a paused crawl reports status %v", snapshot["status"])
	}
	checkpoint, _ := snapshot["checkpoint"].(map[string]interface{})
	if checkpoint == nil {
		t.Fatal("the poll answer carries no checkpoint: 'where did it break' has no source")
	}
	if paused, _ := checkpoint["paused"].(bool); !paused {
		t.Errorf("the checkpoint does not say the crawl is paused: %+v", checkpoint)
	}

	// A paused crawl spends nothing: the visited count does not move.
	before := crawlVisited(t, s, id)
	time.Sleep(500 * time.Millisecond)
	if after := crawlVisited(t, s, id); after != before {
		t.Errorf("a paused crawl kept fetching: %d → %d pages", before, after)
	}

	if recorder := crawlAction(t, s, id, "resume"); recorder.Code != http.StatusOK {
		t.Fatalf("resume returned %d: %s", recorder.Code, recorder.Body.String())
	}
	waitFor(t, func() bool { return crawlVisited(t, s, id) > before })
	if status := crawlSnapshot(t, s, id)["status"]; status == "paused" {
		t.Error("the crawl is still reported as paused after resume")
	}
	crawlAction(t, s, id, "") // no-op read; the cancel below stops it
	stopCrawl(t, s, id)
}

func TestACrawlPausesItselfWhenTheHostStopsAnswering(t *testing.T) {
	var mu sync.Mutex
	served := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		alive := served <= 3
		mu.Unlock()
		if !alive {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/a">a</a><a href="/b">b</a>`+
			`<a href="/c">c</a><a href="/d">d</a></body></html>`)
	}))
	t.Cleanup(target.Close)

	s := crawlServer()
	id := startCrawl(t, s, fmt.Sprintf(
		`{"url":%q,"max_depth":2,"same_origin":true,"failure_pause":2}`, target.URL))
	waitFor(t, func() bool {
		snapshot := crawlSnapshot(t, s, id)
		checkpoint, _ := snapshot["checkpoint"].(map[string]interface{})
		if checkpoint == nil {
			return false
		}
		paused, _ := checkpoint["paused"].(bool)
		return paused
	})
	snapshot := crawlSnapshot(t, s, id)
	checkpoint := snapshot["checkpoint"].(map[string]interface{})
	reason, _ := checkpoint["pause_reason"].(string)
	if !strings.Contains(reason, "consecutive transport failures") {
		t.Errorf("the automatic pause does not name its evidence: %q", reason)
	}
	if snapshot["status"] != "paused" {
		t.Errorf("a paused crawl reports status %v", snapshot["status"])
	}
	stopCrawl(t, s, id)
}

func TestTheThresholdIsTheAnalystsOwnNumberAndItIsReported(t *testing.T) {
	target := crawlTarget(t)
	s := crawlServer()
	id := startCrawl(t, s, fmt.Sprintf(`{"url":%q,"max_depth":0,"failure_pause":7}`, target.URL))
	snapshot := crawlSnapshot(t, s, id)
	checkpoint, _ := snapshot["checkpoint"].(map[string]interface{})
	if checkpoint == nil {
		t.Fatal("the poll answer carries no checkpoint")
	}
	if got, _ := checkpoint["failure_pause"].(float64); int(got) != 7 {
		t.Errorf("checkpoint reports threshold %v, want the analyst's 7", got)
	}
	stopCrawl(t, s, id)
}

func TestAnUnknownCrawlActionIsRefusedRatherThanGuessed(t *testing.T) {
	target := crawlTarget(t)
	s := crawlServer()
	id := startCrawl(t, s, fmt.Sprintf(`{"url":%q,"max_depth":0}`, target.URL))
	if recorder := crawlAction(t, s, id, "detonate"); recorder.Code != http.StatusBadRequest {
		t.Errorf("an unknown action answered %d, want 400", recorder.Code)
	}
	stopCrawl(t, s, id)
}

func crawlVisited(t *testing.T, s *server, id uint64) int {
	t.Helper()
	snapshot := crawlSnapshot(t, s, id)
	visited, _ := snapshot["visited"].(float64)
	return int(visited)
}

func stopCrawl(t *testing.T, s *server, id uint64) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/proxy/target-map/%d", id), nil)
	s.targetMapStatus(recorder, request)
}
