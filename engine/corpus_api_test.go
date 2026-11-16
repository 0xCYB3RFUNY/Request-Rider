package main

// Tests for the corpus enumeration endpoints in `corpus_api.go`.
//
// These cover the parts an operator touches first: the size of a run before it
// starts, the refusal of a target that is not a target, and a run against a live
// `httptest` server rather than a mock transport. A mock would agree with a
// handler that never sends anything, which is the failure this file exists to
// catch — the same reason `RunCorpus` refuses a nil RoundTripper in the first
// place.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"intruder/engine/pkg/passive"
)

func postCorpusRun(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	s := &server{}
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/corpus/run", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	s.scannerCorpusRun(recorder, request)
	return recorder
}

func TestTheCorpusStatsRouteAnswersBeforeAnythingIsSent(t *testing.T) {
	s := &server{}
	request := httptest.NewRequest(http.MethodGet, "/proxy/scanner/corpus/stats", nil)
	recorder := httptest.NewRecorder()
	s.scannerCorpusStats(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var report struct {
		Stats struct {
			Total       int            `json:"total"`
			Selected    int            `json:"selected"`
			UniquePaths int            `json:"unique_paths"`
			ByTag       map[string]int `json:"by_tag"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decoding the report: %v", err)
	}
	if report.Stats.Total < 6000 {
		t.Errorf("the corpus reports %d checks; a count that low means the loader lost the corpus, and a lost corpus reads as a clean site", report.Stats.Total)
	}
	if report.Stats.Selected != report.Stats.Total {
		t.Errorf("with no tag filter selected = %d, want every one of the %d", report.Stats.Selected, report.Stats.Total)
	}
	if report.Stats.UniquePaths <= 0 || report.Stats.UniquePaths > report.Stats.Selected {
		t.Errorf("unique_paths = %d, which cannot describe %d checks", report.Stats.UniquePaths, report.Stats.Selected)
	}
}

func TestTheCorpusStatsRouteNarrowsToTheTagsItWasGiven(t *testing.T) {
	s := &server{}
	request := httptest.NewRequest(http.MethodGet, "/proxy/scanner/corpus/stats?tags=x", nil)
	recorder := httptest.NewRecorder()
	s.scannerCorpusStats(recorder, request)

	var report struct {
		Stats struct {
			Total    int `json:"total"`
			Selected int `json:"selected"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decoding the report: %v", err)
	}
	if report.Stats.Selected == 0 {
		t.Fatal("a tag that matches nothing selected nothing, which cannot be told apart from a filter that is broken")
	}
	if report.Stats.Selected >= report.Stats.Total {
		t.Errorf("the tag filter selected %d of %d: it narrowed nothing", report.Stats.Selected, report.Stats.Total)
	}
}

func TestTheCorpusStatsRouteRefusesABoundItCannotHonour(t *testing.T) {
	s := &server{}
	request := httptest.NewRequest(http.MethodGet, "/proxy/scanner/corpus/stats?max_checks=-1", nil)
	recorder := httptest.NewRecorder()
	s.scannerCorpusStats(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status = %d for a negative bound, want 400", recorder.Code)
	}
}

func TestTheCorpusRunRouteEnumeratesTheTargetItWasGiven(t *testing.T) {
	// A stand that answers 200 to everything, so a run of a handful of checks
	// really exchanges requests rather than merely reporting a shape.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>stand</html>"))
	}))
	defer target.Close()

	recorder := postCorpusRun(t, `{"url":"`+target.URL+`","max_checks":3}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var report struct {
		Findings    []struct{ CheckID, Path string } `json:"findings"`
		Requests    int                              `json:"requests"`
		Checks      int                              `json:"checks"`
		SourceIP    string                           `json:"source_ip"`
		Stats       struct{ Selected int }           `json:"stats"`
		Truncated   bool                             `json:"truncated"`
		DurationMS  int64                            `json:"duration_ms"`
		FindingNote string                           `json:"-"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decoding the report: %v", err)
	}
	if report.Requests == 0 {
		t.Error("the run reports zero requests; a handler that sends nothing and reports findings is worse than one that fails")
	}
	if report.Checks == 0 {
		t.Error("the run reports zero checks evaluated")
	}
	// A bound of three out of six thousand did truncate the selection, and the
	// report has to say so: a clean target plus a silently shortened run reads as a
	// clean target, which is the one claim a report like this must never make.
	if !report.Truncated {
		t.Error("a run bounded to 3 of 6521 checks reports itself as whole")
	}
	if report.Stats.Selected == 0 {
		t.Error("the report carries no selection, so a reader cannot tell what was chosen")
	}
}

func TestCorpusRunCapturesExchangesForSynchronousAndBackgroundRuns(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>stand</html>"))
	}))
	defer target.Close()

	for _, test := range []struct {
		name string
		run  func(*server, string) error
	}{
		{
			name: "synchronous",
			run: func(engine *server, url string) error {
				body := `{"url":"` + url + `","max_checks":1,"proxy":"http://127.0.0.1:1","capture_context":"corpus-sync"}`
				request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/corpus/run", strings.NewReader(body))
				recorder := httptest.NewRecorder()
				engine.scannerCorpusRun(recorder, request)
				if recorder.Code != http.StatusOK {
					return errors.New(recorder.Body.String())
				}
				return nil
			},
		},
		{
			name: "background",
			run: func(engine *server, url string) error {
				body := `{"url":"` + url + `","max_checks":1,"proxy":"http://127.0.0.1:1","capture_context":"corpus-job"}`
				request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/corpus/jobs", strings.NewReader(body))
				recorder := httptest.NewRecorder()
				engine.scannerCorpusJobs(recorder, request)
				if recorder.Code != http.StatusAccepted {
					return errors.New(recorder.Body.String())
				}
				var started struct {
					JobID string `json:"job_id"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
					return err
				}
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					job := engine.corpusJob(started.JobID)
					if job != nil && job.snapshot()["state"] != "running" {
						return nil
					}
					time.Sleep(10 * time.Millisecond)
				}
				return errors.New("corpus job did not finish before the test deadline")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := target.Client().Transport.(*http.Transport)
			store := passive.NewStore()
			engine := &server{
				store:     store,
				transport: transport,
				sourceIPTransport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return nil, errors.New("source IP lookup disabled in test")
				}),
			}
			if err := test.run(engine, target.URL); err != nil {
				t.Fatalf("run corpus: %v", err)
			}
			events := store.List()
			if len(events) == 0 {
				t.Fatal("corpus run sent requests but recorded none")
			}
			for _, event := range events {
				if event.Source != "tool" || !strings.HasPrefix(event.CaptureContext, "corpus-") {
					t.Fatalf("corpus request was not attributed: %+v", event)
				}
			}
		})
	}
}

func TestTheCorpusRunRouteRefusesATargetItCannotEnumerate(t *testing.T) {
	for _, body := range []string{`{"url":"not a url"}`, `{"url":""}`, `{"url":"/relative"}`, `{"url":"ftp://example.invalid/"}`, `not json`} {
		recorder := postCorpusRun(t, body)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("status = %d for %s, want 400", recorder.Code, body)
		}
	}
}

func TestTheCorpusRunRouteRefusesABoundItCannotHonour(t *testing.T) {
	for _, body := range []string{
		`{"url":"http://127.0.0.1:1/","max_checks":-1}`,
		`{"url":"http://127.0.0.1:1/","concurrency":-2}`,
		`{"url":"http://127.0.0.1:1/","timeout_ms":-3}`,
		`{"url":"http://127.0.0.1:1/","delay_ms":-4}`,
	} {
		recorder := postCorpusRun(t, body)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("status = %d for %s, want 400", recorder.Code, body)
		}
	}
}

func TestTheCorpusRunRouteRefusesAMethodThatWouldEnumerate(t *testing.T) {
	s := &server{}
	request := httptest.NewRequest(http.MethodGet, "/proxy/scanner/corpus/run", nil)
	recorder := httptest.NewRecorder()
	s.scannerCorpusRun(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d for a GET, want 405: a GET here would start a run from a link", recorder.Code)
	}
}
