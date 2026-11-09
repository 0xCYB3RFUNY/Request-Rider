package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The bucket phase probes every candidate against every provider, so the pool is
// the only thing that decides how long a large wordlist takes. These tests exist
// because a pool that silently skipped work, reordered rows, or never actually
// overlapped would look exactly like a working one in the UI.

func TestBucketChecksHonourTheExplicitPoolAndKeepEveryProbe(t *testing.T) {
	candidates := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	providers := bucketProviderOrder

	measure := func(workers int) (int, []bucketAnswer) {
		var mu sync.Mutex
		inFlight, peak := 0, 0
		probed := map[string]bool{}
		probe := func(_ context.Context, url, _ string) (int, bool) {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			probed[url] = true
			mu.Unlock()
			time.Sleep(15 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			// One provider in three answers, so the answers are not all-or-nothing
			// and a lost probe has to be visible in the count.
			if strings.Contains(url, "blob.core.windows.net") {
				return 200, true
			}
			return 404, false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		answers, _ := checkBucketCandidates(ctx, nil, candidates, providers, workers, probe)
		if len(probed) != len(candidates)*len(providers) {
			t.Fatalf("pool of %d probed %d of %d candidate/provider pairs", workers, len(probed), len(candidates)*len(providers))
		}
		return peak, answers
	}

	serialPeak, serialAnswers := measure(1)
	widePeak, wideAnswers := measure(4)
	if serialPeak != 1 {
		t.Fatalf("a pool of one must not overlap probes, peak = %d", serialPeak)
	}
	if widePeak < 2 {
		t.Fatalf("a pool of four must overlap probes, peak = %d", widePeak)
	}
	if len(serialAnswers) != len(candidates) || len(wideAnswers) != len(candidates) {
		t.Fatalf("pool size changed the answers: %d serial vs %d wide", len(serialAnswers), len(wideAnswers))
	}
}

// A report that reorders its rows between two runs of the same wordlist cannot be
// compared, so completion order must not leak into the result. A probe that gets
// slower the earlier it is queued makes any leak impossible to miss.
func TestBucketCheckOrderIsTheInputOrderNotTheCompletionOrder(t *testing.T) {
	candidates := []string{"first", "second", "third"}
	providers := bucketProviderOrder
	var callOrder []int
	var mu sync.Mutex
	probe := func(_ context.Context, url, _ string) (int, bool) {
		mu.Lock()
		callOrder = append(callOrder, len(callOrder))
		position := len(callOrder)
		mu.Unlock()
		// The first candidate is the slowest, so completion order is the exact
		// reverse of the input order.
		time.Sleep(time.Duration(30-position*8) * time.Millisecond)
		return 200, true
	}
	answers, applied := checkBucketCandidates(context.Background(), nil, candidates, providers, 6, probe)
	if applied != 6 {
		t.Fatalf("applied pool = %d, want the requested 6", applied)
	}
	if len(answers) != len(candidates)*len(providers) {
		t.Fatalf("answers = %d, want %d", len(answers), len(candidates)*len(providers))
	}
	for index, answer := range answers {
		wantCandidate := candidates[index/len(providers)]
		wantProvider := providers[index%len(providers)]
		if answer.candidate != wantCandidate || answer.provider != wantProvider {
			t.Fatalf("row %d = %s/%s, want %s/%s", index, answer.candidate, answer.provider, wantCandidate, wantProvider)
		}
	}
}

// A pause must be observable between probes, like the DNS phase. Without a
// checkpoint the whole candidate list is already in flight before a pause can be
// seen, which is the same reason the DNS phase is worth a pool at all.
func TestBucketChecksAreAPausePoint(t *testing.T) {
	gate := newPauseGate()
	job := &osintJob{ID: "osint-buckets", done: make(chan struct{}), gate: gate}
	collector := &transformCollector{
		job:      job,
		indexes:  3,
		ctx:      context.Background(),
		stop:     make(chan struct{}),
		progress: func(transformProgress) {},
	}
	var mutex sync.Mutex
	probed := 0
	probe := func(context.Context, string, string) (int, bool) {
		mutex.Lock()
		probed++
		mutex.Unlock()
		return 200, true
	}
	candidates := make([]string, 20)
	for index := range candidates {
		candidates[index] = fmt.Sprintf("name%d", index)
	}
	total := len(candidates) * len(bucketProviderOrder)
	// The gate is closed before the phase starts, so a paused phase must not run
	// to the end.
	gate.pause()
	done := make(chan int, 1)
	go func() {
		answers, _ := checkBucketCandidates(context.Background(), collector, candidates, bucketProviderOrder, 4, probe)
		done <- len(answers)
	}()
	select {
	case answers := <-done:
		t.Fatalf("a paused phase ran to the end with %d answers", answers)
	case <-time.After(150 * time.Millisecond):
	}
	mutex.Lock()
	pausedProbes := probed
	mutex.Unlock()
	if pausedProbes > 4 {
		t.Fatalf("a paused phase probed %d times, more than the pool holds", pausedProbes)
	}
	// The resume releases it and every candidate is still probed against every
	// provider, so the pause suspends the work instead of discarding it.
	gate.resume()
	answers := <-done
	if answers != total {
		t.Fatalf("the resumed phase probed %d of %d candidate/provider pairs", answers, total)
	}
	mutex.Lock()
	finalProbes := probed
	mutex.Unlock()
	if finalProbes != total {
		t.Fatalf("the resumed phase ran %d probes, want %d", finalProbes, total)
	}
}

func TestConcurrencyOptionPrefersTheGenericKeyAndKeepsTheLegacyOne(t *testing.T) {
	cases := []struct {
		name    string
		options map[string]interface{}
		want    int
	}{
		{"nothing named", map[string]interface{}{}, 8},
		{"generic key", map[string]interface{}{"concurrency": float64(24)}, 24},
		{"generic key as text", map[string]interface{}{"concurrency": "12"}, 12},
		// The DNS phase was already driven with this key, and a saved
		// configuration still carries it. Dropping it would reset the operator's
		// choice back to the default without saying so.
		{"legacy dns key still works", map[string]interface{}{"dns_concurrency": float64(16)}, 16},
		{"generic wins over legacy", map[string]interface{}{"concurrency": float64(4), "dns_concurrency": float64(16)}, 4},
		{"zero falls back", map[string]interface{}{"concurrency": float64(0)}, 8},
		{"negative falls back", map[string]interface{}{"concurrency": float64(-4)}, 8},
		{"unreadable falls back", map[string]interface{}{"concurrency": "many"}, 8},
		{"wrong type falls back", map[string]interface{}{"concurrency": true}, 8},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := concurrencyOption(testCase.options, 8); got != testCase.want {
				t.Fatalf("concurrencyOption = %d, want %d", got, testCase.want)
			}
		})
	}
}

// The dialog decides whether to show the control by reading this registry, so a
// transform that gains a pool and forgets to declare it loses the control
// silently. The default the registry states is the number the code actually uses,
// or the field's placeholder describes a value that never applies.
func TestTransformRegistryDeclaresThePoolItRuns(t *testing.T) {
	declared := map[string]map[string]interface{}{}
	for _, item := range transformRegistry {
		id, _ := item["id"].(string)
		declared[id] = item
	}
	for id, wantDefault := range map[string]int{
		"subdomains": bruteForceDefaultWorkers,
		"s3_buckets": bucketCheckDefaultWorkers,
	} {
		item, ok := declared[id]
		if !ok {
			t.Fatalf("transform %q is not in the registry, so the UI cannot learn anything about it", id)
		}
		if enabled, _ := item["concurrency"].(bool); !enabled {
			t.Fatalf("transform %q has a pool but does not declare the concurrency capability", id)
		}
		if item["concurrency_default"] != wantDefault {
			t.Fatalf("transform %q declares default %v, the code uses %d", id, item["concurrency_default"], wantDefault)
		}
	}
	// A transform with no loop of its own must not claim one: a field shown for a
	// single lookup is a field the operator can set and watch being ignored.
	for id, item := range declared {
		switch id {
		case "subdomains", "s3_buckets":
			continue
		}
		if _, claimed := item["concurrency"]; claimed {
			t.Fatalf("transform %q declares a concurrency capability it does not have", id)
		}
	}
}

// Google Storage answers **403 for every name**, including one that was never
// created, so the shared endpoint cannot distinguish a bucket that exists from a
// refusal. Measured 2026-10-02 on a live run: `s3_buckets` with the candidate
// `zzz-definitely-not-a-real-bucket-99887766` stored it as a GCP finding, so any
// domain produced a guaranteed false positive.
func TestGCP403IsNotProofThatTheBucketExists(t *testing.T) {
	owned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What the per-bucket domain does for a name Storage does not hold.
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer owned.Close()

	if exists, err := gcpBucketExists(context.Background(), owned.Client(), owned.URL, "probe"); err != nil || exists {
		t.Fatalf("a name the per-bucket domain refuses must not count as existing: %v %v", exists, err)
	}
}

// The other direction: a bucket that really exists is still found. AWS answers 404
// for a name it does not hold and 403 for one it holds but will not list, so a 403
// there is a finding and this fix must not swallow it.
func TestGCP403OnAnExistingBucketIsStillAFinding(t *testing.T) {
	owned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer owned.Close()
	exists, err := gcpBucketExists(context.Background(), owned.Client(), owned.URL, "real-bucket")
	if err != nil {
		t.Fatalf("gcpBucketExists: %v", err)
	}
	if !exists {
		t.Fatal("a bucket the per-bucket domain refuses to list still exists, and refusing to list is not the same as not existing")
	}
}

// The candidate name has to come back out of the probed URL, or the second question
// is asked about the wrong name.
func TestCandidateNameReadsTheBucketBackOutOfTheProbedURL(t *testing.T) {
	cases := map[string]string{
		"https://zzz-bucket.s3.amazonaws.com/":        "zzz-bucket",
		"https://storage.googleapis.com/some-bucket/": "some-bucket",
		"https://some-bucket.blob.core.windows.net/":  "some-bucket",
	}
	for probed, want := range cases {
		if got := candidateName(probed); got != want {
			t.Errorf("candidateName(%q) = %q, want %q", probed, got, want)
		}
	}
}

// The probe path itself, not only the helper. This is the assertion a test of the
// helper alone is missing: `gcpBucketExists` can be correct while the transform
// still stores an invented bucket, because the branch that calls it does not run.
// So the test drives `s3_buckets` end to end against two servers — the shared
// endpoint that answers 403 for everything, and the per-bucket domain that answers
// 404 — and asserts that nothing came back.
func TestS3BucketsDoesNotStoreAGCPNameThatDoesNotExist(t *testing.T) {
	var asked []string
	perBucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer perBucket.Close()
	shared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every name, invented or not, gets this.
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer shared.Close()

	originals := bucketProviderURLs
	defer func() { bucketProviderURLs = originals }()
	// The template must carry the `%s` the pool substitutes the candidate into,
	// exactly as the real provider table does. Without it `fmt.Sprintf` appends the
	// argument as `%!(EXTRA string=...)` and the test silently probes nothing.
	bucketProviderURLs = map[string]string{
		"gcp_storage": shared.URL + "/%s/",
	}
	result := osintTransformResult{Transform: "s3_buckets"}
	if err := transformS3Buckets(&server{gcpBucketBase: perBucket.URL, transport: shared.Client().Transport.(*http.Transport)},
		context.Background(), &result, osintTransformInput{
			Transform: "s3_buckets", Value: "pravda.ru", ConfirmNetwork: true, EntityType: "domain",
			Options: map[string]interface{}{"candidates": []interface{}{"zzz-definitely-not-a-real-bucket-99887766"}},
		}, nil); err != nil {
		t.Fatalf("s3_buckets: %v", err)
	}
	if len(asked) == 0 {
		t.Fatal("the follow-up question was never asked, so 403 was accepted as " +
			"existence and the test proves nothing")
	}
	for _, item := range result.Entities {
		if item.Type == "cloud_asset" {
			t.Fatalf("stored %q as a finding; Google answers 403 for every name, "+
				"so this says nothing about the bucket existing", item.Identity)
		}
	}
}
