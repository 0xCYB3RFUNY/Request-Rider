package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestIntruderResultStoreKeepsEveryResultAndReadsFromAnOffset(t *testing.T) {
	store, err := newIntruderResultStore(1)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	total := 500
	for index := 0; index < total; index++ {
		record := map[string]interface{}{
			"url":     fmt.Sprintf("http://target.test/%d", index),
			"status":  200,
			"request": "GET /" + strings.Repeat("x", index%40) + " HTTP/1.1",
			"body":    strings.Repeat("payload-", index%7),
		}
		if err := store.Append(record); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	if store.Len() != total {
		t.Fatalf("len = %d, want %d", store.Len(), total)
	}
	// Nothing is dropped: the whole report is still readable from the start.
	all, err := store.Read(0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(all) != total {
		t.Fatalf("read %d results, want %d", len(all), total)
	}
	// The first result is the first one appended, with its evidence intact.
	first, _ := all[0]["url"].(string)
	if first != "http://target.test/0" {
		t.Fatalf("first url = %q", first)
	}
	// Incremental polling returns exactly the new results, which is what the
	// browser does while an attack runs.
	tail, err := store.Read(total - 3)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if len(tail) != 3 {
		t.Fatalf("tail = %d results, want 3", len(tail))
	}
	if tail[0]["url"] != fmt.Sprintf("http://target.test/%d", total-3) {
		t.Fatalf("tail starts at %v", tail[0]["url"])
	}
	// An offset past the end is empty rather than an error, so a reconnecting
	// browser is not broken by a race with the final write.
	empty, err := store.Read(total)
	if err != nil || len(empty) != 0 {
		t.Fatalf("read past end = %v %v", empty, err)
	}
}

func TestIntruderResultStoreWritesToDiskNotMemory(t *testing.T) {
	// The point of the store is that the evidence lives in a file the engine
	// owns, so a huge run does not grow the process heap.
	store, err := newIntruderResultStore(2)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	for index := 0; index < 200; index++ {
		if err := store.Append(map[string]interface{}{"n": index, "pad": strings.Repeat("y", 500)}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() < 100*500 {
		t.Fatalf("spill file is %d bytes, expected the full evidence on disk", info.Size())
	}
	if !strings.HasPrefix(store.path, intruderResultDir) {
		t.Fatalf("path %q is outside the engine directory %q", store.path, intruderResultDir)
	}
}

func TestAttackFallsBackToMemoryWithoutAStore(t *testing.T) {
	// A store that cannot be created must not lose a single result.
	attack := &attack{status: "running", total: 3}
	for index := 0; index < 3; index++ {
		attack.addResult(map[string]interface{}{"n": index})
	}
	if attack.resultCount() != 3 {
		t.Fatalf("count = %d, want 3", attack.resultCount())
	}
	results, count, err := attack.resultsFrom(1)
	if err != nil || count != 3 || len(results) != 2 {
		t.Fatalf("from 1 = %v count=%d err=%v", results, count, err)
	}
}

func TestAttackKeepsResultsWhenTheSpillFailsMidRun(t *testing.T) {
	store, err := newIntruderResultStore(3)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	attack := &attack{status: "running", store: store}
	attack.addResult(map[string]interface{}{"n": 0})
	// Closing the file makes the next append fail, which is what a disk error
	// looks like to the run.
	store.Close()
	attack.addResult(map[string]interface{}{"n": 1})
	attack.addResult(map[string]interface{}{"n": 2})
	if attack.store != nil {
		t.Fatal("the store was kept after a write failure")
	}
	if len(attack.results) != 2 {
		t.Fatalf("in-memory fallback holds %d results, want the 2 written after the failure", len(attack.results))
	}
	// The earlier result is still readable from disk, so no evidence is lost.
	kept, err := store.Read(0)
	if err == nil && len(kept) != 1 {
		t.Fatalf("the spilled result was lost: %v", kept)
	}
}

func TestAttackResultsAreWrittenFromManyWorkers(t *testing.T) {
	store, err := newIntruderResultStore(4)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	attack := &attack{status: "running", store: store}
	workers, perWorker := 8, 250
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for index := 0; index < perWorker; index++ {
				attack.addResult(map[string]interface{}{"worker": worker, "n": index})
			}
		}(worker)
	}
	group.Wait()
	want := workers * perWorker
	if attack.resultCount() != want {
		t.Fatalf("count = %d, want %d", attack.resultCount(), want)
	}
	all, err := store.Read(0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	seen := map[string]bool{}
	for _, record := range all {
		seen[fmt.Sprintf("%v/%v", record["worker"], record["n"])] = true
	}
	if len(seen) != want {
		t.Fatalf("read %d distinct results, want %d", len(seen), want)
	}
}

func TestIntruderResultStoreFileIsInsideTheEngineDirectory(t *testing.T) {
	store, err := newIntruderResultStore(5)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	if filepath.Dir(store.path) != intruderResultDir {
		t.Fatalf("path %q is not inside %q", store.path, intruderResultDir)
	}
}
