package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestCorpusProbe stages a real template tree through the same plan the scanner
// uses and reports what the plan decided. It is how the fixes in this package
// were measured against a real collection, and it is skipped unless a tree is
// named, because a corpus of hundreds of thousands of files is not something a
// unit test may assume exists.
//
//	RR_NUCLEI_CORPUS=/path/to/templates go test ./pkg/scanner/ -run TestCorpusProbe -v -count=1
//	RR_NUCLEI_CORPUS_LIMIT=20000 go test ./pkg/scanner/ -run TestCorpusProbe -v -count=1
//	RR_NUCLEI_CORPUS_VALIDATE=0 go test ./pkg/scanner/ -run TestCorpusProbe -v -count=1
func TestCorpusProbe(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("RR_NUCLEI_CORPUS"))
	if root == "" {
		t.Skip("set RR_NUCLEI_CORPUS to a template tree to probe it")
	}
	limit := envInt("RR_NUCLEI_CORPUS_LIMIT", 0)
	validate := os.Getenv("RR_NUCLEI_CORPUS_VALIDATE") != "0"

	paths, err := corpusFiles(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if limit > 0 && len(paths) > limit {
		paths = paths[:limit]
	}
	t.Logf("files in tree: %d", len(paths))

	dir := t.TempDir()
	staged := make([]StagedFile, 0, len(paths))
	accepted, rejected := 0, 0
	reasons := map[string]int{}
	for index, path := range paths {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		relative := corpusRelative(root, path)
		target := filepath.Join(dir, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(target, payload, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		meta, reason := parseTemplateDocumentWithPath(string(payload), relative)
		file := StagedFile{UploadName: filepath.Base(path), RelativePath: relative}
		if reason != "" {
			file.Reason = reason
			rejected++
			reasons[corpusReasonKey(reason)]++
		} else {
			meta.Digest = digestOf(string(payload))
			file.Meta = meta
			file.StagedPath = target
			accepted++
		}
		staged = append(staged, file)
		if index%5000 == 4999 {
			t.Logf("staged %d/%d", index+1, len(paths))
		}
	}
	t.Logf("staged=%d accepted_by_header=%d rejected_by_header=%d", len(staged), accepted, rejected)
	for _, key := range corpusSorted(reasons) {
		t.Logf("  reject %8d  %s", reasons[key], key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	_ = ctx
	// `RR_NUCLEI_CORPUS_VALIDATE` no longer selects a validation step: the
	// `-validate` pass is gone (see `validationStepFor`), so a plan is built the same
	// way here as it is in a run. The variable is still read so an old invocation of
	// this probe does not fail on an unknown flag, but it has nothing left to turn on.
	request := PlanRequest{Dir: dir, Staged: staged}
	if validate {
		t.Logf("RR_NUCLEI_CORPUS_VALIDATE is set but validation is no longer run; " +
			"the plan below is the one a run would build")
	}
	plan, err := BuildPlan(request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	defer plan.Clean()

	t.Logf("plan: batches=%d planned=%d unplanned=%d id_multiplicity=%d",
		len(plan.Batches), plan.Planned(), len(plan.ledger), plan.Describe()["id_multiplicity"])
	groups := map[string]int{}
	perBatch := map[string][]int{}
	for _, batch := range plan.Batches {
		label := "(none)"
		if len(batch.Capabilities) > 0 {
			names := make([]string, 0, len(batch.Capabilities))
			for _, capability := range batch.Capabilities {
				names = append(names, string(capability))
			}
			label = strings.Join(names, "+")
		}
		groups[label]++
		perBatch[label] = append(perBatch[label], len(batch.Files))
	}
	for _, label := range corpusSorted(groups) {
		t.Logf("  capability %-28s batches=%-6d files=%v", label, groups[label], sumInts(perBatch[label]))
	}
	if dedup, ok := plan.Describe()["deduplication"].(map[string]interface{}); ok {
		encoded, _ := json.Marshal(dedup["files_uploaded"])
		unique, _ := json.Marshal(dedup["unique_content"])
		collapsed, _ := json.Marshal(dedup["collapsed"])
		t.Logf("dedup: files=%s unique=%s collapsed=%s", encoded, unique, collapsed)
	}

	seen := map[string]int{}
	for _, batch := range plan.Batches {
		for _, file := range batch.Files {
			seen[file.Key]++
		}
	}
	for _, entry := range plan.ledger {
		seen[entry.key]++
	}
	duplicated := 0
	for _, count := range seen {
		if count > 1 {
			duplicated++
		}
	}
	t.Logf("accounting: distinct_keys=%d planned_or_ledger=%d duplicated=%d", len(seen), len(staged), duplicated)
	if duplicated != 0 {
		t.Errorf("%d files were accounted for more than once", duplicated)
	}
}

func sumInts(values []int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value := 0
	for _, symbol := range raw {
		if symbol < '0' || symbol > '9' {
			return fallback
		}
		value = value*10 + int(symbol-'0')
	}
	if value <= 0 {
		return fallback
	}
	return value
}

func corpusFiles(root string) ([]string, error) {
	files := make([]string, 0, 8192)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func corpusRelative(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

func corpusReasonKey(reason string) string {
	trimmed := strings.TrimSpace(reason)
	if index := strings.Index(trimmed, "—"); index > 0 {
		return strings.TrimSpace(trimmed[:index])
	}
	return trimmed
}

func corpusSorted(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}
