package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"intruder/engine/pkg/scanner"
)

// resultStatuses are the outcomes that are themselves a claim about the target.
// Everything else has to carry a reason, because "this file did not check
// anything" and "this file checked and found nothing" are opposites.
var resultStatuses = map[string]bool{
	scanner.TemplateMatched:    true,
	scanner.TemplateNotMatched: true,
	scanner.TemplateDuplicate:  true,
	scanner.TemplateNoRequest:  false,
	scanner.TemplateWorkflow:   false,
	scanner.TemplateFlow:       false,
	scanner.TemplateUncompiled: false,
	scanner.TemplateSkipped:    false,
	scanner.TemplateInvalid:    false,
}

const chunkMarker = "#CHUNK\t"

func main() {
	corpus := flag.String("corpus", "", "corpus directory")
	target := flag.String("target", "", "live target URL")
	out := flag.String("out", "", "output TSV; existing chunks are resumed")
	chunkSize := flag.Int("chunk", 200, "files per chunk")
	limit := flag.Int("limit", 0, "use at most this many files (0 = all)")
	dastTarget := flag.String("dast-target", "", "target for chunks that need -dast (defaults to --target)")
	verifyOnly := flag.Bool("verify", false, "only check the accounting of an existing --out")
	flag.Parse()

	if *corpus == "" || *out == "" || (*target == "" && !*verifyOnly) {
		fmt.Fprintln(os.Stderr, "usage: corpuslive --corpus DIR --target URL --out FILE [--chunk N] [--dast-target URL] [--limit N] [--verify]")
		os.Exit(2)
	}
	files, err := corpusPaths(*corpus)
	if err != nil {
		fail("walk %s: %v", *corpus, err)
	}
	if *limit > 0 && *limit < len(files) {
		files = files[:*limit]
	}
	fmt.Fprintf(os.Stderr, "corpus %s: %d files\n", *corpus, len(files))

	done := readDoneChunks(*out)
	rows, err := readRows(*out)
	if err != nil {
		fail("read %s: %v", *out, err)
	}
	corpusRoot := *corpus
	if *verifyOnly {
		verify(corpusRoot, files, rows)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	chunkIndex := 0
	for start := 0; start < len(files); start += *chunkSize {
		end := start + *chunkSize
		if end > len(files) {
			end = len(files)
		}
		chunkIndex++
		chunk := files[start:end]
		key := fmt.Sprintf("%d\t%d\t%d", chunkIndex, start, end)
		if done[key] {
			continue
		}
		runChunk(ctx, corpusRoot, chunk, key, pickTarget(*target, *dastTarget, chunk, corpusRoot), *out, rows)
	}
	fmt.Fprintf(os.Stderr, "swept %d files in %d chunks in %s\n", len(files), chunkIndex, time.Since(started).Round(time.Second))
	verify(corpusRoot, files, rows)
}

// pickTarget routes a chunk to the DAST target when any of its documents asked
// for the fuzzing engine. Deciding it per chunk rather than per file keeps one
// run's accounting comparable: a chunk is one invocation, so one target.
func pickTarget(target, dastTarget string, chunk []string, corpus string) string {
	if strings.TrimSpace(dastTarget) == "" {
		return target
	}
	for _, path := range chunk {
		payload, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		meta, refused := scanner.ParseTemplateDocumentWithPath(string(payload), filepath.ToSlash(path))
		if refused == "" && meta.NeedsDAST() {
			return dastTarget
		}
	}
	return target
}

func runChunk(ctx context.Context, corpus string, chunk []string, key, target, out string, rows map[string]row) {
	label := fmt.Sprintf("chunk %s → %s (%d files)", key, target, len(chunk))
	fmt.Fprintf(os.Stderr, "== %s\n", label)
	started := time.Now()
	result, err := runCorpus(ctx, corpus, chunk, target)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// A cancelled chunk is not a finished chunk: its marker is not written,
			// so a resumed run does it again rather than counting an unfinished
			// batch as accounted for.
			fmt.Fprintf(os.Stderr, "== %s: %v (marker not written, the run resumes here)\n", label, err)
			os.Exit(130)
		}
		// A chunk that could not be staged produced no rows at all, so nothing is
		// written and no marker is either: the resumed run does it again instead of
		// counting a batch that never ran as accounted for.
		fmt.Fprintf(os.Stderr, "== %s: %v (no rows, no marker — the run resumes here)\n", label, err)
		return
	}
	appendRows(out, chunk, result.Templates, key, true)
	for _, item := range result.Templates {
		rows[relativeTo(corpus, item.Path)] = row{status: item.Status, reason: item.Reason}
	}
	counts := map[string]int{}
	for _, item := range result.Templates {
		counts[statusOrUnknown(item.Status)]++
	}
	fmt.Fprintf(os.Stderr, "== %s: %s %v\n", label, time.Since(started).Round(time.Second), counts)
	if result.Stats != nil {
		if exit := fmt.Sprint(result.Stats["exit_code"]); exit != "0" {
			fmt.Fprintf(os.Stderr, "   binary exited %s — see the run diagnostics\n", exit)
		}
	}
}

func appendRows(out string, chunk []string, templates []scanner.TemplateResult, key string, marker bool) {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fail("open %s: %v", out, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, item := range templates {
		fmt.Fprintf(w, "%s\t%s\t%s\n",
			filepath.ToSlash(item.Path),
			statusOrUnknown(item.Status),
			strings.ReplaceAll(strings.ReplaceAll(item.Reason, "\t", " "), "\n", " "))
	}
	if marker {
		fmt.Fprintf(w, "%s%s\n", chunkMarker, key)
	}
	_ = w.Flush()
}

// verify is the deliverable: a mechanical check that every file in the corpus is
// accounted for exactly once, that every row has a status, and that every status
// which is not a plain result carries a reason. A run that cannot be checked
// this way has not proven anything about the corpus, only about itself.
func verify(corpus string, files []string, rows map[string]row) {
	missing := make([]string, 0, 8)
	for _, path := range files {
		if _, ok := rows[relativeTo(corpus, path)]; !ok {
			missing = append(missing, relativeTo(corpus, path))
		}
	}
	counts := map[string]int{}
	reasonless := make([]string, 0, 8)
	for path, item := range rows {
		counts[item.status]++
		if needsReason(item.status) && strings.TrimSpace(item.reason) == "" {
			reasonless = append(reasonless, path+"\t"+item.status)
		}
	}
	sort.Strings(reasonless)
	fmt.Fprintf(os.Stderr, "\n== accounting\n")
	fmt.Fprintf(os.Stderr, "   corpus files: %d\n", len(files))
	fmt.Fprintf(os.Stderr, "   rows written: %d\n", len(rows))
	for _, status := range sortedKeys(counts) {
		fmt.Fprintf(os.Stderr, "   %8d  %s\n", counts[status], status)
	}
	executed := counts[scanner.TemplateMatched] + counts[scanner.TemplateNotMatched]
	fmt.Fprintf(os.Stderr, "   %8d  executed against the target (matched + not matched)\n", executed)
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "   %8d  MISSING from the accounting\n", len(missing))
		for _, path := range missing {
			fmt.Fprintf(os.Stderr, "     %s\n", path)
		}
	}
	if len(reasonless) > 0 {
		fmt.Fprintf(os.Stderr, "   %8d  rows with no reason where one is mandatory\n", len(reasonless))
		for _, line := range reasonless {
			fmt.Fprintf(os.Stderr, "     %s\n", line)
		}
	}
	if len(missing) > 0 || len(reasonless) != 0 {
		fmt.Fprintf(os.Stderr, "VERDICT: FAIL\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "VERDICT: PASS — every file accounted for, every non-result status has a reason\n")
}

func needsReason(status string) bool {
	if result, known := resultStatuses[status]; !known {
		return true
	} else {
		return !result
	}
}

type row struct {
	status string
	reason string
}

func readDoneChunks(path string) map[string]bool {
	done := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return done
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, chunkMarker) {
			done[strings.TrimPrefix(line, chunkMarker)] = true
		}
	}
	return done
}

func readRows(path string) (map[string]row, error) {
	rows := map[string]row{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rows, nil
		}
		return rows, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, chunkMarker) {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		reason := ""
		if len(parts) == 3 {
			reason = parts[2]
		}
		rows[parts[0]] = row{status: parts[1], reason: reason}
	}
	return rows, scanner.Err()
}

func runCorpus(ctx context.Context, corpus string, chunk []string, target string) (scanner.NucleiRun, error) {
	uploads := make([]scanner.UploadFile, 0, len(chunk))
	for _, path := range chunk {
		payload, err := os.ReadFile(path)
		if err != nil {
			return scanner.NucleiRun{}, err
		}
		uploads = append(uploads, scanner.UploadFile{
			Name:    filepath.Base(path),
			Path:    relativeTo(corpus, path),
			Content: string(payload),
		})
	}
	dir, staged, err := scanner.StageUploads(uploads)
	if err != nil {
		return scanner.NucleiRun{}, err
	}
	defer os.RemoveAll(dir)
	// The sweep must measure the product, not a narrower version of it: the scan
	// falls back to this project's own runner for the files the binary refuses, and
	// a sweep that left that path out would report losses the product does not have.
	return scanner.RunNucleiDir(ctx, dir, staged, scanner.NucleiRequest{
		URL:       target,
		Transport: http.DefaultTransport,
	})
}

func corpusPaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

func relativeTo(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

func statusOrUnknown(status string) string {
	if strings.TrimSpace(status) == "" {
		return "(empty)"
	}
	return status
}

func sortedKeys(counts map[string]int) []string {
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

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
