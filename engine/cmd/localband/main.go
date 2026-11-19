package main

// cmd/localband вимірює, скільки шаблонів корпусу цей проєкт виконує сам.
//
// Навіщо окремий стенд, коли є `corpuslive`: `corpuslive` запускає бінарник
// nuclei і рахує, що зробив він. Цей стенд рахує, що робить наш власний раннер
// (`scanner.RunTemplateLocally`), через той самий облік і з тією самою формою
// рядка. Тому два числа можна порівняти прямо, а не на око.
//
// Кожен рядок має статус і причину. Відмова без причини не рахується: вона
// перетворює «ми вміємо N» на число, яке ніхто не може перевірити.
//
// Виміряно на 4 000 `http`-шаблонів офіційного корпусу до цієї фази: пасивна
// смуга оцінює 2 978 (74.5 %), з них 897 відмов — «the document declares N
// request blocks». Цей стенд існує, щоб після кожної фази це число можна було
// виміряти знову, а не запам'ятати.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"intruder/engine/pkg/scanner"
)

// row is one template's outcome, with the path it came from.
//
// The path is part of the row rather than computed at write time: the first
// version of this harness derived it from the status, so every row carried the
// same wrong first column and the refusal list could not be traced to a file.
type row struct {
	path   string
	status string
	reason string
}

func main() {
	corpus := flag.String("corpus", "", "corpus directory")
	target := flag.String("target", "", "live target URL")
	out := flag.String("out", "", "output TSV")
	limit := flag.Int("limit", 0, "use at most this many files (0 = all)")
	timeoutSec := flag.Int("timeout", 30, "per-template wall-clock bound, seconds")
	oastURL := flag.String("oast", "", "OAST provider for {{interactsh-url}}; empty measures without one")
	flag.Parse()

	if *corpus == "" || *out == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: localband --corpus DIR --target URL --out FILE [--limit N] [--timeout SEC]")
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

	rows := make([]row, 0, len(files))
	var matched, matchedNamed int
	began := time.Now()
	for index, path := range files {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			rows = append(rows, row{path: path, status: "unreadable", reason: readErr.Error()})
			continue
		}
		run := runOne(path, string(payload), *target, *timeoutSec, *oastURL)
		if run.Matched {
			matched++
			if run.Name != "" {
				matchedNamed++
			}
		}
		rows = append(rows, row{path: path, status: statusFor(run), reason: run.Reason})
		if (index+1)%500 == 0 {
			fmt.Fprintf(os.Stderr, "  %d/%d  %.1fs\n", index+1, len(files), time.Since(began).Seconds())
		}
	}

	report(rows, matched, matchedNamed, len(files), time.Since(began))
	if err := write(*out, rows); err != nil {
		fail("write %s: %v", *out, err)
	}
}

// runOne gives one template a wall-clock bound, because a template that never
// returns must not turn a measurement into a hang.
// runOne gives one template a wall-clock bound, because a template that never
// returns must not turn a measurement into a hang.
//
// `--oast` is the operator's provider, not a fixture this tool invents: an
// interactsh-protocol server is somebody else's infrastructure, and a local stand-in
// would report callbacks that never came from a target.
// runOne performs one document under a hard wall-clock bound.
//
// The context bound alone was not enough, and that is measured, not assumed: a
// corpus sweep reached **12 500 of 98 662** and then stood still for 19 minutes on
// `gcloud-unrestricted-sqlserver-access.yaml` and its neighbours — `code:` documents
// that execute a **local command**. A local command does not read this context, so
// `context.WithTimeout` expired while the document kept running, the sweep never
// got its result, and the whole run stopped producing rows. The context is still
// passed (it bounds the HTTP side), and a goroutine plus a timer now bounds the
// document itself, so no single document can stop a sweep again.
//
// The abandoned goroutine is deliberately not waited for: the point is to move on,
// and the row records the deadline instead of claiming a verdict.
func runOne(path, content, target string, timeoutSec int, oastURL string) scanner.LocalRun {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	if provider := strings.TrimSpace(oastURL); provider != "" {
		ctx = scanner.WithOASTSource(ctx, &scriptedOAST{base: provider})
	}
	type outcome struct{ run scanner.LocalRun }
	done := make(chan outcome, 1)
	go func() {
		done <- outcome{scanner.RunTemplateLocally(ctx, content, target,
			&measuredTransport{inner: http.DefaultTransport})}
	}()
	// The grace is the time the inner code needs to notice the cancelled context and
	// return on its own. It is bounded, so a document that ignores both still ends.
	select {
	case result := <-done:
		return result.run
	case <-time.After(time.Duration(timeoutSec+10) * time.Second):
		return scanner.LocalRun{
			Skipped: true,
			Reason: fmt.Sprintf(
				"this document did not finish within %d s and was abandoned; a `code:` or "+
					"`file:` document runs a local command, and a local command does not read "+
					"the context this sweep gave it", timeoutSec),
		}
	}
}

// scriptedOAST registers through the engine's own provider API rather than
// speaking the protocol here, so this harness and the product share one client.
type scriptedOAST struct {
	base string
	seq  int
}

func (s *scriptedOAST) NewPayload(context.Context) (string, error) {
	s.seq++
	payload := fmt.Sprintf("%s/rr-scanner-%d", strings.TrimRight(s.base, "/"), s.seq)
	register, err := http.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(
		fmt.Sprintf(`{"listener_id":"rr-scanner-%d","protocols":["http","https"]}`, s.seq)))
	if err != nil {
		return "", err
	}
	register.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(os.Getenv("OAST_AUTH_TOKEN")); token != "" {
		register.Header.Set("Authorization", token)
	}
	response, err := http.DefaultClient.Do(register)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return "", fmt.Errorf("provider answered %s to a registration", response.Status)
	}
	return payload, nil
}

// Await polls the provider for this payload's events, exactly as the engine's own
// listener does.
func (s *scriptedOAST) Await(ctx context.Context, payloadURL string, wait time.Duration) (bool, error) {
	deadline := time.Now().Add(wait)
	endpoint := s.base + "/poll?listener_id=rr-scanner-" + payloadURL[strings.LastIndex(payloadURL, "-")+1:]
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return false, err
		}
		if token := strings.TrimSpace(os.Getenv("OAST_AUTH_TOKEN")); token != "" {
			request.Header.Set("Authorization", token)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return false, err
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			return false, readErr
		}
		if strings.Contains(string(body), `"events":[`) {
			var decoded struct {
				Events []map[string]interface{} `json:"events"`
			}
			if json.Unmarshal(body, &decoded) == nil && len(decoded.Events) > 0 {
				return true, nil
			}
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// statusFor turns a run into a status the accounting can count.
//
// The order matters more than it looks. A run that named a reason has produced no
// verdict, and the only question left is whether it *tried*: a check that was
// attempted and failed is an error, and a check that could not be built is a
// refusal. Everything else is a negative.
//
// The default used to be `not_matched`, and that was the same dishonesty this
// runner exists to remove — in the measuring tool rather than the runner. Measured
// on 500 `code:` templates of the official corpus: 434 were refused with «cannot
// read the flow expression» and were reported as `not_matched`, so the harness
// published 99.8 % coverage for a document in which one template had actually
// produced a verdict. A default that claims a verdict for a check that did not
// happen cannot be repaired by adding more substring rules underneath it, so the
// default is now `refused` and the attempted failures are named explicitly.
func statusFor(run scanner.LocalRun) string {
	switch {
	case run.Matched:
		return "matched"
	case run.Skipped:
		return "refused"
	case run.Reason == "":
		return "not_matched"
	case strings.Contains(run.Reason, "request failed") ||
		strings.Contains(run.Reason, "cannot read the response") ||
		strings.Contains(run.Reason, "script failed") ||
		strings.Contains(run.Reason, "RR_CODE_TIMEOUT_SEC"):
		return "transport_error"
	default:
		return "refused"
	}
}

// measuredTransport counts the requests the runner actually made, so a template
// that is reported as refused can be shown to have sent nothing.
type measuredTransport struct {
	inner http.RoundTripper
	sent  int
}

// RoundTrip counts and forwards. It deliberately does not touch the body.
//
// It did once, to measure it, and that silently emptied it: every request that
// carried a body then failed with `http: ContentLength=595 with Body length 0`,
// which read as 916 broken templates when it was one broken line in this harness.
// A measuring tool that alters what it measures is worse than one that measures
// less.
func (m *measuredTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	m.sent++
	return m.inner.RoundTrip(request)
}

func report(rows []row, matched, matchedNamed, total int, elapsed time.Duration) {
	counts := map[string]int{}
	reasons := map[string]int{}
	for _, entry := range rows {
		counts[entry.status]++
		if entry.status != "matched" && entry.status != "not_matched" && entry.reason != "" {
			reasons[reasonKey(entry.reason)]++
		}
	}
	fmt.Fprintf(os.Stderr, "\n== our runner over %d files in %s\n", total, elapsed.Round(time.Millisecond))
	keys := make([]string, 0, len(counts))
	for status := range counts {
		keys = append(keys, status)
	}
	sort.Slice(keys, func(i, j int) bool { return counts[keys[i]] > counts[keys[j]] })
	for _, status := range keys {
		fmt.Fprintf(os.Stderr, "  %6d  %5.1f%%  %s\n", counts[status], float64(counts[status])*100/float64(total), status)
	}
	fmt.Fprintf(os.Stderr, "\n  templates that matched: %d (%.1f%%), of which %d carried a name\n",
		matched, float64(matched)*100/float64(total), matchedNamed)
	if len(reasons) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nwhy the rest are not executed:\n")
	reasonKeys := make([]string, 0, len(reasons))
	for key := range reasons {
		reasonKeys = append(reasonKeys, key)
	}
	sort.Slice(reasonKeys, func(i, j int) bool { return reasons[reasonKeys[i]] > reasons[reasonKeys[j]] })
	for index, key := range reasonKeys {
		if index >= 14 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(reasonKeys)-index)
			break
		}
		fmt.Fprintf(os.Stderr, "  %6d  %s\n", reasons[key], key)
	}
}

// reasonKey collapses a reason to its first sentence, so templates that differ
// only in a count or a file name are counted together.
func reasonKey(reason string) string {
	trimmed := strings.TrimSpace(reason)
	if index := strings.Index(trimmed, ". "); index > 0 && index < 140 {
		return trimmed[:index+1]
	}
	if len(trimmed) > 140 {
		return trimmed[:140]
	}
	return trimmed
}

func write(path string, rows []row) error {
	handle, err := os.Create(path)
	if err != nil {
		return err
	}
	defer handle.Close()
	for _, entry := range rows {
		fmt.Fprintf(handle, "%s\t%s\t%s\n", entry.path, entry.status, entry.reason)
	}
	return nil
}

func corpusPaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
