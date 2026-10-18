package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A04-11 — the capture token travelled as an argv value.
//
// `-H "X-RequestRider-Capture-Context: <token>"` puts the token in the argv of the nuclei
// process, and argv is world-readable on Linux: `ps -ef` shows it for as long as the scan
// runs. It also landed in `stats["args"]`, which the engine streams to the browser over
// SSE, so the token reached two places it had no reason to be.
//
// nuclei v3.11.1 declares `-H` with `goflags.FileStringSliceOptions`
// (`cmd/nuclei/main.go:359`), so a value naming an existing file is read from that file
// rather than treated as a literal header. That is what makes the token removable from
// argv without changing what the binary receives.

func TestCaptureTokenIsNotInTheArgumentVector(t *testing.T) {
	const token = "s3cret-capture-token-value"
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		URL:     "http://target.test/",
		Headers: map[string]string{"X-RequestRider-Capture-Context": token},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(args)

	joined := strings.Join(args, " ")
	if strings.Contains(joined, token) {
		t.Fatalf("the capture token is in argv, so `ps -ef` shows it during the run: %v", args)
	}
	// The header must still be requested — removing the token from argv is only correct
	// if the token still reaches the proxy.
	if !strings.Contains(joined, "-H") {
		t.Fatalf("the correlation header was dropped along with the token: %v", args)
	}
}

func TestTheHeaderIsPassedAsAFileNucleiCanRead(t *testing.T) {
	const token = "s3cret-capture-token-value"
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		URL:     "http://target.test/",
		Headers: map[string]string{"X-RequestRider-Capture-Context": token},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(args)

	index := indexOfArg(args, "-H")
	if index < 0 || index+1 >= len(args) {
		t.Fatalf("no -H value in %v", args)
	}
	path := args[index+1]
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("-H names %q, which is not a file nuclei can read: %v", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the header file is %v, so another user on the machine can read the token", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read header file: %v", err)
	}
	if !strings.Contains(string(body), token) {
		t.Fatalf("the file does not carry the token, so nuclei would send no header at all:\n%s", body)
	}
	if !strings.Contains(string(body), "X-RequestRider-Capture-Context") {
		t.Fatalf("the header name is missing from the file:\n%s", body)
	}
}

func TestHeaderFileIsRemovedAfterTheRun(t *testing.T) {
	// A leftover 0600 file holding a capture token is still a secret in a temp directory
	// for the rest of the process's life, and the token exists to identify one run.
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		URL:     "http://target.test/",
		Headers: map[string]string{"X-RequestRider-Capture-Context": "token-to-forget"},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	path := args[indexOfArg(args, "-H")+1]
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the header file was never created: %v", err)
	}
	removeNucleiHeaderFiles(args)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the header file survived the run and still holds the token: %v", err)
	}
}

func TestHeaderFileLinesAreSorted(t *testing.T) {
	// `stats.args` is kept verbatim in the report, and a Go map iterates in random order,
	// so an unsorted walk would make two runs of one template folder incomparable.
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		URL: "http://target.test/",
		Headers: map[string]string{
			"Z-Last": "3", "A-First": "1", "M-Middle": "2",
		},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(args)
	body, err := os.ReadFile(args[indexOfArg(args, "-H")+1])
	if err != nil {
		t.Fatalf("read header file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	want := []string{"A-First: 1", "M-Middle: 2", "Z-Last: 3"}
	if len(lines) != len(want) {
		t.Fatalf("got %d header lines, want %d:\n%s", len(lines), len(want), body)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("header line %d is %q, want %q (sorted order keeps runs comparable)", i, lines[i], want[i])
		}
	}
}

func TestHeaderFileLivesOutsideTheStagingDirectory(t *testing.T) {
	// It is read by name from argv, so anything under the staged template tree would be
	// swept into the upload report as if it were a template.
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		URL: "http://target.test/", Headers: map[string]string{"X-RequestRider-Capture-Context": "t"},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(args)
	path := args[indexOfArg(args, "-H")+1]
	if strings.HasPrefix(filepath.Clean(path), "/tmp/staged") {
		t.Fatalf("the header file was written inside the staged template directory: %s", path)
	}
}

// The shipped call site, not the helper.
//
// `TestHeaderFileIsRemovedAfterTheRun` calls the removal function itself, so it passed
// even with the `defer` deleted from `runNucleiBatch` — the test proved the helper works,
// not that anything calls it. This is the same gap the audit found in A01-02, where tests
// exercised a helper directly and the real view never declared itself.
func TestTheBatchThatBuildsTheFileIsTheBatchThatRemovesIt(t *testing.T) {
	source := readSourceFile(t, "nuclei_exec.go")
	batch := functionBody(t, source, "func executeBatch(ctx context.Context, batch NucleiBatch, target string, request NucleiRequest) (batchOutcome, error) {")
	if len(batch) == 0 {
		t.Fatal("executeBatch not found; the source reader stopped matching")
	}
	if !strings.Contains(batch, "removeNucleiHeaderFiles(args)") {
		t.Fatalf("executeBatch builds the header file but never removes it, so the capture "+
			"token stays in a temp file for the rest of the process's life:\n%s", batch)
	}
	// It has to be deferred, or it is skipped on every early return — and the early
	// returns are the normal path for a cancelled scan.
	if !strings.Contains(batch, "defer removeNucleiHeaderFiles(args)") {
		t.Fatalf("the removal is not deferred, so cancellation and every error path leave "+
			"the file behind:\n%s", batch)
	}
	// The file must also not reach the browser: `stats.args` is streamed over SSE.
	if strings.Contains(batch, "outcome.Args = args") {
		t.Fatalf("the recorded argument vector is the raw one, so the header-file path is "+
			"streamed to the browser:\n%s", batch)
	}
	if !strings.Contains(batch, "outcome.Args = redactNucleiHeaderFiles(args)") {
		t.Fatalf("the recorded argument vector is not redacted:\n%s", batch)
	}
}

// No package-level registry of header files: batches run in parallel and a shared slice
// would be a data race, which is exactly what `-race` reported when the first version
// used one.
func TestHeaderFilesAreNotTrackedInSharedState(t *testing.T) {
	source := readSourceFile(t, "nuclei_options.go")
	if strings.Contains(source, "var nucleiHeaderFiles") {
		t.Fatal("header files are back in package-level state, which concurrent batches race on")
	}
	if strings.Contains(source, "func removeNucleiHeaderFiles()") {
		t.Fatal("removal takes no argument, so it can only be reading shared state")
	}
}

// readSourceFile reads a file beside this test, so the assertions are about the shipped
// source and not about a copy of it that could drift.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(data)
}

// functionBody returns the text of the named function, brace-matched.
func functionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, signature)
	if start < 0 {
		return ""
	}
	brace := strings.Index(source[start:], "{")
	if brace < 0 {
		return ""
	}
	brace += start
	depth := 0
	for i := brace; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[brace : i+1]
			}
		}
	}
	return source[brace:]
}

// indexOfArg finds a flag in an argument vector. Named apart from the string-scanning
// `indexOf` already declared in nuclei_progress_test.go, which searches inside a line.
func indexOfArg(values []string, want string) int {
	for i, value := range values {
		if value == want {
			return i
		}
	}
	return -1
}
