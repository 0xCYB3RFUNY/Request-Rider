package scanner

// The flags that put a nuclei run inside the recording proxy.
//
// nuclei is a separate process, so the proxy is the only thing that can observe
// what it sends. Two flags make that happen: the proxy to send through, and the
// correlation token to carry on every request. Both are asserted here rather
// than in the engine, because this is where the argument vector is assembled.

import (
	"os"
	"strings"
	"testing"

	"intruder/engine/pkg/passive"
)

func recordedRequest() NucleiRequest {
	return NucleiRequest{
		URL:     "http://target.test/",
		Proxy:   "http://127.0.0.1:8080",
		Headers: map[string]string{passive.CaptureContextHeader: "run-token-9"},
	}
}

func TestANucleiRunIsToldToUseTheRecordingProxy(t *testing.T) {
	// The binary is a separate process and the proxy is the only thing that can
	// see it, so the two flags below are the whole mechanism: send through the
	// proxy, and carry the token.
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", recordedRequest())
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-proxy http://127.0.0.1:8080") {
		t.Fatalf("the binary is not told to use the recording proxy: %v", args)
	}
	// The token travels in a 0600 file named by argv, not in argv itself: argv is
	// world-readable, so a token in it is visible to every user on the machine for as
	// long as the scan runs (A04-11).
	if strings.Contains(joined, "run-token-9") {
		t.Fatalf("the token is in argv, so ps shows it during the scan: %v", args)
	}
	body := readNucleiHeaderFile(t, args)
	if !strings.Contains(body, passive.CaptureContextHeader+": run-token-9") {
		t.Fatalf("the binary is not told to carry the token:\n%s", body)
	}
	defer removeNucleiHeaderFiles(args)
}

func TestTheNucleiHeaderOrderIsStableAcrossRuns(t *testing.T) {
	// `stats.args` is kept verbatim in the report. A Go map iterates in a random
	// order, so an unsorted walk would make two runs of one template folder
	// impossible to compare.
	first, err := buildNucleiArgs("http://target.test/", "/tmp/staged", recordedRequest())
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(first)
	for run := 0; run < 20; run++ {
		again, err := buildNucleiArgs("http://target.test/", "/tmp/staged", recordedRequest())
		if err != nil {
			t.Fatalf("build args: %v", err)
		}
		defer removeNucleiHeaderFiles(again)
		// Compared redacted, and this is the point: the header file's real name has to be
		// unpredictable — a predictable path in a shared /tmp is a symlink race — so a raw
		// comparison would differ on every run and `stats.args` would stop being a record
		// of the invocation. What the report stores is the redacted vector.
		if strings.Join(redactNucleiHeaderFiles(first), " ") != strings.Join(redactNucleiHeaderFiles(again), " ") {
			t.Fatalf("run %d produced a different argument order:\n %v\n %v", run, first, again)
		}
	}
}

// The report vector must carry no path into the file that held the token, because it is
// streamed to the browser over SSE.
func TestTheRecordedArgumentsCarryNoHeaderFilePath(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", recordedRequest())
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(args)
	recorded := strings.Join(redactNucleiHeaderFiles(args), " ")
	if !strings.Contains(recorded, HeaderFilePlaceholder) {
		t.Fatalf("the recorded vector does not name the header file at all: %s", recorded)
	}
	for _, path := range headerFilePaths(args) {
		if strings.Contains(recorded, path) {
			t.Fatalf("the recorded vector carries the real header-file path %q: %s", path, recorded)
		}
	}
}

// A header with no value is a flag that carries nothing, and the binary would
// be handed a malformed invocation rather than an absent one.
func TestABlankHeaderIsNotEmitted(t *testing.T) {
	request := recordedRequest()
	request.Headers = map[string]string{
		passive.CaptureContextHeader: "run-token-9",
		"X-Empty":                    "   ",
		"  ":                         "value",
	}
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", request)
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	defer removeNucleiHeaderFiles(args)

	// The headers live in a 0600 file rather than in argv, so that the capture token is
	// not readable from `ps -ef` while the scan runs (A04-11). The invariant under test is
	// unchanged — a blank header is dropped, a real one is kept — but the surface it is
	// asserted on moved, so the assertion reads the file nuclei will actually read.
	body := readNucleiHeaderFile(t, args)
	if strings.Contains(body, "X-Empty") {
		t.Fatalf("a blank header value was emitted:\n%s", body)
	}
	if !strings.Contains(body, passive.CaptureContextHeader) {
		t.Fatalf("the real header was dropped with the blank one:\n%s", body)
	}
}

// readNucleiHeaderFile returns the contents of the `-H` file an argument vector names.
func readNucleiHeaderFile(t *testing.T, args []string) string {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-H" {
			continue
		}
		data, err := os.ReadFile(args[i+1])
		if err != nil {
			t.Fatalf("-H names %q, which is not readable: %v", args[i+1], err)
		}
		return string(data)
	}
	t.Fatalf("no -H file in %v", args)
	return ""
}

// An unrecorded run must be handed neither flag: the binary keeps the route
// proxy it has always had, and a token with no run behind it would file the
// exchange under a context nobody can name.
func TestAnUnrecordedRunIsHandedNoProxyAndNoToken(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{URL: "http://target.test/"})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-proxy") {
		t.Fatalf("an unrecorded run was told to use a proxy: %v", args)
	}
	if strings.Contains(joined, "-H") {
		t.Fatalf("an unrecorded run was told to send headers: %v", args)
	}
}
