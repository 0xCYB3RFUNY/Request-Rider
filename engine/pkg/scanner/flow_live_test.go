package scanner

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// Measured against nuclei v3.11.1 with the real binary, on 2026-09-29: a
// template carrying a top-level `flow:` is NOT unrunnable. Two shapes exist and
// both are executed by the binary:
//
//   - `flow: http(1) && http(2)` over an `http:` block — loaded and run with no
//     extra flag at all.
//   - `flow: |` with JavaScript, marked `self-contained: true` — excluded by
//     default, and loaded only when `-esc` is passed. Without `-esc` the batch
//     dies with `[FTL] Could not run nuclei: no templates provided for scan`,
//     which is the message that made "nuclei refuses flow templates" look true.
//
// `documentCapabilities` maps `self-contained: true` to `-esc`, so the engine's
// own argument builder already asks for the flag the second shape needs. This
// test exists to keep that true: it runs the real binary through the real
// staging and run path and fails if either shape falls back to `TemplateFlow`.
//
// It is skipped unless RR_NUCLEI_LIVE names a target, because it makes real
// outbound requests. A test that cannot fail proves nothing, and a test that
// reaches the internet by default belongs to nobody's unit-test run.
func TestLiveSelfContainedFlowTemplatesActuallyRun(t *testing.T) {
	target := os.Getenv("RR_NUCLEI_LIVE")
	if target == "" {
		t.Skip("set RR_NUCLEI_LIVE=<url> to run the real binary against a live target")
	}
	if _, err := os.Stat(nucleiBinary()); err != nil {
		t.Skipf("nuclei binary %q is not available: %v", nucleiBinary(), err)
	}

	// A simple boolean flow. Nuclei runs this one unaided.
	simple := `id: rr-live-simple
info:
  name: RR live simple
  author: requestrider
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers:
      - type: word
        words:
          - "rr-definitely-absent-token"
`
	// A JavaScript flow marked self-contained. Without -esc the binary prints
	// `[WRN] Excluded ... use -esc` and then, if this is the only kind in the
	// batch, exits with `no templates provided for scan`.
	selfContained := `id: rr-live-selfcontained
info:
  name: RR live self contained
  author: requestrider
  severity: info
self-contained: true
flow: |
  http();
http:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers:
      - type: word
        words:
          - "rr-definitely-absent-token"
`

	dir, staged, err := StageUploads([]UploadFile{
		{Name: "live-simple.yaml", Content: simple},
		{Name: "live-selfcontained.yaml", Content: selfContained},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{URL: target})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	byName := map[string]TemplateResult{}
	for _, item := range run.Templates {
		byName[item.Name] = item
	}
	// The binary's own words are the evidence for every claim made about it, so
	// they travel with a failure. Without them a red test names a symptom.
	words := func() string {
		var out strings.Builder
		keys := make([]string, 0, len(run.Stats))
		for key := range run.Stats {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := run.Stats[key]
			text, ok := value.(string)
			if !ok {
				out.WriteString(fmt.Sprintf("%s: %v\n", key, value))
				continue
			}
			out.WriteString(fmt.Sprintf("--- %s ---\n%s\n", key, text))
		}
		return out.String()
	}
	for _, name := range []string{"live-simple.yaml", "live-selfcontained.yaml"} {
		item, known := byName[name]
		if !known {
			t.Fatalf("%s has no row at all: the report cannot account for it\n%s", name, words())
		}
		// The claim this test defends: a flow definition is not a file the binary
		// refuses. If it lands on TemplateFlow the report is telling the operator
		// the template was never checked when in fact the flag was missing.
		if item.Status == TemplateFlow {
			t.Fatalf("%s = %q (%s): the binary ran the flow and the report called it unchecked\n%s", name, item.Status, item.Reason, words())
		}
		t.Logf("%s -> %s (%s)", name, item.Status, item.Reason)
	}
}
