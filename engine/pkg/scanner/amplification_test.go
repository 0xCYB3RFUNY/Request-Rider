package scanner

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A08-02 — the nuclei document path had no amplification guard.
//
// The finding was careful about what it claimed and what it did not: `yaml.Unmarshal`
// from `gopkg.in/yaml.v3` is not `yaml.load` with arbitrary constructors, so there is no
// classic `!!python/object` RCE here, and the upload path already refuses a template over
// the operator's configured byte limit. What was missing was a bound on how much a *small*
// document can inflate into — the alias/anchor expansion that turns kilobytes into hundreds
// of megabytes.
//
// So the guard is not a size limit. A size limit already exists and it is the operator's
// to set; this is a ratio, and its purpose is to name the amplification rather than to cap
// how big a template may legitimately be.

// aliasBomb builds the inflating shape with unique mapping keys, so the document is valid
// YAML. yaml.v3 rejects duplicate keys, and a bomb built out of `k: …` repeated 400 times
// therefore fails to parse for a reason that has nothing to do with amplification — which
// makes it useless as a test, because any assertion about it passes for the wrong cause.
func aliasBomb(blocks int) string {
	var out strings.Builder
	out.WriteString("a: &a [1,1,1,1]\n")
	for i := 0; i < blocks; i++ {
		fmt.Fprintf(&out, "k%d: [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n", i)
	}
	return out.String()
}

func TestAmplificationIsRefusedWithAReadableReason(t *testing.T) {
	bomb := aliasBomb(400)
	// A non-empty reason is a refusal: the function reports why a document should not be
	// decoded, and "" means it is within bounds.
	reason := checkYAMLAmplification(bomb, maxYAMLAmplification)
	if reason == "" {
		t.Fatal("a small document that inflates enormously was accepted")
	}
	if !strings.Contains(strings.ToUpper(reason), "AMPLIFICATION") {
		t.Fatalf("the refusal does not name the cause: %s", reason)
	}
	if _, parsed := parseTemplateDocumentWithPath(bomb, "x.yaml"); !strings.Contains(
		strings.ToUpper(parsed), "AMPLIFICATION") {
		t.Fatalf("the parser accepted an inflating document and said %q", parsed)
	}
}

func TestARealLargeTemplateIsNotRefused(t *testing.T) {
	// The measured real maximum: `wordpress-plugin-detect.yaml` is 9.6 MB of YAML. A guard
	// that refused it would break a template that ships in the official corpus, and a
	// resource guard that breaks real work is worse than no guard.
	large := strings.Repeat("x", 9_600_000)
	if reason := checkYAMLAmplification(large, maxYAMLAmplification); reason != "" {
		t.Fatalf("a 9.6 MB document with no anchors was refused: %s", reason)
	}
}

func TestAnOrdinaryTemplatePasses(t *testing.T) {
	ordinary := "id: my-template\ninfo:\n  name: My Template\n  author: me\n" +
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
	if reason := checkYAMLAmplification(ordinary, maxYAMLAmplification); reason != "" {
		t.Fatalf("an ordinary template was refused: %s", reason)
	}
}

func TestTheLimitIsVisibleAndOverridable(t *testing.T) {
	// A ratio nobody can see or change is a hidden cap, which the project forbids.
	if maxYAMLAmplification <= 1 {
		t.Fatalf("the amplification limit must be a ratio above 1, got %d", maxYAMLAmplification)
	}
	if got := yamlAmplificationLimitFromEnv("RR_YAML_MAX_AMPLIFICATION_TEST", 50); got != 50 {
		t.Fatalf("an explicit value was ignored: got %d", got)
	}
	t.Setenv("RR_YAML_MAX_AMPLIFICATION_TEST", "777")
	if got := yamlAmplificationLimitFromEnv("RR_YAML_MAX_AMPLIFICATION_TEST", 50); got != 777 {
		t.Fatalf("the environment value was ignored: got %d", got)
	}
	t.Setenv("RR_YAML_MAX_AMPLIFICATION_TEST", "nonsense")
	if got := yamlAmplificationLimitFromEnv("RR_YAML_MAX_AMPLIFICATION_TEST", 50); got != 50 {
		t.Fatalf("nonsense changed the limit to %d", got)
	}
	t.Setenv("RR_YAML_MAX_AMPLIFICATION_TEST", "-3")
	if got := yamlAmplificationLimitFromEnv("RR_YAML_MAX_AMPLIFICATION_TEST", 50); got != 50 {
		t.Fatalf("a non-positive value was accepted as %d", got)
	}
}

// Both call sites, not one. The passive band decodes the same documents as an active scan,
// so a guard present only in the active path would mean the same file is refused by a scan
// and accepted by a passive run — an inconsistency that is itself a defect, and one that
// survives a suite which only exercises the active path.
func TestBothDecodePathsApplyTheGuard(t *testing.T) {
	bomb := aliasBomb(400)

	_, reason := parseTemplateDocumentWithPath(bomb, "x.yaml")
	if !strings.Contains(strings.ToUpper(reason), "AMPLIFICATION") {
		t.Fatalf("the active path accepted an inflating document and said %q", reason)
	}

	_, capability := parsePassiveDocument(bomb)
	if !strings.Contains(strings.ToUpper(capability.Reason), "AMPLIFICATION") {
		t.Fatalf("the passive path accepted the same document and said %q", capability.Reason)
	}
}

// The override has to work through the shipped call path, not only inside the helper: a
// helper that reads the environment while both call sites pass a constant would leave the
// operator with no way to change it.
func TestTheOverrideReachesTheCallSite(t *testing.T) {
	bomb := aliasBomb(400)

	t.Setenv("RR_YAML_MAX_AMPLIFICATION", "100000")
	_, reason := parseTemplateDocumentWithPath(bomb, "x.yaml")
	if strings.Contains(strings.ToUpper(reason), "AMPLIFICATION") {
		t.Fatalf("RR_YAML_MAX_AMPLIFICATION=100000 was ignored and the document was still refused: %s", reason)
	}

	t.Setenv("RR_YAML_MAX_AMPLIFICATION", "2")
	_, reason = parseTemplateDocumentWithPath(bomb, "x.yaml")
	if !strings.Contains(strings.ToUpper(reason), "AMPLIFICATION") {
		t.Fatalf("RR_YAML_MAX_AMPLIFICATION=2 was ignored: %q", reason)
	}
}

// The measurement happens on the raw text, without decoding — the decode is the expensive
// step the guard exists to avoid.
//
// The first version of this test built a document out of `&a [1,1,1,1]` repeated, with no
// aliases at all, and asserted it would be refused. It is not, and it should not be:
// anchors with nothing referencing them do not expand. `checkYAMLAmplification` returns
// early when either count is zero precisely because of that, and the test was asserting
// against a shape the guard is not about.
func TestTheMeasurementIsAboutTheDocumentAndNotTheParser(t *testing.T) {
	huge := aliasBomb(400_000) // ~10 MB, far past any real template
	start := time.Now()
	reason := checkYAMLAmplification(huge, maxYAMLAmplification)
	elapsed := time.Since(start)
	if reason == "" {
		t.Fatal("a 10 MB document that expands by orders of magnitude was accepted")
	}
	// Not a benchmark: a loose bound that fails if the check ever starts decoding.
	if elapsed > 2*time.Second {
		t.Fatalf("measuring 10 MB took %v, so the check is doing more than counting", elapsed)
	}
}

func TestAnchorsWithNoAliasesDoNotExpandAndAreNotRefused(t *testing.T) {
	// Anchors nothing references cost one copy each. Refusing them would be the guard
	// misfiring on a shape that is harmless.
	anchorsOnly := strings.Repeat("&a [1,1,1,1]\n", 100_000)
	if reason := checkYAMLAmplification(anchorsOnly, maxYAMLAmplification); reason != "" {
		t.Fatalf("a document of unreferenced anchors was refused: %s", reason)
	}
}
