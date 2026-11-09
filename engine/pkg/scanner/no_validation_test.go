package scanner

import (
	"strings"
	"testing"
)

// The operator's instruction (2026-10-06): remove validation, scan every template.
//
// The separate `nuclei -validate` pass cost 3 s on `http/cves/2025` where the scan
// took 73 s, and it refused a WHOLE run over a single document: on this corpus
//
//	folder                 documents  -validate  ERR lines  exit
//	http                      11 656       19 s       259        1
//	javascript                  131        2 s         3        1
//	nuclei-wordfence-cve      84 999       75 s         2        1
//
// with `[FTL] Could not validate templates` caused by ONE file — `CVE-2025-11833`,
// refused for `access to helper file helpers/wordlists/numbers.txt denied (hard
// link)` — while its 414 neighbours in the same folder were fine. A pre-pass that
// cancels a folder over one document is the opposite of "scan every template".

// The plan has no way to ask for validation. `PlanRequest` carries no `Validate`
// hook, so there is no caller that could start a second `nuclei` process before the
// scan: one invocation per batch, and that invocation is the scan itself.
func TestAPlanRequestHasNoValidationHook(t *testing.T) {
	request := PlanRequest{}
	// A struct literal with only the fields that exist compiles; this test exists so
	// that ADDING a validation hook back is a deliberate change someone sees, rather
	// than something that happens because a field was re-added.
	if request.Staged != nil {
		t.Fatalf("a fresh plan request carries staged files: %+v", request.Staged)
	}
	if strings.Contains(strings.Join(reportPlanKeys(t), ","), "Validation") {
		t.Fatalf("the plan still publishes a validation field: %v", reportPlanKeys(t))
	}
}

// The published report must not name a command this project no longer runs.
//
// Measured on a live `run-dir` right after the pass was removed, the report still
// carried `validation_args` holding `['-duc','-nc','-validate','-t','/…/dns']` and
// `validation_diagnostics` holding the SCAN's own banner. An operator reading those
// would be told a validation ran. They are named here because their absence is the
// contract, not because the plan happens to be empty.
func TestThePlanPublishesNoValidationKeys(t *testing.T) {
	for _, key := range reportPlanKeys(t) {
		for _, banned := range []string{"validation", "Validation"} {
			if strings.Contains(key, banned) {
				t.Fatalf("the plan still publishes %q, which describes a command this "+
					"project no longer runs", key)
			}
		}
	}
}

// Nothing is refused before the run: every document reaches a batch, because a
// refusal discovered during the scan is reported by the scan with the binary's own
// reason rather than cancelling the folder in advance.
func TestEveryDocumentReachesABatchWithNoValidationStep(t *testing.T) {
	dir := writePlainFolder(t, map[string]string{
		"a.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
		"b.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/b\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
		"c.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/c\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
	})
	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: stageInPlace(t, dir)})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if plan.Planned() != 3 {
		t.Fatalf("planned %d of 3 documents: %+v", plan.Planned(), plan.Batches)
	}
	if got := len(plan.Batches[0].Files); got != 3 {
		t.Fatalf("batch holds %d of 3 documents: %+v", got, plan.Batches[0])
	}
}

// reportPlanKeys is the set of top-level keys the plan's own description publishes.
func reportPlanKeys(t *testing.T) []string {
	t.Helper()
	dir := writePlainFolder(t, map[string]string{
		"one.yaml": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/1\"\n    matchers:\n      - type: word\n        words:\n          - hit\n",
	})
	plan, err := BuildPlan(PlanRequest{Dir: dir, Staged: stageInPlace(t, dir)})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	keys := make([]string, 0, 16)
	for key := range plan.Describe() {
		keys = append(keys, key)
	}
	return keys
}
