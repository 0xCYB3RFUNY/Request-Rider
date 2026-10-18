package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func nucleiBinary() string { return envValue("RR_NUCLEI_BINARY", "nuclei") }

// nucleiTimeoutSec is the wall-clock deadline for one nuclei invocation.
//
// It had no default: with `RR_NUCLEI_TIMEOUT_SEC` unset the subprocess ran with
// `execCtx = ctx`, so a template that never answers — a `dns:` template against a
// host that does not resolve, an `ssl:` handshake to a plain-HTTP port — kept the
// whole batch alive with no bound at all. Measured on the official corpus:
// `go run ./cmd/corpuslive nuclei-templates/{dns,ssl,headless}` against a local
// HTTP fixture was still running at 6m32s with zero records written, and the job
// never reaches a terminal state, so the UI's export button stays disabled
// forever.
//
// The default is a bound against hanging, not against work: it is per
// invocation, not per template, and a scan that is still producing records is not
// interrupted early — the context is only consulted when the subprocess is
// stopped. Raising it is one variable, `RR_NUCLEI_TIMEOUT_SEC`, and the value in
// force is reported in the run's stats so the operator can see which bound
// applied rather than discovering it as an unexplained stop.
const defaultNucleiTimeoutSec = 3600

func nucleiTimeoutSec() int {
	if value := optionalPositiveInt("RR_NUCLEI_TIMEOUT_SEC"); value > 0 {
		return value
	}
	return defaultNucleiTimeoutSec
}

// isolatedBatchTimeoutSec bounds a batch that holds one blocking template.
//
// The general deadline answers "how long may the whole run take", which is the
// right question for a folder of 458 HTTP templates. It is the wrong question
// for a batch of one `code` document whose script calls `recv()` without a
// deadline: that document will never return, so the run's own hour-long budget
// becomes its personal one, and nothing else in the batch is waiting on it — it
// is alone in there by construction.
//
// The value is a per-document budget rather than a per-run one, and it is
// reported in the batch's own row so the operator sees which bound applied.
const isolatedBatchTimeoutSec = 120

// batchTimeoutSec is the deadline for one invocation.
func batchTimeoutSec(batch NucleiBatch) int {
	if batch.Key.isolated() {
		if value := optionalPositiveInt("RR_NUCLEI_ISOLATED_TIMEOUT_SEC"); value > 0 {
			return value
		}
		return isolatedBatchTimeoutSec
	}
	// A batch of `headless` documents gets the same short bound, for a different
	// reason: the browser is a **local** resource, and whether it comes up is a
	// fact about the machine, not about the target. Measured here on nuclei
	// v3.11.1: Chromium starts and opens its DevTools endpoint, and the
	// invocation then waits for a session that never finishes — 27 headless
	// files held their batch for 28 minutes with an empty report. The other
	// files in that batch were already reported by their own invocation, so the
	// wait bought nothing at all.
	//
	// It is a deadline rather than a skip because on a machine where the browser
	// does come up the templates are real checks, and this bound is long enough
	// for them: the shortest `-timeout` nuclei honours is seconds, and 120 is
	// twenty-four page loads.
	if batch.drivesBrowser() {
		if value := optionalPositiveInt("RR_NUCLEI_ISOLATED_TIMEOUT_SEC"); value > 0 {
			return value
		}
		return isolatedBatchTimeoutSec
	}
	return nucleiTimeoutSec()
}

// maxTemplateBytes bounds one uploaded template document.
//
// `yaml.Unmarshal` expands anchors and aliases in memory, and the engine process
// holds every job's state — so an unbounded document is a memory-exhaustion path
// reachable from the upload API. The bound is on this path only: Intruder
// legitimately sends huge raw requests, which is why the global Django upload
// limits were removed, and this must not become a global cap by accident.
//
// The value is an explicit field with a visible default, per the project's rule
// that a limit must be seen: the refusal names the limit and the reason
// (TEMPLATE_TOO_LARGE), and the same number is enforced by the Django gateway so
// the operator meets it before the bytes cross the wire.
//
// THE DEFAULT IS 64 MiB BECAUSE 8 MiB MADE THE OFFICIAL CORPUS UNSCANNABLE, and a
// bound that refuses the operator's own corpus is a bound that reduces the tool's
// capability rather than protecting it. Measured 2026-10-07 on `nuclei-templates`
// as shipped: exactly one document exceeds 8 MiB —
// `http/technologies/wordpress/plugins/wordpress-plugin-detect.yaml`, 10 079 081
// bytes — and the Django gateway raises on the **whole chunk** for it, so the
// upload of the 11 664-file `http` folder died at chunk 18 of 26 with HTTP 400
// `TEMPLATE_TOO_LARGE` and the browser's progress panel froze on the last line.
// Every other file in that folder was fine and none of them was ever scanned,
// because the refusal cancels the chunk they share.
//
// 64 MiB clears the largest real template with room to grow and keeps the bound a
// bound: the value stays overridable by `RR_NUCLEI_MAX_TEMPLATE_BYTES`, the
// refusal still names the number, and the gateway enforces the same one.
func maxTemplateBytes() int {
	if value := optionalPositiveInt("RR_NUCLEI_MAX_TEMPLATE_BYTES"); value > 0 {
		return value
	}
	return 64 << 20
}

// maxUploadSessionBytes bounds everything one upload session may stage on disk.
// Chunks accumulate in the session, so a per-file limit alone still allows an
// unbounded session one chunk at a time.
func maxUploadSessionBytes() int {
	if value := optionalPositiveInt("RR_NUCLEI_MAX_UPLOAD_BYTES"); value > 0 {
		return value
	}
	return 10 * maxTemplateBytes()
}
func nucleiRateLimit() int { return optionalPositiveInt("RR_NUCLEI_RATE_LIMIT") }
func nucleiExecTimeout() int {
	return optionalPositiveInt("RR_NUCLEI_EXEC_TIMEOUT_MS")
}

func optionalPositiveInt(name string) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func envValue(name, fallback string) string {
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		return raw
	}
	return fallback
}

// Per-template status values. Every uploaded file ends in exactly one of them,
// which is what makes a run reportable per YAML file instead of as one blob.
const (
	// TemplateMatched means the file loaded and at least one matcher fired.
	TemplateMatched = "matched"
	// TemplateNotMatched means the file loaded and ran, but nothing fired.
	TemplateNotMatched = "not_matched"
	// TemplateSkipped means the binary never executed the file. It is reported
	// separately from "not matched" because a check that never ran says nothing
	// about the target.
	TemplateSkipped = "skipped"
	// TemplateInvalid means the file was refused before the scan. The reason is
	// the one the binary itself printed whenever it could be asked.
	TemplateInvalid = "invalid"
	// TemplateNoRequest means the file ran but did not address the target:
	// `code`/`file` templates and JavaScript using only local capabilities. A
	// target-facing JavaScript module is not requestless just because its type
	// is `javascript`. These rows get their own status rather than being counted
	// as a target check with no match.
	TemplateNoRequest = "no_request"
	// TemplateDuplicate means the file is byte-identical to another file in the
	// same upload. It is the same template under a different name, so running it
	// again would repeat work that is already covered.
	TemplateDuplicate = "duplicate"
	// TemplateWorkflow means the file is a `workflows:` orchestrator and this run's
	// binary produced no JSONL record for it.
	//
	// It is its own status rather than `skipped` because `skipped` means the file
	// never executed, and that is false here. Measured on nuclei v3.11.1: a
	// workflow named with `-w` runs its subtemplates and issues their requests —
	// `adminer-workflow.yaml` against a local fixture produced 9 HTTP connections
	// — but a workflow is not itself a matcher, so it emits no record of its own.
	// Reporting it as `skipped` would tell the operator a check never happened
	// while its requests were on the wire, which is the one claim this report must
	// never make. It matches nothing of its own, so `not_matched` is equally wrong
	// for the same reason: that status says "ran and nothing fired", and a
	// workflow's results belong to its subtemplates, which are reported under their
	// own template ids.
	TemplateWorkflow = "workflow"
	// TemplateFlow means the file declares a top-level `flow:` AND this run's
	// binary produced no record for it, so nothing inside it was checked.
	//
	// Both halves are load-bearing, and the first one used to be wrong on its
	// own. Measured against nuclei v3.11.1 on 2026-09-29, a flow template is
	// NOT a file the binary refuses: `flow: http(1) && http(2)` over an `http:`
	// block is loaded and executed with no extra flag (JSONL record, `"type":
	// "http"`), and a `self-contained: true` JavaScript flow is loaded and
	// executed as `"type":"flow"` because the plan asks for `-esc`. The
	// `[FTL] Could not run nuclei: no templates provided for scan` that made
	// the opposite look true comes from a batch in which *every* file was
	// excluded — the binary names the cause itself: `[WRN] Excluded N
	// self-contained template[s] (disabled as default), use -esc option`.
	//
	// So the status is about the run, not about the file's kind. A flow that ran
	// and matched nothing is an honest miss and is reported as `not_matched`;
	// calling it `flow` would tell the operator a template was never checked when
	// the binary had just checked it. It keeps its own status because a bare
	// "skipped" would not say *why* this kind of file produced no record, and a
	// collection scan must never let an unchecked file read as a checked one.
	// On the official corpus 1 923 of 14 021 templates (13.7 %) are flows.
	TemplateFlow = "flow"

	// TemplateUncompiled means the binary compiled no template out of the file at
	// all, so nothing in it could be checked. It is a separate status because the
	// alternatives both state something false: `skipped` claims a load-time clash
	// in a batch that in fact produced records for its other files, and
	// `not_matched` claims the check ran and came back clean.
	//
	// Measured on nuclei v3.11.1: a document whose `info.tags` contains the
	// reserved token `fuzz` is refused under `-t`, `-t -dast` and `-t -fuzz`
	// alike, each answering `[FTL] Could not run nuclei: no templates provided
	// for scan` with exit 1, while `nuclei -validate` accepts the same file. On
	// the official corpus 37 of 14 072 files carry the tag.
	TemplateUncompiled = "uncompiled"
)

// StagedFile is one uploaded document after validation and staging. Meta is
// nil and Reason is set when the file is rejected before the scan.
// RelativePath is the file's place inside the uploaded folder layout, in slash
// form. It is a reporting field, not a filesystem path: it never carries the
// staging directory, and it is filled even for a file that was rejected, so a
// folder scan can still say which folder an unusable file came from.
type StagedFile struct {
	UploadName   string
	StagedPath   string
	RelativePath string
	Meta         *TemplateMeta
	Reason       string
	Support      bool
}

// TemplateResult is the per-file outcome reported back to the browser.
type TemplateResult struct {
	Name       string                   `json:"name"`
	Path       string                   `json:"path,omitempty"`
	TemplateID string                   `json:"template_id,omitempty"`
	Title      string                   `json:"title,omitempty"`
	Severity   string                   `json:"severity,omitempty"`
	Status     string                   `json:"status"`
	Reason     string                   `json:"reason,omitempty"`
	CVE        []string                 `json:"cve,omitempty"`
	CWE        []string                 `json:"cwe,omitempty"`
	Tags       []string                 `json:"tags,omitempty"`
	Author     []string                 `json:"author,omitempty"`
	Matches    int                      `json:"matches"`
	Findings   []map[string]interface{} `json:"findings,omitempty"`
	// Blocks are the request sections the document declares, and Capabilities
	// the opt-in kinds it needs. They travel with the row so an operator can see
	// why a flag was added without opening the file.
	Blocks       []string `json:"blocks,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	// Digest is the SHA-256 of the document, so two files can be compared by
	// content instead of by name.
	Digest string `json:"digest,omitempty"`
	// Batch is the invocation this file ran in, or 0 when it did not run.
	Batch int `json:"batch,omitempty"`
	// PerformedBy names the path that produced this row: the nuclei binary, or
	// "requestrider" when the binary would not execute the file and this project's
	// own runner did. It is on the row rather than only in the summary because the
	// two verdicts rest on different evidence — a binary row carries nuclei's own
	// JSONL, a runner row carries the exchange this engine sent and scored itself —
	// and a report that mixed them silently could not be told apart from a run
	// where one engine did everything.
	PerformedBy string `json:"performed_by,omitempty"`

	// protocol is the request block the document carries. It is kept internal:
	// the browser is told the outcome, not how the engine read the file, and the
	// only place it is needed is deciding between `not_matched` and `no_request`.
	protocol string
	// batchPath is the path inside the batch directory the binary loads this
	// template from. A planned run loads a per-batch hard link, so the path in the
	// binary's JSONL is not the uploaded one; this is what a record's
	// `template-path` is matched against. It is empty for a file that was never
	// planned.
	batchPath string
}

// Protocol returns the template's request block, read from its own document.
func (r TemplateResult) Protocol() string { return r.protocol }

// NucleiRun is the complete outcome of one template run: the flat finding list
// kept for the shared evidence log, the per-file report, and run statistics.
type NucleiRun struct {
	Findings  []map[string]interface{}
	Templates []TemplateResult
	Stats     map[string]interface{}
}

// CountStatus returns how many template results carry one status.
func (r NucleiRun) CountStatus(status string) (matched int, total int) {
	total = len(r.Templates)
	for _, item := range r.Templates {
		if item.Status == status {
			matched++
		}
	}
	return matched, total
}

// TemplatesReport renders the per-file identity and validation result of staged
// uploads. The upload endpoints return it so the operator sees which file was
// rejected while the remaining chunks are still arriving.
func TemplatesReport(staged []StagedFile) []TemplateResult {
	results := make([]TemplateResult, 0, len(staged))
	for _, file := range staged {
		if file.Support {
			continue
		}
		result := resultFor(file, TemplateNotMatched, "")
		results = append(results, result)
	}
	return results
}

// resultFor renders one staged file as a report row with a known status.
func resultFor(file StagedFile, status, reason string) TemplateResult {
	result := TemplateResult{
		Name:   file.UploadName,
		Path:   reportPath(file),
		Status: status,
	}
	if file.Meta == nil {
		result.Status = TemplateInvalid
		result.Reason = file.Reason
		return result
	}
	result.TemplateID = file.Meta.TemplateID
	result.Title = file.Meta.Name
	result.Severity = file.Meta.Severity
	result.CVE = file.Meta.CVE
	result.CWE = file.Meta.CWE
	result.Tags = file.Meta.Tags
	result.Author = file.Meta.Author
	result.protocol = file.Meta.Protocol
	result.Blocks = file.Meta.BlockKeys
	result.Capabilities = sortedCapabilityKeys(file.Meta.Capabilities)
	result.Digest = file.Meta.Digest
	if reason != "" {
		result.Reason = reason
	}
	return result
}

// UploadFile is one Nuclei template document sent from the browser. Path keeps
// the relative path of a folder upload so templates with the same file name in
// different directories stay distinct.
type UploadFile struct {
	Name     string
	Path     string
	Content  string
	Encoding string
}

// NucleiRequest selects real Nuclei templates by tags or severities. The
// template documents themselves always arrive as uploaded files: no
// server-side template paths are accepted, so there is nothing to configure.
type NucleiRequest struct {
	URL          string
	CategoryPath string
	Tags         []string
	Severity     []string
	// Proxy is the proxy the binary sends through. When it points at the local
	// recording proxy, every template's request is captured there in order,
	// with the complete raw exchange, and the route still applies because the
	// proxy's own transport is the route transport.
	Proxy   string
	Options NucleiOptions
	// deadlineSec is the bound that will stop this invocation, in seconds. It is
	// set by `executeBatch` from the batch's own deadline and read by
	// `buildNucleiArgs`, because a per-request timeout larger than it is
	// unreachable: the invocation ends first, so the request can only ever be
	// reported as "stopped at the deadline".
	//
	// Zero means "not set", which happens when a caller builds arguments without
	// running a batch — the tests do. Then the general run bound applies.
	deadlineSec int
	// Headers are sent on every request the binary makes. This is how the
	// correlation token reaches the recording proxy: the proxy reads it, files
	// the exchange under the context and removes it before forwarding
	// upstream, so the target never sees it.
	Headers map[string]string
	// Transport is the transport this project's own runner sends through, and it is
	// how a file the binary will not execute still gets checked: the run falls back
	// to `RunTemplateLocally` for those rows, using this transport, so every file the
	// operator selected ends the run with a verdict rather than a refusal.
	//
	// It is optional on purpose. A caller with no transport to offer keeps the
	// binary's verdicts and the refusals, and the run statistics say the fallback
	// was unavailable — which is an honest report, where silently guessing a bare
	// client would produce evidence the project cannot show.
	Transport http.RoundTripper
	// OnStats receives live progress while the binary runs. It is nil for the
	// synchronous path, where the caller only wants the final report.
	OnStats func(NucleiProgress)
	// OnProcess is called with the started process so a job can pause and resume
	// it. It is nil on the synchronous path.
	OnProcess func(process *os.Process)
	// OnOutput is called with the JSONL report path the binary writes, so a
	// caller can tail it and stream per-file results while the scan runs.
	OnOutput func(path string)
	// Resolve maps a path the binary reported back to the staged file it came
	// from. A planned run loads templates from per-batch directories, so the
	// staged path is not the path in the JSONL record and attribution has to go
	// through the plan. It is nil when the caller has no staged set.
	Resolve func(path string) (StagedFile, bool)
	// OnPlan receives the finished plan before the first invocation starts, so a
	// live-stream consumer can resolve batch paths to uploaded files.
	OnPlan func(plan *NucleiPlan)
	// Protocols are the opt-in template kinds the documents in this batch need.
	// Nuclei does not load a `code`, `file` or `headless` template unless the
	// matching flag is present, so a folder that contains them needs those flags
	// or the binary reports nothing for those files — or refuses the whole run
	// with "no templates provided for scan". They are read from the documents the
	// operator chose, so the run covers what was selected instead of quietly
	// dropping part of a real template folder.
	Protocols []Capability
	// IsolatedProtocol names the capability this invocation was given its own
	// batch for, and it is the one flag `buildNucleiArgs` may add even though
	// `isolatedFreeFlags` refuses it on a shared invocation.
	//
	// The refusal is right for a shared batch and fatal for the isolated one.
	// Measured on nuclei v3.11.1: `-dast` on a folder that holds no fuzzing
	// template makes the binary abort the whole invocation with `[FTL] Could not
	// run nuclei: no templates provided for scan` and exit 1, so a mixed batch
	// must not carry it. The plan already gives a fuzzing batch its own
	// directory — and there, where every file in the invocation needs the flag and
	// there is no other template to lose, dropping it leaves the binary with a
	// directory it compiles nothing from. That is not a theoretical gap: 54 files
	// of the official corpus are `payloads:`+`fuzzing:` documents, and a run of
	// exactly those 54 against a live target produced 52 `skipped` rows, 2 `flow`
	// rows, `[FTL] no templates provided for scan` and exit 1 — every file lost,
	// with the plan reporting a correct batch layout.
	IsolatedProtocol Capability
	// SkipValidation is kept for callers that build a plan from a directory they
	// have already had the binary load once. It no longer changes what a folder or
	// upload run does: the separate `-validate` pass is gone, see `validationStepFor`.
	SkipValidation bool
}

// nucleiFinding is the JSONL record emitted by the real Nuclei binary. All
// fields that carry evidence or template identity are decoded: the report
// needs the file name, CVE and CWE identifiers, the matched matcher and the
// exact request that produced the match.
type nucleiFinding struct {
	TemplateID   string `json:"template-id"`
	TemplatePath string `json:"template-path"`
	Info         struct {
		Name           string      `json:"name"`
		Author         flexStrings `json:"author"`
		Tags           flexStrings `json:"tags"`
		Description    string      `json:"description"`
		Severity       string      `json:"severity"`
		Reference      flexStrings `json:"reference"`
		Classification struct {
			CVE flexStrings `json:"cve-id"`
			CWE flexStrings `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	MatcherName      string   `json:"matcher-name"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Port             string   `json:"port"`
	Scheme           string   `json:"scheme"`
	URL              string   `json:"url"`
	Path             string   `json:"path"`
	IP               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
	MatchedAt        string   `json:"matched-at"`
	CurlCommand      string   `json:"curl-command"`
	ExtractedResults []string `json:"extracted-results"`
	// Error is the reason the template could not be completed. It is a
	// per-template failure, not a scanner failure: the file ran and the
	// individual request did not work out.
	Error string `json:"error"`
	// MatcherStatus is a pointer: with -ms Nuclei emits a record for every
	// executed template, including matcher failures marked false. An absent
	// value means the field was not reported at all.
	MatcherStatus *bool `json:"matcher-status"`
}

func (hit nucleiFinding) severity() string {
	level := strings.ToUpper(strings.TrimSpace(hit.Info.Severity))
	if level == "" {
		return "INFO"
	}
	return level
}

// isFinding reports whether a JSONL record represents an actual match. With
// `-ms` Nuclei also writes one record per executed template with
// "matcher-status": false; treating those as findings would report every
// template that ran as a vulnerability.
func (hit nucleiFinding) isFinding() bool {
	return hit.MatcherStatus == nil || *hit.MatcherStatus
}

// evidenceText renders the human-readable evidence of one record, shared by the
// final report and the live stream so both word a match the same way.
func (hit nucleiFinding) evidenceText() string {
	evidence := fmt.Sprintf("Matched %s at %s.", hit.Host, hit.MatchedAt)
	if hit.MatcherName != "" {
		evidence = fmt.Sprintf("Matched %s at %s via matcher %q.", hit.Host, hit.MatchedAt, hit.MatcherName)
	}
	if len(hit.ExtractedResults) > 0 {
		evidence += " Extracted: " + strings.Join(hit.ExtractedResults, ", ") + "."
	}
	return evidence
}

// toMap renders one JSONL record as a shared finding. The keys used by the
// builtin scanner (title, severity, evidence, recommendation) are preserved so the
// project evidence log keeps a single finding shape across engines.
func (hit nucleiFinding) toMap() map[string]interface{} {
	infoName := strings.TrimSpace(hit.Info.Name)
	title := hit.TemplateID
	if infoName != "" {
		title = fmt.Sprintf("[%s] %s", hit.TemplateID, infoName)
	}
	finding := map[string]interface{}{
		"severity":       hit.severity(),
		"title":          title,
		"evidence":       hit.evidenceText(),
		"recommendation": "",
		"template_id":    hit.TemplateID,
		"matched_at":     hit.MatchedAt,
		"matcher_name":   hit.MatcherName,
		"type":           hit.Type,
		"ip":             hit.IP,
		"timestamp":      hit.Timestamp,
		"curl_command":   hit.CurlCommand,
		"description":    strings.TrimSpace(hit.Info.Description),
	}
	if hit.Error != "" {
		finding["error"] = oneLine(hit.Error)
	}
	for key, values := range map[string][]string{
		"cve":        nonEmpty(hit.Info.Classification.CVE),
		"cwe":        nonEmpty(hit.Info.Classification.CWE),
		"tags":       nonEmpty(hit.Info.Tags),
		"author":     nonEmpty(hit.Info.Author),
		"references": nonEmpty(hit.Info.Reference),
		"extracted":  nonEmpty(hit.ExtractedResults),
	} {
		if len(values) > 0 {
			finding[key] = values
		}
	}
	return finding
}

// flexStrings decodes a JSON scalar, string array or null into a slice, because
// nuclei emits `author`, `tags` and `cve-id` in more than one shape.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*f = nil
		return nil
	}
	if trimmed[0] == '[' {
		var items []string
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return err
		}
		*f = items
		return nil
	}
	var single string
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil
	}
	*f = []string{single}
	return nil
}

// flexYAMLStrings is the YAML counterpart of flexStrings.
type flexYAMLStrings []string

func (f *flexYAMLStrings) UnmarshalYAML(value *yaml.Node) error {
	switch {
	case value == nil, value.Tag == "!!null":
		*f = nil
	case value.Kind == yaml.SequenceNode:
		var items []string
		if err := value.Decode(&items); err != nil {
			return err
		}
		*f = items
	case value.Kind == yaml.MappingNode:
		*f = nil
	default:
		*f = []string{value.Value}
	}
	return nil
}

// nonEmpty trims the optional list fields nuclei may emit as null or blanks and
// returns nil when nothing is left, so the JSON payload omits them.
func nonEmpty(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true, "unknown": true,
}

// safeRelativePath converts a browser supplied path into one that stays inside
// the staging directory. Traversal is rejected instead of silently rewritten.
func safeRelativePath(raw string) (string, error) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	cleaned = strings.TrimLeft(cleaned, "/")
	parts := make([]string, 0, 4)
	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("path %q escapes the template directory", raw)
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("template path %q is empty", raw)
	}
	return filepath.Join(parts...), nil
}

// displayRelativePath is the reporting twin of safeRelativePath: it produces the
// path a file is shown under, and it never fails. A rejected path is reduced to
// its last segment rather than echoed, so a browser can group a rejected file by
// folder without the report ever carrying a traversal or an absolute path.
func displayRelativePath(raw string, fallback string) string {
	cleaned, err := safeRelativePath(raw)
	if err == nil {
		return filepath.ToSlash(cleaned)
	}
	cleaned, err = safeRelativePath(fallback)
	if err != nil {
		// Nothing safe is left to show. An empty path means "no folder", which
		// the report renders as a loose file rather than as a bogus location.
		return ""
	}
	return filepath.ToSlash(cleaned)
}

// StageUploads validates uploaded YAML documents and stages both usable
// templates and their support files into a fresh temporary directory that keeps
// the uploaded folder layout. The caller removes the directory. Only a rejected
// request (no files, a path that escapes the directory, or a write failure)
// returns an error; a malformed template is reported per file in the returned
// results, while support files are omitted from that report.
func StageUploads(files []UploadFile) (string, []StagedFile, error) {
	if len(files) == 0 {
		return "", nil, fmt.Errorf("at least one template file is required")
	}
	dir, err := os.MkdirTemp("", "rr-nuclei-upload-*")
	if err != nil {
		return "", nil, err
	}
	staged, err := stageInto(dir, files, map[string]int{})
	if err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return dir, staged, nil
}

// stageInto validates and stages one chunk of documents into dir, preserving
// the uploaded folder layout. usedPaths carries the paths already taken in this
// staging session across chunks, so two chunks cannot overwrite each other. The
// caller owns dir and removes it when the session ends.
func stageInto(dir string, files []UploadFile, usedPaths map[string]int) ([]StagedFile, error) {
	staged := make([]StagedFile, 0, len(files))
	for index, file := range files {
		name := strings.TrimSpace(file.Name)
		if name == "" {
			name = fmt.Sprintf("template-%d.yaml", index+1)
		}
		content := []byte(file.Content)
		if file.Encoding == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				return nil, fmt.Errorf("file %q has invalid base64 content: %w", name, err)
			}
			content = decoded
		} else if file.Encoding != "" {
			return nil, fmt.Errorf("file %q has unsupported content encoding %q", name, file.Encoding)
		}
		relative, pathErr := safeRelativePath(file.Path)
		if pathErr != nil {
			if file.Path != "" {
				return nil, pathErr
			}
			relative, pathErr = safeRelativePath(name)
			if pathErr != nil {
				staged = append(staged, StagedFile{UploadName: name, RelativePath: name, Reason: pathErr.Error()})
				continue
			}
		}
		target := filepath.Join(dir, relative)
		if seen := usedPaths[target]; seen > 0 {
			extension := filepath.Ext(relative)
			stem := strings.TrimSuffix(relative, extension)
			relative = fmt.Sprintf("%s-%d%s", stem, seen+1, extension)
			target = filepath.Join(dir, relative)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, err
		}
		usedPaths[target]++
		report := filepath.ToSlash(relative)
		if err := os.WriteFile(target, content, 0o600); err != nil {
			return nil, err
		}
		if !isTemplateFileName(relative) {
			staged = append(staged, StagedFile{
				UploadName: name, StagedPath: target, RelativePath: report, Support: true,
			})
			continue
		}
		if len(content) > maxTemplateBytes() {
			staged = append(staged, StagedFile{
				UploadName: name, StagedPath: target, RelativePath: report,
				Reason: fmt.Sprintf("template exceeds the %d-byte limit (TEMPLATE_TOO_LARGE)", maxTemplateBytes()),
			})
			continue
		}
		if len(content) == 0 || strings.TrimSpace(string(content)) == "" {
			staged = append(staged, StagedFile{
				UploadName: name, StagedPath: target, RelativePath: report, Reason: "file is empty",
			})
			continue
		}
		// The report path follows the final on-disk name, so a folder that held
		// two same-named files still attributes each result to its own file.
		meta, reason := parseTemplateDocumentWithPath(string(content), report)
		if reason != "" {
			staged = append(staged, StagedFile{
				UploadName: name, StagedPath: target, RelativePath: report, Reason: reason,
			})
			continue
		}
		staged = append(staged, StagedFile{UploadName: name, StagedPath: target, RelativePath: report, Meta: meta})
	}
	return staged, nil
}

// batchOutcome is what one invocation of the binary proved.
type batchOutcome struct {
	// Report is the parsed JSONL evidence.
	Report nucleiReport
	// Args is the exact command line that ran.
	Args []string
	// ExitCode is the binary's exit status.
	ExitCode int
	// Failed reports that the binary refused the invocation as a whole instead
	// of running the templates in it.
	Failed bool
	// Error is the process-level failure, if any.
	Error error
	// Stdout and Stderr are the binary's own words, kept whole.
	Stdout string
	Stderr string
	// Batch is the invocation this outcome belongs to.
	Batch int
	// DeadlineSec is the bound that stopped this invocation, or 0 when it
	// finished or was cancelled from outside.
	//
	// It exists because the two are indistinguishable without it. When this
	// project's own deadline fires, the parent context is still live, so
	// `ctx.Err()` is nil and the kill lands in `Error` as a bare
	// `signal: killed`. The report then says "the binary could not be executed
	// for this batch", which is the opposite of what happened: the binary ran,
	// and it was stopped on purpose, at a bound this project chose and can
	// report. Measured on v3.11.1 over the 98 636-file corpus, 38 rows carried
	// that sentence, every one of them from a `headless` batch whose browser
	// never finishes on this machine.
	DeadlineSec int
	// DrivesBrowser records that this batch was the one that had to start a
	// local browser, so a stopped batch can name the resource that stopped
	// responding rather than only the bound.
	DrivesBrowser bool
}

// RunNucleiDir executes the staged templates against one target. The set is
// planned first — validated by the binary, deduplicated by content and split into
// the invocations that can actually run every file — and every planned batch is
// then executed. No flag, filter or template-id clash can silently remove a
// template from the run, and every file ends with a status the run can prove.
//
// The external binary is executed once per batch, without a shell, and every
// JSONL record is attributed back to the uploaded file that produced it through
// the path nuclei reports.
func RunNucleiDir(ctx context.Context, dir string, staged []StagedFile, request NucleiRequest) (NucleiRun, error) {
	target := strings.TrimSpace(request.URL)
	if target == "" {
		return NucleiRun{}, fmt.Errorf("target URL is required")
	}
	if strings.TrimSpace(dir) == "" {
		return NucleiRun{}, fmt.Errorf("template directory is required")
	}
	selectedDir, err := resolveTemplateCategory(dir, request.CategoryPath)
	if err != nil {
		return NucleiRun{}, err
	}
	selectedFiles, err := filterStagedTemplatesByCategory(staged, request.CategoryPath)
	if err != nil {
		return NucleiRun{}, err
	}
	templateCount := 0
	for _, file := range selectedFiles {
		if !file.Support {
			templateCount++
		}
	}
	if templateCount == 0 {
		return NucleiRun{}, fmt.Errorf("selected folder contains no YAML templates")
	}
	staged = selectedFiles
	for _, level := range dedupeLower(request.Severity) {
		if !validSeverities[level] {
			return NucleiRun{}, fmt.Errorf("invalid severity %q", level)
		}
	}
	plan, err := BuildPlan(PlanRequest{Dir: selectedDir, Staged: staged})
	if err != nil {
		return NucleiRun{}, err
	}
	// The plan owns its batch directories from here, so they are removed whether
	// the run finished, failed or was cancelled.
	defer plan.Clean()
	return RunNucleiPlan(ctx, &plan, request)
}

// There is no `-validate` pass, and no step that could ask for one.
//
// WHY IT IS GONE, MEASURED ON v3.11.1 AGAINST THIS CORPUS. The pass cost 3 s on
// `http/cves/2025` where the scan itself took 73 s, and on the operator's own
// folders it refused a WHOLE run because of single files:
//
//	folder                 documents  -validate  ERR lines  exit
//	code                        304        2 s         0        0
//	dast                        251        3 s         0        0
//	dns                          31        1 s         0        0
//	ssl                          38        3 s         0        0
//	javascript                  131        2 s         3        1
//	http                      11 656       19 s       259        1
//	nuclei-wordfence-cve      84 999       75 s         2        1
//
// `[FTL] Could not validate templates` came from ONE document — `CVE-2025-11833`,
// refused for `access to helper file helpers/wordlists/numbers.txt denied (hard
// link)` — while 414 neighbours were fine. The operator's instruction (2026-10-06)
// is to scan every template, and a pre-pass whose verdict cancels 99.8 % of a folder
// is the opposite of that.
//
// What replaced it is not nothing: the run itself reports per file. `-ms` makes the
// binary write a JSONL record for every template it executed, and a file with no
// record did not run and is reported `skipped` with the reason the binary's own
// stderr carries. `nuclei_exec.go` already collects `[FTL]` and `[ERR]` lines from
// every invocation and keeps them in `stats.stderr` and `stats.invocations`, so a
// refusal is still reported — as the scan's own output rather than as a pre-pass
// verdict that could cancel the whole folder.

// RunNucleiPlan executes a built plan. It is separate from RunNucleiDir so a plan
// can be built and asserted on without running anything, and so a caller can see
// the plan before it is spent.
func RunNucleiPlan(ctx context.Context, plan *NucleiPlan, request NucleiRequest) (NucleiRun, error) {
	target := strings.TrimSpace(request.URL)
	// Every file gets its row before anything runs, so a batch that later fails
	// still reports its files rather than losing them. Rows are keyed by the
	// uploaded file and emitted in upload order, so the report reads the way the
	// folder does no matter which batch the plan put a template in.
	run := NucleiRun{Templates: make([]TemplateResult, 0, plan.TotalFiles)}
	rowByKey := make(map[string]int, plan.TotalFiles)
	for _, entry := range plan.ledger {
		key := entry.key
		row := resultFor(entry.file, TemplateInvalid, entry.file.Reason)
		if entry.kind == planInvalidDuplicate {
			row.Status = TemplateDuplicate
		}
		rowByKey[key] = len(run.Templates)
		run.Templates = append(run.Templates, row)
	}
	for _, batch := range plan.Batches {
		for _, batchFile := range batch.Files {
			row := resultFor(batchFile.File, TemplateSkipped, "")
			row.Batch = batch.Index
			row.batchPath = cleanPathForCompare(batchFile.Path)
			rowByKey[batchFile.Key] = len(run.Templates)
			run.Templates = append(run.Templates, row)
		}
	}
	run.Templates = orderRowsByInput(plan.Inputs, run.Templates, rowByKey, plan.rowKeys)
	// The batch-path index is built from the reordered rows, so it points at the
	// row a JSONL record belongs to no matter where the upload order put it.
	rowByBatchPath := make(map[string]int, len(run.Templates))
	for index := range run.Templates {
		if run.Templates[index].batchPath != "" {
			rowByBatchPath[run.Templates[index].batchPath] = index
		}
	}
	if len(plan.Batches) == 0 {
		run.Stats = runStatistics(plan, nil, target, run.Templates)
		return run, nil
	}
	// A planned run loads templates from per-batch directories, so the path in a
	// JSONL record is the batch path. A live-stream consumer needs the same
	// mapping, and it is only known once the plan exists.
	if request.Resolve == nil {
		request.Resolve = plan.Resolve
	}
	if request.OnPlan != nil {
		// The plan is published before the first invocation so a live row can be
		// attributed to the uploaded file it came from, whatever the batch layout.
		request.OnPlan(plan)
	}
	outcomes := make([]batchOutcome, 0, len(plan.Batches))
	for _, batch := range plan.Batches {
		outcome, err := executeBatch(ctx, batch, target, request)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return NucleiRun{}, ctxErr
			}
			return NucleiRun{}, err
		}
		outcomes = append(outcomes, outcome)
		applyBatchOutcome(&run, batch, outcome, rowByBatchPath)
	}
	// The binary is not the only runner, and a refusal by one runner is not the end
	// of a check. Every row the binary left without a verdict is handed to this
	// project's own runner, which sends the document's request through the same
	// recording transport and scores the answer with nuclei's own operators. This
	// runs before the statistics are computed, so the counts the report shows
	// describe the rows the operator can actually read.
	// The two corrections this project's runner makes to a binary `not_matched` are
	// counted on their own, because they are the only rows in the report where two
	// runners disagree about the outcome — and a disagreement that is not counted is
	// a disagreement the operator cannot see.
	corrections := map[string]int{}
	performedLocally := applyLocalFallback(ctx, &run, plan.Inputs, target, request.Transport, corrections)
	// `run.Findings` is the flat list the report and every CSV/HTML export read,
	// and it is assembled from the per-file rows *after* the local fallback has
	// added whatever the binary would not execute.
	//
	// It used to be assigned only inside `if performedLocally > 0`, which reads as
	// "rebuild the list only when the fallback changed it". It does not work that
	// way: the list is a *derived* value, and a run where the binary executed every
	// file — the ordinary case, and the one every operator hits first — left it
	// empty. `run.Templates[i].Findings` was full and `run.Findings` was nil, so
	// the per-file table showed the match and the summary said "0 findings". The
	// same run, with one file the binary refused, produced a correct list, which is
	// why the defect survived: it is invisible in exactly the run that needs no
	// fallback.
	collected := make([]map[string]interface{}, 0, 16)
	for _, item := range run.Templates {
		collected = append(collected, item.Findings...)
	}
	run.Findings = dedupeFindings(collected)
	run.Stats = runStatistics(plan, outcomes, target, run.Templates)
	run.Stats["performed_locally"] = performedLocally
	if corrections[localRunnerRefusalRewrite] > 0 || corrections[localRunnerFindingRewrite] > 0 {
		run.Stats["local_runner_refusals_named"] = corrections[localRunnerRefusalRewrite]
		run.Stats["local_runner_findings"] = corrections[localRunnerFindingRewrite]
		// Said in words, because two counters in a JSON blob are read by nobody.
		// Each of these rows was a `not_matched` the binary recorded without ever
		// sending the request; the first group is now named as a check that did not
		// run, the second is a finding the binary did not report.
		run.Stats["local_runner_correction_note"] = fmt.Sprintf(
			"of the files nuclei recorded as `not_matched`, this project's own runner named %d "+
				"as checks it could not perform (the placeholders were never generated) and found %d "+
				"matching",
			corrections[localRunnerRefusalRewrite], corrections[localRunnerFindingRewrite])
	}
	run.Stats["fallback_note"] = fmt.Sprintf(
		"%d of %d files the binary would not execute, or recorded as not matched without "+
			"executing, were scanned by this project's own runner",
		performedLocally, len(run.Templates))
	return run, nil
}

// orderRowsByInput rewrites the report rows into the order the files were
// uploaded. A planned run builds its rows in the order it intends to execute
// them, which is the right order to *run* and the wrong order to *read*: a folder
// of thirty thousand templates has to come back in the order the operator sent
// it, or the row for a file moves every time the plan changes.
func orderRowsByInput(inputs []StagedFile, rows []TemplateResult, rowByKey map[string]int, rowKeys map[string]string) []TemplateResult {
	if len(inputs) != len(rows) {
		// The plan is supposed to account for every file. If it somehow does not,
		// the rows are already complete and reordering them would only risk
		// dropping one, so they are returned as they are.
		return rows
	}
	ordered := make([]TemplateResult, 0, len(rows))
	used := make([]bool, len(rows))
	unstaged := 0
	for _, file := range inputs {
		key := rowKeys[inputIdentity(file, unstaged)]
		if file.StagedPath == "" {
			unstaged++
		}
		index, known := rowByKey[key]
		if !known || index < 0 || index >= len(rows) || used[index] {
			return rows
		}
		used[index] = true
		ordered = append(ordered, rows[index])
	}
	// A row the input list does not account for is appended rather than dropped.
	for index, row := range rows {
		if !used[index] {
			ordered = append(ordered, row)
		}
	}
	return ordered
}

// dedupeFindings drops a finding that two batches both reported. A template id
// that appears in two batches means two distinct documents declared it, and each
// carries its own evidence; a repeated record is the same template seen twice,
// which the JSONL already deduplicates within a batch.
func dedupeFindings(findings []map[string]interface{}) []map[string]interface{} {
	seen := map[string]bool{}
	unique := make([]map[string]interface{}, 0, len(findings))
	for _, finding := range findings {
		key := findingKey(finding)
		if key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		unique = append(unique, finding)
	}
	return unique
}

func findingKey(finding map[string]interface{}) string {
	parts := make([]string, 0, 4)
	for _, field := range []string{"template_id", "matched_at", "matcher_name", "curl_command"} {
		if value, ok := finding[field]; ok {
			parts = append(parts, fmt.Sprint(value))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\x00")
}

// executeBatch runs the binary once for one batch of the plan.
func executeBatch(ctx context.Context, batch NucleiBatch, target string, request NucleiRequest) (batchOutcome, error) {
	outcome := batchOutcome{Batch: batch.Index}
	// The batch's capability set is the only source of extra flags, so a flag is
	// added exactly for the documents that need it and never for the run at large.
	scoped := request
	scoped.Protocols = batch.Capabilities
	// A batch the plan gave its own directory is the one invocation where the
	// reserved flag belongs: every file in it asked for the capability, so adding
	// it cannot cancel anything.
	//
	// It reads `needsReservedFlag`, not `isolated`. A batch can be isolated for
	// the deadline — a document that declares none of its own — and those
	// documents did not ask for `-dast`. Measured on v3.11.1 against
	// `javascript/` (131 documents): 8 of them were launched with `-dast` on a
	// one-file directory holding no fuzzing template, and every one answered
	// `[FTL] Could not run nuclei: no templates provided for scan` with exit 1 and
	// no records. The flag cancels the invocation; isolation is what saves it.
	if batch.Key.needsReservedFlag() {
		scoped.IsolatedProtocol = isolatedCapability
	}
	// Only -ms makes the binary emit a record for every template it executes, and
	// the report has to be able to tell "ran and matched nothing" from "never
	// ran". The records themselves are not findings: isFinding drops every
	// matcher-status=false line.
	scoped.Options.MatcherStatus = true
	// The bound that will stop this invocation has to reach the argument builder:
	// a per-request timeout above it can never produce a verdict, so it can only
	// ever be reported as "stopped at the deadline".
	scoped.deadlineSec = batchTimeoutSec(batch)
	args, err := buildNucleiArgs(target, batch.Dir, scoped)
	if err != nil {
		// A header file may already exist even though argument building failed partway,
		// so the cleanup is registered before the error return rather than after it.
		return outcome, err
	}
	// The header file holding the capture token is removed as soon as this batch ends, on
	// every path out — including cancellation, which is the path a long run usually takes.
	// A leftover 0600 file with the token in it would otherwise sit in the temp directory
	// for the rest of the process's life.
	defer removeNucleiHeaderFiles(args)
	args = append(args, "-jsonl")
	// Stats are observational only: they make the live progress of a long run
	// visible to the browser and in the engine log without changing how the
	// templates are executed.
	args = append(args, "-stats", "-stats-interval", "1")
	// The report records the redacted vector: the real header-file path is a live path to
	// a file that held the capture token, and `stats.args` is streamed to the browser.
	outcome.Args = redactNucleiHeaderFiles(args)
	output, err := os.CreateTemp("", "rr-nuclei-*.jsonl")
	if err != nil {
		return outcome, err
	}
	outputPath := output.Name()
	_ = output.Close()
	defer os.Remove(outputPath)
	if request.OnOutput != nil {
		// The binary appends a record as each template finishes, so tailing this
		// file is what makes results appear while the scan is still running.
		request.OnOutput(outputPath)
	}
	execCtx := ctx
	cancel := func() {}
	batchDeadlineSec := batchTimeoutSec(batch)
	if batchDeadlineSec > 0 {
		execCtx, cancel = context.WithTimeout(ctx, time.Duration(batchDeadlineSec)*time.Second)
	}
	defer cancel()
	outcome.DrivesBrowser = batch.drivesBrowser()
	command := exec.CommandContext(execCtx, nucleiBinary(), append(args, "-o", outputPath)...)
	// A `code` template runs as a grandchild of this process, so cancellation has
	// to reach the group or the template outlives the scan that started it.
	// Measured: 17 parentless `python3` processes, the oldest twelve hours old,
	// survived batches that were killed on their own deadline. See
	// applyProcessGroup for the numbers.
	applyProcessGroup(command)
	// Nuclei writes flag errors to stdout and its logs and live stats to
	// stderr, so both streams are captured: a rejected flag must not surface as
	// a bare "exit status 2", and the stats lines drive the progress display.
	// Both streams feed the parser because the exact channel a line arrives on
	// is a nuclei implementation detail, not an API promise.
	// The JSONL report still arrives through -o.
	onStats := func(string) {}
	if request.OnStats != nil {
		onStats = func(line string) {
			if update, ok := ParseNucleiStatsLine(line); ok {
				request.OnStats(update)
			}
		}
	}
	reported := newNucleiOutput(onStats)
	diagnostics := newNucleiOutput(onStats)
	command.Stdout = reported
	command.Stderr = diagnostics
	// A killed binary can leave a child holding the diagnostics pipe open, which
	// would keep Wait blocked past the cancellation. Bound the drain so a route
	// switch stays responsive and whatever output arrived is still reported.
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		// A binary that cannot be started is not one bad batch, it is no scanner
		// at all, so it is surfaced as an error instead of being reported as a
		// per-file "not run" for every template in the folder.
		return outcome, err
	}
	if request.OnProcess != nil && command.Process != nil {
		request.OnProcess(command.Process)
	}
	runErr := command.Wait()
	if runErr != nil {
		// A killed process also reports an *exec.ExitError, so a cancelled
		// context has to be checked first. Otherwise a route switch would be
		// reported as an ordinary non-zero exit instead of a cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return outcome, ctxErr
		}
		// The parent is still live, so the only thing that can have stopped this
		// process is the deadline set a few lines above. Recording it is what lets
		// the row say "stopped at 120 s because the browser never answered"
		// instead of "the binary could not be executed".
		if execCtx.Err() != nil {
			outcome.DeadlineSec = batchDeadlineSec
			outcome.Error = nil
			parsed, parseErr := parseNucleiReport(outputPath)
			if parseErr == nil {
				outcome.Report = parsed
			}
			outcome.Stdout = reported.Text()
			outcome.Stderr = diagnostics.Text()
			return outcome, nil
		}
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return outcome, fmt.Errorf("nuclei could not be started: %w", runErr)
		}
		outcome.ExitCode = exitErr.ExitCode()
		outcome.Error = runErr
	}
	parsed, parseErr := parseNucleiReport(outputPath)
	if parseErr != nil {
		return outcome, fmt.Errorf("nuclei output could not be read: %w", parseErr)
	}
	outcome.Report = parsed
	outcome.Stdout = reported.Text()
	outcome.Stderr = diagnostics.Text()
	outcome.Failed = batchRefusedRun(outcome)
	return outcome, nil
}

// batchRefusedRun reports whether the binary refused the invocation as a whole
// rather than running the templates in it. The message is measured on v3.11.1:
// `-dast` on a directory with no fuzzing template, and a `-pt` set the directory
// does not satisfy, both abort with "no templates provided for scan" and no
// record at all, which is indistinguishable from "ran and matched nothing"
// unless the exit status and the text are read together.
func batchRefusedRun(outcome batchOutcome) bool {
	if outcome.Error == nil {
		return false
	}
	if len(outcome.Report.Executed) > 0 || len(outcome.Report.Findings) > 0 {
		return false
	}
	combined := outcome.Stdout + "\n" + outcome.Stderr
	return strings.Contains(combined, "no templates provided for scan")
}

// applyBatchOutcome turns one batch's evidence into final per-file statuses.
//
// A file the binary wrote a record for ran; what that record says decides the
// status. A file the binary never mentioned did not run, and its reason names the
// concrete cause from the run instead of a guess.
func applyBatchOutcome(run *NucleiRun, batch NucleiBatch, outcome batchOutcome, rowByBatchPath map[string]int) {
	executed := 0
	for _, batchFile := range batch.Files {
		clean := cleanPathForCompare(batchFile.Path)
		rowIndex, known := rowByBatchPath[clean]
		if !known {
			continue
		}
		row := &run.Templates[rowIndex]
		// "Executed" is a path set read from the binary's own JSONL output, and it
		// is the only proof that a template actually ran.
		ran := outcome.Report.Executed[clean]
		if ran {
			executed++
		}
		matched := 0
		for _, hit := range outcome.Report.Findings {
			if cleanPathForCompare(hit.TemplatePath) != clean {
				continue
			}
			matched++
			row.Findings = append(row.Findings, hit.toMap())
		}
		switch {
		case matched > 0:
			row.Status = TemplateMatched
			row.Matches = matched
			row.Reason = ""
		case batchFile.File.Meta.IsWorkflow() && !ran:
			// Ordered before `!ran` for the same reason the flow case is: the
			// status is about what the binary does with this kind of file, and
			// `skipped` would assert the opposite of what happened. A workflow
			// ran its subtemplates; it just has no record of its own to be
			// matched on.
			row.Status = TemplateWorkflow
			row.Reason = batchFile.File.Meta.WorkflowReason()
		case batchFile.File.Meta.IsFlow() && !ran:
			// Checked before `!ran`, and the `!ran` test is part of the condition
			// rather than a separate case, because measured on nuclei v3.11.1 a
			// flow template is NOT a file the binary refuses: `flow: http(1) && …`
			// is loaded and run with no extra flag, and a `self-contained: true`
			// JavaScript flow is loaded because `documentCapabilities` asks for
			// `-esc`. So a flow that carries no JSONL record is a file the binary
			// did not execute, and saying so is the whole point of the status: it
			// must never be handed to a flow that DID run, because then the report
			// calls an executed template unchecked — the one claim this report
			// must never make. Measured 2026-09-29: with this case ordered after
			// `!ran` it was unreachable for its stated purpose and caught every
			// flow that ran and matched nothing.
			row.Status = TemplateFlow
			row.Reason = batchFile.File.Meta.FlowReason()
		case batchFile.File.Meta.IsReservedFuzzTagged() && !ran:
			// Ahead of `!ran` because the generic branch blames a load-time clash
			// that did not happen: the batch that names this file also produced
			// records for its other files, so nothing about the batch stopped this
			// one from loading. The binary will not compile it at all, and saying
			// so is the difference between a file the operator knows was never
			// checked and a file they believe was.
			row.Status = TemplateUncompiled
			row.Reason = batchFile.File.Meta.ReservedFuzzTagReason()
		case !ran:
			row.Status = TemplateSkipped
			row.Reason = notRunReason(outcome, batch, batchFile, executed)
		case batchFile.File.Meta.Requestless():
			// A code/file template or local-only JavaScript ran and the binary
			// reported it, but it did not address the target. Reporting "not
			// matched" would claim a check that was never made.
			row.Status = TemplateNoRequest
			row.Reason = fmt.Sprintf(
				"Ran without a target request: this %q template uses only local capabilities, "+
					"so it cannot match or miss against the target.",
				batchFile.File.Meta.Protocol)
		default:
			row.Status = TemplateNotMatched
			row.Reason = requestErrorReason(outcome, clean)
		}
	}
}

// notRunReason explains a file the binary never mentioned, using the facts of
// this invocation rather than a guess.
func notRunReason(outcome batchOutcome, batch NucleiBatch, batchFile BatchFile, executed int) string {
	id := ""
	if batchFile.File.Meta != nil {
		id = batchFile.File.Meta.TemplateID
	}
	if outcome.Failed {
		detail := firstDiagnosticLine(outcome)
		if detail != "" {
			return fmt.Sprintf(
				"Not run: nuclei refused this invocation before running any template, so no file in it was "+
					"executed. The binary said: %s", detail)
		}
		return "Not run: nuclei refused this invocation before running any template, so no file in it was executed."
	}
	if outcome.Error != nil {
		return fmt.Sprintf("Not run: the binary could not be executed for this batch (%s). "+
			"Full binary output is in the run diagnostics.", oneLine(outcome.Error.Error()))
	}
	// Stopped on a bound this project set. The distinction from the branch above
	// is the whole point: the binary started, ran, and was ended on purpose, so
	// "could not be executed" would be false and unhelpful.
	//
	// For a browser batch the bound is short because the resource is local: the
	// browser's coming up is a fact about this machine and not about the target.
	// Measured on v3.11.1 here, Chromium opens its DevTools endpoint and the
	// session never ends — a single 24-file headless batch did not finish in
	// 200 s, against 11 s for a 183-file HTTP batch and 22 s for a 60-file
	// `code` batch on the same fixture.
	if outcome.DeadlineSec > 0 {
		subject := "this batch"
		if outcome.DrivesBrowser {
			subject = "this batch, whose templates drive a local browser"
		}
		// "those results are reported" is only true when there were any. A batch
		// that never got a template out says 0 of N, and claiming results for it
		// would be the same blur as the one this sentence replaces.
		counted := fmt.Sprintf("It executed %d of the %d template(s) before the bound expired", executed, len(batch.Files))
		if executed > 0 {
			counted += ", and those results are reported."
		} else {
			counted += ", so nothing in it was checked."
		}
		return fmt.Sprintf(
			"Not run: nuclei was stopped at this project's %d-second deadline for %s, so no template "+
				"left in it produced a verdict. %s Raise RR_NUCLEI_TIMEOUT_SEC for the whole run, or "+
				"RR_NUCLEI_ISOLATED_TIMEOUT_SEC for a browser or single-template batch, to give it more "+
				"time; full binary output is in the run diagnostics.",
			outcome.DeadlineSec, subject, counted)
	}
	// A capability the binary rejected despite the flag being present is the
	// useful answer, because the operator can act on it.
	if reason := missingCapabilityReason(batch, batchFile); reason != "" {
		return reason
	}
	// The same, for a complaint that names the file by path instead of by id:
	// `[WRN] Could not parse template <path>: could not compile request:
	// cause="no valid engine found" chain="[ftp-service-running] engines
	// 'powershell,powershell.exe' not available on host"`. Measured on this
	// corpus that is the whole of the 62 `skipped` files that carry no id-scoped
	// complaint — a `powershell`-only template on a Linux host, which is a fact
	// about the machine and not about the scan.
	//
	// It is tried **before** the id-scoped reader, and the order is not
	// cosmetic. That one line names the template twice: once as the file the
	// complaint is about, and again inside the quoted `chain=`, which is how
	// nuclei reports a matcher compile error. `strings.Index` finds the *first*
	// `[id]`, so a line that only mentions the id inside `chain=` yields the tail
	// alone — measured output before this ordering:
	//
	//     nuclei named this template and said: engines 'powershell,powershell.exe'
	//     not available on host"
	//
	// which names the missing engine but drops the sentence that says what was
	// refused. The path-scoped reader cuts at the *first* colon after the path,
	// which is the structural one, and keeps the whole complaint.
	if detail := binaryPathComplaintAbout(outcome, batchFile); detail != "" {
		return fmt.Sprintf(
			"Not run: nuclei refused to compile this file and said: %s It executed %d of the %d "+
				"template(s) in this batch, so the batch itself was fine. Full binary output is in the "+
				"run diagnostics.",
			detail, executed, len(batch.Files))
	}
	// The binary's own words about THIS file, when it wrote any. nuclei prints
	// `[<id>] Could not execute code: cause="exit status 1" chain="…"` for a
	// `code` template whose engine died, and `[<id>] Could not parse template …`
	// for one it could not compile — and then produces no JSONL record for that
	// file, which is what lands it in this branch. Measured on v3.11.1 against
	// the official corpus, `CVE-2025-6984` answers exactly that line, with
	// `ModuleNotFoundError: No module named 'langchain_community'` inside it.
	//
	// Without this the row says only "nuclei returned no record", and the cause
	// sits in a diagnostic the operator has to go and find: the file was not
	// merely "not run", it was refused because a Python module it imports is not
	// installed, and that is a fact about the machine rather than about the scan.
	if detail := binaryComplaintAbout(outcome, batchFile); detail != "" {
		return fmt.Sprintf(
			"Not run: nuclei named this template and said: %s It executed %d of the %d template(s) "+
				"in this batch, so the batch itself was fine. Full binary output is in the run diagnostics.",
			detail, executed, len(batch.Files))
	}
	return fmt.Sprintf(
		"Not run: nuclei returned no record for template id %q even though %s was passed for it. "+
			"It executed %d of the %d template(s) in this batch and the options were: %s. "+
			"Full binary output is in the run diagnostics.",
		id, batchLabel(batch), executed, len(batch.Files), strings.Join(outcome.Args, " "))
}

// binaryPathComplaintAbout finds the compile complaint that names this file by
// its staged path rather than by its id.
//
// nuclei writes `Could not parse template <path>: could not compile request:
// cause="…" chain="…"`, and the path is the only thing tying that line to one
// row — a batch prints the complaint for every file it could not build. The
// comparison is on the cleaned path because the binary echoes the staging
// directory it was given, and the row carries the same one.
func binaryPathComplaintAbout(outcome batchOutcome, batchFile BatchFile) string {
	staged := cleanPathForCompare(batchFile.Path)
	if staged == "" {
		return ""
	}
	for _, stream := range []string{outcome.Stderr, outcome.Stdout} {
		for _, line := range strings.Split(stream, "\n") {
			plain := strings.TrimSpace(ansiPattern.ReplaceAllString(line, ""))
			at := strings.Index(plain, "Could not parse template ")
			if at < 0 {
				continue
			}
			rest := plain[at+len("Could not parse template "):]
			end := strings.Index(rest, ":")
			if end < 0 || cleanPathForCompare(rest[:end]) != staged {
				continue
			}
			return oneLine(rest[end+1:])
		}
	}
	return ""
}

// binaryComplaintAbout finds the line nuclei printed about one specific template.
//
// The binary prefixes its per-template diagnostics with the template id in
// brackets, which is what makes the line attributable: a batch prints one line
// per template it had trouble with, and a row about template A must not be
// handed template B's cause. Only lines that carry the id count, so an
// invocation-level complaint still falls through to the batch-level sentence.
func binaryComplaintAbout(outcome batchOutcome, batchFile BatchFile) string {
	if batchFile.File.Meta == nil {
		return ""
	}
	id := strings.TrimSpace(batchFile.File.Meta.TemplateID)
	if id == "" {
		return ""
	}
	for _, stream := range []string{outcome.Stderr, outcome.Stdout} {
		for _, line := range strings.Split(stream, "\n") {
			plain := strings.TrimSpace(ansiPattern.ReplaceAllString(line, ""))
			marker := "[" + id + "]"
			// The marker is not at the start of the line: nuclei prefixes its
			// severity first, so the real text is
			// `[WRN] [CVE-2025-6984] Could not execute code: …`. Anchoring on the
			// marker rather than on the line is what makes this work, and
			// `strings.Index` plus a non-word check on the following character
			// keeps `[id]` from matching inside `[id]-suffix`.
			at := strings.Index(plain, marker)
			if at < 0 {
				continue
			}
			rest := plain[at+len(marker):]
			if rest != "" && !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, ":") {
				continue
			}
			return oneLine(rest)
		}
	}
	return ""
}

// missingCapabilityReason names the flag the document needs when the binary still
// did not load it. It is reached when a capability-gated file produced no record
// despite its flag being in the command line, which is the only situation in
// which the flag set is the actionable answer.
func missingCapabilityReason(batch NucleiBatch, batchFile BatchFile) string {
	if batchFile.File.Meta == nil || len(batchFile.File.Meta.Capabilities) == 0 {
		return ""
	}
	present := map[string]bool{}
	for _, arg := range capabilityFlagArgs(batch.Capabilities) {
		present[arg] = true
	}
	missing := make([]string, 0, len(batchFile.File.Meta.Capabilities))
	for _, capability := range batchFile.File.Meta.Capabilities {
		flag := capabilityFlag[capability]
		if !present[flag] {
			missing = append(missing, flag)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"Not run: this template needs %s, which was passed for it, so nuclei itself refused to load it. "+
			"Full binary output is in the run diagnostics.",
		strings.Join(missing, " and "))
}

func batchLabel(batch NucleiBatch) string {
	if len(batch.Capabilities) == 0 {
		return "no capability flag"
	}
	return strings.Join(capabilityFlagArgs(batch.Capabilities), " ")
}

// requestErrorReason carries a per-template request failure into the row, so a
// template whose individual request timed out is distinguishable from one the
// target simply did not match.
func requestErrorReason(outcome batchOutcome, batchPath string) string {
	for _, hit := range outcome.Report.Findings {
		if cleanPathForCompare(hit.TemplatePath) == batchPath && hit.Error != "" {
			return "Template ran, but its request failed: " + oneLine(hit.Error)
		}
	}
	for _, failure := range outcome.Report.Failures {
		if cleanPathForCompare(failure.TemplatePath) == batchPath {
			return "Template ran, but its request failed: " + oneLine(failure.Error)
		}
	}
	return ""
}

// firstDiagnosticLine returns the most useful single line of the binary's own
// output for a refused invocation.
func firstDiagnosticLine(outcome batchOutcome) string {
	combined := strings.TrimSpace(outcome.Stderr)
	if combined == "" {
		combined = strings.TrimSpace(outcome.Stdout)
	}
	for _, line := range strings.Split(combined, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[FTL]") || strings.HasPrefix(trimmed, "[ERR]") {
			return oneLine(trimmed)
		}
	}
	return ""
}

// runStatistics renders the run counters, the plan and every invocation's own
// evidence. The binary's output is attached per invocation and aggregated at the
// top level, not only on failure: it is the evidence for a template that did not
// run and for any error the operator has to see, and nothing is trimmed to a tail.
func runStatistics(plan *NucleiPlan, outcomes []batchOutcome, target string, templates []TemplateResult) map[string]interface{} {
	matched, total := countStatus(templates, TemplateMatched)
	notMatched, _ := countStatus(templates, TemplateNotMatched)
	invalid, _ := countStatus(templates, TemplateInvalid)
	skipped, _ := countStatus(templates, TemplateSkipped)
	noRequest, _ := countStatus(templates, TemplateNoRequest)
	duplicate, _ := countStatus(templates, TemplateDuplicate)
	findings := 0
	for _, item := range templates {
		findings += len(item.Findings)
	}
	stats := map[string]interface{}{
		"engine": "nuclei",
		"binary": nucleiBinary(),
		// The bound in force, stated rather than implied: a run that stops on the
		// deadline has to say which deadline, or the operator reads it as a crash.
		"timeout_sec": nucleiTimeoutSec(),
		"url":         target,
		"findings":    findings,
		"files":       total,
		"matched":     matched,
		"not_matched": notMatched,
		"invalid":     invalid,
		"skipped":     skipped,
		// Reported apart from "not matched" so a run cannot be read as "every
		// template that did not match, therefore everything was checked".
		"no_request": noRequest,
		// A duplicate is a file whose content is already covered by another file,
		// so it is counted apart from both a check that ran and a check that failed.
		"duplicate": duplicate,
		"executed":  total - invalid - skipped - duplicate,
		"batches":   len(outcomes),
		"exit_code": 0,
	}
	if len(outcomes) == 0 {
		// Nothing was executed. A run in which every file was rejected before the
		// scan is reported as skipped with the per-file reasons, instead of
		// surfacing the binary's empty-directory exit status.
		stats["exit_status"] = "skipped"
		return stats
	}
	worstCode := 0
	anyFailed := false
	anyError := false
	invocations := make([]map[string]interface{}, 0, len(outcomes))
	stdoutParts := make([]string, 0, len(outcomes))
	stderrParts := make([]string, 0, len(outcomes))
	argParts := make([]string, 0, len(outcomes))
	for _, outcome := range outcomes {
		if outcome.ExitCode > worstCode {
			worstCode = outcome.ExitCode
		}
		if outcome.Failed {
			anyFailed = true
		}
		if outcome.Error != nil {
			anyError = true
		}
		label := "batch " + strconv.Itoa(outcome.Batch)
		entry := map[string]interface{}{
			"batch":     outcome.Batch,
			"args":      outcome.Args,
			"exit_code": outcome.ExitCode,
		}
		if outcome.Failed {
			entry["refused"] = true
		}
		if outcome.Error != nil {
			entry["error"] = outcome.Error.Error()
		}
		if text := outcome.Stdout; text != "" {
			entry["stdout"] = text
			stdoutParts = append(stdoutParts, label+"\n"+text)
		}
		if text := outcome.Stderr; text != "" {
			entry["stderr"] = text
			stderrParts = append(stderrParts, label+"\n"+text)
		}
		invocations = append(invocations, entry)
		argParts = append(argParts, label+": "+strings.Join(outcome.Args, " "))
	}
	stats["invocations"] = invocations
	stats["exit_code"] = worstCode
	// The whole-run view of the binary's words. With a single invocation this is
	// exactly that invocation's output, so a one-batch report reads the same as it
	// always did.
	if text := strings.Join(stdoutParts, "\n"); text != "" {
		stats["stdout"] = text
	}
	if text := strings.Join(stderrParts, "\n"); text != "" {
		stats["stderr"] = text
	}
	stats["args"] = argParts
	switch {
	case anyError:
		stats["exit_status"] = "failed"
	case anyFailed:
		// A batch the binary refused is not a scanner failure: the other batches
		// ran, and the refused one says so in its own row.
		stats["exit_status"] = "partial"
	default:
		stats["exit_status"] = "ok"
	}
	// `validation_output` is deliberately NOT published any more. It held the text
	// `nuclei -validate` printed, and after that pass was removed it was being
	// filled from the SCAN's own stderr under a name that said otherwise — a report
	// key describing a command the project no longer runs. The binary's words are
	// still in `stderr` and in each `invocations[].stderr`, under their own names.
	// The plan is merged in last so its own `batches` field wins: the number the
	// operator needs is how many invocations the whole run used, which is the
	// plan's answer, not the count of the ones that started.
	for key, value := range plan.Describe() {
		stats[key] = value
	}
	return stats
}

func countStatus(templates []TemplateResult, status string) (count, total int) {
	for _, item := range templates {
		if item.Status == status {
			count++
		}
	}
	return count, len(templates)
}

var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

// diagnosticsText turns the binary's ANSI coloured output into readable text.
// The full output is kept: it is the evidence for a skipped template or an
// error, so nothing is trimmed to a tail.
func diagnosticsText(raw string) string {
	cleaned := strings.ReplaceAll(ansiPattern.ReplaceAllString(raw, ""), "\r", "")
	lines := make([]string, 0, 16)
	for _, line := range strings.Split(cleaned, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return strings.Join(lines, "\n")
}

func oneLine(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", " "))
}

// nucleiReport is what one JSONL file proves: the matches it carries, the set of
// template paths the binary actually touched, and the per-template failures. The
// second part matters because -ms writes a record for every executed template, so
// a staged file with no record at all was never run.
type nucleiReport struct {
	Findings []nucleiFinding
	Executed map[string]bool
	// Failures are the records whose `error` field is set. They prove the template
	// ran and its individual request did not work out, which is a different
	// statement from both "matched" and "never ran".
	Failures []nucleiFailure
}

// nucleiFailure is one per-template request failure the binary reported.
type nucleiFailure struct {
	TemplatePath string
	TemplateID   string
	Error        string
}

func parseNucleiReport(path string) (nucleiReport, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nucleiReport{}, err
	}
	defer handle.Close()
	report := nucleiReport{Findings: []nucleiFinding{}, Executed: map[string]bool{}}
	reader := bufio.NewReader(handle)
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			line = strings.TrimSpace(line)
			if line != "" {
				var hit nucleiFinding
				// Any well-formed record with a template path proves the binary
				// resolved and executed that template, whether or not a matcher
				// fired.
				if err := json.Unmarshal([]byte(line), &hit); err == nil && hit.TemplateID != "" {
					if trimmed := strings.TrimSpace(hit.TemplatePath); trimmed != "" {
						report.Executed[cleanPathForCompare(trimmed)] = true
					}
					if hit.isFinding() {
						report.Findings = append(report.Findings, hit)
					}
					if strings.TrimSpace(hit.Error) != "" {
						report.Failures = append(report.Failures, nucleiFailure{
							TemplatePath: cleanPathForCompare(hit.TemplatePath),
							TemplateID:   hit.TemplateID,
							Error:        oneLine(hit.Error),
						})
					}
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return report, readErr
		}
	}
	return report, nil
}

func dedupeLower(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}
