package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func nucleiBinary() string  { return envValue("RR_NUCLEI_BINARY", "nuclei") }
func nucleiTimeoutSec() int { return optionalPositiveInt("RR_NUCLEI_TIMEOUT_SEC") }
func nucleiRateLimit() int  { return optionalPositiveInt("RR_NUCLEI_RATE_LIMIT") }
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
	// TemplateSkipped means the binary accepted the file but never executed it,
	// which happens when another file already carries the same template id. It
	// is reported separately so the report never claims a file ran when it did
	// not.
	TemplateSkipped = "skipped"
	// TemplateInvalid means the file never reached the scanner and reports why.
	TemplateInvalid = "invalid"
	// TemplateNoRequest means the file ran and the binary reported it, but the
	// template never addressed the target: `code`, `file` and `javascript`
	// templates run local commands or read local files and issue no HTTP request
	// at all. Counting them as "ran, no matches" claims a check that was never
	// made, so they get their own status with the reason attached.
	TemplateNoRequest = "no_request"
)

// requestLessProtocols are the template types that never address a target URL.
// They execute a local engine or read a local file, so a scan of `-u <target>`
// runs them without a single request to that target. Measured on the installed
// nuclei v10.4.9 template set they are 960 code, 447 file and 192 javascript
// files against 14021 — more than a fifth of a real folder, which is why a run
// reports a request count well below the file count and both are correct.
var requestLessProtocols = map[string]bool{
	"code":       true,
	"file":       true,
	"javascript": true,
}

// TemplateMeta is the reporting identity of one template file, read from the
// document's own header. It is filled before the scan so a file that matched
// nothing is still fully identified in the report.
type TemplateMeta struct {
	TemplateID string
	Name       string
	Severity   string
	Author     []string
	Tags       []string
	CVE        []string
	CWE        []string
	// Protocol is the request block the template carries — `http`, `code` and so
	// on. It decides whether a run against a URL can say anything about it.
	Protocol string
}

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

	// protocol is the request block the document carries. It is kept internal:
	// the browser is told the outcome, not how the engine read the file, and the
	// only place it is needed is deciding between `not_matched` and `no_request`.
	protocol string
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
		result := TemplateResult{
			Name:   file.UploadName,
			Path:   file.RelativePath,
			Status: TemplateNotMatched,
		}
		if file.Meta == nil {
			result.Status = TemplateInvalid
			result.Reason = file.Reason
			results = append(results, result)
			continue
		}
		result.TemplateID = file.Meta.TemplateID
		result.Title = file.Meta.Name
		result.Severity = file.Meta.Severity
		result.CVE = file.Meta.CVE
		result.CWE = file.Meta.CWE
		result.Tags = file.Meta.Tags
		result.Author = file.Meta.Author
		results = append(results, result)
	}
	return results
}

// UploadFile is one Nuclei template document sent from the browser. Path keeps
// the relative path of a folder upload so templates with the same file name in
// different directories stay distinct.
type UploadFile struct {
	Name    string
	Path    string
	Content string
}

// NucleiRequest selects real Nuclei templates by tags or severities. The
// template documents themselves always arrive as uploaded files: no
// server-side template paths are accepted, so there is nothing to configure.
type NucleiRequest struct {
	URL      string
	Tags     []string
	Severity []string
	Proxy    string
	Options  NucleiOptions
	// OnStats receives live progress while the binary runs. It is nil for the
	// synchronous path, where the caller only wants the final report.
	OnStats func(NucleiProgress)
	// OnProcess is called with the started process so a job can pause and resume
	// it. It is nil on the synchronous path.
	OnProcess func(process *os.Process)
	// OnOutput is called with the JSONL report path the binary writes, so a
	// caller can tail it and stream per-file results while the scan runs.
	OnOutput func(path string)
	// Protocols are the request blocks the staged documents carry. Nuclei does not
	// load `code`, `file` or `javascript` templates unless the matching flag is
	// present, so a folder that contains them needs those flags or the binary
	// reports nothing for those files — or refuses the whole run with "no
	// templates provided for scan". They are read from the documents the operator
	// chose, so the run covers what was selected instead of quietly dropping a
	// fifth of a real template folder.
	Protocols []string
}

// ProtocolsNeedingFlag are the request types the binary does not load on its own,
// with the flag that loads them. Measured against the installed nuclei v10.4.9 on a
// folder holding one `http`, one `code`, one `file` and one `javascript` template:
//
//   - no flags            -> `http` and `javascript` load, `code` and `file` do not
//   - `-code`             -> `code` loads and reports; the other three are unaffected
//   - `-pt <types>,code`  -> same as `-code` on its own, so `code` never needs `-pt`
//   - `-pt file`          -> nothing loads: the flag *replaces* the default set, so
//     an `http` template in the same folder disappears and the run exits 1 with
//     "no templates provided for scan"
//
// Only `code` is safe to enable automatically, and only because the operator chose
// a file that needs it. `file` and `headless` are deliberately absent: loading
// them costs the whole default type set, and even when loaded they write no
// record at all for a URL target, so the flag would buy a silently empty run.
// Those two are reported as `no_request` with the flag named, and the operator can
// run them with any flag they want from the Scanner console.
var ProtocolsNeedingFlag = map[string]string{
	"code":     "-code",
	"file":     "-pt file",
	"headless": "-headless",
}

// nucleiFinding is the JSONL record emitted by the real Nuclei binary. All
// fields that carry evidence or template identity are decoded: the report
// needs the file name, CVE and CWE identifiers, the matched matcher and the
// exact request that produced the match.
type nucleiFinding struct {
	TemplateID   string `json:"template-id"`
	TemplatePath string `json:"template-path"`
	TemplateURL  string `json:"template-url"`
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
// builtin scanner (title, severity, evidence, recommendation) are preserved so
// the project evidence log keeps a single finding shape across engines.
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

// protocolBlocks are the top-level sections that make a template do work.
var protocolBlocks = []string{
	"http", "dns", "network", "file", "headless", "ssl", "websocket", "whois", "code", "javascript", "multipart",
}

// parseTemplateDocument reads the identity of a template and reports why the
// Nuclei engine would reject it. The checks mirror nuclei itself: a template
// without `info.author` is dropped as invalid_template, which is what makes the
// binary exit 1 with "no templates provided for scan" when every upload is
// missing it.
func parseTemplateDocument(content string) (*TemplateMeta, string) {
	var document map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		return nil, "invalid YAML: " + oneLine(err.Error())
	}
	rawID, ok := document["id"]
	if !ok || strings.TrimSpace(rawID.Value) == "" {
		return nil, "missing top-level id"
	}
	infoNode, ok := document["info"]
	if !ok {
		return nil, "missing info block"
	}
	var info struct {
		Name           string          `yaml:"name"`
		Author         flexYAMLStrings `yaml:"author"`
		Severity       string          `yaml:"severity"`
		Tags           flexYAMLStrings `yaml:"tags"`
		Description    string          `yaml:"description"`
		Classification struct {
			CVE flexYAMLStrings `yaml:"cve-id"`
			CWE flexYAMLStrings `yaml:"cwe-id"`
		} `yaml:"classification"`
	}
	if err := infoNode.Decode(&info); err != nil {
		return nil, "invalid info block: " + oneLine(err.Error())
	}
	if strings.TrimSpace(info.Name) == "" {
		return nil, "missing info.name"
	}
	if len(nonEmpty(info.Author)) == 0 {
		return nil, "missing info.author — nuclei rejects templates without an author field"
	}
	severity := strings.ToLower(strings.TrimSpace(info.Severity))
	if severity == "" {
		return nil, "missing info.severity"
	}
	if !validSeverities[severity] {
		return nil, fmt.Sprintf("unknown info.severity %q", info.Severity)
	}
	if reason := missingRequestBlock(document); reason != "" {
		return nil, reason
	}
	return &TemplateMeta{
		TemplateID: strings.TrimSpace(rawID.Value),
		Name:       strings.TrimSpace(info.Name),
		Severity:   strings.ToUpper(severity),
		Author:     nonEmpty(info.Author),
		Tags:       nonEmpty(info.Tags),
		CVE:        nonEmpty(info.Classification.CVE),
		CWE:        nonEmpty(info.Classification.CWE),
		Protocol:   requestBlock(document),
	}, ""
}

// protocolsNeedingFlag are the request types the binary does not load on its own.
// `code` is off by default because such a template runs shell commands on the
// machine that runs the scan; the rest are simply not in the default type set.
// Naming the missing flag is what turns "Nuclei returned no record" into
// something the operator can act on.
var protocolsNeedingFlag = map[string]struct {
	flag   string
	reason string
}{
	"code": {"-code", "is not set. It is off by default because a code template runs shell commands on " +
		"the machine running the scan, so it is added only for a folder that actually contains one."},
	"file": {"-pt", "does not name this type. Note that -pt replaces the default type set, so every " +
		"other type has to be named too. A file template reads local files, so it says nothing about a " +
		"target URL."},
	"headless": {"-headless", "is not set. A headless template drives a browser, so it needs the " +
		"browser runtime rather than plain HTTP."},
}

// A file the binary never reported, and the reason is knowable from the document
// itself, is a template the type filter kept out. This is a real situation: on
// the installed nuclei v10.4.9, a folder of only `code` or only `file` templates
// makes the binary exit 1 with "no templates provided for scan", which without
// this would be reported per file as the opaque "Nuclei returned no record".
// See TestUnmetProtocolReasonNamesTheMissingFlag in the test file.

// unmetProtocolReason explains why a file the binary never reported was skipped,
// when the reason is knowable up front from the document and the active flags.
// It returns "" when the type is one Nuclei loads by default, leaving the
// generic "no record" message for the cases only the run itself can explain.
func unmetProtocolReason(meta *TemplateMeta, args []string) string {
	if meta == nil {
		return ""
	}
	need, known := protocolsNeedingFlag[meta.Protocol]
	if !known {
		return ""
	}
	for _, arg := range args {
		switch arg {
		case "-code", "-esc", "-enable-self-contained":
			if meta.Protocol == "code" {
				return ""
			}
		case "-pt":
			// An explicit type set is the operator's own decision, so a type it
			// leaves out is their choice and the generic message is the honest one.
			return ""
		}
	}
	return fmt.Sprintf(
		"Not run: this is a %q template and %s %s. Full binary output is in the run diagnostics.",
		meta.Protocol, need.flag, need.reason)
}

// requestBlock names the request section a template carries. The first block in
// the documented order wins so the name is stable between runs.
func requestBlock(document map[string]yaml.Node) string {
	for _, block := range protocolBlocks {
		if node, ok := document[block]; ok && node.Kind != 0 && node.Tag != "!!null" {
			return block
		}
	}
	return ""
}

func missingRequestBlock(document map[string]yaml.Node) string {
	present := make([]string, 0, len(protocolBlocks))
	for _, block := range protocolBlocks {
		if node, ok := document[block]; ok && node.Kind != 0 && node.Tag != "!!null" {
			present = append(present, block)
		}
	}
	if len(present) == 0 {
		return "no request block — expected one of: " + strings.Join(protocolBlocks, ", ")
	}
	return ""
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

// StageUploads validates every uploaded document and stages the usable ones
// into a fresh temporary directory that keeps the uploaded folder layout. The
// caller removes the directory. Only a rejected request (no files, a path that
// escapes the directory, or a write failure) returns an error; a malformed
// template is reported per file in the returned results.
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
		lowered := strings.ToLower(name)
		if !strings.HasSuffix(lowered, ".yaml") && !strings.HasSuffix(lowered, ".yml") {
			staged = append(staged, StagedFile{UploadName: name, RelativePath: displayRelativePath(file.Path, name), Reason: "not a YAML template"})
			continue
		}
		if strings.TrimSpace(file.Content) == "" {
			staged = append(staged, StagedFile{UploadName: name, RelativePath: displayRelativePath(file.Path, name), Reason: "file is empty"})
			continue
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
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, relative)), 0o700); err != nil {
			return nil, err
		}
		target := filepath.Join(dir, relative)
		if seen := usedPaths[target]; seen > 0 {
			extension := filepath.Ext(relative)
			stem := strings.TrimSuffix(relative, extension)
			relative = fmt.Sprintf("%s-%d%s", stem, seen+1, extension)
			target = filepath.Join(dir, relative)
		}
		usedPaths[target]++
		// The report path follows the final on-disk name, so a folder that held
		// two same-named files still attributes each result to its own file.
		report := filepath.ToSlash(relative)
		meta, reason := parseTemplateDocument(file.Content)
		if reason != "" {
			staged = append(staged, StagedFile{UploadName: name, RelativePath: report, Reason: reason})
			continue
		}
		if err := os.WriteFile(target, []byte(file.Content), 0o600); err != nil {
			return nil, err
		}
		staged = append(staged, StagedFile{UploadName: name, StagedPath: target, RelativePath: report, Meta: meta})
	}
	return staged, nil
}

// RunNucleiDir executes the external Nuclei binary once against one target
// using the prepared template directory, without a shell. Only the target URL
// and tag/severity filters cross the API; the flag set is fixed. Every JSONL
// record is attributed back to the uploaded file that produced it through the
// template path nuclei reports.
func RunNucleiDir(ctx context.Context, dir string, staged []StagedFile, request NucleiRequest) (NucleiRun, error) {
	target := strings.TrimSpace(request.URL)
	if target == "" {
		return NucleiRun{}, fmt.Errorf("target URL is required")
	}
	if strings.TrimSpace(dir) == "" {
		return NucleiRun{}, fmt.Errorf("template directory is required")
	}
	// The types the chosen files need are read from their own documents and
	// handed to the flag builder, so a folder of `code`, `file` or `javascript`
	// templates is actually loaded instead of being reported as nothing found.
	if len(request.Protocols) == 0 {
		protocols := make([]string, 0, len(staged))
		for _, file := range staged {
			if file.Meta != nil && file.Meta.Protocol != "" {
				protocols = append(protocols, file.Meta.Protocol)
			}
		}
		request.Protocols = protocols
	}
	runnable := 0
	results := make([]TemplateResult, 0, len(staged))
	indexByPath := make(map[string]int, len(staged))
	// Nuclei loads one file per template id, so a staged file whose id is also
	// declared by another file may never execute. The group is collected here,
	// while the exact file layout is known, but which member of the group the
	// binary keeps is only known from the report, so the reason is written after
	// the run instead of being predicted now.
	groupByID := map[string][]int{}
	for index, file := range staged {
		if file.Meta != nil && file.Meta.TemplateID != "" {
			groupByID[file.Meta.TemplateID] = append(groupByID[file.Meta.TemplateID], index)
		}
	}
	for _, file := range staged {
		// The default is deliberately "not run yet", not "not matched". A file the
		// binary never reported must not reach the browser already wearing a
		// result, because the pass after the run only *upgrades* a provisional
		// status and cannot tell a real miss from the default. Starting from
		// "skipped" is what let a `javascript` template the binary ran — and which
		// therefore has no JSONL record of its own — be reported as a clean miss
		// against the target.
		result := TemplateResult{
			Name:   file.UploadName,
			Path:   file.RelativePath,
			Status: TemplateSkipped,
		}
		if file.Meta == nil {
			result.Status = TemplateInvalid
			result.Reason = file.Reason
			results = append(results, result)
			continue
		}
		result.TemplateID = file.Meta.TemplateID
		result.Title = file.Meta.Name
		result.Severity = file.Meta.Severity
		result.CVE = file.Meta.CVE
		result.CWE = file.Meta.CWE
		result.Tags = file.Meta.Tags
		result.Author = file.Meta.Author
		result.protocol = file.Meta.Protocol
		if len(groupByID[file.Meta.TemplateID]) > 1 {
			// Marked now so the pre-flight report is already truthful; the exact
			// reason is filled in once the run shows which sibling executed.
			result.Status = TemplateSkipped
		}
		results = append(results, result)
		indexByPath[filepath.Clean(file.StagedPath)] = len(results) - 1
		// A duplicate-id member is still handed to the binary: which member of
		// the group Nuclei keeps is its own decision, and only the report says
		// which one that was. Only an invalid file is never runnable.
		runnable++
	}
	if runnable == 0 {
		// Every file was rejected before the scan. Nothing was executed, so the
		// run is reported as skipped with the per-file reasons instead of
		// surfacing the binary's empty-directory exit status.
		run := NucleiRun{Templates: results}
		run.Stats = map[string]interface{}{
			"engine": nucleiBinary(), "url": target, "files": len(results),
			"findings": 0, "matched": 0, "invalid": len(results),
			"not_matched": 0, "exit_code": 0, "exit_status": "skipped",
		}
		return run, nil
	}
	for _, level := range dedupeLower(request.Severity) {
		if !validSeverities[level] {
			return NucleiRun{}, fmt.Errorf("invalid severity %q", level)
		}
	}
	// The per-file report has to be able to tell "ran and matched nothing" from
	// "never ran", and only -ms makes the binary emit a record for every
	// template it executes. The records themselves are not findings: isFinding
	// drops every matcher-status=false line, so requesting them changes what the
	// report can prove, not what it reports as a finding.
	request.Options.MatcherStatus = true
	args, err := buildNucleiArgs(target, dir, request)
	if err != nil {
		return NucleiRun{}, err
	}
	args = append(args, "-jsonl")
	// Stats are observational only: they make the live progress of a long run
	// visible to the browser and in the engine log without changing how the
	// templates are executed.
	args = append(args, "-stats", "-stats-interval", "1")
	output, err := os.CreateTemp("", "rr-nuclei-*.jsonl")
	if err != nil {
		return NucleiRun{}, err
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
	if timeoutSec := nucleiTimeoutSec(); timeoutSec > 0 {
		execCtx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	}
	defer cancel()
	command := exec.CommandContext(execCtx, nucleiBinary(), append(args, "-o", outputPath)...)
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
		return NucleiRun{}, err
	}
	if request.OnProcess != nil && command.Process != nil {
		request.OnProcess(command.Process)
	}
	runErr := command.Wait()
	exitCode := 0
	if runErr != nil {
		// A killed process also reports an *exec.ExitError, so a cancelled
		// context has to be checked first. Otherwise a route switch would be
		// reported as an ordinary non-zero exit instead of a cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return NucleiRun{}, ctxErr
		}
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return NucleiRun{}, fmt.Errorf("nuclei could not be started: %w", runErr)
		}
		exitCode = exitErr.ExitCode()
	}
	parsed, parseErr := parseNucleiReport(outputPath)
	if parseErr != nil {
		return NucleiRun{}, fmt.Errorf("nuclei output could not be read: %w", parseErr)
	}
	// A file that ran and whose only evidence is a `-ms` record of its own is a
	// miss against the target, which is what `not_matched` means. This is decided
	// from the report, not assumed up front, so a file the binary never touched
	// cannot inherit the wording. The rows start as "not run yet" and each one
	// below is the only place a file acquires a final status.
	for path := range parsed.Executed {
		index, known := indexByPath[path]
		if !known {
			continue
		}
		if requestLessProtocols[results[index].Protocol()] {
			results[index].Status = TemplateNoRequest
			results[index].Reason = fmt.Sprintf(
				"Ran, but checked no URL: this is a %q template, so it ran a local engine or read local files "+
					"and issued no request to the target. It cannot match or miss against a target host.",
				results[index].Protocol())
			continue
		}
		results[index].Status = TemplateNotMatched
	}

	findings := make([]map[string]interface{}, 0, len(parsed.Findings))
	unassigned := 0
	for _, hit := range parsed.Findings {
		finding := hit.toMap()
		findings = append(findings, finding)
		index, ok := indexByPath[filepath.Clean(hit.TemplatePath)]
		if !ok {
			// A template the binary resolved outside the staged directory (for
			// example one pulled from the local template store). Keep the finding
			// and report it instead of dropping evidence.
			unassigned++
			continue
		}
		results[index].Matches++
		results[index].Status = TemplateMatched
		results[index].Findings = append(results[index].Findings, finding)
	}

	// A staged file the binary never touched did not run. Reporting it as
	// "not matched" would claim work that never happened, so it is marked as
	// skipped. The reason is taken from the run itself: for a template-id clash
	// it names the sibling that demonstrably executed, and anything else gets
	// the facts of the run instead of a guess.
	executed := 0
	for _, file := range staged {
		if file.Meta == nil {
			continue
		}
		clean := filepath.Clean(file.StagedPath)
		// "Executed" is a path set read from the binary's own JSONL output. It is
		// the only proof that a template actually ran, and it is deliberately not
		// a per-template status: a `code`, `file` or `javascript` template can run
		// without writing a record of its own, and the browser learns about it
		// through the per-template stream instead.
		ran := parsed.Executed[clean]
		index := indexByPath[clean]
		if ran {
			// The status is already decided from the report above: a local
			// template that ran is `no_request`, anything else that ran is
			// `not_matched`, and a match upgraded it further.
			executed++
			continue
		}
		results[index].Status = TemplateSkipped
		if winner := executedSibling(staged, groupByID[file.Meta.TemplateID], file, parsed.Executed); winner != "" {
			results[index].Reason = fmt.Sprintf(
				"Not run: template id %q is also declared by %s, which Nuclei loaded, "+
					"and Nuclei loads one file per template id.",
				file.Meta.TemplateID, winner)
			continue
		}
		// A local template the binary never loaded: the flag that would load it is
		// the useful answer, because the alternative sentence talks about records
		// the operator cannot influence.
		if reason := unmetProtocolReason(file.Meta, args); reason != "" {
			results[index].Reason = reason
			continue
		}
		results[index].Reason = fmt.Sprintf(
			"Not run: Nuclei returned no record for template id %q. "+
				"It executed %d of the staged template(s) and the active options were: %s. "+
				"Full binary output is in the run diagnostics.",
			file.Meta.TemplateID, executed, strings.Join(args, " "))
	}

	run := NucleiRun{Findings: findings, Templates: results}
	matched, total := run.CountStatus(TemplateMatched)
	notMatched, _ := run.CountStatus(TemplateNotMatched)
	invalid, _ := run.CountStatus(TemplateInvalid)
	skipped, _ := run.CountStatus(TemplateSkipped)
	noRequest, _ := run.CountStatus(TemplateNoRequest)
	stats := map[string]interface{}{
		"engine":      "nuclei",
		"binary":      nucleiBinary(),
		"url":         target,
		"findings":    len(findings),
		"files":       total,
		"matched":     matched,
		"not_matched": notMatched,
		"invalid":     invalid,
		"skipped":     skipped,
		// Reported apart from "not matched" so a run cannot be read as "every
		// template that did not match, therefore everything was checked".
		"no_request":  noRequest,
		"executed":    total - invalid - skipped,
		"exit_code":   exitCode,
		"exit_status": "ok",
	}
	if unassigned > 0 {
		stats["unassigned_findings"] = unassigned
	}
	// The binary's own output is always attached, not only on failure: it is the
	// evidence for why a template was skipped and for any error the operator has
	// to see. Nothing is trimmed or summarised away.
	stats["args"] = args
	if message := reported.Text(); message != "" {
		stats["stdout"] = message
	}
	if message := diagnostics.Text(); message != "" {
		stats["stderr"] = message
	}
	if runErr != nil {
		stats["exit_status"] = "failed"
		stats["error"] = runErr.Error()
	}
	run.Stats = stats
	return run, nil
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

// executedSibling returns the file from the same template-id group that the
// binary actually executed, which is the file that took the id. An empty result
// means no sibling ran, so there is nothing to point at. The sibling is named by
// its path inside the uploaded layout, because a templates folder repeats the
// same file name in several directories and a bare base name is ambiguous there.
func executedSibling(staged []StagedFile, group []int, self StagedFile, executed map[string]bool) string {
	for _, index := range group {
		// The staged path identifies the file, not its name: a templates folder
		// repeats the same base name in several directories, and skipping a
		// same-named sibling here would hide the very file that took the id.
		if self.StagedPath != "" && staged[index].StagedPath == self.StagedPath {
			continue
		}
		if staged[index].StagedPath == "" && staged[index].UploadName == self.UploadName {
			continue
		}
		if executed[filepath.Clean(staged[index].StagedPath)] {
			return displayRelativePath(staged[index].RelativePath, staged[index].UploadName)
		}
	}
	return ""
}

// nucleiReport is what one JSONL file proves: the matches it carries and the
// set of template paths the binary actually touched. The second part matters
// because -ms writes a record for every executed template, so a staged file
// with no record at all was never run.
type nucleiReport struct {
	Findings []nucleiFinding
	Executed map[string]bool
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
						report.Executed[filepath.Clean(trimmed)] = true
					}
					if hit.isFinding() {
						report.Findings = append(report.Findings, hit)
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

func parseNucleiJSONL(path string) ([]nucleiFinding, error) {
	report, err := parseNucleiReport(path)
	if err != nil {
		return nil, err
	}
	return report.Findings, nil
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
