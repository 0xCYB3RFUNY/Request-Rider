package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file is the single source of truth for "what kind of template is this
// document, and what does the binary need in order to run it".
//
// The block list is taken from the binary's own parser, not from guesswork.
// nuclei v3.11.1 declares its request sections as the fields of
// `templates.Template` (pkg/templates/template.go), which the package
// documentation lists as: RequestsHTTP, RequestsDNS, RequestsFile,
// RequestsNetwork, RequestsWithTCP, RequestsHeadless, RequestsSSL,
// RequestsWebsocket, RequestsWHOIS, RequestsCode, RequestsJavascript and
// Workflows. A block that is missing from this list is a block nuclei never
// parses, so a document that only carries it cannot run and saying so is honest.
//
// The capability list is `templates.Capability` (added in v3.10.0) and the
// binary's flag list confirms the one flag per capability. Each of those flags
// *adds* a template kind; none of them narrows the run, which is what makes
// deriving them from the selected documents safe.

// protocolBlock is one section of a template document together with the protocol
// type nuclei reports for a match it produces.
type protocolBlock struct {
	// key is the top-level YAML key.
	key string
	// typeName is the value nuclei writes into the `type` field of a JSONL
	// record, which is what the report shows for a matched template.
	typeName string
	// addressesTarget reports whether executing this block sends a request to
	// the scanned host. A block that does not can neither match nor miss
	// against a URL, so the report has to say that instead of "not matched".
	addressesTarget bool
	// requestless marks a block that runs a local engine or reads local files.
	// It is a subset of !addressesTarget; kept separately because the reason
	// shown to the operator is different.
	requestless bool
}

// protocolBlocks is the documented set of request sections, in the order nuclei
// itself documents them, so the protocol name of a document is stable between
// runs. `requests` and `network` are the deprecated spellings nuclei still
// parses; `tcp` is what `network` was renamed to.
var protocolBlocks = []protocolBlock{
	{key: "http", typeName: "http", addressesTarget: true},
	{key: "requests", typeName: "http", addressesTarget: true},
	{key: "dns", typeName: "dns", addressesTarget: true},
	{key: "ssl", typeName: "ssl", addressesTarget: true},
	{key: "websocket", typeName: "websocket", addressesTarget: true},
	{key: "whois", typeName: "whois", addressesTarget: true},
	{key: "tcp", typeName: "tcp", addressesTarget: true},
	{key: "network", typeName: "network", addressesTarget: true},
	{key: "headless", typeName: "headless", addressesTarget: true},
	// JavaScript can use local helpers or nuclei's network protocol modules;
	// TemplateMeta classifies it from the block's actual imports.
	{key: "javascript", typeName: "javascript"},
	{key: "code", typeName: "code", requestless: true},
	{key: "file", typeName: "file", requestless: true},
	{key: "fuzzing", typeName: "fuzzing", addressesTarget: true},
	{key: "workflows", typeName: "workflow", addressesTarget: true},
	{key: "jarm", typeName: "jarm", addressesTarget: true},
	{key: "asn", typeName: "asn", addressesTarget: true},
	{key: "port", typeName: "port", addressesTarget: true},
	{key: "multi", typeName: "http", addressesTarget: true},
	{key: "ssl-request", typeName: "ssl", addressesTarget: true},
}

// blockKeys is the same list reduced to plain keys, used when a document's
// blocks are rendered into a message.
var blockKeys = func() []string {
	keys := make([]string, 0, len(protocolBlocks))
	seen := map[string]bool{}
	for _, block := range protocolBlocks {
		if seen[block.key] {
			continue
		}
		seen[block.key] = true
		keys = append(keys, block.key)
	}
	return keys
}()

// blockByKey indexes protocolBlocks for lookups by the YAML key.
var blockByKey = func() map[string]protocolBlock {
	index := make(map[string]protocolBlock, len(protocolBlocks))
	for _, block := range protocolBlocks {
		index[block.key] = block
	}
	return index
}()

// Capability is one opt-in template kind that the binary loads only when a flag
// is present. The set mirrors `templates.Capability` in v3.10.0.
type Capability string

// The capabilities nuclei v3.11.1 knows. Every one of them is enabled by adding
// its own flag, and none of them replaces the binary's default type set — which
// is exactly why they can be derived from the selected documents and added
// automatically.
const (
	// CapabilityCode is a `code` template: it runs a local engine.
	CapabilityCode Capability = "code"
	// CapabilityFile is a `file` template: it reads local files.
	CapabilityFile Capability = "file"
	// CapabilityHeadless is a `headless` template: it drives a browser.
	CapabilityHeadless Capability = "headless"
	// CapabilityDAST is a `fuzzing` template: it is driven by the fuzzing engine.
	CapabilityDAST Capability = "dast"
	// CapabilityGlobalMatchers is a template that only declares shared matchers
	// and is included by other templates rather than executed on its own.
	CapabilityGlobalMatchers Capability = "global-matchers"
	// CapabilitySelfContained is a `self-contained: true` template: it carries
	// its own payload instead of importing a helper file.
	CapabilitySelfContained Capability = "self-contained"
)

// capabilityFlag is the CLI flag that loads a capability. `-dast` is included
// because it is the flag nuclei documents for fuzzing templates; `-fuzz` is its
// deprecated spelling and is never emitted.
var capabilityFlag = map[Capability]string{
	CapabilityCode:           "-code",
	CapabilityFile:           "-file",
	CapabilityHeadless:       "-headless",
	CapabilityDAST:           "-dast",
	CapabilityGlobalMatchers: "-egm",
	CapabilitySelfContained:  "-esc",
}

// allCapabilities is the evaluation order nuclei uses. Sorting by it keeps a
// generated flag set stable, which matters because the flag set is part of the
// run diagnostics an operator reads.
var allCapabilities = []Capability{
	CapabilityCode,
	CapabilityFile,
	CapabilityHeadless,
	CapabilityDAST,
	CapabilityGlobalMatchers,
	CapabilitySelfContained,
}

// isolatedCapability is a capability that must be executed in its own nuclei
// invocation rather than alongside the others. `-dast` is the one: measured on
// v3.11.1, adding `-dast` to a folder that holds no fuzzing template makes the
// binary abort the whole run with
// `[FTL] Could not run nuclei: no templates provided for scan` and exit 1, so a
// single flag would silently cancel every other template in the run. Isolating
// it is what keeps "add the flag a document needs" from becoming "scan nothing".
const isolatedCapability = CapabilityDAST

// capabilityKey is the identity of one execution group: the sorted set of
// capabilities a batch needs. Files that need no capability at all share the
// empty key and run in one batch together.
type capabilityKey string

// capabilityKeyOf renders a capability set as a stable key.
func capabilityKeyOf(capabilities []Capability) capabilityKey {
	unique := map[Capability]bool{}
	for _, capability := range capabilities {
		unique[capability] = true
	}
	ordered := make([]string, 0, len(unique))
	for _, capability := range allCapabilities {
		if unique[capability] {
			ordered = append(ordered, string(capability))
		}
	}
	return capabilityKey(strings.Join(ordered, "+"))
}

// parts splits a key back into the tokens that built it, dropping empties.
func (c capabilityKey) parts() []string {
	raw := strings.Split(string(c), "+")
	parts := make([]string, 0, len(raw))
	for _, item := range raw {
		if item != "" {
			parts = append(parts, item)
		}
	}
	return parts
}

// parseCapabilities turns a key back into the capability list it encodes.
//
// A key may carry a trailing marker that is NOT a capability — the template id of
// a document the plan gave a batch of its own. Only the leading run of tokens
// that names a real capability is read, so an isolated batch keeps its isolation
// without acquiring a flag its documents never asked for. Measured: without this
// split, 8 of the 131 documents in `javascript/` were launched with `-dast` and
// every one of them answered `[FTL] no templates provided for scan`, exit 1.
func (c capabilityKey) parseCapabilities() []Capability {
	capabilities := make([]Capability, 0, len(c.parts()))
	for _, item := range c.parts() {
		candidate := Capability(item)
		if _, known := capabilityFlag[candidate]; known {
			capabilities = append(capabilities, candidate)
			continue
		}
		// Everything after the first unknown token is marker text: the key was
		// built by appending a marker to a capability list, so a capability can
		// never follow it.
		break
	}
	return capabilities
}

// isolated reports whether this group has to run on its own.
//
// "On its own" is one condition with two independent reasons, and they are
// separate questions because they cost different things:
//
//   - `needsReservedFlag` — the group holds fuzzing documents, and `-dast` on a
//     directory without one aborts the whole invocation, so the flag needs an
//     invocation that contains nothing else. The FLAG is the reason.
//   - `runsAlone` — the group is a single document the plan gave a batch of its
//     own because it declares no deadline of its own. The DEADLINE is the
//     reason, and no flag is involved.
//
// Conflating them is what made 8 JavaScript documents of the corpus lose their
// verdicts: they were isolated for the deadline, and reading the marker as a
// capability handed them `-dast`, which nuclei answers with `[FTL] no templates
// provided for scan` and exit 1 — measured on v3.11.1 against `javascript/`,
// 131 documents, 8 invocations at exit 1 and zero records between them.
func (c capabilityKey) isolated() bool {
	return c.runsAlone() || c.needsReservedFlag()
}

// needsReservedFlag reports whether this group's own documents declare the
// capability whose flag must not share an invocation with other protocols.
//
// It reads the capability list only — never the marker. A document that never
// asked for the flag cannot be given it, because the flag is not what isolates
// it and adding it there cancels the run.
func (c capabilityKey) needsReservedFlag() bool {
	for _, capability := range c.parseCapabilities() {
		if capability == isolatedCapability {
			return true
		}
	}
	return false
}

// runsAlone reports whether the plan gave this group a batch of its own for a
// reason other than the reserved flag — a document that can block forever, or a
// set of same-id documents the binary would otherwise load only one of.
//
// A key built by appending a marker to a capability list is exactly this shape,
// so "the key carries more tokens than it has capabilities" is the test.
func (c capabilityKey) runsAlone() bool {
	return len(c.parts()) > len(c.parseCapabilities())
}

// BlocksWithoutDeadline reports whether the document can wait on a peer forever.
//
// It answers one question about the document's own text: does a `code` template
// read from a socket or a pipe without ever giving that read a deadline? A
// template that does has no time limit of its own, and nuclei runs every template
// of an invocation in one process, so one such file decides how long the others
// wait. Measured on nuclei v3.11.1 against the official corpus, five documents
// look like this; `code/cves/2016/CVE-2016-8735` calls `recv(4096)` four times
// and never calls `settimeout`, and it held a four-file batch for thirty minutes
// with an empty report.
//
// It is a statement about the file, not a verdict on it: a template that does
// this is still run, on its own and with a deadline, because skipping it would
// lose a real check and running it beside its neighbours costs them theirs.
func (m *TemplateMeta) BlocksWithoutDeadline() bool {
	if m == nil {
		return false
	}
	if m.BlockKey() == "javascript" {
		return m.javascriptNeedsItsOwnProcess()
	}
	if m.BlockKey() != "code" {
		return false
	}
	// The deadline may be set through either spelling, and through the aliases
	// `requests`/`http`, which the block key already resolved.
	body := m.CodeBody
	if strings.TrimSpace(body) == "" {
		return false
	}
	reads := strings.Contains(body, ".recv(") || strings.Contains(body, ".read(") ||
		strings.Contains(body, "requests.get(")
	if reads {
		return !strings.Contains(body, "settimeout") && !strings.Contains(body, "SetTimeout")
	}
	// The second shape is an interactive command that never returns on its own.
	// `code/privilege-escalation/linux/binary/privesc-vim.yaml` runs
	// `vim -c '!whoami'`, and without `-e`/`-es` vim opens a full-screen editor
	// and waits for a keypress that never comes: measured on v3.11.1, that one
	// file held a 114-file batch for twenty-five minutes with an empty report, so
	// the 113 templates beside it lost their verdicts to it. The same is true of
	// the other full-screen programs these local-check templates drive.
	return opensInteractiveTerminal(body)
}

// opensInteractiveTerminal reports whether the script starts a program that takes
// over the terminal and waits for input.
//
// The spelling that matters is the absence of a non-interactive flag: `vim -c` is
// interactive, `vim -es` is not. Only the flag-free forms are listed, because a
// document that spells the flag has already answered the question — and the
// corpus has exactly that answer written down: the three
// `code/privilege-escalation/linux/binary/privesc-{vim,view,vi}.yaml` templates
// all call their editor with `-c` and nothing else, and each of them held a
// batch for twenty-five minutes before this was noticed.
//
// The first version of this list named `vim` alone and the corpus answered with
// `view -c ':!whoami'`, which is the same editor under another name and cost
// another twenty-five minutes. A list of bare names is therefore built from the
// programs, and a program name is matched as a word so `viewmodel` never matches
// `view`.
func opensInteractiveTerminal(body string) bool {
	for _, program := range interactiveTerminalPrograms {
		if !containsWord(body, program) {
			continue
		}
		// The program is present. The question left is whether the invocation
		// carries the flag that turns it into a batch job, and each family spells
		// it differently: vim answers to `-es` or `-e`, the pager to `-F`.
		if nonInteractiveEditorFlag(body, program) {
			continue
		}
		return true
	}
	return false
}

// interactiveTerminalPrograms are the full-screen programs a local-check template
// drives. Each one takes the screen and waits for a keypress that, in a scan, is
// never going to come.
var interactiveTerminalPrograms = []string{"vim", "view", "vi", "nano", "emacs", "less", "top", "tail"}

// nonInteractiveEditorFlag reports whether the invocation already carries the flag
// that makes the program a batch job.
func nonInteractiveEditorFlag(body, program string) bool {
	switch program {
	case "vim", "view", "vi":
		return strings.Contains(body, "-es") || strings.Contains(body, " -e ")
	case "less":
		return strings.Contains(body, "-F")
	case "top", "tail":
		// Both are batch jobs by default; only their interactive forms wait.
		return strings.Contains(body, "-b ") || strings.Contains(body, "-n ")
	}
	return false
}

// containsWord reports whether `word` appears in `text` delimited by anything
// that is not part of a shell word.
func containsWord(text, word string) bool {
	for index := 0; ; {
		at := strings.Index(text[index:], word)
		if at < 0 {
			return false
		}
		at += index
		before := byte(' ')
		if at > 0 {
			before = text[at-1]
		}
		after := byte(' ')
		if at+len(word) < len(text) {
			after = text[at+len(word)]
		}
		index = at + len(word)
		if !isShellWordByte(before) && !isShellWordByte(after) {
			return true
		}
	}
}

func isShellWordByte(b byte) bool {
	return b == '_' || b == '-' || b == '.' || b == '/' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// javascriptNeedsItsOwnProcess reports whether a `javascript` document can be
// left to finish before its neighbours start.
//
// The engines these templates require — `nuclei/smb`, `nuclei/ldap`,
// `nuclei/mysql` — are socket clients with no deadline of their own, and
// `attack: clusterbomb` multiplies one call by the size of the payload cartesian
// product. Measured on v3.11.1 here, `javascript/misconfiguration/smb/smb-shares.yaml`
// combines both: four usernames by six passwords, each one a `ListShares` to
// port 445, `threads: 1`. On a host where 445 is closed it answered
//
//	[WRN] js runtime did not terminate after interrupt; abandoning it to avoid
//	      concurrent use: nuclei js runtime: program failed to terminate after
//	      interrupt: context deadline exceeded
//
// and, in a nine-file batch, held the invocation for twenty-one minutes with an
// empty report — the eight templates beside it lost their verdicts to it. On its
// own it finished in 100 s and wrote nothing, which is the same failure seen from
// the other side.
//
// A single iteration is not enough to identify these: a `javascript` template that
// opens one socket and returns is an ordinary check. What makes this class is the
// cartesian product, so `attack:` with anything other than a single value is the
// signal, together with a socket engine in the `require` list.
func (m *TemplateMeta) javascriptNeedsItsOwnProcess() bool {
	body := m.JavaScriptBody
	if strings.TrimSpace(body) == "" {
		return false
	}
	if !strings.Contains(body, "require(") {
		return false
	}
	if !socketBackedJavascriptEngine(body) {
		return false
	}
	// `attack:` with no value is the default, which is a single value. Measured on
	// this corpus: 192 javascript documents, 18 of them carrying an explicit
	// `clusterbomb`, and only 3 spelling `threads:` — so the cartesian product is
	// the signal that is actually written down.
	return strings.Contains(body, "attack:") && !strings.Contains(body, "attack: single")
}

// socketBackedJavascriptEngine reports whether the script pulls in one of nuclei's
// own socket clients. Those are the engines with no internal deadline.
func socketBackedJavascriptEngine(body string) bool {
	for _, module := range []string{
		"nuclei/smb", "nuclei/ldap", "nuclei/mysql",
		"nuclei/mongodb", "nuclei/redis", "nuclei/mssql", "nuclei/rpc",
	} {
		if strings.Contains(body, module) {
			return true
		}
	}
	return false
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
	// Protocol is the request block the template carries, in nuclei's own type
	// spelling (`http`, `tcp`, `fuzzing`, `workflow`, ...). It decides whether a
	// run against a URL can say anything about the file, and which capability
	// the binary needs in order to load it.
	Protocol string
	// Capabilities are the opt-in kinds the document requires. A document
	// needing none is loaded by the binary on its own.
	Capabilities []Capability
	// BlockKeys are every request section the document declares, in the
	// documented order. A document can mix blocks, so this is wider than
	// Protocol and is what makes "mixed http+code template" reportable.
	BlockKeys []string
	// SelfContained mirrors `self-contained: true`, kept for reporting because
	// the flag that loads such a template is not a protocol flag.
	SelfContained bool
	// GlobalMatchers reports `global-matchers: true`, a shared-matcher helper
	// that is included by other templates instead of being executed itself.
	GlobalMatchers bool
	// Flow reports `flow: <expr>`, a top-level chaining key. Its presence means
	// the document is a flow definition and not a runnable template, which the
	// binary confirms by loading no runnable body and exiting with
	// `[FTL] no templates provided for scan`. Measured on the official corpus:
	// 1 923 of 14 021 files (13.7 %).
	Flow string
	// ReservedFuzzTag reports a document whose `info.tags` contains the reserved
	// token `fuzz`. That token is not an ordinary label: nuclei v3.11.1 refuses to
	// compile the file in every combination measured — `-t`, `-t -dast` and
	// `-t -fuzz` each answer `[FTL] Could not run nuclei: no templates provided
	// for scan` with exit 1 and an empty report — while `nuclei -validate` accepts
	// the same file with "All templates validated successfully". So the validator
	// and the scanner disagree about a file that is neither malformed nor ours to
	// change, and the only honest report is that nothing in it was checked.
	//
	// The search was done by bisection rather than by reading the corpus: a
	// `payloads:`-inside-`http:` document was the first suspect and it is not it.
	// A minimal template whose `http` block carries `payloads:` and a `word`
	// matcher compiles and runs; the same document with `tags: fuzz` added is
	// refused, and removing the tag from the real file that is refused makes it
	// run. Measured on the official corpus: 37 of 14 072 files.
	ReservedFuzzTag bool
	// Digest is the SHA-256 of the document bytes. Two files with the same
	// digest are the same template no matter what they are called and wherever
	// they sit in the uploaded tree, which is what makes content-level duplicate
	// detection exact rather than name-level.
	Digest string
	// CodeBody is the raw text of the `code:` block, kept for the one question
	// it answers that the decoded tree cannot: does this document's own script
	// give its reads a deadline. `BlocksWithoutDeadline` reads it.
	CodeBody string
	// JavaScriptBody is the raw `javascript:` block, read because both module
	// imports and built-in target probes are spelled in its source.
	JavaScriptBody string
}

// IsReservedFuzzTagged reports whether the document carries the reserved `fuzz`
// tag the binary will not compile. It is kept apart from the flow and workflow
// cases because the binary does load those, and saying "the binary refused this
// file" where it actually ran something is the kind of claim the report must
// never make.
func (m *TemplateMeta) IsReservedFuzzTagged() bool { return m != nil && m.ReservedFuzzTag }

// NeedsDAST reports whether the document is one the binary loads only under
// `-dast`. It is the same question `documentCapabilities` answers when it
// derives the flag, exposed so that a caller which has to route the file
// elsewhere — a corpus sweep sending fuzzing templates to a fixture rather than
// to a third party's host — reads the document's own answer instead of guessing
// from a folder name.
func (m *TemplateMeta) NeedsDAST() bool {
	if m == nil {
		return false
	}
	for _, capability := range m.Capabilities {
		if capability == CapabilityDAST {
			return true
		}
	}
	return false
}

// ReservedFuzzTagReason names the tag and the measurement behind the status, so
// an operator can tell "this binary will not run this file" from "this run did
// not get to it" without reading the source.
func (m *TemplateMeta) ReservedFuzzTagReason() string {
	if !m.IsReservedFuzzTagged() {
		return ""
	}
	return "not compiled by the binary: the document's `info.tags` contains the reserved token `fuzz`, and " +
		"nuclei v3.11.1 refuses to compile such a file — measured on this file: `-t`, `-t -dast` and `-t -fuzz` " +
		"each answer `[FTL] Could not run nuclei: no templates provided for scan` with exit 1 and an empty report, " +
		"while `nuclei -validate` accepts the same file. Nothing in it was checked against the target, so this is " +
		"not a miss; removing the tag from the file makes it run."
}

// AddressesTarget reports whether executing this template sends a request to
// the scanned host. A template that does not can neither match nor miss
// against a URL, and the report has to say that rather than "not matched".
func (m *TemplateMeta) AddressesTarget() bool {
	if m == nil {
		return false
	}
	for _, key := range m.BlockKeys {
		if key == "javascript" {
			if m.javascriptAddressesTarget() {
				return true
			}
			continue
		}
		block, known := blockByKey[key]
		if !known || block.addressesTarget {
			return true
		}
	}
	return false
}

// javascriptAddressesTarget reports whether the JavaScript block imports a
// target-facing nuclei protocol module or calls a built-in port probe. Unknown
// nuclei modules are treated as target-facing; only the known local bytes and
// filesystem helpers are exempt.
func (m *TemplateMeta) javascriptAddressesTarget() bool {
	for _, module := range nucleiModulesNeeded(m.JavaScriptBody) {
		if module != "nuclei/bytes" && module != "nuclei/fs" {
			return true
		}
	}
	for _, helper := range []string{"isPortOpen(", "isUDPPortOpen("} {
		if strings.Contains(m.JavaScriptBody, helper) {
			return true
		}
	}
	return false
}

// IsFlow reports whether the document is a flow definition rather than a
// runnable template. nuclei does not execute such a file through `-t`, so the
// report has to say what it is instead of implying a check that never ran.
func (m *TemplateMeta) IsFlow() bool {
	return m != nil && strings.TrimSpace(m.Flow) != ""
}

// IsWorkflow reports whether the document's only request section is
// `workflows`, which makes it an orchestrator of other templates rather than a
// check against the target.
func (m *TemplateMeta) IsWorkflow() bool {
	if m == nil {
		return false
	}
	return onlyWorkflow(m.BlockKeys)
}

// WorkflowReason is the sentence the report shows for a workflow that emitted no
// record. It states what the file is and what the run did, because the status
// alone ("workflow") would not distinguish a workflow that ran from one that was
// never loaded, and the difference is the whole point of the status.
func (m *TemplateMeta) WorkflowReason() string {
	if !m.IsWorkflow() {
		return ""
	}
	return "workflow: this run's binary ran the subtemplates it names and matched nothing on its own; " +
		"results, if any, are reported under the subtemplate's own template id"
}

// FlowReason is the sentence the report shows for a flow file the binary did
// not execute. Short on purpose — the report names the fact, the documentation
// explains it.
//
// The wording was wrong until 2026-09-29 and said flow files are "not a runnable
// template" that "nuclei does not execute". Measured against nuclei v3.11.1 that
// is false: `flow: http(1) && http(2)` is loaded and run with no extra flag, and
// a `self-contained: true` JavaScript flow is loaded because the plan asks for
// `-esc`. The status is therefore not about what a flow *is* but about what this
// particular run did with it, and the sentence has to say that.
func (m *TemplateMeta) FlowReason() string {
	if !m.IsFlow() {
		return ""
	}
	return "flow definition: this run's binary produced no record for it, so nothing in it was checked"
}

// Requestless reports whether the template runs a local engine or reads local
// files, which is why it produces no request to the target at all.
func (m *TemplateMeta) Requestless() bool {
	if m == nil {
		return false
	}
	if len(m.BlockKeys) == 0 {
		return false
	}
	for _, key := range m.BlockKeys {
		if key == "javascript" {
			if m.javascriptAddressesTarget() {
				return false
			}
			continue
		}
		block, known := blockByKey[key]
		if !known || !block.requestless {
			return false
		}
	}
	return true
}

// BlockKey returns the document key that produced Protocol. Protocol is stored
// in nuclei's type spelling, so the two differ for the deprecated spellings
// (`requests` -> http, `network` -> tcp) and for the blocks whose type name is
// shared (`multi` -> http).
func (m *TemplateMeta) BlockKey() string {
	if m == nil {
		return ""
	}
	for _, key := range m.BlockKeys {
		if block, known := blockByKey[key]; known && block.typeName == m.Protocol {
			return key
		}
	}
	if len(m.BlockKeys) > 0 {
		return m.BlockKeys[0]
	}
	return ""
}

// documentInfo is the `info` block of a template. Only the fields the report
// shows are decoded; the rest of the block is data the binary reads and the
// report does not need.
type documentInfo struct {
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

// notATemplate marks a YAML file that is part of a templates tree but is not a
// template at all. A merged community collection carries GitHub issue forms,
// CI configs and nuclei template profiles next to the templates, and reporting
// them as "no request block" sends the operator looking for a missing `http:`
// that was never supposed to be there.
type notATemplate struct {
	reason string
}

// profileKeys are the top-level keys of a nuclei template profile
// (`-tp profile.yml`). A file made only of these is a profile, not a template.
var profileKeys = map[string]bool{
	"templates": true, "tags": true, "include-tags": true, "exclude-tags": true,
	"include-id": true, "exclude-id": true, "severity": true, "type": true,
	"exclude-type": true, "authors": true, "exclude-authors": true,
	"include-conditions": true, "conditions": true,
	// Measured against the official corpus: `code`, `var`, `headless`,
	// `disable-update-check` and `concurrency` appear as top-level keys of
	// profiles there — `profiles/alibaba-cloud-config.yml`, `profiles/all.yml`
	// and `profiles/k8s-cluster-security.yml` carry `code:` and `var:` and no
	// `id`, and were reported as `missing top-level id` instead of being
	// recognised as profiles. `var:` in particular is not a selection key: it is
	// template input, and a profile carrying only `var:` plus `code:` still
	// selects nothing on its own.
	"code": true, "var": true, "headless": true, "concurrency": true,
	"disable-update-check": true,
}

// classifyNonTemplate reports why a document is not a nuclei template, or
// returns an empty reason when it is one. A profile is recognised by having no
// `id` while carrying only profile keys, and by its position inside a `profiles`
// directory, which is where nuclei itself keeps them.
//
// A document that declares a request section is always treated as a template,
// however broken its header is. Without that rule a template whose author forgot
// the `id` would be filed under "not a template", which sends the operator
// looking for a file they never uploaded instead of at the one missing key.
func classifyNonTemplate(document map[string]yaml.Node, relativePath string) string {
	if len(document) == 0 {
		return "file is empty"
	}
	if _, hasID := document["id"]; hasID {
		return ""
	}
	// A request section is the one thing only a template can carry.
	if len(requestBlocks(document)) > 0 {
		return ""
	}
	onlyProfileKeys := true
	for key := range document {
		if !profileKeys[strings.ToLower(key)] {
			onlyProfileKeys = false
			break
		}
	}
	// A profile is a selection of other templates. It is recognised by carrying
	// only selection keys, so a template that merely forgot its `id` is still
	// reported as a malformed template rather than as a profile.
	if onlyProfileKeys {
		// A selection key is what makes it a profile. `code:` alone does not: it
		// enables a template kind, and a document carrying nothing but it selects
		// nothing — so the check is deliberately on the selection keys only, and
		// the sentence below names the ones present.
		present := make([]string, 0, 8)
		for _, key := range []string{"templates", "tags", "include-tags", "exclude-tags",
			"include-id", "exclude-id", "severity", "type", "exclude-type",
			"authors", "exclude-authors", "include-conditions", "conditions"} {
			if _, ok := document[key]; ok {
				present = append(present, key)
			}
		}
		if len(present) > 0 {
			return "this is a nuclei template profile, not a template: it only selects other templates by " +
				"path, tag, severity, author or condition (" + strings.Join(present, ", ") +
				"). Load the templates it points at instead."
		}
	}
	// The last sentence has to say what the file is, because the two files that
	// reach it in the official corpus sit *inside* template directories and read
	// as lost templates: `helpers/payloads/swagger.yml` is an OpenAPI document and
	// `http/technologies/wappalyzer-mapping.yml` is a technology-name mapping.
	// Saying only "no `id`, no `info`, no request section" leaves an operator
	// looking for a corpus problem that does not exist, so the shape is named.
	if description, ok := describeNonTemplateShape(document); ok {
		return description
	}
	first := strings.ToLower(firstSegment(relativePath))
	if first == ".github" || first == ".gitlab" || first == ".circleci" {
		return "this is a repository configuration file, not a nuclei template"
	}
	// The same statement applies to a dotfile at the root of a tree that was
	// uploaded whole: `.pre-commit-config.yml` is the one in the official corpus,
	// and it used to be reported as a template missing an `id`.
	if strings.HasPrefix(firstSegment(relativePath), ".") {
		return "this is a repository configuration file, not a nuclei template"
	}
	return "file has no `id`, no `info` block and no request section, so it is not a nuclei template"
}

// describeNonTemplateShape names what a non-template file actually is, for the
// shapes the official corpus contains. Measured on nuclei-templates: a Swagger /
// OpenAPI document (`swagger: '2.0'` with `info:` and `paths:`), and a flat
// technology mapping (`node.js: nodejs`). Both are refused by the binary too —
// `nuclei -validate -t <file>` answers "Could not find template" — so the point is
// not to accept them but to stop calling them broken templates.
//
// A flat mapping is only recognised when every key is an identifier and every
// value a short scalar, because that is the shape `wappalyzer-mapping.yml` has
// and a mapping is the only thing in the corpus with it. A file that merely looks
// sparse is not called a mapping.
func describeNonTemplateShape(document map[string]yaml.Node) (string, bool) {
	for _, key := range []string{"swagger", "openapi"} {
		if _, ok := document[key]; !ok {
			continue
		}
		if _, hasInfo := document["info"]; hasInfo {
			if _, hasPaths := document["paths"]; hasPaths {
				return fmt.Sprintf(
					"this is a Swagger/OpenAPI document, not a nuclei template: it declares %q with `info` and "+
						"`paths`, which a template never does. It is payload data for templates to send, not a check "+
						"to run.", key), true
			}
		}
	}
	if technologyMapping(document) {
		return "this is a technology-name mapping, not a nuclei template: a flat list of fingerprints " +
			"(`node.js: nodejs`) that a template loads by name. It checks nothing on its own.", true
	}
	return "", false
}

// technologyMapping reports whether every key of the document is an identifier
// and every value a short scalar. Anything richer is a template that happens to
// be sparse, and calling it a mapping would be the same mistake in the other
// direction.
func technologyMapping(document map[string]yaml.Node) bool {
	if len(document) == 0 {
		return false
	}
	for key, node := range document {
		if strings.ContainsAny(key, " \t") || len(key) > 64 {
			return false
		}
		if node.Kind != yaml.ScalarNode {
			return false
		}
		if len(node.Value) > 64 {
			return false
		}
	}
	return true
}

func firstSegment(path string) string {
	cleaned := strings.ReplaceAll(path, "\\", "/")
	cleaned = strings.TrimLeft(cleaned, "/")
	if index := strings.IndexByte(cleaned, '/'); index >= 0 {
		return cleaned[:index]
	}
	return cleaned
}

// digestOf is the content identity of a document. Byte-identical files are the
// same template, which is the only comparison that is true regardless of file
// name, folder or line endings introduced by whatever copied them.
func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// rawBlockBody returns the source text of one top-level block, taken from the
// document bytes rather than from the decoded tree.
//
// The decoded tree would not answer the question `BlocksWithoutDeadline` asks —
// it would re-render the script and lose the spelling the author wrote, which is
// exactly the spelling being looked for. It also costs nothing here: the bytes
// are already in hand at parse time.
func rawBlockBody(content, key string) string {
	lines := strings.Split(content, "\n")
	start := -1
	for index, line := range lines {
		if line != key+":" {
			continue
		}
		start = index
		break
	}
	if start < 0 {
		return ""
	}
	body := make([]string, 0, len(lines)-start)
	for _, line := range lines[start+1:] {
		// A line that is not indented and not a comment has left the block.
		if line != "" && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			break
		}
		body = append(body, line)
	}
	return strings.Join(body, "\n")
}

// onlyWorkflow reports whether a document's request sections are exactly one
// `workflows` block.
//
// It is a separate question from "does this document mention workflows", because
// a document that mixes a workflow with a real request section does produce
// findings, and its findings carry a severity — so that document still has to
// declare one.
func onlyWorkflow(blocks []string) bool {
	return len(blocks) == 1 && blocks[0] == "workflows"
}

// parseTemplateDocument reads the identity, the request sections and the
// required capabilities of a template, and reports why the Nuclei engine would
// refuse it. The header checks mirror nuclei itself: a template without
// `info.author` is dropped as invalid_template, which is what makes the binary
// exit 1 with "no templates provided for scan" when every upload is missing it.
//
// The request-section list is the binary's own, so a document whose only section
// is `tcp`, `requests` or `workflows` is recognised instead of being called
// invalid. The remaining verdict — whether nuclei can actually parse the file —
// belongs to the binary, and `nuclei -validate` is what supplies it; see
// nuclei_validate.go.
func parseTemplateDocument(content string) (*TemplateMeta, string) {
	meta, reason := parseTemplateDocumentWithPath(content, "")
	return meta, reason
}

// parseTemplateDocumentWithPath is parseTemplateDocument with the uploaded
// location available, which is what lets a non-template file be recognised as a
// profile or a repository config instead of as a broken template.
func parseTemplateDocumentWithPath(content, relativePath string) (*TemplateMeta, string) {
	// Before the decode, not after: the decode is the expensive step, and an inflating
	// document is exactly the one that makes it expensive. See nuclei_amplification.go for
	// why this is a ratio rather than a second size limit.
	if reason := checkYAMLAmplification(content, yamlAmplificationLimitFromEnv(
		"RR_YAML_MAX_AMPLIFICATION", maxYAMLAmplification)); reason != "" {
		return nil, reason
	}
	var document map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		return nil, "invalid YAML: " + oneLine(err.Error())
	}
	if reason := classifyNonTemplate(document, relativePath); reason != "" {
		return nil, reason
	}
	rawID, ok := document["id"]
	if !ok || strings.TrimSpace(rawID.Value) == "" {
		return nil, "missing top-level id"
	}
	infoNode, ok := document["info"]
	if !ok {
		return nil, "missing info block"
	}
	var info documentInfo
	if err := infoNode.Decode(&info); err != nil {
		return nil, "invalid info block: " + oneLine(err.Error())
	}
	if strings.TrimSpace(info.Name) == "" {
		return nil, "missing info.name"
	}
	if len(nonEmpty(info.Author)) == 0 {
		return nil, "missing info.author — nuclei rejects templates without an author field"
	}
	blocks := requestBlocks(document)
	severity := strings.ToLower(strings.TrimSpace(info.Severity))
	// `workflows` is an orchestrator, not a check: it names the templates to run
	// and therefore has no severity of its own, because it produces no finding to
	// weigh. Demanding one dropped every workflow in a real corpus — 207 files
	// that `nuclei -validate` accepts, and the binary is the authority on what it
	// accepts. The requirement therefore holds for every other block, and for a
	// document that merely *also* carries a `workflows` section alongside a real
	// one: only a document whose sole section is `workflows` is exempt.
	if severity == "" && !onlyWorkflow(blocks) {
		return nil, "missing info.severity"
	}
	if severity != "" && !validSeverities[severity] {
		return nil, fmt.Sprintf("unknown info.severity %q", info.InfoSeverity())
	}
	if len(blocks) == 0 {
		return nil, "no request block — a nuclei template declares one of: " + strings.Join(blockKeys, ", ")
	}
	// The first block in the documented order is the one a JSONL record reports as
	// its `type`, so a document that mixes blocks is named by the kind nuclei
	// would label it with. The rest travel in BlockKeys.
	primary := blockByKey[blocks[0]]
	capabilities, selfContained, globalMatchers := documentCapabilities(document, blocks)
	// The reserved `fuzz` tag is recorded rather than refused at parse time. The
	// file is a real check, `nuclei -validate` accepts it, and dropping it here
	// would lose a file the operator did nothing wrong with — and, worse, would
	// hide the refusal rather than name it. The run is where that is said.
	reservedFuzz := tagTokens(document)[reservedFuzzTag]
	meta := &TemplateMeta{
		TemplateID:      strings.TrimSpace(rawID.Value),
		Name:            strings.TrimSpace(info.Name),
		Severity:        strings.ToUpper(severity),
		Author:          nonEmpty(info.Author),
		Tags:            nonEmpty(info.Tags),
		CVE:             nonEmpty(info.Classification.CVE),
		CWE:             nonEmpty(info.Classification.CWE),
		Protocol:        primary.typeName,
		Capabilities:    capabilities,
		BlockKeys:       blocks,
		ReservedFuzzTag: reservedFuzz,
		SelfContained:   selfContained,
		GlobalMatchers:  globalMatchers,
		Flow:            flowExpression(document),
		Digest:          digestOf(content),
		CodeBody:        rawBlockBody(content, "code"),
		JavaScriptBody:  rawBlockBody(content, "javascript"),
	}
	return meta, ""
}

// flowExpression returns the document's top-level `flow:` value, or an empty
// string. It is read from the node rather than from a typed struct because a
// flow key sits beside `id` and `info`, not inside any request block, and
// missing it is what turns a flow into a silent "no matches".
func flowExpression(document map[string]yaml.Node) string {
	node, ok := document["flow"]
	if !ok || node.Kind == 0 || node.Tag == "!!null" {
		return ""
	}
	return oneLine(strings.TrimSpace(node.Value))
}

// InfoSeverity is the severity as written in the document, kept for a message
// that quotes the operator's own spelling.
func (info documentInfo) InfoSeverity() string { return info.Severity }

// requestBlocks names the request sections a document declares, in the order
// nuclei documents them so the name is stable between runs.
// requestBlocks returns the request sections a document declares.
//
// A switch is not a section. `code: true` and `headless: true` are the profile
// keys that *enable* those template kinds, while `code:` as a list of
// `{engine, source}` entries and `headless:` as a list of `steps` are the
// sections themselves — the two are the same YAML key with different values, so
// they are told apart by the node kind rather than by the name. Getting this
// wrong is not cosmetic: a profile carrying `code: true` was counted as having a
// request section, so it was never recognised as a profile and was reported as a
// template with a missing `id`.
func requestBlocks(document map[string]yaml.Node) []string {
	present := make([]string, 0, 4)
	for _, block := range protocolBlocks {
		node, ok := document[block.key]
		if !ok || node.Kind == 0 || node.Tag == "!!null" {
			continue
		}
		if node.Kind == yaml.ScalarNode {
			continue
		}
		if node.Kind == yaml.SequenceNode && len(node.Content) == 0 {
			continue
		}
		present = append(present, block.key)
	}
	return present
}

// scalarTrue reads a top-level boolean, which is how the capability switches are
// written. An absent or non-scalar value is false rather than an error: the
// binary treats it the same way, and a template that writes `self-contained: 1`
// still loads.
func scalarTrue(document map[string]yaml.Node, key string) bool {
	node, ok := document[key]
	if !ok || node.Kind != yaml.ScalarNode {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(node.Value)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// reservedDASTTag and reservedFuzzTag are the two tag tokens the binary treats as
// statements about the engine rather than as labels. `fuzz` is the one it will
// not compile at all; see TemplateMeta.ReservedFuzzTag for the measurement.
const (
	reservedDASTTag = "dast"
	reservedFuzzTag = "fuzz"
)

// tagTokens reads `info.tags` as a set of lowercase tokens. The corpus writes it
// both as a comma string and as a YAML list, and a tag set is what both the
// capability derivation and the reserved-tag refusal read, so both spellings are
// parsed here once rather than in two places that could disagree.
func tagTokens(document map[string]yaml.Node) map[string]bool {
	tokens := map[string]bool{}
	node, ok := document["info"]
	if !ok {
		return tokens
	}
	var meta documentInfo
	if node.Decode(&meta) != nil {
		return tokens
	}
	for _, tag := range meta.Tags {
		// The corpus writes `tags` both as a YAML list and as one comma-separated
		// string, and `flexYAMLStrings` keeps the string form as a single element.
		// Reading only the element would miss the reserved token in exactly the
		// files that carry it, so the string is split here.
		for _, part := range strings.Split(tag, ",") {
			if trimmed := strings.ToLower(strings.TrimSpace(part)); trimmed != "" {
				tokens[trimmed] = true
			}
		}
	}
	return tokens
}

// dastPayloadBlocks counts, inside the document's `http:`/`requests:` sections,
// how many blocks carry `payloads:` and how many of those also carry the
// `fuzzing:` key that names the engine to drive them.
//
// The second count is the DAST question, and reading it from the block rather
// than from a top-level `fuzzing:` section closes a measured loss:
// `documentCapabilities` derived `-dast` from a top-level `fuzzing:` section
// only, so a `http:` block carrying `payloads:`+`fuzzing:` — the shape 54 files
// of the official corpus use — asked for no flag. Verified on
// `dast/ai/ai-code-execution.yaml` against `https://ria.ru/`: 0 records with
// `-t .`, 1 record with `-t . -dast`.
//
// The first count is reported but deliberately not acted on. A `payloads:`
// block with no `fuzzing:` key beside it looks like the pre-v3 spelling and is
// not: measured, `http/cves/2000/CVE-2000-0114.yaml`, `CVE-2008-2052.yaml` and
// `CVE-2010-0219.yaml` all carry it and all produce a record. Treating the shape
// as a refusal would have named 695 files the binary runs perfectly well.
func dastPayloadBlocks(document map[string]yaml.Node) (withEngine, withoutEngine int) {
	for _, key := range []string{"http", "requests"} {
		for _, block := range sequenceEntries(document, key) {
			payloads, ok := block["payloads"]
			if !ok || payloads.Kind == 0 || payloads.Tag == "!!null" {
				continue
			}
			if _, named := block["fuzzing"]; named {
				withEngine++
				continue
			}
			withoutEngine++
		}
	}
	return withEngine, withoutEngine
}

// sequenceEntries returns the mapping entries of a document section written as
// either `- {…}` or a single `{…}`. A switch such as `code: true` is not a
// section and yields nothing, which is the same node-kind rule `requestBlocks`
// uses; asking twice would be a second spelling of the same question.
func sequenceEntries(document map[string]yaml.Node, key string) []map[string]yaml.Node {
	node, ok := document[key]
	if !ok || node.Kind == 0 || node.Tag == "!!null" {
		return nil
	}
	entries := make([]map[string]yaml.Node, 0, 2)
	switch node.Kind {
	case yaml.MappingNode:
		var entry map[string]yaml.Node
		if node.Decode(&entry) == nil {
			entries = append(entries, entry)
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			var entry map[string]yaml.Node
			if item.Decode(&entry) == nil && len(entry) > 0 {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

// documentCapabilities derives the opt-in kinds a document needs from its own
// sections. It is read from the document rather than from a flag the operator
// set, because the operator named the files and each file says what it is.
func documentCapabilities(document map[string]yaml.Node, blocks []string) ([]Capability, bool, bool) {
	selfContained := scalarTrue(document, "self-contained")
	globalMatchers := scalarTrue(document, "global-matchers")
	required := map[Capability]bool{}
	for _, key := range blocks {
		switch block := blockByKey[key]; block.typeName {
		case "code":
			required[CapabilityCode] = true
		case "file":
			required[CapabilityFile] = true
		case "headless":
			required[CapabilityHeadless] = true
		case "fuzzing":
			required[CapabilityDAST] = true
		}
	}
	// A `payloads:` block that names its `fuzzing:` engine is driven by the fuzzing
	// engine, and the binary loads it only under `-dast`. Reading it from the
	// block rather than from a top-level `fuzzing:` section is what closes the
	// loss `dastPayloadBlocks` documents.
	if withEngine, _ := dastPayloadBlocks(document); withEngine > 0 {
		required[CapabilityDAST] = true
	}
	// `dast` in the tag list is the second spelling of the same need, and a
	// corpus carries both: `dast/ai/ai-code-execution.yaml` writes
	// `tags: ai,rce,oast,dast` and its block carries both `payloads:` and
	// `fuzzing:`, so the block alone would cover it. The tag is read as well
	// because a document that declares it and describes its engine differently
	// must not be the reason a run loses the file.
	if tagTokens(document)[reservedDASTTag] {
		required[CapabilityDAST] = true
	}
	if selfContained {
		required[CapabilitySelfContained] = true
	}
	if globalMatchers {
		required[CapabilityGlobalMatchers] = true
	}
	capabilities := make([]Capability, 0, len(required))
	for _, capability := range allCapabilities {
		if required[capability] {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities, selfContained, globalMatchers
}

// capabilityFlagArgs renders the flags for a capability set. The result is
// ordered by nuclei's own evaluation order so the generated command line is
// reproducible and can be pasted into a terminal to reproduce a run.
func capabilityFlagArgs(capabilities []Capability) []string {
	required := map[Capability]bool{}
	for _, capability := range capabilities {
		required[capability] = true
	}
	args := make([]string, 0, len(required))
	for _, capability := range allCapabilities {
		if required[capability] {
			args = append(args, capabilityFlag[capability])
		}
	}
	return args
}

// capabilityDescription explains a capability in the report, so an operator sees
// why a flag was added rather than an unexplained command line.
func capabilityDescription(capability Capability) string {
	switch capability {
	case CapabilityCode:
		return "a `code` template runs a local engine, so the binary only loads it with -code"
	case CapabilityFile:
		return "a `file` template reads local files, so the binary only loads it with -file"
	case CapabilityHeadless:
		return "a `headless` template drives a browser, so the binary only loads it with -headless"
	case CapabilityDAST:
		return "a `fuzzing` template is driven by the fuzzing engine, so the binary only loads it with -dast"
	case CapabilityGlobalMatchers:
		return "a global-matcher helper is only loaded with -egm, and it is included by other templates " +
			"rather than executed on its own"
	case CapabilitySelfContained:
		return "a self-contained template carries its own payload instead of importing a helper file, " +
			"so the binary only loads it with -esc"
	}
	return string(capability)
}

// explainCapabilities renders the reasons a document needs the flags it needs,
// one per line. It is the message shown next to a file that could not be run, so
// the operator can act without reading the source.
func explainCapabilities(capabilities []Capability) string {
	if len(capabilities) == 0 {
		return ""
	}
	lines := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		lines = append(lines, fmt.Sprintf("%s: %s", capabilityFlag[capability], capabilityDescription(capability)))
	}
	return strings.Join(lines, "; ")
}

// sortedCapabilityKeys renders a capability set for a report field.
func sortedCapabilityKeys(capabilities []Capability) []string {
	keys := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		keys = append(keys, string(capability))
	}
	sort.Strings(keys)
	return keys
}

// ParseTemplateDocumentWithPath is parseTemplateDocumentWithPath exported for the
// out-of-package corpus tool (`engine/cmd/corpusrefusals`), which has to classify
// every file of a real template tree and cannot reach an unexported parser.
//
// It exists because the refusal question could not be answered before it: the
// corpus probe counts refusals by reason, which does not say which files they
// are, and there was no way to go from "6 refused" to the list to fix.
func ParseTemplateDocumentWithPath(content, relativePath string) (*TemplateMeta, string) {
	return parseTemplateDocumentWithPath(content, relativePath)
}
