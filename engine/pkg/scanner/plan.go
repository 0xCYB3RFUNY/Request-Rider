package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file turns a staged set of templates into the list of nuclei invocations
// that will run all of them.
//
// Two properties of the binary force the plan, and both were measured on
// v3.11.1 rather than assumed:
//
//  1. It loads exactly one file per template id. Two staged files that declare
//     the same `id` cannot both run in one invocation — the second is dropped
//     without a word, whether the files are named separately, listed
//     comma-separated or filtered with `-id`. A merged collection hits this
//     constantly: in 382 396 unique documents there were only 207 214 distinct
//     ids, and 76 731 ids carried more than one document. The plan therefore
//     spreads the members of an id group across separate batches, which is the
//     minimum number of invocations that can prove every file ran.
//
//  2. Some capability flags abort a whole invocation that does not need them.
//     `-dast` is the one: added to a folder with no fuzzing template, nuclei
//     prints `[FTL] Could not run nuclei: no templates provided for scan` and
//     exits 1, so every other template in that invocation is cancelled too. A
//     flag derived from one document must never be able to silence the rest, so
//     each capability group gets its own batches.
//
// Everything else stays in one invocation: the flags that only add a template
// kind — `-code`, `-file`, `-headless`, `-egm`, `-esc` — were verified to widen
// the run rather than replace it.

// NucleiPlan is the full execution plan of one scan.
type NucleiPlan struct {
	// Root is the directory the plan was built against.
	Root string
	// Batches are the invocations, in execution order.
	Batches []NucleiBatch
	// Invalid are the files that will not be run at all, with the reason: the
	// binary refused them, or they duplicate a file that is.
	Invalid []StagedFile
	// Dedup is what content-level duplicate removal collapsed.
	Dedup DuplicateReport
	// TotalFiles is how many staged files the plan accounts for.
	TotalFiles int
	// Inputs is the staged set in upload order. The report is emitted in this
	// order so a folder reads the way the operator uploaded it, whatever the plan
	// decided to execute first.
	Inputs []StagedFile
	// ledger pairs every unplanned file with the reason it is unplanned and with the
	// row key that puts it back in its slot in the upload.
	ledger []ledgerEntry
	// rowKeys maps an uploaded file's identity to its row key, so the finished
	// report can be ordered by upload position rather than by execution order.
	rowKeys map[string]string
}

// inputIdentity names an uploaded file for lookup. A file that reached the disk is
// named by its staged path, which stageInto keeps unique inside an upload. A file
// rejected before staging has no path, so it is named by its upload name, its
// reported path and its index among the unstaged files — which together are unique
// because a folder cannot hold the same name twice in the same place after
// stageInto has made the staged paths unique.
func inputIdentity(file StagedFile, unstagedIndex int) string {
	if file.StagedPath != "" {
		return "path:" + cleanPathForCompare(file.StagedPath)
	}
	return fmt.Sprintf("unstaged:%d:%s|%s", unstagedIndex, file.UploadName, reportPath(file))
}

// assignInputKeys gives every uploaded file a stable identity and a row key, both
// derived from the upload position. The plan copies them onto its ledger and batch
// entries, which is what lets the finished report be put back in upload order
// instead of the order the plan happened to execute.
func assignInputKeys(inputs []StagedFile) (byIdentity, keyByIdentity map[string]string) {
	byIdentity = make(map[string]string, len(inputs))
	keyByIdentity = make(map[string]string, len(inputs))
	unstaged := 0
	for position, file := range inputs {
		identity := inputIdentity(file, unstaged)
		if file.StagedPath == "" {
			unstaged++
		}
		byIdentity[identity] = identity
		keyByIdentity[identity] = fmt.Sprintf("row:%d", position)
	}
	return byIdentity, keyByIdentity
}

// ledgerEntry pairs an unplanned file with the reason it is unplanned and the row
// key that ties it back to its slot in the upload.
type ledgerEntry struct {
	file StagedFile
	kind planInvalidKind
	key  string
}

// planInvalidKind records why a file is not planned, so a duplicate is reported
// as a duplicate and a refusal as a refusal. A template that merely looks like
// another one is not the same statement as one nuclei cannot parse.
type planInvalidKind int

const (
	planInvalidRefused planInvalidKind = iota
	planInvalidDuplicate
)

// keyFor looks up the row key of an uploaded file. A staged file is found by its
// path; a file that never reached the disk is found by its upload identity, and the
// caller passes the index it holds among the unstaged files so two identically
// named rejects in the same folder stay apart.
func keyFor(keys map[string]string, file StagedFile, unstagedIndex int) string {
	return keys[inputIdentity(file, unstagedIndex)]
}

// unstagedIndex reports a rejected file's position among the rejected ones, which
// is how its upload identity is completed.
func unstagedIndex(file StagedFile, rejected []StagedFile) int {
	for index, candidate := range rejected {
		if candidate.StagedPath != "" {
			continue
		}
		if candidate.UploadName == file.UploadName && reportPath(candidate) == reportPath(file) {
			return index
		}
	}
	return 0
}

// InvalidResults renders every unplanned file as a report row. A file the binary
// refused is `invalid`; a byte-identical copy is `duplicate`, which is a
// different statement: nothing is wrong with it, it is simply the same template
// under a second name.
func (p *NucleiPlan) InvalidResults() []TemplateResult {
	results := make([]TemplateResult, 0, len(p.ledger))
	for _, entry := range p.ledger {
		status := TemplateInvalid
		if entry.kind == planInvalidDuplicate {
			status = TemplateDuplicate
		}
		results = append(results, resultFor(entry.file, status, entry.file.Reason))
	}
	return results
}

// Resolve maps a path the binary reported back to the staged file it came from.
// It is what makes attribution work when a template is loaded from a per-batch
// directory instead of from the staging root.
func (p *NucleiPlan) Resolve(path string) (StagedFile, bool) {
	clean := cleanPathForCompare(path)
	for _, batch := range p.Batches {
		for _, batchFile := range batch.Files {
			if cleanPathForCompare(batchFile.Path) == clean {
				return batchFile.File, true
			}
		}
	}
	return StagedFile{}, false
}

// BatchFile is one template inside a batch: the staged file it came from and the
// path the binary will load it from. The two differ because a batch directory
// holds a hard link, and the JSONL record names the path nuclei read — so
// attribution has to go through this pair rather than through the staged path.
type BatchFile struct {
	// File is the staged upload this template came from.
	File StagedFile
	// Path is the absolute path inside the batch directory.
	Path string
	// Key ties the file back to its position in the upload.
	Key string
}

// NucleiBatch is one nuclei invocation: a directory of templates plus the
// capability flags the binary needs to load them.
type NucleiBatch struct {
	// Index is the batch's position in the plan, starting at 1.
	Index int
	// Dir is the directory holding exactly this batch's templates.
	Dir string
	// InPlace reports that Dir is the folder the operator chose rather than a
	// directory this plan created, and that the plan therefore must not remove it.
	//
	// It is set only for a single batch whose files all already live under the
	// root: the operator named a folder and `-t` is pointed at that folder itself,
	// so nothing is copied and nothing may be deleted afterwards.
	InPlace bool
	// Key is the capability set this batch is run with.
	Key capabilityKey
	// Capabilities are the flags the batch adds.
	Capabilities []Capability
	// Files are the templates in this batch, in plan order.
	Files []BatchFile
	// MaxTemplateIDMultiplicity is the largest number of same-id documents the
	// plan had to spread for this batch, which is why more than one batch exists.
	MaxTemplateIDMultiplicity int
}

// drivesBrowser reports whether this batch's documents ask for the browser
// protocol. The question is asked of the batch rather than of one file, because
// the browser is a single process shared by everything in the invocation.
//
// It is also why `groupByCapability` strips the capability from every key that
// does not need it: a batch that reports true here carries `-headless`, and a
// browser that never finishes must not be something an unrelated template waits
// on. Measured on v3.11.1 here, nine templates in the corpus accounting — five
// `javascript`, four `http`, none carrying a `headless:` block — lost their
// verdicts to a neighbour's browser before that split existed.
func (b NucleiBatch) drivesBrowser() bool {
	for _, capability := range b.Capabilities {
		if capability == CapabilityHeadless {
			return true
		}
	}
	return false
}

// PlanRequest is what building a plan needs.
type PlanRequest struct {
	// Dir is the staging root the batch directories are created under.
	Dir string
	// Staged is the full set of uploaded files, invalid ones included.
	Staged []StagedFile
}

// BuildPlan deduplicates and partitions a staged set into the invocations that
// will run every runnable template exactly once.
//
// There is no validation pass in here any more. A document the binary cannot load
// is no longer refused in advance: it is staged, planned, run, produces no JSONL
// record and is reported `skipped` with the reason the binary's own stderr carries.
// That is the operator's rule (2026-10-06) and it is also what the measurement
// supported — the `-validate` pass cancelled whole folders over a single refused
// file, `http` among them.
//
// The plan is deterministic: the same staged set always produces the same
// batches in the same order, so a report can be reproduced and a regression test
// can name the batch a file lands in.
func BuildPlan(request PlanRequest) (NucleiPlan, error) {
	plan := NucleiPlan{Root: request.Dir, TotalFiles: len(request.Staged), Inputs: request.Staged}
	_, keyByIdentity := assignInputKeys(request.Staged)
	plan.rowKeys = keyByIdentity
	// Every staged file is planned. Nothing is refused in advance: a document the
	// binary cannot load runs, produces no record, and the run reports it as
	// `skipped` with the binary's own reason — see `BuildPlan`.
	//
	// The exception is a file this project's OWN parser could not read. That is not
	// the binary refusing it: there is no document on disk to hand the binary, so it
	// goes to the ledger as `invalid` with the parse reason rather than failing the
	// whole plan on a missing file.
	accepted, preRejected := splitPreRejected(request.Staged)
	for _, file := range preRejected {
		plan.ledger = append(plan.ledger, ledgerEntry{
			file: file, kind: planInvalidRefused,
			key: keyFor(keyByIdentity, file, unstagedIndex(file, preRejected)),
		})
	}
	deduped, dedup := DedupeStaged(accepted)
	plan.Dedup = dedup
	// A duplicate is not an error, it is a file whose content is already covered.
	// It is reported as such rather than being planned into a batch that would
	// only re-run the same template.
	unique, duplicates := splitDuplicates(deduped, dedup)
	for _, file := range markDuplicates(duplicates, dedup) {
		plan.ledger = append(plan.ledger, ledgerEntry{
			file: file, kind: planInvalidDuplicate, key: keyFor(keyByIdentity, file, 0),
		})
	}

	groups := groupByCapability(unique)
	keys := make([]capabilityKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}

	// Isolated groups run last so a folder is scanned with the plain flag set
	// first, which is the run an operator is waiting for.
	sort.Slice(keys, func(i, j int) bool {
		left, right := keys[i], keys[j]
		if left.isolated() != right.isolated() {
			return !left.isolated()
		}
		return left < right
	})
	index := 0
	for _, key := range keys {
		files := groups[key]
		multiplicity := maxIDMultiplicity(files)
		capabilities := key.parseCapabilities()
		for _, chunk := range spreadByID(files, multiplicity) {
			index++
			batch, err := materialiseBatch(request.Dir, index, key, capabilities, chunk, multiplicity, keyByIdentity)
			if err != nil {
				// A batch that cannot be written would silently lose its files, so
				// the plan fails loudly instead of scanning a subset.
				plan.removeBatches()
				return NucleiPlan{}, err
			}
			plan.Batches = append(plan.Batches, batch)
		}
	}
	return plan, nil
}

// removeBatches deletes the batch directories of a plan, so a plan that will not
// be run leaves nothing behind on disk.
//
// It deliberately does not clear p.Batches. Once a plan is handed to a job its
// metadata is read from another goroutine — the live event stream resolves every
// reported path back to its staged file through Resolve — so emptying the slice
// here was a write racing that read. The batch list is small next to the findings
// it describes, and both callers treat the plan as finished: the planning failure
// path returns an empty plan, and Clean runs after the report is built.
func (p *NucleiPlan) removeBatches() {
	for _, batch := range p.Batches {
		if batch.Dir == "" {
			continue
		}
		// A batch kept in place IS the folder the operator chose, and removing it
		// would delete their corpus. `materialiseBatch` leaves a single batch there
		// so `-t` names their folder; this is the other half of that decision, and
		// the two have to agree or a run would delete what it was pointed at.
		if batch.InPlace {
			continue
		}
		_ = os.RemoveAll(batch.Dir)
	}
}

// Clean removes the batch directories of a finished plan.
func (p *NucleiPlan) Clean() {
	if p == nil {
		return
	}
	p.removeBatches()
}

// splitPreRejected separates the files this project's own parser could not read
// from the ones it could.
//
// A rejected file has no `Meta` and no document on disk, so planning it would fail on
// a missing source rather than on anything to do with the scan. It is reported
// `invalid` with the parse reason — which is a fact about the file, not about the
// binary. This is NOT the `-validate` pass: nothing here starts a nuclei process, and
// a file the binary refuses at scan time is handled by the run instead.
func splitPreRejected(staged []StagedFile) (accepted, rejected []StagedFile) {
	for _, file := range staged {
		if file.Meta == nil || file.StagedPath == "" {
			rejected = append(rejected, file)
			continue
		}
		accepted = append(accepted, file)
	}
	return accepted, rejected
}

// splitDuplicates separates the unique documents from the copies that collapse
// into them. Both come back from DedupeStaged in one slice, so the copies are
// recognised by the digest map rather than by position.
func splitDuplicates(deduped []StagedFile, dedup DuplicateReport) (unique, duplicates []StagedFile) {
	groupByDigest := map[string]DuplicateGroup{}
	for _, group := range dedup.Groups {
		groupByDigest[group.Digest] = group
	}
	firstSeen := map[string]bool{}
	for _, file := range deduped {
		if file.Meta == nil || file.Meta.Digest == "" {
			unique = append(unique, file)
			continue
		}
		if !firstSeen[file.Meta.Digest] {
			firstSeen[file.Meta.Digest] = true
			unique = append(unique, file)
			continue
		}
		duplicates = append(duplicates, file)
	}
	return unique, duplicates
}

// markDuplicates gives every removed copy the reason that names the file that
// took its place, and returns the copies so the caller can ledger them.
func markDuplicates(duplicates []StagedFile, dedup DuplicateReport) []StagedFile {
	keptByDigest := map[string]DuplicateGroup{}
	for _, group := range dedup.Groups {
		keptByDigest[group.Digest] = group
	}
	for index := range duplicates {
		if duplicates[index].Meta == nil {
			continue
		}
		group, known := keptByDigest[duplicates[index].Meta.Digest]
		if !known {
			// The group summary is capped, so a copy whose group fell outside the
			// cap still gets a truthful reason without naming its twin.
			duplicates[index].Reason = "Not run separately: this file is byte-identical to another file in " +
				"this upload, so it is the same template under a different name and one copy is enough."
			continue
		}
		duplicates[index].Reason = duplicateReason(reportPath(duplicates[index]), group)
	}
	return duplicates
}

// groupByCapability buckets runnable files by the capability set they need. Two
// files that need no capability at all land in the same bucket, because that is
// the run the binary performs with no extra flag.
func groupByCapability(files []StagedFile) map[capabilityKey][]StagedFile {
	groups := map[capabilityKey][]StagedFile{}
	for _, file := range files {
		var capabilities []Capability
		if file.Meta != nil {
			capabilities = file.Meta.Capabilities
		}
		// `-headless` starts a browser for the whole invocation, and nuclei keeps
		// it alive until every template in that invocation has finished. Measured
		// on v3.11.1 here, Chromium opens its DevTools endpoint and the session
		// never ends, so a document that needs no browser at all is held by one
		// that does:
		//
		//	nuclei -t . -w . -it . -ms -or -timeout 5        -> no record, 240 s
		//	the same file with -headless removed              -> 1 record, 17 s
		//
		// Nine templates in the corpus accounting landed there — five `javascript`,
		// four `http`, none of them carrying a `headless:` block — and each lost its
		// verdict to a neighbour's browser.
		//
		// So the flag follows the documents that asked for it and nobody else. It
		// is added per batch from `batch.Capabilities`, which this keeps honest:
		// a batch whose documents never named a headless block never receives it.
		// Splitting costs one extra invocation per run that has both kinds, which
		// is the smallest price that gives an HTTP template its own answer.
		//
		// The document's own capability set is the source of truth, not a key
		// cleaned afterwards: `capabilityKeyOf` already renders `headless` only for
		// documents that asked for it, so there is nothing to strip. A document
		// that merely *contains* a headless block — `flow+headless+http`, which
		// this corpus has 193 of — is a headless document, and treating it as one
		// is what keeps its neighbours out of the browser's way.
		key := capabilityKeyOf(capabilities)
		// A document that can block forever gets a batch of its own, so its
		// deadline costs one template instead of every template sharing the
		// invocation.
		//
		// The shape is read from the document, not guessed: a `code` template
		// whose script calls `recv(` or `read(` without ever setting a socket
		// timeout waits on a peer that never answers. Measured on the official
		// corpus: 5 of its documents look like this, and
		// `code/cves/2016/CVE-2016-8735` — four `recv()` calls and not one
		// `settimeout` — held a 4-file batch for 30 minutes with nothing written,
		// so the three templates beside it lost their verdicts to it.
		//
		// Two such documents must not meet either. They run in one process, so the
		// second one only starts when the first returns — and the first never
		// does, so the second's own deadline begins after a wait it did not cause
		// and cannot shorten. Hence the template id in the key: one document, one
		// batch, every time.
		//
		// The deadline itself is not this function's business: it is applied by
		// `executeBatch` to an isolated batch, which is what the key below
		// selects. What this function guarantees is only that such a document is
		// never a neighbour.
		if file.Meta != nil && file.Meta.BlocksWithoutDeadline() {
			// The batch runs alone, but it does NOT need the isolated capability's
			// flag. Those are two different questions, and conflating them cost a
			// whole folder: `groupByCapability` put the document in a key that
			// *starts* with `dast`, and `executeBatch` reads the key's first element
			// as the capability to add — so 8 JavaScript documents that need no
			// fuzzing flag were launched with `-dast` on a one-file directory that
			// holds no fuzzing template. Measured on nuclei v3.11.1 against
			// `javascript/` (131 documents): all 8 invocations answered `[FTL]
			// Could not run nuclei: no templates provided for scan`, exit 1 and
			// zero records — 8 real checks performed by nobody.
			//
			// The flag was already documented as fatal for exactly this shape: a
			// directory with no template of the protocol the flag names. What was
			// missing is that a batch key may carry a *marker*, and the marker is
			// not a capability.
			//
			// So the key is the document's own capability set plus a separator and
			// the template id, and only the part before the separator is read as a
			// capability. `dast` is not injected here: a document that really needs
			// `-dast` already asked for it, and `documentCapabilities` put it in the
			// set.
			alone := capabilityKey(strings.Join(
				append(capabilityKeyOf(capabilities).parts(), file.Meta.TemplateID), "+"))
			groups[alone] = append(groups[alone], file)
			continue
		}
		groups[key] = append(groups[key], file)
	}
	return groups
}

// maxIDMultiplicity is the largest number of runnable documents that share one
// template id inside a capability group. It is the number of invocations that
// group provably needs, because the binary keeps one file per id.
func maxIDMultiplicity(files []StagedFile) int {
	counts := map[string]int{}
	highest := 0
	for _, file := range files {
		if file.Meta == nil {
			continue
		}
		counts[file.Meta.TemplateID]++
		if counts[file.Meta.TemplateID] > highest {
			highest = counts[file.Meta.TemplateID]
		}
	}
	return highest
}

// spreadByID partitions a group into `multiplicity` batches such that no batch
// holds two documents with the same template id.
//
// The split is round-robin over the id groups ordered by size, so the batches
// come out close to equal instead of one huge batch and a trail of empty ones —
// which matters because every batch costs a process start.
func spreadByID(files []StagedFile, multiplicity int) [][]StagedFile {
	if multiplicity <= 1 {
		return [][]StagedFile{files}
	}
	byID := map[string][]StagedFile{}
	order := make([]string, 0, len(files))
	for _, file := range files {
		id := ""
		if file.Meta != nil {
			id = file.Meta.TemplateID
		}
		if _, known := byID[id]; !known {
			order = append(order, id)
		}
		byID[id] = append(byID[id], file)
	}
	sort.SliceStable(order, func(i, j int) bool {
		left, right := len(byID[order[i]]), len(byID[order[j]])
		if left != right {
			return left > right
		}
		return order[i] < order[j]
	})
	batches := make([][]StagedFile, multiplicity)
	for _, id := range order {
		members := byID[id]
		for index, file := range members {
			batches[index%multiplicity] = append(batches[index%multiplicity], file)
		}
	}
	result := make([][]StagedFile, 0, multiplicity)
	for _, batch := range batches {
		if len(batch) > 0 {
			result = append(result, batch)
		}
	}
	return result
}

// materialiseBatch writes one batch's templates into their own directory, keeping
// the uploaded folder layout so a report path still points at the file that
// produced it.
//
// A ROOT THAT IS ITSELF THE SELECTION is left where it is, when this is the only
// batch. The operator named a folder and expects that folder after `-t`; with one
// invocation there is nothing to separate, so creating `batch-00001` inside it
// would name a copy of their folder instead and would leave the plan writing into
// the folder it was pointed at. The files are then already in place and are
// referenced rather than linked, so nothing is copied and nothing is written.
//
// A second batch must never do this: it needs its own directory, or the shared
// template-id this split exists for would load in one invocation again.
func materialiseBatch(root string, index int, key capabilityKey, capabilities []Capability, files []StagedFile, multiplicity int, keyByIdentity map[string]string) (NucleiBatch, error) {
	inPlace := index == 1 && multiplicity <= 1 && everyFileUnder(files, root)
	dir := root
	if !inPlace {
		dir = filepath.Join(root, batchDirName(index, key))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return NucleiBatch{}, fmt.Errorf("batch %d could not be created: %w", index, err)
		}
	}
	batch := NucleiBatch{
		Index:                     index,
		Dir:                       dir,
		InPlace:                   inPlace,
		Key:                       key,
		Capabilities:              capabilities,
		Files:                     make([]BatchFile, 0, len(files)),
		MaxTemplateIDMultiplicity: multiplicity,
	}
	for _, file := range files {
		relative := relativeStagePath(root, file.StagedPath)
		if relative == "" || relative == file.StagedPath {
			// A file outside the staging root still needs a place in the batch, and
			// the report path is what identifies it, so its uploaded name is used.
			relative = filepath.ToSlash(file.UploadName)
		}
		target := filepath.Join(dir, filepath.FromSlash(relative))
		if inPlace && target == file.StagedPath {
			// The file is already exactly where the batch wants it: linking it onto
			// itself would fail, and copying it would double a corpus for nothing.
			batch.Files = append(batch.Files, BatchFile{
				File: file, Path: target, Key: keyFor(keyByIdentity, file, 0),
			})
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return NucleiBatch{}, fmt.Errorf("batch %d could not stage %q: %w", index, relative, err)
		}
		if err := linkOrCopy(file.StagedPath, target); err != nil {
			return NucleiBatch{}, fmt.Errorf("batch %d could not stage %q: %w", index, relative, err)
		}
		batch.Files = append(batch.Files, BatchFile{
			File: file, Path: target, Key: keyFor(keyByIdentity, file, 0),
		})
	}
	return batch, nil
}

// everyFileUnder reports whether every file lives inside dir.
//
// It decides whether a batch may be left in place: a file from outside the root
// still has to be copied in, so the shortcut applies only when there is nothing to
// copy. `filepath.Rel` answering `..` is the shape that decides it, which is the
// same test `relativeStagePath` already uses.
func everyFileUnder(files []StagedFile, dir string) bool {
	if dir == "" || len(files) == 0 {
		return false
	}
	for _, file := range files {
		if file.StagedPath == "" {
			return false
		}
		relative, err := filepath.Rel(dir, file.StagedPath)
		if err != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// Planned returns how many files the plan will execute.
func (p *NucleiPlan) Planned() int {
	total := 0
	for _, batch := range p.Batches {
		total += len(batch.Files)
	}
	return total
}

// Describe renders the plan for the run statistics, so the operator sees why a
// large folder needs more than one invocation instead of watching it silently
// split.
func (p *NucleiPlan) Describe() map[string]interface{} {
	batches := make([]map[string]interface{}, 0, len(p.Batches))
	highest := 1
	for _, batch := range p.Batches {
		if batch.MaxTemplateIDMultiplicity > highest {
			highest = batch.MaxTemplateIDMultiplicity
		}
	}
	reason := "one invocation runs the whole selection"
	if highest > 1 {
		reason = fmt.Sprintf(
			"%d invocations are required because %d uploaded files declare the same template id, "+
				"and Nuclei loads exactly one file per template id",
			highest, highest)
	}
	for _, batch := range p.Batches {
		entry := map[string]interface{}{
			"index": batch.Index,
			"files": len(batch.Files),
		}
		if len(batch.Capabilities) > 0 {
			entry["capabilities"] = sortedCapabilityKeys(batch.Capabilities)
			entry["flags"] = capabilityFlagArgs(batch.Capabilities)
		}
		if batch.Key.needsReservedFlag() {
			entry["isolated"] = true
			entry["isolated_reason"] = fmt.Sprintf(
				"%s aborts an invocation that holds no such template, so it is run on its own",
				capabilityFlag[isolatedCapability])
		} else if batch.Key.runsAlone() {
			// A document isolated for its own missing deadline is NOT isolated
			// because of the reserved flag, and saying so here named a flag the
			// invocation does not carry. The reason an operator reads is the one
			// that decides the bound.
			entry["isolated"] = true
			entry["isolated_reason"] = fmt.Sprintf(
				"this document declares no deadline of its own, so it runs alone and its bound is "+
					"the isolated one (%ds) rather than the run's own; no flag is added for it",
				batchTimeoutSec(batch))
		}
		batches = append(batches, entry)
	}
	return map[string]interface{}{
		"batches":           len(p.Batches),
		"planned_files":     p.Planned(),
		"not_planned":       len(p.Invalid),
		"id_multiplicity":   highest,
		"invocation_reason": reason,
		"batch_detail":      batches,
		"deduplication":     summariseDuplicates(p.Dedup),
	}
}

// The `validation*` keys this used to publish are gone, and their absence is the
// point. Measured on a live `run-dir` after the `-validate` pass was removed, the
// report still carried:
//
//	validation_args        ['-duc','-nc','-validate','-t','/…/dns']
//	validation_diagnostics '<the scan's own banner and counters>'
//	validation             {'refused': 0}
//
// Two of those were lies: an operator reading `validation_args` would see a command
// this project no longer runs, and `validation_diagnostics` held output from the
// SCAN, which is what `stderr` already reports. A report field that describes a
// command nobody runs is worse than a missing field, so the keys were removed rather
// than left to answer zero. The refusal evidence is still in the run: a file the
// binary would not load produced no JSONL record, so it is reported `skipped` with
// the reason, and the binary's own `[ERR]` lines are in `stderr`.

// cleanPathForCompare normalises a path for map keys so a path written by the
// browser, by filepath.Rel or by nuclei itself resolves to one key.
func cleanPathForCompare(path string) string {
	return filepath.Clean(strings.TrimSpace(path))
}
