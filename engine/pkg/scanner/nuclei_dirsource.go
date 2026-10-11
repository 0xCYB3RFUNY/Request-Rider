package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Template directory support.
//
// A folder of templates is the shape an operator actually has: the official
// corpus, a team folder, a checkout of someone's collection. Uploading it file
// by file is the wrong shape for that — the browser has to carry every byte
// before anything runs, and the run cannot start until the last chunk lands.
//
// So a directory is a first-class source. `StageTemplateDir` reads the folder
// in place and produces the same `[]StagedFile` the upload path produces,
// without copying anything: the plan hard-links each file into its own batch
// directory, so the corpus is written once, by the plan, and only for the
// batches that will actually run.
//
// Nothing here filters. Whatever is in the folder is what the run plans, and the
// plan is what splits it into the invocations that can execute it: a folder
// holding `headless:` documents is split so those documents get an invocation
// with `-headless`, instead of one invocation that nuclei refuses as a whole.

// TemplateFileNote is one document an inspection could not use.
type TemplateFileNote struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// TemplateDirReport is what a folder contains, read on request.
type TemplateDirReport struct {
	// Path is the folder that was inspected.
	Path string `json:"path"`
	// Total counts every template document found, usable or not.
	Total int `json:"total"`
	// Valid counts the documents that parsed.
	Valid int `json:"valid"`
	// Types are the protocol types present, which is what `-pt` accepts.
	Types []string `json:"types,omitempty"`
	// Capabilities are the extra flags the folder's documents need. They are
	// reported, not enforced: the plan adds them per invocation.
	Capabilities []string `json:"capabilities,omitempty"`
	// Invalid names each document that could not be used, with the reason.
	Invalid []TemplateFileNote `json:"invalid,omitempty"`
	// Error is set when the folder itself could not be read.
	Error string `json:"error,omitempty"`
}

// TemplateDirEntry is one folder offered to the operator as a template source.
//
// It carries a file COUNT and no per-document analysis. A dropdown is
// read the moment the panel opens, and the official corpus is 98 662 documents:
// walking it and counting names takes 301 ms, while parsing every document takes
// 134 s. A control that stalls for two minutes to fill a list is a broken
// control, so the listing stays cheap and the analysis happens when a folder is
// actually selected. Deciding whether a folder is a template folder at all is
// not that analysis: it reads the first line of one file per folder, which
// `countTemplateFiles` measures.
type TemplateDirEntry struct {
	// Path is the absolute directory the operator selects.
	Path string `json:"path"`
	// Name is the path relative to its corpus root, so `http/cves` reads as a
	// category rather than as an absolute path.
	Name string `json:"name"`
	// Root is the corpus the folder belongs to.
	Root string `json:"root"`
	// Files counts the template documents in this folder and below it.
	Files int `json:"files"`
}

// TemplateType is one value `-pt` accepts, offered to the operator as the
// template type to run.
type TemplateType struct {
	// Value is what is passed to `-pt`.
	Value string `json:"value"`
	// Label is the same value, kept as a separate field so a caller may present
	// it differently without parsing the flag value back out of a caption.
	Label string `json:"label"`
}

// templateTypeOrder is the binary's own `-pt` documentation, in the order the
// help prints it: dns, file, http, headless, tcp, workflow, ssl, websocket,
// whois, code, javascript.
//
// IT IS THE BINARY'S LIST, NOT A CURATED ONE. `-pt` is validated by nuclei and
// anything outside this set makes it exit 2 with "is not a valid extract type",
// so a shorter hand-picked list would only hide types the operator may want, and
// a longer one would offer values that cannot run. `validNucleiTypes` is the
// membership check the argument builder already uses, and this order is its
// documentation; a value in one and not the other is a bug in one of them, so
// the test asserts they agree.
var templateTypeOrder = []string{
	"dns", "file", "http", "headless", "tcp",
	"workflow", "ssl", "websocket", "whois",
	"code", "javascript",
}

// TemplateTypes returns the values `-pt` accepts, in the binary's own order.
//
// Nothing is discovered or filtered here: the set is fixed by the flag, so this
// is a constant list rather than a scan of whatever corpus happens to be
// installed. A corpus that contains no `ssl` document still offers `ssl`,
// because the flag accepts it and an operator may be pointing at a different
// corpus.
func TemplateTypes() []TemplateType {
	types := make([]TemplateType, 0, len(templateTypeOrder))
	for _, value := range templateTypeOrder {
		types = append(types, TemplateType{Value: value, Label: value})
	}
	return types
}

// templateDirRoots are the folders the picker offers, and they are named — never
// guessed.
//
// The operator's rule, 2026-10-06: pick a folder, and that folder's absolute path
// is what `-t` gets. A corpus this project does not know about is therefore
// something the operator points at, not something the engine goes looking for. The
// guesses this used to make — `~/.local/nuclei-templates`, `~/nuclei-templates`,
// `~/Desktop/`, `~/Downloads/`, `/usr/share/`, `/opt/` — are removed, because a
// folder appearing in the picker that the operator never asked for is a folder that
// can be picked by mistake, and the run of it is real traffic to a real target.
//
// `RR_NUCLEI_TEMPLATE_DIR` is a PATH LIST (`:`-separated) and its order is the
// order the picker offers and the order `ResolveTemplateDir` searches, so a name
// present in two roots resolves to the first.
//
// `RR_NUCLEI_TEMPLATES_DIR` is read as well, and it is not an alias by taste: it is
// the name `start.sh` and `run-engine.sh` exported since the feature landed, while
// the engine only ever read the singular form, so an operator who followed the
// documented name got a variable nothing consumed and a corpus that was silently
// invisible. Both resolve now.
// TemplateDirRoots is templateDirRoots, exported for the engine's startup sweep.
func TemplateDirRoots() []string { return templateDirRoots() }

func templateDirRoots() []string {
	roots := make([]string, 0, 8)
	for _, name := range []string{"RR_NUCLEI_TEMPLATE_DIR", "RR_NUCLEI_TEMPLATES_DIR"} {
		configured := strings.TrimSpace(os.Getenv(name))
		if configured == "" {
			continue
		}
		for _, part := range strings.Split(configured, string(os.PathListSeparator)) {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				roots = appendUniquePath(roots, trimmed)
			}
		}
	}
	return roots
}

func appendUniquePath(roots []string, candidate string) []string {
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return roots
	}
	for _, existing := range roots {
		if existing == absolute {
			return roots
		}
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return roots
	}
	return append(roots, absolute)
}

// ListTemplateDirs enumerates the template folders an operator can select.
//
// Every subdirectory holding at least one template document is offered, with the
// count of documents in it. A folder that holds `.yaml` files but no template is
// not offered: the corpus root carries `.github/`, `profiles/` and
// `helpers/payloads/`, and selecting one of them is a run that answers
// `[FTL] Could not run nuclei: no templates provided for scan`. See
// `countTemplateFiles` for what "holds a template" is measured by, and why the
// count itself still comes from names only.
//
// A name is offered once, by the first root that holds it. Two roots holding the
// same category is the normal case — the operator's own corpus and a clone of the
// official one both have `http` — and `ResolveTemplateDir` answers a relative name
// against the roots in this same order. Offering both would therefore put a row in
// the dropdown that cannot be selected: picking the second `http` would send the
// name and run the FIRST root's folder, while the row's file count belongs to the
// second. One row per name, from the root that wins, is what the run does.
func ListTemplateDirs() []TemplateDirEntry {
	roots := templateDirRoots()
	rootRank := make(map[string]int, len(roots))
	for index, root := range roots {
		if _, seen := rootRank[root]; !seen {
			rootRank[root] = index
		}
	}
	entries := make([]TemplateDirEntry, 0, 64)
	seen := make(map[string]bool, 64)
	seenName := make(map[string]bool, 64)
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				// A folder that cannot be read is skipped, not fatal: the corpus
				// root itself may hold files this process cannot open while the
				// folders below it are all readable.
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if !entry.IsDir() {
				return nil
			}
			files, holdsTemplate := countTemplateFiles(path)
			if files == 0 || !holdsTemplate {
				return nil
			}
			absolute, absErr := filepath.Abs(path)
			if absErr != nil || seen[absolute] {
				return nil
			}
			seen[absolute] = true
			name, relErr := filepath.Rel(root, absolute)
			if relErr != nil {
				name = filepath.Base(absolute)
			}
			name = filepath.ToSlash(name)
			if seenName[name] {
				return nil
			}
			seenName[name] = true
			entries = append(entries, TemplateDirEntry{
				Path:  absolute,
				Name:  name,
				Root:  root,
				Files: files,
			})
			return nil
		})
		_ = walkErr
	}
	// Roots in the order `templateDirRoots` gives them, which is the order
	// `ResolveTemplateDir` searches, and names alphabetically inside a root.
	sort.SliceStable(entries, func(i, j int) bool {
		if rootRank[entries[i].Root] != rootRank[entries[j].Root] {
			return rootRank[entries[i].Root] < rootRank[entries[j].Root]
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}

// countTemplateFiles counts the template documents in dir and below it, and
// reports whether any of them actually is one.
//
// The count is names only: it opens nothing. That is the difference between a
// dropdown that answers in 301 ms on the 98 662-document corpus and one that
// answers in 134 s, and a document that cannot be parsed is still counted — the
// run reports it as `invalid` with its reason, which is where that belongs.
//
// The second answer is what keeps a folder that holds no template out of the
// dropdown. A corpus root is not only templates: the official one carries
// `.github/ISSUE_TEMPLATE`, `.github/workflows`, `profiles/` and
// `helpers/payloads/`, and all four hold `.yaml` files, so name counting offers
// them and the operator picks a folder that answers
// `[FTL] Could not run nuclei: no templates provided for scan`. Measured on the
// official corpus: 878 folders hold a `.yaml`, 872 hold at least one that
// declares a top-level `id:`, and the 6 that do not are exactly
// `.github`, `.github/ISSUE_TEMPLATE`, `.github/workflows`, `profiles`,
// `helpers/payloads` and the corpus root.
//
// `id:` is used because it is the one key a nuclei template cannot compile
// without, and because reading it stops at the first line: one folder that holds
// templates costs one open and one short read, not a parse. Measured cost of
// qualifying all 878 folders: 0.1 s.
func countTemplateFiles(dir string) (count int, holdsTemplate bool) {
	walkErr := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !isTemplateFileName(entry.Name()) {
			return nil
		}
		count++
		if !holdsTemplate && documentDeclaresID(path) {
			holdsTemplate = true
		}
		return nil
	})
	_ = walkErr
	return count, holdsTemplate
}

// documentDeclaresID reports whether the document opens a top-level `id:` key.
//
// The key must start in the first column, because that is where nuclei requires
// it: an `id:` nested under `info:` or sitting inside a list is some other
// field, and a folder is not a template folder because it holds one. The line is
// read as it is and the scan returns at the first match, so for a real template
// the cost is the first line of the file. It deliberately does not parse: this
// runs on the dropdown path, and the question here is only "is this a template",
// not "what does it need" — the second question is asked by `InspectTemplateDir`,
// once, for the folder the operator actually selected.
func documentDeclaresID(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadString('\n')
		if strings.HasPrefix(line, "id:") {
			return true
		}
		if readErr != nil {
			// `io.EOF` and anything else both end the scan: a file that cannot be
			// read to the end holds no `id:` we can offer it on, and the count that
			// counts it is reported by the folder's own inspection with the reason.
			return false
		}
	}
}

// InspectTemplateDir reads a folder's documents and reports what they need, so
// the operator can see a category's contents before starting a run.
//
// It parses every document, so it is a call the operator asks for rather than a
// call a dropdown makes. The answers come from the same `TemplateMeta` the run
// itself uses, so the panel cannot describe a folder differently from the way it
// is executed.
func InspectTemplateDir(dir string) TemplateDirReport {
	resolved, err := ResolveTemplateDir(dir)
	if err != nil {
		return TemplateDirReport{Path: dir, Error: err.Error()}
	}
	report := TemplateDirReport{Path: resolved}
	typeSeen := make(map[string]bool, 8)
	capabilitySeen := make(map[string]bool, 8)
	walkErr := filepath.WalkDir(resolved, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !isTemplateFileName(entry.Name()) {
			return nil
		}
		relative, relErr := filepath.Rel(resolved, path)
		if relErr != nil {
			relative = entry.Name()
		}
		report.Total++
		meta, reason := readTemplateMeta(path)
		if reason != "" {
			report.Invalid = append(report.Invalid, TemplateFileNote{
				Path: filepath.ToSlash(relative), Reason: reason,
			})
			return nil
		}
		report.Valid++
		// A template with more than one block appears under each of them,
		// because that is what the folder actually contains.
		for _, key := range meta.BlockKeys {
			if lowered := strings.ToLower(strings.TrimSpace(key)); lowered != "" {
				typeSeen[lowered] = true
			}
		}
		for _, capability := range meta.Capabilities {
			if capability != "" {
				capabilitySeen[string(capability)] = true
			}
		}
		return nil
	})
	if walkErr != nil {
		report.Error = walkErr.Error()
		return report
	}
	report.Types = sortedFlagKeys(typeSeen)
	report.Capabilities = sortedFlagKeys(capabilitySeen)
	return report
}

// sortedFlagKeys returns the seen flags in a stable order, so a listing built
// from a map walk reads the same on every call. It is distinct from the
// package's own `sortedKeys`, which unwraps a `map[string][]string`.
func sortedFlagKeys(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func isTemplateFileName(name string) bool {
	lowered := strings.ToLower(name)
	return strings.HasSuffix(lowered, ".yaml") || strings.HasSuffix(lowered, ".yml")
}

// readTemplateMeta reads one document from disk and parses it. The content is
// released as soon as the parse returns, so a corpus walk holds one document.
func readTemplateMeta(path string) (*TemplateMeta, string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, "template could not be read"
	}
	if len(content) == 0 {
		return nil, "file is empty"
	}
	if len(content) > maxTemplateBytes() {
		return nil, fmt.Sprintf("template exceeds the %d-byte limit (TEMPLATE_TOO_LARGE)", maxTemplateBytes())
	}
	return parseTemplateDocumentWithPath(string(content), filepath.Base(path))
}

// ResolveTemplateDir turns what the operator selected into an absolute
// directory that exists.
//
// A selection may be an absolute path, a path relative to one of the known
// corpus roots (which is what the dropdown offers, `http/cves`), or the name of
// one of those roots. Nothing is filtered by name or by location: the operator
// may name any directory this process can read.
func ResolveTemplateDir(selection string) (string, error) {
	trimmed := strings.TrimSpace(selection)
	if trimmed == "" {
		return "", fmt.Errorf("a template directory is required")
	}
	if absolute, err := filepath.Abs(trimmed); err == nil {
		if info, statErr := os.Stat(absolute); statErr == nil && info.IsDir() {
			return absolute, nil
		}
	}
	roots := templateDirRoots()
	for _, root := range roots {
		candidate := filepath.Join(root, filepath.FromSlash(trimmed))
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("template directory %q was not found", trimmed)
}

// stageTemplateDirInto mirrors a template directory into root and returns the
// staged set the upload path returns.
//
// WHY A MIRROR AND NOT THE ORIGINAL PATHS. The plan turns each staged file into a
// path inside a batch directory with `filepath.Rel(root, stagedPath)`. Given a
// file outside root, `filepath.Rel` succeeds and answers with a `../..` chain —
// so pointing `StagedPath` straight at the corpus would make every batch write
// its templates back into the corpus, or above it. Mirroring keeps every staged
// path inside the root the caller owns, which is also what makes the plan's own
// cleanup sufficient: the run removes the mirror and nothing else is touched.
//
// The mirror is hard links, so a 6.5 GB corpus costs one directory entry per
// file rather than a second copy of every byte. `linkOrCopy` falls back to a
// byte copy where the filesystem does not allow a link.
func stageTemplateDirInto(root, dir string) ([]StagedFile, error) {
	// A template may name a helper file by a path relative to the CORPUS ROOT,
	// not to itself: `ids: helpers/wordlists/numbers.txt` is how the official
	// corpus spells it, and it appears in templates that live in `http/cves/`.
	// nuclei resolves such a path against the directory it was given, so a
	// mirror holding only the selected folder makes the binary answer
	// "access to helper file … denied" and refuse the file.
	//
	// Measured on `http/cves` (4 320 documents): without this, 6 documents are
	// reported `invalid` for exactly that reason while their helper file sits
	// unread a few directories up. The helpers are mirrored too, under the same
	// relative path, so the reference resolves. Only the documents are reported
	// as run rows — a helper is not a template and is never planned as one.
	corpusRoot := templateCorpusRoot(dir)
	// The helper tree is mirrored first and then skipped by the document walk,
	// so a wordlist is present for the binary to read without ever becoming a
	// report row: a row per helper would claim the folder held documents it does
	// not hold.
	skipRelative := ""
	if corpusRoot != dir {
		if relative, err := filepath.Rel(corpusRoot, dir); err == nil {
			skipRelative = relative
		}
	}
	// The count is not reported here: it is a staging detail, and a report that
	// mentioned it would invite the reader to look for it in the results.
	_ = mirrorTemplateHelpers(corpusRoot, root)
	staged := make([]StagedFile, 0, 256)
	walkErr := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			// A nested `helpers/` is corpus material, not a runnable selection.
			if entry.Name() == "helpers" && skipRelative != "" && entry.Name() != filepath.Base(dir) {
				if relative, relErr := filepath.Rel(dir, path); relErr == nil && relative != "." {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !isTemplateFileName(entry.Name()) {
			return nil
		}
		relative, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			relative = entry.Name()
		}
		// A corpus is operator-supplied input, so a name that tries to climb out
		// is refused rather than joined into the root. `safeRelativePath` is the
		// same check the upload path applies.
		if _, pathErr := safeRelativePath(filepath.ToSlash(relative)); pathErr != nil {
			staged = append(staged, StagedFile{
				UploadName:   entry.Name(),
				RelativePath: filepath.ToSlash(relative),
				Reason:       pathErr.Error(),
			})
			return nil
		}
		report := filepath.ToSlash(relative)
		meta, reason := readTemplateMeta(path)
		if reason != "" {
			staged = append(staged, StagedFile{UploadName: entry.Name(), RelativePath: report, Reason: reason})
			return nil
		}
		target := filepath.Join(root, filepath.FromSlash(report))
		if mkErr := os.MkdirAll(filepath.Dir(target), 0o700); mkErr != nil {
			return mkErr
		}
		if linkErr := linkOrCopy(path, target); linkErr != nil {
			return linkErr
		}
		staged = append(staged, StagedFile{
			UploadName:   entry.Name(),
			StagedPath:   target,
			RelativePath: report,
			Meta:         meta,
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if len(staged) == 0 {
		return nil, fmt.Errorf("no template documents found in %q", dir)
	}
	sort.Slice(staged, func(i, j int) bool {
		return staged[i].RelativePath < staged[j].RelativePath
	})
	return staged, nil
}

// templateCorpusRoot returns the corpus a selected folder belongs to.
//
// The answer is the folder itself when it is not inside a known corpus, because
// a folder the operator pointed at directly is its own root and a helper path in
// it is relative to it.
// templateCorpusRoot returns the corpus a selected folder belongs to.
//
// A known corpus answers by path. An unknown one answers by shape: nuclei
// resolves a helper path against the root it was handed, so a folder that has a
// sibling `helpers/` tree has a parent that IS the corpus root, whatever that
// parent is called. Without that, a corpus this installation does not know about
// is treated as its own root, no helper is mirrored, and every document naming a
// helper is refused.
func templateCorpusRoot(dir string) string {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	for _, root := range templateDirRoots() {
		if relative, relErr := filepath.Rel(root, absolute); relErr == nil &&
			relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return root
		}
	}
	// Shape: climb while the parent holds a `helpers/` tree and this folder does
	// not look like one itself. Bounded by the filesystem root, and a corpus with
	// no helpers simply keeps its own folder as the root.
	parent := filepath.Dir(absolute)
	for depth := 0; parent != "" && parent != "/" && depth < 8; depth++ {
		if info, statErr := os.Stat(filepath.Join(parent, "helpers")); statErr == nil && info.IsDir() {
			return parent
		}
		parent = filepath.Dir(parent)
	}
	return absolute
}

// mirrorTemplateHelpers copies the corpus's `helpers/` tree into the mirror at the
// same relative path, so a template that names a helper by its corpus-relative
// path finds it.
//
// It walks only the helper files, never parsing them: nuclei reads them itself,
// and they are payloads and wordlists rather than templates. A helper that cannot
// be linked is skipped rather than fatal, because one missing wordlist must not
// cost the operator the whole folder run.
func mirrorTemplateHelpers(corpusRoot, root string) int {
	if corpusRoot == "" {
		return 0
	}
	source := filepath.Join(corpusRoot, "helpers")
	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return 0
	}
	mirrored := 0
	walkErr := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(corpusRoot, path)
		if relErr != nil {
			return nil
		}
		target := filepath.Join(root, relative)
		if mkErr := os.MkdirAll(filepath.Dir(target), 0o700); mkErr != nil {
			return nil
		}
		if linkErr := linkOrCopy(path, target); linkErr != nil {
			return nil
		}
		mirrored++
		return nil
	})
	_ = walkErr
	return mirrored
}

// RunNucleiTemplateDir runs every template document in a directory.
//
// It is `RunNucleiDir` with the folder read from disk instead of from an upload
// session: the plan still validates, deduplicates, and splits the folder into the
// invocations that can execute it, so a folder holding `headless:` or `code:`
// documents runs those documents in an invocation that has their flag rather
// than in one the binary refuses as a whole.
//
// Measured on v3.11.1: a folder of eleven `http/cves` documents that include a
// `headless:`-only and a `code:`+`http:` template answers `rc=1, 0 loaded` when
// the invocation carries no flag for them, so pointing `-t` at a mixed folder
// without splitting it runs nothing at all.
//
// WHAT THE OPERATOR SEES IN `-t`. The operator named a folder and expects that
// folder's absolute path after `-t`, and on most folders that is exactly what the
// binary receives. A folder whose documents all fit ONE invocation is passed by
// its own absolute path — no mirror, no batch directory, no `.rr-nuclei-mirror-*`
// — because there is nothing to split and the binary reads the operator's files
// where they are. Measured on this corpus: `cloud/aws/sqs`, `dns`, `ssl`,
// `http/cves/2025` and `javascript` each plan to a single invocation.
//
// A folder that DOES need more than one invocation keeps the mirror, and the run
// says so: nuclei loads one file per `template-id`, so two documents sharing an id
// in one invocation means the second silently never runs (measured on v3.11.1 for
// `-t a -t b`, `-t a,b` and `-id`). 76 731 ids in this corpus carry more than one
// document, so the mirror is not a detail that can be dropped — it is what makes
// "every template ran" true. `source` names the folder for the single-invocation
// case and the mirror for the split one, and it is reported in `stats`.
func RunNucleiTemplateDir(ctx context.Context, dir string, request NucleiRequest) (NucleiRun, error) {
	resolved, err := ResolveTemplateDir(dir)
	if err != nil {
		return NucleiRun{}, err
	}
	// The plan is built first so the run can tell whether it needs to mirror at
	// all. A mirror is paid for on every folder, and it is only needed to give a
	// split run a directory of its own per invocation.
	staged, err := stageTemplateDirForRun(resolved)
	if err != nil {
		return NucleiRun{}, err
	}
	if plan, planErr := BuildPlan(PlanRequest{Dir: resolved, Staged: staged}); planErr == nil &&
		len(plan.Batches) == 1 {
		// One invocation: the operator's folder IS the batch directory, so `-t`
		// names the folder they chose and nothing is copied.
		run, runErr := RunNucleiDir(ctx, resolved, staged, request)
		recordSourceDir(&run, resolved)
		return run, runErr
	}
	root, cleanup, err := templateMirrorRoot(resolved)
	if err != nil {
		return NucleiRun{}, err
	}
	defer cleanup()
	mirrored, err := stageTemplateDirInto(root, resolved)
	if err != nil {
		return NucleiRun{}, err
	}
	run, err := RunNucleiDir(ctx, root, mirrored, request)
	recordSourceDir(&run, resolved)
	return run, err
}

// recordSourceDir names the folder the operator chose, next to the invocation the
// binary actually ran.
//
// Without it a run of one folder is indistinguishable from a run of its mirror:
// `stats.args` shows `.rr-nuclei-mirror-*/batch-00001-…`, and an operator reading
// the diagnostics cannot tell whether the mirror was necessary. It also carries the
// split, so the reason the mirror exists is visible in the run rather than in a
// commit message.
func recordSourceDir(run *NucleiRun, resolved string) {
	if run == nil || resolved == "" {
		return
	}
	if run.Stats == nil {
		run.Stats = map[string]interface{}{}
	}
	run.Stats["source_dir"] = resolved
}

// stageTemplateDirForRun reads a folder in place for the single-invocation path:
// the staged files are the operator's own files, so the binary is pointed at them
// rather than at a copy. `StagedPath` stays absolute, which is what lets the plan
// name the real file in a report row.
func stageTemplateDirForRun(dir string) ([]StagedFile, error) {
	corpusRoot := templateCorpusRoot(dir)
	skipRelative := ""
	if corpusRoot != dir {
		if relative, err := filepath.Rel(corpusRoot, dir); err == nil {
			skipRelative = relative
		}
	}
	staged := make([]StagedFile, 0, 256)
	walkErr := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if entry.Name() == "helpers" && skipRelative != "" && entry.Name() != filepath.Base(dir) {
				if relative, relErr := filepath.Rel(dir, path); relErr == nil && relative != "." {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !isTemplateFileName(entry.Name()) {
			return nil
		}
		relative, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			relative = entry.Name()
		}
		report := filepath.ToSlash(relative)
		// The document is read, not copied: the binary is pointed at the operator's
		// own file. The parse still happens here because the plan needs `Meta` to
		// split by capability and to report an unusable document with its reason —
		// and because a run that reported a template it never read would be a lie.
		meta, reason := readTemplateMeta(path)
		if reason != "" {
			staged = append(staged, StagedFile{UploadName: report, RelativePath: report, Reason: reason})
			return nil
		}
		staged = append(staged, StagedFile{
			StagedPath:   path,
			RelativePath: report,
			UploadName:   report,
			Meta:         meta,
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if len(staged) == 0 {
		return nil, fmt.Errorf("no template documents found in %q", dir)
	}
	sort.Slice(staged, func(i, j int) bool { return staged[i].RelativePath < staged[j].RelativePath })
	return staged, nil
}

// templateMirrorRoot creates the directory a run mirrors its templates into.
//
// IT IS A SIBLING OF THE CORPUS, NOT A CHILD OF IT, and that placement is the
// whole reason. Two properties depend on it:
//
//   - The mirror must share a filesystem with the corpus so `os.Link` succeeds
//     and the mirror costs one directory entry per file instead of a second copy
//     of every byte. Measured on this machine: the corpus sits on device 2049
//     and `/tmp` on device 38, so a mirror under `/tmp` fails every link with
//     "Invalid cross-device link" and silently degrades to byte-copying 906 MB
//     on every run.
//   - A run must never write inside the folder it was pointed at. A child of the
//     corpus would also be walked by the next run and mirrored into itself.
//
// A corpus root whose parent cannot hold a directory (no write permission, or no
// parent at all) falls back to the system temp directory and pays the copy,
// because a scan that cannot stage its templates cannot run at all.
// templateMirrorPrefix names every folder this engine stages into. The name is
// hidden and corpus-prefixed so a directory listing of the parent shows where it
// came from and it is not mistaken for content — and so the startup sweep below
// recognises its own leftovers without matching a user's directory by accident.
const templateMirrorPrefix = ".rr-nuclei-mirror-"

// templateMirrorLive is the set of mirrors this process is currently using.
//
// It exists because a mirror cannot be recognised as stale by age alone: a scan
// of a large collection legitimately runs for tens of minutes. A sweep that only
// asked "is this old?" would eventually delete the staging of a job that is still
// running. Naming the live ones makes the sweep exact instead of hopeful.
var templateMirrorLive = struct {
	mutex sync.Mutex
	paths map[string]struct{}
}{paths: map[string]struct{}{}}

func markTemplateMirrorLive(path string) {
	templateMirrorLive.mutex.Lock()
	defer templateMirrorLive.mutex.Unlock()
	templateMirrorLive.paths[path] = struct{}{}
}

func releaseTemplateMirror(path string) {
	templateMirrorLive.mutex.Lock()
	delete(templateMirrorLive.paths, path)
	templateMirrorLive.mutex.Unlock()
	os.RemoveAll(path)
}

func templateMirrorIsLive(path string) bool {
	templateMirrorLive.mutex.Lock()
	defer templateMirrorLive.mutex.Unlock()
	_, live := templateMirrorLive.paths[path]
	return live
}

// SweepStaleTemplateMirrors removes mirrors this engine left behind, and returns
// how many it removed.
//
// MEASURED 2026-10-10. A scan of `nuclei-templates/http/misconfiguration` left
// `nuclei-templates/http/.rr-nuclei-mirror-580477302` — 986 staged copies of
// templates — sitting inside the corpus. Cancelling the job does not leave one;
// that was reproduced and it cleans up correctly. Killing the engine while a job
// is staged does, and that is what an operator does when restarting the stack
// mid-scan.
//
// The cost is not the disk. A mirror is created in the scanned folder's PARENT —
// putting it outside would make a scan of the corpus root mirror the corpus into
// itself — so the leftover lands inside the tree the next scan walks, and those
// 986 templates are then loaded a second time. The baseline run that measured
// this reported 10 062 executed templates with 986 of them duplicated.
//
// It therefore walks the corpus rather than looking only beside its root: the
// folder an operator scans is `http/misconfiguration` as often as it is the root,
// and its leftover sits in `http/`. A mirror this process is using is never
// touched, so a running job keeps its staging whatever its age, and the walk does
// not descend into a mirror it has just removed.
func SweepStaleTemplateMirrors(corpus string) int {
	resolved, err := ResolveTemplateDir(corpus)
	if err != nil {
		return 0
	}
	removed := 0
	// A mirror of the corpus root itself sits beside it, not inside it.
	if parent := filepath.Dir(resolved); parent != "" && parent != resolved {
		removed += sweepTemplateMirrorEntries(parent)
	}
	// And mirrors of any folder inside it sit inside it.
	removed += sweepTemplateMirrorTree(resolved, 0)
	return removed
}

func sweepTemplateMirrorTree(root string, depth int) int {
	// A collection is walked once; this bounds the sweep if a corpus turns out to
	// contain a directory cycle through a link.
	if depth > 32 {
		return 0
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), templateMirrorPrefix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if templateMirrorIsLive(path) {
			continue
		}
		if err := os.RemoveAll(path); err == nil {
			removed++
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), templateMirrorPrefix) {
			continue
		}
		removed += sweepTemplateMirrorTree(filepath.Join(root, entry.Name()), depth+1)
	}
	return removed
}

func sweepTemplateMirrorEntries(parent string) int {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), templateMirrorPrefix) {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		if templateMirrorIsLive(path) {
			continue
		}
		if err := os.RemoveAll(path); err == nil {
			removed++
		}
	}
	return removed
}

func templateMirrorRoot(corpus string) (string, func(), error) {
	parent := filepath.Dir(corpus)
	if parent != "" && parent != corpus {
		if root, err := os.MkdirTemp(parent, templateMirrorPrefix+"*"); err == nil {
			markTemplateMirrorLive(root)
			return root, func() { releaseTemplateMirror(root) }, nil
		}
	}
	root, err := os.MkdirTemp("", templateMirrorPrefix+"*")
	if err != nil {
		return "", nil, err
	}
	markTemplateMirrorLive(root)
	return root, func() { releaseTemplateMirror(root) }, nil
}
