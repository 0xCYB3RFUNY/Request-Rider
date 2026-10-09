package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"net/url"
)

// sortedHeaderNames lists the header names a run sends, in a stable order.
//
// A name or a value that is only whitespace is skipped rather than emitted: the
// binary takes `header: value` as one string, and an empty one would be a flag
// that carries nothing and reads as a malformed invocation.
func sortedHeaderNames(headers map[string]string) []string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name, value := range headers {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NucleiOptions is the operator-facing set of advanced scan switches. Every
// field maps to exactly one Nuclei flag, so the browser never sends a raw
// command line: the flag set stays fixed and each value is validated here.
type NucleiOptions struct {
	ExcludeSeverity  []string `json:"exclude_severity"`
	ExcludeTags      []string `json:"exclude_tags"`
	IncludeTags      []string `json:"include_tags"`
	Types            []string `json:"types"`
	TemplateIDs      []string `json:"template_ids"`
	ExcludeTemplates []string `json:"exclude_templates"`
	ExcludeMatchers  []string `json:"exclude_matchers"`
	Concurrency      int      `json:"concurrency"`
	RateLimit        int      `json:"rate_limit"`
	// RateLimitDuration is the window `-rld` uses, in seconds. It is separate
	// from RateLimit because the two are separate flags: a run may send 5
	// requests per second, or 300 per minute, and only the second can be said
	// without picking a window. Zero leaves the binary's own default of 1s,
	// which is what `-rl` alone already implies.
	RateLimitDuration int    `json:"rate_limit_duration"`
	Retries           int    `json:"retries"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	MaxRedirects      int    `json:"max_redirects"`
	MaxHostErrors     int    `json:"max_host_errors"`
	FollowRedirects   bool   `json:"follow_redirects"`
	FollowHostRedirs  bool   `json:"follow_host_redirects"`
	DisableClustering bool   `json:"disable_clustering"`
	Headless          bool   `json:"headless"`
	Interactsh        *bool  `json:"interactsh"`
	InteractshURL     string `json:"interactsh_url"`
	InteractshToken   string `json:"interactsh_token"`
	StoreResponse     bool   `json:"store_response"`
	OmitRaw           *bool  `json:"omit_raw"`
	NoColor           bool   `json:"no_color"`
	// Debug adds `-debug`, which makes the binary print every request and every
	// response it sends. It is on the run's own diagnostics and nowhere else: the
	// captured stdout/stderr already go to the report, so this widens what a
	// single invocation shows rather than adding a second output path.
	Debug              bool `json:"debug"`
	MatcherStatus      bool `json:"matcher_status"`
	PayloadConcurrency int  `json:"payload_concurrency"`
	ProbeConcurrency   int  `json:"probe_concurrency"`
}

// validNucleiTypes are the template section names reported for local folder
// discovery. They are not passed to Nuclei as a protocol-type filter.
var validNucleiTypes = map[string]bool{
	"dns": true, "file": true, "http": true, "headless": true, "tcp": true,
	"workflow": true, "ssl": true, "websocket": true, "whois": true,
	"code": true, "javascript": true,
}

// HeaderFilePrefix names the files this package creates for `-H`.
//
// It is a prefix rather than a registry because a registry would be package-level mutable
// state shared by every concurrent batch, and `RunNucleiPlan` runs batches in parallel.
// `-race` found exactly that: every batch appending to and clearing one slice. So nothing
// is recorded globally; each batch recognises and removes its own file from its own
// argument vector.
const HeaderFilePrefix = "rr-nuclei-headers-"

// headerFilePaths returns the `-H` values in `args` that name a file this package wrote.
//
// MATCHED ON THE BASE NAME, NOT THE WHOLE VALUE. The value in argv is an absolute path, so
// matching the prefix against the full string never matches and both the redaction and the
// removal silently did nothing — the capture token stayed in the recorded vector and the
// 0600 file stayed in the temp directory. A silent no-op is what the three tests below
// caught, and it is why the base name is the thing compared.
func headerFilePaths(args []string) []string {
	var paths []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-H" {
			continue
		}
		if filepath.Base(args[i+1]) == "." || strings.HasPrefix(filepath.Base(args[i+1]), HeaderFilePrefix) {
			paths = append(paths, args[i+1])
		}
	}
	return paths
}

// removeNucleiHeaderFiles deletes the header files named by `args`.
//
// A leftover 0600 file holding a capture token is still a secret sitting in a temp
// directory for the rest of the process's life, and the token's whole purpose is to
// identify one run's traffic, so it must not outlive the run. Deleting from `args` rather
// than from a registry is what makes this safe under concurrent batches.
func removeNucleiHeaderFiles(args []string) {
	for _, path := range headerFilePaths(args) {
		_ = os.Remove(path)
	}
}

// writeNucleiHeaderFile writes the header set to a 0600 file in the system temp directory.
//
// 0600 from the moment of creation, not chmod-ed afterwards: between `CreateTemp` and a
// later `Chmod` the file exists at the process umask, which on a shared machine is a
// window in which another user can open it. The token would be readable for exactly as
// long as that window takes.
func writeNucleiHeaderFile(headers map[string]string) (string, error) {
	file, err := os.CreateTemp("", HeaderFilePrefix+"*.txt")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		_ = os.Remove(path)
		return "", err
	}
	// `name: value` per line, sorted, which is the literal form `-H` would have taken.
	for _, name := range sortedHeaderNames(headers) {
		if _, err := file.WriteString(name + ": " + headers[name] + "\n"); err != nil {
			file.Close()
			_ = os.Remove(path)
			return "", err
		}
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// HeaderFilePlaceholder is what the report shows in place of the header file's real name.
//
// The file name has to be unpredictable — a predictable path in a shared `/tmp` is a
// symlink race — but `stats["args"]` is kept verbatim so two runs of one template folder
// stay comparable, and a random name in argv makes every run differ. So the binary is
// handed the real path and the report records the placeholder.
const HeaderFilePlaceholder = "<capture-headers-file>"

// redactNucleiHeaderFiles returns the argument vector as the report should record it: the
// temp file's name replaced by `HeaderFilePlaceholder`.
//
// It also removes a second exposure the finding named: `stats["args"]` is streamed to the
// browser over SSE, so the recorded vector must not carry a path into a file that held the
// capture token while the run was in progress.
func redactNucleiHeaderFiles(args []string) []string {
	redacted := make([]string, len(args))
	copy(redacted, args)
	for _, path := range headerFilePaths(args) {
		for i, value := range redacted {
			if value == path {
				redacted[i] = HeaderFilePlaceholder
			}
		}
	}
	return redacted
}

// buildNucleiArgs renders the fixed flag set for one run. The target URL, the
// batch directory and the validated option values are the only variable parts;
// the binary is executed without a shell.
//
// The capability flags are derived from the documents in this batch, not from the
// run as a whole. Measured on nuclei v3.11.1, `-code`, `-file`, `-headless`,
// `-egm` and `-esc` each *widen* a run — they add a template kind and leave the
// default type set alone — so adding them for the documents that declare the
// matching section is safe. `-dast` is the exception and is never added here: it
// aborts an invocation that holds no fuzzing template, so the plan runs it in an
// invocation of its own. `-pt` is never added: it replaces Nuclei's default
// type set and can silently exclude uploaded files. The browser stages the
// complete uploaded tree; the engine validates the selected relative folder
// and gives that exact directory to Nuclei as the -t source.
//
// The header set is emitted in sorted order. A Go map iterates in a random
// order, so an unsorted walk would produce a different `-H` order on every run
// of the same templates — and `stats.args` is kept verbatim in the report, so
// two runs of one template folder would stop being comparable.
// buildNucleiArgs assembles one invocation for one batch directory.
//
// The two opening flags are load-bearing and both were arrived at by measurement.
//
// `-duc` keeps the run offline-deterministic: without it nuclei checks for a new
// version on every start, which turns a repeatable measurement into one that
// depends on the network.
//
// `-nc -v` in place of `-silent` is the second, and it is the more important of
// the two. `-silent` is not merely quiet: it removes the per-template
// diagnostics, and those are the only place the binary says *why* a template
// produced no record. Without `-v` the binary names only the *count*:
//
//	nuclei -silent  ->  [FTL] Could not run nuclei: no templates provided for scan
//	nuclei -nc      ->  [WRN] Found 2 templates with runtime error
//	                    (use -validate flag for further examination)
//	nuclei -nc -v   ->  [WRN] Could not parse template <path>: could not compile
//	                    request: cause="no valid engine found"
//	                    chain="[anonymous-sam-enumeration-enabled] engines
//	                    'powershell,powershell.exe' not available on host"
//
// Only the third carries the path and the cause. Both of those lines are what
// `binaryComplaintAbout` and `binaryPathComplaintAbout` read, so without them 103
// of the 98 636 rows in the corpus measurement fell back to "nuclei returned no
// record for template id …" with no cause at all — the very defect the
// reason-reading exists to remove, reintroduced by a quietness flag.
//
// `-v` cannot be combined with `-silent`: nuclei refuses the pair outright with
// `[FTL] Program exiting: both verbose and silent mode specified`. So the choice
// is not "verbose and silent" but "verbose or blind".
//
// What the quiet flags buy is a clean terminal, and nothing here needs one: both
// streams are captured into the run's diagnostics rather than inherited, so the
// banner and the live output never reach the operator's terminal either way. The
// price of reading the reasons, measured on a 50-file folder: 372 bytes of stderr
// with `-silent`, 1214 with `-nc`, 9915 with `-nc -v` — about 200 bytes per
// template, so roughly 40 KB for a full 200-file batch, and it is stored in
// `stats.stderr`, which the report already returns in full. The
// `-stats -stats-interval` lines that drive the progress display arrive in all
// three.
//
// Template records are not lost. Two runs of the same folder differ in *both*
// directions — some ids appear only with `-silent`, some only without — which is
// the folder's own timing sensitivity against a fixture rather than an effect of
// the flag: `-silent` 48 and 48, `-nc` 44 and 41.
//
// `-nc` rather than no colour flag at all, because the binary colours its output
// and the captured diagnostics are shown to the operator as plain text.
func buildNucleiArgs(target, dir string, request NucleiRequest) ([]string, error) {
	options := request.Options
	if err := options.validate(); err != nil {
		return nil, err
	}
	// -duc keeps the run offline-deterministic, -silent keeps the terminal
	// clean, -o receives the JSONL the report is parsed from.
	//
	// `-w <dir>` names the same directory as a workflow source as well. A
	// workflow is not a template: nuclei loads one through `-w` and refuses the
	// whole invocation through `-t` when nothing else in the directory is a
	// template, exiting 1 with "no templates provided for scan". Measured on
	// nuclei v3.11.1 against this corpus: a directory of the 207 workflow
	// templates reports exactly that with `-t`, and runs with `-w`; a directory
	// of 458 http templates gives an identical 330 matches either way, so naming
	// the directory twice costs a directory walk and changes nothing when there
	// are no workflows in it. Without it a folder that was parsed, staged,
	// planned and reported as eight files was a run that never executed one of
	// them.
	// `-esc` and `-nss` are passed on every invocation, not only on the batches
	// whose documents declare `self-contained: true`.
	//
	// The operator's rule (2026-10-05) is that `-t`, `-esc` and `-nss` are
	// mandatory for a template run, with the remaining capability flags added
	// for the templates that need them. `-t` was already unconditional here.
	// `-esc` was only reachable through `capabilityFlag[CapabilitySelfContained]`,
	// so a run of a folder with no self-contained document went out without it,
	// and any self-contained template the binary then loaded on its own was a
	// template this run had not declared.
	//
	// `-nss` is nuclei's `-no-strict-syntax`: "disable strict syntax check on
	// templates" (`nuclei -h` on v3.11.1). It was not passed at all, so the
	// binary's own strict check could refuse a document and drop it from the run
	// while the report still counted it as planned — the plan lists the file, the
	// run produces no row for it, and nothing in `stats` says why.
	//
	// `-as` was measured and deliberately left out: it rewrites template tags
	// from target technology detection, which changes *which* templates run
	// rather than whether they can.
	absoluteDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve template directory: %w", err)
	}
	args := []string{"-duc", "-nc", "-v", "-target", target, "-t", absoluteDir, "-w", absoluteDir, "-esc", "-nss"}
	if proxy := strings.TrimSpace(request.Proxy); proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	// `-it <dir>` re-admits everything the binary's own ignore list excluded.
	//
	// nuclei ships `~/.config/nuclei/.nuclei-ignore`, rewritten on every run
	// from nuclei-templates, and it carries 5 tags (`dos`, `local`, `fuzz`,
	// `bruteforce`, `txt-service`) and 14 file paths. Every template it names is
	// loaded, planned, staged and reported by this project, and then never
	// executed — the invocation answers `[FTL] Could not run nuclei: no
	// templates provided for scan` when a batch consists only of ignored files,
	// and for the rest returns a JSONL record per *other* template while the
	// ignored ones produce none. Measured on nuclei v3.11.1 against the
	// official corpus (13 764 files): 91 files came back `skipped` with the
	// reason "nuclei returned no record for template id …" even though
	// `-code -esc` had been passed for them.
	//
	// The ignore list is nuclei's own opinion about defaults, not the
	// operator's instruction to this tool. The operator uploaded those files and
	// asked for them to be checked, and this tool's contract already says every
	// file is reported with a real verdict. Whether a `dos` or a `local` template
	// is a good check is the operator's call, and it is answerable per template
	// through `-etags`, which still works alongside this.
	//
	// It is the flag that covers both halves at once. Measured on a directory of
	// one `dos` template, one `local` template and one file from the list of
	// 14: `-t . -w .` alone executed 0, `-itags dos,local` executed 3, `-it .`
	// executed 3 — so naming the directory is what re-admits the ignored files,
	// and it needs no per-tag list that would go stale the moment nuclei updates
	// its own.
	args = append(args, "-it", absoluteDir)
	// The correlation token travels as a header on every request — but as a FILE, not as
	// an argument value, and that is the whole point of this being a file.
	//
	// WHY. `-H "Name: token"` puts the token in the argv of the nuclei process, and argv
	// is world-readable on Linux: `ps -ef` shows it for as long as the scan runs, to every
	// user on the machine. It also landed in `stats["args"]`, which the engine streams to
	// the browser over SSE, so the token reached two places it had no reason to be.
	//
	// HOW IT STILL WORKS. nuclei's `-H` is declared with
	// `goflags.FileStringSliceOptions` (verified in
	// nuclei/v3@v3.11.1/cmd/nuclei/main.go:359), so a value that names an existing file
	// is read from that file instead of being treated as a literal header. The file is
	// created with 0600 and removed by `removeNucleiHeaderFile` once the run is over.
	//
	// SORTED, still. A Go map iterates in random order, and `stats.args` is kept verbatim
	// in the report, so an unsorted walk would make two runs of one template folder stop
	// being comparable.
	if len(request.Headers) > 0 {
		headerFile, err := writeNucleiHeaderFile(request.Headers)
		if err != nil {
			return nil, err
		}
		// From here the caller owns the file and removes it as soon as this function
		// returns. Anything that fails later must not leave it behind: there is no caller
		// to clean it up yet, and a 0600 file holding the capture token would sit in the
		// temp directory for the rest of the process's life with nobody left who knows it
		// exists.
		owned := true
		defer func() {
			if owned {
				_ = os.Remove(headerFile)
			}
		}()
		args = append(args, "-H", headerFile)
		owned = false
	}
	if values := dedupeLower(request.Tags); len(values) > 0 {
		args = append(args, "-tags", strings.Join(values, ","))
	}
	if values := dedupeLower(request.Severity); len(values) > 0 {
		args = append(args, "-severity", strings.Join(values, ","))
	}
	if values := dedupeLower(options.ExcludeSeverity); len(values) > 0 {
		args = append(args, "-es", strings.Join(values, ","))
	}
	if values := dedupeLower(options.ExcludeTags); len(values) > 0 {
		args = append(args, "-etags", strings.Join(values, ","))
	}
	if values := dedupeLower(options.IncludeTags); len(values) > 0 {
		args = append(args, "-itags", strings.Join(values, ","))
	}
	// Capability flags come from the documents in the batch, independent of
	// which folder the operator selected in the browser.
	args = append(args, isolatedFreeFlags(request.Protocols)...)
	// The isolated batch is the single place the reserved flag is safe: it
	// holds nothing but the documents that asked for it, so it cannot cancel
	// a neighbour the way it would on a shared invocation.
	if request.IsolatedProtocol != "" {
		args = append(args, capabilityFlag[request.IsolatedProtocol])
	}
	if values := dedupeStrings(options.TemplateIDs); len(values) > 0 {
		args = append(args, "-id", strings.Join(values, ","))
	}
	if values := dedupeStrings(options.ExcludeTemplates); len(values) > 0 {
		args = append(args, "-et", strings.Join(values, ","))
	}
	if values := dedupeStrings(options.ExcludeMatchers); len(values) > 0 {
		args = append(args, "-em", strings.Join(values, ","))
	}
	for _, item := range []struct {
		flag  string
		value int
	}{
		{"-c", options.Concurrency},
		{"-rl", options.RateLimit},
		{"-rld", options.RateLimitDuration},
		{"-retries", options.Retries},
		{"-timeout", options.TimeoutSeconds},
		{"-mr", options.MaxRedirects},
		{"-mhe", options.MaxHostErrors},
		{"-pc", options.PayloadConcurrency},
		{"-prc", options.ProbeConcurrency},
	} {
		if item.value > 0 {
			args = append(args, item.flag, strconv.Itoa(item.value))
		}
	}
	if options.FollowRedirects {
		args = append(args, "-fr")
	}
	if options.FollowHostRedirs {
		args = append(args, "-fhr")
	}
	if options.DisableClustering {
		args = append(args, "-dc")
	}
	if options.Headless {
		args = append(args, "-headless")
	}
	if options.Interactsh != nil && !*options.Interactsh {
		args = append(args, "-ni")
	}
	// `-iserver` is how a scan stops sending out-of-band callbacks to somebody
	// else's server.
	//
	// Measured on the corpus this project just accounted for: **596 of 98 636
	// templates carry `interactsh-url`** — they make the *target* call back to a
	// unique hostname, and nuclei answers by registering that hostname with an
	// OAST server. With no `-iserver` the binary defaults to a fixed list, and its
	// own help prints it: `oast.pro, oast.live, oast.site, oast.online, oast.fun,
	// oast.me`. So every one of those 596 checks reports a verdict, and every
	// one of them also reports to a third party, while this project's own
	// listener (`POST /api/oast`) never sees a byte of it.
	//
	// The engine cannot be the server for that: it is an OAST *client*
	// (`engine/oast.go`, `POST <provider>/register` then `GET <provider>/poll`),
	// not an implementation of the interactsh protocol nuclei speaks. So the
	// honest fix is not to invent a server here but to let the operator name the
	// one their infrastructure runs, which is a flag nuclei already has.
	//
	// Both values are validated rather than passed through, because a malformed
	// URL makes the binary exit 2 with `invalid interactsh server url`, and an
	// empty `-iserver` argument is worse than none: it would look configured and
	// silently fall back.
	if server := strings.TrimSpace(options.InteractshURL); server != "" {
		parsed, err := url.Parse(server)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("interactsh_url %q must be an absolute URL with a scheme and a host", server)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("interactsh_url scheme %q is not supported: use http or https", parsed.Scheme)
		}
		args = append(args, "-iserver", server)
		if token := strings.TrimSpace(options.InteractshToken); token != "" {
			args = append(args, "-itoken", token)
		}
	} else if token := strings.TrimSpace(options.InteractshToken); token != "" {
		return nil, fmt.Errorf("interactsh_token needs interactsh_url: the token is meaningless without a server to authenticate against")
	}
	// `-ni` excludes every OAST template, so a server named alongside it is
	// configured for a run that will never use it. The binary accepts the pair
	// and says nothing, which leaves the operator believing their infrastructure
	// is receiving callbacks while none can arrive.
	if options.Interactsh != nil && !*options.Interactsh && strings.TrimSpace(options.InteractshURL) != "" {
		return nil, fmt.Errorf(
			"interactsh is disabled while interactsh_url is set: `-ni` excludes every OAST template, " +
				"so the server would be configured for a run that can never reach it. Enable interactsh, " +
				"or clear interactsh_url.")
	}
	if options.StoreResponse {
		args = append(args, "-sresp")
	}
	if options.MatcherStatus {
		args = append(args, "-ms")
	}
	if options.NoColor {
		args = append(args, "-nc")
	}
	if options.Debug {
		args = append(args, "-debug")
	}
	omitRaw := true
	if options.OmitRaw != nil {
		omitRaw = *options.OmitRaw
	}
	if omitRaw {
		args = append(args, "-or")
	}
	// Environment defaults stay a fallback: an explicit option always wins, and
	// nothing is injected when neither is set.
	if options.RateLimit <= 0 {
		if rateLimit := nucleiRateLimit(); rateLimit > 0 {
			args = append(args, "-rl", strconv.Itoa(rateLimit))
		}
	}
	if options.TimeoutSeconds <= 0 {
		if execTimeout := nucleiExecTimeout(); execTimeout > 0 {
			args = append(args, "-timeout", strconv.Itoa(execTimeout/1000))
		} else if pauseSupported() {
			// A pausable run gets a request timeout that a pause cannot exhaust.
			//
			// Nuclei's `-timeout` is a wall-clock deadline on each input, armed
			// before the request goes out. Pausing suspends the process, so no
			// timer fires while it is stopped — but the deadline it was armed
			// with is still absolute, and it expires anyway. On resume every
			// request then fails at once with "got err while executing", which is
			// exactly what an operator sees when a pause is long enough: the
			// binary complaining and the run's error count climbing for no
			// reason at all. Measured against a real 12-template run held for
			// 60 s, the default produced 8 failed requests, and this value
			// produced none.
			//
			// What the value has to outlive is a **pause**, and a pause cannot
			// outlast the bound that stops the invocation — past that point the
			// run is over whether or not it is paused. So the request deadline
			// is clamped to that bound, and clamping is what makes the earlier
			// claim true.
			//
			// That claim used to be that a large value "does not slow a healthy
			// scan". Measured on v3.11.1 here, it did. And the cost lands on one
			// specific shape rather than on every template:
			//
			//	raw:/unsafe:   -timeout 1 → 4 s, 2 → 7 s, 3 → 10 s,
			//	               5 → 16 s, 8 → 25 s        (3 × the value, exact)
			//	plain http     -timeout 1 → 35 s, 5 → 33 s   (10 records, flat)
			//
			// So `-timeout` is not a deadline on the request: for a document that
			// speaks raw HTTP, nuclei waits the whole value on each of three
			// reads, and the document's price is three times whatever is written
			// here. A plain `http` document never notices the value at all.
			//
			// With this project's old 86 400-second default, a single `raw:`
			// document cost 72 hours of waiting and could only ever end as
			// "stopped at this project's 3600-second deadline" — the exact
			// sentence this repository had to be taught to say instead of "the
			// binary could not be executed". The clamp removes the unreachable
			// part. It does not make a raw document cheap, and it is not meant
			// to: that is a trade between pausing a run and finishing a batch,
			// and an operator settles it with the two knobs below.
			//
			//	RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS  pause-proof value, verbatim
			//	RR_NUCLEI_EXEC_TIMEOUT_MS           explicit request timeout
			//
			// The second is the one to reach for when a batch holds a `raw:`
			// document and the run has to finish: at 10 000 ms such a document
			// costs 30 s instead of 72 hours.
			//
			// WHAT CHANGED ON 2026-10-07, AND WHY.
			//
			// The value used to be derived from the run deadline even when nobody
			// asked for it: `bound = min(86400, deadlineSec)`, and the run deadline
			// is `RR_NUCLEI_TIMEOUT_SEC`, 3600 by default. So every run told the
			// binary "you may take an hour to read one input", and a folder holding
			// a single slow document could not finish. Measured on `http/cves`
			// (4356 documents) against the local vulnerable target, the same folder
			// and the same binary, differing only in this flag:
			//
			//	nuclei's own default (no -timeout)   exited, rc=0,  39 s, 4345 records, 137 matched
			//	-timeout 3600 (what we passed)      did not exit inside a 300 s cap
			//
			// The stack behind it is in the binary's own dump, taken with SIGQUIT at
			// the moment it stopped: the main goroutine sits in
			// `core.(*WorkPool).Wait` — `executeTemplateSpray` counts a document as
			// done when it is dispatched, so its own `percent 100` is not a finished
			// scan — while one worker reads a response body that never ends
			// (`net.(*conn).Read`, "IO wait, 1 minutes") and others wait in
			// `net/http.(*Transport).getConn` for a connection the stuck one holds.
			//
			// That is what an operator sees as "the scan reached 70 % and froze", and
			// it is also why History stayed empty: the job never reached a terminal
			// state, and `views.py` writes a tool's traffic on the terminal state
			// alone.
			//
			// So the run deadline stops being a per-read budget. It was always a
			// question about the whole run, and it is enforced in Go, by the context
			// the invocation is started with. A pause-proof value remains available
			// for the case it was written for — an operator who pauses a run — and
			// is now only passed when it is asked for by name.
			if seconds := pausableRequestTimeoutSeconds(request.deadlineSec); seconds > 0 {
				args = append(args, "-timeout", strconv.Itoa(seconds))
			}
		}
	}
	return args, nil
}

// isolatedFreeFlags renders the capability flags that are safe to add to an
// invocation. `-dast` is excluded on purpose: measured on v3.11.1 it makes the
// binary abort an invocation that holds no fuzzing template, with
// `[FTL] Could not run nuclei: no templates provided for scan` and exit 1, so
// adding it to a mixed batch would cancel every other template in that batch.
// The plan gives such a batch its own invocation instead.
//
// `-esc` is skipped for the same reason it is skipped from the argument list,
// not for the same reason: it is no longer conditional. `buildNucleiArgs` puts
// it on every invocation, so a self-contained batch that also emitted it here
// would carry the flag twice.
func isolatedFreeFlags(capabilities []Capability) []string {
	safe := make([]Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability == isolatedCapability || capability == CapabilitySelfContained {
			continue
		}
		safe = append(safe, capability)
	}
	return capabilityFlagArgs(safe)
}

// none and the run can be paused. Overridable for a site that needs a different
// bound; see nucleiPausableTimeoutSeconds.
// pausableRequestTimeoutSeconds is the per-request deadline a pausable run gets.
//
// The value exists so a pause cannot exhaust a request. It is therefore bounded
// by the deadline that actually stops the invocation: a pause cannot outlast
// that bound, and a request deadline above it is unreachable — the invocation
// ends first, so the request can only be reported as "stopped at the deadline".
//
// An operator's own value is taken verbatim, larger or not. The clamp applies to
// the default, not to a decision.
// pausableRequestTimeoutSeconds is the per-read budget to hand the binary, in
// seconds, or zero to hand it none at all.
//
// Zero is the answer for an operator who asked for nothing: nuclei then keeps its
// own default, which is what finishes a folder of ordinary documents — see the
// measurement in the call site. A non-zero answer comes from one of two names:
//
//   - `RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS`, written verbatim, for a run that is
//     paused: pausing suspends the process, so no timer fires while it is
//     stopped, but the deadline each request was armed with is absolute and
//     expires anyway. On resume every in-flight request then fails at once with
//     "got err while executing", which is what an operator sees when a pause ran
//     long enough. Measured against a real 12-template run held for 60 s, the
//     binary's own default produced 8 failed requests and this value produced
//     none.
//
//   - the run deadline, clamped, when that deadline was written down explicitly.
//     Past that point the invocation is over whether or not it is paused, so a
//     per-read budget above it can never be spent.
//
// The clamp used to be the *default*, and that is the defect this function now
// documents: it handed "an hour for the whole run" to "an hour for one read".
func pausableRequestTimeoutSeconds(deadlineSec int) int {
	if raw := strings.TrimSpace(os.Getenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return value
		}
	}
	// A deadline the operator wrote down is a request in its own right; a deadline
	// that is only a default is not, because a default is not a choice.
	written := optionalPositiveInt("RR_NUCLEI_TIMEOUT_SEC")
	if written <= 0 {
		return 0
	}
	// The batch deadline is the one that stops this invocation, so it is the
	// ceiling. With no batch yet, the written run bound is the only ceiling there
	// is.
	if deadlineSec <= 0 || deadlineSec > written {
		deadlineSec = written
	}
	bound := 86400
	if bound > deadlineSec {
		bound = deadlineSec
	}
	return bound
}

func (o NucleiOptions) validate() error {
	for _, level := range o.ExcludeSeverity {
		if !validSeverities[strings.ToLower(strings.TrimSpace(level))] {
			return fmt.Errorf("invalid exclude_severity %q", level)
		}
	}
	if len(dedupeLower(o.Types)) > 0 {
		return fmt.Errorf("options.types is no longer supported; select a template directory category")
	}
	for name, value := range map[string]int{
		"concurrency":         o.Concurrency,
		"rate_limit":          o.RateLimit,
		"retries":             o.Retries,
		"timeout_seconds":     o.TimeoutSeconds,
		"max_redirects":       o.MaxRedirects,
		"max_host_errors":     o.MaxHostErrors,
		"payload_concurrency": o.PayloadConcurrency,
		"probe_concurrency":   o.ProbeConcurrency,
	} {
		if value < 0 {
			return fmt.Errorf("%s must not be negative", name)
		}
	}
	return nil
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	return result
}
