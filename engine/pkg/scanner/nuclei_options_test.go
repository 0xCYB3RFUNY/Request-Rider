package scanner

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func hasArg(args []string, flag string) bool {
	return slices.Contains(args, flag)
}

func TestBuildNucleiArgsUsesAbsoluteTemplateDirectory(t *testing.T) {
	relative := filepath.Join("templates", "code")
	absolute, err := filepath.Abs(relative)
	if err != nil {
		t.Fatalf("resolve expected path: %v", err)
	}
	args, err := buildNucleiArgs("http://target.test/", relative, NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if got := argValue(t, args, "-t"); got != absolute {
		t.Fatalf("-t = %q, want absolute path %q: %v", got, absolute, args)
	}
	if got := argValue(t, args, "-target"); got != "http://target.test/" {
		t.Fatalf("-target = %q: %v", got, args)
	}
	if hasArg(args, "-u") || hasArg(args, "-pt") {
		t.Fatalf("legacy flag in argv: %v", args)
	}
}

func argValue(t *testing.T, args []string, flag string) string {
	t.Helper()
	index := slices.Index(args, flag)
	if index < 0 || index+1 >= len(args) {
		t.Fatalf("flag %q is missing from %v", flag, args)
	}
	return args[index+1]
}

func TestBuildNucleiArgsMapsEveryOptionToOneFlag(t *testing.T) {
	omitRaw := false
	interactsh := false
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Proxy: "socks5://127.0.0.1:9050",
		Tags:  []string{"cve", "CVE"},
		Options: NucleiOptions{
			ExcludeSeverity:    []string{"info"},
			ExcludeTags:        []string{"fuzz"},
			IncludeTags:        []string{"headless"},
			TemplateIDs:        []string{"CVE-2021-44228", " log4j* "},
			ExcludeTemplates:   []string{"helpers/"},
			ExcludeMatchers:    []string{"fuzzy"},
			Concurrency:        40,
			PayloadConcurrency: 10,
			ProbeConcurrency:   20,
			RateLimit:          30,
			Retries:            2,
			TimeoutSeconds:     7,
			MaxRedirects:       3,
			MaxHostErrors:      5,
			FollowRedirects:    true,
			FollowHostRedirs:   true,
			Headless:           true,
			Interactsh:         &interactsh,
			StoreResponse:      true,
			OmitRaw:            &omitRaw,
			NoColor:            true,
			MatcherStatus:      true,
		},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	for flag, want := range map[string]string{
		"-target":  "http://target.test/",
		"-t":       "/tmp/staged",
		"-proxy":   "socks5://127.0.0.1:9050",
		"-tags":    "cve",
		"-es":      "info",
		"-etags":   "fuzz",
		"-itags":   "headless",
		"-id":      "CVE-2021-44228,log4j*",
		"-et":      "helpers/",
		"-em":      "fuzzy",
		"-c":       "40",
		"-pc":      "10",
		"-prc":     "20",
		"-rl":      "30",
		"-retries": "2",
		"-timeout": "7",
		"-mr":      "3",
		"-mhe":     "5",
	} {
		if got := argValue(t, args, flag); got != want {
			t.Fatalf("%s = %q, want %q (%v)", flag, got, want, args)
		}
	}
	for _, flag := range []string{"-fr", "-fhr", "-headless", "-ni", "-sresp", "-nc", "-ms"} {
		if !hasArg(args, flag) {
			t.Fatalf("%s is missing from %v", flag, args)
		}
	}
	if hasArg(args, "-or") {
		t.Fatalf("omit_raw=false must not add -or: %v", args)
	}
	// `-nc -v` replaces `-silent`, and this test is what says so. An untouched
	// options panel must still produce a run whose stderr carries the
	// per-template diagnostics, because those are the only place the binary says
	// why a template produced no record. Measured on v3.11.1: with `-silent`
	// those lines are absent and 103 of 98 636 corpus rows fall back to "nuclei
	// returned no record for template id …" with no cause; without `-v` the
	// binary prints only "[WRN] Found 2 templates with runtime error" and still
	// names no file. The streams are captured rather than inherited, so the
	// banner and the verbosity cost nothing visible.
	if !hasArg(args, "-duc") || !hasArg(args, "-nc") || !hasArg(args, "-v") {
		t.Fatalf("the fixed flag set changed: %v", args)
	}
	// nuclei refuses this pair outright, so `-silent` cannot be reintroduced as
	// "quiet plus verbose".
	if hasArg(args, "-silent") {
		t.Fatalf("-silent removes the diagnostics the reasons are read from: %v", args)
	}
	// No OAST server is named on the operator's behalf. 596 of the 98 636
	// templates in the corpus send the target to a unique hostname, and without
	// `-iserver` the binary answers with its own list — `oast.pro, oast.live,
	// oast.site, oast.online, oast.fun, oast.me`, printed by the binary's own
	// `-h`. Picking one here would be this tool choosing where a stranger's
	// target reports, which is not a default this project may set.
	if hasArg(args, "-iserver") {
		t.Fatalf("an untouched panel named an OAST server: %v", args)
	}
}

func TestBuildNucleiArgsDefaultsAreConservative(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(args, "-u") || hasArg(args, "-pt") {
		t.Fatalf("run used a legacy target or protocol-type flag: %v", args)
	}
	if !hasArg(args, "-or") {
		t.Fatalf("omit_raw must default to true: %v", args)
	}
	if hasArg(args, "-ni") {
		t.Fatalf("interactsh must stay enabled unless explicitly disabled: %v", args)
	}
	// An untouched options panel must not add any optional switch — including
	// `-timeout`. It used to have exactly one exception, and that exception is what
	// froze the scanner: a run can be paused with SIGSTOP, so the value was made
	// large enough that no pause could exhaust it, and the only value large enough
	// was the run's own deadline. The binary then had permission to spend an hour
	// reading one input, and a folder with one slow document never finished — see
	// `TestTheRunDeadlineIsNotHandedToTheBinaryAsAReadBudget` for the measurement.
	// An operator who pauses and wants the old behaviour asks for it by name:
	// `RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS`.
	// `-nc` and `-v` are deliberately absent from this list: they are part of the
	// base invocation, not something an options panel adds, and the fixed-set
	// assertion in TestBuildNucleiArgsMapsEveryOptionToOneFlag is what holds them.
	for _, flag := range []string{"-c", "-rl", "-retries", "-mr", "-mhe", "-pc", "-prc", "-fr", "-fhr", "-headless", "-sresp", "-ms", "-es", "-etags", "-itags", "-pt", "-id", "-et", "-em", "-timeout"} {
		if hasArg(args, flag) {
			t.Fatalf("empty options added %s: %v", flag, args)
		}
	}
	// The pause-proof value is still there, it is simply asked for. Asserted
	// through the helper rather than as a literal so the two cannot drift apart.
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "7200")
	paused, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args with an asked-for pause-proof value: %v", err)
	}
	if value := argValue(t, paused, "-timeout"); value != strconv.Itoa(pausableRequestTimeoutSeconds(0)) {
		t.Fatalf("asked-for request timeout = %q, want %d: %v",
			value, pausableRequestTimeoutSeconds(0), paused)
	}
}

// The binary's own ignore list must not silently drop the operator's files.
//
// nuclei ships `~/.config/nuclei/.nuclei-ignore`, rewritten on every run from
// nuclei-templates, carrying 5 tags (`dos`, `local`, `fuzz`, `bruteforce`,
// `txt-service`) and 14 file paths. Every file it names is planned, staged and
// reported by this project, and then never executed: measured on v3.11.1 over
// the official corpus, 91 of 13 764 files came back `skipped` with "nuclei
// returned no record for template id …" despite `-code -esc` being passed for
// them, and a batch made only of ignored files answers `[FTL] Could not run
// nuclei: no templates provided for scan`.
//
// The flag is asserted on the staged directory rather than on a constant,
// because naming a *different* directory would satisfy this test while
// re-admitting nothing — which is exactly the failure it exists to prevent.
func TestBuildNucleiArgsReAdmitsTheBinariesOwnIgnoredFiles(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if !hasArg(args, "-it") {
		t.Fatalf("nuclei's .nuclei-ignore excludes the operator's files and nothing re-admits them: %v", args)
	}
	if value := argValue(t, args, "-it"); value != "/tmp/staged" {
		t.Fatalf("-it = %q, want the staged directory the run loads from: %v", value, args)
	}
}

// The re-admission must not become a way to widen a narrowed run: an explicit
// exclusion still wins, because that is the operator's own instruction rather
// than nuclei's default.
func TestBuildNucleiArgsKeepsExclusionsAlongsideReAdmission(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{ExcludeTags: []string{"fuzz"}},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if value := argValue(t, args, "-etags"); value != "fuzz" {
		t.Fatalf("-etags = %q, want the operator's own exclusion: %v", value, args)
	}
	if value := argValue(t, args, "-it"); value != "/tmp/staged" {
		t.Fatalf("-it = %q, want the staged directory: %v", value, args)
	}
}

// An operator who sets a timeout keeps it: the pause-proof default is a fallback
// for an untouched options panel, never an override.
func TestBuildNucleiArgsKeepsAnExplicitRequestTimeout(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{TimeoutSeconds: 7},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if value := argValue(t, args, "-timeout"); value != "7" {
		t.Fatalf("explicit request timeout was replaced: %q in %v", value, args)
	}
}

func TestBuildNucleiArgsRejectsInvalidValues(t *testing.T) {
	for name, options := range map[string]NucleiOptions{
		"bad exclude severity":        {ExcludeSeverity: []string{"nonsense"}},
		"legacy protocol type filter": {Types: []string{"http"}},
		"negative concurrency":        {Concurrency: -1},
		"negative retries":            {Retries: -5},
	} {
		if _, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{Options: options}); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestBuildNucleiArgsOptionBeatsEnvironmentFallback(t *testing.T) {
	t.Setenv("RR_NUCLEI_RATE_LIMIT", "5")
	t.Setenv("RR_NUCLEI_EXEC_TIMEOUT_MS", "4000")
	// Without options the environment values are the only source.
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if argValue(t, args, "-rl") != "5" || argValue(t, args, "-timeout") != "4" {
		t.Fatalf("environment fallback lost: %v", args)
	}
	// An explicit option wins and is not duplicated.
	args, err = buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{RateLimit: 60, TimeoutSeconds: 11},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if argValue(t, args, "-rl") != "60" || argValue(t, args, "-timeout") != "11" {
		t.Fatalf("explicit option did not win: %v", args)
	}
	if strings.Count(strings.Join(args, " "), "-rl") != 1 {
		t.Fatalf("-rl was added twice: %v", args)
	}
}

// `-debug` widens what one invocation prints. It is the flag the operator asked
// for by name, so it is asserted in both directions: present when asked for, and
// absent otherwise, because a run nobody asked to debug should not carry it.
func TestBuildNucleiArgsAddsDebugOnlyWhenAsked(t *testing.T) {
	quiet, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(quiet, "-debug") {
		t.Fatalf("a run nobody asked to debug carries -debug: %v", quiet)
	}
	verbose, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{Debug: true},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if !hasArg(verbose, "-debug") {
		t.Fatalf("Debug: true produced no -debug: %v", verbose)
	}
}

// The delay the operator sets is `-rl` with an explicit window. Both are asked
// for together, and neither appears when the field is empty — an untouched panel
// must not slow a run down by naming a window the operator did not choose.
func TestBuildNucleiArgsMapsTheRateLimitWindow(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{RateLimit: 5, RateLimitDuration: 60},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if got := valueAfter(args, "-rl"); got != "5" {
		t.Fatalf("-rl = %q, want 5: %v", got, args)
	}
	if got := valueAfter(args, "-rld"); got != "60" {
		t.Fatalf("-rld = %q, want 60: %v", got, args)
	}
	// A rate with no window is the run the operator actually described: the
	// binary's own one-second default, named by nothing.
	noWindow, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{RateLimit: 5},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(noWindow, "-rld") {
		t.Fatalf("an empty window still produced -rld: %v", noWindow)
	}
	if got := valueAfter(noWindow, "-rl"); got != "5" {
		t.Fatalf("-rl = %q, want 5: %v", got, noWindow)
	}
}
