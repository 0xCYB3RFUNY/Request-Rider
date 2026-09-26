package scanner

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func hasArg(args []string, flag string) bool {
	return slices.Contains(args, flag)
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
			Types:              []string{"http", "HTTP"},
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
		"-u":       "http://target.test/",
		"-t":       "/tmp/staged",
		"-proxy":   "socks5://127.0.0.1:9050",
		"-tags":    "cve",
		"-es":      "info",
		"-etags":   "fuzz",
		"-itags":   "headless",
		"-pt":      "http",
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
	if !hasArg(args, "-duc") || !hasArg(args, "-silent") {
		t.Fatalf("the fixed flag set changed: %v", args)
	}
}

func TestBuildNucleiArgsDefaultsAreConservative(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if !hasArg(args, "-or") {
		t.Fatalf("omit_raw must default to true: %v", args)
	}
	if hasArg(args, "-ni") {
		t.Fatalf("interactsh must stay enabled unless explicitly disabled: %v", args)
	}
	// An untouched options panel must not add any optional switch, with one
	// deliberate exception: `-timeout`. A run can be paused with SIGSTOP, and
	// nuclei's request deadline is absolute wall-clock, so it expires while the
	// process is stopped and every request then fails on resume. A pausable run
	// therefore gets a request timeout no pause can exhaust, and an operator who
	// wants a tighter bound still sets it explicitly.
	for _, flag := range []string{"-c", "-rl", "-retries", "-mr", "-mhe", "-pc", "-prc", "-fr", "-fhr", "-headless", "-sresp", "-nc", "-ms", "-es", "-etags", "-itags", "-pt", "-id", "-et", "-em"} {
		if hasArg(args, flag) {
			t.Fatalf("empty options added %s: %v", flag, args)
		}
	}
	if pauseSupported() {
		if !hasArg(args, "-timeout") {
			t.Fatalf("a pausable run needs a pause-proof request timeout: %v", args)
		}
		if value := argValue(t, args, "-timeout"); value != strconv.Itoa(pausableRequestTimeoutSeconds()) {
			t.Fatalf("request timeout = %q, want %d: %v", value, pausableRequestTimeoutSeconds(), args)
		}
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
		"bad exclude severity": {ExcludeSeverity: []string{"nonsense"}},
		"bad type":             {Types: []string{"carrier-pigeon"}},
		// `network` and `multipart` look plausible but the binary rejects them
		// for -pt, so they must not be offered.
		"network type":         {Types: []string{"network"}},
		"multipart type":       {Types: []string{"multipart"}},
		"negative concurrency": {Concurrency: -1},
		"negative retries":     {Retries: -5},
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
