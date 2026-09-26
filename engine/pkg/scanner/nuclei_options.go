package scanner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// NucleiOptions is the operator-facing set of advanced scan switches. Every
// field maps to exactly one Nuclei flag, so the browser never sends a raw
// command line: the flag set stays fixed and each value is validated here.
type NucleiOptions struct {
	ExcludeSeverity    []string `json:"exclude_severity"`
	ExcludeTags        []string `json:"exclude_tags"`
	IncludeTags        []string `json:"include_tags"`
	Types              []string `json:"types"`
	TemplateIDs        []string `json:"template_ids"`
	ExcludeTemplates   []string `json:"exclude_templates"`
	ExcludeMatchers    []string `json:"exclude_matchers"`
	Concurrency        int      `json:"concurrency"`
	RateLimit          int      `json:"rate_limit"`
	Retries            int      `json:"retries"`
	TimeoutSeconds     int      `json:"timeout_seconds"`
	MaxRedirects       int      `json:"max_redirects"`
	MaxHostErrors      int      `json:"max_host_errors"`
	FollowRedirects    bool     `json:"follow_redirects"`
	FollowHostRedirs   bool     `json:"follow_host_redirects"`
	DisableClustering  bool     `json:"disable_clustering"`
	Headless           bool     `json:"headless"`
	Interactsh         *bool    `json:"interactsh"`
	StoreResponse      bool     `json:"store_response"`
	OmitRaw            *bool    `json:"omit_raw"`
	NoColor            bool     `json:"no_color"`
	MatcherStatus      bool     `json:"matcher_status"`
	PayloadConcurrency int      `json:"payload_concurrency"`
	ProbeConcurrency   int      `json:"probe_concurrency"`
}

// validNucleiTypes are the protocol types Nuclei accepts for -pt/-ept. The list
// matches the binary's own -pt documentation exactly: passing anything else
// makes Nuclei exit 2 with an "is not a valid extract type" message.
var validNucleiTypes = map[string]bool{
	"dns": true, "file": true, "http": true, "headless": true, "tcp": true,
	"workflow": true, "ssl": true, "websocket": true, "whois": true,
	"code": true, "javascript": true,
}

// buildNucleiArgs renders the fixed flag set for one run. The target URL, the
// staged template directory and the validated option values are the only
// variable parts; the binary is executed without a shell.
func buildNucleiArgs(target, dir string, request NucleiRequest) ([]string, error) {
	options := request.Options
	if err := options.validate(); err != nil {
		return nil, err
	}
	// -duc keeps the run offline-deterministic, -silent keeps the terminal
	// clean, -o receives the JSONL the report is parsed from.
	args := []string{"-duc", "-silent", "-u", target, "-t", dir}
	if proxy := strings.TrimSpace(request.Proxy); proxy != "" {
		args = append(args, "-proxy", proxy)
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
	if values := dedupeLower(options.Types); len(values) > 0 {
		args = append(args, "-pt", strings.Join(values, ","))
	}
	// `-code` stands alone: it is the one flag that loads a chosen template type
	// without narrowing everything else, so a folder containing one is really run
	// instead of being reported as nothing found.
	if autoCodeFlag(request.Protocols, options.Types) {
		args = append(args, "-code")
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
	if options.StoreResponse {
		args = append(args, "-sresp")
	}
	if options.MatcherStatus {
		args = append(args, "-ms")
	}
	if options.NoColor {
		args = append(args, "-nc")
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
			// The value is deliberately large rather than exact, because a pause
			// has no upper bound by design. It only bounds how long Nuclei waits
			// on a host that never answers; it does not slow a healthy scan, and
			// an operator who wants a tighter bound still sets it explicitly.
			args = append(args, "-timeout", strconv.Itoa(pausableRequestTimeoutSeconds()))
		}
	}
	return args, nil
}

// autoCodeFlag reports whether `-code` has to be added so the chosen files are
// actually loaded by the binary.
//
// Picking a folder means every file in it gets a chance to run, and Nuclei does
// not load a `code` template on its own: a folder of only `code` files makes the
// binary exit 1 with "no templates provided for scan", and a mixed folder reports
// nothing for those files while the other 14000 report normally. The flag is
// derived from the documents the operator selected, so a web-only folder gets
// none and its command line is byte-for-byte what it was.
//
// An explicit type set suppresses it. `-pt` replaces the binary's whole default
// type set (measured: `-pt file` on a folder that also holds an `http` template
// exits 1 with nothing loaded), so a narrowed set is the operator narrowing the
// run, and widening it back would execute local commands they did not ask for.
// `-code` is the one case where the operator already named the type.
func autoCodeFlag(protocols, explicit []string) bool {
	if types := dedupeLower(explicit); len(types) > 0 {
		return namedType(types, "code")
	}
	for _, protocol := range dedupeLower(protocols) {
		if protocol == "code" {
			return true
		}
	}
	return false
}

func namedType(types []string, protocol string) bool {
	for _, kind := range types {
		if strings.ToLower(strings.TrimSpace(kind)) == protocol {
			return true
		}
	}
	return false
}

// none and the run can be paused. Overridable for a site that needs a different
// bound; see nucleiPausableTimeoutSeconds.
func pausableRequestTimeoutSeconds() int {
	if raw := strings.TrimSpace(os.Getenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return value
		}
	}
	return 86400
}

func (o NucleiOptions) validate() error {
	for _, level := range o.ExcludeSeverity {
		if !validSeverities[strings.ToLower(strings.TrimSpace(level))] {
			return fmt.Errorf("invalid exclude_severity %q", level)
		}
	}
	for _, kind := range o.Types {
		if !validNucleiTypes[strings.ToLower(strings.TrimSpace(kind))] {
			return fmt.Errorf("invalid type %q", kind)
		}
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
