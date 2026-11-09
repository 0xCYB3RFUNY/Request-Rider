package scanner

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// NucleiProgress is the live state of one running scan. Percent is -1 while the
// total request count is not known yet, which lets the browser show an
// indeterminate bar instead of inventing a percentage.
type NucleiProgress struct {
	Phase          string  `json:"phase"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	Templates      int     `json:"templates"`
	Hosts          int     `json:"hosts"`
	RPS            int     `json:"rps"`
	Matched        int     `json:"matched"`
	Errors         int     `json:"errors"`
	RequestsDone   int     `json:"requests_done"`
	RequestsTotal  int     `json:"requests_total"`
	Percent        float64 `json:"percent"`
}

// NewNucleiProgress returns the initial, unknown-progress state.
func NewNucleiProgress(phase string) NucleiProgress {
	return NucleiProgress{Phase: phase, Percent: -1}
}

var nucleiStatFields = map[string]*regexp.Regexp{
	"templates":   regexp.MustCompile(`Templates:\s*(\d+)`),
	"hosts":       regexp.MustCompile(`Hosts:\s*(\d+)`),
	"rps":         regexp.MustCompile(`RPS:\s*(\d+)`),
	"matched":     regexp.MustCompile(`Matched:\s*(\d+)`),
	"errors":      regexp.MustCompile(`Errors:\s*(\d+)`),
	"requests":    regexp.MustCompile(`Requests:\s*(\d+)/(\d+)`),
	"percent":     regexp.MustCompile(`\((\d+)%\)`),
	"elapsedTime": regexp.MustCompile(`^\[(\d+):(\d+):(\d+)\]`),
}

func statInt(re *regexp.Regexp, line string) int {
	match := re.FindStringSubmatch(line)
	if len(match) < 2 {
		return 0
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return value
}

// nucleiJSONStats is the machine-readable stats line. Nuclei emits this shape
// in JSONL mode and the pipe-delimited shape otherwise, so both are parsed.
type nucleiJSONStats struct {
	Duration  string `json:"duration"`
	Templates string `json:"templates"`
	Hosts     string `json:"hosts"`
	RPS       string `json:"rps"`
	Matched   string `json:"matched"`
	Errors    string `json:"errors"`
	Requests  string `json:"requests"`
	Total     string `json:"total"`
	Percent   string `json:"percent"`
	// Findings also arrive on this stream as JSONL, so their identity has to be
	// told apart explicitly: only stats carry templates+requests+total.
	TemplateID string `json:"template-id"`
}

func parseJSONStatsLine(trimmed string) (NucleiProgress, bool) {
	if !strings.HasPrefix(trimmed, "{") {
		return NucleiProgress{}, false
	}
	var stats nucleiJSONStats
	if err := json.Unmarshal([]byte(trimmed), &stats); err != nil {
		return NucleiProgress{}, false
	}
	if stats.TemplateID != "" || stats.Templates == "" || stats.Requests == "" || stats.Total == "" {
		return NucleiProgress{}, false
	}
	progress := NucleiProgress{
		Phase:          "running",
		Templates:      statValue(stats.Templates),
		Hosts:          statValue(stats.Hosts),
		RPS:            statValue(stats.RPS),
		Matched:        statValue(stats.Matched),
		Errors:         statValue(stats.Errors),
		RequestsDone:   statValue(stats.Requests),
		RequestsTotal:  statValue(stats.Total),
		ElapsedSeconds: parseClock(stats.Duration),
		Percent:        -1,
	}
	if progress.RequestsTotal > 0 {
		progress.Percent = float64(progress.RequestsDone) / float64(progress.RequestsTotal) * 100
		if percent := statValue(stats.Percent); percent >= 0 && percent <= 100 {
			// Nuclei's own figure wins when it disagrees with the ratio.
			progress.Percent = float64(percent)
		}
	}
	return progress, true
}

// ParseNucleiStatsLine turns one Nuclei stats line into a progress update. It
// reports false for findings, log lines and error messages, so they never reach
// the progress channel.
func ParseNucleiStatsLine(line string) (NucleiProgress, bool) {
	trimmed := strings.TrimSpace(line)
	if progress, ok := parseJSONStatsLine(trimmed); ok {
		return progress, true
	}
	if !strings.Contains(trimmed, "Templates:") || !strings.Contains(trimmed, "Requests:") {
		return NucleiProgress{}, false
	}
	progress := NucleiProgress{
		Phase:     "running",
		Templates: statInt(nucleiStatFields["templates"], trimmed),
		Hosts:     statInt(nucleiStatFields["hosts"], trimmed),
		RPS:       statInt(nucleiStatFields["rps"], trimmed),
		Matched:   statInt(nucleiStatFields["matched"], trimmed),
		Errors:    statInt(nucleiStatFields["errors"], trimmed),
		Percent:   -1,
	}
	match := nucleiStatFields["requests"].FindStringSubmatch(trimmed)
	if len(match) != 3 {
		return NucleiProgress{}, false
	}
	progress.RequestsDone, _ = strconv.Atoi(match[1])
	progress.RequestsTotal, _ = strconv.Atoi(match[2])
	if progress.RequestsTotal > 0 {
		progress.Percent = float64(progress.RequestsDone) / float64(progress.RequestsTotal) * 100
	}
	if clock := nucleiStatFields["elapsedTime"].FindStringSubmatch(trimmed); len(clock) == 4 {
		progress.ElapsedSeconds = parseClock(strings.Join(clock[1:], ":"))
	}
	return progress, true
}

func statValue(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return value
}

// parseClock turns "0:01:07" or "1:07" into seconds.
func parseClock(raw string) float64 {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) == 0 {
		return 0
	}
	total := 0
	for _, part := range parts {
		number, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return float64(total)
		}
		total = total*60 + number
	}
	return float64(total)
}

// nucleiOutput collects a subprocess stream, keeps every line for the run
// diagnostics, and reports Nuclei stats lines as they arrive. Nothing is
// dropped: the collected output is the evidence the operator reads, so a run is
// never summarised away.
type nucleiOutput struct {
	mutex  sync.Mutex
	buffer string
	lines  []string
	onLine func(string)
}

func newNucleiOutput(onLine func(string)) *nucleiOutput {
	return &nucleiOutput{onLine: onLine}
}

func (o *nucleiOutput) Write(payload []byte) (int, error) {
	o.mutex.Lock()
	o.buffer += string(payload)
	parts := strings.Split(o.buffer, "\n")
	o.buffer = parts[len(parts)-1]
	complete := parts[:len(parts)-1]
	o.lines = append(o.lines, complete...)
	o.mutex.Unlock()
	if o.onLine != nil {
		for _, line := range complete {
			if strings.TrimSpace(line) != "" {
				o.onLine(line)
			}
		}
	}
	return len(payload), nil
}

// Text returns the collected stream with ANSI sequences removed.
func (o *nucleiOutput) Text() string {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return diagnosticsText(strings.Join(o.lines, "\n"))
}
