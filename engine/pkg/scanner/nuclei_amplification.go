package scanner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// A08-02 — the nuclei document path had no bound on amplification.
//
// WHAT THIS IS NOT. It is not a size limit, and deliberately so: the upload path already
// refuses a template over the operator's configured byte limit
// (`TEMPLATE_TOO_LARGE`), and a second size limit here would be a second, invisible cap on
// how big a template may be — which the project forbids.
//
// WHAT IT IS. A *ratio*. A small YAML document whose anchors and aliases expand into
// hundreds of megabytes is the shape that turns a kilobyte upload into a gigabyte of
// node tree, and the measurement has to happen **before** `yaml.Unmarshal`, because the
// decode is the expensive step the guard exists to avoid.
//
// HOW IT IS MEASURED. Anchors and aliases are counted in the raw text — `&name`
// definitions and `*name` references — and the document's own byte length is the
// denominator. That is a cheap upper-bound estimate, and it errs towards accepting: the
// real expansion depends on how large each anchor's value is, which is only known after a
// decode. So this guard is the cheap first line, not a proof, and the comment says so
// rather than implying a guarantee it cannot deliver.
//
// THE LIMIT IS VISIBLE AND OVERRIDABLE. `RR_YAML_MAX_AMPLIFICATION` changes it, an
// unparseable value falls back with a warning rather than silently, and the default is
// generous enough for the largest real template measured in the official corpus
// (`wordpress-plugin-detect.yaml`, 9.6 MB of YAML).

// maxYAMLAmplification is aliases-per-byte above which a document is refused. 50 is chosen
// because a real nuclei template expands by well under that, and the bomb shapes expand by
// orders of magnitude more.
const maxYAMLAmplification = 50

// yamlAmplificationLimitFromEnv reads the override, falling back loudly rather than
// silently — an operator who sets a nonsense value must not believe they changed anything.
func yamlAmplificationLimitFromEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 1 {
		fmt.Fprintf(os.Stderr, "warning: %s=%q is not a usable ratio, using %d\n", name, raw, fallback)
		return fallback
	}
	return value
}

// checkYAMLAmplification reports why `content` should not be decoded, or "" when it is
// within bounds.
func checkYAMLAmplification(content string, limit int) string {
	// Anchors and aliases are the only YAML construct that expands. Counting the raw
	// bytes is enough: each contributes a `&name` and each reference a `*name`, and both
	// markers are single characters that cannot appear in a scalar without being one.
	anchors := strings.Count(content, "&") - strings.Count(content, "&amp;")
	aliases := strings.Count(content, "*")
	if anchors == 0 || aliases == 0 {
		return ""
	}
	// Compare against a floor so a tiny document is not refused for ordinary structure: a
	// 40-byte template with two anchors and two references is a normal template, not a bomb.
	const floorBytes = 4096
	denominator := len(content)
	if denominator < floorBytes {
		denominator = floorBytes
	}
	ratio := (anchors + aliases) * 1000 / denominator
	if ratio <= limit {
		return ""
	}
	return fmt.Sprintf(
		"TEMPLATE_AMPLIFICATION_EXCEEDED: %d anchors and %d aliases in %d bytes "+
			"(~%d per kilobyte, limit %d per kilobyte); this shape inflates far beyond "+
			"its own size, so it is refused before decoding",
		anchors, aliases, len(content), ratio, limit,
	)
}
