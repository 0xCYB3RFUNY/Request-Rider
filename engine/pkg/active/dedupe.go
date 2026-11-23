package active

// De-duplication of host-property findings.
//
// Some detectors answer a question about the server, not about one URL:
// Misconfig reads the response headers and Methods asks which HTTP verbs the
// endpoint answers. Both are declared LevelEndpoint, and that is deliberate:
// a deployment can answer OPTIONS differently on /login and /api, and a scan
// that only checked the start URL would miss it. Paying for the check on every
// crawled page is therefore coverage, not waste.
//
// The waste is in the report. On a uniform target - which every intentionally
// vulnerable training application is - the same answer comes back for every
// page and the operator gets the same row four, seven or twenty times, each
// with a different endpoint and ID. That is noise that hides the injection
// rows, and it also inflates the finding count in progress and in the report.
//
// The fix is at the report boundary rather than in the detectors' Level:
// every page is still probed; only identical host-property rows are collapsed,
// and the collapse is announced in a warning so the number in the report is
// honest about what happened.
import "fmt"

// hostPropertyModules are the modules whose finding is a property of the
// deployment rather than of one URL. Their Level stays LevelEndpoint so the
// scan keeps checking every path; only their identical report rows collapse.
var hostPropertyModules = map[string]bool{
	"methods":   true,
	"misconfig": true,
}

// dedupeHostPropertyFindings collapses identical rows from host-property
// modules, keeping the first occurrence in run order. The dedupe key excludes
// Endpoint, ID and PoCCurl (which embed the endpoint) but keeps everything that
// describes the observation: module, title, severity, tier, evidence, param,
// payload shape without the URL, description and CWE.
//
// A payload that is only the probed URL (`OPTIONS http://host/path`) is
// normalised to the verb so two pages with the same answer compare equal.
func dedupeHostPropertyFindings(findings []Finding) ([]Finding, int) {
	seen := make(map[string]bool, len(findings))
	out := make([]Finding, 0, len(findings))
	collapsed := 0
	for _, f := range findings {
		if !hostPropertyModules[f.Module] {
			out = append(out, f)
			continue
		}
		key := f.Module + "\x00" + f.Title + "\x00" + string(f.Severity) + "\x00" +
			string(f.Tier) + "\x00" + f.Evidence + "\x00" + f.Param + "\x00" +
			normaliseHostPayload(f.Payload) + "\x00" + f.Description + "\x00" + f.CWE
		if seen[key] {
			collapsed++
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out, collapsed
}

// normaliseHostPayload removes the endpoint from a payload that is just a verb
// plus the probed URL, so `OPTIONS http://host/a` and `OPTIONS http://host/b`
// compare equal when the answer is the same. Other payloads are left alone.
func normaliseHostPayload(payload string) string {
	for _, verb := range []string{"OPTIONS", "TRACE", "GET", "POST", "PUT", "DELETE", "PROPFIND"} {
		if len(payload) > len(verb)+1 && payload[:len(verb)] == verb && payload[len(verb)] == ' ' {
			return verb
		}
	}
	return payload
}

// hostPropertyWarning is the visible record of the collapse. A report that
// silently dropped rows would be reporting a different number from the one the
// engine produced, which is the same class of dishonesty as a hidden cap.
func hostPropertyWarning(collapsed int) string {
	return fmt.Sprintf(
		"%d identical host-property finding(s) were collapsed into one row each; "+
			"every crawled page was still probed - the rows were the same answer from a different URL",
		collapsed)
}
