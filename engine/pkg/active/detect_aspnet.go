package active

// ASPDotNet reads three .NET-specific disclosures: the trace endpoint, the
// debug configuration and an unencrypted ViewState.
//
// Burp reports them as three checks — `0x00100280` (ASP.NET tracing enabled),
// `0x00100800` (ASP.NET debugging enabled) and `0x00400600` (ASP.NET ViewState
// without MAC) — and they belong together because they are all properties of one
// runtime answering on one origin, so the module is one and the module-level
// cost is one.
//
// Why the ViewState row is potential and not verified. Encrypting a ViewState
// and signing it are two different decisions in the same runtime: the leading
// byte this run reads says which one the page took, and `0xFF` — encryption —
// means the payload is opaque while saying nothing about a signature. Verifying
// the *signature* requires the machine key the application holds, and a scanner
// that does not hold it cannot prove the MAC is absent. So the row reports what
// is measurable — the payload is not encrypted and its contents are readable —
// and names the part it did not measure. A scanner that claimed the MAC was
// missing on the strength of the leading byte would be claiming the thing it
// cannot see.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ASPDotNet is the .NET disclosure reader.
type ASPDotNet struct{}

// Name implements Module.
func (ASPDotNet) Name() string { return "aspnet" }

// Level implements Module.
// Runs once per host: the trace endpoint and the configuration are properties
// of the origin, not of one page.
func (ASPDotNet) Level() Level { return LevelHost }

// aspNetConfigPaths are the configuration locations this module asks for on its
// own account. A table rather than a literal for the reason `crossDomainPaths`
// is: the interesting-path measurement subtracts a detector's own paths, and it
// reads them from the package's tables.
var aspNetConfigPaths = []string{"/web.config", "/web.debug.config", "/trace.axd", "/elmah.axd"}

var (
	// aspTraceMarkers are what the trace endpoint serves when it is on.
	aspTraceMarkers = []string{
		"Application Trace",
		"Request Details",
		"Trace.axd",
		"<title>Application Trace</title>",
	}
	// aspNetDebugMarkers are what a debug-mode configuration declares.
	aspNetDebugMarkers = []string{
		"<compilation debug=\"true\"",
		"<compilation defaultlanguage",
		"<customerrors mode=\"off\"",
		"<customerrors mode=\"remotenly\"",
	}
	// aspNetYellowScreenMarkers are what a debugging-enabled server answers an
	// unhandled error with.
	aspNetYellowScreenMarkers = []string{
		"Server Error in '/' Application",
		"Runtime Error",
		"Stack Trace:",
		"[SqlException",
		"[NullReferenceException",
	}
	// viewStateFieldRe is the hidden field the framework puts in every
	// post-back form.
	viewStateFieldRe = regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']__VIEWSTATE["'][^>]*value\s*=\s*["']([^"']+)["']`)
)

// Scan probes the origin for the three .NET disclosures.
func (ASPDotNet) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	origin, base, ok := originOf(p.URL)
	if !ok {
		return nil
	}
	var out []Finding
	for _, path := range aspNetConfigPaths {
		target := base + path
		resp, err := t.Do(ctx, http.MethodGet, target, nil, false, http.Header{
			"Accept": {"text/html, application/xml, */*"},
		})
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if strings.HasSuffix(path, "trace.axd") {
			if marker := aspFirstMatch(resp.Body, aspTraceMarkers); marker != "" {
				out = append(out, aspNetFinding(origin, target, path, "ASP.NET Tracing Enabled",
					SeverityMedium, "Application Trace", marker,
					"The trace endpoint answers with the framework's own trace page. Tracing "+
						"records every request the application served — the URL, the headers, the "+
						"form values, the session and the exception text — and this page reads that "+
						"record back to whoever asks for it.",
					"Turn tracing off in `system.web/trace` (`enabled=\"false\"`), and remove "+
						"`trace.axd` from any deployment that is not a local development "+
						"machine. Where it must stay, restrict it to a caller the application "+
						"has authenticated as itself."))
			}
			continue
		}
		if marker := aspFirstMatch(resp.Body, aspNetDebugMarkers); marker != "" {
			out = append(out, aspNetFinding(origin, target, path, "ASP.NET Debugging Enabled",
				SeverityMedium, "compilation debug / customErrors", marker,
				"The configuration file answers with debugging switched on. A debug build emits "+
					"a full stack trace, the source paths and the query text for every unhandled "+
					"error, so the error page becomes a map of the application's internals rather "+
					"than a message.",
				"Set `<compilation debug=\"false\">` and `<customErrors mode=\"On\">` (or "+
					"`RemoteOnly`) in every deployed configuration, and keep the debug file out "+
					"of the deployment entirely."))
			continue
		}
	}
	// The view-state row reads the page the surface already returned, so it
	// costs no request and belongs outside the loop above.
	if finding := aspViewState(p, baseline); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// aspFirstMatch returns the first marker present in a body, so the evidence
// line names the string that was found rather than a category.
func aspFirstMatch(body string, markers []string) string {
	for _, marker := range markers {
		if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
			return marker
		}
	}
	return ""
}

// aspNetFinding renders one .NET row.
func aspNetFinding(origin, target, path, title string, claimed Severity, kind, marker, description, remediation string) Finding {
	finding, _ := NewFinding(Spec{
		Module:      "aspnet",
		Title:       title,
		Claimed:     claimed,
		Tier:        TierVerified,
		Point:       Point{URL: target, Method: http.MethodGet, Origin: origin},
		Payload:     "GET " + target,
		Evidence:    kind + " at " + path + " → " + marker,
		Description: description,
		Remediation: remediation,
	})
	return finding
}

// aspViewState reads the page's own ViewState and reports what it discloses.
//
// The measurement is the payload's leading byte, read after a base64 decode:
// `0xFF` is the framework's marker for an encrypted ViewState and anything else
// is a payload in the clear. The MAC is deliberately *not* claimed, because a
// machine key this run does not hold is the only thing that can verify it.
func aspViewState(p Point, baseline *Response) *Finding {
	if baseline == nil || baseline.StatusCode >= 400 {
		return nil
	}
	match := viewStateFieldRe.FindStringSubmatch(baseline.Body)
	if len(match) < 2 {
		return nil
	}
	encoded := strings.TrimSpace(match[1])
	if encoded == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(encoded, " ", "+"))
	if err != nil || len(decoded) < 2 {
		return nil
	}
	if decoded[0] == 0xFF {
		// Encrypted: the payload is opaque and this run has nothing to read.
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "aspnet",
		Title:   "ASP.NET ViewState Carries an Unencrypted Payload",
		Claimed: SeverityLow,
		Tier:    TierPotential,
		Point:   p,
		Payload: "__VIEWSTATE=" + aspTruncate(encoded, 48),
		Evidence: fmt.Sprintf("__VIEWSTATE decodes to %d byte(s); leading byte 0x%02X, so the "+
			"payload is not encrypted. %s", len(decoded), decoded[0], aspViewStatePreview(decoded)),
		Description: "The page's ViewState is not encrypted, so its contents — the controls, the " +
			"view state of every field on the page and any value the application put in it — are " +
			"readable by anyone who reads the HTML. This row reports the missing encryption, " +
			"which is measurable from the payload itself. It does **not** claim the ViewState is " +
			"unsigned: a MAC is a different setting, and verifying it needs the machine key the " +
			"application holds, which this run does not.",
		Remediation: "Encrypt the ViewState (`<machineKey validation=\"3DES\">` or the " +
			"`ViewStateEncryptionMode=\"Always\"` setting), keep the MAC on regardless, and never " +
			"place a secret in view state on the assumption that it is hidden.",
	})
	return &finding
}

// aspViewStatePreview reads the printable prefix of a decoded ViewState, so the
// evidence line shows a reader what is actually in the payload.
func aspViewStatePreview(decoded []byte) string {
	const limit = 48
	printable := make([]byte, 0, limit)
	for _, b := range decoded[:min(len(decoded), limit)] {
		if b >= 0x20 && b < 0x7f {
			printable = append(printable, b)
			continue
		}
		printable = append(printable, '.')
	}
	return "Readable prefix: `" + string(printable) + "`"
}

// aspTruncate shortens a value for a payload column without hiding the shape.
func aspTruncate(value string, keep int) string {
	if len(value) <= keep {
		return value
	}
	return value[:keep] + "…"
}
