package active

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Smuggling probes endpoints for HTTP Request Smuggling (CL.TE / TE.CL desync).
// Corresponds to Burp Suite check:
// 0x00200140 (HTTP request smuggling)
type Smuggling struct{}

// Name implements Module.
func (Smuggling) Name() string { return "smuggling" }

// Level implements Module.
func (Smuggling) Level() Level { return LevelEndpoint }

func (s Smuggling) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}

	var out []Finding

	// Probe 1: CL.TE probe
	// Front-end reads Content-Length: 6, Back-end reads Transfer-Encoding chunked.
	// The 0-chunk terminates the back-end body, leaving trailing data or causing timeout.
	clteBody := "0\r\n\r\nX"
	clteHeaders := http.Header{
		"Transfer-Encoding": {"chunked"},
		"Content-Length":    {"6"},
	}

	start := time.Now()
	respCLTE, err := t.DoBody(ctx, http.MethodPost, p.URL, []byte(clteBody), "application/x-www-form-urlencoded", false, clteHeaders)
	duration := time.Since(start)

	// In HTTP/1.1 proxies, a timeout (> 4 seconds while baseline took < 1s) or server error 500 with desync marker indicates CL.TE
	isCLTEDesync := (err != nil && strings.Contains(err.Error(), "timeout") && baseline.Duration < time.Second) ||
		(duration > 4*time.Second && baseline.Duration < time.Second)

	if isCLTEDesync {
		evidence := fmt.Sprintf("CL.TE probe delayed connection by %v (baseline: %v). Front-end and back-end proxies parse request lengths differently.", duration, baseline.Duration)
		finding, _ := NewFinding(Spec{
			Module:      "smuggling",
			Title:       "HTTP Request Smuggling (CL.TE Potential)",
			Claimed:     SeverityHigh,
			Tier:        TierPotential,
			Point:       p,
			Payload:     "Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX",
			Evidence:    evidence,
			Description: "The endpoint exhibited a significant delay or timeout when supplied with conflicting Content-Length and Transfer-Encoding headers. This indicates the front-end server processes Content-Length while the back-end processes Transfer-Encoding.",
			Remediation: "Configure the front-end server to exclusively use HTTP/2 to back-end servers, or disable connection reuse and reject requests containing ambiguous Transfer-Encoding or Content-Length headers.",
		})
		out = append(out, finding)
	}

	// Probe 2: TE.CL Obfuscation probe
	// Testing obfuscated Transfer-Encoding header support
	teclBody := "4\r\nTEST\r\n0\r\n\r\n"
	teclHeaders := http.Header{
		"Transfer-Encoding": {"chunked, identity"},
		"Content-Length":    {"4"},
	}

	startTE := time.Now()
	_, errTE := t.DoBody(ctx, http.MethodPost, p.URL, []byte(teclBody), "application/x-www-form-urlencoded", false, teclHeaders)
	durationTE := time.Since(startTE)

	if (errTE != nil && strings.Contains(errTE.Error(), "timeout") && baseline.Duration < time.Second) ||
		(durationTE > 4*time.Second && baseline.Duration < time.Second) {
		evidence := fmt.Sprintf("TE.CL probe delayed connection by %v (baseline: %v).", durationTE, baseline.Duration)
		finding, _ := NewFinding(Spec{
			Module:      "smuggling",
			Title:       "HTTP Request Smuggling (TE.CL Potential)",
			Claimed:     SeverityHigh,
			Tier:        TierPotential,
			Point:       p,
			Payload:     "Transfer-Encoding: chunked, identity\r\nContent-Length: 4",
			Evidence:    evidence,
			Description: "The endpoint delayed or timed out on conflicting Transfer-Encoding obfuscations. The front-end parses Transfer-Encoding while the back-end falls back to Content-Length.",
			Remediation: "Normalize incoming headers at the front-end reverse proxy and reject malformed or duplicate Transfer-Encoding headers.",
		})
		out = append(out, finding)
	}

	_ = respCLTE
	return out
}
