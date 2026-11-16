// Shellshock: CVE-2014-6271 and the parsing bug that made it a class rather than
// a number.
//
// # What the bug is
//
// bash 1.3 through 4.3 parses a function definition out of an environment
// variable, so a value like `() { :; }; echo; /bin/bash -c '…'` is read as a
// function body and then executed. A CGI server turns request headers into
// environment variables, which puts a request header in reach of bash. The
// consequence is remote command execution from nothing more exotic than a
// `User-Agent` line.
//
// The payload in this file executes one command, and the command is `echo`.
//
// That is the whole design. A Shellshock check that opens a shell, spawns a
// process, binds a port or writes a file has stopped being a check and started
// being the attack — and a scanner is the tool most likely to be pointed at a
// host the operator does not own, precisely because nobody suspects it is
// vulnerable. The marker here prints a string and nothing else; a host that
// executes it has answered the question, and a host that does not has answered
// it too.
//
// # Why the observable is not a response
//
// This is what makes Shellshock awkward to detect and the reason the module is
// not a copy of `CMDi` with a different payload.
//
// On a vulnerable CGI, the injected command's stdout lands on the CGI's stdout
// **before** the status line. The bytes a client receives are therefore not an
// HTTP response: there is no status line for a parser to find. So the classic
// signature is not a row in the body — it is that the exchange cannot be parsed
// at all while the same request without the payload parses fine.
//
// That difference is the finding, and it is why the module reads the *outcome* of
// the request rather than only its content. Reporting "the server returned a
// malformed response" without the control arm would be a coin flip: proxies,
// rate limiters and flaky origins produce the same thing.
//
// # The control arm, and why it is the same request
//
// The baseline the scan already took is the control: same URL, same method, same
// everything, minus the payload. A payload that fails where the baseline
// succeeded is a signal; a host that fails every request is a host with a network
// problem, and the module says nothing about it.
//
// The marker in the body is still checked, because a host behind a reverse proxy
// that sanitises the status line can pass the command's output through in a
// header or a body instead. Both signals are reported, and `Fresh` is what keeps
// a page that happens to contain the word from being a finding.
//
// # Why two headers and not five
//
// `User-Agent` and `Referer` are the two a CGI setup reliably exposes, and they
// are what the published check uses. `Cookie`, `Accept-Language` and the rest are
// also parsed by bash, but a module that probed all five would spend five
// requests per endpoint to repeat the same conclusion — and this detector runs
// once per unique URL, so the cost is five times the number of pages. Two is the
// point where the second vector still pays for itself.
package active

import (
	"context"
	"fmt"
	"net/http"
)

// Shellshock is the Shellshock detector.
type Shellshock struct{}

// Name implements Module.
func (Shellshock) Name() string { return "shellshock" }

// Level implements Module.
//
// Endpoint, not parameter: the vector is a request *header*, so there is no
// injectable surface to hang it on and a parameter-level module would never be
// handed the place where the bug lives.
func (Shellshock) Level() Level { return LevelEndpoint }

// shellshockMarker is what the injected command prints.
//
// It carries the module's own name so a triager can see where the string came
// from, and it is long enough that no page is likely to contain it by accident —
// which matters because `Fresh` compares against the baseline, and a short marker
// raises the chance of matching something real.
const shellshockMarker = "rr-shellshock-9c2f4a7e"

// shellshockPayload is the function definition bash mis-parses.
//
// The `:` is a builtin no-op, so the "function body" is valid and the shell
// proceeds to the next command instead of erroring on an empty body. `/bin/bash
// -c 'echo …'` is an explicit interpreter rather than the running one, because
// the running one may be a restricted shell that refuses `-c`.
func shellshockPayload() string {
	return fmt.Sprintf("() { :;}; echo; /bin/bash -c 'echo %s'", shellshockMarker)
}

// shellshockVectors are the headers a probe is sent in.
var shellshockVectors = []string{"User-Agent", "Referer"}

// Scan implements Module.
func (sh Shellshock) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		// Without a baseline there is no control arm, and a payload that fails
		// on its own proves nothing: the host may simply be down.
		return nil
	}
	var findings []Finding
	for _, header := range shellshockVectors {
		if finding := sh.shellshockProbe(ctx, t, p, baseline, header); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

// shellshockProbe sends one header probe and reads the outcome.
func (Shellshock) shellshockProbe(ctx context.Context, t *Transport, p Point, baseline *Response, header string) *Finding {
	extra := http.Header{}
	extra.Set(header, shellshockPayload())
	resp, err := t.Fire(ctx, p, p.Param, "", false, extra)

	payload := shellshockPayload()

	// Signal one: the command's output came back in something the client could
	// parse. A proxy that sanitises the status line is the case this catches.
	if err == nil && Fresh(baseline, resp, shellshockMarker) {
		finding, _ := NewFinding(Spec{
			Module:  "shellshock",
			Title:   "Shellshock: an injected command executed through " + header,
			Claimed: SeverityCritical,
			Tier:    TierVerified,
			Point:   p,
			Payload: payload,
			Evidence: fmt.Sprintf(
				"%s: %q, and the response carries %q, which the unmodified request did not",
				header, payload, shellshockMarker),
			Description: "A bash in the range affected by CVE-2014-6271 parses a function " +
				"definition out of an environment variable, and a CGI server builds those " +
				"variables from request headers. The command that ran printed a marker; it " +
				"was not a shell, and nothing on the target was changed.",
			Remediation: "Patch bash past 4.3-005, or stop passing raw request headers to " +
				"bash as environment variables.",
		})
		return &finding
	}

	// Signal two: the exchange could not be parsed, where the identical request
	// without the payload parses. On an affected CGI the command's stdout lands
	// before the status line, so there is no status line to parse.
	if err != nil {
		finding, _ := NewFinding(Spec{
			Module:  "shellshock",
			Title:   "Shellshock: " + header + " payload broke the response, the plain request did not",
			Claimed: SeverityHigh,
			Tier:    TierVerified,
			Point:   p,
			Payload: payload,
			Evidence: fmt.Sprintf(
				"%s: %q made the exchange unreadable (%s), while the same request without the payload was answered %s",
				header, payload, err, baseline.Status),
			Description: "The injected command's output precedes the HTTP status line, so a " +
				"shell reached by this header produces a response no client can parse. The " +
				"baseline — the same URL, the same method, no payload — was answered normally, " +
				"which is what separates this from a host that simply failed to answer.",
			Remediation: "Patch bash past 4.3-005, or stop passing raw request headers to " +
				"bash as environment variables.",
		})
		return &finding
	}
	return nil
}
