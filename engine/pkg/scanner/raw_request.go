package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// `raw:` — це 1 263 з 4 000 відказів нашого раннера, тобто 31.6 % вибірки
// офіційного корпусу. Це найбільша окрема прогалина, і вона не потребує нічого
// нового: запит у ній написаний словами.
//
//	raw:
//	  - |
//	    GET /../../../..//etc/passwd HTTP/1.1
//	    Host: {{Hostname}}
//
// Різниця у вірності, яку треба назвати: nuclei з `unsafe: true` пише байти
// дослівно, а цей раннер розбирає їх і віддає через `net/http`. Заголовки
// тому нормалізуються.
//
// Це вимірювана різниця, а не привід відмови: `net/http` приймає `AAAA / HTTP/1.1`
// так само, як nuclei, і саме це потрібно honeypot-шаблонам на кшталт
// `dionaea-http-honeypot-detect`. Коли розбіжність стане важливою, її треба
// міряти на конкретному шаблоні, а не припускати зараз.

// parsedRawRequest is one `raw:` block taken apart.
type parsedRawRequest struct {
	Method  string
	Path    string
	Version string
	Headers map[string]string
	Body    string
	// Host is the host the request line's headers name, which is not necessarily
	// the target being scanned: a raw request may address another origin.
	Host string
}

// parseRawRequest takes one raw request apart and reports why it could not, if
// it could not.
//
// The refusals are the point. Each one is a case where sending something would
// mean sending a *different* request from the one the template wrote, and a
// verdict on a different request is not this template's verdict.
func parseRawRequest(raw, target string, dynamic map[string]string) (parsedRawRequest, string) {
	text := expandDynamic(strings.ReplaceAll(raw, "\r\n", "\n"), mustParseTarget(target), dynamic)
	lines := strings.Split(text, "\n")

	cursor := 0
	for cursor < len(lines) && strings.TrimSpace(lines[cursor]) == "" {
		cursor++
	}
	// `@`-prefixed lines are nuclei's own directives — `@timeout 10s`,
	// `@tls-sni`, `@Host` — and they sit above the request line. Measured on the
	// corpus: 34 templates of a 4 000 sample open their raw request with one, and
	// reading it as a header line produced `the raw header line "POST /… HTTP/1.1"
	// has no colon`, because the real request line was then read as a header.
	directives := 0
	for cursor < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[cursor]), "@") {
		directives++
		cursor++
		for cursor < len(lines) && strings.TrimSpace(lines[cursor]) == "" {
			cursor++
		}
	}
	if cursor >= len(lines) {
		if directives > 0 {
			return parsedRawRequest{}, fmt.Sprintf(
				"the raw request carries %d directive line(s) and no request line after them, so there is "+
					"nothing to send", directives)
		}
		return parsedRawRequest{}, "the raw request is empty, so there is no request line to send"
	}

	// Three fields, and the third may be absent: `GET /` is a valid request line.
	fields := strings.Fields(lines[cursor])
	if len(fields) < 2 {
		return parsedRawRequest{}, fmt.Sprintf(
			"the raw request line %q has fewer than two fields, so there is no method and no path to send",
			oneLine(lines[cursor]))
	}
	parsed := parsedRawRequest{
		Method:  fields[0],
		Path:    fields[1],
		Version: "HTTP/1.1",
		Headers: map[string]string{},
	}
	if len(fields) > 2 {
		parsed.Version = fields[2]
	}
	cursor++

	for cursor < len(lines) {
		line := lines[cursor]
		if strings.TrimSpace(line) == "" {
			// The blank line ends the headers. Everything after it is the body,
			// byte for byte, including its own line breaks.
			parsed.Body = strings.Join(lines[cursor+1:], "\n")
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return parsedRawRequest{}, fmt.Sprintf(
				"the raw header line %q has no colon, so there is no header name and value to send",
				oneLine(line))
		}
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "Host") {
			parsed.Host = strings.TrimSpace(value)
			cursor++
			continue
		}
		parsed.Headers[name] = strings.TrimSpace(value)
		cursor++
	}
	return parsed, ""
}

// rawRequestURL resolves the request target against the scan's target.
//
// A raw request usually spells an origin-form path. It may also spell an absolute
// URL, and that is a different origin from the one being scanned — so it is
// honoured as written rather than rewritten onto the scan's target.
func rawRequestURL(parsed parsedRawRequest, target string) (string, string) {
	if strings.HasPrefix(parsed.Path, "http://") || strings.HasPrefix(parsed.Path, "https://") {
		return parsed.Path, ""
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return "", fmt.Sprintf("the raw request path %q is neither origin-form (starting with '/') nor an "+
			"absolute URL", oneLine(parsed.Path))
	}
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Host == "" {
		return "", fmt.Sprintf("target %q must be an absolute URL with a host", oneLine(target))
	}
	base.Path = parsed.Path
	base.RawQuery = ""
	return base.String(), ""
}

// mustParseTarget parses the scan's target, substituting an empty URL when it
// cannot be parsed so that placeholder expansion still has somewhere to read
// from. The caller reports the real refusal, because only it knows whether the
// target was the thing that was wrong.
func mustParseTarget(target string) *url.URL {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return &url.URL{}
	}
	return parsed
}

// runRawRequest sends one `raw:` block and scores the response.
//
// It is the same verdict path as a structured block: the request goes through the
// recording transport, the exchange becomes a `PassiveExchange`, and nuclei's own
// operators judge it. The only difference is that the request line and the
// headers were written by the template rather than built from fields.
func runRawRequest(
	ctx context.Context,
	document *passiveDocument,
	request passiveRequest,
	target string,
	transport httpTransport,
	dynamic map[string]string,
) LocalRun {
	run := LocalRun{}
	// Which of these raw entries can be built was already decided, one entry at a
	// time, by `usableRaw` on the way in.
	//
	// It used to be decided again here, for the block as a whole — which made the
	// per-entry filter dead: a mutation removing `usableRaw`'s filter changed
	// nothing observable, because this check caught everything first. That is how
	// a block with three raw entries lost all three instead of one, and how a test
	// that cannot fail gets mistaken for one that passes.
	started := time.Now()
	parsedTarget, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsedTarget.Host == "" {
		run.Reason = fmt.Sprintf("target %q must be an absolute URL with a host", oneLine(target))
		return run
	}
	var lastReason string
	for _, raw := range request.Raw {
		parsed, reason := parseRawRequest(raw, target, dynamic)
		if reason != "" {
			lastReason = reason
			continue
		}
		absolute, reason := rawRequestURL(parsed, target)
		if reason != "" {
			lastReason = reason
			continue
		}
		httpRequest, buildErr := http.NewRequestWithContext(ctx, parsed.Method, absolute, strings.NewReader(parsed.Body))
		if buildErr != nil {
			lastReason = "cannot build the request: " + oneLine(buildErr.Error())
			continue
		}
		for name, value := range parsed.Headers {
			if strings.EqualFold(name, "Content-Length") {
				continue
			}
			httpRequest.Header.Set(name, value)
		}
		// `Host` is a request-line header in raw HTTP and `Request.Host` in Go.
		// Moving it is what makes a raw request that names another origin reach
		// that origin rather than the one being scanned.
		host := parsed.Host
		if host == "" {
			host = parsedTarget.Host
		}
		httpRequest.Host = host
		if httpRequest.Header.Get("User-Agent") == "" {
			httpRequest.Header.Set("User-Agent", "RequestRider")
		}

		response, doErr := transport.RoundTrip(httpRequest)
		if doErr != nil {
			lastReason = "request failed: " + oneLine(doErr.Error())
			continue
		}
		payload, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			lastReason = "cannot read the response: " + oneLine(readErr.Error())
			continue
		}
		elapsed := time.Since(started)
		run.Elapsed = elapsed
		run.StatusCode = response.StatusCode
		run.Response = localRawResponse(response, payload)
		run.Request = localRawWrittenRequest(parsed, httpRequest)

		exchange := PassiveExchange{
			Method:        parsed.Method,
			URL:           absolute,
			Host:          parsedTarget.Scheme + "://" + parsedTarget.Host,
			RawRequest:    run.Request,
			RawResponse:   run.Response,
			StatusCode:    response.StatusCode,
			Body:          string(payload),
			Header:        response.Header.Clone(),
			Duration:      elapsed,
			ContentLength: response.ContentLength,
			Dynamic:       dynamic,
		}
		verdict := scoreCompiled(document, request, exchange)
		run.Matched = verdict.Matched
		run.MatcherNames = verdict.MatcherNames
		run.Extracts = verdict.Extracts
		run.Dynamic = verdict.Dynamic
		run.ExtractLists = verdict.ExtractLists
		return run
	}
	run.Reason = lastReason
	if run.Reason == "" {
		run.Reason = "the template's raw request produced nothing that reached the target"
	}
	return run
}

// localRawWrittenRequest renders what the runner actually put on the wire.
//
// It is rendered from the parsed request rather than echoed from the template,
// because the template's bytes and the sent bytes are not the same string once
// headers have been normalised — and a report that showed the template's version
// would be showing evidence that never went anywhere.
func localRawWrittenRequest(parsed parsedRawRequest, request *http.Request) string {
	var builder strings.Builder
	path := request.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&builder, "%s %s %s\r\n", parsed.Method, path, parsed.Version)
	fmt.Fprintf(&builder, "Host: %s\r\n", request.Host)
	names := make([]string, 0, len(request.Header))
	for name := range request.Header {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		for _, value := range request.Header[name] {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	builder.WriteString("\r\n")
	builder.WriteString(parsed.Body)
	return builder.String()
}
