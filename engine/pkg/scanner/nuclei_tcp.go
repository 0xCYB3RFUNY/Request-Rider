package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// `tcp:` — 289 шаблонів офіційного корпусу. Виміряна форма:
//
//	host:    289      inputs: 278      matchers:   288
//	port:    253      read:     45      extractors: 113
//	data:    278      tls:       8      dsl:        53
//
// Тобто документ описує розмову: що надіслати (`data:`) і скільки прочитати
// (`read:`), а оператори дивляться на те, що прийшло.
//
// Матчери читають переважно `raw`, `body` і `data` — 67 із 289; решта 32 читають
// іменовані кроки (`ehlo`, `help`, `info`, `note`, `szl`, `banner`, `system_info`),
// і кожен такий крок тут отримує ім'я за порядком читання.

// tcpDialTimeout bounds how long the connection itself may take.
const tcpDialTimeout = 15 * time.Second

// tcpReadTimeout bounds one read.
//
// It is the deadline for one `read: N`, not for the whole conversation: a template
// that reads 1024 bytes four times is given four chances, and each one is reported
// when it expires rather than silently ending the conversation early.
var tcpReadTimeout = 10 * time.Second

// tcpExchangeMaxBytes bounds what one conversation may accumulate.
const tcpExchangeMaxBytes = 1 << 20

// tcpStepInput is one `inputs:` element.
//
// An element may carry both `data:` and `read:`, which nuclei reads as
// "send this, then read" — `http/cves/2018/CVE-2018-6882.yaml` writes
// `- data: "EHLO {{base}}\r\n"` with a following `- read: 1024`, but several
// templates put `read:` on the same element as the data it answers.
type tcpStepInput struct {
	Data string `yaml:"data"`
	Read int    `yaml:"read"`
}

// runTcpDocument performs each `tcp:` block against the target's host.
func runTcpDocument(ctx context.Context, document *passiveDocument, blocks []passiveRequest, target string) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	host, port, reason := tcpEndpoint(target, blocks[0])
	if reason != "" {
		run.Skipped = true
		run.Reason = reason
		return run
	}
	for index, block := range blocks {
		stepHost, stepPort, stepReason := tcpEndpoint(target, block)
		if stepReason != "" {
			run.Skipped = true
			run.Reason = stepReason
			return run
		}
		if index > 0 && (stepHost != host || stepPort != port) {
			// A second block naming another endpoint is a sequence over two
			// connections, and this runner performs one block at a time. Saying so
			// is better than silently reusing the first endpoint: the operator would
			// read a verdict about a host nobody dialled.
			run.Skipped = true
			run.Reason = fmt.Sprintf(
				"tcp block %d of %d names %s:%s, while the first names %s:%s; this runner opens one "+
					"connection per block, so each block is judged on its own endpoint",
				index+1, len(blocks), stepHost, stepPort, host, port)
			return run
		}
		transcript, names, stepReason := converse(ctx, stepHost, stepPort, block)
		if stepReason != "" {
			run.Skipped = true
			run.Reason = fmt.Sprintf("tcp block %d of %d: %s", index+1, len(blocks), stepReason)
			return run
		}
		verdict := scoreTcpBlock(document, block, transcript, names)
		run.Request += transcriptRequest(stepHost, stepPort, block)
		run.Response += transcript
		run.Extracts = append(run.Extracts, verdict.Extracts...)
		for name, values := range verdict.ExtractLists {
			run.ExtractLists[name] = append(run.ExtractLists[name], values...)
		}
		if verdict.Matched {
			run.Matched = true
			if len(run.MatcherNames) == 0 {
				run.MatcherNames = verdict.MatcherNames
			}
			continue
		}
	}
	// A block that connected, exchanged bytes and matched nothing is a real
	// negative, so the run says so by leaving `Matched` false and raising
	// nothing.
	//
	// It used to answer `Skipped: true` with the reason «all N tcp block(s) ran
	// and matched nothing», which contradicted itself in one sentence: the status
	// reads «Not run» / «Не запускався» in the UI, the filter and the export, while
	// the reason said the block ran. The contract of `Skipped` forbids it outright —
	// the field is documented as «a request that could not be built at all», and a
	// block that read a banner is not that. Measured on the live product: nuclei
	// itself writes `"matcher-status": false` for exactly this template, so the row
	// that reached the operator contradicted the binary it came from.
	//
	// Nothing is lost by the silence. A negative needs no reason — only `invalid`,
	// `skipped` and `no_request` do — and the transcript this runner kept is what
	// proves the conversation happened rather than being assumed.
	//
	// A block that could not reach the target is a different case and still says
	// so: `converse` returns a reason for it and that path returns above.
	return run
}

// tcpEndpoint resolves the host and port a block dials.
//
// The host comes from the template's `host:`, which is written `{{Hostname}}` in
// 253 of the 289 templates — that is the operator's target host, not a name to look
// up. A template that writes a literal instead gets that literal, because the
// operator put it there.
func tcpEndpoint(target string, block passiveRequest) (string, string, string) {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsed.Host == "" {
		return "", "", fmt.Sprintf(
			"the run's target %q is not an absolute URL, so a `tcp:` block has no host to dial", target)
	}
	hostName, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		port = "443"
		if parsed.Scheme == "http" {
			port = "80"
		}
	}
	for _, written := range block.TcpHost {
		resolved := strings.TrimSpace(expandDynamic(written, parsed, nil))
		// `{{Hostname}}` is already gone: `expandDynamic` above substituted it with
		// the target's host — the same host this function is already holding. A case
		// for the spelling looked meaningful and measured unreachable: the mutation
		// that removed it changed nothing, which is how a branch nobody executes gets
		// mistaken for one that works.
		switch resolved {
		case "":
			continue
		default:
			// `{{Hostname}}:25` — the host is the target's own, the port is the
			// template's. Written as one assignment to two variables it read as if
			// the host were being recomputed; `go vet` was right that the left side
			// is a self-assignment.
			if withPort := strings.TrimPrefix(resolved, "{{Hostname}}:"); withPort != resolved {
				port = withPort
				continue
			}
			if splitHost, splitPort, splitErr := net.SplitHostPort(resolved); splitErr == nil {
				hostName, port = splitHost, splitPort
				continue
			}
			hostName = resolved
		}
	}
	if block.TcpPort > 0 {
		port = strconv.Itoa(block.TcpPort)
	}
	if hostName == "" {
		return "", "", "the block names no host and the run's target has none"
	}
	return hostName, port, ""
}

// converse performs one block's inputs over one connection and returns everything
// that came back, plus the text of each read step under the name matchers use.
func converse(ctx context.Context, host, port string, block passiveRequest) (string, map[string]string, string) {
	dialer := &net.Dialer{Timeout: tcpDialTimeout}
	var connection net.Conn
	var err error
	if block.TcpTLS {
		connection, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port),
			&tls.Config{ServerName: host})
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		return "", nil, "cannot connect: " + oneLine(err.Error())
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	transcript := &strings.Builder{}
	names := map[string]string{}
	stepIndex := 0
	truncated := false
	for _, input := range block.TcpInputs {
		if err := ctx.Err(); err != nil {
			return transcript.String(), names, "the conversation was cancelled: " + oneLine(err.Error())
		}
		if input.Data != "" {
			written := expandDynamic(input.Data, mustParseTarget(schemeHost(host, port)), nil)
			if _, writeErr := connection.Write([]byte(written)); writeErr != nil {
				return transcript.String(), names, "cannot write to the connection: " + oneLine(writeErr.Error())
			}
			transcript.WriteString("> " + printable(written))
		}
		if input.Read <= 0 {
			continue
		}
		stepIndex++
		read, readErr := readSome(connection, input.Read)
		if readErr != nil && len(read) == 0 {
			return transcript.String(), names, fmt.Sprintf(
				"read %d of step %d got nothing: %s", input.Read, stepIndex, oneLine(readErr.Error()))
		}
		text := string(read)
		transcript.WriteString(text)
		// Two names per read, because the corpus uses both: the numbered step
		// (`ehlo`, `help`) and the bare part. Which is which is not knowable from
		// the document, so both resolve to the same text.
		names[fmt.Sprintf("step%d", stepIndex)] = text
		names[fmt.Sprintf("step_%d", stepIndex)] = text
		if transcript.Len() >= tcpExchangeMaxBytes {
			truncated = true
			break
		}
	}
	if truncated {
		transcript.WriteString("\n[conversation truncated at this project's transcript limit]")
	}
	return transcript.String(), names, ""
}

// readSome reads up to `want` bytes, returning whatever arrived before the
// deadline rather than failing the whole conversation on a short read.
//
// A banner that arrives in three TCP segments is normal, and a template that waited
// for `read: 1024` to be satisfied in full would refuse every service that greets in
// pieces.
func readSome(connection net.Conn, want int) ([]byte, error) {
	if want > tcpExchangeMaxBytes {
		want = tcpExchangeMaxBytes
	}
	_ = connection.SetReadDeadline(time.Now().Add(tcpReadTimeout))
	buffer := make([]byte, want)
	read, err := connection.Read(buffer)
	if read == 0 && err != nil {
		return nil, err
	}
	return buffer[:read], nil
}

// scoreTcpBlock judges the conversation with the same operators a response goes
// through.
func scoreTcpBlock(document *passiveDocument, block passiveRequest, transcript string, names map[string]string) PassiveMatch {
	parts := map[string]string{
		"raw":      transcript,
		"body":     transcript,
		"data":     transcript,
		"response": transcript,
	}
	for name, value := range names {
		parts[name] = value
	}
	exchange := PassiveExchange{
		Method:      "TCP",
		URL:         "tcp://" + mustParseTarget(schemeHost("localhost", "0")).Host,
		Host:        "localhost",
		RawRequest:  transcriptRequest("", "", block),
		RawResponse: transcript,
		Body:        transcript,
		StatusCode:  0,
		Parts:       parts,
	}
	return scoreCompiled(document, block, exchange)
}

// transcriptRequest shows the conversation's own inputs, because a verdict without
// the bytes that produced it is not evidence.
func transcriptRequest(host, port string, block passiveRequest) string {
	if host != "" {
		host = host + ":" + port
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "TCP %s\n", host)
	for _, input := range block.TcpInputs {
		if input.Data != "" {
			fmt.Fprintf(&builder, "> %s\n", printable(input.Data))
		}
		if input.Read > 0 {
			fmt.Fprintf(&builder, "  read %d bytes\n", input.Read)
		}
	}
	return builder.String()
}

// printable turns the escapes a template writes into the bytes it means, so the
// transcript shows what actually went on the wire rather than the source spelling.
func printable(text string) string {
	replacer := strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t", `\x00`, "\x00")
	return replacer.Replace(text)
}

func schemeHost(host, port string) string {
	return "http://" + host + ":" + port
}
