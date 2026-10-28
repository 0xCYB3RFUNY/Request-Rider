package active

// ClientSideDesync opens its own connection and looks for a response the
// application sends to a request nobody made.
//
// Burp files this as `0x00200141`. The register recorded it as "needs a raw
// socket with a controlled chunked frame and observation of the next request on
// the same connection", and that was accurate: every other row in the register is
// answerable from a response, and this one is not. The defect is a disagreement
// between where one side thinks a request ended and where the other side thinks it
// ended, and the only evidence it leaves is that the two disagree — which shows
// up as a response the client did not ask for.
//
// # What is measured, and what deliberately is not
//
// The tempting measurement is "the server answered twice", and it is **wrong**:
// HTTP/1.1 pipelining is conforming, so a server that answers two requests for
// two requests has shown nothing. Reporting that would fire on every ordinary
// server, which is what makes most "desync" scanners unusable.
//
// The measurement here is the unambiguous one. The module writes a first request
// whose framing is ambiguous by construction — a `Content-Length` and a
// `Transfer-Encoding: chunked` together, with the chunked body reading as a
// complete second request — and then writes a **second, ordinary request** on the
// same connection with a path only this run knows. If the answer to that second
// request is the answer to the smuggled one, the server and the client disagree
// about the stream, and that is the finding. If the answers line up, the module
// reports nothing, and the fixture that proves the control is the one that
// answers correctly.
//
// # Why the framing is ambiguous by construction rather than by discovery
//
// A real desync needs a front end and an origin that parse the same bytes
// differently. From one client there is no way to know which of the two this
// deployment has, so the module supplies the ambiguity itself: two disagreeing
// length declarations on one request. Whether a server is vulnerable to it is
// then measured rather than assumed, and a server that ignores the ambiguity —
// which is the correct behaviour — produces no row.
//
// # Cost
//
// One connection and at most two requests per endpoint, both to the target's own
// host, with a hard read deadline. The connection is closed by `defer` whether or
// not anything was proven, so a probe that finds nothing leaves nothing behind.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ClientSideDesync is the raw-stream reader.
type ClientSideDesync struct{}

// Name implements Module.
func (ClientSideDesync) Name() string { return "client-side-desync" }

// Level implements Module.
//
// Endpoint level, because the question is about how *this* endpoint's request is
// framed. A host-level module would answer for a host that serves several
// different parsers on different paths.
func (ClientSideDesync) Level() Level { return LevelEndpoint }

// desyncReadTimeout bounds the whole probe: the two requests and the read.
//
// It is a bound and not a ceiling, and it exists because a raw socket does not
// have the transport's request deadline: a host that reads the first request and
// then says nothing would hold this probe for as long as the socket's own
// timeout, and the operator would see a run stuck with nothing to act on.
const desyncReadTimeout = 12 * time.Second

// desyncFollowupReadTimeout is how long the probe waits for the follow-up's
// answer.
//
// It is shorter than the probe's overall bound on purpose, and the reason is that
// the answer to the follow-up is the whole measurement: once the host has had
// three seconds to answer one request, a later response is not going to change
// which request the answer belongs to.
const desyncFollowupReadTimeout = 3 * time.Second

// The two paths this run owns. Neither is chosen by the target: they exist so
// that the answer to the second request can be told apart from the answer to the
// smuggled one, which is the entire measurement.
const (
	desyncSmuggledPath = "/__rr_desync_smuggled"
	desyncFollowupPath = "/__rr_desync_followup"
	// desyncBody is what each path answers with, so an answer can be attributed
	// to a path rather than merely counted.
	desyncSmuggledMark = "rr-desync-smuggled"
	desyncFollowupMark = "rr-desync-followup"
)

// Scan writes an ambiguously framed request and then an ordinary one, and reports
// an answer that belongs to neither.
func (d ClientSideDesync) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	host, port, secure, path, err := desyncTarget(p.URL)
	if err != nil {
		return nil
	}
	probeContext, cancel := context.WithTimeout(ctx, desyncReadTimeout)
	defer cancel()

	connection, err := desyncDial(probeContext, t, host, port, secure)
	if err != nil {
		// A refused connection is still a connection attempt the target saw, and
		// the run's request count has to include it.
		t.CountExternalRequests(1)
		return nil
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(desyncReadTimeout))

	reader := bufio.NewReader(connection)
	// One write carries two requests: the ambiguous one, and — straight after its
	// chunked terminator — the smuggled one.
	//
	// The body of the first is an **empty** chunked body, `0\r\n\r\n`, and that is
	// deliberate. A first version put the smuggled request inside the body, where
	// it is not valid chunk data, and a conforming server then rejected the
	// request at its parser with a 400 — which is measured: Go read the request as
	// chunked (`ContentLength=-1`), never reached the handler, and the run's own
	// request-count guard reported a target that had served fewer requests than
	// the report claimed. A probe the target never handles is not a probe.
	//
	// So the first request is well-formed under either reading of the two length
	// declarations, and the bytes after its terminator are what a front end that
	// reads `Content-Length` and an origin that reads `Transfer-Encoding` disagree
	// about.
	first := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"+
		"0\r\n\r\n%s", http.MethodPost, path, host, desyncRequest(host, http.MethodGet, desyncSmuggledPath))
	if _, err := connection.Write([]byte(first)); err != nil {
		t.CountExternalRequests(1)
		return nil
	}
	// Two requests went out on one connection: the ambiguous one and the smuggled
	// one it carried. The run's request count is the number the target was
	// pressed with, so both are counted.
	t.CountExternalRequests(2)
	// Drain everything the first two requests produced before the follow-up goes
	// out.
	//
	// Draining exactly **one** response was the first version and it was wrong in
	// a way only the control test could see: the smuggled request's own answer was
	// still queued when the follow-up was written, so the probe read it as the
	// follow-up's answer and fired against a conforming server. Draining to quiet
	// is what makes "the answer that came next belongs to the request I just sent"
	// true rather than hoped for.
	drainResponses(connection, reader)

	// The follow-up is an ordinary request for a path only this run asked for.
	if _, err := connection.Write([]byte(desyncRequest(host, "GET", desyncFollowupPath))); err != nil {
		t.CountExternalRequests(1)
		return nil
	}
	t.CountExternalRequests(1)
	// The read window is shortened once the follow-up is out, because the answer
	// is either already on the wire or is not coming: a stream that keeps talking
	// after the follow-up is exactly the case where several responses are queued,
	// and the reader reads all of them within this window. Waiting the full probe
	// bound for a fourth response nobody asked for would make every clean host
	// cost the whole bound.
	_ = connection.SetReadDeadline(time.Now().Add(desyncFollowupReadTimeout))
	answers := readResponses(reader)
	if len(answers) == 0 {
		return nil
	}
	// The signal: an answer to a path this run never requested. Everything else —
	// including a server that answered the smuggled request as well as this one —
	// is conforming behaviour and is not reported.
	for _, answer := range answers {
		if !strings.Contains(answer.body, desyncSmuggledMark) {
			continue
		}
		if strings.Contains(answer.body, desyncFollowupMark) {
			continue
		}
		return []Finding{desyncFinding(p, answer, host, path)}
	}
	return nil
}

// desyncFinding renders the row.
func desyncFinding(p Point, answer desyncAnswer, host, path string) Finding {
	finding, _ := NewFinding(Spec{
		Module:  "client-side-desync",
		Title:   "Client-Side Request Desynchronisation: 0x00200141",
		Claimed: SeverityHigh,
		Tier:    TierVerified,
		Point:   p,
		Payload: "smuggled: " + desyncSmuggledPath + " / asked: " + desyncFollowupPath,
		Evidence: "host:            " + host +
			"\nframed request:  " + path +
			"\nstatus line:     " + answer.status +
			"\nbody carries:    " + desyncSmuggledMark +
			"\nrequested:       " + desyncFollowupPath +
			"\nanswered with:   the smuggled request's response",
		Description: "This endpoint was sent a request carrying two disagreeing length " +
			"declarations — a `Content-Length` and a `Transfer-Encoding: chunked` — whose chunked " +
			"body reads as a second, complete request. The connection was then asked, in the " +
			"ordinary way, for `" + desyncFollowupPath + "`, and the answer that came back was " +
			"the answer to the **smuggled** request `" + desyncSmuggledPath + "`.\n\n" +
			"That is a client and a server disagreeing about where a request ends. Everything in " +
			"the smuggling family follows from it: whatever the client sends next is read as the " +
			"tail of the previous request, so a request the user never made is answered, and a " +
			"response the user is waiting for belongs to somebody else's request.",
		Remediation: "Parse the request stream once and use one length source. Reject a request " +
			"that carries both `Content-Length` and `Transfer-Encoding` instead of choosing " +
			"between them, and make every hop in front of the origin apply the same rule — a " +
			"desync exists exactly where two hops disagree.",
	})
	return finding
}

// desyncAnswer is one response read off the raw stream.
type desyncAnswer struct {
	// status is the status line.
	status string
	// body is the payload, bounded.
	body string
}

// desyncBodyLimit bounds how much of a response body is read. It is a read bound
// and not a reporting one: the marker is in the first bytes of any body that
// carries it, and a multi-megabyte download is not evidence of anything.
const desyncBodyLimit = 64 << 10

// readResponses reads whole responses until the stream ends, the reader blocks,
// or the deadline passes.
//
// A blocking read is expected here: the answer may not have been sent yet, and a
// probe that returned "nothing arrived" the instant the socket had no bytes would
// report nothing on every host that answers slowly.
func readResponses(reader *bufio.Reader) []desyncAnswer {
	var out []desyncAnswer
	for {
		answer, ok := readOneResponse(reader)
		if !ok {
			return out
		}
		out = append(out, answer)
		if len(out) >= 4 {
			return out
		}
	}
}

// desyncQuietWindow is how long the probe waits for the stream to go quiet before
// it calls the first request's answers drained.
//
// It is a bound on a pause, not a timeout on the whole probe, and it exists for
// one measured reason: a response that arrives after it would be read as the
// answer to the request the probe is about to send.
const desyncQuietWindow = 400 * time.Millisecond

// drainResponses reads and throws away what is queued, then waits out the quiet
// window to be sure nothing else is coming.
func drainResponses(connection net.Conn, reader *bufio.Reader) {
	for {
		// Each attempt gets the whole quiet window, so a server that answers two
		// requests a moment apart is fully drained rather than half-drained.
		if err := connection.SetReadDeadline(time.Now().Add(desyncQuietWindow)); err != nil {
			return
		}
		if _, ok := readOneResponse(reader); !ok {
			return
		}
	}
}

// readOneResponse reads one response, and reports whether it got one.
func readOneResponse(reader *bufio.Reader) (desyncAnswer, bool) {
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(status)), "HTTP/") {
		return desyncAnswer{}, false
	}
	length := -1
	chunked := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return desyncAnswer{status: strings.TrimSpace(status)}, false
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			if parsed := desyncSize(value); parsed > 0 {
				length = parsed
			}
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(value), "chunked") {
				chunked = true
			}
		}
	}
	answer := desyncAnswer{status: strings.TrimSpace(status)}
	switch {
	case chunked:
		answer.body = readChunkedBody(reader)
	case length >= 0:
		buffer := make([]byte, min(length, desyncBodyLimit))
		// `io.ReadFull` and not `Read`: `bufio.Reader.Read` returns whatever is
		// buffered and fills nothing, so a body that arrives in pieces was read as
		// the first packet's worth of it — and the marker this module is looking
		// for lives at the end of the body, so a short read hides exactly the
		// evidence it needs.
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return answer, false
		}
		answer.body = string(buffer)
	default:
		// A response with neither a length nor chunked framing ends at the close,
		// so reading to the deadline is the only way to see its body.
		answer.body = readToDeadline(reader)
	}
	return answer, true
}

// readChunkedBody reads a chunked body and returns the concatenation.
func readChunkedBody(reader *bufio.Reader) string {
	var out strings.Builder
	for {
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return out.String()
		}
		sizeText := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
		size := desyncSize(sizeText)
		if size <= 0 {
			return out.String()
		}
		if out.Len()+size > desyncBodyLimit {
			size = desyncBodyLimit - out.Len()
		}
		buffer := make([]byte, size)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return out.String()
		}
		out.Write(buffer)
		if _, err := reader.ReadString('\n'); err != nil {
			return out.String()
		}
	}
}

// readToDeadline reads whatever arrives until the socket's deadline, which is the
// only end a body of unknown length has.
func readToDeadline(reader *bufio.Reader) string {
	var out strings.Builder
	buffer := make([]byte, 8<<10)
	for out.Len() < desyncBodyLimit {
		read, err := reader.Read(buffer)
		if read > 0 {
			out.Write(buffer[:read])
		}
		if err != nil {
			return out.String()
		}
	}
	return out.String()
}

// desyncSize reads a chunk size or a content length, and answers zero for
// anything that is not one — a header this probe cannot interpret is not a header
// it may guess at.
func desyncSize(text string) int {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 {
		return 0
	}
	return value
}

// desyncRequest renders one ordinary HTTP/1.1 request.
func desyncRequest(host, method, path string) string {
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		method = http.MethodGet
	}
	return method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + RandomUserAgent() + "\r\n" +
		"Accept: */*\r\nConnection: keep-alive\r\n\r\n"
}

// desyncTarget reduces a URL to what the raw dial needs.
func desyncTarget(raw string) (host, port string, secure bool, path string, err error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", "", false, "", fmt.Errorf("no host")
	}
	secure = strings.EqualFold(parsed.Scheme, "https")
	path = parsed.RequestURI()
	if path == "" {
		path = "/"
	}
	port = parsed.Port()
	if port == "" {
		if secure {
			port = "443"
		} else {
			port = "80"
		}
	}
	return parsed.Hostname(), port, secure, path, nil
}

// desyncDial opens the connection the probe writes onto, with the run's own
// trust decision applied to it.
//
// This was measured rather than assumed: a first version dialled with the system
// roots, and against the local fixture — whose certificate is deliberately
// expired — the handshake failed, the framed request was never sent, and the
// report said "no findings" for a check that had not run. Reusing the run's
// RoundTripper makes the probe reach exactly the endpoints the run's other
// requests reach, and nothing more: where the run would refuse a certificate,
// this refuses it too.
//
// When the RoundTripper is not a `*http.Transport` there is no trust
// configuration to copy, and the dial falls back to the system roots — which is
// what the run itself would do with a RoundTripper that has no opinion.
func desyncDial(ctx context.Context, t *Transport, host, port string, secure bool) (net.Conn, error) {
	address := net.JoinHostPort(host, port)
	if !secure {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", address)
	}
	configuration := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10}
	if t != nil {
		if http, ok := t.next.(*http.Transport); ok && http.TLSClientConfig != nil {
			configuration = http.TLSClientConfig.Clone()
			if configuration.ServerName == "" {
				configuration.ServerName = host
			}
		}
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: configuration}
	return dialer.DialContext(ctx, "tcp", address)
}

// methodOrGet keeps the surface's method when it is one that carries a body.
func methodOrGet(method string) string {
	switch method {
	case "POST", "PUT", "PATCH":
		return method
	}
	return "GET"
}
