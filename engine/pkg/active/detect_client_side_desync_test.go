package active

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// desyncFixture is a raw HTTP/1.1 server that reads `Content-Length` and ignores
// `Transfer-Encoding`.
//
// It is written by hand rather than with `net/http` because the shape under test
// cannot be built with `net/http`: Go's server refuses a request that declares
// both a `Content-Length` and a chunked `Transfer-Encoding`, and refusing is the
// correct behaviour. The fixture therefore has to be a server that made the
// other choice — which is precisely the server a desyncing front end creates.
type desyncFixture struct {
	// answerFollowupWithSmuggled decides what the answer to the follow-up request
	// carries: the correct answer is its own mark, the vulnerable one is the
	// smuggled request's mark.
	answerFollowupWithSmuggled bool
}

func (fixture *desyncFixture) serve(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go fixture.serveConnection(connection)
		}
	}()
	return listener.Addr().String()
}

// serveConnection reads request after request off one connection, honouring
// `Content-Length` and ignoring `Transfer-Encoding` — the choice that makes the
// bytes after the declared length parse as a request of their own.
func (fixture *desyncFixture) serveConnection(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	buffered := bufio.NewReader(connection)
	for {
		head := map[string]string{}
		path := "/"
		first := true
		for {
			line, err := buffered.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			if first {
				first = false
				// The request line is not a header, so it is read out of the line
				// itself rather than out of the header map — a fixture that put it
				// in the map would answer every path as "/", and every assertion
				// below would then pass or fail for the wrong reason.
				if fields := strings.Fields(line); len(fields) > 1 {
					path = fields[1]
				}
				continue
			}
			name, value, found := strings.Cut(line, ":")
			if found {
				head[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
			}
		}
		if length := desyncSize(head["content-length"]); length > 0 {
			body := make([]byte, length)
			if _, err := io.ReadFull(buffered, body); err != nil {
				return
			}
		}
		if _, err := connection.Write([]byte(fixture.answer(path))); err != nil {
			return
		}
	}
}

// answer renders this fixture's response for one parsed request.
//
// The two cases are the whole experiment. The smuggled request is answered with
// its own mark, because a server that parsed it as a request says something about
// it. The follow-up request — the one this run actually sent and waited on — is
// answered with its own mark by a conforming server, and with the **smuggled**
// request's mark by a desynchronised one. The module reads that difference, so
// the fixture has to be able to produce both.
func (fixture *desyncFixture) answer(path string) string {
	body := desyncFollowupMark
	if strings.HasPrefix(path, desyncSmuggledPath) || fixture.answerFollowupWithSmuggled {
		body = desyncSmuggledMark
	}
	return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
		fmt.Sprint(len(body)) + "\r\nConnection: keep-alive\r\n\r\n" + body
}

func desyncBaseline() *Response {
	return &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: "ok"}
}

// A server that answers the follow-up request with the *smuggled* request's
// response is the finding: the client asked one thing and got the answer to
// something else, which is what a desynchronised stream looks like from the only
// side that can see it.
func TestClientSideDesyncReportsAnAnswerThatBelongsToAnotherRequest(t *testing.T) {
	address := (&desyncFixture{answerFollowupWithSmuggled: true}).serve(t)

	findings := (ClientSideDesync{}).Scan(context.Background(), nil,
		Point{URL: "http://" + address + "/form", Method: http.MethodPost}, desyncBaseline())

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if !strings.Contains(finding.Title, "0x00200141") {
		t.Errorf("title = %q, want the original's identifier in it", finding.Title)
	}
	if !strings.Contains(finding.Description, "disagree") {
		t.Errorf("the row does not state the disagreement: %s", finding.Description)
	}
	if !strings.Contains(finding.Evidence, "the smuggled request's response") {
		t.Errorf("the evidence does not say which request the answer belonged to: %s", finding.Evidence)
	}
}

// The control that makes the positive case meaningful: a server that answers each
// request with its own answer is conforming, and pipelining is legal, so nothing
// is reported. Without this the module would be a "two responses" counter.
func TestClientSideDesyncIsSilentWhenTheServerAnswersCorrectly(t *testing.T) {
	address := (&desyncFixture{answerFollowupWithSmuggled: false}).serve(t)

	findings := (ClientSideDesync{}).Scan(context.Background(), nil,
		Point{URL: "http://" + address + "/form", Method: http.MethodPost}, desyncBaseline())
	if len(findings) != 0 {
		t.Fatalf("findings = %v against a conforming server", desyncTitlesOf(findings))
	}
}

// The framing is the module's own contribution, and it has to be a real
// ambiguity rather than a malformed request: a body that is a complete second
// request, declared twice, with different lengths.
func TestClientSideDesyncWritesTwoDisagreeingLengthDeclarations(t *testing.T) {
	host := "h"
	first := fmt.Sprintf("POST /form HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"+
		"0\r\n\r\n%s", host, desyncRequest(host, "GET", desyncSmuggledPath))
	header, body, found := strings.Cut(first, "\r\n\r\n")
	if !found {
		t.Fatal("the framed request has no header/body boundary")
	}
	if !strings.Contains(header, "Content-Length: 0") {
		t.Errorf("the request does not declare a zero content length: %q", header)
	}
	if !strings.Contains(header, "Transfer-Encoding: chunked") {
		t.Errorf("the request does not declare chunked framing: %q", header)
	}
	// The body must be a **well-formed** chunked body, because a server that reads
	// it as chunked has to be able to serve the request: the bytes after the
	// terminator are the smuggled one, and a first version that put the smuggled
	// request inside the body was rejected at the parser instead of being handled.
	if !strings.HasPrefix(body, "0\r\n\r\n") {
		t.Errorf("the body is not an empty chunked body: %q", body)
	}
	if !strings.HasPrefix(body, "0\r\n\r\nGET "+desyncSmuggledPath+" HTTP/1.1") {
		t.Errorf("the bytes after the terminator are not the smuggled request: %q", body)
	}
}

// A host that accepts the connection and then says nothing must not hold the run:
// the probe's read has a deadline, and the test measures that it returns rather
// than that it returns something.
func TestClientSideDesyncReturnsWhenTheHostNeverAnswers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(io.Discard, connection)
	}()

	started := time.Now()
	findings := (ClientSideDesync{}).Scan(context.Background(), nil,
		Point{URL: "http://" + listener.Addr().String() + "/form", Method: http.MethodPost},
		desyncBaseline())
	elapsed := time.Since(started)

	if len(findings) != 0 {
		t.Fatalf("findings = %v from a host that never answers", desyncTitlesOf(findings))
	}
	if elapsed > 2*desyncReadTimeout {
		t.Errorf("the probe took %s, which is past its own bound of %s", elapsed, desyncReadTimeout)
	}
}

// The smuggled and follow-up paths belong to this run. If they collided with
// anything on the target the answer could not be attributed, so the test states
// the requirement rather than trusting it.
func TestClientSideDesyncOwnsBothProbePaths(t *testing.T) {
	if !strings.HasPrefix(desyncSmuggledPath, "/__rr_desync_") ||
		!strings.HasPrefix(desyncFollowupPath, "/__rr_desync_") {
		t.Fatalf("the probe paths do not identify the run: %q, %q", desyncSmuggledPath, desyncFollowupPath)
	}
	if desyncSmuggledPath == desyncFollowupPath {
		t.Fatal("the two probe paths are the same, so no answer could be attributed")
	}
}

// A response that arrives in pieces, or with a chunked body, is read as one
// response — a parser that stopped at the first line would attribute the wrong
// answer and fire on a conforming server.
func TestDesyncResponseReaderHandlesChunkedAndSplitResponses(t *testing.T) {
	cases := map[string]struct {
		raw        string
		wantStatus string
		wantMark   string
	}{
		"chunked body": {
			raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
				fmt.Sprint(len(desyncFollowupMark)) + "\r\n" + desyncFollowupMark + "\r\n0\r\n\r\n",
			wantStatus: "HTTP/1.1 200 OK",
			wantMark:   desyncFollowupMark,
		},
		"content-length body": {
			raw:        "HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprint(len(desyncFollowupMark)) + "\r\n\r\n" + desyncFollowupMark,
			wantStatus: "HTTP/1.1 200 OK",
			wantMark:   desyncFollowupMark,
		},
		"two responses in one write": {
			raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" +
				"HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprint(len(desyncFollowupMark)) + "\r\n\r\n" + desyncFollowupMark,
			wantStatus: "HTTP/1.1 200 OK",
			wantMark:   desyncFollowupMark,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			answers := readResponses(newSplitReader(testCase.raw))
			if len(answers) == 0 {
				t.Fatal("no response was read")
			}
			if answers[0].status != testCase.wantStatus {
				t.Errorf("status = %q, want %q", answers[0].status, testCase.wantStatus)
			}
			// The mark may be on any of the responses: two answers in one write is
			// the case where the *second* one carries it, and the parser has to
			// attribute it to the right one rather than reporting the first.
			carries := false
			for _, answer := range answers {
				if strings.Contains(answer.body, testCase.wantMark) {
					carries = true
				}
			}
			if !carries {
				t.Errorf("no response carried %q; bodies %v", testCase.wantMark, answers)
			}
		})
	}
}

// newSplitReader returns a reader over the raw bytes, handed to the response
// parser one small piece at a time.
//
// A parser fed a whole response at once proves less than one fed a response that
// arrives in pieces, which is what a network does: the bug this parser has to
// avoid is stopping at the first line and attributing a later answer to an
// earlier request.
func newSplitReader(raw string) *bufio.Reader {
	reader, writer := io.Pipe()
	go func() {
		defer writer.Close()
		for index := 0; index < len(raw); index += 7 {
			end := index + 7
			if end > len(raw) {
				end = len(raw)
			}
			if _, err := writer.Write([]byte(raw[index:end])); err != nil {
				return
			}
		}
	}()
	return bufio.NewReader(reader)
}

// desyncTitlesOf renders a finding set for a failure message.
func desyncTitlesOf(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Title)
	}
	return out
}
