package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// oobVectorFixture is an application that reaches whatever address it is handed,
// through each of the three roads the vectors use: a document it parses, a
// command line it runs, and a header it turns into a URL.
//
// Each road is a separate switch, because a detector that fired without its own
// road being present would be measuring the fixture rather than the check.
type oobVectorFixture struct {
	mu sync.Mutex
	// parsesXML makes the application parse the submitted value as XML.
	parsesXML bool
	// runsCommands makes the application run the submitted value as a command.
	runsCommands bool
	// followsHeaders makes the application fetch any URL it is sent in a header.
	followsHeaders bool
	// seen records what arrived, so a test can assert the probe reached the
	// application rather than only that a row appeared.
	seen []string
}

func (fixture *oobVectorFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// `ParseForm` rather than `r.URL.Query`: the probes submit by POST, and a
		// handler that read only the query string would see nothing and the whole
		// fixture would be measuring the wrong thing.
		_ = r.ParseForm()
		fixture.mu.Lock()
		value := r.Form.Get("xml")
		if value == "" {
			value = r.Form.Get("cmd")
		}
		if value == "" {
			for _, candidate := range r.Form {
				if len(candidate) > 0 && candidate[0] != "" {
					value = candidate[0]
				}
			}
		}
		fixture.seen = append(fixture.seen, value)
		parsesXML, runsCommands, followsHeaders := fixture.parsesXML, fixture.runsCommands, fixture.followsHeaders
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch {
		case parsesXML && strings.Contains(value, "<!ENTITY"):
			// A parser that resolves the entity fetches its system identifier.
			// The address is taken from the document, which is exactly the
			// behaviour the row is about.
			if identifier := oobBetween(value, `SYSTEM "`, `"`); identifier != "" {
				if fetched, err := (&http.Client{Timeout: 3 * time.Second}).Get(identifier); err == nil {
					fetched.Body.Close()
				}
			}
		case runsCommands && strings.ContainsAny(value, ";&|`"):
			// A command line is run through a shell, which is what makes the
			// payload's own metacharacters meaningful.
			runShellCommand(value)
		case followsHeaders:
			for _, name := range []string{"Referer", "X-Forwarded-For", "X-Original-Host"} {
				if target := r.Header.Get(name); strings.HasPrefix(target, "http") {
					if fetched, err := (&http.Client{Timeout: 3 * time.Second}).Get(target); err == nil {
						fetched.Body.Close()
					}
				}
			}
		}
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	t.Cleanup(server.Close)
	return server
}

func (fixture *oobVectorFixture) arrived() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]string(nil), fixture.seen...)
}

// oobBetween reads the text between two markers, or an empty string.
func oobBetween(text, open, close string) string {
	index := strings.Index(text, open)
	if index < 0 {
		return ""
	}
	rest := text[index+len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// runShellCommand runs a command line the way a shell would, without a shell.
//
// Each metacharacter-separated segment is executed on its own, which is enough to
// make `; curl …` reach the network while keeping the fixture out of the business
// of interpreting pipes and redirections. A first version dropped the program name
// with `fields[1:]` and then looked for `curl` in the arguments, so every segment
// whose program had flags before its URL — which is all of them — ran nothing.
func runShellCommand(value string) {
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == '|' || r == '&'
	}) {
		fields := strings.Fields(segment)
		for index := range fields {
			fields[index] = strings.Trim(fields[index], "();`'\"$")
		}
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		program := fields[0]
		if program == "nslookup" || program == "getent" {
			// A resolver is not available to a local fixture and the run's
			// evidence is the callback channel, not DNS; nothing to do here.
			continue
		}
		for _, argument := range fields[1:] {
			if strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://") {
				if fetched, err := (&http.Client{Timeout: 3 * time.Second}).Get(argument); err == nil {
					fetched.Body.Close()
				}
				break
			}
		}
	}
}

// newOASTFixture starts the out-of-band service and returns a client for it.
func newOASTFixture(t *testing.T) (*oastFixture, *OASTClient) {
	t.Helper()
	service := &oastFixture{}
	server := service.server(t)
	// The payload address has to be one the target in this test can actually
	// reach, so the service hands out **its own** address. A first version
	// returned the placeholder `canary.oast.example`, nothing resolved it, and
	// all three positive cases failed for a reason that had nothing to do with the
	// detectors — which is exactly the shape of a fixture that tests the network
	// instead of the code.
	service.domain = strings.TrimPrefix(server.URL, "http://")
	client, err := NewOASTClient(context.Background(),
		OASTSettings{ServerURL: server.URL, PollInterval: 10 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("NewOASTClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return service, client
}

func oobSurface(server *httptest.Server, param string) Point {
	return Point{URL: server.URL + "/submit", Method: http.MethodPost, Param: param,
		Values: map[string][]string{param: {"value"}}}
}

func oobBaseline() *Response {
	return &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body>ok</body></html>"}
}

// A document whose entity points at the watched address, and a parser that
// resolves it, is the XXE read primitive — and the callback is what separates it
// from a document that was merely accepted.
func TestOutOfBandXMLProvesACallbackFromAParsedEntity(t *testing.T) {
	service, client := newOASTFixture(t)
	fixture := &oobVectorFixture{parsesXML: true}
	server := fixture.server(t)

	findings := (outOfBandXML{client: client}).Scan(context.Background(), mustTransport(t),
		oobSurface(server, "xml"), oobBaseline())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the parser resolved the entity", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "<!ENTITY") {
		t.Errorf("payload = %q, want the submitted document", findings[0].Payload)
	}
	if !strings.Contains(findings[0].Description, "Not proven") {
		t.Errorf("the row does not say what it did not prove: %s", findings[0].Description)
	}
	_ = service
}

// The control: the same document, and an application that stores it without
// parsing it. Nothing is fetched, and "no callback" is the answer the row needs.
func TestOutOfBandXMLIsSilentWhenTheDocumentIsNotParsed(t *testing.T) {
	_, client := newOASTFixture(t)
	fixture := &oobVectorFixture{}
	server := fixture.server(t)

	findings := (outOfBandXML{client: client}).Scan(context.Background(), mustTransport(t),
		oobSurface(server, "xml"), oobBaseline())
	if len(findings) != 0 {
		t.Fatalf("findings = %d against an application that never parses", len(findings))
	}
	if len(fixture.arrived()) == 0 {
		t.Error("the document never reached the application, so the silence proves nothing")
	}
}

// A value that reaches a command line and makes it fetch the watched address is
// command execution, and the callback is what separates it from a parameter that
// merely looks like a command.
func TestOutOfBandCommandProvesACallbackFromTheCommandLine(t *testing.T) {
	_, client := newOASTFixture(t)
	fixture := &oobVectorFixture{runsCommands: true}
	server := fixture.server(t)

	findings := (outOfBandCommand{client: client}).Scan(context.Background(), mustTransport(t),
		oobSurface(server, "cmd"), oobBaseline())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the command reached a fetch", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q: a value that reached a shell is the top of the list",
			findings[0].Severity, SeverityCritical)
	}
	if len(fixture.arrived()) == 0 {
		t.Error("the command never reached the application, so the row proves nothing")
	}
}

// A header the application turns into a URL is the third road, and it is the only
// one that does not involve a parameter value at all.
func TestOutOfBandHeaderProvesACallbackFromAHeader(t *testing.T) {
	_, client := newOASTFixture(t)
	fixture := &oobVectorFixture{followsHeaders: true}
	server := fixture.server(t)

	findings := (outOfBandHeader{client: client}).Scan(context.Background(), mustTransport(t),
		Point{URL: server.URL + "/page", Method: http.MethodGet}, oobBaseline())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the header was turned into a fetch", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "Referer:") {
		t.Errorf("payload = %q, want the header that carried the address", findings[0].Payload)
	}
}

// The control: an application that ignores every header it is sent.
func TestOutOfBandHeaderIsSilentWhenNoHeaderIsUsed(t *testing.T) {
	_, client := newOASTFixture(t)
	fixture := &oobVectorFixture{}
	server := fixture.server(t)

	findings := (outOfBandHeader{client: client}).Scan(context.Background(), mustTransport(t),
		Point{URL: server.URL + "/page", Method: http.MethodGet}, oobBaseline())
	if len(findings) != 0 {
		t.Fatalf("findings = %d against an application that uses no header", len(findings))
	}
}

// The four detectors are registered by pointer, because a value-registered one is
// handed a copy of the client and the assignment disappears. This is the guard
// against that, and it exists because the first version registered them as values
// and three detectors were silently clientless for a whole run.
func TestEveryOutOfBandDetectorIsRegisteredByPointer(t *testing.T) {
	byPointer := map[string]int{}
	for _, module := range AllModules() {
		switch module.(type) {
		case *OutOfBand, *outOfBandXML, *outOfBandCommand, *outOfBandHeader:
			byPointer[module.Name()]++
		case OutOfBand, outOfBandXML, outOfBandCommand, outOfBandHeader:
			t.Errorf("%s is registered by value; shareOutOfBand writes to a copy", module.Name())
		}
	}
	for _, name := range []string{"out-of-band", "out-of-band-xml", "out-of-band-cmd", "out-of-band-header"} {
		if byPointer[name] != 1 {
			t.Errorf("%s is registered by pointer %d time(s), want exactly 1", name, byPointer[name])
		}
	}
}

// The payload shapes cover the shells the original distinguishes, and the DNS form
// is among them because a resolver is the shortest way for a target to reach a
// name it was given.
func TestOutOfBandCommandPayloadsCoverTheShells(t *testing.T) {
	payloads := oobCommandPayloads("canary.oast.example")
	joined := strings.Join(payloads, "\n")
	for _, marker := range []string{"curl", "wget", "nslookup", "$(", "`"} {
		if !strings.Contains(joined, marker) {
			t.Errorf("no payload covers %q; got %v", marker, payloads)
		}
	}
}
