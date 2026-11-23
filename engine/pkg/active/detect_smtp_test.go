package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// smtpFixture is an application whose mail layer quotes what it was given. It is
// the shape the check reads: the value reached the mail transport, and the
// transport's objection came back in the response.
type smtpFixture struct {
	mu       sync.Mutex
	received []string
	// answer is what the mail layer says. It is set by the test rather than
	// hard-coded, because the two rows read different phrases and a fixture that
	// always said the same thing could only prove one of them.
	answer string
}

func (fixture *smtpFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		value := r.Form.Get("email")
		fixture.mu.Lock()
		// The header-injection shape: the transport received the whole value
		// rather than the address alone, so a line break is in what it was given.
		fixture.received = append(fixture.received, value)
		answer := fixture.answer
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><p>" + answer + "</p></body></html>"))
	}))
	t.Cleanup(server.Close)
	return server
}

func (fixture *smtpFixture) values() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]string(nil), fixture.received...)
}

func (fixture *smtpFixture) sawLineBreak() bool {
	for _, value := range fixture.values() {
		if strings.ContainsAny(value, "\r\n") {
			return true
		}
	}
	return false
}

func smtpSurface(server *httptest.Server, param string) Point {
	return Point{
		URL:    server.URL + "/contact",
		Method: http.MethodPost,
		Param:  param,
		Values: map[string][]string{param: {"visitor@example.invalid"}},
	}
}

func smtpBaseline() *Response {
	return &Response{StatusCode: 200,
		Header: http.Header{"Content-Type": {"text/html"}},
		Body:   "<html><body><p>Thank you.</p></body></html>"}
}

// The transport quoting the command it built is the strongest evidence there is
// from inside an HTTP client, and it produces both rows: the interaction with the
// outside service, and the header injection inside the message.
func TestSMTPInjectionReportsBothRowsWhenTheTransportQuotesTheCommand(t *testing.T) {
	fixture := &smtpFixture{answer: `SMTP error from remote mail server: 550 5.1.1 <a@b>: Recipient address rejected` +
		`<br>while sending MAIL FROM:<&lt;visitor@example.invalid&gt;&gt;`}
	server := fixture.server(t)

	findings := (SMTPInjection{}).Scan(context.Background(), mustTransport(t),
		smtpSurface(server, "email"), smtpBaseline())

	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2: %v", len(findings), smtpTitlesOf(findings))
	}
	var header, interaction Finding
	for _, finding := range findings {
		switch {
		case strings.Contains(finding.Title, "0x00200800"):
			header = finding
		case strings.Contains(finding.Title, "0x00300220"):
			interaction = finding
		}
	}
	if header.Title == "" || interaction.Title == "" {
		t.Fatalf("one of the two rows is missing; got %v", smtpTitlesOf(findings))
	}
	if !fixture.sawLineBreak() {
		t.Error("the probe did not reach the transport with a line break, so nothing was proven")
	}
	if !strings.Contains(header.Evidence, "Not proven here") {
		t.Errorf("the row does not name what it did not prove: %s", header.Evidence)
	}
	if !strings.Contains(header.Description, "header injection") {
		t.Errorf("the header-injection row does not say what the injection enables: %s", header.Description)
	}
}

// A bare rejection is a weaker thing than a quoted command: it proves the value
// reached the mail layer and was refused, not what the layer built. Only the
// header-injection row may fire on it — reporting the interaction row there would
// claim the application talked SMTP on this path when the evidence does not say so.
func TestSMTPInjectionReportsOnlyHeaderInjectionOnABareRejection(t *testing.T) {
	fixture := &smtpFixture{answer: "550 5.1.1 Message or domain not found"}
	server := fixture.server(t)

	findings := (SMTPInjection{}).Scan(context.Background(), mustTransport(t),
		smtpSurface(server, "email"), smtpBaseline())

	if len(findings) != 1 || !strings.Contains(findings[0].Title, "0x00200800") {
		t.Fatalf("findings = %v, want only the header-injection row", smtpTitlesOf(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want the lower of the two rows: a bare rejection proves less",
			findings[0].Severity)
	}
}

// The control: an application that sends no mail and says nothing about mail. A
// CRLF probe against it is a CRLF probe against a contact form, and the row has
// to stay silent.
func TestSMTPInjectionIsSilentWhenNothingMentionsMail(t *testing.T) {
	fixture := &smtpFixture{answer: "Thank you, we will be in touch."}
	server := fixture.server(t)

	findings := (SMTPInjection{}).Scan(context.Background(), mustTransport(t),
		smtpSurface(server, "email"), smtpBaseline())
	if len(findings) != 0 {
		t.Fatalf("findings = %v, want none", smtpTitlesOf(findings))
	}
}

// A parameter that does not carry mail is not probed. That is a cost decision
// about this detector and not a restriction on the target, and the test names it
// as such: it must be possible to see that the parameter list is the only thing
// that was skipped.
func TestSMTPInjectionDoesNotProbeParametersThatDoNotCarryMail(t *testing.T) {
	fixture := &smtpFixture{answer: "SMTP error from remote mail server: 550 rejected"}
	server := fixture.server(t)

	findings := (SMTPInjection{}).Scan(context.Background(), mustTransport(t),
		smtpSurface(server, "message"), smtpBaseline())
	if len(findings) != 0 {
		t.Fatalf("findings = %v, want none for a parameter that carries no mail", smtpTitlesOf(findings))
	}
	if len(fixture.values()) != 0 {
		t.Errorf("the parameter was probed anyway: %v", fixture.values())
	}
}

// The name list is the detector's only cost bound, so it has to fold the
// separators a form library invents rather than match one spelling.
func TestSMTPParamNameFoldingReachesTheSameDecision(t *testing.T) {
	for _, name := range []string{"email", "Email", "user_email", "user-email", " user.email "} {
		if !carriesMail(name) {
			t.Errorf("%q did not fold onto a mail name", name)
		}
	}
	// A framework-invented parameter that merely ends in two letters must not
	// reach the probe: `to` is excluded from suffix matching for this reason.
	for _, name := range []string{"message", "page", "id", "photo", "auto"} {
		if carriesMail(name) {
			t.Errorf("%q folded onto a mail name", name)
		}
	}
}

// smtpTitlesOf renders a finding set for a failure message.
func smtpTitlesOf(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Title)
	}
	return out
}
