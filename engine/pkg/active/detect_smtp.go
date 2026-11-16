package active

// SMTPInjection probes the one path in an application that turns a parameter
// value into a protocol the application does not speak itself: the mail it
// sends.
//
// Burp files two checks here, `0x00200800` SMTP header injection and `0x00300220`
// external service interaction (SMTP). The register recorded both as
// "SMTP is not HTTP" and that was accurate about the *protocol* and wrong about
// the *check*: what an HTTP client can observe is not a sent mail, it is the
// application's own account of what its mail layer did with the value. When a
// server passes an unsanitized value to `mail()`, `sendmail()` or an SMTP relay
// and the relay objects, the object is usually in the response body — as a
// status line, as a bounce, or as a PHP/Perl/Java warning that quotes the command
// it tried. That text is a fact about the application, it is readable over HTTP,
// and it is the difference between "this parameter is not mail-related" and "this
// parameter is concatenated into a mail command".
//
// # What is proven and what is not
//
// Proven: the application's mail layer received a value containing a line break
// the client supplied, and the layer rejected or mis-parsed it. That is header
// injection whether or not the injected header took effect.
//
// Not proven, and not claimed: that a mail was delivered, that it went to a third
// party, or that an attacker received it. Those need an SMTP listener and a
// mailbox, and this run has neither. A row that implied delivery would be a
// guess, and the register would then be claiming a capability the scanner does
// not have.
//
// # Why the SMTP-interaction row is not the same row twice
//
// `0x00300220` is about the application *reaching* an external service, and the
// evidence for it is different in kind: the value appears inside a message the
// transport assembled, which is the moment the application talked to something
// outside itself. So the second row fires only when the quoted text carries the
// command the application built (`RCPT TO`, `MAIL FROM`, the relay host), not on
// a bare status code. A generic relay rejection is the header-injection row; a
// quoted command is both.
//
// # Why this does not guess which parameters are mail-related
//
// The parameter names are checked against a list, and a parameter that is not on
// it is not probed. That is not a scope rule and it is not a restriction on
// what the target may be: it is a cost decision, stated here because it is
// visible in the report's request count. Sending a CRLF at every parameter of
// every form is a mail-bomb risk against a real contact form, and the names that
// carry mail are a small, readable, testable list.

import (
	"context"
	"strings"
)

// SMTPInjection is the mail-layer reader.
type SMTPInjection struct{}

// Name implements Module.
func (SMTPInjection) Name() string { return "smtp-injection" }

// Level implements Module.
//
// Parameter level, because the value is the argument: the check is about what a
// particular parameter's value does when it reaches the mail layer, and a
// parameter the operator never supplied has nothing to say about it.
func (SMTPInjection) Level() Level { return LevelParam }

// smtpParamNames are the parameter names this probe will send at.
//
// The list is a cost decision, not a scope rule: it bounds how many requests a
// contact form receives from a scan, and it is the reason the request count in
// the report is what it is. A name on the list can be probed whatever the target
// is, and a name off it is not probed at all — which is a limit of this detector,
// not a restriction on the target.
var smtpParamNames = map[string]bool{
	"mail": true, "email": true, "to": true, "from": true,
	"recipient": true, "recipients": true, "contact": true,
	"feedback": true, "notify": true,
	"addr": true, "address": true, "sender": true,
}

// smtpSuffixNames are the names a longer name may **end** with.
//
// Matching on a suffix is what makes `user_email`, `notify-email` and
// `contactemail` reach the same decision as `email`, and it is limited to names
// long enough to be distinctive: `to` is excluded from suffix matching on
// purpose, because every framework invents a parameter that ends in it.
var smtpSuffixNames = []string{
	"email", "mail", "recipient", "recipients", "sender", "address", "addr",
	"contact", "feedback", "notify",
}

// carriesMail reports whether a parameter's folded name is one this probe will
// send at.
func carriesMail(name string) bool {
	folded := normalisedParamName(name)
	if smtpParamNames[folded] {
		return true
	}
	for _, suffix := range smtpSuffixNames {
		if strings.HasSuffix(folded, suffix) {
			return true
		}
	}
	return false
}

// smtpProbes are the values sent, each carrying a line break and a line that
// only means something to an SMTP or a mail header parser.
//
// The break is written literally in the value rather than URL-encoded because the
// question is whether the application encodes it before handing the value to the
// mail layer; an encoded form would only prove the probe reached the server.
var smtpProbes = []string{
	"rr-smtp-probe@example.invalid\r\nBcc: rr-smtp-witness@example.invalid",
	"rr-smtp-probe@example.invalid\nBcc: rr-smtp-witness@example.invalid",
	"rr-smtp-probe@example.invalid\r\nSubject: rr-smtp-injected",
	"rr-smtp-probe@example.invalid\r\n\r\nrr-smtp-body",
}

// smtpEvidence is a phrase that only a mail layer produces.
//
// The phrases are grouped because the two rows read different ones: a transport
// phrase proves the application reached an SMTP service, and a generic rejection
// or quoting proves only that the value reached one.
type smtpEvidence struct {
	// phrase is what to look for, lower-case.
	phrase string
	// transport marks a phrase that names the SMTP conversation itself — the
	// command the application built, or the relay it talked to — rather than a
	// bare error about the value.
	transport bool
}

// smtpEvidencePhrases are the phrases, ordered so a transport phrase is found
// before a generic one when both are present.
var smtpEvidencePhrases = []smtpEvidence{
	{phrase: "mail from", transport: true},
	{phrase: "rcpt to", transport: true},
	{phrase: "smtp error from", transport: true},
	{phrase: "smtp server:", transport: true},
	{phrase: "smtp(", transport: true},
	{phrase: "sendmail(", transport: true},
	{phrase: "mail() failed", transport: true},
	{phrase: "unable to send mail", transport: true},
	{phrase: "could not send email", transport: true},
	{phrase: "unable to send email", transport: true},
	{phrase: "failed to send message", transport: true},
	{phrase: "550", transport: false},
	{phrase: "553", transport: false},
	{phrase: "554", transport: false},
	{phrase: "message or domain not found", transport: false},
	{phrase: "invalid recipient", transport: false},
	{phrase: "mailbox unavailable", transport: false},
	{phrase: "unrouteable address", transport: false},
	{phrase: "injection detected", transport: false},
	{phrase: "header injection", transport: false},
	{phrase: "newline in", transport: false},
	{phrase: "carriage return", transport: false},
}

// Scan sends a line break at every mail-shaped parameter and reads the answer.
func (SMTPInjection) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if p.Param == "" || !carriesMail(p.Param) {
		return nil
	}
	if baseline == nil || isPublicResource(p.URL) {
		return nil
	}

	var transportEvidence, genericEvidence *smtpEvidence
	var genericResponse *Response
	var genericProbe string

	for _, probe := range smtpProbes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, probe, false, nil)
		if err != nil || resp == nil {
			continue
		}
		if transportEvidence == nil {
			if match := smtpPhraseIn(resp); match != nil && match.transport {
				transportEvidence = match
			}
		}
		if genericEvidence == nil {
			if match := smtpPhraseIn(resp); match != nil && !match.transport {
				genericEvidence = match
				genericResponse = resp
				genericProbe = probe
			}
		}
		if transportEvidence != nil && genericEvidence != nil {
			break
		}
	}

	var out []Finding
	if transportEvidence != nil {
		out = append(out, smtpRow(p, transportEvidence.phrase, genericResponse, genericProbe,
			"0x00200800", SeverityHigh,
			"The application passed a value containing a line break to its mail layer, and the "+
				"layer answered about the SMTP conversation itself — \""+transportEvidence.phrase+
				"\" appears in the response. A recipient list, a subject or a body that ends at a "+
				"newline is a header the client chose, which is header injection: the client can "+
				"add headers, and through a recipient header it can add a recipient.",
			"Reject line breaks in every mail-header value. Validate the address against a "+
				"syntax the mail layer cannot be escaped out of, and build the message from "+
				"structured fields rather than by concatenating strings."))
		out = append(out, smtpRow(p, transportEvidence.phrase, genericResponse, genericProbe,
			"0x00300220", SeverityMedium,
			"The application used this parameter in a message it assembled for an external SMTP "+
				"service, and the transport quoted the command it built (\""+transportEvidence.phrase+
				"\"). The application therefore speaks SMTP on this path with data a client "+
				"supplied — the interaction with the outside service is the finding, and what it "+
				"carried is what the header-injection row above is about.",
			"Keep the SMTP conversation off the request path where a client can reach it: send "+
				"mail from a worker with a fixed envelope, and validate the client-supplied part "+
				"before it reaches the message builder."))
	}
	if genericEvidence != nil && transportEvidence == nil {
		out = append(out, smtpRow(p, genericEvidence.phrase, genericResponse, genericProbe,
			"0x00200800", SeverityMedium,
			"The application passed a value containing a line break to its mail layer, and the "+
				"layer rejected it with \""+genericEvidence.phrase+"\". A transport that refuses "+
				"the newline today refuses it because something upstream noticed; the value still "+
				"reached the mail layer unsanitized, and a relay that does not notice is one "+
				"configuration change away.",
			"Reject line breaks in every mail-header value before the message is assembled, rather "+
				"than relying on the relay to notice them."))
	}
	return out
}

// smtpRow renders one of the two mail rows.
func smtpRow(p Point, phrase string, resp *Response, probe, index string, severity Severity,
	description, remediation string) Finding {
	evidence := "the response quoted: " + phrase
	if resp != nil {
		evidence = "status: " + strings.TrimSpace(resp.Status) +
			"\nquoted: " + phrase +
			"\n" + Snippet(resp.Body, phrase, 200)
	}
	finding, _ := NewFinding(Spec{
		Module:  "smtp-injection",
		Title:   "SMTP " + smtpRowLabel(index) + ": " + index,
		Claimed: severity,
		Tier:    TierVerified,
		Point:   p,
		Payload: probe,
		Evidence: evidence +
			"\n\nNot proven here: that a message was delivered, or where it went. This run has no " +
			"SMTP listener and no mailbox, so it reports what the application said about its own " +
			"mail layer and stops there.",
		Description: description,
		Remediation: remediation,
	})
	return finding
}

// smtpRowLabel is the human half of the title.
func smtpRowLabel(index string) string {
	if index == "0x00300220" {
		return "External Service Interaction"
	}
	return "Header Injection"
}

// smtpPhraseIn returns the first evidence phrase the response carries.
//
// The search is over the body **and** the status, because a relay's rejection
// reaches an HTTP client in whichever of the two the application chose, and
// finding it in only one of them would make the detector's answer depend on the
// framework in use rather than on the behaviour.
func smtpPhraseIn(resp *Response) *smtpEvidence {
	haystack := strings.ToLower(resp.Body + "\n" + resp.Status)
	for index := range smtpEvidencePhrases {
		candidate := smtpEvidencePhrases[index]
		if strings.Contains(haystack, candidate.phrase) {
			return &candidate
		}
	}
	return nil
}

// normalisedParamName folds a parameter name to the form the name list uses:
// lower-case, with the separators a form library invents removed. `user_email`
// and `user-email` therefore reach the same decision as `email`.
func normalisedParamName(name string) string {
	var out strings.Builder
	for _, symbol := range strings.ToLower(strings.TrimSpace(name)) {
		switch symbol {
		case '_', '-', '.', '[', ']', ' ':
			continue
		}
		out.WriteRune(symbol)
	}
	return out.String()
}
