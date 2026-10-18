package active

// Base64Parameter asks whether a parameter's base64 is decoded before it is used.
//
// Burp's check is `0x00700200` (Base64-encoded data in parameter). The check is
// not "this parameter looks like base64" — a great many values are base64 of
// something ordinary — but "this parameter's *decoded* value is what the
// application reads", which is a materially different injection point: what a
// payload has to survive is an encoding layer, and an escaping decision made on
// the encoded form never sees the decoded one.
//
// The measurement is therefore insertion **inside** the encoded region rather
// than next to it. The run takes the value the surface already carries, decodes
// it, puts a canary in the middle, re-encodes it and sends that. The canary in
// the response is proof the value travelled through a decoder, because a server
// that read the base64 as text would echo the base64 — where the canary is not
// readable — and a server that ignored the parameter altogether would echo
// neither.
//
// The control is the run's own baseline rather than a second probe: `Fresh`
// compares against what the page already said, so a canary that is already on
// the page disqualifies the row instead of confirming it.

import (
	"context"
	"encoding/base64"
	"strings"
)

// Base64Parameter is the encoded-parameter probe.
type Base64Parameter struct{}

// Name implements Module.
func (Base64Parameter) Name() string { return "base64-param" }

// Level implements Module.
func (Base64Parameter) Level() Level { return LevelParam }

// base64ParamCanary is the token inserted into the decoded half. It is fixed for
// the reason `urlOverrideCanary` is fixed and is asserted for by the same test.
const base64ParamCanary = "rrb64canary"

// base64ParamMinLen is the shortest value this module will decode. A one- or
// two-character value decodes to nothing, and a probe whose insertion point is
// an empty string measures the transport rather than the application.
const base64ParamMinLen = 8

// Scan inserts a canary into the parameter's decoded value and reports whether
// the application reads the decoded form.
func (Base64Parameter) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if p.Values == nil || p.Param == "" {
		return nil
	}
	value := strings.TrimSpace(p.Values.Get(p.Param))
	if len(value) < base64ParamMinLen {
		return nil
	}
	decoded, ok := base64DecodesToText(value)
	if !ok {
		return nil
	}

	// The canary is fixed, and that is deliberate: a finding's identity hashes
	// its payload, so a random canary would make two runs of the same target
	// produce two different reports — which is what
	// `TestScanReportIsDeterministic` refuses. What the canary needs is
	// *freshness against this page*, which `Fresh` measures below, not
	// randomness the target has never seen the value of.
	canary := base64ParamCanary
	// The canary goes into the middle of the decoded value, before a character
	// the decoding is likely to tolerate, so the re-encoded form stays a valid
	// base64 string of a different length rather than nonsense.
	insertAt := len(decoded) / 2
	rewritten := decoded[:insertAt] + canary + decoded[insertAt:]

	reencoded, err := encodeLikeSource(value, rewritten)
	if err != nil || reencoded == "" {
		return nil
	}
	resp, err := t.Fire(ctx, p, p.Param, reencoded, false, nil)
	if err != nil || resp == nil {
		return nil
	}
	if !Fresh(baseline, resp, canary) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "base64-param",
		Title:    "Base64-Encoded Parameter Decoded by the Server",
		Claimed:  SeverityLow,
		Tier:     TierVerified,
		Point:    p,
		Payload:  reencoded,
		Evidence: "sent `" + aspTruncate(reencoded, 64) + "`; the decoded value carries " + canary + " and the response carries it fresh",
		Description: "The parameter `" + p.Param + "` arrives base64-encoded and the server " +
			"decodes it before use: a value this run inserted into the decoded half came back " +
			"in the response. The application therefore reads a representation the " +
			"transport does not show, so an escaping or validation decision taken on the " +
			"encoded form never sees the value the page actually renders, and any payload it " +
			"held has already survived one decode step.",
		Remediation: "Validate after decoding, not before: parse the parameter, check the " +
			"decoded structure, and encode at the point of output. Treat the encoded form as a " +
			"transport detail with no security meaning of its own.",
	})
	return []Finding{finding}
}

// base64DecodesToText reports whether a value is base64 that decodes to
// something a reader would call text.
//
// Both the standard and the URL alphabet are tried because a parameter that
// carries a URL is usually encoded with `-` and `_`. A value that decodes to
// binary is not a decoding error and is still a decoding — so the probe accepts
// it — but its insertion point is then invisible, and a row reporting it would
// be a row about a value the response can never show.
func base64DecodesToText(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if _, err := base64.StdEncoding.DecodeString(trimmed); err != nil {
		if _, err := base64.URLEncoding.DecodeString(trimmed); err != nil {
			// Two attempts failing is not a base64 value. A run that padded and
			// retried would report on values that are not base64 at all.
			return "", false
		}
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
			if isPrintableText(decoded) {
				return string(decoded), true
			}
			return "", false
		}
	}
	return "", false
}

// isPrintableText reports whether a byte slice is text a reader would call
// printable, which is what makes a canary inside it observable.
func isPrintableText(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	printable := 0
	for _, b := range raw {
		switch {
		case b == '\t' || b == '\n' || b == '\r':
		case b >= 0x20 && b < 0x7f:
			printable++
		case b >= 0x80:
			// A UTF-8 continuation or lead byte is text as well, and a value
			// that is base64 of UTF-8 is base64 of text.
			printable++
		default:
			return false
		}
	}
	return printable >= len(raw)/2
}

// encodeLikeSource re-encodes a rewritten value in the same alphabet the source
// used, so the request differs from the original only in the decoded content.
func encodeLikeSource(original, rewritten string) (string, error) {
	switch {
	case strings.ContainsAny(original, "-_"):
		return base64.URLEncoding.EncodeToString([]byte(rewritten)), nil
	default:
		return base64.StdEncoding.EncodeToString([]byte(rewritten)), nil
	}
}
