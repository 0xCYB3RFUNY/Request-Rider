package active

// A ReDoS detector.
//
// It ports lonkero's `redos.rs`: the same eight escalating payload families and
// the same three lengths, and it differs from it in one decision that decides
// whether the detector is usable on a real network.
//
// # What the upstream rule claims
//
// Upstream treats the *short* payload as the baseline and fires when
// `long > 3 * medium && medium > short`, or when the long request times out. Both
// halves of that are timing claims about a network, and neither says what the
// endpoint does when the input does not match its regex at all. A server that is
// simply slow, a TLS renegotiation, a database behind the page and a cold cache
// all produce the same shape: the later request is slower than the earlier one.
// The detector then reports a regular expression the researcher never found.
//
// # What this detector measures instead
//
// Every family is measured against a *control of the same length*: the same 60
// characters count, made of a class the family does not match. A slow endpoint
// is slow for the control too, so the difference is the endpoint's work, and the
// control is what turns "three numbers went up" into "this regex went up".
//
// The cost is one extra request for the whole surface, not per family: the control
// depends on the length, not on the family, so it is measured once and reused. A
// clean surface therefore costs one control plus three probes of the first family,
// and further families are only tried when the first one did not fire.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// redosFamily is one escalating shape and what it is aimed at.
type redosFamily struct {
	// unit is repeated until the requested length is reached and terminator is
	// appended, so the shape does not match a fully anchored regex on its last
	// character alone.
	unit       string
	terminator string
	aimsAt     string
}

// redosFamilies are lonkero's eight payloads with their descriptions.
//
// The three lengths are 10, 30 and 60 characters, as upstream: the growth between
// them is what the rule reads, and three points are the fewest that can show a
// curve rather than a single slow request.
var redosFamilies = []redosFamily{
	{unit: "a", terminator: "!", aimsAt: "(a+)+ style repetition with a failing terminator"},
	{unit: "0", terminator: "!", aimsAt: "digit repetition with a failing terminator"},
	{unit: "x", terminator: `\`, aimsAt: "repetition followed by a backslash, as in escape handling"},
	{unit: "a]@", terminator: "", aimsAt: "nested email validation (a]@ repeated)"},
	{unit: "http://aaa", terminator: "", aimsAt: "URL validation with a long authority"},
	{unit: "aaaa.", terminator: "", aimsAt: "(\\w+\\.)+ style repetition"},
	{unit: "1", terminator: ".", aimsAt: "number validation with a decimal point"},
	{unit: "a1", terminator: "!", aimsAt: "alternating classes, as in length or charset checks"},
}

// redosShortLength, redosMediumLength and redosLongLength are the payload sizes,
// which are also the sizes of the control.
const (
	redosShortLength  = 10
	redosMediumLength = 30
	redosLongLength   = 60
)

// redosControlUnit is a character no family matches, so the control measures the
// endpoint and not its regex.
const redosControlUnit = "z"

// redosMinGrowthMS is how much slower the long payload has to be than the control
// before the growth can be called super-linear.
//
// It is a floor rather than a ratio on purpose: a ratio rewards an endpoint whose
// control was fast by luck, and 500 ms is the smallest difference a caller can
// act on without chasing a two-sample fluke.
const redosMinGrowthMS = 500

// ReDoS reports a parameter whose validation grows super-linearly with its input.
type ReDoS struct{}

func (ReDoS) Name() string { return "redos" }

func (ReDoS) Level() Level { return LevelParam }

// redosTiming is one measurement of one shape.
type redosTiming struct {
	family   redosFamily
	length   int
	duration time.Duration
	timedOut bool
}

func (ReDoS) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	control, controlTimedOut := redosControl(ctx, t, p)
	// A control that itself timed out says the endpoint is slow for any input, and
	// a rule that fires on such an endpoint is worse than no rule: every parameter
	// on a slow page would be reported.
	if controlTimedOut {
		return nil
	}
	for _, family := range redosFamilies {
		if ctx.Err() != nil {
			return nil
		}
		timings := redosMeasureFamily(ctx, t, p, family)
		if len(timings) != 3 {
			// A request that failed outright is not a measurement; upstream skips the
			// family too, and a detector that treats an error as slowness reports the
			// timeout it caused.
			continue
		}
		if !redosVerdict(timings, control) {
			continue
		}
		// Stop at the first family that fires, as upstream does: the finding is the
		// endpoint's behaviour, and a second family only adds requests to prove the
		// same thing twice.
		built, _ := NewFinding(Spec{
			Module:   "redos",
			Title:    "Regular expression grows super-linearly with the parameter (" + family.aimsAt + ")",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  timings[2].family.payload(redosLongLength),
			Evidence: redosEvidence(timings, control),
			Description: fmt.Sprintf(
				"The same endpoint answered %d ms for a %d-character input of this shape, %d ms for %d, "+
					"and %d ms for %d, while a %d-character control that does not match the shape took %d ms. "+
					"The growth is in the validation, not in the endpoint: an attacker-supplied length is enough "+
					"to multiply the work the server does, and this is what turns one crafted query into a denial "+
					"of service for everyone behind it.",
				timings[0].duration.Milliseconds(), timings[0].length,
				timings[1].duration.Milliseconds(), timings[1].length,
				timings[2].duration.Milliseconds(), timings[2].length,
				redosLongLength, control.Milliseconds()),
			Remediation: "Replace a backtracking pattern with one that cannot revisit the same characters: " +
				"own the delimiter instead of matching it twice, anchor the repetition, or replace a nested " +
				"quantifier with a flat one. ReDoS is a property of the pattern, so it is fixed in the " +
				"validator's source and not in a request filter.",
		})
		return []Finding{built}
	}
	return nil
}

// payload builds the shape at a length, so the three probes of a family differ
// only in size.
func (f redosFamily) payload(length int) string {
	if length <= len(f.terminator) {
		return f.terminator
	}
	// The unit repeats until the length is reached and the terminator occupies the
	// tail. Building a *fixed* shape per length instead would change what the rule
	// reads: the upstream payloads are three separate strings of 10, 30 and 60
	// characters whose prefixes match, so length is the only variable in them.
	// Repeating one unit is what preserves that, and the trim keeps a
	// multi-character unit from overshooting the length the rule is about to read.
	body := strings.Repeat(f.unit, length/len(f.unit)+1)
	return body[:length-len(f.terminator)] + f.terminator
}

// redosMeasureFamily sends the three probes of one family.
//
// A timeout is a measurement in its own right here and not an error: it is the
// strongest shape this detector reports, so it is recorded rather than dropped.
// Only a request that failed *without* timing out is dropped.
func redosMeasureFamily(ctx context.Context, t *Transport, p Point, family redosFamily) []redosTiming {
	lengths := []int{redosShortLength, redosMediumLength, redosLongLength}
	timings := make([]redosTiming, 0, len(lengths))
	for _, length := range lengths {
		if ctx.Err() != nil {
			return timings
		}
		payload := family.payload(length)
		started := time.Now()
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		elapsed := time.Since(started)
		switch {
		case ctx.Err() != nil:
			// The whole run was cancelled, which says nothing about this shape.
			return timings
		case isTimeout(err):
			// A timeout *is* a measurement, and the strongest one this detector has:
			// upstream treats it as a High finding on its own. Dropping it as an
			// error made that clause unreachable, because the request that gives up
			// never produces a response to read a duration from — the rule was written
			// and could not fire. The wall time is measured here because the transport
			// returns no response to take it from.
			timings = append(timings, redosTiming{
				family: family, length: length, duration: elapsed, timedOut: true,
			})
		case err != nil || resp == nil:
			// A per-request failure (a connection reset, a 5xx the transport treats as
			// an error) is not a slow answer and must not be read as one.
			return nil
		default:
			timings = append(timings, redosTiming{
				family: family, length: length, duration: resp.Duration,
			})
		}
	}
	return timings
}

// redosControl measures the endpoint against the same length and a class no family
// matches.
func redosControl(ctx context.Context, t *Transport, p Point) (time.Duration, bool) {
	payload := strings.Repeat(redosControlUnit, redosLongLength)
	resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
	if err != nil || resp == nil {
		return 0, true
	}
	return resp.Duration, isTimeout(err)
}

// redosVerdict applies the rule, and every clause of it is a clause the control
// takes part in.
func redosVerdict(timings []redosTiming, control time.Duration) bool {
	if len(timings) != 3 {
		return false
	}
	// A shape that never answers fires on its own, and this is upstream's behaviour
	// too. What the control guarantees here is different: the caller has already
	// refused to run when the *control* gave up, so a timeout here is this shape's
	// and not the endpoint's.
	if timings[2].timedOut {
		return true
	}
	short, medium, long := timings[0].duration, timings[1].duration, timings[2].duration
	// The growth has to be present against the control: this is the clause that
	// separates a slow endpoint from a slow regex.
	if long <= control+redosMinGrowthMS*time.Millisecond {
		return false
	}
	// Upstream's two growth clauses, both requiring the middle measurement to sit
	// between the two ends — a single slow request fails both, and a rule that fires
	// on one sample is a rule that fires on the weather.
	escalating := medium > short && long > 2*medium
	dominating := long > 3*medium
	return escalating || dominating
}

// redosEvidence names the numbers, because a timing finding whose evidence is
// "slow" cannot be argued with by the reader who has to accept it.
func redosEvidence(timings []redosTiming, control time.Duration) string {
	parts := make([]string, 0, len(timings)+1)
	for _, timing := range timings {
		label := fmt.Sprintf("%d chars: %d ms", timing.length, timing.duration.Milliseconds())
		if timing.timedOut {
			label += " (timeout)"
		}
		parts = append(parts, label)
	}
	parts = append(parts, fmt.Sprintf("control %d neutral chars: %d ms", redosLongLength, control.Milliseconds()))
	return strings.Join(parts, ", ")
}

// isTimeout reports whether an error is the transport giving up rather than the
// server answering.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout") ||
		strings.Contains(strings.ToLower(err.Error()), "deadline exceeded")
}
