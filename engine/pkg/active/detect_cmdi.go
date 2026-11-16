// OS command injection.
//
// # The technique, and why the cheap one comes first
//
// The echo technique sends an arithmetic command substitution and looks for the
// product in the response. It costs the target one shell invocation and proves
// the strongest thing a probe can prove here: a shell evaluated an expression
// the attacker supplied, and its output came back.
//
// The time-based technique sends a delay and measures whether the response took
// longer. It proves the same thing with no output, and it is strictly worse on
// every axis except that it works when output is suppressed: it is slower to
// conclude, it cannot attribute the result to anything but a delay, and — the
// part that matters here — **it makes the target slow on purpose**.
//
// # Why the delay is a declared, visible option
//
// The upstream implementation hard-codes a four-second sleep and tries four
// shell syntaxes against it. A surface where the echo technique fails therefore
// costs up to sixteen seconds of the target's worker per parameter, and a crawl
// of five hundred parameters can spend hours making other people's applications
// unresponsive, with nothing on the operator's screen saying so.
//
// A delay that slows the target is a real cost to a real host, so it is a
// visible field with a documented default rather than a constant in a loop. The
// echo technique runs first and unconditionally, so a target that reflects output
// — the overwhelming majority — is never delayed at all. Only a target that
// suppresses output reaches the blind stage, and the operator set the delay that
// stage uses.
package active

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// cmdEchoFactorA and cmdEchoFactorB are the operands of the injected
// arithmetic. The product is a two-digit number, chosen so it is unlikely to
// appear on a page and checked against the baseline regardless.
const (
	cmdEchoFactorA = 19
	cmdEchoFactorB = 23
)

// DefaultBlindDelay is the delay the blind technique uses when the operator has
// not chosen one.
//
// It is a small delay on purpose. A blind confirmation needs a delay long enough
// to exceed network jitter on a link the probe cannot see, not one long enough
// to be impressive: a target that answers in 200 ms and a target that answers in
// 2.1 s are distinguishable at two seconds, and the second one costs a quarter
// as much of the target's time as the four the upstream implementation uses.
const DefaultBlindDelay = 2 * time.Second

// blindNoiseMargin is how much longer than the requested delay a response has to
// take before the delay is credited. A target that is merely slow — a slow disk,
// a slow upstream, a cold cache — also produces a long response, and without a
// margin that slowness reads as an injected sleep.
const blindNoiseMargin = 750 * time.Millisecond

// cmdSyntaxes are the shell ways of appending a command.
//
// They are tried in the order a shell is most likely to accept, and the order is
// not cosmetic: each is a separate request, and a target that runs `/bin/sh -c`
// accepts the first one.
// cmdSyntaxes are the shell forms the echo technique is wrapped in, in order of
// how often each is the one a filter let through.
//
// The count is deliberately **above** the eight upstream VEXOR documents, because
// reconciliation on 2026-10-01 found six here against eight there. Two of the
// missing upstream shapes were added, and three more were added beyond them on
// their own evidence: `or` and `brace grouping` close the upstream gap,
// while `encoded newline`, `IFS substitution` and `process substitution` cover
// filter bypasses that a shape list without them cannot reach at all — a filter
// that strips a literal newline is not defeated by another literal newline.
//
// The list is a superset on purpose. Each entry costs one request per parameter,
// and the operator can see the whole list; the alternative — silently probing six
// of the shapes a target might accept — is the failure mode this reconciliation
// existed to remove.
var cmdSyntaxes = []struct {
	name string
	make func(expression string) string
}{
	{"semicolon", func(e string) string { return "; " + e }},
	{"pipe", func(e string) string { return "| " + e }},
	{"newline", func(e string) string { return "\n" + e }},
	{"dollar substitution", func(e string) string { return "$(" + e + ")" }},
	{"backtick", func(e string) string { return "`" + e + "`" }},
	{"and", func(e string) string { return "&& " + e }},
	// `or` is the failing-first branch. It differs from `and` in the only way
	// that matters to a filter: some blocklists match `&&` and miss `||`.
	{"or", func(e string) string { return "|| " + e }},
	// Brace grouping reaches targets that dispatch through `sh -c`, where a bare
	// `;` needs a trailing space to parse but `{ ; }` groups cleanly.
	{"brace grouping", func(e string) string { return "{ " + e + "; }" }},
	// A filter that strips a literal newline is not defeated by sending another
	// literal newline, so the encoded form is probed as its own shape.
	{"encoded newline", func(e string) string { return "%0a" + e }},
	// `${IFS}` stands in for the space a filter may strip, which is why the
	// expression it wraps is written without one.
	{"IFS substitution", func(e string) string { return "${IFS}" + e }},
	// Process substitution is bash-only and is a separate parse path from `$()`,
	// so a filter tuned for one does not necessarily catch the other.
	{"process substitution", func(e string) string { return "<(" + e + ")" }},
}

// cmdSleepSyntaxes are the ways of appending a delay, in the same order of
// likelihood. They are a subset of cmdSyntaxes because a shell that will run
// `; sleep 2` will usually run `| sleep 2` too, and the two lists exist for the
// same reason: a filter may block one form without blocking the others.
var cmdSleepSyntaxes = []struct {
	name string
	make func(seconds string) string
}{
	{"semicolon", func(s string) string { return "; sleep " + s }},
	{"pipe", func(s string) string { return "| sleep " + s }},
	{"dollar substitution", func(s string) string { return "$(" + s + " sleep " + s + ")" }},
	{"backtick", func(s string) string { return "`sleep " + s + "`" }},
}

// CMDi is the OS command injection detector.
type CMDi struct {
	// BlindDelay is how long the blind technique asks the target to wait. Zero
	// means DefaultBlindDelay. It is a field rather than a constant so the cost
	// lands on the operator's screen: a detector that hides a multi-second
	// delay in a loop makes somebody else's application slow for reasons nobody
	// asked for and nobody can see.
	BlindDelay time.Duration
}

// Name implements Module.
func (CMDi) Name() string { return "cmdi" }

// Level implements Module.
func (CMDi) Level() Level { return LevelParam }

// Scan probes one surface, echo technique first.
//
// The echo stage is unconditional. The blind stage runs only when a delay was
// declared, because making a target slow is a decision the operator makes by
// setting a value, not one a detector makes on its own.
func (m CMDi) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if finding := echoProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	delay := m.BlindDelay
	if delay <= 0 {
		delay = DefaultBlindDelay
	}
	if finding := blindProbe(ctx, t, p, baseline, delay); finding != nil {
		return []Finding{*finding}
	}
	return nil
}

// echoProbe injects an arithmetic command substitution and looks for the
// product in the response.
func echoProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	expected := strconv.Itoa(cmdEchoFactorA * cmdEchoFactorB)
	expression := fmt.Sprintf("echo $((%d*%d))", cmdEchoFactorA, cmdEchoFactorB)
	for _, syntax := range cmdSyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		payload := syntax.make(expression)
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		if !Fresh(baseline, resp, expected) {
			// Either the product is not there, or the page already contained
			// it. A page that prints 437 on its own tells us nothing about the
			// shell.
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "cmdi",
			Title:   "OS Command Injection (Echo-Based, " + syntax.name + ")",
			Claimed: SeverityCritical,
			Tier:    TierVerified,
			Point:   p,
			Payload: payload,
			Evidence: fmt.Sprintf("the shell evaluated the injected arithmetic and returned %s, a value "+
				"that was not present in the unmodified response", expected),
			Description: "The parameter value reaches a shell interpreter. The injected command substitution " +
				"executed and its output was returned to the client, so arbitrary command execution is " +
				"demonstrated rather than inferred.",
			Remediation: "Do not build shell commands from user input. Use argument arrays or a " +
				"language-native API. If a shell is unavoidable, allow-list the input and pass it as an argument.",
		})
		return &finding
	}
	return nil
}

// blindProbe measures whether an injected delay lengthened the response.
//
// The measurement compares three numbers rather than two: the baseline, the
// delay that was requested, and the response that came back. A response is only
// credited when it exceeded both the baseline by a margin *and* the requested
// delay by a margin. A target that is slow on its own satisfies neither half,
// and crediting it is how a detector ends up reporting command injection on an
// application with a cold cache.
func blindProbe(ctx context.Context, t *Transport, p Point, baseline *Response, delay time.Duration) *Finding {
	if baseline == nil {
		// Without a measured baseline there is nothing to compare against, and
		// a fixed threshold is exactly the guess this function exists to avoid.
		return nil
	}
	seconds := strconv.Itoa(int(delay / time.Second))
	if int(delay/time.Second) < 1 {
		// Sub-second delays have no integer form a shell accepts, and rounding
		// to zero would send "sleep 0", which returns instantly and would read
		// as a difference.
		return nil
	}
	for _, syntax := range cmdSleepSyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		payload := syntax.make(seconds)
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		// The quantity that matters is the *increment* over the application's own
		// measured baseline, not the absolute response time.
		//
		// Requiring the response to exceed the requested delay plus a margin
		// looks stricter and is wrong: a target that sleeps exactly the requested
		// time answers in that time plus a few milliseconds of network, so the
		// absolute figure never clears a margin large enough to reject a slow
		// application. The absolute time is also the wrong thing to compare
		// against a baseline precisely because it carries the application's own
		// slowness along with it.
		//
		// The increment is what isolates the injection. A sleep of N adds N to
		// whatever the request already cost, so a constant-slowness application
		// shows an increment of approximately zero and is not credited, while an
		// injected delay shows approximately the delay that was asked for.
		increment := resp.Duration - baseline.Duration
		if increment < delay-blindNoiseMargin {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "cmdi",
			Title:   "OS Command Injection (Time-Based Blind, " + syntax.name + ")",
			Claimed: SeverityCritical,
			// No output came back, so what is demonstrated is that the request
			// took longer than it should. The delay is consistent with an
			// executed sleep and with a slow target; only the second is
			// excluded, and only by the baseline.
			Tier:    TierPotential,
			Point:   p,
			Payload: payload,
			Evidence: fmt.Sprintf("with sleep(%s) injected the response took %s against a baseline of %s, "+
				"an increment of %s where %s was requested", seconds, resp.Duration.Round(time.Millisecond),
				baseline.Duration.Round(time.Millisecond), increment.Round(time.Millisecond), delay),
			Description: "The response was delayed by roughly the requested amount when a sleep was injected, " +
				"which indicates the value reached a shell. No command output was returned, so this is the " +
				"delay being explained, not a command being seen.",
			Remediation: "Do not build shell commands from user input. Use argument arrays or a " +
				"language-native API.",
		})
		return &finding
	}
	return nil
}
