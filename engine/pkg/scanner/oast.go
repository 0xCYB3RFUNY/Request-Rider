package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// `{{interactsh-url}}` — 53 відмови на вибірці з 4 000 і 596 шаблонів у корпусі.
// Це єдиний протокол, для якого ми не можемо нічого згенерувати самі: адреса має
// бути справжньою, і справжня вона тоді, коли на неї можуть зателефонувати.
//
// Тому тут не генератор, а джерело: рушій уже має OAST-слухач
// (`POST /api/oast`, далі `POST <provider>/register` і `GET <provider>/poll`), і
//Scanner ніколи не повинен заводити другий. Інтерфейс нижче — це те, що йому
//потрібно, а реалізація живе в `engine/oast.go` поверх наявних методів.

// OASTSource hands out a callback address and reports whether the target called it.
//
// The two halves are separate on purpose: a template that only *sends* the
// address needs `NewPayload`, and the wait afterwards belongs to the run, not to
// the substitution — the same listener serves every block of a document.
type OASTSource interface {
	// NewPayload registers one listener and returns the URL a template puts into
	// a request, or says why it could not.
	NewPayload(ctx context.Context) (payloadURL string, err error)
	// Await reports whether a callback to payloadURL arrived within the bound.
	Await(ctx context.Context, payloadURL string, wait time.Duration) (bool, error)
}

// oastContextKey is the context key the source travels under. It is unexported so
// no caller outside this package can install one by accident: an OAST source is a
// capability with an external cost, not a convenience.
type oastContextKey struct{}

// WithOASTSource gives a run the ability to substitute `{{interactsh-url}}`.
//
// A run without one refuses the placeholder by name, which is the honest outcome:
// sending the literal `{{interactsh-url}}` to a target would score the target's
// answer to that text as the template's verdict.
func WithOASTSource(ctx context.Context, source OASTSource) context.Context {
	if source == nil {
		return ctx
	}
	return context.WithValue(ctx, oastContextKey{}, source)
}

// OASTSourceFrom reads the source a run was given.
func OASTSourceFrom(ctx context.Context) (OASTSource, bool) {
	source, ok := ctx.Value(oastContextKey{}).(OASTSource)
	return source, ok && source != nil
}

// oastRefusal names what is missing when a document needs `{{interactsh-url}}`.
func oastRefusal() string {
	return "the block asks for {{interactsh-url}}, which is a callback address rather than a generated " +
		"string: it is only real if something can be called at it. This run has no OAST source, so there " +
		"is no address to substitute — set one up and pass it to the run rather than letting the literal " +
		"placeholder go on the wire"
}

// blockNeedsOAST reports whether a block uses the callback placeholder.
func blockNeedsOAST(block passiveRequest) bool {
	for _, value := range block.Path {
		if strings.Contains(value, "{{interactsh-url}}") {
			return true
		}
	}
	if strings.Contains(block.Body, "{{interactsh-url}}") {
		return true
	}
	for _, value := range block.Headers {
		if strings.Contains(value, "{{interactsh-url}}") {
			return true
		}
	}
	for _, raw := range block.Raw {
		if strings.Contains(raw, "{{interactsh-url}}") {
			return true
		}
	}
	return false
}

// newOASTPayload takes one callback address for a run.
//
// It is asked once per run rather than per block, because a listener is state on
// an external service: asking twice for one document would open two listeners and
// leave the first one to be reaped by whoever owns the provider's retention.
func newOASTPayload(ctx context.Context) (string, OASTSource, string) {
	source, ok := OASTSourceFrom(ctx)
	if !ok {
		return "", nil, oastRefusal()
	}
	payload, err := source.NewPayload(ctx)
	if err != nil {
		return "", nil, "no callback address could be registered: " + oneLine(err.Error())
	}
	if strings.TrimSpace(payload) == "" {
		return "", nil, "the OAST source returned an empty callback address, so there is nothing to substitute"
	}
	return payload, source, ""
}

// oastWaitAfterSend is how long a run waits for a callback after the request that
// names the address has gone out.
//
// It is a default and it is reported: a template whose target calls back in five
// seconds and one that calls back in a minute are both real, and the caller can
// change the bound. The value here is what the OAST provider's own poll interval
// needs plus room for one round trip, not a silent cap.
const oastWaitAfterSend = 10 * time.Second

// documentOAST takes one callback address for a document, when it needs one.
//
// It returns nil values and no reason when no block asks for an address, so the
// capability costs nothing on a document that does not use it — which is every
// document except the 596 in the corpus that carry `interactsh-url`.
func documentOAST(ctx context.Context, blocks []passiveRequest) (map[string]string, string) {
	needs := false
	for _, block := range blocks {
		if blockNeedsOAST(block) {
			needs = true
			break
		}
	}
	if !needs {
		return nil, ""
	}
	payload, _, reason := newOASTPayload(ctx)
	if reason != "" {
		return nil, reason
	}
	// The key is the placeholder's own name, so substitution is the same path as
	// any extracted value and no second mechanism exists to drift from it.
	return map[string]string{"interactsh-url": payload}, ""
}

// OASTHitKey is the dynamic-value name a callback writes when one arrives.
//
// It is a name rather than a flag because the value travels the same road as
// everything else the run knows: a later block can read it, and the report can
// show it.
const OASTHitKey = "oast_callback_received"

// awaitOAST waits for a callback and records it.
//
// The wait happens after the request that named the address has gone out, so it
// is bounded by the run and not by the template: an `interactsh-url` template has
// no response matcher to satisfy, and "no callback" is its negative answer.
func awaitOAST(ctx context.Context, source OASTSource, payloadURL string) (bool, error) {
	if source == nil {
		return false, nil
	}
	wait := oastWaitAfterSend
	if override, ok := OASTWaitFromContext(ctx); ok {
		wait = override
	}
	return source.Await(ctx, payloadURL, wait)
}

// oastWaitContextKey carries the caller's wait bound.
type oastWaitContextKey struct{}

// WithOASTWait sets how long a run waits for a callback. A run with no bound uses
// `oastWaitAfterSend`.
func WithOASTWait(ctx context.Context, wait time.Duration) context.Context {
	if wait <= 0 {
		return ctx
	}
	return context.WithValue(ctx, oastWaitContextKey{}, wait)
}

// OASTWaitFromContext reads the bound the caller set.
func OASTWaitFromContext(ctx context.Context) (time.Duration, bool) {
	wait, ok := ctx.Value(oastWaitContextKey{}).(time.Duration)
	return wait, ok && wait > 0
}

// settleOAST asks whether a callback arrived for the address this request used.
//
// It reports a reason only when the caller asked the question and the answer
// could not be obtained. A block that never named an address returns false with
// no reason, so the ordinary path pays one map lookup and nothing else.
func settleOAST(ctx context.Context, block passiveRequest, dynamic map[string]string) (bool, string) {
	if !blockNeedsOAST(block) {
		return false, ""
	}
	payload := strings.TrimSpace(dynamic["interactsh-url"])
	if payload == "" {
		return false, "the block names a callback address but this run holds none, so there is nothing to " +
			"wait on — the address has to be registered before the request goes out, not after"
	}
	// One mechanism, not two: the source that handed out the address is the one
	// asked about the callback. A separate hook in the context would be a second
	// path to the same answer, and the two could disagree.
	source, ok := OASTSourceFrom(ctx)
	if !ok {
		return false, fmt.Sprintf("the run has no OAST source, so the callback to %s cannot be awaited; the "+
			"request went out with the address substituted, and its answer is unknown rather than negative", payload)
	}
	hit, err := awaitOAST(ctx, source, payload)
	if err != nil {
		return false, "the callback to " + payload + " could not be awaited: " + oneLine(err.Error())
	}
	return hit, ""
}

// withOASTHit records the callback in the values a later block can read.
func withOASTHit(dynamic map[string]string) map[string]string {
	if dynamic == nil {
		dynamic = map[string]string{}
	}
	dynamic[OASTHitKey] = "true"
	return dynamic
}
