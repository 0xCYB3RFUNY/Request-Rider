package scanner

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Послідовність запитів — це те, чого не вистачало найбільшій частині корпусу.
//
// Виміряно на 4 000 `http`-шаблонів офіційного корпусу: смуга оцінює 2 978
// (74.5 %), і 897 відказів з них мають одну причину — «the document declares N
// request blocks». Тобто майже чверть шаблонів корпусу не оцінюється не
// через складність, а через те, що смуга має один збережений обмін.
//
// Цей файл знімає саме цю причину: він сам робить запити, тож послідовність
// блоків для нього не послідовність невідомих обмінів, а послідовність його
// власних. Матчери й екстрактори — це nuclei's `pkg/operators`, які вже
// використовуються, тож семантика `dsl:`, `word`, `regex`, `status`, `size`,
// `binary` і видобування `json`/`regex`/`kval`/`xpath` тут не переписується.

// localState carries what a later request needs from an earlier one.
//
// `dynamic` holds the extracted values, which nuclei exposes to a later request
// as `{{value}}` and `{{template.<name>}}`. They are strings here because that is
// what a header, a path and a body can hold: an extractor may produce a list,
// and a list has no spelling in a request line.
type localState struct {
	document  *passiveDocument
	target    *url.URL
	transport httpTransport
	dynamic   map[string]string
	steps     []LocalRun
	// considered counts every request the document stands for, including the ones
	// that could not be built, so the skip note can say "N of M" against the whole
	// document rather than against one block.
	considered int
}

// runRequestSequence walks a document's request blocks in document order.
//
// The rule it implements is nuclei's own: a request after the first is sent only
// when the previous one matched. That is what `req-condition` means and what its
// default of `true` says, and it is why a multi-block template is a *test* and
// not a list of requests — a login that returned a token has to have worked
// before the token is used.
func runRequestSequence(ctx context.Context, document *passiveDocument, target string, transport httpTransport, oast map[string]string) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	parsedTarget, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsedTarget.Host == "" {
		run.Reason = fmt.Sprintf("target %q must be an absolute URL with a host", target)
		return run
	}
	state := &localState{
		document:  document,
		target:    parsedTarget,
		transport: transport,
		dynamic:   map[string]string{},
	}
	// The callback address joins the extracted values, because that is what it is
	// for a request: a `{{name}}` a later block can send.
	for name, value := range oast {
		state.dynamic[name] = value
	}
	blocks := allPassiveRequests(document)
	if len(blocks) == 0 {
		run.Reason = "the document declares no http request block, so there is no request to send"
		return run
	}
	previousMatched := false
	for index, block := range blocks {
		// `req-condition` defaults to true, so a later block is sent only when
		// the previous one matched. The field is a pointer because the default is
		// the opposite of Go's zero value, and a plain bool would silently make
		// every chain send every request.
		gated := block.ReqCondition == nil || *block.ReqCondition
		if index > 0 && gated && !previousMatched {
			// Reporting this as "did not match" rather than as an error is the
			// point: the chain stopped where nuclei stops it, which is a
			// verdict, not a failure.
			run.Reason = fmt.Sprintf(
				"stopped at request %d of %d: its req-condition is true and request %d did not match, "+
					"so this one was never sent", index+1, len(blocks), index)
			break
		}
		expanded, reason := expandBlockRequests(block)
		if reason != "" {
			run.Reason = fmt.Sprintf("request %d of %d: %s", index+1, len(blocks), reason)
			break
		}
		// A block counts as matched when any of the requests it stands for
		// matched — for a single-request block that is itself. The value is what
		// gates the next block, so it must not be set unconditionally: a chain
		// whose first block missed has to stop, and that is the whole point of
		// `req-condition`.
		blockMatched := false
		// A generated request whose placeholders cannot all be substituted is
		// skipped, not fatal to the block.
		//
		// Measured against v3.11.1 on `http/exposures/configs/laravel-env.yaml`:
		// 21 payload values, one of them `/.env.{{DN}}`, and nuclei opened **20**
		// connections — it dropped exactly the one it could not resolve and
		// scanned the rest. Refusing the whole template over one unresolvable
		// value would cost 20 real checks, so the skip is what nuclei does and the
		// count of what was skipped goes into the reason.
		var skipped []string
		for position, generated := range expanded {
			// Whether a request can be built is decided inside `runOneRequest`, at
			// the granularity of one path or one raw entry.
			//
			// It used to be decided here, once per block, and that was both wrong
			// and dead: wrong because a block with three raw entries and one bad
			// one lost all three, and dead because the check inside
			// `runOneRequest` had already skipped it — so a mutation that removed
			// the per-entry filter changed nothing observable, which is how a test
			// that cannot fail gets mistaken for a test that passes.
			step := state.execute(ctx, generated)
			if step.Skipped {
				skipped = append(skipped, fmt.Sprintf("%d of %d (%s)",
					position+1, len(expanded), step.Reason))
				continue
			}
			state.steps = append(state.steps, step)
			if step.Reason != "" {
				run.Reason = fmt.Sprintf(
					"request %d of %d, generated %d of %d: %s",
					index+1, len(blocks), position+1, len(expanded), step.Reason)
				break
			}
			if step.SkippedNote != "" {
				skipped = append(skipped, step.SkippedNote)
			}
			if step.Matched {
				blockMatched = true
				run.Matched = true
				run.MatcherNames = step.MatcherNames
				// A payload block is a sweep: one of its generated requests
				// matching is the template matching. Stopping there is what keeps
				// a clusterbomb from sending requests after the answer arrived.
				break
			}
		}
		if run.Reason != "" {
			break
		}
		if len(skipped) > 0 && !blockMatched {
			// Not an error: the block ran, and this says what it could not use.
			// The reason is additive — a chain that stops further down must keep
			// its own reason, so this is appended rather than replacing.
			run.Reason = fmt.Sprintf(
				"skipped %d of the %d requests this block stands for, whose placeholders could not be "+
					"generated: %s", len(skipped), len(expanded), strings.Join(skipped, "; "))
		}
		previousMatched = blockMatched
	}
	for _, step := range state.steps {
		if run.Request == "" {
			run.Request, run.Response = step.Request, step.Response
			run.StatusCode, run.Elapsed = step.StatusCode, step.Elapsed
			continue
		}
		run.Request += "\n--- " + step.Request
		run.Response += "\n--- " + step.Response
		run.Extracts = append(run.Extracts, step.Extracts...)
	}
	if run.Reason != "" {
		// A broken chain has not refuted the template's claim, so it is not a
		// match, and the reason above says why it is not a clean miss either.
		run.Matched = false
	}
	return run
}

// execute sends one block, scores it, and keeps whatever it extracted.
func (s *localState) execute(ctx context.Context, block passiveRequest) LocalRun {
	expanded := expandBlockPlaceholders(block, s.target, s.dynamic)
	step := runOneRequest(ctx, s.document, expanded, s.target.String(), s.transport, s.dynamic)
	if step.Reason != "" {
		return step
	}
	for name, value := range step.Dynamic {
		s.dynamic[name] = value
	}
	return step
}

// expandBlockPlaceholders substitutes the target, the extracted values, and
// nothing else.
//
// The refusals are the important half. A placeholder this runner does not
// generate — `{{randstr}}`, `{{interactsh-url}}`, a fuzzing marker — left in
// place would put a literal `{{randstr}}` on the wire and the response to it
// would be scored as the template's verdict. So the whole block is refused, and
// the refusal names the placeholder.
func expandBlockPlaceholders(block passiveRequest, target *url.URL, dynamic map[string]string) passiveRequest {
	out := block
	if out.Path != nil {
		out.Path = make([]string, len(block.Path))
		for index, path := range block.Path {
			out.Path[index] = expandDynamic(path, target, dynamic)
		}
	}
	out.Body = expandDynamic(block.Body, target, dynamic)
	if block.Headers != nil {
		out.Headers = make(map[string]string, len(block.Headers))
		for name, value := range block.Headers {
			out.Headers[name] = expandDynamic(value, target, dynamic)
		}
	}
	return out
}

// placeholderPattern finds every `{{...}}` in one value.
var placeholderPattern = regexp.MustCompile(`\{\{[^{}]*\}\}`)

// ungeneratedPlaceholders lists the placeholders a value uses that this runner
// does not produce, in document order and without repeats.
func ungeneratedPlaceholders(value string, dynamic map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, token := range placeholderPattern.FindAllString(value, -1) {
		name := localPlaceholderName(token)
		if name == "" || localKnownPlaceholder(name) {
			continue
		}
		// A value an earlier block extracted is known, so it is substituted. A
		// name that merely *looks* like one — `{{to_lower(x)}}` — is not known,
		// and putting it on the wire literally would score the target's answer
		// to the literal text as the template's verdict.
		if wanted := dynamicValueName(name); wanted != "" {
			if _, ok := dynamic[wanted]; ok {
				continue
			}
		}
		// A generator this runner implements is produced at send time, so it is
		// not a refusal. The refusal table lives with the generator, because the
		// reason it can generate one and not another is a fact about that
		// generator and not about this scan.
		if generatorRefusal(name) == "" && generateable(name) {
			continue
		}
		if !seen[token] {
			seen[token] = true
			out = append(out, token)
		}
	}
	return out
}

// generateable reports whether this runner can produce the placeholder itself.
func generateable(name string) bool {
	switch strings.TrimSpace(name) {
	case "randstr":
		return true
	default:
		return false
	}
}

// localKnownPlaceholder reports whether the runner substitutes this one itself.
func localKnownPlaceholder(name string) bool {
	switch name {
	case "BaseURL", "base_url", "Hostname", "host", "RootURL", "rand_base":
		// `rand_base` is substituted from the target's own host, so it is a
		// spelling rather than a generator.
		return true
	}
	return false
}

// dynamicValueName reads the value a placeholder asks for. `{{token}}` and
// `{{template.token}}` are the two spellings nuclei templates use.
func dynamicValueName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	if rest, found := strings.CutPrefix(trimmed, "template."); found {
		return strings.TrimSpace(rest)
	}
	if strings.Contains(trimmed, "(") || strings.Contains(trimmed, ".") {
		// A call or a qualified expression this runner does not evaluate.
		return ""
	}
	return trimmed
}

// localPlaceholderName strips the braces off a placeholder token.
func localPlaceholderName(token string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(token, "{{"), "}}"))
}

// expandDynamic substitutes the target, then the extracted values, then leaves
// anything else alone. Callers check `ungeneratedPlaceholders` first, so a value
// that reaches here unresolved is one the caller has already accepted.
func expandDynamic(value string, target *url.URL, dynamic map[string]string) string {
	replaced := localExpandPath(value, target)
	for name, replacement := range dynamic {
		replaced = strings.ReplaceAll(replaced, "{{template."+name+"}}", replacement)
		replaced = strings.ReplaceAll(replaced, "{{"+name+"}}", replacement)
	}
	// `{{randstr}}` is drawn per occurrence, which is what nuclei does: two
	// occurrences in one path are two different values, not one repeated.
	// The failure is not swallowed — a generator that cannot draw leaves the
	// placeholder, and the caller's refusal check has already passed it, so it
	// would go out literally. Drawing from crypto/rand does not fail in
	// practice, and saying so here would be an unmeasurable claim.
	if strings.Contains(replaced, "{{randstr}}") {
		if drawn, err := generateRandStr(); err == nil {
			replaced = strings.ReplaceAll(replaced, "{{randstr}}", drawn)
		}
	}
	return replaced
}

// blockPlaceholderRefusals returns the placeholders one block uses that this
// runner would have to invent.
// dynamic is what earlier blocks have extracted so far, so a placeholder that
// will be known by the time this block is sent is not a refusal.
func blockPlaceholderRefusals(block passiveRequest, dynamic map[string]string) []string {
	var out []string
	for _, value := range block.Path {
		out = append(out, ungeneratedPlaceholders(value, dynamic)...)
	}
	out = append(out, ungeneratedPlaceholders(block.Body, dynamic)...)
	for _, value := range block.Headers {
		out = append(out, ungeneratedPlaceholders(value, dynamic)...)
	}
	// `Raw` was missing from this list, and that was not a harmless omission.
	//
	// Measured: 162 of the 4 000 templates put a placeholder inside a `raw:`
	// block — mostly `{{interactsh-url}}` in an XML body — and with `Raw` unread
	// they all passed the check and went out on the wire with the literal text in
	// it. Their verdicts were then the target's answer to `{{interactsh-url}}`,
	// which is not what the template asked. They are refused now, and they will
	// run for real once a callback address exists.
	for _, value := range block.Raw {
		out = append(out, ungeneratedPlaceholders(value, dynamic)...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// localJudgeability answers the runner's own question: with its own requests,
// can this project run this document at all?
//
// It is deliberately a different question from `passiveJudgeability`, whose
// answer is about judging one stored exchange. A refusal here is not a gap in
// the matcher semantics — it is a protocol or a generator this runner does not
// have yet, and each refusal names which one.
//
// `content` is the document as uploaded, and it is read for exactly one reason:
// to name the protocol a template actually declares. The decoded document holds
// only http, requests and file, so a template written in `code` would otherwise
// be refused as "declares no request block", which is true and useless.
func localJudgeability(document *passiveDocument, content string) string {
	blocks := allPassiveRequests(document)
	if len(blocks) == 0 {
		declared := declaredNonHTTPProtocols(content)
		// `code:` is performed by this runner now, so a document that declares
		// only it is not a refusal — it is work.
		//
		// It used to be refused here with the sentence «it has no code engine yet»,
		// and that sentence became a lie the moment the engine landed: the
		// capability check runs before the dispatcher, so the engine was never
		// reached and every code template was reported as unperformable. Six tests
		// written with the engine found it in one run.
		runnable, unrunnable := codeIsRunnable(document, declared)
		if runnable {
			return ""
		}
		// `file:` is performed too — against a local path the operator named. The
		// refusal below names it as a protocol this runner cannot do, which stopped
		// being true when `nuclei_file.go` landed.
		if unrunnable == "file" && len(document.File) > 0 {
			return ""
		}
		// `tcp:` is performed too — it dials the target's own host and port.
		if unrunnable == "tcp" && len(document.Tcp) > 0 {
			return ""
		}
		// `javascript:` is performed for the documents that need no nuclei protocol
		// library; the rest are refused by `runJavaScriptDocument` with the module
		// named, so the capability check must not refuse them first with a vaguer
		// sentence.
		if unrunnable == "javascript" && len(document.JavaScriptBlocks) > 0 {
			return ""
		}
		// `headless:` is performed too, through the project's own browser worker.
		if unrunnable == "headless" && len(document.HeadlessBlocks) > 0 {
			return ""
		}
		if unrunnable != "" {
			// `code: true` and no block of its own is its own case, and saying
			// "no engine" about it would be wrong: there is no block to name an
			// engine. Measured: 7 of 500 sampled templates write exactly that, and
			// their script lives inside a `flow:` expression instead.
			// Two different documents, and one message about them would be wrong for
			// both. A block that exists but names no engine is missing an engine; a
			// bare `code: true` has no block at all, and its script is elsewhere.
			if len(document.CodeBlocks) == 0 {
				return fmt.Sprintf("the document writes `code: %s` with no block and no request to run, so this "+
					"runner has nothing of its own to execute here; its script lives in the document's `flow:` "+
					"expression, which this runner does not read", unrunnable)
			}
			return fmt.Sprintf("the document declares a %s block and no request block, and this runner "+
				"cannot run it here: the block names no engine this host has an interpreter for (engine tried: %s)",
				unrunnable, codeEngineNames(document))
		}
		return "the document declares no http or requests block, so this runner has nothing to send"
	}
	for _, block := range blocks {
		if len(block.Fuzzing) > 0 {
			return "the block declares a fuzzing engine, which drives a browser against live inputs"
		}
		if block.Race {
			return "the block asks for a race condition, which needs the requests sent concurrently on one session"
		}
		if block.Pipeline {
			return "the block asks for pipelining, which needs several requests written before any response is read"
		}
	}
	return ""
}

// codeIsRunnable reports whether a document's `code:` blocks can be executed here.
//
// The answer has two parts on purpose: whether the document can run at all, and what
// it declares when it cannot, so the refusal names the protocol instead of saying
// "no requests". An interpreter is looked up rather than assumed, because a document
// that names `powershell` on a host without it produced nothing and a verdict of
// `not_matched` would be a claim about a check that never ran.
func codeIsRunnable(document *passiveDocument, declared []string) (bool, string) {
	if len(document.CodeBlocks) == 0 {
		return false, firstDeclared(declared)
	}
	for _, block := range document.CodeBlocks {
		if strings.TrimSpace(block.CodeSource) == "" {
			return false, "code"
		}
		if firstCodeEngine(block) == "" {
			return false, "code"
		}
	}
	return true, ""
}

// firstDeclared returns the first declared protocol, for a refusal that names one.
func firstDeclared(declared []string) string {
	if len(declared) == 0 {
		return ""
	}
	return declared[0]
}

// nonHTTPProtocolKeys are the top-level protocol keys this runner does not
// perform. It is a list rather than a check so the refusal can name what the
// file really declares.
var nonHTTPProtocolKeys = []string{
	"code", "dns", "file", "headless", "javascript", "network", "port",
	"ssl", "tcp", "whois", "websocket", "workflows", "jarm", "asn", "multi",
}

// declaredNonHTTPProtocols reads the document as text for its top-level keys.
func declaredNonHTTPProtocols(content string) []string {
	var out []string
	for _, key := range nonHTTPProtocolKeys {
		if localTopLevelKey(content, key) {
			out = append(out, key)
		}
	}
	return out
}

// localTopLevelKey reports whether the document declares `key:` at column zero.
func localTopLevelKey(content, key string) bool {
	for _, line := range strings.Split(content, "\n") {
		if line == key+":" || strings.HasPrefix(line, key+": ") {
			return true
		}
	}
	return false
}
