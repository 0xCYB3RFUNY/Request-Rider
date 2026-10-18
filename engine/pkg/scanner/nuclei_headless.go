package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// `headless:` — 222 документи корпусу. Виміряна форма:
//
//	крок `navigate`     229   крок `waitdialog`  203   крок `script`  47
//	крок `waitload`      28   крок `setheader`     4   крок `click`    3
//	крок `text`           2   крок `sleep`         1   `screenshot`   1
//	блоків             229   з кількома          1   `payloads:`   198
//
// Документ описує не HTTP-запит, а **розмову з браузером**: відкрити сторінку,
// дочекатися діалогу, який вона показує, і назвати те, що в ньому було. Матчер
// потім судить на рядках на кшталт `reflected == true` та `reflected_message == num`.
//
// `waitdialog` — причина, чому протокол не можна виконати без справжнього браузера:
// значення, звірене з шаблоном, мешкає **всередині** `alert()`, яку викликає код
// сторінки. Обхід, який повертає DOM, його не бачить.
//
// Правила підстановки (`fuzzing:`) несуть `part` (`query`, `path`, `header`),
// `type` (`prefix`, `postfix`, `replace`), `mode` і `fuzz` — список значень, де
// `{{payload}}`, `{{url_encode(payload)}}` та `{{num}}` (лічильник спроби)
// підставляються.

// The worker's service key is gone: `RR_INTERNAL_API_KEY` and
// `X-RequestRider-Internal-Key` were removed end to end, so this file no longer
// reads the environment to sign a call. The duplicated constants it used to keep
// in sync with `engine/internal_auth.go` left with them — a package under `pkg/`
// could not import package main, which is why they were strings twice.

// headlessWorkerEnv names the environment variable holding the browser worker.
//
// The worker is this project's own Playwright service, already part of the stack
// (`browser-worker/worker.py`, `POST /headless/probe`). Reusing it is deliberate: a
// second browser inside the Go engine would be a second installation, a second
// browser download and a second place where a browser is left running.
const headlessWorkerEnv = "BROWSER_WORKER_URL"

// headlessWorkerDefault is the same address the rest of the project uses.
const headlessWorkerDefault = "http://127.0.0.1:8090"

// headlessProbeTimeoutMs is the default navigation deadline of one probe.
//
// It is a guard against a page that never finishes loading, not a bound on what a
// template may ask for: a `timeout_ms` in the document overrides it, and the value
// that bit is named in the answer.
const headlessProbeTimeoutMs = 20000

// headlessDialogWaitMs is how long a page is given to speak after load.
//
// A dialog fired from `setTimeout` arrives after `load` fires, so a zero wait would
// report `false` for every template whose payload the page renders slightly late.
const headlessDialogWaitMs = 1200

// headlessProbe is one browser answer, in the shape the worker's endpoint returns.
type headlessProbe struct {
	Dialog        bool   `json:"dialog"`
	DialogMessage string `json:"dialog_message"`
	DialogType    string `json:"dialog_type"`
	Dialogs       int    `json:"dialogs"`
	Status        int    `json:"status"`
	Body          string `json:"body"`
	FinalURL      string `json:"final_url"`
	Error         string `json:"error"`
}

// headlessStep is one `steps:` entry.
type headlessStep struct {
	Action string           `yaml:"action"`
	Name   string           `yaml:"name"`
	Args   headlessStepArgs `yaml:"args"`
}

// headlessStepArgs is a step's `args:` map.
//
// It is kept as a map rather than a struct because the measured vocabulary is open —
// `url`, `code`, `by`, `xpath`, `value`, `key`, `max-duration` all appear — and a
// struct would silently drop whatever this project's parser has not heard of, which
// is how a step runs with an argument it never received.
type headlessStepArgs map[string]string

// headlessFuzzRule is one `fuzzing:` entry.
type headlessFuzzRule struct {
	Part string   `yaml:"part"`
	Type string   `yaml:"type"`
	Mode string   `yaml:"mode"`
	Fuzz []string `yaml:"fuzz"`
	Name string   `yaml:"name"`
}

// runHeadlessDocument drives one `headless:` block per entry and scores it.
//
// The browser is asked once per (payload value × fuzzing rule) combination, because
// that is what the document asks for: `dast/vulnerabilities/xss/dom-xss.yaml` sends
// one payload and applies it to both the query and the path, so the page has to be
// loaded twice with different injections.
func runHeadlessDocument(ctx context.Context, document *passiveDocument, blocks []passiveRequest,
	target string, dynamic map[string]string) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	worker := headlessWorkerURL()
	for index, block := range blocks {
		verdict, reason := runHeadlessBlock(ctx, document, block, target, dynamic, worker)
		if reason != "" {
			run.Skipped = true
			run.Reason = fmt.Sprintf("headless block %d of %d: %s", index+1, len(blocks), reason)
			return run
		}
		run.Request += verdict.Request
		run.Response += verdict.Response
		run.Extracts = append(run.Extracts, verdict.Extracts...)
		for name, values := range verdict.ExtractLists {
			run.ExtractLists[name] = append(run.ExtractLists[name], values...)
		}
		if verdict.Matched {
			run.Matched = true
			if len(run.MatcherNames) == 0 {
				run.MatcherNames = verdict.MatcherNames
			}
			// `stop-at-first-match` is honoured below, inside `runHeadlessBlock`,
			// because stopping early is what it is for: every further combination is
			// another page load whose answer the operator does not need.
			break
		}
	}
	// A block that ran and found nothing is a **negative result**, not a refusal, and
	// this runner does not mark it as one.
	//
	// Measured: it used to, and 25 of the 222 corpus blocks came back labelled as
	// "ran and matched nothing" — a sentence that reads as a failure to run while
	// describing a check that ran to the end against a live browser. `skipped` means
	// "not performed", and a row saying that is a statement the run cannot back; the
	// HTTP path was fixed for exactly this earlier, and the headless path was left
	// with the same defect.
	return run
}

// runHeadlessBlock performs one block's combinations.
func runHeadlessBlock(ctx context.Context, document *passiveDocument, block passiveRequest,
	target string, dynamic map[string]string, worker string) (LocalRun, string) {
	out := LocalRun{TemplateID: document.ID, Name: document.Info.Name}

	navigate, reason := headlessNavigateStep(block)
	if reason != "" {
		return out, reason
	}
	if navigate == "" {
		return out, "the block's steps name no `navigate` action, so there is no page to open"
	}
	combinations, reason := headlessCombinations(block)
	if reason != "" {
		return out, reason
	}
	if len(combinations) == 0 {
		// A block with no `fuzzing:` still navigates once, unchanged — measured, 24
		// of the 222 corpus blocks are exactly that shape: `navigate`, then a
		// `waitdialog` or a `script` that judges the page as it is. Refusing them
		// for "nothing to send" threw away the check; there is something to send,
		// and it is the step's own `navigate`.
		combinations = []headlessFuzz{{target: "none"}}
	}

	// The navigate URL is written `{{BaseURL}}` in the corpus, and it is the run's
	// own target — a browser given the literal text would open a host that does not
	// exist, and the block would report nothing on a page nobody ever reached.
	parsedTarget := mustParseTarget(target)
	page := expandDynamic(navigate, parsedTarget, dynamic)
	for _, combination := range combinations {
		if err := ctx.Err(); err != nil {
			return out, "the run was cancelled: " + oneLine(err.Error())
		}
		pageURL, headers, reason := applyHeadlessFuzz(page, combination)
		if reason != "" {
			return out, reason
		}
		answer, reason := headlessProbeOnce(ctx, worker, pageURL, headers)
		if reason != "" {
			return out, reason
		}
		parts, native, transcript := headlessParts(block, answer, combination)
		exchange := PassiveExchange{
			Method:      "HEADLESS",
			URL:         pageURL,
			Host:        mustParseTarget(pageURL).Host,
			RawRequest:  transcript,
			RawResponse: answer.Body,
			Body:        answer.Body,
			StatusCode:  answer.Status,
			Header:      http.Header{},
			Parts:       parts,
			Native:      native,
		}
		verdict := scoreCompiled(document, block, exchange)
		out.Request += transcript
		out.Response += answer.Body
		out.Extracts = append(out.Extracts, verdict.Extracts...)
		for name, values := range verdict.ExtractLists {
			out.ExtractLists[name] = append(out.ExtractLists[name], values...)
		}
		if verdict.Matched {
			out.Matched = true
			out.MatcherNames = verdict.MatcherNames
			return out, ""
		}
	}
	return out, ""
}

// headlessParts turns a browser answer into the parts a matcher reads.
//
// `<name>` is `"true"` or `"false"` — whether the named step saw anything — and
// `<name>_message` is what it saw. Both spellings come from the corpus DSL
// (`reflected == true`, `reflected_message == num`), and they are written as text
// because a `dsl:` matcher compares against a string.
func headlessParts(block passiveRequest, answer headlessProbe, combination headlessFuzz) (
	map[string]string, map[string]interface{}, string) {
	native := map[string]interface{}{}
	parts := map[string]string{
		"body":        answer.Body,
		"response":    answer.Body,
		"raw":         answer.Body,
		"status_code": strconv.Itoa(answer.Status),
		"dialog":      strconv.FormatBool(answer.Dialog),
		"final_url":   answer.FinalURL,
	}
	if answer.Error != "" {
		parts["error"] = answer.Error
	}
	for _, step := range block.HeadlessSteps {
		if step.Action != "waitdialog" || strings.TrimSpace(step.Name) == "" {
			continue
		}
		name := strings.TrimSpace(step.Name)
		// The flag is a **bool**, exactly as nuclei's own headless runtime writes it
		// (`page_actions.go:931`: `out[act.Name] = true`). Measured: with a bool the
		// corpus expression `reflected == true` matches, with the string "true" the
		// same expression cannot match at all — govaluate compares the parameter to a
		// bool. A string here would have left 203 of the 222 corpus blocks unable to
		// fire, while every test on them stayed green.
		//
		// A step naming several dialogs matched when at least one appeared, which is
		// what nuclei's `waitdialog` means and what `dialogs == 1` would lose.
		native[name] = answer.Dialog
		parts[name+"_message"] = answer.DialogMessage
		parts[name+"_count"] = strconv.Itoa(answer.Dialogs)
		if answer.DialogType != "" {
			// nuclei's own runtime writes `<name>_type` from the dialog's own type
			// (`out[act.Name+"_type"]`), so a template may branch on it.
			parts[name+"_type"] = answer.DialogType
		}
	}
	transcript := fmt.Sprintf("HEADLESS %s\n", combination.target)
	if combination.headerName != "" {
		transcript += "with header " + combination.headerName + ": " + combination.headerValue + "\n"
	}
	if answer.Dialog {
		transcript += "dialog: " + answer.DialogMessage + "\n"
	} else {
		transcript += "dialog: none\n"
	}
	if answer.Status > 0 {
		transcript += "status: " + strconv.Itoa(answer.Status) + "\n"
	}
	if answer.Error != "" {
		transcript += "browser: " + answer.Error + "\n"
	}
	return parts, native, transcript
}

// headlessFuzz is one resolved (payload value × fuzzing rule) pair.
type headlessFuzz struct {
	target      string
	headerName  string
	headerValue string
	value       string
}

// headlessCombinations expands the block's payloads and fuzzing rules.
//
// Measured over the corpus: `payloads:` in 198 of the 222 documents and `fuzzing:` in
// 196, so a block is normally a small cross product rather than a single injection.
// The cross product is walked in a fixed order — payload values in written order,
// rules in written order — because a `stop-at-first-match` block then stops on the
// same combination twice, and a run that reports a different one each time cannot be
// reproduced.
func headlessCombinations(block passiveRequest) ([]headlessFuzz, string) {
	rules, reason := headlessFuzzRules(block)
	if reason != "" {
		return nil, reason
	}
	if len(rules) == 0 {
		return nil, ""
	}
	out := []headlessFuzz{}
	for ruleIndex, rule := range rules {
		part := strings.ToLower(strings.TrimSpace(rule.Part))
		switch part {
		case "query", "path", "header", "":
		default:
			return nil, fmt.Sprintf(
				"the fuzzing rule %d injects into %q; this runner performs `query`, `path` and `header`",
				ruleIndex+1, rule.Part)
		}
		if len(rule.Fuzz) == 0 {
			return nil, fmt.Sprintf("the fuzzing rule %d carries no `fuzz:` values to send", ruleIndex+1)
		}
		for _, raw := range rule.Fuzz {
			// The combination's own position, so `{{num}}` counts combinations rather
			// than repeating per rule.
			number := len(out)
			value, missing := expandHeadlessPayload(raw, headlessPayloads(block), number)
			if len(missing) > 0 {
				return nil, fmt.Sprintf(
					"the fuzzing rule %d names payload %s, which the document does not declare (it declares %s)",
					ruleIndex+1, strings.Join(missing, ", "), describePayloads(headlessPayloads(block)))
			}
			// `{{num}}` counts the combination, so a payload written `alert({{num}})`
			// carries a distinct marker per attempt and `…_message == num` can match
			// only the attempt whose marker came back.
			out = append(out, headlessFuzz{
				value:      value,
				headerName: strings.TrimSpace(rule.Name),
				target:     part,
			})
		}
	}
	return out, ""
}

// headlessFuzzRules reads the block's `fuzzing:` rules.
//
// Same reason as `headlessPayloads`: `passiveRequest` already carries
// `fuzzing` as raw `yaml.Node` for the HTTP protocol, and a second field with the
// same tag makes `yaml.v3` panic on every document — measured twice, once for
// `payloads` and once for this. The rules are therefore read from the nodes the
// block already holds.
func headlessFuzzRules(block passiveRequest) ([]headlessFuzzRule, string) {
	if len(block.Fuzzing) == 0 {
		return nil, ""
	}
	out := make([]headlessFuzzRule, 0, len(block.Fuzzing))
	for position, node := range block.Fuzzing {
		var rule headlessFuzzRule
		if err := node.Decode(&rule); err != nil {
			return nil, fmt.Sprintf("fuzzing rule %d cannot be read: %s", position+1, oneLine(err.Error()))
		}
		out = append(out, rule)
	}
	return out, ""
}

// headlessPayloads reads the block's `payloads:` map as the lists of values a
// `fuzzing:` rule may address.
//
// The key is shared with the HTTP block's own `payloads:` — a `headless:` block is
// decoded into the same struct — so a second field with the same YAML tag would
// make `yaml.v3` panic on `duplicated key 'payloads'` for **every** document,
// including the ones that were working. Measured: the panic fired before a single
// assertion ran.
//
// The values arrive as `interface{}` because nuclei's own payload reader does too,
// and a headless payload is a list of strings.
func headlessPayloads(block passiveRequest) map[string][]string {
	if len(block.Payloads) == 0 {
		return nil
	}
	out := make(map[string][]string, len(block.Payloads))
	for name, raw := range block.Payloads {
		switch typed := raw.(type) {
		case string:
			out[name] = []string{typed}
		case []interface{}:
			for _, item := range typed {
				out[name] = append(out[name], fmt.Sprint(item))
			}
		case []string:
			out[name] = append(out[name], typed...)
		default:
			out[name] = []string{fmt.Sprint(typed)}
		}
	}
	return out
}

// describePayloads names what a document does declare.
func describePayloads(payloads map[string][]string) string {
	if len(payloads) == 0 {
		return "none"
	}
	names := make([]string, 0, len(payloads))
	for name := range payloads {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// expandHeadlessPayload substitutes a fuzz value's own placeholders.
//
// Three spellings, all measured in the corpus: `{{name}}` for a declared payload,
// `{{url_encode(name)}}` for the same value as a query component, and `{{num}}` for the
// value's own index — which is why a payload written `alert({{num}})` carries a
// distinct marker per attempt and a template can compare `…_message == num`.
// The placeholder delimiters, named rather than spelled inline.
//
// Written inline they read as `"{{url_encode(" + name + "}}"` and `"{{" + name +
// "}}"`, which is three adjacent brace pairs on one line — and that line is the one
// this file could not be parsed past, with the compiler pointing at a `,` and
// reporting a string literal that was plainly closed. Naming the halves removes the
// ambiguity instead of debugging it.
const (
	headlessEncodePrefix = "url_encode("
	headlessEncodeSuffix = ")"
	headlessPlainPrefix  = "{{"
	headlessPlainSuffix  = "}}"
	headlessNumberToken  = "{{num}}"
)

func expandHeadlessPayload(raw string, payloads map[string][]string, number int) (string, []string) {
	// `{{num}}` first, and deliberately: `url_encode` percent-escapes braces, so a
	// number substituted afterwards is no longer the token
	// `{{url_encode(`+`name`+`)}}` closes with. Measured, the escaped form reached the
	// page literally — `marker-%7B%7Bnum%7D%7D` — so every payload that counts its own
	// attempts sent a constant, and `…_message == num` could never hold.
	out := replaceAll(raw, headlessNumberToken, strconv.Itoa(number))
	// One pass per payload group, plus one more, and **not** one pass over a map.
	//
	// A payload may name another payload: the corpus declares
	// `payload: ['{{concat("{{", "{{first}}*{{second}}", "}}")}}']`, and `{{first}}`
	// only appears after `{{payload}}` has been substituted. With a single pass over a
	// Go map the order is random, so the inner name was substituted when it was not yet
	// there and never again — measured, the value arrived as
	// `{{{{first}}}}`, braces and all, and the page reflected that.
	//
	// The bound is `len(payloads)+1` passes because each pass can only introduce names
	// that were already declared, so the text cannot keep changing after that.
	for pass := 0; pass <= len(payloads); pass++ {
		before := out
		for name, values := range payloads {
			value := ""
			if len(values) > 0 {
				// Inside the payload too, and before `url_encode`: a payload written
				// `evidence-{{num}}` escaped first becomes
				// `evidence-%7B%7Bnum%7D%7D`, which the page reflects literally. Measured —
				// the transcript carried that exact string, so the attempt number never
				// reached anything at all.
				value = replaceAll(values[number%len(values)], headlessNumberToken, strconv.Itoa(number))
			}
			out = replaceAll(out, headlessPlainPrefix+headlessEncodePrefix+name+headlessEncodeSuffix+headlessPlainSuffix,
				url.QueryEscape(value))
			out = replaceAll(out, headlessPlainPrefix+name+headlessPlainSuffix, value)
		}
		if out == before {
			break
		}
	}
	// Everything undeclared is named **before** `concat` is expanded, because a
	// concatenation may legitimately build text full of braces: the corpus payload
	// `{{concat("{{", "{{first}}*{{second}}", "}}")}}` produces `{{first*second}}`,
	// which is the point of it. Checking afterwards would call that result an
	// undeclared placeholder and refuse a document that is in fact complete.
	if missing := headlessUndeclaredNames(raw, payloads); len(missing) > 0 {
		return out, missing
	}
	// `concat(…)` last, and deliberately: its arguments carry `{{name}}` references
	// that must already be resolved, or the concatenation would build a string full
	// of placeholder text instead of the page's payload.
	built, why := expandHeadlessConcat(out)
	if why != "" {
		return out, []string{why}
	}
	return built, nil
}

// expandHeadlessConcat replaces `{{concat("a", "b")}}` with `a`+`b`.
//
// Measured on one corpus document — `angular-client-side-template-injection.yaml`
// carries the payload `{{concat("{{", "{{first}}*{{second}}", "}}")}}`, which builds
// the `{{first*second}}` an Angular expression uses. Splitting is on commas that are
// neither inside a quoted argument nor inside parentheses, because the arguments are
// themselves brace-bearing text.
func expandHeadlessConcat(text string) (string, string) {
	for {
		start := strings.Index(text, headlessConcatPrefix)
		if start < 0 {
			return text, ""
		}
		arguments, width := headlessConcatArguments(text[start:])
		if width == 0 {
			return text, headlessConcatPrefix + "… is not closed"
		}
		var built strings.Builder
		for _, argument := range splitHeadlessArguments(arguments) {
			built.WriteString(unquoteHeadlessArgument(argument))
		}
		text = text[:start] + built.String() + text[start+width:]
	}
}

// unquoteHeadlessArgument removes the quotes that delimited an argument.
//
// Measured: keeping them built `"{{" "firstValue*secondValue" "}}"`, so the
// concatenation produced a quoted, comma-separated string instead of the text the
// page is meant to evaluate.
func unquoteHeadlessArgument(argument string) string {
	trimmed := strings.TrimSpace(argument)
	if len(trimmed) >= 2 {
		first, last := trimmed[0], trimmed[len(trimmed)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return trimmed[1 : len(trimmed)-1]
		}
	}
	return trimmed
}

// splitHeadlessArguments splits on commas that are outside quotes and parentheses.
func splitHeadlessArguments(text string) []string {
	var out []string
	depth, quoted, start := 0, byte(0), 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case quoted != 0:
			if c == quoted {
				quoted = 0
			}
		case c == '"' || c == '\'':
			quoted = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	return append(out, text[start:])
}

// headlessUndeclaredNames names the payloads a fuzz value references but the
// document never declares.
//
// It reads the **raw** value, before anything is substituted, and that is the whole
// point: the question is "which names does this document fail to declare?", and
// asking it of the substituted text asked a different one. Measured: after
// substitution the text was `{{concat("{{", "firstValue*secondValue", "}}")}}`,
// whose braces come from the concatenation itself, and the scanner called them an
// undeclared placeholder — refusing a document that was complete.
//
// `num` and the two helper spellings are not payload names: `{{num}}` is answered
// by this function's caller and `{{url_encode(x)}}`/`{{concat(…)}}` name the helper
// plus an argument, not a group.
func headlessUndeclaredNames(raw string, payloads map[string][]string) []string {
	var missing []string
	headlessScanNames(raw, payloads, &missing, false)
	return missing
}

// headlessScanNames walks one text, appending every payload name it references that
// the document does not declare.
//
// A named function rather than a closure because it recurses: a `concat(…)` call's
// arguments are themselves text with names in them. Written as `scan := func() {
// … scan(…) }` it does not compile at all — Go reports `undefined: scan` inside the
// initializer, which is the least informative message the failure could have had.
// `wordOnly` is set when the text is a concat argument: there a token counts as a
// name only if it is exactly `{{word}}`. The corpus writes the literal pair of
// braces as its own argument — `concat("{{", …)` — and without this that `{{` paired
// with the next `}}` and produced a token named `{{, {{first}}`, refusing a complete
// document for a payload declared two lines above.
func headlessScanNames(text string, payloads map[string][]string, missing *[]string, wordOnly bool) {
	for cursor := 0; cursor < len(text); {
		start := strings.Index(text[cursor:], headlessPlainPrefix)
		if start < 0 {
			return
		}
		cursor += start
		// A `concat(…)` call is a construct, not a payload name, and its own closing
		// is `)}}` rather than the `}}` that ends the braces inside its arguments.
		// Measured: scanning naively read
		// `{{concat("{{", "{{first}}*{{second}}", "}}")}}` as one token named
		// `concat("{{", "{{first}}*{{second}}`, and refused a complete document for a
		// payload it declares two lines above.
		if strings.HasPrefix(text[cursor:], headlessConcatPrefix) {
			arguments, width := headlessConcatArguments(text[cursor:])
			if width == 0 {
				return
			}
			// Quoted spans **inside** a concat call are literal: the corpus writes
			// `concat("{{", …)` to produce a pair of braces, and a scanner that read
			// that `{{` as a placeholder opener reported the token `{{", "{{first}}`
			// and refused a complete document.
			//
			// Known limit, stated rather than hidden: a payload name that appears
			// **only** inside such a quoted argument is substituted but not reported
			// as undeclared. One corpus document does this; the substitution still
			// happens, so the page receives the placeholder text instead of a value,
			// and the transcript shows it.
			headlessScanNames(headlessUnquoteHeadlessSpans(arguments), payloads, missing, true)
			cursor += width
			continue
		}
		end := strings.Index(text[cursor:], headlessPlainSuffix)
		if end < 0 {
			return
		}
		token := text[cursor+2 : cursor+end]
		cursor += end + 2
		if wordOnly && !isHeadlessWord(token) {
			continue
		}
		// The braces are already stripped, so the helper is spelled `url_encode(x)`
		// here, not `{{url_encode(x)}}`. Measured: it did not match either prefix, so
		// every `{{url_encode(injection)}}` in the corpus was reported as an
		// undeclared payload named `url_encode(injection)` — **192 of the 222 blocks**,
		// refused over a payload the document declares on the line above.
		name := token
		if strings.HasPrefix(name, headlessEncodePrefix) && strings.HasSuffix(name, ")") {
			name = strings.TrimSuffix(strings.TrimPrefix(name, headlessEncodePrefix), ")")
		}
		switch name {
		case "num", "concat", "":
			continue
		}
		if _, declared := payloads[name]; !declared {
			*missing = append(*missing, headlessPlainPrefix+token+headlessPlainSuffix)
		}
	}
}

// isHeadlessWord reports whether a token is a plain name: a payload group, a helper,
// or `num`. Anything else is literal text that happens to sit between braces.
func isHeadlessWord(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if !isLetter && !(isDigit && i > 0) {
			return false
		}
	}
	return true
}

// headlessUnquoteHeadlessSpans removes the quotes of a concat call's arguments,
// leaving the text between them.
//
// It is used only for **checking**, never for building: the value keeps its quotes'
// content and loses only the delimiters, which `unquoteHeadlessArgument` does per
// argument when the concatenation is actually performed.
func headlessUnquoteHeadlessSpans(text string) string {
	var out strings.Builder
	quoted := byte(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quoted != 0:
			if c == quoted {
				quoted = 0
				continue
			}
			out.WriteByte(c)
		case c == '"' || c == '\'':
			quoted = c
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

// headlessConcatPrefix is the construct's opening, as it is written in a payload.
const headlessConcatPrefix = "{{concat("

// headlessConcatArguments returns a `concat(…)` call's arguments and the width of
// the whole call, so a caller can step past it instead of through it.
//
// A width of zero means the call is not closed, which the caller reports rather than
// guessing at the end of the text.
func headlessConcatArguments(text string) (string, int) {
	after := len(headlessConcatPrefix)
	depth, quoted, end := 0, byte(0), -1
	for i := after; i < len(text); i++ {
		switch c := text[i]; {
		case quoted != 0:
			if c == quoted {
				quoted = 0
			}
		case c == '"' || c == '\'':
			quoted = c
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				end = i
			} else {
				depth--
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 || end+2 >= len(text) || text[end+1] != '}' || text[end+2] != '}' {
		return "", 0
	}
	return text[after:end], end + 3
}

// applyHeadlessFuzz injects one value into the page's URL or headers.
func applyHeadlessFuzz(pageURL string, fuzz headlessFuzz) (string, map[string]string, string) {
	switch fuzz.target {
	case "none", "":
		// No injection: the block's own steps are the whole check.
		return pageURL, nil, ""
	case "query":
		separator := "?"
		if strings.Contains(pageURL, "?") {
			separator = "&"
		}
		return pageURL + separator + fuzz.value, nil, ""
	case "path":
		parsed, err := url.Parse(pageURL)
		if err != nil {
			return "", nil, "the step's url cannot be read: " + oneLine(err.Error())
		}
		parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + fuzz.value
		return parsed.String(), nil, ""
	case "header":
		// An empty part and a missing header are the same refusal: nuclei treats a
		// rule with no `part:` as a header injection, and a header nobody named is a
		// header the operator did not choose.
		if strings.TrimSpace(fuzz.headerName) == "" {
			return "", nil, fmt.Sprintf(
				"the fuzzing rule injects into a header but names none, and there is no default: " +
					"a header a template did not name is a header the operator did not choose")
		}
		return pageURL, map[string]string{fuzz.headerName: fuzz.value}, ""
	}
	return "", nil, fmt.Sprintf("this runner performs `query`, `path` and `header`, not %q", fuzz.target)
}

// headlessNavigateStep finds the `navigate` action and its URL.
func headlessNavigateStep(block passiveRequest) (string, string) {
	for _, step := range block.HeadlessSteps {
		if strings.EqualFold(step.Action, "navigate") {
			raw, _ := step.Args["url"]
			if strings.TrimSpace(raw) == "" {
				return "", "the `navigate` step carries no `args.url`"
			}
			return strings.TrimSpace(raw), ""
		}
	}
	return "", ""
}

// headlessWorkerURL is the browser worker's address.
func headlessWorkerURL() string {
	if configured := strings.TrimSpace(os.Getenv(headlessWorkerEnv)); configured != "" {
		return strings.TrimSuffix(configured, "/")
	}
	return headlessWorkerDefault
}

// headlessProbeOnce asks the worker to open one page and report what it did.
//
// A refusal names its cause instead of returning a blank answer: the difference
// between "the page said nothing" and "the browser never started" is the difference
// between a negative and an unperformed check.
func headlessProbeOnce(ctx context.Context, worker, pageURL string, headers map[string]string) (headlessProbe, string) {
	body, err := json.Marshal(map[string]any{
		"url":               pageURL,
		"timeout_ms":        headlessProbeTimeoutMs,
		"dialog_timeout_ms": headlessDialogWaitMs,
		"wait_load":         true,
		"headers":           headers,
	})
	if err != nil {
		return headlessProbe{}, "cannot describe the probe: " + oneLine(err.Error())
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		worker+"/headless/probe", bytes.NewReader(body))
	if err != nil {
		return headlessProbe{}, "cannot address the browser worker: " + oneLine(err.Error())
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return headlessProbe{}, fmt.Sprintf(
			"the browser worker at %s did not answer (%s). `headless:` needs the project's own "+
				"Playwright service, because the value a template judges on is the text of an "+
				"`alert()` the page fires, and only a browser can see it",
			worker, oneLine(err.Error()))
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if readErr != nil {
		return headlessProbe{}, "the browser worker's answer was cut short: " + oneLine(readErr.Error())
	}
	var answer headlessProbe
	if err := json.Unmarshal(raw, &answer); err != nil {
		return headlessProbe{}, fmt.Sprintf("the browser worker answered %d with text that is not JSON: %s",
			response.StatusCode, oneLine(truncateOutput(string(raw))))
	}
	if response.StatusCode != http.StatusOK {
		return headlessProbe{}, fmt.Sprintf("the browser worker answered %d: %s",
			response.StatusCode, oneLine(truncateOutput(answer.Error)))
	}
	if strings.TrimSpace(answer.Error) != "" {
		// The browser was reached and the page did not behave. That is an outcome of
		// the check, so it is scored rather than refused: a template that judges on a
		// dialog simply finds none.
		answer.Dialog = false
		answer.DialogMessage = ""
	}
	return answer, ""
}

// replaceAll is `strings.ReplaceAll` under a name this file owns, so the placeholder
// helpers above read as substitutions instead of as concatenated string literals.
func replaceAll(text, old, new string) string {
	return strings.ReplaceAll(text, old, new)
}

// headlessDeadline keeps the wall-clock bound of one document visible in the log.
const headlessDeadline = 5 * time.Minute
