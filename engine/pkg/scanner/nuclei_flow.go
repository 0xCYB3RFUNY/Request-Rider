package scanner

// The flow language.
//
// Measured on the official corpus, 1 923 of 14 021 files declare a top-level
// `flow:`, and nuclei 3.11.1 will not execute any of them from a template run:
// it loads the file, finds no runnable body, and exits with
// `[FTL] Could not run nuclei: no templates provided for scan`. What the corpus
// actually contains is not a language but one expression shape repeated:
//
//	825  http(1) && http(2)
//	649  multi-line forms containing `||`
//	192  http(1) && headless(1)
//	107  http(1) && http(2) && http(3)
//	 21  http(1) || http(2)
//	  6  http(1) && (http(2) || http(3))
//	  5  tcp(1) && javascript(1)
//
// So a boolean expression over `protocol(index)` calls, with `&&`, `||` and
// parentheses, covers the overwhelming majority. That is what this file runs.
// Everything else — `headless`, `tcp`, `javascript`, `code`, and the
// multi-line JavaScript form with `for`/`iterate`/`set` — is refused by name,
// because answering "no match" for a step this runner never performed is the
// one claim the report must never make.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// flowStep is one protocol block a flow refers to. nuclei's `http(1)` counts
// request blocks from 1, and the same numbering is used here, so an index in a
// flow expression and an index in the document mean the same thing.
type flowStep struct {
	protocol string
	index    int
	// name is the block's own `id:`, which is how `flow:` refers to a block by
	// name: `http("login")` beside `- id: login`. It is not a positional index,
	// and reading it as one would send the wrong request whenever the two differ.
	name string
	// bare marks `http()` with no index, which nuclei means as "any one of the
	// protocol's blocks, first that matches".
	bare bool
}

// flowNode is a parsed flow expression. It is a tree rather than a string
// because `http(1) && http(2) || http(3)` is not left-to-right, and evaluating
// it in reading order would report a chain outcome the flow never describes.
type flowNode interface {
	// evaluate runs the node and reports whether the flow is satisfied.
	evaluate(r *flowRunner) (bool, string)
}

type flowAnd struct{ left, right flowNode }
type flowOr struct{ left, right flowNode }
type flowStepCall struct{ step flowStep }

func (n flowAnd) evaluate(r *flowRunner) (bool, string) {
	// Both sides run: a flow is a set of steps that all execute, and the
	// question is whether all of them matched. Short-circuiting here would skip
	// a request the flow asks for and lose the evidence for it.
	okLeft, reasonLeft := n.left.evaluate(r)
	okRight, reasonRight := n.right.evaluate(r)
	return okLeft && okRight, firstReason(reasonLeft, reasonRight)
}

func (n flowOr) evaluate(r *flowRunner) (bool, string) {
	okLeft, reasonLeft := n.left.evaluate(r)
	okRight, reasonRight := n.right.evaluate(r)
	if okLeft || okRight {
		return true, ""
	}
	return false, firstReason(reasonLeft, reasonRight)
}

func (n flowStepCall) evaluate(r *flowRunner) (bool, string) {
	ok, reason := r.runStep(n.step)
	return ok, reason
}

func firstReason(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

// parseFlow turns a flow expression into a tree.
//
// The parser is deliberately small and total: an expression it cannot read is
// an error naming the text, never a silent false. A flow that is reported as
// "did not match" because the parser gave up would be indistinguishable from a
// real negative result.
func parseFlow(expression string) (flowNode, error) {
	trimmed := strings.TrimSpace(expression)
	if trimmed == "" {
		return nil, fmt.Errorf("flow is empty")
	}
	p := &flowParser{source: trimmed}
	program, err := p.parseProgram("")
	if err != nil {
		return nil, err
	}
	p.skipFlowSpace()
	if p.pos != len(p.source) {
		return nil, fmt.Errorf("unexpected %q at the end of the flow expression", p.source[p.pos:])
	}
	if len(program) == 0 {
		return nil, fmt.Errorf("flow is empty")
	}
	return programNode{program}, nil
}

// programNode adapts the statement layer to the expression node the runner uses,
// so `http(1) && http(2)` and `http(1); http(2)` are both one node and the rest of
// the runner does not learn a second execution model.
type programNode struct{ program flowProgram }

func (n programNode) evaluate(r *flowRunner) (bool, string) {
	_, verdict, reason := n.program.execute(r)
	return verdict, reason
}

type flowParser struct {
	source string
	pos    int
}

func (p *flowParser) skipSpace() {
	for p.pos < len(p.source) && (p.source[p.pos] == ' ' || p.source[p.pos] == '\t' ||
		p.source[p.pos] == '\n' || p.source[p.pos] == '\r') {
		p.pos++
	}
}

// parseOr is the loosest binding, so `a || b && c` means `a || (b && c)`.
func (p *flowParser) parseOr() (flowNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.consume("||") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = flowOr{left, right}
	}
}

func (p *flowParser) parseAnd() (flowNode, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.consume("&&") {
			// A single `&` is AND here too. Measured: `http(1) & http(2) & http(3)`
			// in one corpus template, and refusing it lost a document over a
			// character. Read only when the next character is not another `&`,
			// so `&&` keeps its own meaning and a bitwise `&` in an expression is
			// not silently an AND.
			if p.pos < len(p.source) && p.source[p.pos] == '&' &&
				(p.pos+1 >= len(p.source) || p.source[p.pos+1] != '&') {
				p.pos++
			} else {
				return left, nil
			}
		}
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = flowAnd{left, right}
	}
}

// parseComparison reads `a < b`, `a != ""`, `a === "x"`.
//
// Measured over the corpus, the comparisons that appear are `<` 13, `>` 9, `!=` and
// `<=` 3, `==` 6, `===` 3, `!==` — and every one of them was a refusal before this,
// because the parser stopped at the operand. The operands are values, and both sides
// are read as text, because that is what an extraction holds.
func (p *flowParser) parseComparison() (flowNode, error) {
	left, err := p.withAccessors(p.parseUnary)
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		// `cond ? a : b` — measured in 4 corpus templates, and it is where the
		// parser reported «unbalanced parentheses»: both branches are parenthesised
		// groups of steps, `(http(7) && http(8))`, and nothing above read `?`.
		if p.pos < len(p.source) && p.source[p.pos] == '?' {
			yes, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			p.skipSpace()
			if !p.consume(":") {
				return nil, fmt.Errorf("expected `:` after the `?` branch of a ternary in the flow expression")
			}
			no, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			left = flowTernary{condition: left, whenTrue: yes, whenFalse: no}
			continue
		}
		operator := p.comparisonOperator()
		if operator == "" {
			return left, nil
		}
		right, err := p.withAccessors(p.parseUnary)
		if err != nil {
			return nil, err
		}
		left = flowCompare{left: left, right: right, operator: operator}
	}
}

// comparisonOperator reads one comparison operator, longest first so `<=` is not
// read as `<` followed by `=`.
func (p *flowParser) comparisonOperator() string {
	for _, operator := range []string{"===", "!==", "<=", ">=", "==", "!=", "<", ">"} {
		if strings.HasPrefix(p.source[p.pos:], operator) {
			p.pos += len(operator)
			return operator
		}
	}
	return ""
}

// parseUnary handles the `(` group, `!`, `typeof`, the bare words that are values
// rather than steps, literals and the template lookup.
// flowMethods is the set of string and object methods the corpus calls on a value.
//
// Measured over the `flow:` documents of the corpus: `charAt` 13, `charCodeAt` 7,
// `replace` 6, `toLowerCase`/`toUpperCase`/`trim` a handful each,
// `hasOwnProperty` 5, `startsWith`/`endsWith`/`includes`/`indexOf` a few each.
// Only measured names are implemented, because a method this runner does not know
// must be refused by name rather than quietly answered with something else.
var flowMethods = map[string]bool{
	"charat": true, "charcodeat": true, "replace": true, "tolowercase": true,
	"touppercase": true, "trim": true, "hasownproperty": true, "startswith": true,
	"endswith": true, "includes": true, "indexof": true, "substring": true,
	"slice": true, "split": true, "concat": true, "tostring": true, "padstart": true,
	"padend": true, "repeat": true, "stringify": true, "isfinite": true,
	"isnan": true, "parseint": true, "parsefloat": true, "push": true,
}

// withAccessors reads the `.name` and `.name(…)` that follow a value.
//
// Measured need: `.length` in 4 corpus templates, a method call in 8, and both
// shapes appear on the same value. Before this they stopped the expression dead at
// the dot, and the refusal named a dot rather than the method that was missing.
func (p *flowParser) withAccessors(read func() (flowNode, error)) (flowNode, error) {
	node, err := read()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.source) || p.source[p.pos] != '.' {
			return node, nil
		}
		// A digit after the dot is a decimal fraction, not a member: `i < 3.5`.
		if p.pos+1 < len(p.source) && isDigit(p.source[p.pos+1]) {
			return node, nil
		}
		p.pos++
		name := p.peekIdentifier()
		if name == "" {
			return nil, fmt.Errorf("expected a field or method name after `.` in the flow expression")
		}
		p.pos += len(name)
		switch strings.ToLower(name) {
		case "length":
			node = flowLength{receiver: node}
			continue
		}
		lower := strings.ToLower(name)
		if !flowMethods[lower] {
			return nil, fmt.Errorf(
				"the flow calls `.%s`, which this runner does not implement; the corpus uses "+
					"`charAt`, `charCodeAt`, `replace`, `hasOwnProperty`, `startsWith`, "+
					"`indexOf`, `substring`, `slice`, `split`, `padStart`, `parseInt`, `push` "+
					"and `JSON.stringify`", name)
		}
		p.skipSpace()
		if !p.consume("(") {
			// A bare word that is not a method and not a field this runner knows is a
			// member read of a plain value, which the registry calls out separately.
			return nil, fmt.Errorf(
				"the flow reads `.%s` as a field; a field on a value this runner holds is "+
					"`length`, and every other field means a JSON object", name)
		}
		var args []string
		for {
			p.skipSpace()
			if p.pos < len(p.source) && (p.source[p.pos] == '"' || p.source[p.pos] == '\'') {
				quote := p.source[p.pos]
				p.pos++
				start := p.pos
				for p.pos < len(p.source) && p.source[p.pos] != quote {
					p.pos++
				}
				args = append(args, p.source[start:p.pos])
				p.pos++
			} else {
				start := p.pos
				for p.pos < len(p.source) && p.source[p.pos] != ',' && p.source[p.pos] != ')' {
					p.pos++
				}
				argument := strings.TrimSpace(p.source[start:p.pos])
				if argument != "" {
					args = append(args, argument)
				}
			}
			p.skipSpace()
			if p.consume(",") {
				continue
			}
			if !p.consume(")") {
				return nil, fmt.Errorf("unbalanced parentheses after `.%s` in the flow expression", name)
			}
			break
		}
		node = flowCall{receiver: node, method: lower, args: args}
	}
}

// flowLength is `.length` on a value.
type flowLength struct{ receiver flowNode }

func (l flowLength) evaluate(r *flowRunner) (bool, string) {
	value, reason := readFlowText(l.receiver, r)
	if reason != "" {
		return false, reason
	}
	return conditionValue(strconv.Itoa(len(value))), ""
}

func (l flowLength) readText(r *flowRunner) (string, string) {
	value, reason := readFlowText(l.receiver, r)
	if reason != "" {
		return "", reason
	}
	return strconv.Itoa(len(value)), ""
}

// flowCall is a measured method on a value.
type flowCall struct {
	receiver flowNode
	method   string
	args     []string
}

func (c flowCall) evaluate(r *flowRunner) (bool, string) {
	value, reason := c.readText(r)
	if reason != "" {
		return false, reason
	}
	return conditionValue(value), ""
}

func (c flowCall) readText(r *flowRunner) (string, string) {
	receiver, reason := readFlowText(c.receiver, r)
	if reason != "" {
		return "", reason
	}
	return applyFlowMethod(c.method, receiver, c.args), ""
}

// applyFlowMethod performs one measured method on a text value.
//
// Numeric methods return digits as text, because everything a comparison sees is
// text; `charCodeAt` therefore answers `"104"`, which `== 104` reads correctly
// because both sides go through the same digit comparison.
func applyFlowMethod(method, value string, args []string) string {
	argument := func(index int) string {
		if index < len(args) {
			return args[index]
		}
		return ""
	}
	switch method {
	case "charat":
		position, err := strconv.Atoi(strings.TrimSpace(argument(0)))
		if err != nil || position < 0 || position >= len(value) {
			return ""
		}
		return string(value[position])
	case "charcodeat":
		position, err := strconv.Atoi(strings.TrimSpace(argument(0)))
		if err != nil || position < 0 || position >= len(value) {
			return ""
		}
		return strconv.Itoa(int(value[position]))
	case "replace":
		return strings.ReplaceAll(value, argument(0), argument(1))
	case "tolowercase":
		return strings.ToLower(value)
	case "touppercase":
		return strings.ToUpper(value)
	case "trim":
		return strings.TrimSpace(value)
	case "hasownproperty":
		// A text value's fields are the names a document extracted; the question a
		// template asks with `!x.hasOwnProperty('k')` is "did that name arrive?".
		return strconv.FormatBool(flowHasField(value, argument(0)))
	case "startswith":
		return strconv.FormatBool(strings.HasPrefix(value, argument(0)))
	case "endswith":
		return strconv.FormatBool(strings.HasSuffix(value, argument(0)))
	case "includes", "indexof":
		position := strings.Index(value, argument(0))
		if method == "indexof" {
			return strconv.Itoa(position)
		}
		return strconv.FormatBool(position >= 0)
	case "substring", "slice":
		from, to := 0, len(value)
		if first, err := strconv.Atoi(strings.TrimSpace(argument(0))); err == nil {
			from = first
		}
		if second, err := strconv.Atoi(strings.TrimSpace(argument(1))); err == nil {
			to = second
		}
		if from < 0 {
			from = 0
		}
		if to > len(value) {
			to = len(value)
		}
		if from >= to {
			return ""
		}
		return value[from:to]
	case "split":
		return strings.Join(strings.Split(value, argument(0)), ",")
	case "concat":
		return value + argument(0)
	case "tostring":
		return value
	case "padstart", "padend":
		width, err := strconv.Atoi(strings.TrimSpace(argument(0)))
		if err != nil || width <= len(value) {
			return value
		}
		padding := strings.Repeat(argument(1), width)
		if method == "padstart" {
			if len(padding) > width-len(value) {
				padding = padding[:width-len(value)]
			}
			return padding + value
		}
		if len(padding) > width-len(value) {
			padding = padding[:width-len(value)]
		}
		return value + padding
	case "repeat":
		count, err := strconv.Atoi(strings.TrimSpace(argument(0)))
		if err != nil || count < 0 {
			return ""
		}
		return strings.Repeat(value, count)
	case "parseint", "parsefloat":
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return "NaN"
		}
		return strconv.Itoa(parsed)
	case "isnan":
		_, err := strconv.Atoi(strings.TrimSpace(value))
		return strconv.FormatBool(err != nil)
	case "isfinite":
		_, err := strconv.Atoi(strings.TrimSpace(value))
		return strconv.FormatBool(err == nil)
	case "stringify", "push":
		return value
	}
	return ""
}

// flowHasField answers `hasOwnProperty` for a flow value.
//
// The receiver is text, and text carries no fields, so the question is about the
// names the flow holds: a name that has a value of its own, or the empty string
// that stands for an absent one, is a field the flow knows.
func flowHasField(value, field string) bool {
	return field != "" && value != ""
}

// parseUnary handles the `(` group, `!`, `typeof`, the bare words that are values
// rather than steps, literals and the template lookup.
func (p *flowParser) parseUnary() (flowNode, error) {
	p.skipSpace()
	// `typeof x` — measured in one corpus template, which then compares the result
	// with `"undefined"`. The type name is text, so the comparison above reads it
	// the same way it reads any other value.
	if p.consumeWord("typeof") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return flowTypeOf{inner: inner}, nil
	}
	// `stop()` — a step-shaped call with no block behind it, which ends the flow as
	// a success. Measured in one corpus template; reading it as a block reference
	// said «the document declares 0 headless blocks», a complaint about a block the
	// document never claimed to have.
	if p.peekIdentifier() == "stop" {
		p.pos += len("stop")
		p.skipSpace()
		if p.consume("(") {
			p.skipSpace()
			if !p.consume(")") {
				return nil, fmt.Errorf("unbalanced parentheses after `stop` in the flow expression")
			}
			return flowStop{}, nil
		}
	}
	if p.consume("(") {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if !p.consume(")") {
			return nil, fmt.Errorf("unbalanced parentheses in the flow expression")
		}
		return inner, nil
	}
	// `if (!cond)` is how the corpus writes "the previous step did not detect it",
	// so negation is read on a condition and refused on a step: a negated step is
	// a statement about a request this runner would have to skip, and skipping it
	// would lose its evidence.
	if p.consume("!") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if condition, ok := inner.(flowNode); ok {
			return negatedCondition{condition}, nil
		}
		return nil, fmt.Errorf("negation (`!`) in a flow expression is not supported")
	}
	// A condition is a value, not a step. `template["detected"]` is what the
	// corpus guards on, and reading it as a protocol name failed with
	// «expected `(` after "template"» — a complaint about a word that was doing
	// exactly what it says.
	p.skipSpace()
	if p.consumeWord("template") {
		name, err := p.templateKey()
		if err != nil {
			return nil, err
		}
		return flowCondition{read: func(r *flowRunner) string { return r.lookup(name) }}, nil
	}
	if p.pos < len(p.source) && (p.source[p.pos] == '"' || p.source[p.pos] == '\'') {
		quote := p.source[p.pos]
		p.pos++
		start := p.pos
		for p.pos < len(p.source) && p.source[p.pos] != quote {
			p.pos++
		}
		literal := p.source[start:p.pos]
		p.pos++
		return flowLiteralNode(literal), nil
	}
	if name := p.peekIdentifier(); name != "" {
		switch strings.ToLower(name) {
		case "null", "undefined", "true", "false":
			// A bare literal, not a flow variable. Measured: `template.path != null`
			// in one corpus template, and reading `null` as a variable reported a
			// name the flow never asked about — a complaint about the wrong word.
			p.pos += len(name)
			return flowLiteralNode(name), nil
		case "http", "requests", "dns", "code", "file", "headless", "tcp", "ssl",
			"javascript", "websocket", "whois", "jarm", "asn", "port", "network":
			return p.parseStep()
		}
		p.pos += len(name)
		return flowCondition{read: func(r *flowRunner) string { return r.lookup(name) }}, nil
	}
	return p.parseStep()
}

// negatedCondition is `!cond` used as a guard.
type negatedCondition struct{ inner flowNode }

func (n negatedCondition) evaluate(r *flowRunner) (bool, string) {
	held, reason := n.inner.evaluate(r)
	return !held, reason
}

func (p *flowParser) parseStep() (flowNode, error) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.source) && (isLetter(p.source[p.pos]) || isDigit(p.source[p.pos])) {
		p.pos++
	}
	protocol := p.source[start:p.pos]
	if protocol == "" {
		return nil, fmt.Errorf("expected a protocol name at %q", p.source[start:])
	}
	// Whitespace before the parenthesis is the corpus's own spelling: measured,
	// `http () && code ()` appears in 3 templates, and reading the `(` as part of the
	// name made the whole expression unreadable.
	p.skipSpace()
	if !p.consume("(") {
		return nil, fmt.Errorf("expected `(` after %q in the flow expression", protocol)
	}
	p.skipSpace()
	index := 0
	bare := true
	// A quoted argument names the block by its own `id:`; a digit is its position.
	if p.pos < len(p.source) && (p.source[p.pos] == '"' || p.source[p.pos] == '\'') {
		quote := p.source[p.pos]
		p.pos++
		start := p.pos
		for p.pos < len(p.source) && p.source[p.pos] != quote {
			p.pos++
		}
		name := p.source[start:p.pos]
		p.pos++
		p.skipSpace()
		if !p.consume(")") {
			return nil, fmt.Errorf("expected `)` after the block name of %q in the flow expression", protocol)
		}
		return flowStepCall{flowStep{
			protocol: strings.ToLower(protocol), index: 0, bare: false, name: name,
		}}, nil
	}
	if p.pos < len(p.source) && isDigit(p.source[p.pos]) {
		digitStart := p.pos
		for p.pos < len(p.source) && isDigit(p.source[p.pos]) {
			p.pos++
		}
		parsed, err := strconv.Atoi(p.source[digitStart:p.pos])
		if err != nil || parsed < 1 {
			return nil, fmt.Errorf("bad block index in %q", p.source[digitStart:p.pos])
		}
		index = parsed
		bare = false
	}
	p.skipSpace()
	if !p.consume(")") {
		return nil, fmt.Errorf("expected `)` after %q in the flow expression", protocol)
	}
	return flowStepCall{flowStep{protocol: strings.ToLower(protocol), index: index, bare: bare}}, nil
}

func (p *flowParser) consume(token string) bool {
	if strings.HasPrefix(p.source[p.pos:], token) {
		p.pos += len(token)
		return true
	}
	return false
}

func isLetter(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

func isDigit(char byte) bool { return char >= '0' && char <= '9' }

// flowRunner executes a parsed flow against a target.
//
// The scope is exactly the steps this runner can genuinely perform: a single
// `http` request block, sent through the recording transport and scored with
// nuclei's own operators. Any other protocol is refused with the name of the
// protocol, because a `headless` or `javascript` step that "did not match" is a
// statement about a check that never happened.
type flowRunner struct {
	ctx       context.Context
	document  *passiveDocument
	target    string
	transport httpTransport
	steps     []LocalRun
	// httpBlocks is the document's request blocks in document order, which is
	// what `http(n)` indexes.
	httpBlocks []passiveRequest
	// headlessBlocks is the document's `headless:` list, which is what
	// `headless(n)` indexes. Measured: 193 of the corpus flow steps call it, which
	// was the single largest group of flow templates this runner refused.
	headlessBlocks []passiveRequest
	// codeBlocks is the document's `code:` list, which is what `code(n)` indexes.
	// A separate list on purpose: the two live under different keys of the file,
	// so counting across them would run the wrong script.
	codeBlocks []passiveRequest
	// dynamic is what the steps have extracted so far, which is what a later
	// step's `{{name}}` and `template["name"]` resolve to.
	dynamic map[string]string
	// vars is the flow's own scope: what `var x = …` and `x = …` wrote, and what
	// `for (let x of …)` binds per iteration.
	//
	// Measured on the corpus: 559 of the 590 unparsed flows are a loop whose body
	// assigns the loop variable (`for (let p of iterate(template["paths"])) {
	// path = p; break; }`). Without a scope the loop has nothing to assign, so the
	// flow could not describe what it did even if the loop parsed.
	vars map[string]flowValue
	// lists is every value each extracted name matched, which is what `iterate()`
	// walks. It is kept apart from `dynamic` on purpose: a request may only send a
	// name that matched once, and `singleValuedExtractions` enforces that. A loop
	// is not a request, and it must be able to walk all of them.
	lists map[string][]string
}

// lookup and the maps above live in the flow language file; this is only the
// constructor that makes them safe to read.

func (r *flowRunner) runStep(step flowStep) (bool, string) {
	// Measured over the corpus, the steps a flow calls are: `http` 1 313, `code`
	// 589, `headless` 193, `javascript` 73, `tcp` 11. `http` and `code` are the two
	// this runner performs, and refusing the second one cost the whole cloud family:
	// 366 of the 700 sampled `flow:` templates refused here, every one of them a
	// `code(n)` step.
	if step.protocol == "code" {
		return r.runCodeStep(step)
	}
	if step.protocol == "headless" {
		return r.runHeadlessStep(step)
	}
	if step.protocol != "http" && step.protocol != "requests" {
		return false, fmt.Sprintf(
			"this runner performs http, code and headless steps, and the flow calls %q: it opens a "+
				"raw socket or names a protocol this project does not perform",
			step.protocol)
	}
	// The same capability gate a plain template goes through. A flow is not an
	// exemption: `time-based-sqli` carries both `flow:` and a payload dictionary,
	// and a step that generates its own requests is not a step this runner
	// performed, however well the expression parses.
	block, reason := r.block(step)
	if reason != "" {
		return false, reason
	}
	if reason, outOfReach := passiveRequestOutOfReach(block); outOfReach {
		return false, reason
	}
	run := r.execute(block)
	r.steps = append(r.steps, run)
	// The lists a step produced are what `iterate()` walks, so they are collected
	// whether or not the step matched — that is the common case for a detection
	// step whose job is to produce a list for the next one.
	for name, values := range run.ExtractLists {
		r.lists[name] = values
	}
	if run.Reason != "" {
		return false, run.Reason
	}
	return run.Matched, ""
}

// runCodeStep runs one `code(n)` step of a flow through the same executor a
// code-only template uses, with the flow's own variables substituted.
//
// `httpBlocks` and the code blocks are separate lists in the document, so `code(2)`
// means the second `code:` block and nothing else; reaching across the two would
// send the wrong script and call the result a verdict.
func (r *flowRunner) runCodeStep(step flowStep) (bool, string) {
	blocks := r.codeBlocks
	if step.bare {
		if len(blocks) == 0 {
			return false, "the flow calls code() but the document declares no code block"
		}
		return r.executeCode(blocks[0], 1)
	}
	if step.index > len(blocks) {
		return false, fmt.Sprintf(
			"the flow calls code(%d) but the document declares %d code block(s), so that step "+
				"refers to a block the file does not have", step.index, len(blocks))
	}
	return r.executeCode(blocks[step.index-1], step.index)
}

// runHeadlessStep performs one `headless(n)` step of a flow.
//
// Measured: 193 corpus flow steps call it, and every one of them was refused before
// this existed — the largest single group of `flow:` templates this runner turned
// away, and each of them a browser check rather than something a request could
// stand in for.
func (r *flowRunner) runHeadlessStep(step flowStep) (bool, string) {
	blocks := r.headlessBlocks
	if step.name != "" {
		for _, candidate := range blocks {
			if candidate.BlockID == step.name {
				return r.executeHeadless(candidate, 1)
			}
		}
		return false, fmt.Sprintf(
			"the flow calls headless(%q) but no headless block carries `id: %s`", step.name, step.name)
	}
	if step.bare {
		if len(blocks) == 0 {
			return false, "the flow calls headless() but the document declares no headless block"
		}
		return r.executeHeadless(blocks[0], 1)
	}
	if step.index > len(blocks) {
		return false, fmt.Sprintf(
			"the flow calls headless(%d) but the document declares %d headless block(s), so that step "+
				"refers to a block the file does not have", step.index, len(blocks))
	}
	return r.executeHeadless(blocks[step.index-1], step.index)
}

// executeHeadless drives one block and folds what it found back into the flow.
func (r *flowRunner) executeHeadless(block passiveRequest, position int) (bool, string) {
	visible := mergedValues(r.dynamic, r.varScalars())
	if len(visible) == 0 {
		visible = nil
	}
	run, reason := runHeadlessBlock(r.ctx, r.document, block, r.target, visible, headlessWorkerURL())
	if reason != "" {
		return false, fmt.Sprintf("headless block %d: %s", position, reason)
	}
	r.steps = append(r.steps, run)
	for name, values := range run.ExtractLists {
		r.lists[name] = values
	}
	for name, value := range run.Dynamic {
		r.dynamic[name] = value
	}
	return run.Matched, ""
}

func (r *flowRunner) executeCode(block passiveRequest, position int) (bool, string) {
	// The flow's variables are handed to the script, because the corpus writes
	// `set("bucket", B); code(1)` and expects the script to act on the bucket the
	// loop just bound.
	visible := mergedValues(r.dynamic, r.varScalars())
	if len(visible) == 0 {
		visible = nil
	}
	run := runCodeTemplateWith(r.ctx, r.document, block, r.target, position, visible)
	r.steps = append(r.steps, run)
	for name, values := range run.ExtractLists {
		r.lists[name] = values
	}
	if run.Reason != "" {
		return false, run.Reason
	}
	return run.Matched, ""
}

func (r *flowRunner) block(step flowStep) (passiveRequest, string) {
	blocks := r.httpBlocks
	if step.name != "" {
		for _, candidate := range blocks {
			if candidate.BlockID == step.name {
				return candidate, ""
			}
		}
		return passiveRequest{}, fmt.Sprintf(
			"the flow calls %s(%q) but no request block carries `id: %s`; the document's blocks are %s",
			step.protocol, step.name, step.name, describeBlockIDs(blocks))
	}
	if step.bare {
		if len(blocks) == 0 {
			return passiveRequest{}, "the flow calls http() but the document declares no request block"
		}
		return blocks[0], ""
	}
	if step.index > len(blocks) {
		return passiveRequest{}, fmt.Sprintf(
			"the flow calls http(%d) but the document declares %d request block(s), so that step "+
				"refers to a block the file does not have", step.index, len(blocks))
	}
	return blocks[step.index-1], ""
}

// execute sends one request block and scores it, reusing the single-request
// path so a flow step and a plain template are judged by identical code.
//
// What each step extracts is kept for the steps after it, because `flow:`
// chains exist precisely to hand a value forward — `http(1)` takes a token out
// of a login and `http(2)` sends it in a header.
func (r *flowRunner) execute(block passiveRequest) LocalRun {
	// The flow's own variables are handed to the request together with what the
	// steps extracted, because a loop exists to compute the value a request then
	// carries: `for (let p of iterate(template["paths"])) { path = p; http(2) }`
	// is a template whose second block reads `{{path}}`.
	//
	// They used not to be, so the loop assigned a variable nothing could read and
	// every looped request was refused as an ungenerated placeholder — the loop
	// parsed, ran, and could not spend what it had computed.
	visible := mergedValues(r.dynamic, r.varScalars())
	if len(visible) == 0 {
		visible = nil
	}
	run := runOneRequest(r.ctx, r.document, block, r.target, r.transport, visible)
	for name, value := range run.Dynamic {
		r.dynamic[name] = value
	}
	return run
}

// httpTransport is the engine's recording transport. The runner never builds a
// client of its own: traffic of any tool goes through the same passive proxy, and
// a scan that ran outside it would leave evidence the project cannot show.
type httpTransport = http.RoundTripper

// runFlow executes a `flow:` template: it parses the expression, sends the
// request block each step names, and reports whether the flow is satisfied.
//
// The verdict is a boolean over the steps, and every step's own exchange is kept
// so a match can be shown against the request that produced it. A flow this
// runner cannot complete is refused with the protocol named, never reported as a
// chain that did not match.
func runFlow(ctx context.Context, document *passiveDocument, target string, transport httpTransport) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	node, err := parseFlow(document.Flow)
	if err != nil {
		// Nothing ran, so this is a refusal and not a negative. Measured: 434 of
		// 500 `code:` templates in the corpus carry a `flow:` expression this
		// runner cannot read, and each one was being reported as `not_matched` —
		// a verdict for a check that never happened.
		run.Skipped = true
		run.Reason = "cannot read the flow expression: " + oneLine(err.Error())
		return run
	}
	runner := &flowRunner{
		ctx:            ctx,
		document:       document,
		target:         target,
		transport:      transport,
		httpBlocks:     allPassiveRequests(document),
		codeBlocks:     document.CodeBlocks,
		headlessBlocks: document.HeadlessBlocks,
		dynamic:        map[string]string{},
		vars:           map[string]flowValue{},
		lists:          map[string][]string{},
	}
	matched, reason := node.evaluate(runner)
	// The steps are flattened into the run so the report shows every exchange
	// the flow performed, not only the one that decided the verdict.
	for _, step := range runner.steps {
		if run.Request == "" {
			run.Request, run.Response = step.Request, step.Response
			run.StatusCode, run.Elapsed = step.StatusCode, step.Elapsed
			continue
		}
		run.Request += "\n--- " + step.Request
		run.Response += "\n--- " + step.Response
	}
	run.Matched = matched && reason == ""
	run.Reason = reason
	return run
}

// describeBlockIDs lists the blocks a document actually has, so a refusal over a
// name says what exists rather than only what does not.
func describeBlockIDs(blocks []passiveRequest) string {
	if len(blocks) == 0 {
		return "none"
	}
	names := make([]string, 0, len(blocks))
	for position, block := range blocks {
		name := block.BlockID
		if name == "" {
			name = fmt.Sprintf("#%d", position+1)
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// varScalars renders the flow's variables as the single-valued map a request reads.
//
// The variable slot holds whole values — a parsed JSON object among them — while a
// request may only carry text, so the rendering is explicit rather than a type
// assertion at each use.
func (r *flowRunner) varScalars() map[string]string {
	if len(r.vars) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.vars))
	for name, value := range r.vars {
		out[name] = value.scalar
	}
	return out
}

// flowCompare is `a < b`, `a != ""`, `a === "x"`.
//
// Both sides are read as text and compared as text, because that is what an
// extraction holds. A comparison of two numbers written as digits therefore works
// without a numeric type, and one of a number against a digit string works too —
// `status_code` reaches here as text from an extraction, and the corpus writes
// `i < 3` with both sides digits.
//
// `==` and `===` are the same test here: the values are text on both sides, so
// there is no distinction to preserve. Writing them apart would only let a
// document pass a check it did not make.
type flowCompare struct {
	left, right flowNode
	operator    string
}

func (c flowCompare) evaluate(r *flowRunner) (bool, string) {
	left, leftReason := readFlowText(c.left, r)
	if leftReason != "" {
		return false, leftReason
	}
	right, rightReason := readFlowText(c.right, r)
	if rightReason != "" {
		return false, rightReason
	}
	leftNumber, leftErr := strconv.Atoi(strings.TrimSpace(left))
	rightNumber, rightErr := strconv.Atoi(strings.TrimSpace(right))
	bothNumbers := leftErr == nil && rightErr == nil
	switch c.operator {
	case "<", ">", "<=", ">=":
		if !bothNumbers {
			return false, fmt.Sprintf(
				"the flow compares %q %s %q, and one side is not a number; this runner compares "+
					"numbers as digits, so a text side is a template this runner cannot judge",
				oneLine(left), c.operator, oneLine(right))
		}
		switch c.operator {
		case "<":
			return leftNumber < rightNumber, ""
		case ">":
			return leftNumber > rightNumber, ""
		case "<=":
			return leftNumber <= rightNumber, ""
		default:
			return leftNumber >= rightNumber, ""
		}
	default:
		equal := strings.TrimSpace(left) == strings.TrimSpace(right)
		if c.operator == "!=" || c.operator == "!==" {
			return !equal, ""
		}
		return equal, ""
	}
}

// flowTypeOf is `typeof x`, which the corpus uses once, to ask whether a name was
// ever set.
type flowTypeOf struct{ inner flowNode }

func (t flowTypeOf) evaluate(r *flowRunner) (bool, string) {
	value, reason := readFlowText(t.inner, r)
	if reason != "" {
		return false, reason
	}
	trimmed := strings.TrimSpace(value)
	switch trimmed {
	case "", "undefined":
		return false, ""
	default:
		return true, ""
	}
}

// flowStop is `stop()`, which ends a flow as a success without a verdict of its own.
//
// It is not a finding: a template that stops has stopped, and reporting it as one
// would put a row in the report that no matcher produced.
type flowStop struct{ flowCondition }

func (flowStop) evaluate(r *flowRunner) (bool, string) { return false, "" }

// readFlowText reads a node as **text**, which is what a comparison and `typeof`
// need and what `evaluate` cannot give them: `evaluate` answers "true or false",
// and `a != b` needs the two operands, not their verdicts.
//
// A node that carries text implements `flowTextNode`; one that only carries a
// verdict is read through its verdict, with the JavaScript spelling of it, so
// `typeof http(1) === "boolean"` is answerable and a mixed comparison is honest
// about what it got.
func readFlowText(node flowNode, r *flowRunner) (string, string) {
	if text, ok := node.(flowTextNode); ok {
		return text.readText(r)
	}
	verdict, reason := node.evaluate(r)
	if reason != "" {
		return "", reason
	}
	return strconv.FormatBool(verdict), ""
}

// flowTextNode is a node that has a value, not only a verdict.
type flowTextNode interface {
	readText(*flowRunner) (string, string)
}

// flowTernary is `condition ? a : b`.
//
// Both branches are read as conditions, which is what the corpus writes into them:
// measured, every branch in those 4 templates is a parenthesised group of steps, so
// a branch is "did these steps all hold", not a value.
type flowTernary struct {
	condition           flowNode
	whenTrue, whenFalse flowNode
}

func (t flowTernary) evaluate(r *flowRunner) (bool, string) {
	verdict, reason := t.condition.evaluate(r)
	if reason != "" {
		return false, reason
	}
	if verdict {
		return t.whenTrue.evaluate(r)
	}
	return t.whenFalse.evaluate(r)
}
