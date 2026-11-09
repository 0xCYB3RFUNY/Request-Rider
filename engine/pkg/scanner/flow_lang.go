package scanner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// `flow:` is not one expression but a small language, and the corpus shows it.
// Measured over the 1 909 templates that carry `flow:`:
//
//	1 261 parse with the expression parser this file grew out of
//	  590  for (let name of iterate(template["x"])) { … }     ← the whole remainder
//	   19  if (cond) { … }
//	   13  http("name") instead of http(3)
//	   12  var x = …, `;` separators, `//` comments, function wrappers
//
// The dominant form is a loop whose body assigns the loop variable to a flow
// variable, so a variable scope is not an optional extra here — without it the
// loop has nothing to assign and the flow cannot describe what it did.
//
// Nothing here replaces the existing parser. `parseFlow` still returns one node
// for `a && b || c`; the statement layer sits above it and reuses it for the
// conditions inside `if` and for the bare `http(n)` calls that make up a flow's
// body.

// flowValue is what a flow expression yields: a scalar, or the list `iterate()`
// produces.
//
// The two are kept apart on purpose. `template["name"]` is one value, and a
// request may only send one, because a name extracted several times has no single
// correct substitution. `iterate(template["name"])` is asking for all of them and
// runs no request, so the list is only ever walked by the interpreter.
type flowValue struct {
	scalar string
	list   []string
	isList bool
	// json is the decoded value of a `JSON.parse(…)` expression, when this value is
	// one. A flow that indexes into parsed JSON reads it from here and nowhere
	// else, so there is no second parser to disagree with the first.
	json interface{}
	// runner binds the value's flow to the runner that produced it, so a member read
	// can look another extraction up in the same place every other lookup does. It is
	// set where the value is built and nowhere else.
	runner *flowRunner
	// name is the key this value addresses, kept beside its content.
	//
	// `iterate(template["found"])` has to know *which* name to walk, and it used to
	// ask by resolving the inner expression against an empty runner: the lookup
	// returned nothing, so every loop over an extracted name was refused with
	// «iterate() … hands it a literal» — including all 559 templates of the corpus
	// that loop over `iterate(template.x)`.
	name string
}

// flowStatement is one statement of a flow body.
//
// `execute` returns whether the flow should keep going: `break` and a failed
// `if` guard both stop the walk without making the flow unfulfilled, which is not
// the same thing as a step that did not match.
type flowStatement interface {
	execute(r *flowRunner) (proceed bool, reason string)
}

// flowProgram is a parsed flow body.
type flowProgram []flowStatement

// execute runs the statements and reports two separate things.
//
// `proceed` says whether the walk should continue: `break` and a failed guard both
// stop it. `verdict` says whether the flow is satisfied: it is the AND over the
// bare step calls.
//
// They were one value once, and `break` could not work: a body whose only
// statement was `break` returned the verdict — true — as its "keep going" answer,
// the loop read it as continue, and `break` looped over every value. Measured: a
// flow written with `break` sent 3 requests where the template named 2.
//
// Anything that used the two meanings in different places would silently disagree
// with itself, so they are separate values now.
func (p flowProgram) execute(r *flowRunner) (proceed bool, verdict bool, reason string) {
	verdict = true
	for _, statement := range p {
		if expression, ok := statement.(flowExpressionStatement); ok {
			// Evaluated once, here. Calling `execute` and then evaluating the same
			// node again sent every request twice — measured, 4 requests where the
			// flow named 2.
			stepMatched, stepReason := expression.node.evaluate(r)
			if stepReason != "" {
				return false, false, stepReason
			}
			verdict = verdict && stepMatched
			continue
		}
		keepGoing, statementReason := statement.execute(r)
		if statementReason != "" {
			return false, false, statementReason
		}
		if !keepGoing {
			return false, verdict, ""
		}
	}
	return true, verdict, ""
}

// flowAssign stores a value into a flow variable.
type flowAssign struct {
	name    string
	compute func(r *flowRunner) (flowValue, error)
}

func (s flowAssign) execute(r *flowRunner) (bool, string) {
	value, err := s.compute(r)
	if err != nil {
		return false, err.Error()
	}
	r.vars[s.name] = value
	return true, ""
}

// flowIf runs its body only when the condition holds.
type flowIf struct {
	condition flowNode
	body      flowProgram
	// negated marks `if (!cond)`, which the corpus uses as "the previous step did
	// not detect it, so try the fallback".
	negated bool
}

func (s flowIf) execute(r *flowRunner) (bool, string) {
	held, reason := s.condition.evaluate(r)
	if reason != "" {
		return false, reason
	}
	if s.negated {
		held = !held
	}
	if !held {
		return true, ""
	}
	keepGoing, _, reason := s.body.execute(r)
	if !keepGoing {
		return false, reason
	}
	return true, reason
}

// flowFor walks a list, which is what `for (let x of iterate(y))` means.
type flowFor struct {
	variable string
	source   func(r *flowRunner) (flowValue, error)
	body     flowProgram
}

func (s flowFor) execute(r *flowRunner) (bool, string) {
	values, err := s.source(r)
	if err != nil {
		return false, err.Error()
	}
	for _, item := range values.list {
		r.vars[s.variable] = flowValue{scalar: item, name: s.variable}
		proceed, _, walkReason := s.body.execute(r)
		if walkReason != "" {
			return false, walkReason
		}
		if !proceed {
			// `break` leaves the loop, and the loop's own outcome is that it ran:
			// a flow whose only `break` is the last statement of the last loop has
			// not failed, it has finished.
			return true, ""
		}
	}
	return true, ""
}

// flowBreak stops the innermost loop.
type flowBreak struct{}

func (flowBreak) execute(*flowRunner) (bool, string) { return false, "" }

// flowExpressionStatement is a step call that stands alone as a statement, which
// is how a flow says `http(1);`.
type flowExpressionStatement struct{ node flowNode }

func (s flowExpressionStatement) execute(r *flowRunner) (bool, string) {
	_, reason := s.node.evaluate(r)
	if reason != "" {
		return false, reason
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// parseProgram reads a whole flow body into statements.
//
// Separators are `;` and newlines, because the corpus uses both, and `//` comments
// are skipped: a leading comment block is how several of these templates document
// their own steps, and a parser that stops at `//` refuses a template whose logic
// it would otherwise read perfectly.
func (p *flowParser) parseProgram(closing string) (flowProgram, error) {
	program := flowProgram{}
	for {
		p.skipFlowSpace()
		if p.pos >= len(p.source) {
			if closing != "" {
				return nil, fmt.Errorf("unexpected end of the flow expression, expected %q", closing)
			}
			return program, nil
		}
		// `consume("")` is always true — `strings.HasPrefix` of anything against an
		// empty prefix — so an unguarded call ended every top-level program before
		// reading a single statement, and `http(1) && http(2)` came back as
		// "unexpected … at the end".
		if closing != "" && p.consume(closing) {
			return program, nil
		}
		statement, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		if statement != nil {
			program = append(program, statement)
		}
		p.skipFlowSpace()
		p.consume(";")
	}
}

// skipFlowSpace moves past whitespace, newlines and `//` comments.
func (p *flowParser) skipFlowSpace() {
	for p.pos < len(p.source) {
		char := p.source[p.pos]
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			p.pos++
			continue
		}
		if strings.HasPrefix(p.source[p.pos:], "//") {
			for p.pos < len(p.source) && p.source[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		// A block comment is rarer but appears in the same templates.
		if strings.HasPrefix(p.source[p.pos:], "/*") {
			end := strings.Index(p.source[p.pos+2:], "*/")
			if end < 0 {
				p.pos = len(p.source)
				return
			}
			p.pos += 2 + end + 2
			continue
		}
		return
	}
}

func (p *flowParser) parseStatement() (flowStatement, error) {
	p.skipFlowSpace()
	if p.pos >= len(p.source) {
		return nil, nil
	}
	// `var x = …` and `let x = …` declare; `x = …` assigns. Both write the same
	// place, because a flow variable is one slot either way, and keeping them
	// separate would only mean two parsers for one store.
	// `const` joins `var` and `let`: measured in 2 corpus templates, and it declares
	// into the same slot — a flow variable is one store, and a third keyword for it
	// would be a second store.
	if p.consumeWord("var") || p.consumeWord("let") || p.consumeWord("const") {
		name, err := p.parseIdentifier()
		if err != nil {
			return nil, err
		}
		// The space before `=` was not skipped, so `let x = 1` was unreadable and
		// the refusal named the declaration rather than the missing space. Measured:
		// 6 corpus documents write a declaration with a space before `=`.
		p.skipFlowSpace()
		if !p.consume("=") {
			return nil, fmt.Errorf("expected `=` after the declaration of %q", name)
		}
		compute, err := p.parseValueExpression()
		if err != nil {
			return nil, err
		}
		return flowAssign{name: name, compute: compute}, nil
	}
	if p.consumeWord("if") {
		return p.parseIf()
	}
	if p.consumeWord("for") {
		return p.parseFor()
	}
	if p.consumeWord("break") {
		return flowBreak{}, nil
	}
	// `set("name", value)` is how these flows hand a loop variable to a later
	// block: measured, it is the first statement of the loop body in the cloud
	// templates (`for (let B of iterate(template.buckets)) { set("bucket", B); … }`),
	// so a loop that cannot read it stops at the first line of its own body.
	if p.consumeWord("set") {
		p.skipFlowSpace()
		if !p.consume("(") {
			return nil, fmt.Errorf("expected `(` after `set` in the flow expression")
		}
		target, err := p.parseValueExpression()
		if err != nil {
			return nil, err
		}
		p.skipFlowSpace()
		if !p.consume(",") {
			return nil, fmt.Errorf("expected `,` between the name and the value of `set` in the flow expression")
		}
		compute, err := p.parseValueExpression()
		if err != nil {
			return nil, err
		}
		p.skipFlowSpace()
		if !p.consume(")") {
			return nil, fmt.Errorf("expected `)` after `set` in the flow expression")
		}
		return flowSet{name: target, value: compute}, nil
	}
	// A bare `{ … }` is a group, not a step. Measured: several cloud templates
	// open their body with one, so refusing it would refuse the loop that
	// contains it.
	p.skipFlowSpace()
	if p.pos < len(p.source) && p.source[p.pos] == '{' {
		p.pos++
		body, err := p.parseProgram("}")
		if err != nil {
			return nil, err
		}
		return flowGroup{body: body}, nil
	}
	// A bare identifier followed by `=` is an assignment; anything else is an
	// expression that stands alone as a statement.
	if name := p.peekIdentifier(); name != "" {
		mark := p.pos
		p.pos += len(name)
		p.skipFlowSpace()
		if p.pos < len(p.source) && p.source[p.pos] == '=' && p.source[p.pos+1] != '=' {
			p.pos++
			compute, err := p.parseValueExpression()
			if err != nil {
				return nil, err
			}
			return flowAssign{name: name, compute: compute}, nil
		}
		p.pos = mark
	}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	return flowExpressionStatement{node: node}, nil
}

func (p *flowParser) parseIf() (flowStatement, error) {
	p.skipFlowSpace()
	if !p.consume("(") {
		return nil, fmt.Errorf("expected `(` after `if` in the flow expression")
	}
	negated := p.consume("!")
	condition, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipFlowSpace()
	if !p.consume(")") {
		return nil, fmt.Errorf("expected `)` after the condition of `if` in the flow expression")
	}
	p.skipFlowSpace()
	if !p.consume("{") {
		return nil, fmt.Errorf("expected `{` after the condition of `if` in the flow expression")
	}
	body, err := p.parseProgram("}")
	if err != nil {
		return nil, err
	}
	return flowIf{condition: condition, body: body, negated: negated}, nil
}

// parseFor reads `for (let name of iterate(<value>)) { body }` and the
// `for (name of <value>)` spelling without the keyword.
//
// A C-style `for (let i = 0; i < n; i++)` appears three times in the corpus and is
// refused by name rather than half-read: it needs a counter variable that no
// template's request can see, so pretending to support it would report requests
// the flow never asked for.
func (p *flowParser) parseFor() (flowStatement, error) {
	p.skipFlowSpace()
	if !p.consume("(") {
		return nil, fmt.Errorf("expected `(` after `for` in the flow expression")
	}
	p.skipFlowSpace()
	p.consumeWord("let")
	p.consumeWord("var")
	variable, err := p.parseIdentifier()
	if err != nil {
		return nil, err
	}
	p.skipFlowSpace()
	if !p.consumeWord("of") {
		// `for (let i = 0; i < n; i++)` — measured in 7 corpus documents, and it was
		// refused by name as unreadable. The refusal said the counter is something a
		// request "cannot read", which is true of a *request* and irrelevant here: the
		// counter is a flow variable like any other, it is compared as digits, and the
		// body reads it through `set` and `template`.
		return p.parseCountedFor(variable)
	}
	p.skipFlowSpace()
	source, err := p.parseValueExpression()
	if err != nil {
		return nil, err
	}
	p.skipFlowSpace()
	if !p.consume(")") {
		return nil, fmt.Errorf("expected `)` after the loop header of `for` in the flow expression")
	}
	p.skipFlowSpace()
	if !p.consume("{") {
		return nil, fmt.Errorf("expected `{` after the loop header of `for` in the flow expression")
	}
	body, err := p.parseProgram("}")
	if err != nil {
		return nil, err
	}
	return flowFor{variable: variable, source: source, body: body}, nil
}

// parseValueExpression reads what a flow stores or iterates: a template lookup, a
// flow variable, a quoted string, a number, or `iterate(<any of those>)`.
func (p *flowParser) parseValueExpression() (func(r *flowRunner) (flowValue, error), error) {
	p.skipFlowSpace()
	// `[a, b, c]` — an array literal. Measured in 4 corpus templates
	// (`var paths = ["/contact-us/", "/contact/", …]`), and without it the refusal
	// named the declaration rather than the bracket.
	if p.pos < len(p.source) && p.source[p.pos] == '[' {
		p.pos++
		var items []string
		for {
			p.skipFlowSpace()
			if p.pos < len(p.source) && p.source[p.pos] == ']' {
				p.pos++
				break
			}
			if p.pos < len(p.source) && (p.source[p.pos] == '"' || p.source[p.pos] == '\'') {
				quote := p.source[p.pos]
				p.pos++
				start := p.pos
				for p.pos < len(p.source) && p.source[p.pos] != quote {
					p.pos++
				}
				items = append(items, p.source[start:p.pos])
				p.pos++
			} else {
				start := p.pos
				depth := 0
				for p.pos < len(p.source) && (depth > 0 || (p.source[p.pos] != ',' && p.source[p.pos] != ']')) {
					if p.source[p.pos] == '[' {
						depth++
					}
					if p.source[p.pos] == ']' {
						depth--
					}
					p.pos++
				}
				items = append(items, strings.TrimSpace(p.source[start:p.pos]))
			}
			p.skipFlowSpace()
			if p.consume(",") {
				continue
			}
			if p.consume("]") {
				break
			}
			return nil, fmt.Errorf("unbalanced brackets in an array literal in the flow expression")
		}
		return func(*flowRunner) (flowValue, error) {
			// The items stay **text**: an array this runner hands to a script is a
			// list of strings, and a nested literal keeps its own brackets so the
			// script sees the shape the template wrote.
			return flowValue{isList: true, list: items, runner: nil}, nil
		}, nil
	}
	if p.consumeWord("iterate") {
		if !p.consume("(") {
			return nil, fmt.Errorf("expected `(` after `iterate` in the flow expression")
		}
		inner, err := p.parseValueExpression()
		if err != nil {
			return nil, err
		}
		p.skipFlowSpace()
		if !p.consume(")") {
			return nil, fmt.Errorf("expected `)` after the argument of `iterate` in the flow expression")
		}
		iterated := func(r *flowRunner) (flowValue, error) {
			name, err := valueName(inner)
			if err != nil {
				return flowValue{}, err
			}
			if name == "" {
				return flowValue{}, fmt.Errorf("iterate() takes the name of an extracted value, and this flow hands it a literal")
			}
			// Every extracted value, in order, which is what `for (let p of
			// iterate(template["paths"]))` walks. The single-valued slot is not
			// touched here: a request must still refuse a name that matched
			// several times.
			list := r.lists[name]
			if len(list) == 0 {
				return flowValue{isList: true}, nil
			}
			return flowValue{isList: true, list: list, name: name}, nil
		}
		// `iterate(template.postid)[0]` — measured on 178 corpus templates, the
		// single commonest remaining shape. Indexing has to be part of the iterate
		// expression, not a separate statement, or the list is read whole where the
		// template asked for one element.
		indexed, indexErr := p.withIndex(iterated)
		if indexErr != nil {
			return nil, indexErr
		}
		return indexed, nil
	}
	if p.consumeWord("template") {
		name, err := p.templateKey()
		if err != nil {
			return nil, err
		}
		reader := func(r *flowRunner) (flowValue, error) {
			if items, listed := r.lists[name]; listed && len(items) > 1 {
				return flowValue{scalar: items[0], list: items, isList: true, name: name}, nil
			}
			return flowValue{scalar: r.lookup(name), name: name}, nil
		}
		indexed, indexErr := p.withIndex(reader)
		if indexErr != nil {
			return nil, indexErr
		}
		return indexed, nil
	}
	// `JSON.parse(x)` — 110 викликів у корпусі, переважно в хмарних шаблонах, де
	// відповідь gcloud розбирається на поле: `VMData = JSON.parse(VMData)`, потім
	// `VMData["name"]`.
	//
	// Без нього хмарна родина не читається в принципі, а не «читається не до
	// кінця»: вираз зупиняється на першому `.parse(`.
	if p.consumeWord("JSON") {
		p.skipFlowSpace()
		if !p.consume(".") {
			return nil, fmt.Errorf("expected `.parse(` after `JSON` in the flow expression")
		}
		if !p.consumeWord("parse") {
			return nil, fmt.Errorf("expected `parse` after `JSON.` in the flow expression")
		}
		p.skipFlowSpace()
		if !p.consume("(") {
			return nil, fmt.Errorf("expected `(` after `JSON.parse` in the flow expression")
		}
		inner, err := p.parseValueExpression()
		if err != nil {
			return nil, err
		}
		p.skipFlowSpace()
		if !p.consume(")") {
			return nil, fmt.Errorf("expected `)` after `JSON.parse(…)` in the flow expression")
		}
		return func(r *flowRunner) (flowValue, error) {
			value, err := inner(r)
			if err != nil {
				return flowValue{}, err
			}
			decoded, decodeErr := parseFlowJSON(value.scalar)
			if decodeErr != nil {
				return flowValue{}, decodeErr
			}
			return flowValue{scalar: value.scalar, name: value.name, json: decoded}, nil
		}, nil
	}
	if p.pos < len(p.source) && (p.source[p.pos] == '"' || p.source[p.pos] == '\'') {
		quote := p.source[p.pos]
		p.pos++
		start := p.pos
		for p.pos < len(p.source) && p.source[p.pos] != quote {
			p.pos++
		}
		if p.pos >= len(p.source) {
			return nil, fmt.Errorf("unterminated string in the flow expression")
		}
		literal := p.source[start:p.pos]
		p.pos++
		return func(*flowRunner) (flowValue, error) {
			return flowValue{scalar: literal, name: literal}, nil
		}, nil
	}
	if name := p.peekIdentifier(); name != "" {
		p.pos += len(name)
		reader := func(r *flowRunner) (flowValue, error) {
			if items, listed := r.lists[name]; listed && len(items) > 1 {
				// A name extracted more than once is a list, and indexing it is the
				// only honest way to read it: the single-valued slot refuses it on
				// purpose, and a list read as a scalar would be one arbitrary pick.
				return flowValue{scalar: items[0], list: items, isList: true, name: name, runner: r}, nil
			}
			if value, ok := r.vars[name]; ok {
				return flowValue{scalar: value.scalar, json: value.json, list: value.list,
					isList: value.isList, name: name, runner: r}, nil
			}
			return flowValue{scalar: r.lookup(name), name: name, runner: r}, nil
		}
		// `[…]` may follow: `template.typename[0]` appears in 11 corpus templates.
		return p.withIndex(reader)
	}
	return nil, fmt.Errorf(
		"this flow stores a value this runner cannot read at %q: it understands a template lookup, a flow "+
			"variable, a quoted string and iterate()", p.source[p.pos:])
}

// valueName resolves an inner expression back to the name it addresses, which is
// what `iterate` needs.
func valueName(inner func(*flowRunner) (flowValue, error)) (string, error) {
	probe := &flowRunner{vars: map[string]flowValue{}, dynamic: map[string]string{}, lists: map[string][]string{}}
	value, err := inner(probe)
	if err != nil {
		return "", err
	}
	return value.name, nil
}

// templateKey reads `.name` and `["name"]`, the two spellings the corpus uses.
func (p *flowParser) templateKey() (string, error) {
	p.skipFlowSpace()
	if p.consume("[") {
		p.skipFlowSpace()
		if p.pos >= len(p.source) || (p.source[p.pos] != '"' && p.source[p.pos] != '\'') {
			return "", fmt.Errorf("expected a quoted name inside `template[…]` in the flow expression")
		}
		quote := p.source[p.pos]
		p.pos++
		start := p.pos
		for p.pos < len(p.source) && p.source[p.pos] != quote {
			p.pos++
		}
		name := p.source[start:p.pos]
		p.pos++
		if !p.consume("]") {
			return "", fmt.Errorf("expected `]` after `template[%q]` in the flow expression", name)
		}
		return name, nil
	}
	if p.consume(".") {
		name, err := p.parseIdentifier()
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("expected `.name` or `[\"name\"]` after `template` in the flow expression")
}

func (p *flowParser) parseIdentifier() (string, error) {
	p.skipFlowSpace()
	start := p.pos
	for p.pos < len(p.source) && (isLetter(p.source[p.pos]) || isDigit(p.source[p.pos]) ||
		p.source[p.pos] == '_' || p.source[p.pos] == '-') {
		p.pos++
	}
	if start == p.pos {
		return "", fmt.Errorf("expected a name at %q", p.source[p.pos:])
	}
	return p.source[start:p.pos], nil
}

// peekIdentifier reads an identifier without consuming it.
func (p *flowParser) peekIdentifier() string {
	saved := p.pos
	p.skipFlowSpace()
	name, err := p.parseIdentifier()
	p.pos = saved
	if err != nil {
		return ""
	}
	return name
}

// consumeWord reads a keyword only when it stands alone, so `iffy` is an
// identifier and `if` is a keyword.
func (p *flowParser) consumeWord(word string) bool {
	p.skipFlowSpace()
	if !strings.HasPrefix(p.source[p.pos:], word) {
		return false
	}
	end := p.pos + len(word)
	if end < len(p.source) {
		next := p.source[end]
		if isLetter(next) || isDigit(next) || next == '_' || next == '-' {
			return false
		}
	}
	p.pos = end
	return true
}

// ---------------------------------------------------------------------------
// Reading values at run time
// ---------------------------------------------------------------------------

// lookup reads a name from what the steps extracted, then from the flow's own
// variables.
//
// The order is deliberate: a variable the flow assigned is the flow's own answer
// and must not be overwritten by an extraction of the same name, because the
// assignment is what a later step is written to send.
// lookupValue answers whether a name has a value at all, which a member read must
// know: `template.items` naming nothing is a refusal, and `template.items` naming an
// empty string is a value that happens to be empty.
func (r *flowRunner) lookupValue(name string) (string, bool) {
	if value, ok := r.vars[name]; ok {
		return value.scalar, true
	}
	if value, ok := r.dynamic[name]; ok {
		return value, true
	}
	if value, ok := r.lists[name]; ok && len(value) > 0 {
		return value[0], true
	}
	return "", false
}

func (r *flowRunner) lookup(name string) string {
	if value, ok := r.vars[name]; ok && value.scalar != "" {
		return value.scalar
	}
	if value, ok := r.dynamic[name]; ok {
		return value
	}
	return ""
}

// conditionValue turns a scalar into the boolean a guard reads.
//
// A template condition is written against JavaScript's rules, where an empty
// string is false; the corpus relies on that in `if (template["x"] && …)`. Reading
// an empty string as true would take the fallback branch on every detection, which
// is the opposite of what the template says.
func conditionValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case "", "false", "0", "null", "undefined":
		return false
	default:
		return true
	}
}

// flowCondition reads `template["x"]`, a variable or a literal as a guard.
//
// It is a node so it can sit inside `&&` and `||`, which the corpus uses to
// write `if (template["a"] && template["b"])`.
type flowCondition struct{ read func(*flowRunner) string }

func (c flowCondition) evaluate(r *flowRunner) (bool, string) {
	return conditionValue(c.read(r)), ""
}

// readText is the value behind the verdict, which a comparison needs: `evaluate`
// answers "true or false", and `a != b` needs the two operands.
func (c flowCondition) readText(r *flowRunner) (string, string) { return c.read(r), "" }

// andCondition and orCondition combine guards. Unlike the step combinators these
// may short-circuit, because nothing is executed by reading a value.
type andCondition struct {
	left, right flowNode
	flowCondition
}

type orCondition struct {
	left, right flowNode
	flowCondition
}

func (n andCondition) evaluate(r *flowRunner) (bool, string) {
	left, reason := n.left.evaluate(r)
	if !left {
		return false, reason
	}
	return n.right.evaluate(r)
}

func (n orCondition) evaluate(r *flowRunner) (bool, string) {
	left, reason := n.left.evaluate(r)
	if left {
		return true, reason
	}
	return n.right.evaluate(r)
}

// flowNumber is the value of a bare number in an expression, so `i < 3` and
// `parseInt` reads as something rather than a parse error.
type flowNumber struct{ value string }

func (n flowNumber) evaluate(r *flowRunner) (bool, string) { return conditionValue(n.value), "" }

func (n flowNumber) readText(r *flowRunner) (string, string) { return n.value, "" }

// flowVariableName reports whether an identifier is a flow keyword, so
// `parseOr` refuses `if` in a condition with a message that names the real cause.
func (p *flowParser) flowVariableName() (string, error) {
	name, err := p.parseIdentifier()
	if err != nil {
		return "", err
	}
	switch strings.ToLower(name) {
	case "iterate", "template":
		return "", fmt.Errorf("%q is a value in a flow expression, not a condition", name)
	}
	return name, nil
}

// flowLiteralNode turns a scalar into a node that can appear in a condition.
func flowLiteralNode(value string) flowNode {
	if _, err := strconv.Atoi(value); err == nil {
		return flowNumber{value: value}
	}
	return flowCondition{read: func(*flowRunner) string { return value }}
}

// flowSet is `set("name", value)`, which stores into the same scope an assignment
// writes to. It is a statement and not a function call because its whole point is
// to be a statement: the corpus never uses the value it produces.
type flowSet struct {
	name  func(*flowRunner) (flowValue, error)
	value func(r *flowRunner) (flowValue, error)
}

func (s flowSet) execute(r *flowRunner) (bool, string) {
	target, err := s.name(r)
	if err != nil {
		return false, err.Error()
	}
	value, err := s.value(r)
	if err != nil {
		return false, err.Error()
	}
	r.vars[target.scalar] = value
	return true, ""
}

// flowGroup is a bare `{ … }`, which exists only to hold statements.
type flowGroup struct{ body flowProgram }

func (s flowGroup) execute(r *flowRunner) (bool, string) {
	proceed, _, reason := s.body.execute(r)
	return proceed, reason
}

// parseFlowJSON decodes the text a `JSON.parse(…)` was given.
//
// The error names the text and its first bytes: these expressions run against a
// command's stdout, and the usual failure is that the command printed something
// other than JSON, which without the text is indistinguishable from a template bug.
func parseFlowJSON(text string) (interface{}, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, fmt.Errorf("JSON.parse() was given nothing to parse")
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		preview := trimmed
		if len(preview) > 60 {
			preview = preview[:60]
		}
		return nil, fmt.Errorf("JSON.parse() cannot read this text (%s): %s",
			strings.ReplaceAll(oneLine(preview), "\n", " "), oneLine(err.Error()))
	}
	return decoded, nil
}

// flowIndex reads `value[index]` or `value["field"]`.
//
// Measured on the corpus: `template.typename[0]` in 11 templates, and the cloud
// family indexes parsed JSON by field name. Both spellings go through this one
// function, so there is no second indexing rule to drift.
func flowIndex(base flowValue, index flowValue) (flowValue, string) {
	if decoded := base.json; decoded != nil {
		if items, isList := decoded.([]interface{}); isList {
			position, ok := jsonIndexNumber(index.scalar)
			if !ok {
				return flowValue{}, fmt.Sprintf(
					"this value is a JSON array of %d item(s) and cannot be read by the name %q; index it with [0]",
					len(items), index.scalar)
			}
			if position < 0 || position >= len(items) {
				return flowValue{}, fmt.Sprintf("the parsed JSON has %d item(s), and the flow asked for [%s]",
					len(items), index.scalar)
			}
			return flowValue{scalar: jsonScalar(items[position]), json: items[position]}, ""
		}
		object, isObject := decoded.(map[string]interface{})
		if !isObject {
			return flowValue{}, fmt.Sprintf("this value is not something that can be indexed by %q", index.scalar)
		}
		found, ok := object[index.scalar]
		if !ok {
			return flowValue{}, fmt.Sprintf(
				"the parsed JSON has no field %q; it has %s", index.scalar, jsonFieldNames(object))
		}
		return flowValue{scalar: jsonScalar(found), json: found, name: index.scalar}, ""
	}
	// A member on a plain value is a lookup of another extracted name.
	//
	// Measured: `for (let pod of template.items)` appears in 6 corpus templates, and
	// before this it was refused as "not something that can be indexed" — the value
	// `template` carries is text, and a member on text is how these documents name
	// another extraction. `template.items` and `template["items"]` are the same name,
	// and treating them differently would refuse half the corpus's spelling of itself.
	if base.json == nil && len(base.list) == 0 && base.name != "" && base.runner != nil {
		if value, ok := base.runner.lookupValue(index.scalar); ok {
			return flowValue{scalar: value, name: index.scalar}, ""
		}
		return flowValue{}, fmt.Sprintf(
			"the flow reads %q from %q, but the document extracted no such value; "+
				"names read here are the extractions of the steps that ran before it",
			index.scalar, base.name)
	}
	if len(base.list) > 0 {
		position, ok := jsonIndexNumber(index.scalar)
		if !ok {
			return flowValue{}, fmt.Sprintf(
				"this value is a list of %d item(s) and cannot be read by the name %q; index it with [0]", len(base.list), index.scalar)
		}
		if position < 0 || int(position) >= len(base.list) {
			return flowValue{}, fmt.Sprintf("this value is a list of %d item(s), and the flow asked for [%s]",
				len(base.list), index.scalar)
		}
		return flowValue{scalar: base.list[position], list: base.list, isList: true}, ""
	}
	return flowValue{}, fmt.Sprintf(
		"this value is a single string and cannot be indexed by %q; only a name extracted several times is a list",
		index.scalar)
}

// jsonIndexNumber reads an index that may be a number or a numeric string.
func jsonIndexNumber(text string) (int, bool) {
	if parsed, err := strconv.Atoi(strings.TrimSpace(text)); err == nil {
		return parsed, true
	}
	return 0, false
}

// jsonScalar renders a decoded JSON value as the text a flow compares.
func jsonScalar(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

// jsonFieldNames names what a decoded object does have, so a refusal over a missing
// field is usable.
func jsonFieldNames(object map[string]interface{}) string {
	if len(object) == 0 {
		return "no fields"
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 12 {
		return strings.Join(names[:12], ", ") + fmt.Sprintf(", and %d more", len(names)-12)
	}
	return strings.Join(names, ", ")
}

// withIndex wraps a value reader so that `[0]` or `["field"]` may follow it.
//
// One place, because the corpus uses both spellings on the same kind of value:
// `template.typename[0]` by position, and `JSON.parse(x)["name"]` by field. Two
// implementations of the same indexing would eventually disagree about a boundary.
func (p *flowParser) withIndex(read func(*flowRunner) (flowValue, error)) (func(*flowRunner) (flowValue, error), error) {
	for {
		p.skipFlowSpace()
		if p.pos < len(p.source) && p.source[p.pos] == '.' {
			// `subnet.name` after `subnet = JSON.parse(subnet)`. Measured: 176 corpus
			// templates read a parsed value by field, and without this the cloud
			// family stops at the first `.name`.
			p.pos++
			start := p.pos
			for p.pos < len(p.source) && (isLetter(p.source[p.pos]) || isDigit(p.source[p.pos]) ||
				p.source[p.pos] == '_') {
				p.pos++
			}
			field := p.source[start:p.pos]
			if field == "" {
				return nil, fmt.Errorf("expected a field name after `.` in the flow expression")
			}
			inner := read
			read = func(r *flowRunner) (flowValue, error) {
				base, err := inner(r)
				if err != nil {
					return flowValue{}, err
				}
				indexed, why := flowIndex(base, flowValue{scalar: field})
				if why != "" {
					return flowValue{}, fmt.Errorf("%s", why)
				}
				return indexed, nil
			}
			continue
		}
		if p.pos >= len(p.source) || p.source[p.pos] != '[' {
			return read, nil
		}
		p.pos++
		p.skipFlowSpace()
		index := ""
		if p.pos < len(p.source) && (p.source[p.pos] == '"' || p.source[p.pos] == '\'') {
			quote := p.source[p.pos]
			p.pos++
			start := p.pos
			for p.pos < len(p.source) && p.source[p.pos] != quote {
				p.pos++
			}
			index = p.source[start:p.pos]
			p.pos++
		} else {
			start := p.pos
			for p.pos < len(p.source) && p.source[p.pos] != ']' {
				p.pos++
			}
			index = strings.TrimSpace(p.source[start:p.pos])
		}
		p.skipFlowSpace()
		if !p.consume("]") {
			return nil, fmt.Errorf("expected `]` after the index %q in the flow expression", index)
		}
		inner := read
		key := index
		read = func(r *flowRunner) (flowValue, error) {
			base, err := inner(r)
			if err != nil {
				return flowValue{}, err
			}
			indexed, why := flowIndex(base, flowValue{scalar: key})
			if why != "" {
				return flowValue{}, fmt.Errorf("%s", why)
			}
			return indexed, nil
		}
	}
}

// parseCountedFor reads `for (let i = 0; i < n; i++) { body }`.
//
// The counter is a flow variable, so the body reads it by the same path as any
// other name — which is why it needs no type of its own. The test is a normal
// condition expression over digits, and the step is `i++`, `i--` or `i += n`.
func (p *flowParser) parseCountedFor(variable string) (flowStatement, error) {
	// The parser stands right after the counter's name. A counted loop writes its
	// initial value there — `for (let i = 0; …` — while the `for…of` form this
	// function was reached from does not. Consuming `= 0` before the `;` is what makes
	// the two spellings land in the same place; without it the refusal said the
	// counter had no initial value when the value stood two characters away.
	p.skipFlowSpace()
	initialText := ""
	if p.consume("=") {
		p.skipFlowSpace()
		start := p.pos
		for p.pos < len(p.source) && p.source[p.pos] != ';' {
			p.pos++
		}
		initialText = strings.TrimSpace(p.source[start:p.pos])
	}
	if !p.consume(";") {
		return nil, fmt.Errorf(
			"this flow loops with `for (…; …; …)` but the counter %q has no initial value", variable)
	}
	start, err := strconv.Atoi(initialText)
	if err != nil {
		return nil, fmt.Errorf(
			"the loop counter %q starts at %q, which is not a number; this runner counts with digits, "+
				"so a counter that starts at something else is a template it cannot run", variable, initialText)
	}
	if !p.consume(";") {
		return nil, fmt.Errorf("the loop counter %q has no condition", variable)
	}
	test, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipFlowSpace()
	if !p.consume(";") {
		return nil, fmt.Errorf("the loop over %q has no step", variable)
	}
	step, err := p.parseCountedStep(variable)
	if err != nil {
		return nil, err
	}
	p.skipFlowSpace()
	if !p.consume(")") {
		return nil, fmt.Errorf("expected `)` after the counter %q of a counted loop", variable)
	}
	p.skipFlowSpace()
	if !p.consume("{") {
		return nil, fmt.Errorf("expected `{` after the counted loop over %q", variable)
	}
	body, err := p.parseProgram("}")
	if err != nil {
		return nil, err
	}
	return flowCountedFor{variable: variable, start: start, test: test, step: step, body: body}, nil
}

// parseCountedStep reads `i++`, `i--` or `i += 3`.
func (p *flowParser) parseCountedStep(variable string) (int, error) {
	p.skipFlowSpace()
	if name := p.peekIdentifier(); name != "" {
		p.pos += len(name)
		p.skipFlowSpace()
		switch {
		case p.consume("++"):
			return 1, nil
		case p.consume("--"):
			return -1, nil
		case p.consume("+="), p.consume("-="):
			p.skipFlowSpace()
			start := p.pos
			for p.pos < len(p.source) && isDigit(p.source[p.pos]) {
				p.pos++
			}
			amount, err := strconv.Atoi(p.source[start:p.pos])
			if err != nil {
				return 0, fmt.Errorf("the step of the loop over %q adds %q, which is not a number",
					variable, p.source[start:p.pos])
			}
			if p.pos < len(p.source) && p.source[p.pos] == '=' {
				p.pos++
			}
			return amount, nil
		}
	}
	return 0, fmt.Errorf("this runner reads a counted loop with `++`, `--` or `+=`, and this one has neither")
}

// flowCountedFor is `for (let i = 0; i < n; i++)`.
type flowCountedFor struct {
	variable string
	start    int
	test     flowNode
	step     int
	body     flowProgram
}

func (f flowCountedFor) execute(r *flowRunner) (bool, string) {
	for counter := f.start; ; counter += f.step {
		r.vars[f.variable] = flowValue{scalar: strconv.Itoa(counter), name: f.variable, runner: r}
		verdict, reason := f.test.evaluate(r)
		if reason != "" {
			return false, reason
		}
		if !verdict {
			return true, ""
		}
		if counter < 0 && f.step < 0 {
			// A negative step and a negative counter would otherwise walk away from
			// every bound; stopping here is a refusal, not a silent end.
			return false, fmt.Sprintf(
				"the loop over %q passed below zero and its step keeps going down, so it has no end "+
					"this runner can see", f.variable)
		}
		// `proceed` and `verdict` are separate values in this language: `break`
		// stops the walk without saying the flow is satisfied, and reading the
		// verdict as "keep going" once made `break` loop over every value.
		_, _, bodyReason := f.body.execute(r)
		if bodyReason != "" {
			return false, bodyReason
		}
	}
}
