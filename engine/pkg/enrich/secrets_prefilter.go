package enrich

import (
	"regexp/syntax"
	"strings"
	"sync"
)

// A prefilter answers one question before a rule's regex is allowed to run: can
// this rule possibly match this body?
//
// It exists because of a measurement, not a hunch. Running every rule over one
// whole 512 KB body took 54.1 s against 43.3 s for the old per-line loop, and the
// reason is static and countable: 307 of the 543 registered patterns can cross a
// line break — their source contains `\s`, `\n` or `(?s)` — so on one continuous
// haystack the engine explores a larger state space than it did when a newline
// was a hard boundary. Correctness is not negotiable here (see `ScanSecrets`), so
// the cost is paid by not running rules that cannot match.
//
// # What a prefilter may assert
//
// A group of literals is returned only when **every** match of the pattern is
// guaranteed to contain at least one of them. That guarantee is why the walker is
// deliberately quiet: an optional construct contributes nothing, an alternation
// contributes only what every branch requires, and anything the walker does not
// recognise contributes nothing. A group that is missing costs one regex run; a
// group that is wrong costs a finding — and a lost finding is the failure this
// project has already paid for more than once.
//
// Case folding is handled by searching a lowercased copy of the body. That is
// sound in the direction that matters: lowercasing the haystack can only *add*
// occurrences, never remove them, so a rule is only skipped when the literal is
// genuinely absent. A non-ASCII case-insensitive literal is left to the regex
// engine, because Unicode folding is subtler than a lowercasing.

// literalGroup is a disjunction the body must satisfy: at least one of
// `literals` has to be present. `folded` says it is matched case-insensitively,
// which is decided by the pattern, not by the body.
type literalGroup struct {
	literals []string
	folded   bool
}

// prefilterCache keys the compiled walk by pattern source. Rules are compiled once
// and scanned per body, so the walk happens once per distinct pattern even though
// the scan runs it once per rule per body. Tests that hand `scanWithRules` an
// ad-hoc rule slice go through the same cache rather than a second path.
var prefilterCache sync.Map // string -> []literalGroup

// prefilterForPattern returns the literal groups a pattern requires, or nil when
// the pattern has to be run.
func prefilterForPattern(pattern string) []literalGroup {
	if cached, ok := prefilterCache.Load(pattern); ok {
		return cached.([]literalGroup)
	}
	groups := compilePrefilter(pattern)
	prefilterCache.Store(pattern, groups)
	return groups
}

// compilePrefilter parses the pattern and walks it for required literals. A
// pattern that does not parse is left to the regex engine, which will report the
// error itself at compile time rather than here.
func compilePrefilter(pattern string) []literalGroup {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	parsed = parsed.Simplify()
	return requiredLiterals(parsed)
}

// requiredLiterals returns the conjunctions of literals a match of re must satisfy.
func requiredLiterals(re *syntax.Regexp) []literalGroup {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil
		}
		literal := string(re.Rune)
		folded := re.Flags&syntax.FoldCase != 0
		if folded {
			if !isASCII(literal) {
				return nil
			}
			literal = strings.ToLower(literal)
		}
		return []literalGroup{{literals: []string{literal}, folded: folded}}

	case syntax.OpCapture:
		return requiredLiterals(re.Sub[0])

	case syntax.OpPlus:
		return requiredLiterals(re.Sub[0])

	case syntax.OpRepeat:
		// `x{0,}` can match nothing at all, so only a lower bound of one or more
		// makes its content required.
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
		return nil

	case syntax.OpConcat:
		// Every element has to match, so every element's requirement holds.
		var out []literalGroup
		for _, sub := range re.Sub {
			out = append(out, requiredLiterals(sub)...)
		}
		return out

	case syntax.OpAlternate:
		return sharedAcrossBranches(re.Sub)
	}
	// OpQuest, OpStar, OpCharClass, OpAnyChar, OpBeginLine, OpEmptyMatch and
	// anything a future syntax version adds: no requirement.
	return nil
}

// sharedAcrossBranches keeps the literals that every branch of an alternation
// requires, because an alternation matches only when one whole branch matched.
// A branch that requires nothing empties the requirement, which is the honest
// answer rather than the useful one.
func sharedAcrossBranches(branches []*syntax.Regexp) []literalGroup {
	if len(branches) == 0 {
		return nil
	}
	shared := requiredLiterals(branches[0])
	if len(shared) == 0 {
		return nil
	}
	for _, branch := range branches[1:] {
		other := requiredLiterals(branch)
		if len(other) == 0 {
			return nil
		}
		shared = intersectGroups(shared, other)
		if len(shared) == 0 {
			return nil
		}
	}
	return shared
}

// intersectGroups keeps the groups that appear on both sides, literal for
// literal. Two branches requiring different literals is not a shared
// requirement, and reporting one anyway would skip a rule that could match.
func intersectGroups(left, right []literalGroup) []literalGroup {
	var out []literalGroup
	for _, a := range left {
		for _, b := range right {
			if a.folded != b.folded || len(a.literals) != len(b.literals) {
				continue
			}
			same := true
			for i := range a.literals {
				if a.literals[i] != b.literals[i] {
					same = false
					break
				}
			}
			if same {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// prefilterAllows reports whether the body could satisfy every group. `folded` is
// the lowercased body, supplied by the caller so it is built at most once per scan.
func prefilterAllows(groups []literalGroup, body, folded string) bool {
	for _, group := range groups {
		haystack := body
		if group.folded {
			haystack = folded
		}
		found := false
		for _, literal := range group.literals {
			if strings.Contains(haystack, literal) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// needsFoldedBody reports whether any group has to be looked for in the
// lowercased body, so a body nobody asks a folded question about is not copied.
func needsFoldedBody(groups [][]literalGroup) bool {
	for _, set := range groups {
		for _, group := range set {
			if group.folded {
				return true
			}
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}