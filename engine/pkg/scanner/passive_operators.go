package scanner

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var (
	regexCompileCacheMu sync.RWMutex
	regexCompileCache   = make(map[string]*regexp.Regexp, 256)
)

func compileCachedRegex(pattern string) (*regexp.Regexp, error) {
	limit := operatorsCacheLimit
	if limit > 0 {
		regexCompileCacheMu.RLock()
		cached, ok := regexCompileCache[pattern]
		regexCompileCacheMu.RUnlock()
		if ok {
			return cached, nil
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	if limit > 0 {
		regexCompileCacheMu.Lock()
		if len(regexCompileCache) >= limit {
			regexCompileCache = make(map[string]*regexp.Regexp, 256)
		}
		regexCompileCache[pattern] = re
		regexCompileCacheMu.Unlock()
	}
	return re, nil
}

// MatcherType represents the kind of matcher in a template.
type MatcherType string

const (
	StatusMatcher MatcherType = "status"
	SizeMatcher   MatcherType = "size"
	WordsMatcher  MatcherType = "word"
	RegexMatcher  MatcherType = "regex"
	BinaryMatcher MatcherType = "binary"
	DSLMatcher    MatcherType = "dsl"
	XPathMatcher  MatcherType = "xpath"
)

type MatcherTypeHolder struct {
	MatcherType MatcherType
}

func (h *MatcherTypeHolder) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "status":
		h.MatcherType = StatusMatcher
	case "size":
		h.MatcherType = SizeMatcher
	case "word", "words":
		h.MatcherType = WordsMatcher
	case "regex":
		h.MatcherType = RegexMatcher
	case "binary":
		h.MatcherType = BinaryMatcher
	case "dsl":
		h.MatcherType = DSLMatcher
	case "xpath":
		h.MatcherType = XPathMatcher
	default:
		h.MatcherType = MatcherType(s)
	}
	return nil
}

// ExtractorType represents the kind of extractor in a template.
type ExtractorType string

const (
	RegexExtractor ExtractorType = "regex"
	KValExtractor  ExtractorType = "kval"
	JSONExtractor  ExtractorType = "json"
	XPathExtractor ExtractorType = "xpath"
	DSLExtractor   ExtractorType = "dsl"
)

type ExtractorTypeHolder struct {
	ExtractorType ExtractorType
}

func (h *ExtractorTypeHolder) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "regex":
		h.ExtractorType = RegexExtractor
	case "kval":
		h.ExtractorType = KValExtractor
	case "json":
		h.ExtractorType = JSONExtractor
	case "xpath":
		h.ExtractorType = XPathExtractor
	case "dsl":
		h.ExtractorType = DSLExtractor
	default:
		h.ExtractorType = ExtractorType(s)
	}
	return nil
}

// Matcher performs checking against parts of an HTTP exchange.
type Matcher struct {
	Type              MatcherTypeHolder `yaml:"type"`
	Condition         string            `yaml:"condition"`
	Part              string            `yaml:"part"`
	Negative          bool              `yaml:"negative"`
	Name              string            `yaml:"name"`
	Internal          bool              `yaml:"internal"`
	Status            []int             `yaml:"status"`
	Size              []int             `yaml:"size"`
	Words             []string          `yaml:"words"`
	Regex             []string          `yaml:"regex"`
	Binary            []string          `yaml:"binary"`
	DSL               []string          `yaml:"dsl"`
	compiledRegex     []*regexp.Regexp
	compiledBinaries  [][]byte
}

func (m *Matcher) GetType() MatcherType {
	return m.Type.MatcherType
}

func (m *Matcher) Result(matched bool) bool {
	if m.Negative {
		return !matched
	}
	return matched
}

func (m *Matcher) ResultWithMatchedSnippet(matched bool, snippet []string) (bool, []string) {
	if m.Negative {
		return !matched, snippet
	}
	return matched, snippet
}

func (m *Matcher) MatchStatusCode(statusCode int) bool {
	for _, expected := range m.Status {
		if expected == statusCode {
			return true
		}
	}
	return false
}

func (m *Matcher) MatchSize(size int) bool {
	for _, expected := range m.Size {
		if expected == size {
			return true
		}
	}
	return false
}

func (m *Matcher) MatchWords(item string, data map[string]interface{}) (bool, []string) {
	if len(m.Words) == 0 {
		return false, nil
	}
	isAnd := strings.EqualFold(m.Condition, "and")
	matchedWords := make([]string, 0, len(m.Words))

	for _, word := range m.Words {
		if strings.Contains(item, word) {
			matchedWords = append(matchedWords, word)
			if !isAnd {
				return true, matchedWords
			}
		} else if isAnd {
			return false, nil
		}
	}

	if isAnd && len(matchedWords) == len(m.Words) {
		return true, matchedWords
	}
	return len(matchedWords) > 0, matchedWords
}

func (m *Matcher) MatchRegex(item string) (bool, []string) {
	if len(m.compiledRegex) == 0 {
		return false, nil
	}
	isAnd := strings.EqualFold(m.Condition, "and")
	matched := make([]string, 0, len(m.compiledRegex))

	for _, re := range m.compiledRegex {
		if loc := re.FindString(item); loc != "" {
			matched = append(matched, loc)
			if !isAnd {
				return true, matched
			}
		} else if isAnd {
			return false, nil
		}
	}

	if isAnd && len(matched) == len(m.compiledRegex) {
		return true, matched
	}
	return len(matched) > 0, matched
}

func (m *Matcher) MatchBinary(item string) (bool, []string) {
	if len(m.compiledBinaries) == 0 {
		return false, nil
	}
	isAnd := strings.EqualFold(m.Condition, "and")
	matched := make([]string, 0, len(m.compiledBinaries))

	for _, b := range m.compiledBinaries {
		if strings.Contains(item, string(b)) {
			matched = append(matched, hex.EncodeToString(b))
			if !isAnd {
				return true, matched
			}
		} else if isAnd {
			return false, nil
		}
	}
	if isAnd && len(matched) == len(m.compiledBinaries) {
		return true, matched
	}
	return len(matched) > 0, matched
}

func (m *Matcher) MatchDSL(data map[string]interface{}) bool {
	if len(m.DSL) == 0 {
		return false
	}
	isAnd := strings.EqualFold(m.Condition, "and")
	for _, expr := range m.DSL {
		val := evalDSLExpression(expr, data)
		if val {
			if !isAnd {
				return true
			}
		} else if isAnd {
			return false
		}
	}
	return isAnd
}

func (m *Matcher) MatchXPath(item string) bool {
	return false
}

// Extractor extracts information from an exchange.
type Extractor struct {
	Type          ExtractorTypeHolder `yaml:"type"`
	Part          string              `yaml:"part"`
	Name          string              `yaml:"name"`
	Internal      bool                `yaml:"internal"`
	Group         int                 `yaml:"group"`
	Regex         []string            `yaml:"regex"`
	KVal          []string            `yaml:"kval"`
	JSON          []string            `yaml:"json"`
	XPath         []string            `yaml:"xpath"`
	DSL           []string            `yaml:"dsl"`
	compiledRegex []*regexp.Regexp
}

func (e *Extractor) GetType() ExtractorType {
	return e.Type.ExtractorType
}

func (e *Extractor) ExtractRegex(item string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, re := range e.compiledRegex {
		matches := re.FindAllStringSubmatch(item, -1)
		for _, m := range matches {
			if e.Group >= 0 && e.Group < len(m) {
				out[m[e.Group]] = struct{}{}
			} else if len(m) > 0 {
				out[m[0]] = struct{}{}
			}
		}
	}
	return out
}

func (e *Extractor) ExtractKval(data map[string]interface{}) map[string]struct{} {
	out := make(map[string]struct{})
	for _, k := range e.KVal {
		normKey := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
		if val, ok := data[normKey]; ok {
			out[fmt.Sprintf("%v", val)] = struct{}{}
		}
	}
	return out
}

func (e *Extractor) ExtractJSON(item string) map[string]struct{} {
	out := make(map[string]struct{})
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(item), &parsed); err != nil {
		return out
	}
	for _, jPath := range e.JSON {
		if val, ok := parsed[jPath]; ok {
			out[fmt.Sprintf("%v", val)] = struct{}{}
		}
	}
	return out
}

func (e *Extractor) ExtractXPath(item string) map[string]struct{} {
	return nil
}

func (e *Extractor) ExtractDSL(data map[string]interface{}) map[string]struct{} {
	out := make(map[string]struct{})
	for _, expr := range e.DSL {
		res := evalDSLString(expr, data)
		if res != "" {
			out[res] = struct{}{}
		}
	}
	return out
}

func extractorSupportsMap(extractor *Extractor) bool {
	return extractor.GetType() == KValExtractor || extractor.GetType() == DSLExtractor
}

// Operators groups matchers and extractors for a template block.
type Operators struct {
	MatchersCondition string       `yaml:"matchers-condition"`
	Matchers          []*Matcher   `yaml:"matchers"`
	Extractors        []*Extractor `yaml:"extractors"`
}

type OperatorsResult struct {
	Matches        map[string][]string
	Extracts       map[string][]string
	OutputExtracts []string
	DynamicValues  map[string]interface{}
	PayloadValues  map[string]interface{}
}

func (op *Operators) Compile() error {
	for _, m := range op.Matchers {
		for _, r := range m.Regex {
			re, err := compileCachedRegex(r)
			if err != nil {
				return err
			}
			m.compiledRegex = append(m.compiledRegex, re)
		}
		for _, b := range m.Binary {
			decoded, err := hex.DecodeString(strings.ReplaceAll(b, " ", ""))
			if err == nil {
				m.compiledBinaries = append(m.compiledBinaries, decoded)
			}
		}
	}
	for _, e := range op.Extractors {
		for _, r := range e.Regex {
			re, err := compileCachedRegex(r)
			if err != nil {
				return err
			}
			e.compiledRegex = append(e.compiledRegex, re)
		}
	}
	return nil
}

type MatchFunc func(data map[string]interface{}, matcher *Matcher) (bool, []string)
type ExtractFunc func(data map[string]interface{}, extractor *Extractor) map[string]struct{}

func (op *Operators) Execute(data map[string]interface{}, matchFunc MatchFunc, extractFunc ExtractFunc, isInternal bool) (*OperatorsResult, bool) {
	result := &OperatorsResult{
		Matches:       make(map[string][]string),
		Extracts:      make(map[string][]string),
		DynamicValues: make(map[string]interface{}),
		PayloadValues: make(map[string]interface{}),
	}

	isAnd := strings.EqualFold(op.MatchersCondition, "and")
	matchedCount := 0

	for _, m := range op.Matchers {
		matched, snippets := matchFunc(data, m)
		if matched {
			matchedCount++
			mName := m.Name
			if mName == "" {
				mName = string(m.GetType())
			}
			result.Matches[mName] = snippets
			if !isAnd && len(op.Matchers) > 0 {
				break
			}
		} else if isAnd && len(op.Matchers) > 0 {
			break
		}
	}

	overallMatched := false
	if len(op.Matchers) == 0 {
		overallMatched = false
	} else if isAnd {
		overallMatched = (matchedCount == len(op.Matchers))
	} else {
		overallMatched = (matchedCount > 0)
	}

	// Run extractors regardless of match when requested
	for _, e := range op.Extractors {
		values := extractFunc(data, e)
		if len(values) > 0 {
			var list []string
			for v := range values {
				list = append(list, v)
				result.OutputExtracts = append(result.OutputExtracts, v)
			}
			eName := e.Name
			if eName == "" {
				eName = string(e.GetType())
			}
			result.Extracts[eName] = list
		}
	}

	return result, overallMatched
}

// Global cache limits stub to maintain API compatibility
var operatorsCacheLimitVal = 4096


// Simple DSL Evaluator
func evalDSLExpression(expr string, data map[string]interface{}) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}

	// Handle OR
	if parts := splitTopLevel(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalDSLExpression(p, data) {
				return true
			}
		}
		return false
	}

	// Handle AND
	if parts := splitTopLevel(expr, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalDSLExpression(p, data) {
				return false
			}
		}
		return true
	}

	// Handle parentheses
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		return evalDSLExpression(expr[1:len(expr)-1], data)
	}

	// Handle NOT
	if strings.HasPrefix(expr, "!") {
		return !evalDSLExpression(expr[1:], data)
	}

	// Handle comparison: ==, !=, >=, <=, >, < at top level only (outside quotes and parens)
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if parts := splitTopLevel(expr, op); len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal := evalDSLValue(left, data)
			rightVal := evalDSLValue(right, data)

			return compareValues(leftVal, rightVal, op)
		}
	}

	// Boolean function calls like contains(...)
	val := evalDSLValue(expr, data)
	if b, ok := val.(bool); ok {
		return b
	}
	return false
}

func evalDSLString(expr string, data map[string]interface{}) string {
	val := evalDSLValue(expr, data)
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}

func evalDSLValue(token string, data map[string]interface{}) interface{} {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}

	// String literal
	if (strings.HasPrefix(token, "'") && strings.HasSuffix(token, "'")) ||
		(strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"")) {
		return token[1 : len(token)-1]
	}

	// Integer literal
	if n, err := strconv.Atoi(token); err == nil {
		return n
	}

	// Boolean literal
	if token == "true" {
		return true
	}
	if token == "false" {
		return false
	}

	// Function calls: fn(arg1, arg2...)
	if open := strings.Index(token, "("); open > 0 && strings.HasSuffix(token, ")") {
		fnName := strings.ToLower(strings.TrimSpace(token[:open]))
		argsStr := token[open+1 : len(token)-1]
		args := splitArgs(argsStr)

		switch fnName {
		case "contains":
			if len(args) == 2 {
				s1 := fmt.Sprintf("%v", evalDSLValue(args[0], data))
				s2 := fmt.Sprintf("%v", evalDSLValue(args[1], data))
				return strings.Contains(s1, s2)
			}
		case "to_lower":
			if len(args) == 1 {
				s := fmt.Sprintf("%v", evalDSLValue(args[0], data))
				return strings.ToLower(s)
			}
		case "to_upper":
			if len(args) == 1 {
				s := fmt.Sprintf("%v", evalDSLValue(args[0], data))
				return strings.ToUpper(s)
			}
		case "base64":
			if len(args) == 1 {
				s := fmt.Sprintf("%v", evalDSLValue(args[0], data))
				return base64.StdEncoding.EncodeToString([]byte(s))
			}
		case "md5":
			if len(args) == 1 {
				s := fmt.Sprintf("%v", evalDSLValue(args[0], data))
				h := md5.Sum([]byte(s))
				return hex.EncodeToString(h[:])
			}
		case "len":
			if len(args) == 1 {
				s := fmt.Sprintf("%v", evalDSLValue(args[0], data))
				return len(s)
			}
		}
	}

	// Variable lookup in data map
	if v, ok := data[token]; ok {
		return v
	}
	// Try lowercase with underscore
	norm := strings.ToLower(strings.ReplaceAll(token, "-", "_"))
	if v, ok := data[norm]; ok {
		return v
	}

	return token
}

func compareValues(left, right interface{}, op string) bool {
	// Numeric comparison
	lInt, lIsInt := toInt(left)
	rInt, rIsInt := toInt(right)
	if lIsInt && rIsInt {
		switch op {
		case "==":
			return lInt == rInt
		case "!=":
			return lInt != rInt
		case ">":
			return lInt > rInt
		case "<":
			return lInt < rInt
		case ">=":
			return lInt >= rInt
		case "<=":
			return lInt <= rInt
		}
	}

	// String / fallback comparison
	lStr := fmt.Sprintf("%v", left)
	rStr := fmt.Sprintf("%v", right)
	switch op {
	case "==":
		return lStr == rStr
	case "!=":
		return lStr != rStr
	}
	return false
}

func toInt(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case float64:
		return int64(n), true
	case string:
		if i, err := strconv.ParseInt(n, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

func splitTopLevel(s, sep string) []string {
	var parts []string
	parenDepth := 0
	inQuote := false
	var quoteChar rune
	start := 0

	runes := []rune(s)
	sepRunes := []rune(sep)

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if inQuote {
			if r == quoteChar {
				inQuote = false
			}
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = true
			quoteChar = r
			continue
		}
		if r == '(' {
			parenDepth++
			continue
		}
		if r == ')' {
			parenDepth--
			continue
		}

		if parenDepth == 0 && i+len(sepRunes) <= len(runes) {
			match := true
			for j := 0; j < len(sepRunes); j++ {
				if runes[i+j] != sepRunes[j] {
					match = false
					break
				}
			}
			if match {
				parts = append(parts, string(runes[start:i]))
				start = i + len(sepRunes)
				i += len(sepRunes) - 1
			}
		}
	}
	parts = append(parts, string(runes[start:]))
	if len(parts) == 1 {
		return nil
	}
	return parts
}

func splitArgs(s string) []string {
	var args []string
	parenDepth := 0
	inQuote := false
	var quoteChar rune
	start := 0

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if inQuote {
			if r == quoteChar {
				inQuote = false
			}
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = true
			quoteChar = r
			continue
		}
		if r == '(' {
			parenDepth++
			continue
		}
		if r == ')' {
			parenDepth--
			continue
		}
		if parenDepth == 0 && r == ',' {
			args = append(args, strings.TrimSpace(string(runes[start:i])))
			start = i + 1
		}
	}
	if start < len(runes) {
		args = append(args, strings.TrimSpace(string(runes[start:])))
	}
	return args
}
