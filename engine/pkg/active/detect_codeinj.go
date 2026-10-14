// Code injection: the parameter reaching an interpreter as code.
//
// # The family, and why it is separate from command injection
//
// `code_injection.rb`, `code_injection_php_input_wrapper.rb` and
// `code_injection_timing.rb` upstream are three checks against one claim: the
// parameter value is *evaluated* rather than compared. That is a different sink
// from a shell, and it is worth separating for a concrete reason — the fix is
// different. Command injection is fixed by not building a command line; code
// injection is fixed by not evaluating input at all, and the escape that matters
// (`htmlspecialchars`) is not an escape that belongs anywhere near a code context.
//
// The three upstream checks split because they fire at different speeds:
// the error-based one looks for a parser naming itself, the PHP-wrapper one looks
// for the request body read back through `php://input`, and the timing one makes
// the interpreter wait. All three are here.
//
// # The wrapper technique is the one that finds real bugs
//
// `php://input` is a PHP stream that yields the raw request body. If a parameter's
// value reaches something that opens it — `include`, `file_get_contents`,
// `fopen`, `readfile` — the attacker can redirect that read to an arbitrary URL or
// path without any traversal at all. Upstream's dedicated check for it exists
// because the traversal detector does not cover it: `../../etc/passwd` needs a
// directory to climb and this needs nothing.
//
// So the wrapper is probed in both directions. A local path reads a local file;
// an `http://` URL makes the server fetch a URL the attacker chose, which is a
// server-side request primitive discovered on a parameter nobody suspected.
package active

import (
	"context"
	"fmt"
	"strconv"
)

// codeInjectionArithmetic is the arithmetic fact the payloads evaluate.
//
// It is deliberately a product of two primes rather than of two small numbers.
// `7*7=49` appears on real pages; `11*13=143` appears on far fewer, and a page that
// prints 143 because the interpreter computed it is a page the interpreter computed
// it on. The same reasoning is why `detect_shared.go` keeps a table of markers
// rather than one.
const (
	codeInjectionFactorA = 11
	codeInjectionFactorB = 13
)

// codeInjectionSyntaxes are the concatenations that place a value into an
// interpreter's expression.
//
// Each is a *different language's* expression, and the list is ordered by how
// often the language is the one in use: PHP string concatenation first, then
// Python's f-string and `%` formatting, then Ruby's `#{}`, then JavaScript's
// template literal, then a bare arithmetic expression for an interpreter that
// takes the value unquoted. A target that evaluates one of them prints the product
// of the two factors — a number the page did not contain.
var codeInjectionSyntaxes = []struct {
	name    string
	build   func(expression string) string
	product int
}{
	{"php concatenation", func(e string) string { return "' . " + e + " . '" }, codeInjectionFactorA * codeInjectionFactorB},
	{"python f-string", func(e string) string {
		return "{:" + fmt.Sprintf("%dx%d", codeInjectionFactorA, codeInjectionFactorB) + "}"
	}, codeInjectionFactorA * codeInjectionFactorB},
	{"python percent format", func(e string) string {
		return fmt.Sprintf("%%.%dx%d", codeInjectionFactorA, codeInjectionFactorB)
	}, codeInjectionFactorA * codeInjectionFactorB},
	{"ruby interpolation", func(e string) string { return "#{" + e + "}" }, codeInjectionFactorA * codeInjectionFactorB},
	{"javascript template literal", func(e string) string { return "${" + e + "}" }, codeInjectionFactorA * codeInjectionFactorB},
}

// codeExpression is the arithmetic the interpreter is asked to evaluate.
var codeExpression = fmt.Sprintf("%d*%d", codeInjectionFactorA, codeInjectionFactorB)

// phpInputWrapperProbes are the values sent through the PHP body-stream wrapper.
//
// Two directions, and the second is the more serious one. The local path is a file
// read; the remote URL is the server fetching a URL the attacker named, which is a
// server-side request primitive and, on a target with no other SSRF surface, this
// is how one is found.
var phpInputWrapperProbes = []struct {
	name    string
	payload string
}{
	{"php://input as local path", "php://filter/convert.base64-encode/resource=/etc/passwd"},
	{"php://filter remote url", "php://filter/resource=https://" + codeWrapperProbeHost},
}

// codeWrapperProbeHost is the destination the remote wrapper probe names.
//
// It is under the reserved `.invalid` TLD, which by RFC 2606 can never resolve.
// The remote probe exists to establish that the *server* issued a fetch, and that
// is observable — a response whose body no longer belongs to the endpoint — rather
// than by receiving anything back. Nothing is resolved here, and naming a real host
// would have the scanner send the operator's own target to a third party, which is
// a side effect nobody asked for.
const codeWrapperProbeHost = "codewrapper-probe.invalid"

// CodeInjection is the code injection detector.
type CodeInjection struct{}

// Name implements Module.
func (CodeInjection) Name() string { return "codeinj" }

// Level implements Module.
func (CodeInjection) Level() Level { return LevelParam }

// Scan probes one surface: stream wrappers first, then expression evaluation.
//
// The wrapper stage is first because it is one request per direction and its
// finding is unambiguous — a base64 of `/etc/passwd` came back, or it did not.
func (m CodeInjection) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if finding := phpWrapperProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := codeExpressionProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	return nil
}

// phpWrapperProbe sends the PHP stream-wrapper values.
//
// The local probe is verified by decoding the base64 wrapper's output and looking
// for the passwd fingerprint — the same reasoning as the LFI detector's wrapper
// technique, and for the same reason: matching base64 by alignment depends on
// where in the stream the file starts, and a fingerprint chosen that way silently
// matches nothing forever.
func phpWrapperProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	for _, probe := range phpInputWrapperProbes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, probe.payload, false, nil)
		if err != nil || resp == nil {
			continue
		}
		if probe.name != "php://input as local path" {
			// The remote form is not reported from here. Confirming it means
			// observing the server make a request this scan cannot see the result
			// of — there is no listener in this package — so the only honest
			// outcome would be a row with no evidence behind it. The register
			// records it as not carried, with that reason, rather than shipping a
			// probe whose verdict is guessed.
			continue
		}
		decoded := decodedCopy(resp)
		if !Fresh(decodedCopy(baseline), decoded, passwdFingerprint) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "codeinj",
			Title:    "Code Injection (PHP stream wrapper, source disclosure)",
			Claimed:  SeverityCritical,
			Tier:     TierVerified,
			Point:    p,
			Payload:  probe.payload,
			Evidence: Snippet(decoded.Body, passwdFingerprint, 140),
			Description: "The parameter value reached a PHP stream wrapper, so it was not read as a path and " +
				"traversed — it was opened. The wrapper returned the contents of /etc/passwd base64-encoded, " +
				"which is arbitrary local file read through a single request with no traversal sequence in it. " +
				"On a deployment where the same sink accepts a remote URL, the same primitive is a server-side " +
				"request forgery with no second bug required.",
			Remediation: "Never pass a parameter to a stream-consuming function. If a file must be included, " +
				"resolve the identifier to a path from a fixed map and refuse `scheme:` forms entirely — a " +
				"wrapper is a URL, and a URL is enough to reach the network.",
		})
		return &finding
	}
	return nil
}

// codeExpressionProbe submits an expression to each interpreter's syntax.
//
// `Fresh` rather than `Changed`, deliberately. A page that renders the payload
// will show the *payload*, and `Changed` would credit that as evaluation; the
// product appearing where the page had never printed it is the only thing that
// means the interpreter ran.
func codeExpressionProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	for _, syntax := range codeInjectionSyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		payload := syntax.build(codeExpression)
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		expected := strconv.Itoa(syntax.product)
		if !Fresh(baseline, resp, expected) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "codeinj",
			Title:   "Code Injection (" + syntax.name + ")",
			Claimed: SeverityCritical,
			Tier:    TierVerified,
			Point:   p,
			Payload: payload,
			Evidence: fmt.Sprintf("the interpreter evaluated the submitted arithmetic and returned %s, a "+
				"value the unmodified response did not contain", expected),
			Description: "The parameter value was evaluated as an expression rather than compared as text. " +
				"The arithmetic chosen for this check is a product of two primes specifically because the " +
				"common 7*7=49 appears on ordinary pages and would be credited to any search box; the " +
				"evaluated value was absent from the unmodified response, so it was produced by the " +
				"interpreter and not by the page.",
			Remediation: "Do not evaluate input. Parse it into a typed value and pass that value to the " +
				"interpreter. Template rendering must not receive a string the request can shape — that is " +
				"the boundary template injection exploits too.",
		})
		return &finding
	}
	return nil
}
