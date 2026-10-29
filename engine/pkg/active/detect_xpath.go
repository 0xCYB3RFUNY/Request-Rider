// XPath injection.
//
// # Why it is not "SQL injection for XML"
//
// An XPath expression is not an SQL statement and none of the SQL detector's
// techniques reach it. `'` terminates an SQL string; in XPath it terminates a
// string too, but the grammar it exposes is a *path expression* with axes,
// predicates and node tests — there is no `UNION`, no `SELECT`, and no way to
// append a second query, because the whole language has no way to say it. A
// detector that fires SQL payloads at an XPath sink therefore reports either
// nothing or a coincidental match, and the report cannot tell the analyst which
// instrument produced the row.
//
// # What can actually be demonstrated
//
// The strongest claim available for XPath is a boolean difference: XPath has a
// real boolean type, so `count(//*) > 0` is a truth the engine evaluates, and
// feeding it an expression that evaluates false must change what the page prints
// if the input is being parsed as XPath at all. That is the technique this
// detector leads with.
//
// Error disclosure is the second technique, and it is where upstream spends its
// whole budget: `xpath_injection/errors.txt` is twenty-four strings spanning
// libxml2, PHP's SimpleXML, Apache Xalan, MSXML and .NET's XPath. Those are not
// noise to be filtered — each names a distinct implementation, so the match also
// says which stack to look at. That is worth carrying verbatim rather than
// paraphrasing into three generic patterns, because a paraphrase of twenty-four
// strings into three loses every stack but the most common one.
//
// # The freshness check is not optional here
//
// "Expected ')' in" and "Empty Path Expression" are phrases that appear in
// documentation, in a forum post, and in the source of a parser itself. A
// detector that substring-matches them against a page without asking whether the
// page already said them reports injection on every site with a search box. Every
// signature here goes through `FreshFold`, because XPath parsers localise their
// messages and the case of the page's own copy is not the case of the message.
package active

import (
	"context"
	"fmt"
)

// xpathErrorSignatures are the parser error strings, grouped by the
// implementation that emits them.
//
// The grouping is not decoration: it is what turns a match into a lead. An
// operator reading "libxml2 library function failed" knows the target parses XML
// with C, and "SimpleXMLElement::xpath()" names PHP before any exploit is
// written. Upstream keeps these as one flat list of twenty-four lines, so the
// stack is recoverable only by the operator guessing from the text; keeping the
// grouping costs nothing and is the difference between a fingerprint and a lead.
var xpathErrorSignatures = []struct {
	// stack names the implementation the signature belongs to, and is reported
	// with the match.
	stack string
	// signature is one parser message. Entries are single, non-overlapping
	// fragments: the two that name a runtime as well as a condition
	// ("A document must contain exactly one root element.") are kept whole,
	// because shortening them to make the table regular would lose the stack.
	signature string
}{
	// libxml2, which is the C library under PHP, Python, Perl, Ruby and most
	// native bindings.
	{"libxml2", "xmlXPathEval: evaluation failed"},
	{"libxml2", "libxml2 library function failed"},
	{"libxml2", "xmlsec library function failed"},
	{"libxml2", "A closing bracket expected in"},
	{"libxml2", "An operand in Union Expression does not produce a node-set"},
	{"libxml2", "Cannot convert expression to a number"},
	{"libxml2", "Document Axis does not allow any context Location Steps"},
	{"libxml2", "Empty Path Expression"},
	{"libxml2", "Empty Relative Location Path"},
	{"libxml2", "Empty Union Expression"},
	{"libxml2", "Expected ')' in"},
	{"libxml2", "Expected node test or name specification after axis operator"},
	{"libxml2", "Expression must evaluate to a node-set."},
	{"libxml2", "Expected token ']'"},
	{"libxml2", "A document must contain exactly one root element."},
	// PHP's own SimpleXML wrapper.
	{"PHP SimpleXML", "SimpleXMLElement::xpath()"},
	// Apache Xalan, the reference Java implementation.
	{"Apache Xalan", "XPathException"},
	{"Apache Xalan", "org.apache.xpath.XPath"},
	{"Apache Xalan", "Incompatible XPath key"},
	{"Apache Xalan", "Incorrect Variable Binding"},
	// MSXML and .NET, whose messages arrive as HTML fragments rather than as
	// plain text, so the markup around them is part of the fingerprint.
	{"MSXML / .NET", "MS.Internal.Xml."},
	{"MSXML / .NET", "Unknown error in XPath"},
	{"MSXML / .NET", "<p>msxml4.dll</font>"},
	{"MSXML / .NET", "<p>msxml3.dll</font>"},
	{"COM", "error '80004005'"},
}

// xpathBooleanProbes are the two halves of a boolean pair.
//
// `count(//*)` is used rather than a bare comparison because it has no
// dependency on the document's shape: `//*` matches every element whatever the
// document contains, so `count(//*) > 0` is true for any well-formed XML and
// `count(//*) > 1000000` is false for any document a browser will render. A pair
// built on a name that has to exist — `//user/password` — reports nothing on a
// document with no such element, which is the ordinary case, and the technique
// would look broken rather than inapplicable.
var xpathBooleanProbes = []struct {
	name  string
	truth string
	falsy string
}{
	{"count", `' AND count(//*) > 0 AND '`, `' AND count(//*) > 1000000 AND '`},
	{"node-set", `' AND //*[0] AND '`, `' AND not(//*[999999999]) AND '`},
}

// XPath is the XPath injection detector.
type XPath struct{}

// Name implements Module.
func (XPath) Name() string { return "xpath" }

// Level implements Module.
func (XPath) Level() Level { return LevelParam }

// Scan probes one surface: error disclosure first, then the boolean pair.
//
// Error disclosure comes first because it is one request and it can carry the
// stack, and because a target that leaks its parser's messages rarely needs the
// differential stage at all.
func (m XPath) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if finding := xpathErrorProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := xpathBooleanProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	return nil
}

// xpathErrorPayloads are the strings sent to make a parser complain.
//
// Each ends in a construct that is valid only outside a predicate, so a value
// interpolated into `concat('//user[', <here> ,']')` produces a parse error rather
// than an empty match. `'` alone is not enough: a target that escapes quotes
// first will simply see a rejected value, and the parser never runs.
var xpathErrorPayloads = []string{
	`'`,
	`' AND `,
	`'))]`,
	`')]`,
	`//*[`,
}

// xpathErrorProbe looks for a parser naming its own failure.
func xpathErrorProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	for _, payload := range xpathErrorPayloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		for _, entry := range xpathErrorSignatures {
			if !FreshFold(baseline, resp, entry.signature) {
				continue
			}
			finding, _ := NewFinding(Spec{
				Module:   "xpath",
				Title:    "XPath Injection (parser error, " + entry.stack + ")",
				Claimed:  SeverityHigh,
				Tier:     TierVerified,
				Point:    p,
				Payload:  payload,
				Evidence: Snippet(resp.Body, entry.signature, 140),
				Description: "The submitted value was parsed as an XPath expression and the parser reported a " +
					"failure in its own words. The stack named in the title (" + entry.stack + ") is the " +
					"implementation that produced it, so the message is diagnostic rather than merely " +
					"incriminating. The signature was absent from the unmodified response, so it was the " +
					"injection that produced it.",
				Remediation: "Do not build XPath expressions by string concatenation. Bind the value as a " +
					"parameter, or compare it inside the document rather than inside the path.",
			})
			return &finding
		}
	}
	return nil
}

// xpathBooleanProbe sends both halves of a boolean pair.
//
// The refusal is deliberate and it is the difference between this technique and a
// reflection test. XPath is a real boolean language, so a target that evaluates
// the expression must render the two halves differently; a target that merely
// echoes the input renders them *identically*, because echoing is faithful and
// does not care what the string means. A detector that counted a changed
// response as signal here would therefore reward exactly the case where nothing
// is wrong.
func xpathBooleanProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	if baseline == nil {
		return nil
	}
	for _, probe := range xpathBooleanProbes {
		if ctx.Err() != nil {
			return nil
		}
		truth, err := t.Fire(ctx, p, p.Param, probe.truth, false, nil)
		if err != nil {
			continue
		}
		falsy, err := t.Fire(ctx, p, p.Param, probe.falsy, false, nil)
		if err != nil {
			continue
		}
		// The echo is stripped from both answers before they are compared, and the
		// reason is a live run rather than an argument. This function's premise is
		// that a target which only echoes renders the two payloads identically,
		// because echoing is faithful. That holds for a raw echo and fails for an
		// encoded one: a page that writes the value into `href` percent-encodes it,
		// so the two payloads come back with different lengths and the difference
		// between them is the escaping — read here as the engine evaluating XPath,
		// and reported at the strongest tier the tool has. A live run against a news
		// site produced exactly that row. After stripping, a page that only echoes
		// is byte-identical again and only a real evaluation survives.
		truthBody := stripEcho(truth.Body, probe.truth)
		falsyBody := stripEcho(falsy.Body, probe.falsy)
		if truthBody == falsyBody {
			continue
		}
		between := Divergence(truthBody, falsyBody)
		if between < xpathDivergenceFloor {
			continue
		}
		// The difference has to appear twice. One pair of answers differing is not
		// evidence that the expression was evaluated; see `confirmDivergence`.
		if !confirmDivergence(ctx, t, p, probe.truth, probe.falsy, xpathDivergenceFloor) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "xpath",
			Title:   "XPath Injection (boolean differential, " + probe.name + ")",
			Claimed: SeverityHigh,
			Tier:    TierVerified,
			Point:   p,
			Payload: probe.truth,
			Evidence: fmt.Sprintf("a predicate that evaluates true and the same predicate evaluating "+
				"false produce responses that diverge by %.3f, so the expression is being evaluated as "+
				"XPath rather than printed", between),
			Description: "Two payloads differing only in the truth value of an XPath predicate produce " +
				"different responses. Because XPath has a boolean type, a target that renders both payloads " +
				"verbatim would render them identically — so the difference is the engine evaluating the " +
				"expression, and the row is verified rather than capped.",
			Remediation: "Bind the value as a parameter instead of concatenating it into the path. If a " +
				"path must be assembled, validate it against a fixed set of permitted element names.",
		})
		return &finding
	}
	return nil
}

// xpathDivergenceFloor is how far apart the two halves must land before the
// difference is credited.
//
// Two thresholds appear in this file and they are not the same number for the
// same reason. The operator and differential stages want to notice that *something*
// moved and cap the row, so their floor is tiny. The boolean stage is credited as
// verified, so its floor is large enough that a rotating nonce cannot reach it:
// the difference has to be structural, not a changed request id.
const xpathDivergenceFloor = 0.01
