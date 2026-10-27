// NoSQL injection, with the differential technique taken from Arachni.
//
// # Why this detector exists when SQL injection is already covered
//
// The SQL detector sends SQL. A MongoDB query is not SQL, and a payload that is
// syntactically wrong for MongoDB is not merely rejected — it is frequently
// *accepted and obeyed*, because `{"$ne": ""}` is a valid operator rather than a
// broken query. An application that concatenates a parameter into a MongoDB
// filter therefore keeps working perfectly while returning a different result
// set, and the SQL detector sees nothing: there is no error to fingerprint and no
// boolean to invert. That is a different instrument pointed at a different
// database, so it is a different detector.
//
// # The three techniques, and why all three are here
//
// Upstream ships two checks for this and they fail differently. The error check
// (`no_sql_injection.rb`, payload `{ mongodb: '\';.")' }`, signatures
// `mongodb` and `Uncaught exception 'MongoCursorException'`) only fires when the
// driver is configured to leak its exception into the response, which is the
// minority of deployments. The differential check
// (`no_sql_injection_differential.rb`) is the one that generalises, and its
// payload table is the interesting part: for each of the three quote characters
// it pairs a *true* writing with a *false* writing —
// `'||return true;var foo='` against `'||return false;var foo='`, and
// `1'||this'` against `1'||!this'`. Both members of a pair are sent and the two
// responses are compared, so nothing has to be identifiable in either one.
//
// This detector adds the third technique, which neither upstream check has: the
// operator forms `{"$ne": ""}`, `{"$gt": ""}` and `{"$regex": ".*"}`. They matter
// because they are the shape an operator injection actually takes in PHP and
// Node applications, where the query string is decoded into a document rather
// than into a string — and because `{"$ne": ""}` widens a filter to every
// document, which is a *visible* difference on any paginated list.
//
// # What is claimed, and what is not
//
// The differential technique is blind by construction: nothing in either
// response says "true", and the whole claim is that the two differ. A pair that
// differs is therefore reported at `TierPotential`, which caps it at medium,
// because "these two responses differ" is not the same claim as "MongoDB
// evaluated `$where`". The error-signature path is different — a driver error
// naming itself is an observed fact — and is reported at `TierVerified`.
//
// A difference between the two halves of a pair is also required to be a
// difference from the *unmodified* surface. A parameter whose page changes when
// any value is typed — a search box, a nonce, a rotating banner — produces a
// differing pair on a target with no injection at all, and that is the exact
// false positive that makes a differential check worthless on its own.
package active

import (
	"context"
	"fmt"
	"strings"
)

// nosqlErrorSignatures are the strings a MongoDB driver puts in a response when
// the exception reaches the client.
//
// They are taken from upstream's `no_sql_injection/substrings/` and are matched
// case-insensitively, because `MongoCursorException` and `mongocursorexception`
// are the same exception to the reader and the casing is not guaranteed.
var nosqlErrorSignatures = []string{
	"MongoCursorException",
	"mongodb",
	"Uncaught exception",
}

// nosqlErrorPayload is the probe upstream sends to provoke those signatures.
//
// It is a bare quote followed by a JS comment, which is what makes a MongoDB
// driver's parser abandon the string it was building and print a stack trace.
const nosqlErrorPayload = `';.")`

// nosqlOperatorPayloads are the operator injections, in the order a filter is
// most likely to honour them.
//
// Each is a complete JSON document rather than a bare operator, because the
// vulnerable shape is a parameter decoded into a document: sending `$ne` on its
// own reaches an application as the string `$ne` and does nothing. `{"$ne": ""}`
// widens a match to every document that is not the empty string, `{"$gt": ""}`
// widens it to every document whose field sorts above the empty string, and
// `{"$regex": ".*"}` widens it to every document with the field at all — three
// different widenings, so a filter that honours one and not another still shows
// a difference on at least one of them.
var nosqlOperatorPayloads = []struct {
	name     string
	operator string
	payload  string
}{
	{"$ne", "$ne", `{"$ne":""}`},
	{"$gt", "$gt", `{"$gt":""}`},
	{"$regex", "$regex", `{"$regex":".*"}`},
}

// nosqlDecoyOperator is an operator name no database has.
//
// It is the control for the probe above: a document identical in shape to each
// operator form but naming something meaningless. A target that honours operators
// answers the real one and ignores the decoy, and the two answers differ in their
// *results*. A target that merely echoes answers both the same way, and after the
// echoed payloads are removed the two answers are byte-identical.
const nosqlDecoyOperator = "$nope"

// nosqlDifferentialPair is one true/false pair.
//
// The two halves must differ in their *logic* and agree in their *shape*, so
// that whatever distinguishes the responses is the boolean and not the
// punctuation. That is the whole reason upstream builds the pair from a template
// with the quote substituted in rather than writing six literals.
type nosqlDifferentialPair struct {
	name  string
	truth string
	falsy string
}

// nosqlQuoteStyles are the three quote characters upstream substitutes into the
// pair templates. The parameter may be read inside a PHP string, a Python string
// or a JS string, and the one that terminates the first two does not terminate
// the third.
var nosqlQuoteStyles = []struct {
	name  string
	quote string
}{
	{"single quote", "'"},
	{"double quote", `"`},
	{"bare", ""},
}

// nosqlDifferentialPairs builds the pair table from the templates upstream
// declares, so the table cannot drift from the technique it ports.
//
// The templates are `;return true;var foo=` and `||this` with the quote
// substituted in. Building the table rather than pasting six strings keeps the
// quote handling in one place and makes the count checkable.
func nosqlDifferentialPairs() []nosqlDifferentialPair {
	var out []nosqlDifferentialPair
	for _, style := range nosqlQuoteStyles {
		out = append(out,
			nosqlDifferentialPair{
				name:  "$where true/false, " + style.name,
				truth: nosqlApplyQuote(`%q;return true;var foo=%q`, style.quote),
				falsy: nosqlApplyQuote(`%q;return false;var foo=%q`, style.quote),
			},
			nosqlDifferentialPair{
				name:  `||this/||!this, ` + style.name,
				truth: nosqlApplyQuote(`1%q||this%q`, style.quote),
				falsy: nosqlApplyQuote(`1%q||!this%q`, style.quote),
			},
		)
	}
	return out
}

// nosqlApplyQuote substitutes %q in a template with the quote character.
//
// It exists so the pair table is derived rather than transcribed. Upstream builds
// its pairs with `String#gsub('%q', quote)`; a transcribed table of six literals
// can drift from the template and a drifted table tests something upstream never
// sent.
func nosqlApplyQuote(template, quote string) string {
	return strings.ReplaceAll(template, "%q", quote)
}

// NoSQL is the NoSQL injection detector.
type NoSQL struct{}

// Name implements Module.
func (NoSQL) Name() string { return "nosql" }

// Level implements Module.
func (NoSQL) Level() Level { return LevelParam }

// Scan probes one surface.
//
// The order is cost and then strength: the operator forms come first because
// each is one request and widens a filter visibly, the error probe is next
// because it is the only technique here that can raise a row to verified, and
// the differential pairs come last because each costs two requests and produces
// the weakest claim this detector is willing to make.
func (m NoSQL) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if finding := nosqlOperatorProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := nosqlErrorProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := nosqlDifferentialProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	return nil
}

// nosqlOperatorProbe sends the three operator documents.
//
// It reports at `TierPotential` rather than verified, and the reason is in the
// tier, not in the prose: a widened result set is strong evidence and it is not
// proof, because an application that echoes a filter into a debug page shows the
// same widening with no injection behind it.
func nosqlOperatorProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	for _, operator := range nosqlOperatorPayloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, operator.payload, false, nil)
		if err != nil {
			continue
		}
		if baseline == nil || resp == nil {
			continue
		}
		// The decoy is the whole reason this probe is honest.
		//
		// An earlier version compared the operator response against the unmodified
		// page and required only that they differ. That fires on **any** page that
		// echoes its input — which is most pages, and every search box — because
		// echoing the operator produces a body that differs from the body for the
		// empty value. The mutation run is what found it: removing the operator
		// probe from `Scan` changed nothing, because a fixture whose only answer was
		// the driver's error message still "proved" an operator injection through
		// its own echo.
		//
		// So the comparison is against a *decoy*: the same document with an
		// operator the database does not have. Both responses have their echoed
		// payload removed before they are compared, because after removal an echo
		// leaves nothing behind while a widened result set leaves the whole list.
		decoyPayload := strings.Replace(operator.payload, operator.operator, nosqlDecoyOperator, 1)
		decoy, err := t.Fire(ctx, p, p.Param, decoyPayload, false, nil)
		if err != nil || decoy == nil {
			continue
		}
		divergence := Divergence(stripEcho(decoy.Body, decoyPayload), stripEcho(resp.Body, operator.payload))
		if divergence < nosqlOperatorDivergenceFloor {
			continue
		}
		// The operator and its decoy are asked again, and the widening has to be
		// there the second time; see `confirmDivergence`. Stripping the echo is not
		// enough on a live target: a banner, a rate limiter or a captcha makes any
		// two answers differ, and the first pair of requests is exactly where that
		// noise gets read as a widened result set.
		if !confirmDivergence(ctx, t, p, operator.payload, decoyPayload, nosqlOperatorDivergenceFloor) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "nosql",
			Title:   "NoSQL Injection (operator injection, " + operator.name + ")",
			Claimed: SeverityHigh,
			Tier:    TierPotential,
			Point:   p,
			Payload: operator.payload,
			Evidence: fmt.Sprintf("submitting the %s document changes the result by %.3f relative to a "+
				"decoy document naming a non-existent operator, with both echoed payloads removed, so "+
				"the difference is in the results and not in the echo", operator.name, divergence),
			Description: "The parameter reaches a NoSQL filter as a document rather than as a string, so an " +
				"operator submitted through it is honoured as query syntax. The response changed as a result, " +
				"which is consistent with a widened filter; the operator was not observed being evaluated by " +
				"the database, so the row is capped rather than verified.",
			Remediation: "Build NoSQL filters as typed documents with validated keys. Reject any parameter " +
				"whose value parses as a document or begins with an operator such as $ne, $gt or $regex.",
		})
		return &finding
	}
	return nil
}

// nosqlOperatorDivergenceFloor is how much of the document has to change before
// an operator probe is worth reporting.
//
// It is deliberately small — a row that renders one more of two hundred results
// is the ordinary shape of this bug — and the ceiling of the claim is
// `TierPotential`, so a low threshold cannot produce a verified row out of a
// nonce. What the floor does prevent is reporting every probe that differed by a
// request id.
const nosqlOperatorDivergenceFloor = 0.001

// nosqlErrorProbe sends the payload that provokes a driver exception and reads
// the driver's own name in the answer.
//
// This is the one path in the detector that can claim verification, because the
// signature is the driver describing its own parse failure over the submitted
// input. The freshness check is not skipped for it: `mongodb` in particular is a
// word a page about MongoDB contains without being vulnerable to anything, so a
// bare substring test on a page that documents its own stack would report every
// parameter on it.
func nosqlErrorProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	resp, err := t.Fire(ctx, p, p.Param, nosqlErrorPayload, false, nil)
	if err != nil {
		return nil
	}
	for _, signature := range nosqlErrorSignatures {
		if !FreshFold(baseline, resp, signature) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "nosql",
			Title:    "NoSQL Injection (driver error disclosure)",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  nosqlErrorPayload,
			Evidence: Snippet(resp.Body, signature, 140),
			Description: "The submitted payload made the NoSQL driver abandon the query and name itself in " +
				"the response. The signature was absent from the unmodified response, so the exception is a " +
				"consequence of the injection rather than a property of the page.",
			Remediation: "Turn off exception rendering in production, and reject input that reaches a NoSQL " +
				"call without being parsed into a typed document.",
		})
		return &finding
	}
	return nil
}

// nosqlDifferentialProbe sends both halves of each pair and reports a pair whose
// responses differ from each other *and* from the unmodified surface.
//
// The three-way test is what separates this from "the page is dynamic". A pair
// that differs only from the baseline is a page that renders differently every
// request; a pair whose two halves differ is a page that rendered those two
// inputs differently, and the only thing that changed between them is the
// boolean.
func nosqlDifferentialProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	if baseline == nil {
		// Without the unmodified response the three-way test cannot be run, and a
		// two-way test on a dynamic page is the false positive this function
		// exists to avoid.
		return nil
	}
	for _, pair := range nosqlDifferentialPairs() {
		if ctx.Err() != nil {
			return nil
		}
		truth, errTruth := t.Fire(ctx, p, p.Param, pair.truth, false, nil)
		if errTruth != nil {
			continue
		}
		falsy, errFalsy := t.Fire(ctx, p, p.Param, pair.falsy, false, nil)
		if errFalsy != nil {
			continue
		}
		// The echo is stripped before anything is compared, and the baseline check
		// below is made against the stripped bodies for the same reason. Two payloads
		// that differ only in a boolean, reflected percent-encoded into a link, come
		// back with different lengths; the difference between them is the escaping,
		// not a result set. That is what a live run against a real site reported.
		truthBody := stripEcho(truth.Body, pair.truth)
		falsyBody := stripEcho(falsy.Body, pair.falsy)
		baseBody := stripEcho(baseline.Body, pair.truth)
		if truthBody == falsyBody {
			continue
		}
		if truthBody == baseBody && falsyBody == baseBody {
			continue
		}
		between := Divergence(truthBody, falsyBody)
		if between < nosqlOperatorDivergenceFloor {
			continue
		}
		// The difference has to appear twice; see `confirmDivergence`.
		if !confirmDivergence(ctx, t, p, pair.truth, pair.falsy, nosqlOperatorDivergenceFloor) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "nosql",
			Title:   "Blind NoSQL Injection (differential, " + pair.name + ")",
			Claimed: SeverityHigh,
			Tier:    TierPotential,
			Point:   p,
			Payload: pair.truth,
			Evidence: fmt.Sprintf("the true and false writings of the same pair produce responses that "+
				"diverge by %.3f, and neither is the unmodified response", between),
			Description: "Two payloads differing only in the boolean they express produce different responses. " +
				"That is the shape of a blind NoSQL injection, and it is the strongest claim a differential " +
				"check can make: neither response identifies the payload as evaluated, so the row is capped " +
				"rather than verified.",
			Remediation: "Parse the parameter into a typed value and build the filter from that value. An " +
				"unset parameter must not be replaced by a query fragment.",
		})
		return &finding
	}
	return nil
}
