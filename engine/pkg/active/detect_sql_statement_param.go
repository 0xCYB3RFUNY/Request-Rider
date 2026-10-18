package active

// SQLStatementInParameter names the parameter whose own value is already SQL.
//
// Burp's check is `0x00400480` (SQL statement in request parameter). It is a
// reader, not a probe: the value is what the operator's own request or the page's
// own form already carried, and asking the server about it again would spend a
// request to rediscover a fact the request states.
//
// Why the value has to be an actual *statement*, not a fragment. A parameter
// named `order` carrying `asc` is not SQL. A parameter carrying
// `union select password from users` is, and it means the application was built
// to accept a query from the client — which is the whole finding, before any
// injection is attempted. The inference patterns are therefore whole-clause
// patterns: a statement keyword followed by a column list, not a keyword alone.
//
// The severity is information because the row documents what the application
// accepts, not what an attacker achieved. A page that takes a full `SELECT` is a
// page an operator has to look at, and a scanner that escalated it to high
// without a successful injection would be reporting the possibility rather than
// the fact.

import (
	"context"
	"regexp"
	"strings"
)

// SQLStatementInParameter is the SQL-in-a-parameter reader.
type SQLStatementInParameter struct{}

// Name implements Module.
func (SQLStatementInParameter) Name() string { return "sql-statement-param" }

// Level implements Module.
func (SQLStatementInParameter) Level() Level { return LevelParam }

// sqlStatementPatterns are the whole-clause shapes that make a value a
// statement. Each one carries what it means, so the evidence line says which
// clause was found rather than that "SQL was detected".
var sqlStatementPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"union select", regexp.MustCompile(`(?i)\bunion\s+(all\s+)?select\b`)},
	{"select from", regexp.MustCompile(`(?i)\bselect\s+.{1,120}\bfrom\s+[\w\x60.'"\[\]$-]{1,64}`)},
	{"insert into", regexp.MustCompile(`(?i)\binsert\s+into\s+[\w\x60.'"\[\]$-]{1,64}`)},
	{"update set", regexp.MustCompile(`(?i)\bupdate\s+[\w\x60.'"\[\]$-]{1,64}\s+set\s+`)},
	{"delete from", regexp.MustCompile(`(?i)\bdelete\s+from\s+[\w\x60.'"\[\]$-]{1,64}`)},
	{"drop table", regexp.MustCompile(`(?i)\bdrop\s+(table|database|schema)\s+[\w\x60.'"\[\]$-]{1,64}`)},
	{"truncate table", regexp.MustCompile(`(?i)\btruncate\s+(table\s+)?[\w\x60.'"\[\]$-]{1,64}`)},
	{"call procedure", regexp.MustCompile(`(?i)\b(call|exec|execute)\s+[\w\x60.'"\[\]$.]{1,64}`)},
	{"or tautology", regexp.MustCompile(`(?i)\b(or|and)\s+['"]?[\w]{1,32}['"]?\s*(=|<>|like)\s*['"]?[\w]{1,32}['"]?\s*(--|#|/\*|\bor\b|\band\b)`)},
	{"stacked query", regexp.MustCompile(`(?i);\s*(select|insert|update|delete|drop|create|grant)\b`)},
	{"schema read", regexp.MustCompile(`(?i)\bfrom\s+(information_schema|pg_catalog|sqlite_master|sysobjects|msysobjects)\b`)},
	{"sleep or waitfor", regexp.MustCompile(`(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`)},
	{"hex or char cast", regexp.MustCompile(`(?i)\b(char|unhex|concat|concat_ws|load_file|group_concat)\s*\(`)},
}

// Scan reports the parameter when its own value is a SQL statement.
func (SQLStatementInParameter) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if p.Values == nil || p.Param == "" {
		return nil
	}
	value := p.Values.Get(p.Param)
	if strings.TrimSpace(value) == "" {
		return nil
	}
	// A value that short cannot carry a statement with a column list, and the
	// shortest pattern here needs far more room than this.
	if len(value) < 12 {
		return nil
	}
	matched := []string{}
	for _, candidate := range sqlStatementPatterns {
		if candidate.pattern.MatchString(value) {
			matched = append(matched, candidate.name)
			if len(matched) >= 2 {
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "sql-statement-param",
		Title:    "SQL Statement in Request Parameter",
		Claimed:  SeverityInfo,
		Tier:     TierVerified,
		Point:    p,
		Payload:  "<" + p.Param + " value redacted>",
		Evidence: "parameter `" + p.Param + "` carries: " + strings.Join(matched, ", "),
		Description: "The parameter `" + p.Param + "` on " + p.URL + " carries a SQL statement (" +
			strings.Join(matched, ", ") + "). The application therefore accepts a query, or a " +
			"fragment of one, from the client — which means the query text is already on the " +
			"wrong side of the boundary and any escaping decision the server makes is being " +
			"applied to something a caller wrote. The value itself is not reproduced here: it is " +
			"the operator's data.",
		Remediation: "Take structured input — a filter name, a sort direction, a page number — and " +
			"build the query from a fixed statement with bound parameters. If a caller genuinely " +
			"chooses columns, map their choice through an allow-list on the server side.",
	})
	return []Finding{finding}
}
