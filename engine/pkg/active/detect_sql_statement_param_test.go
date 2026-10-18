package active

import (
	"context"
	"net/url"
	"testing"
)

// The value the application itself shipped is the finding, so the test hands the
// module a parameter whose value is already a statement.
func TestSQLStatementInParameterReportsTheStatementItWasHanded(t *testing.T) {
	point := Point{
		URL:    "http://example.com/report",
		Method: "GET",
		Param:  "filter",
		Values: url.Values{"filter": {"1 union select password from users--"}},
	}
	findings := (SQLStatementInParameter{}).Scan(context.Background(), nil, point, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Title != "SQL Statement in Request Parameter" {
		t.Errorf("title = %q", findings[0].Title)
	}
	// The value is the operator's data, not this run's, so it must not be
	// reproduced in the payload column.
	if findings[0].Payload == "1 union select password from users--" {
		t.Errorf("the operator's own value was reproduced in the payload column: %q", findings[0].Payload)
	}
}

// The control: values that contain a keyword but are not statements. `order by
// name` is a sort, `select` as a checkbox name is a field, and a short value
// cannot carry a clause with a column list at all.
func TestSQLStatementInParameterIgnoresValuesThatAreNotStatements(t *testing.T) {
	for _, value := range []string{
		"asc",
		"select",
		"order by name",
		"1 or 1=1",
		"user@example.com",
		"",
	} {
		point := Point{
			URL:    "http://example.com/report",
			Method: "GET",
			Param:  "sort",
			Values: url.Values{"sort": {value}},
		}
		if findings := (SQLStatementInParameter{}).Scan(context.Background(), nil, point, nil); len(findings) != 0 {
			t.Fatalf("value %q: findings = %d, want 0", value, len(findings))
		}
	}
}

// A surface with no original value set is a surface this module has nothing to
// read, and it must decline rather than report the empty string.
func TestSQLStatementInParameterIsSilentWithoutValues(t *testing.T) {
	point := Point{URL: "http://example.com/report", Method: "GET", Param: "sort"}
	if findings := (SQLStatementInParameter{}).Scan(context.Background(), nil, point, nil); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
