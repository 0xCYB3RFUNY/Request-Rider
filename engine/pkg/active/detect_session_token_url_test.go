package active

import (
	"context"
	"net/http"
	"testing"
)

// The parameter's own name is the whole finding, so the test is a table of names
// and of names that only *look* like session identifiers.
func TestSessionTokenInURLNamesTheParameterItWasHanded(t *testing.T) {
	for _, name := range []string{"jsessionid", "phpsessid", "session_id", "SESSIONID", "sid"} {
		point := Point{URL: "http://example.com/", Method: http.MethodGet, Param: name}
		findings := SessionTokenInURL{}.Scan(context.Background(), nil, point, nil)
		if len(findings) != 1 {
			t.Fatalf("parameter %q: findings = %d, want 1", name, len(findings))
		}
		if findings[0].Title != "Session Token in URL" {
			t.Errorf("parameter %q: title = %q", name, findings[0].Title)
		}
	}
}

// `token` on its own is a CSRF token, a reset token and a search parameter
// depending on the day. A detector that reported all three would be a detector
// nobody reads.
func TestSessionTokenInURLIgnoresATokenThatIsNotASession(t *testing.T) {
	for _, name := range []string{"token", "csrf", "csrf_token", "q", "page", "api_token"} {
		point := Point{URL: "http://example.com/", Method: http.MethodGet, Param: name}
		if findings := (SessionTokenInURL{}).Scan(context.Background(), nil, point, nil); len(findings) != 0 {
			t.Fatalf("parameter %q: findings = %d, want 0", name, len(findings))
		}
	}
}

// A surface with no name is not a surface this module can answer about, and a
// nil baseline is not a reason to guess.
func TestSessionTokenInURLIsSilentWithoutAParameter(t *testing.T) {
	point := Point{URL: "http://example.com/", Method: http.MethodGet}
	if findings := (SessionTokenInURL{}).Scan(context.Background(), nil, point, nil); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
