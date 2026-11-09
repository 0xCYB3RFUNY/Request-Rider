package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fixtureForm is a page carrying the four form shapes the module reads, plus one
// shape it must *not* report: a POST form with a password field, which keeps the
// credential out of the query string.
const fixtureForm = `<html><body>` +
	`<form action="/search" method="get"><input name="q" type="text">` +
	`<input name="user" type="text"><input name="pass" type="password"></form>` +
	`<form action="/login" method="post"><input name="user" type="text">` +
	`<input name="pass" type="password"></form>` +
	`<form action="/upload" method="post" enctype="multipart/form-data">` +
	`<input name="document" type="file"></form>` +
	`<form action="/subscribe" method="get"><input name="email" type="text"></form>` +
	`</body></html>`

func formFixtureServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(fixtureForm))
	}))
}

func TestFormSemanticsReportsWhatTheMarkupDeclares(t *testing.T) {
	server := formFixtureServer()
	defer server.Close()

	point := Point{URL: server.URL + "/", Method: http.MethodGet, Origin: server.URL + "/"}
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: fixtureForm}

	findings := FormSemantics{}.Scan(context.Background(), nil, point, baseline)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one for the upload form, one for the password-by-GET form)", len(findings))
	}
	titles := map[string]bool{}
	for _, finding := range findings {
		titles[finding.Title] = true
	}
	if !titles["File Upload Functionality"] {
		t.Errorf("no upload row; got %v", titles)
	}
	if !titles["Password Submitted Using GET Method"] {
		t.Errorf("no password-by-GET row; got %v", titles)
	}
}

// The POST form is the control: a password field that does not travel in the URL
// is not what the check names, and a detector that reported it would be
// describing a shape the application does not have.
func TestFormSemanticsIgnoresAPasswordThatDoesNotTravelByGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form action="/login" method="post">` +
			`<input name="user" type="text"><input name="pass" type="password">` +
			`</form></body></html>`))
	}))
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}}
	findings := FormSemantics{}.Scan(context.Background(), nil,
		Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "GET") {
			t.Fatalf("reported %q against a form that submits by POST", finding.Title)
		}
	}
}

// A page with no forms at all is the empty state, and it must be silent rather
// than reporting the absence of a defect as a finding.
func TestFormSemanticsIsSilentOnAPageWithoutForms(t *testing.T) {
	baseline := &Response{StatusCode: 200,
		Header: http.Header{"Content-Type": {"text/html"}},
		Body:   "<html><body><p>nothing here</p></body></html>"}
	findings := FormSemantics{}.Scan(context.Background(), nil,
		Point{URL: "http://example.com/", Method: http.MethodGet}, baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
