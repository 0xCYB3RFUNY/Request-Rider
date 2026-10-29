package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGraphQLIntrospectionAndSuggestions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		if strings.Contains(body, "__schema") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"},{"name":"Product"}]}}}`)
			return
		}

		if strings.Contains(body, "__nonExistentFieldXYZ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":[{"message":"Cannot query field '__nonExistentFieldXYZ' on type 'Query'. Did you mean '__schema'?"}]}`)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := GraphQL{}

	// Test endpoint pointing directly to GraphQL
	p := Point{
		URL:    server.URL + "/graphql",
		Method: http.MethodPost,
		Origin: server.URL,
	}

	findings := detector.Scan(context.Background(), transport, p, nil)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (introspection + suggestions), got %d: %+v", len(findings), findings)
	}

	foundIntro := false
	foundSuggest := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Introspection") {
			foundIntro = true
		}
		if strings.Contains(f.Title, "Suggestions") {
			foundSuggest = true
		}
	}

	if !foundIntro {
		t.Errorf("missing GraphQL Introspection finding")
	}
	if !foundSuggest {
		t.Errorf("missing GraphQL Suggestions finding")
	}
}

func TestGraphQLDisabledDoesNotReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"errors":[{"message":"GraphQL introspection is forbidden."}]}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := GraphQL{}
	p := Point{
		URL:    server.URL + "/graphql",
		Method: http.MethodPost,
	}

	findings := detector.Scan(context.Background(), transport, p, nil)
	for _, f := range findings {
		if strings.Contains(f.Title, "Introspection") {
			t.Errorf("expected no introspection finding on disabled server, got: %+v", f)
		}
	}
}

// Burp's check is `0x00200514` (GraphQL content type not validated), and the
// browser's own rule is what makes it a finding: a cross-origin POST with
// `application/json` triggers a preflight and `text/plain` does not. The fixture
// therefore answers the same operation from the banned type, which is the only
// observable that separates "accepts anything" from "validates".
func TestGraphQLReportsAContentTypeItShouldHaveRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(bodyBytes), "__schema") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// The defect: the operation is answered whatever the content type said.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer server.Close()

	point := Point{URL: server.URL + "/graphql", Method: http.MethodPost, Origin: server.URL}
	findings := (GraphQL{}).Scan(context.Background(), mustTransport(t), point, nil)

	found := false
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Content Type Not Validated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no content-type row; findings = %+v", findings)
	}
}

// The control is a server that refuses the banned type. A validating endpoint
// answers an error, and reporting it would be reporting the server's own correct
// behaviour as a finding.
func TestGraphQLSilentWhenTheContentTypeIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			_, _ = io.WriteString(w, `{"errors":[{"message":"Unsupported content type"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer server.Close()

	point := Point{URL: server.URL + "/graphql", Method: http.MethodPost, Origin: server.URL}
	for _, finding := range (GraphQL{}).Scan(context.Background(), mustTransport(t), point, nil) {
		if strings.Contains(finding.Title, "Content Type Not Validated") {
			t.Fatalf("reported %q against a server that validates", finding.Title)
		}
	}
}
