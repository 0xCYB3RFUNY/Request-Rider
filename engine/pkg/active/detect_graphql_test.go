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
