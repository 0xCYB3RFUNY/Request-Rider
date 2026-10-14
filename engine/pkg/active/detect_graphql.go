package active

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// GraphQL probes an endpoint or origin for exposed GraphQL interfaces,
// introspection enabled, and field suggestions.
// Corresponds to Burp Suite checks:
// 0x00200510 (GraphQL endpoint found)
// 0x00200512 (GraphQL introspection enabled)
// 0x00200513 (GraphQL suggestions enabled)
type GraphQL struct{}

// Name implements Module.
func (GraphQL) Name() string { return "graphql" }

// Level implements Module.
func (GraphQL) Level() Level { return LevelEndpoint }

// defaultGraphQLPaths are paths commonly used for GraphQL endpoints.
var defaultGraphQLPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/gql",
	"/query",
}

func (g GraphQL) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if isPublicResource(p.URL) {
		return nil
	}
	parsed, err := url.Parse(p.URL)
	if err != nil {
		return nil
	}

	var targets []string
	lowerPath := strings.ToLower(parsed.Path)
	if strings.Contains(lowerPath, "graphql") || strings.Contains(lowerPath, "gql") {
		targets = append(targets, p.URL)
	} else if parsed.Path == "" || parsed.Path == "/" {
		for _, path := range defaultGraphQLPaths {
			u := *parsed
			u.Path = path
			u.RawQuery = ""
			targets = append(targets, u.String())
		}
	} else {
		return nil
	}

	var out []Finding
	for _, targetURL := range targets {
		findings := g.probeEndpoint(ctx, t, p, targetURL)
		out = append(out, findings...)
	}
	return out
}

func (g GraphQL) probeEndpoint(ctx context.Context, t *Transport, p Point, targetURL string) []Finding {
	var out []Finding

	// Probe 1: Introspection query
	introQuery := `{"query":"query Introspect{__schema{queryType{name}types{name}}}"}`
	resp, err := t.DoBody(ctx, http.MethodPost, targetURL, []byte(introQuery), "application/json", false, http.Header{
		"Accept": {"application/json"},
	})
	if err != nil || resp == nil {
		return nil
	}

	// Check if this is a GraphQL endpoint
	isGQL := strings.Contains(resp.Body, "__schema") ||
		strings.Contains(resp.Body, "GraphQL") ||
		strings.Contains(resp.Body, "Must provide query string") ||
		strings.Contains(resp.Body, "Syntax Error") ||
		strings.Contains(resp.Body, "Cannot query field")

	if !isGQL {
		return nil
	}

	// 1. Introspection Enabled (0x00200512)
	if strings.Contains(resp.Body, "__schema") && strings.Contains(resp.Body, "queryType") {
		evidence := resp.Body
		if len(evidence) > 200 {
			evidence = evidence[:200] + "..."
		}
		finding, _ := NewFinding(Spec{
			Module:      "graphql",
			Title:       "GraphQL Introspection Enabled",
			Claimed:     SeverityLow,
			Tier:        TierVerified,
			Point:       Point{URL: targetURL, Method: http.MethodPost, Origin: p.Origin},
			Payload:     introQuery,
			Evidence:    evidence,
			Description: "The GraphQL endpoint answered a full schema introspection query. Introspection reveals the complete data model, types, fields, queries, and mutations available to attackers.",
			Remediation: "Disable GraphQL introspection in production environments (e.g. Apollo Server introspection: false, graphql-js validationRules).",
		})
		out = append(out, finding)
	}

	// Probe 2: Field Suggestions Enabled (0x00200513)
	suggestQuery := `{"query":"query SuggestCheck{__nonExistentFieldXYZ}"}`
	respSug, err := t.DoBody(ctx, http.MethodPost, targetURL, []byte(suggestQuery), "application/json", false, http.Header{
		"Accept": {"application/json"},
	})
	if err == nil && respSug != nil {
		if strings.Contains(respSug.Body, "Did you mean") {
			evidence := respSug.Body
			if len(evidence) > 200 {
				evidence = evidence[:200] + "..."
			}
			finding, _ := NewFinding(Spec{
				Module:      "graphql",
				Title:       "GraphQL Field Suggestions Enabled",
				Claimed:     SeverityInfo,
				Tier:        TierVerified,
				Point:       Point{URL: targetURL, Method: http.MethodPost, Origin: p.Origin},
				Payload:     suggestQuery,
				Evidence:    evidence,
				Description: "The GraphQL endpoint suggests valid field names when an invalid field is queried (\"Did you mean ...\"). This assists attackers in brute-forcing hidden schema elements even when introspection is disabled.",
				Remediation: "Disable field suggestions in production error formatters or use a reverse proxy to sanitize GraphQL error responses.",
			})
			out = append(out, finding)
		}
	}

	return out
}
