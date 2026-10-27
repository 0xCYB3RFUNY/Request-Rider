package active

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// GraphQL probes an endpoint or origin for exposed GraphQL interfaces,
// introspection enabled, field suggestions, and an endpoint that accepts a
// content type it should not.
// Corresponds to Burp Suite checks:
// 0x00200510 (GraphQL endpoint found)
// 0x00200512 (GraphQL introspection enabled)
// 0x00200513 (GraphQL suggestions enabled)
// 0x00200514 (GraphQL content type not validated)
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

	// Probe 3: Content type not validated (0x00200514)
	if finding := g.contentTypeProbe(ctx, t, p, targetURL, introQuery); finding != nil {
		out = append(out, *finding)
	}

	return out
}

// contentTypeProbe asks whether the endpoint executes a query that arrives with
// a content type it is not supposed to accept.
//
// Burp's check is `0x00200514` (GraphQL content type not validated). What makes
// it more than a spec pedantry is the browser's own rule: a cross-origin `POST`
// with `application/json` triggers a preflight, and a `text/plain` or
// `application/x-www-form-urlencoded` one does not. An endpoint that answers the
// same operation from either of those is an endpoint any page on the internet can
// drive with a form and no preflight — which turns introspection, and any
// mutation the visitor's session can reach, into a cross-site write.
//
// The measurement is the *same operation* arriving under the wrong type and
// still answering the schema, because a GraphQL server's own "you must use JSON"
// message is what a validating one says, and it is present in the response when
// the server is doing its job.
func (g GraphQL) contentTypeProbe(ctx context.Context, t *Transport, p Point, targetURL, query string) *Finding {
	accepted := make([]string, 0, 2)
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded"} {
		resp, err := t.DoBody(ctx, http.MethodPost, targetURL, []byte(query), contentType, false, http.Header{
			"Accept": {"application/json"},
		})
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.Body, "__schema") && strings.Contains(resp.Body, "queryType") {
			accepted = append(accepted, contentType)
		}
	}
	if len(accepted) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "graphql",
		Title:    "GraphQL Content Type Not Validated",
		Claimed:  SeverityMedium,
		Tier:     TierVerified,
		Point:    Point{URL: targetURL, Method: http.MethodPost, Origin: p.Origin},
		Payload:  query + "\nContent-Type: " + strings.Join(accepted, " / "),
		Evidence: "the introspection query answered identically under Content-Type: " + strings.Join(accepted, " and "),
		Description: "The GraphQL endpoint executed the operation it received with a Content-Type it " +
			"is not required to accept (" + strings.Join(accepted, ", ") + "). A browser does not " +
			"send a preflight for either of those, so a page on another origin can drive this " +
			"endpoint with a plain form, using whatever session the visitor already holds. " +
			"Introspection is the operation this run proved it with; a mutation is the one an " +
			"attacker would want.",
		Remediation: "Accept only `application/json` (and `application/graphql-response+json` for " +
			"the answer) and reject every other content type before the query is parsed. A " +
			"reverse proxy that enforces it is enough, because the browser cannot send the " +
			"banned types as a form without the endpoint answering them.",
	})
	return &finding
}
