package active

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OpenAPI probes for exposed Swagger and OpenAPI definitions.
// Corresponds to Burp Suite check:
// 0x00600900 (OpenAPI definition found)
type OpenAPI struct{}

// Name implements Module.
func (OpenAPI) Name() string { return "openapi" }

// Level implements Module.
func (OpenAPI) Level() Level { return LevelEndpoint }

// defaultOpenAPIPaths are well-known paths where OpenAPI/Swagger JSON specs are hosted.
var defaultOpenAPIPaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/v2/api-docs",
	"/v3/api-docs",
	"/api-docs",
	"/api/openapi.json",
	"/api/swagger.json",
	"/swagger/v1/swagger.json",
}

func (o OpenAPI) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if isPublicResource(p.URL) {
		return nil
	}
	parsed, err := url.Parse(p.URL)
	if err != nil {
		return nil
	}

	var targets []string
	lowerPath := strings.ToLower(parsed.Path)
	if strings.HasSuffix(lowerPath, "swagger.json") || strings.HasSuffix(lowerPath, "openapi.json") || strings.Contains(lowerPath, "api-docs") {
		targets = append(targets, p.URL)
	} else if parsed.Path == "" || parsed.Path == "/" {
		for _, path := range defaultOpenAPIPaths {
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
		if finding := o.probePath(ctx, t, p, targetURL); finding != nil {
			out = append(out, *finding)
		}
	}
	return out
}

func (o OpenAPI) probePath(ctx context.Context, t *Transport, p Point, targetURL string) *Finding {
	resp, err := t.Do(ctx, http.MethodGet, targetURL, nil, false, http.Header{
		"Accept": {"application/json, */*"},
	})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	// Must be JSON and contain OpenAPI or Swagger markers
	var doc struct {
		Swagger string                 `json:"swagger"`
		OpenAPI string                 `json:"openapi"`
		Info    map[string]interface{} `json:"info"`
		Paths   map[string]interface{} `json:"paths"`
	}

	if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
		return nil
	}

	specVersion := ""
	if doc.OpenAPI != "" {
		specVersion = "OpenAPI " + doc.OpenAPI
	} else if doc.Swagger != "" {
		specVersion = "Swagger " + doc.Swagger
	} else if len(doc.Paths) == 0 {
		return nil
	}

	title := "API Specification"
	if t, ok := doc.Info["title"].(string); ok && t != "" {
		title = t
	}

	endpointsCount := len(doc.Paths)
	evidence := fmt.Sprintf("Found %s: %q with %d paths declared.", specVersion, title, endpointsCount)
	if len(resp.Body) > 200 {
		evidence += "\n" + resp.Body[:200] + "..."
	} else {
		evidence += "\n" + resp.Body
	}

	finding, _ := NewFinding(Spec{
		Module:      "openapi",
		Title:       fmt.Sprintf("OpenAPI/Swagger Definition Found (%s)", specVersion),
		Claimed:     SeverityInfo,
		Tier:        TierVerified,
		Point:       Point{URL: targetURL, Method: http.MethodGet, Origin: p.Origin},
		Payload:     "GET " + targetURL,
		Evidence:    evidence,
		Description: "An OpenAPI/Swagger specification was discovered. It exposes full documentation of API routes, HTTP methods, parameters, authentication schemes, and internal models.",
		Remediation: "If the API documentation is not intended to be public, restrict access to authorized users or disable API definition endpoints in production.",
	})
	return &finding
}
