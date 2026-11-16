package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestDetectSourceMappingURL verifies detection of line comments, block comments, and inline Data URIs.
func TestDetectSourceMappingURL(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantURL       string
		wantInline    bool
		wantFound     bool
		wantPayloadSub string
	}{
		{
			name:       "empty body",
			body:       "",
			wantFound:  false,
		},
		{
			name:       "plain javascript without sourcemap",
			body:       "console.log('hello world');",
			wantFound:  false,
		},
		{
			name:       "standard line comment",
			body:       "var a = 1;\n//# sourceMappingURL=bundle.js.map\n",
			wantURL:    "bundle.js.map",
			wantInline: false,
			wantFound:  true,
		},
		{
			name:       "legacy @ line comment",
			body:       "var a = 1;\n//@ sourceMappingURL=/static/app.min.js.map",
			wantURL:    "/static/app.min.js.map",
			wantInline: false,
			wantFound:  true,
		},
		{
			name:       "block comment",
			body:       "var b = 2; /*# sourceMappingURL=main.chunk.js.map */",
			wantURL:    "main.chunk.js.map",
			wantInline: false,
			wantFound:  true,
		},
		{
			name: "inline base64 data uri",
			body: fmt.Sprintf("var c = 3;\n//# sourceMappingURL=data:application/json;base64,%s",
				base64.StdEncoding.EncodeToString([]byte(`{"version":3,"sources":["src/index.ts"]}`))),
			wantInline:     true,
			wantFound:      true,
			wantPayloadSub: `"version":3`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawURL, isInline, payload, found := detectSourceMappingURL([]byte(tc.body))
			if found != tc.wantFound {
				t.Fatalf("detectSourceMappingURL() found = %v, want %v", found, tc.wantFound)
			}
			if !tc.wantFound {
				return
			}
			if tc.wantURL != "" && rawURL != tc.wantURL {
				t.Errorf("rawURL = %q, want %q", rawURL, tc.wantURL)
			}
			if isInline != tc.wantInline {
				t.Errorf("isInline = %v, want %v", isInline, tc.wantInline)
			}
			if tc.wantPayloadSub != "" && !strings.Contains(string(payload), tc.wantPayloadSub) {
				t.Errorf("payload %q does not contain %q", string(payload), tc.wantPayloadSub)
			}
		})
	}
}

// TestParseSourceMapJSON validates parsing valid and invalid source map v3 json payloads.
func TestParseSourceMapJSON(t *testing.T) {
	valid := `{"version":3,"file":"out.js","sources":["webpack:///src/app.tsx"],"sourcesContent":["export const a = 1;"]}`
	sm, err := parseSourceMapJSON([]byte(valid))
	if err != nil {
		t.Fatalf("unexpected error parsing valid source map: %v", err)
	}
	if sm.Version != 3 || len(sm.Sources) != 1 || len(sm.SourcesContent) != 1 {
		t.Fatalf("parsed source map invalid: %+v", sm)
	}

	invalid := `{"version":2,"sources":[]}`
	if _, err := parseSourceMapJSON([]byte(invalid)); err == nil {
		t.Fatal("expected error parsing non-v3 empty source map, got nil")
	}
}

// TestCleanSourcePath verifies stripping bundler artifacts from original source paths.
func TestCleanSourcePath(t *testing.T) {
	cases := map[string]string{
		"webpack:///src/components/Admin.tsx":  "src/components/Admin.tsx",
		"vite://app/src/api/auth.ts":           "app/src/api/auth.ts",
		"turbopack:///pages/admin/users.tsx":   "pages/admin/users.tsx",
		"../../src/config/secrets.js":          "src/config/secrets.js",
		"./src/index.js":                       "src/index.js",
		"~/lib/db.ts":                          "lib/db.ts",
	}
	for input, want := range cases {
		got := cleanSourcePath(input)
		if got != want {
			t.Errorf("cleanSourcePath(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestExtractRoutesFromSourcePath verifies convention-based route extraction from Next.js paths.
func TestExtractRoutesFromSourcePath(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"webpack:///src/pages/index.tsx", []string{"/"}},
		{"webpack:///src/pages/admin/dashboard.tsx", []string{"/admin/dashboard"}},
		{"webpack:///src/pages/api/v1/auth/login.ts", []string{"/api/v1/auth/login"}},
		{"webpack:///src/app/management/tokens/page.tsx", []string{"/management/tokens"}},
		{"webpack:///src/app/api/webhooks/stripe/route.ts", []string{"/api/webhooks/stripe"}},
	}

	for _, tc := range cases {
		routes := extractRoutesFromSourcePath(tc.path)
		if len(routes) != len(tc.want) {
			t.Fatalf("extractRoutesFromSourcePath(%q) = %v, want %v", tc.path, routes, tc.want)
		}
		for i, w := range tc.want {
			if routes[i] != w {
				t.Errorf("extractRoutesFromSourcePath(%q)[%d] = %q, want %q", tc.path, i, routes[i], w)
			}
		}
	}
}

// TestExtractEndpointsAndRoutesFromContent verifies AST/regex extraction from unminified sources.
func TestExtractEndpointsAndRoutesFromContent(t *testing.T) {
	sourceCode := `
import axios from 'axios';

// Express routes
router.get('/api/internal/stats', handleStats);
app.post('/api/v2/users/create', handleCreate);

// React router
const Routes = () => (
    <Route path="/admin/settings" element={<AdminSettings />} />
);

// Fetch & Axios calls
export async function loadUserData(userId) {
    const res = await fetch('/api/v1/user/profile?id=123&token=abc');
    return axios.post('/api/auth/refresh');
}

// Internal constant
const DEBUG_ENDPOINT = "/api/debug/dump";
`
	baseURL, _ := url.Parse("https://app.example.com/assets/app.js")
	endpoints, routes, _ := extractEndpointsAndRoutesFromContent("src/api/client.ts", sourceCode, baseURL)

	expectedEndpoints := map[string]string{
		"/api/internal/stats":      "GET",
		"/api/v2/users/create":     "POST",
		"/admin/settings":          "GET",
		"/api/v1/user/profile":     "GET",
		"/api/auth/refresh":        "POST",
		"/api/debug/dump":          "",
	}

	for path, method := range expectedEndpoints {
		found := false
		for _, ep := range endpoints {
			if strings.HasPrefix(ep.URL, path) {
				found = true
				if method != "" && ep.Method != method {
					t.Errorf("endpoint %q method = %q, want %q", ep.URL, ep.Method, method)
				}
				if ep.Resolved == "" || !strings.HasPrefix(ep.Resolved, "https://app.example.com") {
					t.Errorf("endpoint %q resolved %q invalid", ep.URL, ep.Resolved)
				}
			}
		}
		if !found {
			t.Errorf("expected endpoint %q not found in extracted endpoints: %+v", path, endpoints)
		}
	}

	// Verify query params extracted for /api/v1/user/profile?id=123&token=abc
	for _, ep := range endpoints {
		if strings.HasPrefix(ep.URL, "/api/v1/user/profile") {
			if len(ep.Query) < 2 {
				t.Errorf("query params not extracted: %+v", ep.Query)
			}
		}
	}

	if len(routes) < 5 {
		t.Errorf("expected at least 5 routes, got %d", len(routes))
	}
}

// TestAnalyzeSourceMapEndToEnd verifies full source map analysis including sensitive file discovery.
func TestAnalyzeSourceMapEndToEnd(t *testing.T) {
	sm := &sourceMapV3{
		Version: 3,
		Sources: []string{
			"webpack:///src/config/.env.production",
			"webpack:///src/admin/authController.ts",
			"webpack:///src/pages/admin/keys.tsx",
			"webpack:///node_modules/react/index.js",
		},
		SourcesContent: []string{
			`DATABASE_URL="postgres://admin:secret@db.internal:5432/main"`,
			`router.post('/api/admin/rotate-keys', (req, res) => {});`,
			`export default function KeysPage() { return fetch('/api/keys/list'); }`,
			`module.exports = React;`,
		},
	}

	baseURL, _ := url.Parse("https://target.corp/static/bundle.js")
	result := analyzeSourceMap("https://target.corp/static/bundle.js", sm, baseURL)

	if result.SourceMap == nil {
		t.Fatal("result.SourceMap is nil")
	}
	if result.SourceMap.SourcesCount != 4 {
		t.Errorf("SourcesCount = %d, want 4", result.SourceMap.SourcesCount)
	}

	// Check sensitive files identified
	if len(result.SourceMap.SensitiveFiles) < 2 {
		t.Errorf("expected sensitive files (.env, admin), got: %v", result.SourceMap.SensitiveFiles)
	}

	// Check endpoints extracted
	foundRotate := false
	foundKeys := false
	for _, ep := range result.Endpoints {
		if ep.URL == "/api/admin/rotate-keys" {
			foundRotate = true
		}
		if ep.URL == "/api/keys/list" {
			foundKeys = true
		}
	}
	if !foundRotate || !foundKeys {
		t.Errorf("missing extracted endpoints from sourcesContent: %+v", result.Endpoints)
	}

	// Check findings include source_map and source_map_file
	hasSMFinding := false
	hasFileFinding := false
	for _, fd := range result.Findings {
		if fd.Kind == jsFindingSourceMap {
			hasSMFinding = true
		}
		if fd.Kind == jsFindingSourceMapFile {
			hasFileFinding = true
		}
	}
	if !hasSMFinding {
		t.Error("missing jsFindingSourceMap finding")
	}
	if !hasFileFinding {
		t.Error("missing jsFindingSourceMapFile finding")
	}

	// Check links joined crawl frontier
	if len(result.Links) == 0 {
		t.Error("expected frontier links from clean discovered routes, got none")
	}
}

// TestAnalyzeJavaScriptWithInlineSourceMap verifies analyzeJavaScript end-to-end with an inline Data URI source map.
func TestAnalyzeJavaScriptWithInlineSourceMap(t *testing.T) {
	smJSON := `{"version":3,"sources":["src/api/internal.ts"],"sourcesContent":["fetch('/api/v3/internal/status');"]}`
	encodedSM := base64.StdEncoding.EncodeToString([]byte(smJSON))

	jsBody := fmt.Sprintf(`
var app = true;
fetch('/api/v1/public');
//# sourceMappingURL=data:application/json;base64,%s
`, encodedSM)

	analysis := analyzeJavaScript("https://example.com/app.min.js", []byte(jsBody))

	if analysis.SourceMap == nil {
		t.Fatal("analysis.SourceMap is nil for inline source map")
	}
	if !analysis.SourceMap.Inline {
		t.Error("analysis.SourceMap.Inline should be true")
	}
	if analysis.SourceMap.EndpointsDiscovered == 0 {
		t.Error("analysis.SourceMap.EndpointsDiscovered should be > 0")
	}

	// Check both public endpoint from minified code and internal endpoint from source map exist
	hasPublic := false
	hasInternal := false
	for _, ep := range analysis.Endpoints {
		if ep.URL == "/api/v1/public" {
			hasPublic = true
		}
		if ep.URL == "/api/v3/internal/status" {
			hasInternal = true
			if len(ep.Types) == 0 || ep.Types[0] != "sourcemap" {
				t.Errorf("expected sourcemap type for internal endpoint, got: %v", ep.Types)
			}
		}
	}

	if !hasPublic {
		t.Error("missing public endpoint from JS body")
	}
	if !hasInternal {
		t.Error("missing internal endpoint from source map sourcesContent")
	}

	// Check that the internal endpoint was added to the crawl frontier (analysis.links)
	hasInternalLink := false
	for _, link := range analysis.links {
		if strings.Contains(link, "/api/v3/internal/status") {
			hasInternalLink = true
		}
	}
	if !hasInternalLink {
		t.Errorf("crawl frontier links missing internal endpoint: %v", analysis.links)
	}
}

// TestAnalyzeJavaScriptWithDirectSourceMapFile verifies analyzing a .map file directly.
func TestAnalyzeJavaScriptWithDirectSourceMapFile(t *testing.T) {
	smJSON := []byte(`{
		"version": 3,
		"file": "bundle.js",
		"sources": ["webpack:///src/routes/admin.ts"],
		"sourcesContent": ["router.get('/admin/management/dashboard', handler);"]
	}`)

	analysis := analyzeJavaScript("https://example.com/bundle.js.map", smJSON)

	if analysis.SourceMap == nil {
		t.Fatal("expected analysis.SourceMap for direct .map file, got nil")
	}
	if len(analysis.Endpoints) == 0 {
		t.Fatal("expected discovered endpoints in direct .map analysis")
	}
	if analysis.Endpoints[0].URL != "/admin/management/dashboard" {
		t.Errorf("endpoint = %q, want %q", analysis.Endpoints[0].URL, "/admin/management/dashboard")
	}
}
