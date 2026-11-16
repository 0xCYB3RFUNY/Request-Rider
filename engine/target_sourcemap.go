package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// sourceMapV3 represents the standard Source Map v3 schema (RFC / TC39).
type sourceMapV3 struct {
	Version        int      `json:"version"`
	File           string   `json:"file,omitempty"`
	SourceRoot     string   `json:"sourceRoot,omitempty"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
	Names          []string `json:"names,omitempty"`
	Mappings       string   `json:"mappings,omitempty"`
}

// jsSourceMap captures the results of Source Map detection, extraction, and AST analysis.
type jsSourceMap struct {
	URL                 string   `json:"url"`
	Resolved            string   `json:"resolved,omitempty"`
	Inline              bool     `json:"inline"`
	Sources             []string `json:"sources,omitempty"`
	SourcesCount        int      `json:"sources_count"`
	EndpointsDiscovered int      `json:"endpoints_discovered"`
	RoutesDiscovered    int      `json:"routes_discovered"`
	SensitiveFiles      []string `json:"sensitive_files,omitempty"`
}

// sourceMapAnalysisResult bundles what was extracted from a Source Map.
type sourceMapAnalysisResult struct {
	SourceMap *jsSourceMap
	Endpoints []jsEndpoint
	Routes    []jsRoute
	Findings  []jsFinding
	Links     []string
}

// sourceMappingURL patterns (line comments and block comments).
var (
	sourceMappingURLRegex      = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
	sourceMappingURLBlockRegex = regexp.MustCompile(`/\*[#@]\s*sourceMappingURL=([^\s*'"]+)\s*\*/`)

	// AST and framework route/call regexes for unminified source code.
	sourceMapExpressRouteRegex = regexp.MustCompile(`(?i)(?:app|router|server)\.(get|post|put|delete|patch|options|all|use)\s*\(\s*['"\x60](/[^'"\x60\s\)]+)['"\x60]`)
	sourceMapReactRouteRegex   = regexp.MustCompile(`(?i)(?:<Route|<NavLink)\s+[^>]*path\s*=\s*['"\x60](/[^'"\x60\s]+)['"\x60]`)
	sourceMapObjectRouteRegex  = regexp.MustCompile(`(?i)\bpath\s*:\s*['"\x60](/[^'"\x60\s]+)['"\x60]`)
	sourceMapHTTPClientRegex   = regexp.MustCompile(`(?i)(?:fetch|axios(?:\.(get|post|put|delete|patch))?|\$\.(get|post|ajax)|http\.(get|post|put|delete))\s*\(\s*['"\x60](/[^'"\x60\s]+)['"\x60]`)
	sourceMapAPIPathRegex      = regexp.MustCompile(`['"\x60](/(?:api|v[0-9]+|internal|admin|auth|oauth|debug|management|webhook|graphql|users?|account|payment)[^'"\x60\s\?\(\)]*)['"\x60]`)
)

// sensitivePathKeywords identifies paths that disclose internal architectures or credentials.
var sensitivePathKeywords = []string{
	"admin", "internal", "secret", "auth", "token", "config", ".env",
	"dashboard", "metrics", "debug", "management", "backoffice",
	"credential", "password", "private", "oauth", "saml", "jwt",
}

// detectSourceMappingURL extracts the sourceMappingURL from a JavaScript body if present.
func detectSourceMappingURL(body []byte) (rawURL string, isInline bool, inlinePayload []byte, found bool) {
	if len(body) == 0 {
		return "", false, nil, false
	}

	// 1. Line comment check: //# sourceMappingURL=...
	if match := sourceMappingURLRegex.FindSubmatch(body); len(match) > 1 {
		rawURL = strings.TrimSpace(string(match[1]))
		found = true
	} else if match := sourceMappingURLBlockRegex.FindSubmatch(body); len(match) > 1 {
		// 2. Block comment check: /*# sourceMappingURL=... */
		rawURL = strings.TrimSpace(string(match[1]))
		found = true
	}

	if !found {
		return "", false, nil, false
	}

	// Check if inline Data URI
	if strings.HasPrefix(rawURL, "data:") {
		isInline = true
		payload := extractDataURIPayload(rawURL)
		if len(payload) > 0 {
			inlinePayload = payload
		}
	}

	return rawURL, isInline, inlinePayload, true
}

// extractDataURIPayload decodes base64 or URL-encoded Data URI payload.
func extractDataURIPayload(dataURI string) []byte {
	commaIdx := strings.Index(dataURI, ",")
	if commaIdx == -1 {
		return nil
	}
	header := dataURI[:commaIdx]
	data := dataURI[commaIdx+1:]

	if strings.Contains(header, ";base64") {
		// Base64 encoded
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err == nil {
			return decoded
		}
		// Try raw (unpadded) base64
		decoded, err = base64.RawStdEncoding.DecodeString(data)
		if err == nil {
			return decoded
		}
	} else {
		// URL-encoded or plain
		unescaped, err := url.QueryUnescape(data)
		if err == nil {
			return []byte(unescaped)
		}
		return []byte(data)
	}
	return nil
}

// parseSourceMapJSON parses raw JSON into a sourceMapV3 struct.
func parseSourceMapJSON(data []byte) (*sourceMapV3, error) {
	var sm sourceMapV3
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, err
	}
	if sm.Version != 3 && len(sm.Sources) == 0 {
		return nil, fmt.Errorf("not a valid source map v3 (version=%d, sources=%d)", sm.Version, len(sm.Sources))
	}
	return &sm, nil
}

// cleanSourcePath sanitizes source file paths by stripping compiler/bundler prefixes.
func cleanSourcePath(p string) string {
	p = strings.TrimSpace(p)
	prefixes := []string{
		"webpack:///", "webpack://",
		"vite:///", "vite://",
		"turbopack:///", "turbopack://",
		"file:///", "file://",
		"./", "../", "~/",
	}
	for {
		stripped := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(p, prefix) {
				p = strings.TrimPrefix(p, prefix)
				stripped = true
			}
		}
		if !stripped {
			break
		}
	}
	return strings.TrimLeft(p, "/")
}

// isSensitiveSourcePath determines whether an original source file path warrants attention.
func isSensitiveSourcePath(p string) bool {
	lower := strings.ToLower(p)
	for _, kw := range sensitivePathKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isNodeModulesSource reports whether a source path belongs to a third-party dependency.
func isNodeModulesSource(p string) bool {
	lower := strings.ToLower(p)
	return strings.Contains(lower, "node_modules/") || strings.Contains(lower, "vendor/")
}

// extractRoutesFromSourcePath extracts potential routes from Next.js / framework conventions.
func extractRoutesFromSourcePath(sourcePath string) []string {
	cleaned := cleanSourcePath(sourcePath)
	var routes []string

	// Next.js Pages router: pages/admin/users.tsx -> /admin/users
	if idx := strings.Index(cleaned, "pages/"); idx != -1 {
		sub := cleaned[idx+len("pages/"):]
		// Strip extension (.tsx, .jsx, .ts, .js)
		if dot := strings.LastIndex(sub, "."); dot != -1 {
			sub = sub[:dot]
		}
		if sub == "index" {
			routes = append(routes, "/")
		} else if strings.HasSuffix(sub, "/index") {
			routes = append(routes, "/"+strings.TrimSuffix(sub, "/index"))
		} else {
			routes = append(routes, "/"+sub)
		}
	}

	// Next.js App router: app/admin/settings/page.tsx -> /admin/settings
	// app/api/auth/route.ts -> /api/auth
	if idx := strings.Index(cleaned, "app/"); idx != -1 {
		sub := cleaned[idx+len("app/"):]
		if strings.HasSuffix(sub, "/page.tsx") || strings.HasSuffix(sub, "/page.jsx") ||
			strings.HasSuffix(sub, "/page.ts") || strings.HasSuffix(sub, "/page.js") {
			route := sub[:strings.LastIndex(sub, "/page.")]
			routes = append(routes, "/"+route)
		} else if strings.HasSuffix(sub, "/route.ts") || strings.HasSuffix(sub, "/route.js") {
			route := sub[:strings.LastIndex(sub, "/route.")]
			routes = append(routes, "/"+route)
		}
	}

	return routes
}

// extractEndpointsAndRoutesFromContent parses unminified JavaScript/TypeScript source code.
func extractEndpointsAndRoutesFromContent(sourceFile, content string, base *url.URL) (endpoints []jsEndpoint, routes []jsRoute, findings []jsFinding) {
	lines := strings.Split(content, "\n")
	seenEndpoints := make(map[string]bool)
	seenRoutes := make(map[string]bool)
	byPath := make(map[string]int)

	addEndpoint := func(rawPath, method, callType string, lineNum int) {
		rawPath = strings.TrimSpace(rawPath)
		if rawPath == "" || strings.Contains(rawPath, "${") {
			return
		}
		// Split query params
		parsedPath := rawPath
		var queryParams []string
		if qIdx := strings.Index(rawPath, "?"); qIdx != -1 {
			parsedPath = rawPath[:qIdx]
			qStr := rawPath[qIdx+1:]
			for _, pair := range strings.Split(qStr, "&") {
				if k, _, found := strings.Cut(pair, "="); found && k != "" {
					queryParams = append(queryParams, k)
				} else if pair != "" {
					queryParams = append(queryParams, pair)
				}
			}
		}

		if existingIdx, exists := byPath[parsedPath]; exists {
			if method != "" && endpoints[existingIdx].Method == "" {
				endpoints[existingIdx].Method = strings.ToUpper(method)
				endpoints[existingIdx].URL = rawPath
				if len(queryParams) > 0 && len(endpoints[existingIdx].Query) == 0 {
					endpoints[existingIdx].Query = queryParams
				}
				return
			}
			if method == "" || endpoints[existingIdx].Method == strings.ToUpper(method) {
				return
			}
		}

		key := method + " " + parsedPath
		if seenEndpoints[key] {
			return
		}
		seenEndpoints[key] = true

		resolved := ""
		if base != nil {
			if relURL, err := url.Parse(rawPath); err == nil {
				resolved = base.ResolveReference(relURL).String()
			}
		}

		endpoint := jsEndpoint{
			URL:      rawPath,
			Method:   strings.ToUpper(method),
			Types:    []string{"sourcemap"},
			Query:    queryParams,
			Resolved: resolved,
		}
		byPath[parsedPath] = len(endpoints)
		endpoints = append(endpoints, endpoint)

		if !seenRoutes[parsedPath] {
			seenRoutes[parsedPath] = true
			routes = append(routes, jsRoute{
				Route:    parsedPath,
				Source:   "sourcemap:" + callType,
				Line:     lineNum,
				Resolved: resolved,
			})
		}
	}

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1

		// 1. Express / Router: app.get('/api/users')
		for _, m := range sourceMapExpressRouteRegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 2 {
				method := strings.ToUpper(m[1])
				path := m[2]
				addEndpoint(path, method, "router", lineNum)
			}
		}

		// 2. React Router: <Route path="/admin" />
		for _, m := range sourceMapReactRouteRegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				addEndpoint(m[1], "GET", "react_route", lineNum)
			}
		}

		// 3. Object router: path: "/settings"
		for _, m := range sourceMapObjectRouteRegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				addEndpoint(m[1], "GET", "object_route", lineNum)
			}
		}

		// 4. HTTP Clients: fetch('/api/v1/auth')
		for _, m := range sourceMapHTTPClientRegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 4 {
				path := m[4]
				method := "GET"
				if m[1] != "" {
					method = m[1]
				} else if m[2] != "" {
					method = m[2]
				} else if m[3] != "" {
					method = m[3]
				}
				addEndpoint(path, method, "client", lineNum)
			}
		}

		// 5. API Path Literals: "/api/internal/debug"
		for _, m := range sourceMapAPIPathRegex.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				addEndpoint(m[1], "", "path_literal", lineNum)
			}
		}
	}

	return endpoints, routes, findings
}

// analyzeSourceMap unpacks and extracts project structure, routes, and endpoints from a source map.
func analyzeSourceMap(pageURL string, sm *sourceMapV3, base *url.URL) sourceMapAnalysisResult {
	result := sourceMapAnalysisResult{
		SourceMap: &jsSourceMap{
			URL:                 pageURL,
			SourcesCount:        len(sm.Sources),
			EndpointsDiscovered: 0,
			RoutesDiscovered:    0,
			Sources:             []string{},
			SensitiveFiles:      []string{},
		},
		Endpoints: []jsEndpoint{},
		Routes:    []jsRoute{},
		Findings:  []jsFinding{},
		Links:     []string{},
	}

	seenEndpoints := make(map[string]bool)
	seenRoutes := make(map[string]bool)
	seenLinks := make(map[string]bool)
	var sensitiveFiles []string

	// 1. Process sources list and detect sensitive source paths
	for _, rawSource := range sm.Sources {
		cleaned := cleanSourcePath(rawSource)
		if cleaned == "" {
			continue
		}
		result.SourceMap.Sources = append(result.SourceMap.Sources, cleaned)

		if isSensitiveSourcePath(cleaned) && !isNodeModulesSource(cleaned) {
			sensitiveFiles = append(sensitiveFiles, cleaned)
			// Report sensitive project file disclosure
			result.Findings = append(result.Findings, jsFinding{
				Kind:     jsFindingSourceMapFile,
				Severity: jsSeverityMedium,
				Subject:  cleaned,
				Evidence: "source map project file: " + cleaned,
				Line:     0,
				Count:    1,
			})
		}

		// Extract routes from convention
		for _, convRoute := range extractRoutesFromSourcePath(cleaned) {
			if !seenRoutes[convRoute] {
				seenRoutes[convRoute] = true
				resolved := convRoute
				if base != nil {
					if relURL, err := url.Parse(convRoute); err == nil {
						resolved = base.ResolveReference(relURL).String()
					}
				}
				result.Routes = append(result.Routes, jsRoute{
					Route:    convRoute,
					Source:   "sourcemap:convention",
					Line:     0,
					Resolved: resolved,
				})
				if !seenEndpoints["GET "+convRoute] {
					seenEndpoints["GET "+convRoute] = true
					result.Endpoints = append(result.Endpoints, jsEndpoint{
						URL:      convRoute,
						Method:   "GET",
						Types:    []string{"sourcemap"},
						Resolved: resolved,
					})
				}
				if isCleanFrontierRoute(convRoute) {
					seenLinks[resolved] = true
				}
			}
		}
	}
	result.SourceMap.SensitiveFiles = sensitiveFiles

	// 2. Process sourcesContent if present
	if len(sm.SourcesContent) > 0 {
		for idx, content := range sm.SourcesContent {
			if content == "" {
				continue
			}
			sourceFile := "source"
			if idx < len(sm.Sources) {
				sourceFile = sm.Sources[idx]
			}

			eps, rts, fds := extractEndpointsAndRoutesFromContent(sourceFile, content, base)
			for _, ep := range eps {
				key := ep.Method + " " + ep.URL
				if !seenEndpoints[key] {
					seenEndpoints[key] = true
					result.Endpoints = append(result.Endpoints, ep)
					if isCleanFrontierRoute(ep.URL) && ep.Resolved != "" {
						seenLinks[ep.Resolved] = true
					}
				}
			}
			for _, rt := range rts {
				if !seenRoutes[rt.Route] {
					seenRoutes[rt.Route] = true
					result.Routes = append(result.Routes, rt)
				}
			}
			result.Findings = append(result.Findings, fds...)
		}
	}

	// 3. Assemble crawl frontier links
	for link := range seenLinks {
		result.Links = append(result.Links, link)
	}
	sort.Strings(result.Links)

	result.SourceMap.EndpointsDiscovered = len(result.Endpoints)
	result.SourceMap.RoutesDiscovered = len(result.Routes)

	// Report overall Source Map disclosure finding
	severity := jsSeverityInfo
	if len(sensitiveFiles) > 0 || len(result.Endpoints) > 0 {
		severity = jsSeverityMedium
	}
	result.Findings = append(result.Findings, jsFinding{
		Kind:     jsFindingSourceMap,
		Severity: severity,
		Subject:  "source_map",
		Evidence: fmt.Sprintf("Source map contains %d sources, %d endpoints, %d sensitive files",
			len(sm.Sources), len(result.Endpoints), len(sensitiveFiles)),
		Line:  0,
		Count: 1,
	})

	return result
}

// isCleanFrontierRoute checks if a discovered path is suitable for the crawl frontier.
func isCleanFrontierRoute(path string) bool {
	if strings.HasPrefix(path, "/") &&
		!strings.Contains(path, ":") &&
		!strings.Contains(path, "[") &&
		!strings.Contains(path, "{") &&
		!strings.Contains(path, "*") &&
		!strings.Contains(path, "EXPR") {
		return true
	}
	return false
}

// isDirectSourceMapJSON checks if the raw bytes form a source map v3 directly.
func isDirectSourceMapJSON(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return false
	}
	return bytes.Contains(trimmed, []byte(`"version"`)) &&
		bytes.Contains(trimmed, []byte(`"sources"`))
}
