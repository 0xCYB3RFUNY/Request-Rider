package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	maxTransformResponseBytes = envLimit("RR_OSINT_MAX_TRANSFORM_RESPONSE_BYTES", 1<<20)
	maxSubdomainResults       = envLimit("RR_OSINT_MAX_SUBDOMAIN_RESULTS", 200)
	maxDNSWords               = envLimit("RR_OSINT_MAX_DNS_WORDS", 100)
	maxGitHubResponseBytes    = envLimit("RR_OSINT_MAX_GITHUB_RESPONSE_BYTES", 256<<10)
)

type osintTransformInput struct {
	Transform      string                 `json:"transform"`
	Value          string                 `json:"value"`
	Options        map[string]interface{} `json:"options"`
	ConfirmNetwork bool                   `json:"confirm_network"`
}

type transformEntity struct {
	Type       string                 `json:"type"`
	Identity   string                 `json:"identity"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Provenance map[string]interface{} `json:"provenance,omitempty"`
}

type transformRelation struct {
	Type       string                 `json:"type"`
	SourceType string                 `json:"source_type"`
	Source     string                 `json:"source"`
	TargetType string                 `json:"target_type"`
	Target     string                 `json:"target"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Provenance map[string]interface{} `json:"provenance,omitempty"`
}

type osintTransformResult struct {
	Transform   string                 `json:"transform"`
	ObservedAt  string                 `json:"observed_at"`
	LocalOnly   bool                   `json:"local_only"`
	NetworkUsed bool                   `json:"network_used"`
	Entities    []transformEntity      `json:"entities"`
	Relations   []transformRelation    `json:"relations"`
	Warnings    []string               `json:"warnings"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var githubUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}$`)

var transformRegistry = []map[string]interface{}{
	{"id": "email_recon", "network": false, "description": "Local email normalization and domain expansion; no mass profile enumeration."},
	{"id": "username_enum", "network": false, "description": "Local username normalization; external platform enumeration is intentionally disabled."},
	{"id": "ip_geo", "network": false, "description": "Local IP normalization with optional environment-only GeoIP JSON database."},
	{"id": "email_domain", "network": false, "description": "Extract the normalized domain from an email address."},
	{"id": "username_normalize", "network": false, "description": "Normalize a username for graph correlation."},
	{"id": "domain_normalize", "network": false, "description": "Normalize a domain identity without network access."},
	{"id": "url_host", "network": false, "description": "Extract a host entity from an HTTP(S) URL."},
	{"id": "reverse_dns", "network": true, "description": "Resolve PTR names for an IP; explicit confirmation required."},
	{"id": "dns_records", "network": true, "description": "Resolve A/AAAA records for a domain; explicit confirmation required."},
	{"id": "subdomains", "network": true, "description": "Bounded crt.sh and DNS transform; requires explicit network confirmation."},
	{"id": "github_recon", "network": true, "description": "Bounded public GitHub profile lookup; requires explicit network confirmation."},
	{"id": "wayback_urls", "network": true, "description": "Query public archive indexes for URLs; explicit confirmation required."},
	{"id": "s3_buckets", "network": true, "description": "Check a bounded, user-supplied bucket candidate list; explicit confirmation required."},
}

func transformError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
}

func validateTransformValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 {
		return ""
	}
	for _, character := range value {
		if character < 32 && character != '\t' {
			return ""
		}
	}
	return value
}

func entity(transformType, identity string, properties, provenance map[string]interface{}) transformEntity {
	if properties == nil {
		properties = map[string]interface{}{}
	}
	if provenance == nil {
		provenance = map[string]interface{}{}
	}
	return transformEntity{Type: transformType, Identity: identity, Properties: properties, Provenance: provenance}
}

func (s *server) osintTransformRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": transformRegistry})
}

func (s *server) osintTransform(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input osintTransformInput
	decoder := json.NewDecoder(io.LimitReader(r.Body, int64(maxTransformResponseBytes)))
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OSINT_TRANSFORM", err)
		return
	}
	input.Transform = strings.ToLower(strings.TrimSpace(input.Transform))
	input.Value = validateTransformValue(input.Value)
	if input.Value == "" {
		writeError(w, http.StatusBadRequest, "INVALID_OSINT_TRANSFORM", transformError("INVALID_VALUE", "transform value is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.runOSINTTransform(ctx, input)
	if err != nil {
		code := "OSINT_TRANSFORM_FAILED"
		if strings.HasPrefix(err.Error(), "NETWORK_CONFIRMATION_REQUIRED:") {
			code = "NETWORK_CONFIRMATION_REQUIRED"
		}
		writeError(w, http.StatusBadRequest, code, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) runOSINTTransform(ctx context.Context, input osintTransformInput) (osintTransformResult, error) {
	result := osintTransformResult{
		Transform:  input.Transform,
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		LocalOnly:  true,
		Entities:   []transformEntity{},
		Relations:  []transformRelation{},
		Warnings:   []string{},
	}
	var err error
	switch input.Transform {
	case "email_recon":
		err = runEmailRecon(&result, input.Value)
	case "username_enum":
		err = runUsernameEnum(&result, input.Value)
	case "ip_geo":
		err = runIPGeo(&result, input.Value)
	case "email_domain":
		err = runEmailDomain(&result, input.Value)
	case "username_normalize":
		err = runUsernameEnum(&result, input.Value)
	case "domain_normalize":
		err = runDomainNormalize(&result, input.Value)
	case "url_host":
		err = runURLHost(&result, input.Value)
	case "reverse_dns":
		err = s.runReverseDNS(ctx, &result, input)
	case "dns_records":
		err = s.runDNSRecords(ctx, &result, input)
	case "subdomains":
		err = s.runSubdomainTransform(ctx, &result, input)
	case "github_recon":
		err = s.runGitHubRecon(ctx, &result, input)
	case "wayback_urls":
		err = s.runWaybackURLs(ctx, &result, input)
	case "s3_buckets":
		err = s.runS3Buckets(ctx, &result, input)
	default:
		return result, transformError("UNKNOWN_TRANSFORM", "unsupported OSINT transform")
	}

	return result, err
}

func runEmailDomain(result *osintTransformResult, value string) error {
	parsed, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || !strings.Contains(parsed.Address, "@") {
		return transformError("INVALID_EMAIL", "email must be a plain address")
	}
	domain := strings.ToLower(strings.SplitN(parsed.Address, "@", 2)[1])
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}))
	return nil
}

func runDomainNormalize(result *osintTransformResult, value string) error {
	domain, err := normalizeDomainForTransform(value)
	if err != nil {
		return err
	}
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}))
	return nil
}

func runURLHost(result *osintTransformResult, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (strings.ToLower(parsed.Scheme) != "http" && strings.ToLower(parsed.Scheme) != "https") || parsed.Hostname() == "" {
		return transformError("INVALID_URL", "URL must be absolute HTTP(S)")
	}
	host := strings.ToLower(parsed.Hostname())
	result.Entities = append(result.Entities, entity("url", parsed.String(), nil, map[string]interface{}{"source": "local_transform"}), entity("domain", host, nil, map[string]interface{}{"source": "local_transform"}))
	result.Relations = append(result.Relations, transformRelation{Type: "hosted_on", SourceType: "url", Source: parsed.String(), TargetType: "domain", Target: host})
	return nil
}

func (s *server) runReverseDNS(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "reverse DNS performs a network lookup")
	}
	ip := net.ParseIP(strings.TrimSpace(input.Value))
	if ip == nil {
		return transformError("INVALID_IP", "IP address is invalid")
	}
	result.LocalOnly, result.NetworkUsed = false, true
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	result.Entities = append(result.Entities, entity("ip", ip.String(), nil, map[string]interface{}{"source": "reverse_dns"}))
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		result.Entities = append(result.Entities, entity("domain", name, nil, map[string]interface{}{"source": "reverse_dns"}))
		result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: name, TargetType: "ip", Target: ip.String()})
	}
	return nil
}

func (s *server) runDNSRecords(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "DNS lookup performs a network request")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly, result.NetworkUsed = false, true
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "dns_records"}))
	for _, ip := range ips {
		result.Entities = append(result.Entities, entity("ip", ip, nil, map[string]interface{}{"source": "dns_records"}))
		result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: domain, TargetType: "ip", Target: ip})
	}
	return nil
}

func (s *server) runWaybackURLs(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "archive lookup performs a network request")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly, result.NetworkUsed = false, true
	query := "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape(domain+"/*") + "&output=json&fl=original&collapse=urlkey"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, query, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 10 * time.Second, Transport: s.requestTransport()}).Do(request)
	if err != nil {
		return transformError("WAYBACK_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxTransformResponseBytes)+1))
	if err != nil || len(body) > maxTransformResponseBytes {
		return transformError("WAYBACK_RESPONSE_INVALID", "archive response exceeded the configured size")
	}
	var rows [][]string
	if response.StatusCode < 200 || response.StatusCode >= 300 || json.Unmarshal(body, &rows) != nil {
		return transformError("WAYBACK_RESPONSE_INVALID", fmt.Sprintf("archive returned HTTP %d", response.StatusCode))
	}
	for _, row := range rows {
		if len(row) == 0 || len(result.Entities) >= maxSubdomainResults {
			break
		}
		parsed, parseErr := url.Parse(strings.TrimSpace(row[0]))
		if parseErr != nil || parsed.Hostname() == "" {
			continue
		}
		target := parsed.String()
		result.Entities = append(result.Entities, entity("url", target, nil, map[string]interface{}{"source": "wayback"}))
		result.Relations = append(result.Relations, transformRelation{Type: "observed_at", SourceType: "url", Source: target, TargetType: "domain", Target: domain})
	}
	return nil
}

func (s *server) runS3Buckets(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "bucket checks perform network requests")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	candidates := stringSliceOption(input.Options, "candidates")
	if len(candidates) == 0 {
		candidates = []string{strings.Split(domain, ".")[0]}
	}
	result.LocalOnly, result.NetworkUsed = false, true
	client := &http.Client{Timeout: 8 * time.Second, Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" || strings.ContainsAny(candidate, "/?#:@") {
			continue
		}
		target := "https://" + candidate + ".s3.amazonaws.com/"
		request, reqErr := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if reqErr != nil {
			continue
		}
		response, reqErr := client.Do(request)
		if reqErr != nil {
			continue
		}
		response.Body.Close()
		if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusForbidden {
			result.Entities = append(result.Entities, entity("cloud_asset", target, map[string]interface{}{"provider": "aws_s3", "status": response.StatusCode}, map[string]interface{}{"source": "s3_head"}))
			result.Relations = append(result.Relations, transformRelation{Type: "hosted_on", SourceType: "cloud_asset", Source: target, TargetType: "domain", Target: domain})
		}
	}
	return nil
}
func runEmailRecon(result *osintTransformResult, value string) error {
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || !strings.Contains(value, "@") {
		return transformError("INVALID_EMAIL", "email must be a plain address")
	}
	parts := strings.SplitN(address.Address, "@", 2)
	email := strings.ToLower(parts[0] + "@" + parts[1])
	domain := strings.ToLower(parts[1])
	result.Entities = append(result.Entities,
		entity("email", email, map[string]interface{}{"local_part": parts[0]}, map[string]interface{}{"source": "local_transform"}),
		entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}),
	)
	result.Relations = append(result.Relations, transformRelation{
		Type: "contains", SourceType: "email", Source: email, TargetType: "domain", Target: domain,
		Provenance: map[string]interface{}{"source": "local_transform"},
	})
	result.Warnings = append(result.Warnings, "External social-profile enumeration is disabled by default; no API keys or mass requests were sent.")
	return nil
}

func runUsernameEnum(result *osintTransformResult, value string) error {
	username := strings.TrimSpace(value)
	if !usernamePattern.MatchString(username) {
		return transformError("INVALID_USERNAME", "username contains unsupported characters")
	}
	result.Entities = append(result.Entities, entity("username", username, map[string]interface{}{"canonical": strings.ToLower(username)}, map[string]interface{}{"source": "local_transform"}))
	result.Warnings = append(result.Warnings, "External platform enumeration is intentionally disabled; use a separately reviewed provider adapter.")
	return nil
}

func runIPGeo(result *osintTransformResult, value string) error {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return transformError("INVALID_IP", "IP address is invalid")
	}
	properties := map[string]interface{}{"geo_source": "unavailable"}
	warnings := []string{"GeoIP database is not configured; no database download or network lookup was performed."}
	if geo, ok := lookupLocalGeoIP(ip.String()); ok {
		properties = geo
		properties["geo_source"] = "local_json"
		warnings = []string{}
	}
	result.Entities = append(result.Entities, entity("ip", ip.String(), properties, map[string]interface{}{"source": "local_transform"}))
	result.Warnings = append(result.Warnings, warnings...)
	return nil
}

func lookupLocalGeoIP(ip string) (map[string]interface{}, bool) {
	path := strings.TrimSpace(os.Getenv("OSINT_GEOIP_JSON"))
	if path == "" {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 5<<20 {
		return nil, false
	}
	var entries map[string]map[string]interface{}
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, false
	}
	bestBits := -1
	var best map[string]interface{}
	for prefix, value := range entries {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil || !network.Contains(parsedIP) {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones > bestBits {
			bestBits = ones
			best = value
		}
	}
	return best, best != nil
}

func normalizeDomainForTransform(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(value))
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return "", transformError("INVALID_DOMAIN", "domain is invalid")
	}
	parsed, err := url.Parse("https://" + domain)
	if err != nil || parsed.Hostname() == "" || strings.ContainsAny(domain, "/?#@\\") {
		return "", transformError("INVALID_DOMAIN", "domain is invalid")
	}
	return strings.TrimSuffix(parsed.Hostname(), "."), nil
}

func (s *server) runSubdomainTransform(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "subdomain discovery performs bounded DNS and crt.sh requests")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "transform_input"}))
	found := map[string]bool{}
	queryURL := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err == nil {
		request.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
		client := &http.Client{Timeout: 10 * time.Second, Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		response, requestErr := client.Do(request)
		if requestErr != nil {
			result.Warnings = append(result.Warnings, "crt.sh lookup failed: "+requestErr.Error())
		} else {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maxTransformResponseBytes)+1))
			response.Body.Close()
			if readErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 || len(body) > maxTransformResponseBytes {
				result.Warnings = append(result.Warnings, fmt.Sprintf("crt.sh returned an unusable response (status=%d)", response.StatusCode))
			} else {
				var rows []struct {
					NameValue string `json:"name_value"`
				}
				if json.Unmarshal(body, &rows) == nil {
					for _, row := range rows {
						for _, name := range strings.Split(row.NameValue, "\n") {
							name = strings.ToLower(strings.TrimSpace(name))
							name = strings.TrimPrefix(name, "*.")
							if name != domain && strings.HasSuffix(name, "."+domain) && len(found) < maxSubdomainResults {
								found[name] = true
							}
						}
					}
				}
			}
		}
	}
	words := stringSliceOption(input.Options, "words")
	resolver := net.DefaultResolver
	if s.routes != nil {
		resolver = s.routes.resolver()
	}
	for _, word := range words {
		if len(found) >= maxSubdomainResults {
			break
		}
		candidate := strings.ToLower(strings.TrimSpace(word))
		if candidate == "" || strings.ContainsAny(candidate, " /:@") {
			continue
		}
		candidate += "." + domain
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ips, lookupErr := resolver.LookupHost(lookupCtx, candidate)
		cancel()
		if lookupErr != nil {
			continue
		}
		found[candidate] = true
		for _, address := range ips {
			result.Entities = append(result.Entities, entity("ip", address, nil, map[string]interface{}{"source": "dns_guess"}))
			result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "subdomain", Source: candidate, TargetType: "ip", Target: address, Provenance: map[string]interface{}{"source": "dns_guess"}})
		}
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maxSubdomainResults {
		names = names[:maxSubdomainResults]
	}
	for _, name := range names {
		result.Entities = append(result.Entities, entity("subdomain", name, nil, map[string]interface{}{"source": "crt.sh_or_dns"}))
		result.Relations = append(result.Relations, transformRelation{Type: "subdomain_of", SourceType: "subdomain", Source: name, TargetType: "domain", Target: domain, Provenance: map[string]interface{}{"source": "crt.sh_or_dns"}})
	}
	return nil
}

func stringSliceOption(options map[string]interface{}, key string) []string {
	values, ok := options[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
		if len(result) >= maxDNSWords {
			break
		}
	}
	return result
}

func (s *server) runGitHubRecon(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "GitHub profile lookup performs a public network request")
	}
	username := strings.TrimSpace(input.Value)
	if !githubUsernamePattern.MatchString(username) {
		return transformError("INVALID_GITHUB_USERNAME", "GitHub username is invalid")
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/users/"+url.PathEscape(username), nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
	request.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 10 * time.Second, Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return transformError("GITHUB_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxGitHubResponseBytes)+1))
	if err != nil || len(body) > maxGitHubResponseBytes {
		return transformError("GITHUB_RESPONSE_INVALID", "GitHub response exceeded the bounded size")
	}
	if response.StatusCode == http.StatusNotFound {
		result.Warnings = append(result.Warnings, "GitHub profile was not found")
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return transformError("GITHUB_LOOKUP_FAILED", fmt.Sprintf("GitHub returned HTTP %d", response.StatusCode))
	}
	var profile struct {
		Login       string `json:"login"`
		HTMLURL     string `json:"html_url"`
		PublicRepos int    `json:"public_repos"`
		Followers   int    `json:"followers"`
		Type        string `json:"type"`
	}
	if json.Unmarshal(body, &profile) != nil || profile.Login == "" {
		return transformError("GITHUB_RESPONSE_INVALID", "GitHub response did not contain a profile")
	}
	result.Entities = append(result.Entities, entity("username", profile.Login, map[string]interface{}{
		"html_url": profile.HTMLURL, "public_repos": profile.PublicRepos, "followers": profile.Followers, "account_type": profile.Type, "github_profile": true,
	}, map[string]interface{}{"source": "github_public_api"}))
	result.Warnings = append(result.Warnings, "Commit/email extraction is not performed by this bounded adapter.")
	return nil
}
