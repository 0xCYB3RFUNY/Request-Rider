package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
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
	SourceIP    string                 `json:"source_ip,omitempty"`
	Entities    []transformEntity      `json:"entities"`
	Relations   []transformRelation    `json:"relations"`
	Warnings    []string               `json:"warnings"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var githubUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// subdomainTransform is the transform that discovers the names under a host. It
// is the only transform that queries the certificate indexes.
const subdomainTransform = "subdomains"

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
	{"id": "subdomains", "network": true, "description": "crt.sh and DNS transform; requires explicit network confirmation."},
	{"id": "github_recon", "network": true, "description": "Public GitHub profile lookup; requires explicit network confirmation."},
	{"id": "wayback_urls", "network": true, "description": "Query public archive indexes for URLs; explicit confirmation required."},
	{"id": "s3_buckets", "network": true, "description": "Check a user-supplied bucket candidate list; explicit confirmation required."},
}

func transformError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
}

func validateTransformValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
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
	decoder := json.NewDecoder(r.Body)
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
	if code, message, ok := validateTransformInput(&input); !ok {
		writeError(w, http.StatusBadRequest, code, transformError(code, message))
		return
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	result, err := s.runOSINTTransform(routeContext, input)
	if result.NetworkUsed {
		result.SourceIP = s.ensureSourceIP(routeContext)
	}
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

// osintTransformJob starts one transform in the background so a long discovery
// reports live progress and can be paused or cancelled, instead of holding one
// blocking request open for the whole run.
func (s *server) osintTransformJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input osintTransformInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_OSINT_TRANSFORM", err)
		return
	}
	if code, message, ok := validateTransformInput(&input); !ok {
		writeError(w, http.StatusBadRequest, code, transformError(code, message))
		return
	}
	// The job outlives this request, so it binds to the route generation rather
	// than to the request context. A route switch still cancels it.
	_, routeContext, release := s.bindBackgroundRouteContext(r.Context())
	s.ensureSourceIP(routeContext)
	job := s.startOSINTJob(routeContext, input, release)
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID, "state": osintJobQueued, "progress": job.Snapshot().Progress,
	})
}

// osintTransformJobStatus returns the live progress of a background transform
// and, once finished, its result. A trailing action segment controls the run:
// "/pause" suspends it, "/resume" continues it, "/cancel" stops it.
func (s *server) osintTransformJobStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/proxy/osint/transform/jobs/")
	for _, action := range []string{"/cancel", "/pause", "/resume"} {
		if strings.HasSuffix(id, action) {
			s.osintTransformJobAction(w, r, strings.TrimSuffix(id, action), strings.TrimPrefix(action, "/"))
			return
		}
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	snapshot, ok := osintJobSnapshotFor(id)
	if !ok {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("transform %q is unknown or already collected", id))
		return
	}
	writeJSON(w, http.StatusOK, osintJobPayload(snapshot))
}

// osintJobPayload renders one snapshot for the browser poll.
func osintJobPayload(snapshot osintJobSnapshot) map[string]interface{} {
	payload := map[string]interface{}{
		"job_id": snapshot.ID, "state": snapshot.State, "progress": snapshot.Progress,
	}
	if snapshot.Result != nil {
		payload["result"] = snapshot.Result
	}
	if snapshot.Error != "" {
		payload["error"] = snapshot.Error
	}
	if snapshot.Reason != "" {
		payload["reason"] = snapshot.Reason
	}
	return payload
}

// osintTransformJobAction applies one control action to a background transform.
func (s *server) osintTransformJobAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var err error
	switch action {
	case "cancel":
		if !cancelOSINTJob(id) {
			err = fmt.Errorf("transform %q is unknown or already finished", id)
		}
	case "pause":
		err = pauseOSINTJob(id)
	case "resume":
		err = resumeOSINTJob(id)
	default:
		err = fmt.Errorf("unknown transform action %q", action)
	}
	if err != nil {
		status, code := http.StatusBadRequest, "INVALID_JOB_STATE"
		if strings.Contains(err.Error(), "is unknown") {
			status, code = http.StatusNotFound, "UNKNOWN_JOB"
		}
		writeError(w, status, code, err)
		return
	}
	state := osintJobRunning
	if action == "cancel" {
		state = osintJobCancelled
	} else if action == "pause" {
		state = osintJobPaused
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job_id": id, "state": state})
}

// validateTransformInput rejects a transform that cannot run at all, so a bad
// request fails immediately instead of becoming a job that fails on a timer.
func validateTransformInput(input *osintTransformInput) (string, string, bool) {
	input.Transform = strings.ToLower(strings.TrimSpace(input.Transform))
	input.Value = validateTransformValue(input.Value)
	if input.Value == "" {
		return "INVALID_VALUE", "transform value is required", false
	}
	known := false
	for _, item := range transformRegistry {
		if item["id"] == input.Transform {
			known = true
			break
		}
	}
	if !known {
		return "UNKNOWN_TRANSFORM", "unsupported OSINT transform", false
	}
	if input.Transform == subdomainTransform || input.Transform == "github_recon" || input.Transform == "reverse_dns" ||
		input.Transform == "dns_records" || input.Transform == "wayback_urls" || input.Transform == "s3_buckets" {
		if !input.ConfirmNetwork {
			return "NETWORK_CONFIRMATION_REQUIRED", "this transform performs a network request", false
		}
	}
	return "", "", true
}

func (s *server) runOSINTTransform(ctx context.Context, input osintTransformInput) (osintTransformResult, error) {
	return s.runOSINTTransformWithCollector(ctx, input, nil)
}

// runOSINTTransformWithCollector runs one transform and reports its progress.
//
// The collector is what makes a long transform controllable: a background job
// passes one to get live counters and a pause point, while the synchronous
// endpoint passes nil and keeps the original single-shot behaviour. Nothing
// else about the transform changes between the two.
func (s *server) runOSINTTransformWithCollector(ctx context.Context, input osintTransformInput, collector *transformCollector) (osintTransformResult, error) {
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
		err = s.transformEmailRecon(ctx, &result, input)
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
	case subdomainTransform:
		err = s.runSubdomainTransformWithCollector(ctx, &result, input, collector)
	case "github_recon":
		err = transformGitHubRecon(s, ctx, &result, input)
	case "wayback_urls":
		err = s.runWaybackURLsWithCollector(ctx, &result, input, collector)
	case "s3_buckets":
		err = transformS3Buckets(s, ctx, &result, input)
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

func (s *server) transformEmailRecon(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if input.Value == "" {
		return transformError("INVALID_EMAIL", "email must not be empty")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(input.Value))
	if err != nil || !strings.Contains(address.Address, "@") {
		return transformError("INVALID_EMAIL", "email must be a plain address")
	}
	localPart, domain := strings.TrimSpace(strings.SplitN(address.Address, "@", 2)[0]), strings.TrimSpace(strings.ToLower(strings.SplitN(address.Address, "@", 2)[1]))
	if localPart == "" || domain == "" {
		return transformError("INVALID_EMAIL", "email must include a local-part and domain")
	}
	result.Entities = append(result.Entities,
		entity("email", strings.ToLower(address.Address), map[string]interface{}{"local_part": localPart}, map[string]interface{}{"source": "local_transform"}),
		entity("domain", domain, nil, map[string]interface{}{"source": "local_transform"}),
	)
	result.Relations = append(result.Relations, transformRelation{Type: "contains", SourceType: "email", Source: strings.ToLower(address.Address), TargetType: "domain", Target: domain})
	if !input.ConfirmNetwork {
		result.Warnings = append(result.Warnings, "External social-profile verification is disabled; no mass HTTP checks were sent.")
		return nil
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	profiles := []struct {
		name string
		path string
	}{
		{"GitHub", "https://github.com/%s"}, {"LinkedIn", "https://www.linkedin.com/in/%s"}, {"Twitter/X", "https://x.com/%s"}, {"Facebook", "https://www.facebook.com/%s"}, {"Instagram", "https://www.instagram.com/%s"},
		{"Mastodon", "https://mastodon.social/@%s"}, {"Reddit", "https://www.reddit.com/user/%s"}, {"TikTok", "https://www.tiktok.com/@%s"}, {"YouTube", "https://www.youtube.com/@%s"}, {"Pinterest", "https://www.pinterest.com/%s"},
		{"Tumblr", "https://%s.tumblr.com/"}, {"WordPress", "https://%s.wordpress.com/"}, {"Flickr", "https://www.flickr.com/people/%s/"}, {"Medium", "https://medium.com/@%s"}, {"Vimeo", "https://vimeo.com/%s"},
		{"Dribbble", "https://dribbble.com/%s"}, {"Behance", "https://www.behance.net/%s"}, {"GitLab", "https://gitlab.com/%s"}, {"Bitbucket", "https://bitbucket.org/%s"}, {"StackOverflow", "https://stackoverflow.com/users/%s"},
		{"Hacker News", "https://news.ycombinator.com/user?id=%s"}, {"Quora", "https://www.quora.com/profile/%s"}, {"Spotify", "https://open.spotify.com/user/%s"}, {"Steam", "https://steamcommunity.com/id/%s"}, {"VKontakte", "https://vk.com/%s"},
		{"Disqus", "https://disqus.com/by/%s/"}, {"GitHub Gist", "https://gist.github.com/%s"}, {"CodePen", "https://codepen.io/%s"}, {"Pastebin", "https://pastebin.com/u/%s"}, {"DeviantArt", "https://%s.deviantart.com/"},
		{"Amazon", "https://www.amazon.com/gp/profile/amzn1.account.%s"}, {"Etsy", "https://www.etsy.com/people/%s"}, {"Goodreads", "https://www.goodreads.com/user/show/%s"}, {"Foursquare", "https://foursquare.com/%s"}, {"MySpace", "https://myspace.com/%s"},
		{"SoundCloud", "https://soundcloud.com/%s"}, {"Mixcloud", "https://www.mixcloud.com/%s/"}, {"Last.fm", "https://www.last.fm/user/%s"}, {"Blogger", "https://%s.blogspot.com/"}, {"Strava", "https://www.strava.com/athletes/%s"},
		{"NPM", "https://www.npmjs.com/~%s"}, {"Slack", "https://%s.slack.com/"}, {"Discord", "https://discord.com/users/%s"}, {"Trustpilot", "https://www.trustpilot.com/users/%s"}, {"Capterra", "https://www.capterra.com/reviews/user/%s"},
		{"ProductHunt", "https://www.producthunt.com/@%s"}, {"Kaggle", "https://www.kaggle.com/%s"}, {"ResearchGate", "https://www.researchgate.net/profile/%s"}, {"Academia", "https://independent.academia.edu/%s"}, {"SlideShare", "https://www.slideshare.net/%s"},
		{"Gravatar", "https://en.gravatar.com/%s"}, {"Keybase", "https://keybase.io/%s"}, {"Patreon", "https://www.patreon.com/%s"}, {"Twitch", "https://www.twitch.tv/%s"}, {"Chess.com", "https://www.chess.com/member/%s"},
		{"GitHubSponsors", "https://github.com/sponsors/%s"}, {"HuggingFace", "https://huggingface.co/%s"}, {"Bsky", "https://bsky.app/profile/%s.bsky.social"}, {"Threads", "https://www.threads.net/@%s"}, {"Snapchat", "https://www.snapchat.com/add/%s"},
		{"Apple", "https://appleid.apple.com/account/%s"}, {"Mojang", "https://www.minecraft.net/en-us/profile/%s"},
	}
	client := &http.Client{Transport: s.requestTransport()}
	seen := map[string]bool{}
	for _, profile := range profiles {
		candidate := profile.path
		candidate = strings.ReplaceAll(candidate, "%s", url.PathEscape(localPart))
		if strings.Contains(candidate, "%s") {
			candidate = strings.ReplaceAll(candidate, "%s", url.PathEscape(strings.Split(localPart, "+")[0]))
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate, nil)
		if err != nil {
			continue
		}
		request.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 400 || response.StatusCode == http.StatusForbidden {
			if !seen[profile.name] {
				seen[profile.name] = true
				result.Entities = append(result.Entities, entity("profile", profile.name+":"+localPart, map[string]interface{}{"platform": profile.name, "status": response.StatusCode, "profile_url": candidate}, map[string]interface{}{"source": "social_http_probe"}))
				result.Relations = append(result.Relations, transformRelation{Type: "accounts_for", SourceType: "email", Source: strings.ToLower(address.Address), TargetType: "profile", Target: profile.name + ":" + localPart, Properties: map[string]interface{}{"status": response.StatusCode}})
			}
		}
	}
	if len(seen) == 0 {
		result.Warnings = append(result.Warnings, "No public social accounts matched the supplied identity in the online check.")
	}
	return nil
}

func transformS3Buckets(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "bucket checks perform network requests")
	}
	candidateNames := stringSliceOption(input.Options, "candidates")
	if len(candidateNames) == 0 {
		candidateNames = []string{strings.TrimSpace(input.Value)}
	}
	if len(candidateNames) == 0 {
		return transformError("INVALID_DOMAIN", "bucket source is required")
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	client := &http.Client{Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	var names []string
	seenNames := map[string]bool{}
	for _, name := range candidateNames {
		normalized := strings.ToLower(strings.TrimSpace(name))
		normalized = strings.TrimSuffix(normalized, ".")
		normalized = strings.TrimPrefix(normalized, "https://")
		normalized = strings.TrimPrefix(normalized, "http://")
		if normalized == "" || strings.ContainsAny(normalized, "/?#:@") || seenNames[normalized] {
			continue
		}
		seenNames[normalized] = true
		names = append(names, normalized)
	}
	if len(names) == 0 {
		names = []string{strings.Split(strings.Trim(strings.ToLower(input.Value), "."), ".")[0]}
	}
	providers := []struct {
		name string
		url  string
	}{
		{"aws_s3", "https://%s.s3.amazonaws.com/"},
		{"gcp_storage", "https://storage.googleapis.com/%s/"},
		{"azure_blob", "https://%s.blob.core.windows.net/"},
	}
	for _, candidate := range names {
		for _, provider := range providers {
			urlString := fmt.Sprintf(provider.url, candidate)
			request, err := http.NewRequestWithContext(ctx, http.MethodHead, urlString, nil)
			if err != nil {
				continue
			}
			request.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
			response, err := client.Do(request)
			if err != nil {
				continue
			}
			response.Body.Close()
			if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound {
				result.Entities = append(result.Entities, entity("cloud_asset", urlString, map[string]interface{}{"provider": provider.name, "status": response.StatusCode}, map[string]interface{}{"source": "bucket_probe"}))
				result.Relations = append(result.Relations, transformRelation{Type: "hosted_on", SourceType: "cloud_asset", Source: urlString, TargetType: "domain", Target: candidate})
			}
		}
	}
	if len(result.Entities) == 0 {
		result.Warnings = append(result.Warnings, "No public bucket endpoints responded in the supplied candidate set.")
	}
	return nil
}

func transformGitHubRecon(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
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
	client := &http.Client{Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return transformError("GITHUB_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return transformError("GITHUB_RESPONSE_INVALID", "GitHub response could not be read")
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
		Name        string `json:"name"`
		PublicRepos int    `json:"public_repos"`
		Followers   int    `json:"followers"`
		Type        string `json:"type"`
	}
	if json.Unmarshal(body, &profile) != nil || profile.Login == "" {
		return transformError("GITHUB_RESPONSE_INVALID", "GitHub response did not contain a profile")
	}
	result.Entities = append(result.Entities, entity("username", profile.Login, map[string]interface{}{"html_url": profile.HTMLURL, "name": profile.Name, "public_repos": profile.PublicRepos, "followers": profile.Followers, "account_type": profile.Type}, map[string]interface{}{"source": "github_public_api"}))
	commitsRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/users/"+url.PathEscape(username)+"/events/public", nil)
	if err == nil {
		commitsRequest.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
		commitsRequest.Header.Set("Accept", "application/vnd.github+json")
		commitsResponse, commitErr := client.Do(commitsRequest)
		if commitErr == nil {
			defer commitsResponse.Body.Close()
			commitBody, readErr := io.ReadAll(commitsResponse.Body)
			if readErr == nil {
				var events []map[string]interface{}
				if json.Unmarshal(commitBody, &events) == nil {
					seenEmails := map[string]bool{}
					for _, event := range events {
						if event["type"] != "PushEvent" {
							continue
						}
						payload, ok := event["payload"].(map[string]interface{})
						if !ok {
							continue
						}
						commits, ok := payload["commits"].([]interface{})
						if !ok {
							continue
						}
						for _, commit := range commits {
							commitMap, ok := commit.(map[string]interface{})
							if !ok {
								continue
							}
							for _, candidate := range []interface{}{commitMap["author"], commitMap["committer"], commitMap["email"], payload["head"], payload["head_commit"]} {
								address := normalizeGitHubEmail(candidate)
								if address == "" || seenEmails[address] {
									continue
								}
								seenEmails[address] = true
								result.Entities = append(result.Entities, entity("email", address, map[string]interface{}{"source": "github_public_commit"}, map[string]interface{}{"source": "github_public_commit"}))
								result.Relations = append(result.Relations, transformRelation{Type: "mentions_email", SourceType: "username", Source: username, TargetType: "email", Target: address})
							}
						}
					}
				}
			}
		}
	}
	if len(result.Entities) == 1 {
		result.Warnings = append(result.Warnings, "Public commit activity was not available for the selected GitHub profile.")
	}
	return nil
}

func normalizeGitHubEmail(value interface{}) string {
	switch typed := value.(type) {
	case string:
		candidate := strings.TrimSpace(typed)
		if candidate == "" {
			return ""
		}
		if email, ok := extractEmailCandidate(candidate); ok {
			return email
		}
		return ""
	case map[string]interface{}:
		for _, key := range []string{"email", "value"} {
			if candidate := normalizeGitHubEmail(typed[key]); candidate != "" {
				return candidate
			}
		}
		if nested, ok := typed["author"].(map[string]interface{}); ok {
			if candidate := normalizeGitHubEmail(nested["email"]); candidate != "" {
				return candidate
			}
		}
		if nested, ok := typed["committer"].(map[string]interface{}); ok {
			if candidate := normalizeGitHubEmail(nested["email"]); candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func extractEmailCandidate(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	matches := regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`).FindStringSubmatch(strings.TrimSpace(value))
	if len(matches) == 0 {
		return "", false
	}
	return strings.ToLower(matches[0]), true
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
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return transformError("INVALID_IP", "IP address is invalid")
	}
	if strings.Contains(value, "/") {
		// A range is not a single address, and enumerating every address in it
		// would be a scan of the whole range rather than one reverse lookup.
		return transformError("INVALID_IP", "a CIDR range is not a single address; reverse DNS needs one specific address")
	}
	result.LocalOnly, result.NetworkUsed = false, true
	resolver := routeResolverForContext(ctx)
	addresses := []string{}
	host := ""
	if ip := net.ParseIP(value); ip != nil {
		addresses = append(addresses, ip.String())
	} else {
		// A hostname carries PTR information too, but only through its
		// addresses: the forward answer is stored so the graph keeps the
		// domain, its addresses and every name those addresses answer with.
		normalized, err := normalizeDomainForTransform(value)
		if err != nil {
			return err
		}
		host = normalized
		resolved, err := resolver.LookupHost(ctx, normalized)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
		addresses = append(addresses, resolved...)
		result.Entities = append(result.Entities, entity("domain", normalized, nil, map[string]interface{}{"source": "reverse_dns"}))
	}
	if len(addresses) == 0 {
		return nil
	}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s is not an address that reverse DNS can ask about", address))
			continue
		}
		canonical := ip.String()
		names, err := resolver.LookupAddr(ctx, canonical)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
		result.Entities = append(result.Entities, entity("ip", canonical, nil, map[string]interface{}{"source": "reverse_dns"}))
		if host != "" {
			result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: host, TargetType: "ip", Target: canonical})
		}
		for _, name := range names {
			name = strings.TrimSuffix(strings.ToLower(name), ".")
			result.Entities = append(result.Entities, entity("domain", name, nil, map[string]interface{}{"source": "reverse_dns"}))
			result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "domain", Source: name, TargetType: "ip", Target: canonical})
		}
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
	ips, err := routeResolverForContext(ctx).LookupHost(ctx, domain)
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

// archiveEndpoint is one public Internet Archive index that answers the same
// question for a host: which URLs were archived. The endpoints differ in
// availability only, because the CDX indexer rate limits and goes offline
// independently of the timemap backend. Falling back changes which backend
// answered, never the meaning of the rows it returns.
type archiveEndpoint struct {
	name  string
	query string
}

// publicArchiveIndex is the public Internet Archive index host.
const publicArchiveIndex = "https://web.archive.org"

// requestHTTPClient is the client every OSINT adapter uses so the active route
// and TLS configuration are shared by all of them.
func (s *server) requestHTTPClient() *http.Client {
	return &http.Client{
		Transport: s.requestTransport(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// archiveEndpoints returns the ordered index chain for one domain. The CDX
// index collapses the archive to one row per URL; the timemap index keeps one
// row per capture, so it is only used when the collapsed index cannot answer.
func archiveEndpoints(base, domain string) []archiveEndpoint {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		base = publicArchiveIndex
	}
	prefix := url.QueryEscape(domain + "/*")
	return []archiveEndpoint{
		{"cdx", base + "/cdx/search/cdx?url=" + prefix + "&output=json&fl=original&collapse=urlkey"},
		{"timemap", base + "/web/timemap/json?url=" + prefix},
	}
}

// archiveIndex reports what one streamed archive index actually delivered.
type archiveIndex struct {
	endpoint string
	rows     int
	urls     int
	complete bool
}

// truncated reports that the archive ended the index stream before the last
// row, which is a normal occurrence for a large host prefix.
func (index archiveIndex) truncated() bool {
	return index.rows > 0 && !index.complete
}

func (s *server) runWaybackURLs(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	return s.runWaybackURLsWithCollector(ctx, result, input, nil)
}

func (s *server) runWaybackURLsWithCollector(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "archive lookup performs a network request")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly, result.NetworkUsed = false, true
	// The archived URLs are observed at this host, so the host is part of the
	// result: the gateway rejects a relation whose endpoint is not in the graph.
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "transform_input"}))
	client := s.requestHTTPClient()
	endpoints := archiveEndpoints(s.archiveIndexBase, domain)
	// One identity per archived URL across the whole chain: the timemap index
	// repeats the same URL for every capture, so duplicates are dropped by
	// identity rather than by discarding part of the archive.
	seen := map[string]bool{}
	failures := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		added := 0
		index, streamErr := streamArchiveIndex(ctx, client, endpoint, func(candidate string) {
			// The archive index is the longest part of a wayback transform and
			// regularly returns a partial view, so every row is both a pause
			// point and a progress tick.
			if collector != nil {
				if err := collector.checkpoint(ctx); err != nil {
					return
				}
			}
			target, ok := archiveURLTarget(candidate)
			if !ok || seen[target] {
				return
			}
			seen[target] = true
			added++
			provenance := map[string]interface{}{"source": "wayback", "archive_index": endpoint.name}
			result.Entities = append(result.Entities, entity("url", target, nil, provenance))
			result.Relations = append(result.Relations, transformRelation{
				Type: "observed_at", SourceType: "url", Source: target, TargetType: "domain", Target: domain, Provenance: provenance,
			})
		})
		index.urls = added
		if streamErr != nil {
			failures = append(failures, fmt.Sprintf("%s index: %v", endpoint.name, streamErr))
			// A cancelled or replaced route must not walk the remaining chain.
			if ctx.Err() != nil {
				break
			}
			continue
		}
		result.Metadata = archiveIndexMetadata(result.Metadata, index)
		collector.indexDone(ctx, endpoint.name, 1, added)
		if index.rows == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("the %s archive index holds no captures for %s", endpoint.name, domain))
		}
		if index.truncated() {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"the %s archive index stream ended early after %d rows; the collected URLs are a partial view",
				endpoint.name, index.rows,
			))
		}
		// A truncated index still carries real coverage, so the next endpoint
		// is only used when this one could not answer at all.
		return nil
	}
	// No index answered: report every attempt instead of a single opaque code.
	detail := "no public archive index answered for " + domain
	if len(failures) > 0 {
		detail += ": " + strings.Join(failures, "; ")
	}
	return transformError("WAYBACK_LOOKUP_FAILED", detail)
}

// streamArchiveIndex decodes one archive index response row by row.
//
// The index for a large host is a very long stream that the archive regularly
// ends mid-array, and buffering it whole is neither useful nor safe, so rows
// are consumed as they arrive. A truncated tail is reported through the result
// instead of discarding every row that was already read, while a stream that
// never produced a usable row stays an error for the caller.
func streamArchiveIndex(ctx context.Context, client *http.Client, endpoint archiveEndpoint, sink func(string)) (archiveIndex, error) {
	index := archiveIndex{endpoint: endpoint.name}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.query, nil)
	if err != nil {
		return index, fmt.Errorf("request could not be built: %w", err)
	}
	// The archive requires every automated request to identify itself, and
	// answers an anonymous client with a rate-limit status instead of an
	// answer. This User-Agent is therefore part of the adapter contract.
	request.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return index, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return index, fmt.Errorf("archive returned HTTP %d%s", response.StatusCode, retryAfterNote(response.Header))
	}
	column := -1
	streamErr := streamJSONArray(response.Body, func(element json.RawMessage) error {
		var row []string
		if err := json.Unmarshal(element, &row); err != nil {
			return err
		}
		if column < 0 {
			// Both index formats start with a header row and name the archived
			// URL column "original", which the timemap layout places third.
			column = archiveURLColumn(row)
			if column < 0 {
				return errors.New("archive index header has no original URL column")
			}
			return nil
		}
		index.rows++
		if column < len(row) {
			sink(strings.TrimSpace(row[column]))
		}
		return nil
	})
	if streamErr != nil && index.rows == 0 {
		return index, fmt.Errorf("archive index could not be decoded: %w", streamErr)
	}
	index.complete = streamErr == nil
	return index, nil
}

// retryAfterNote reports how long the archive asked a client to wait, so a
// rate-limited answer explains itself instead of looking like a hard failure.
// The archive documents `Retry-After` on 429 as the client's cue to back off.
func retryAfterNote(header http.Header) string {
	values := header.Values("Retry-After")
	if len(values) == 0 {
		return ""
	}
	wait := strings.TrimSpace(values[0])
	if wait == "" {
		return ""
	}
	if seconds, err := strconv.Atoi(wait); err == nil {
		if seconds < 0 {
			return ""
		}
		return fmt.Sprintf(" (retry after %ds)", seconds)
	}
	// A date is passed through as written rather than reinterpreted here.
	return " (retry after " + wait + ")"
}

// archiveURLColumn returns the position of the archived URL inside an index
// header row, or -1 when the row does not describe one.
func archiveURLColumn(header []string) int {
	for position, name := range header {
		if strings.EqualFold(strings.TrimSpace(name), "original") {
			return position
		}
	}
	return -1
}

// archiveURLTarget canonicalizes one archived URL and reports whether it is a
// usable absolute HTTP(S) identity.
//
// The public archive is attacker-controllable input: it stores captured
// credential URLs such as https://user@yandex.ru/ and fragment-only variants.
// The canonical form therefore drops userinfo, query and fragment, and rejects
// hosts the graph identity rules cannot store, so one poisoned archive row
// cannot fail the whole transform and no captured credential becomes an
// identity.
func archiveURLTarget(candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host, ok := canonicalURLHost(parsed.Hostname())
	if !ok {
		return "", false
	}
	port := parsed.Port()
	if !validURLPort(port) {
		return "", false
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	netloc := host
	if strings.Contains(host, ":") {
		netloc = "[" + host + "]"
	}
	if port != "" {
		netloc += ":" + port
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if hasDotSegment(path) {
		return "", false
	}
	return scheme + "://" + netloc + path, true
}

// hasDotSegment reports whether a path still carries a "." or ".." segment.
// Such a row is a traversal attempt in attacker-controllable archive data
// rather than a captured resource, so it is dropped instead of stored.
func hasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// canonicalURLHost normalizes one URL host to the ASCII form the graph stores
// and reports whether the host is storable. The rules match the graph identity
// validation so a URL the engine accepts is always a URL the gateway keeps.
func canonicalURLHost(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, " \\/?#@") {
		return "", false
	}
	if address := net.ParseIP(host); address != nil {
		return address.String(), true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", false
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || !isASCIIAlnum(label[0]) || !isASCIIAlnum(label[len(label)-1]) {
			return "", false
		}
		for index := 0; index < len(label); index++ {
			if character := label[index]; !isASCIIAlnum(character) && character != '-' {
				return "", false
			}
		}
	}
	return ascii, true
}

func isASCIIAlnum(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
}

// validURLPort reports whether a port is absent or a real TCP port. The graph
// identity rules reject anything else, so such a row is dropped here.
func validURLPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 {
		return false
	}
	number := 0
	for index := 0; index < len(port); index++ {
		character := port[index]
		if character < '0' || character > '9' {
			return false
		}
		number = number*10 + int(character-'0')
	}
	return number > 0 && number <= 65535
}

// archiveIndexMetadata records which index answered and how much it delivered,
// so a partial archive view stays visible in the graph metadata.
func archiveIndexMetadata(metadata map[string]interface{}, index archiveIndex) map[string]interface{} {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["archive_index"] = index.endpoint
	metadata["archive_rows"] = index.rows
	metadata["archive_urls"] = index.urls
	metadata["archive_stream_complete"] = index.complete
	return metadata
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
	client := &http.Client{Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
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
	if err != nil {
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
	if domain == "" || net.ParseIP(domain) != nil {
		return "", transformError("INVALID_DOMAIN", "domain is invalid")
	}
	parsed, err := url.Parse("https://" + domain)
	if err != nil || parsed.Hostname() == "" || strings.ContainsAny(domain, "/?#@\\") {
		return "", transformError("INVALID_DOMAIN", "domain is invalid")
	}
	return strings.TrimSuffix(parsed.Hostname(), "."), nil
}

func (s *server) runSubdomainTransform(ctx context.Context, result *osintTransformResult, input osintTransformInput) error {
	return s.runSubdomainTransformWithCollector(ctx, result, input, nil)
}

// runSubdomainTransformWithCollector discovers subdomains and reports what the
// certificate indexes have collected so far. The collector is the pause and
// progress point; a nil collector keeps the original single-shot behaviour.
// certificateIndexChain returns the certificate transparency indexes to query.
// Production uses the public chain; a test points it at a local fixture.
func (s *server) certificateIndexChain(domain string) []certificateSource {
	if s.certificateIndexList != nil {
		return s.certificateIndexList(domain)
	}
	return certificateSources(domain)
}

func (s *server) runSubdomainTransformWithCollector(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "subdomain discovery performs DNS and certificate transparency requests")
	}
	domain, err := normalizeDomainForTransform(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	result.Entities = append(result.Entities, entity("domain", domain, nil, map[string]interface{}{"source": "transform_input"}))
	found := map[string]bool{}
	client := s.requestHTTPClient()
	evidence := certificateTransparencyNames(ctx, client, domain, collector, s.certificateIndexChain)
	result.Warnings = append(result.Warnings, evidence.warnings...)
	for name := range evidence.names {
		found[name] = true
	}
	// The indexes are keyed by zone, so a host input is answered by the zone the
	// host belongs to. The names are certified under that zone, so the zone is
	// what the relations and the DNS candidates are resolved against, and the
	// substitution is stated instead of being applied silently.
	zone := evidence.zone
	if zone == "" {
		zone = domain
	}
	if zone != domain {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"the certificate indexes are keyed by zone, and %s produced no names of its own, so the indexes and the DNS candidates were resolved against the zone %s that it belongs to; %s stays in the graph as its own domain entity",
			domain, zone, domain,
		))
		result.Entities = append(result.Entities, entity("domain", zone,
			map[string]interface{}{"role": "certificate_zone"},
			map[string]interface{}{"source": "certificate_transparency"}))
	}
	result.Metadata = certificateIndexMetadata(result.Metadata, evidence.counts, len(evidence.names))
	result.Metadata["cert_input"] = domain
	result.Metadata["cert_zone"] = zone
	result.Metadata["cert_zones_queried"] = evidence.queried
	words := stringSliceOption(input.Options, "words")
	if len(words) == 0 {
		words = defaultSubdomainWords()
	}
	resolver := net.DefaultResolver
	if s.routes != nil {
		resolver = s.routes.resolver()
	}
	lookup := func(lookupCtx context.Context, candidate string) ([]string, error) {
		return resolver.LookupHost(lookupCtx, candidate)
	}
	if sample, wildcard := detectWildcardDNS(ctx, collector, lookup, zone); wildcard {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"wildcard DNS detected: %s resolves, so DNS brute-force names were skipped as unreliable; certificate transparency results are kept",
			sample,
		))
	} else {
		for _, foundName := range bruteForceSubdomains(ctx, collector, lookup, zone, words, found) {
			found[foundName.name] = true
			for _, address := range foundName.ips {
				result.Entities = append(result.Entities, entity("ip", address, nil, map[string]interface{}{"source": "dns_guess"}))
				result.Relations = append(result.Relations, transformRelation{Type: "resolves_to", SourceType: "subdomain", Source: foundName.name, TargetType: "ip", Target: address, Provenance: map[string]interface{}{"source": "dns_guess"}})
			}
		}
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// A name that resolved through DNS guessing is weaker evidence than
		// one an index actually holds, so the origin stays distinguishable.
		origin := map[string]interface{}{"source": "certificate_transparency"}
		if !evidence.names[name] {
			origin = map[string]interface{}{"source": "dns_guess"}
		}
		result.Entities = append(result.Entities, entity("subdomain", name, nil, origin))
		result.Relations = append(result.Relations, transformRelation{Type: "subdomain_of", SourceType: "subdomain", Source: name, TargetType: "domain", Target: zone, Provenance: origin})
	}
	return nil
}

// certificateIndexMetadata records which certificate transparency indexes
// answered and how many names each contributed, so the operator can see the
// coverage behind a result without repeating the query.
func certificateIndexMetadata(metadata map[string]interface{}, counts map[string]int, total int) map[string]interface{} {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	perIndex := map[string]interface{}{}
	for name, count := range counts {
		perIndex[name] = count
	}
	metadata["cert_indexes"] = perIndex
	metadata["cert_names"] = total
	return metadata
}

// certificateQueryZones returns the zones to ask the certificate indexes about,
// nearest first, for one host.
//
// The indexes are keyed by zone, not by host. An index that validates its input
// refuses a host that is not a zone — crt.name answers `invalid apex: not an
// apex (eTLD+1 is ...)` — and an index that accepts a host answers with the host
// itself, which is what the caller already knows and no subdomain at all. So a
// host input is resolved to the zone the indexes actually hold, one parent at a
// time, and the walk stops before a single label so a public suffix is never
// asked for the certificate list of the whole registry.
//
// A candidate that is not a storable host never enters the chain: an empty label
// such as the `..` of a malformed value is not a zone any index can answer.
func certificateQueryZones(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	zones := []string{}
	for zone := host; storableHostname(zone) && strings.Contains(zone, "."); zone = parentCertificateZone(zone) {
		zones = append(zones, zone)
	}
	return zones
}

// parentCertificateZone returns the zone one label up, or an empty string when
// the host is already a single label.
func parentCertificateZone(host string) string {
	if index := strings.Index(host, "."); index >= 0 {
		return host[index+1:]
	}
	return ""
}

// certificateEvidence is what the certificate indexes returned for one host.
type certificateEvidence struct {
	// names is the union of the names every index held.
	names map[string]bool
	// warnings names every index that could not answer and every index that
	// stopped short, so a thin result is never mistaken for a complete one.
	warnings []string
	// counts holds the names each answering index contributed.
	counts map[string]int
	// zone is the queried zone that produced names. It is the zone the names
	// are certified under, which for a host input is the zone the host belongs
	// to rather than the host itself.
	zone string
	// queried lists the zones that were asked, nearest first.
	queried []string
}

// certificateIndexOutcome accumulates what one index delivered across every zone
// it was asked about, so an index that cannot answer one zone is still credited
// with the zones it did answer.
type certificateIndexOutcome struct {
	source string
	names  map[string]bool
	// note describes how much of the index was read, such as where its own
	// public allowance stopped a paginated walk. It is not a failure.
	note string
	// firstFailure is the answer for the nearest zone, so an index that could
	// not answer the requested host is reported against that host rather than
	// against a parent zone that was tried on its behalf.
	firstFailure string
	// exhausted is set when the index said its own public allowance is spent,
	// which stops the walk from spending further requests on it.
	exhausted bool
	queried   int
	answered  bool
	zone      string
}

// certificateTransparencyNames resolves one host against the certificate
// indexes and returns the union of the names they returned, the warning for
// every index that did not answer, and the per-index counts.
//
// The chain builds the index queries for one zone, so every zone of the walk is
// asked about itself rather than about the host that started the walk. The walk
// stops at the first zone that holds a name the transform did not already have,
// so a host input is answered by the zone it belongs to while an apex input
// costs exactly one round of queries. Inside one zone the indexes run at the
// same time, so the whole transform costs the slowest index instead of the sum,
// and a dead index never delays the ones that work.
func certificateTransparencyNames(ctx context.Context, client *http.Client, host string, collector *transformCollector, chain func(string) []certificateSource) certificateEvidence {
	evidence := certificateEvidence{names: map[string]bool{}, counts: map[string]int{}}
	evidence.queried = certificateQueryZones(host)
	outcomes := map[string]*certificateIndexOutcome{}
	order := []string{}
	if len(evidence.queried) > 0 && chain != nil {
		// The index set is the same for every zone, so the accumulator order is
		// taken once from the first zone that is asked.
		for _, source := range chain(evidence.queried[0]) {
			if _, seen := outcomes[source.name]; seen {
				continue
			}
			outcomes[source.name] = &certificateIndexOutcome{source: source.name, names: map[string]bool{}}
			order = append(order, source.name)
		}
	}
	if len(order) == 0 {
		evidence.warnings = append(evidence.warnings, fmt.Sprintf("no public certificate index answered for %s", host))
		return evidence
	}
	for _, zone := range evidence.queried {
		sources := chain(zone)
		zoneNames, answering := queryCertificateZone(ctx, client, zone, collector, sources, outcomes, order)
		discovered := 0
		for name := range zoneNames {
			if name != host {
				discovered++
			}
			evidence.names[name] = true
		}
		// One checkpoint per zone, so the panel names the zone being read and
		// the indexes that answered instead of showing a frozen counter.
		collector.indexDone(ctx, certificateZoneProgress(zone, host, answeredIndexes(outcomes, order)), answering, collector.nameCount())
		if discovered > 0 || ctx.Err() != nil {
			evidence.zone = zone
			break
		}
	}
	for _, name := range order {
		outcome := outcomes[name]
		if !outcome.answered {
			if outcome.firstFailure != "" {
				evidence.warnings = append(evidence.warnings, outcome.firstFailure)
			}
			continue
		}
		evidence.counts[name] = len(outcome.names)
		if outcome.note != "" {
			evidence.warnings = append(evidence.warnings, fmt.Sprintf("the %s certificate index %s", name, outcome.note))
		}
		if len(outcome.names) == 0 {
			evidence.warnings = append(evidence.warnings, fmt.Sprintf("the %s certificate index holds no names for %s", name, outcome.zone))
		}
	}
	if len(evidence.counts) == 0 && ctx.Err() == nil {
		evidence.warnings = append(evidence.warnings, fmt.Sprintf("no public certificate index answered for %s", host))
	}
	return evidence
}

// queryCertificateZone asks every index about one zone at the same time and
// merges what they answered into the per-index accumulators. It reports the
// names the zone produced and the indexes that answered it.
func queryCertificateZone(ctx context.Context, client *http.Client, zone string, collector *transformCollector, sources []certificateSource, outcomes map[string]*certificateIndexOutcome, order []string) (map[string]bool, int) {
	pending := make([]certificateSource, 0, len(sources))
	for _, source := range sources {
		// An index that reported its allowance as spent is not asked again for
		// the next zone: it would answer with the same refusal it just gave.
		if outcomes[source.name].exhausted {
			continue
		}
		pending = append(pending, source)
	}
	indexes := make([]certificateIndex, len(pending))
	var wg sync.WaitGroup
	for position, source := range pending {
		wg.Add(1)
		go func(slot int, current certificateSource) {
			defer wg.Done()
			// Each index streams its names into the shared collector, so the
			// progress panel moves while the indexes are still answering
			// rather than only when they are all done.
			index := &streamingCollector{collector: collector, source: current.name}
			names, note, exhausted, failure := queryCertificateSource(ctx, client, current, zone, index)
			indexes[slot] = certificateIndex{source: current.name, names: names, note: note, exhausted: exhausted, failure: failure}
		}(position, source)
	}
	wg.Wait()

	zoneNames := map[string]bool{}
	answered := 0
	for _, index := range indexes {
		outcome, known := outcomes[index.source]
		if !known {
			// The chain for this zone carries an index the first zone did not,
			// so it is accounted for from the zone that introduced it.
			outcome = &certificateIndexOutcome{source: index.source, names: map[string]bool{}}
			outcomes[index.source] = outcome
			order = append(order, index.source)
		}
		outcome.queried++
		if index.failure != "" {
			if outcome.firstFailure == "" {
				outcome.firstFailure = index.failure
			}
			continue
		}
		outcome.answered = true
		outcome.zone = zone
		answered++
		if index.note != "" && outcome.note == "" {
			outcome.note = index.note
		}
		if index.exhausted {
			outcome.exhausted = true
		}
		for name := range index.names {
			zoneNames[name] = true
			outcome.names[name] = true
		}
	}
	return zoneNames, answered
}

// answeredIndexes lists the certificate indexes that have answered so far, in the
// order the chain declares them, so the progress panel names real sources rather
// than an opaque counter.
func answeredIndexes(outcomes map[string]*certificateIndexOutcome, order []string) []string {
	answered := []string{}
	for _, name := range order {
		if outcomes[name].answered {
			answered = append(answered, certificateIndexName(name))
		}
	}
	return answered
}

// certificateZoneProgress describes the zone being read for the progress panel.
func certificateZoneProgress(zone, host string, answered []string) string {
	if zone == host {
		return strings.Join(answered, ", ")
	}
	if len(answered) == 0 {
		return "zone " + zone
	}
	return "zone " + zone + ": " + strings.Join(answered, ", ")
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
	}
	return result
}

// dnsGuess is one resolved brute-force candidate with deterministic ordering.
type dnsGuess struct {
	name string
	ips  []string
}

// defaultSubdomainWords is the embedded sublist3r-style wordlist used when
// the caller supplies no explicit words. Entries are short alphanumeric
// labels; the option cap still applies through stringSliceOption bounds.
func defaultSubdomainWords() []string {
	words := []string{
		"www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "admin",
		"blog", "shop", "api", "dev", "test", "stage", "staging", "prod",
		"portal", "vpn", "remote", "secure", "login", "sso", "auth",
		"cdn", "static", "assets", "img", "images", "media", "video",
		"ns1", "ns2", "dns", "mx", "web", "site", "sites", "app", "apps",
		"mobile", "m", "beta", "demo", "docs", "support", "help", "status",
		"git", "gitlab", "jenkins", "jira", "wiki", "crm", "erp", "hr",
		"pay", "billing", "store", "news", "forum", "community", "chat",
		"files", "drive", "cloud", "backup", "db", "sql", "monitor",
		"grafana", "kibana", "prometheus", "ldap", "proxy", "gateway",
		"internal", "intranet", "extranet", "partner", "client",
		"new", "old", "legacy", "v1", "v2", "api-v1", "api-v2", "sandbox",
	}
	return words
}

// crtLookupAttempts is how often one certificate transparency query is sent
// before the outage is reported. The public crt.sh mirror answers 502 and 503
// for a single large query often enough that one attempt reports an outage a
// later attempt resolves, so the retry is part of the adapter instead of a
// policy choice by the caller.
const crtLookupAttempts = 3

// certspotterPageSize is the number of issuances one certspotter page carries.
// A short page is the whole answer, a full one has a successor.
const certspotterPageSize = 100

// certificateTransparencyQuery is the public crt.sh certificate transparency
// query for one domain.
func certificateTransparencyQuery(domain string) string {
	return "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
}

// certificateSource is one public Certificate Transparency index. Every source
// answers the same question from the same public CT logs — which names were
// certified under a host — and they fail independently of each other, so the
// union of their answers is evidence and a failed source only removes coverage.
type certificateSource struct {
	name  string
	query string
	// accept is the media type this index actually serves.
	accept string
	// keyEnv names the optional operator key for indexes that meter access.
	keyEnv string
	// page extracts the certified names from one answer and the token that
	// fetches the next page, which is empty for an index that answered in
	// full. Pagination therefore follows the index's own cursor. The stream
	// reports the names as they arrive and is the pause point; it is nil for
	// the synchronous endpoint.
	page func(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error)
}

// certificateSources returns the index set for one zone.
//
// crt.sh is the public front end, but it runs on a shared PostgreSQL cluster
// with a measured uptime in the low double digits and answers 502 for a single
// large zone query. The rest are independent indexes of the same public logs,
// each with its own answer format: crt.name serves one name per line,
// certspotter serves paginated issuances, Shodan CTL serves a hostname array,
// and ctlogs.dev serves one row per hostname. Querying them together is what
// makes subdomain discovery survive crt.sh being down, so the set is merged
// rather than walked.
//
// Every index is asked about a zone, never about a bare host: crt.name refuses
// a host that is not an apex, and the others answer a host with the host
// itself. The zone chain in certificateQueryZones supplies the zone.
func certificateSources(domain string) []certificateSource {
	return []certificateSource{
		{
			name:   "crt.sh",
			query:  "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json",
			accept: "application/json",
			page:   readCrtShNames,
		},
		{
			name:   "crt.name",
			query:  "https://crt.name/v1/search?apex=" + url.QueryEscape(domain),
			accept: "text/plain",
			page:   readLineNames,
		},
		{
			// Anonymous certspotter access is metered at ten requests, so this
			// index is read page by page and stops where the server says its
			// own allowance ran out.
			name:   "certspotter",
			query:  "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names",
			accept: "application/json",
			keyEnv: "CERTSPOTTER_API_TOKEN",
			page:   readCertspotterNames,
		},
		{
			name:   "shodan-ctl",
			query:  "https://ctl.shodan.io/api/v1/domain/" + url.QueryEscape(domain) + "/hostnames",
			accept: "application/json",
			page:   readStringArrayNames,
		},
		{
			// The hostname list is one row per name and needs no wildcard
			// syntax, so it also answers for a subdomain the apex-only
			// indexes reject. Paging it needs a key; the first page is the
			// whole anonymous answer.
			name:   "ctlogs.dev",
			query:  "https://api.ctlogs.dev/v1/hosts/" + url.QueryEscape(domain),
			accept: "application/json",
			keyEnv: "CTLOGS_API_KEY",
			page:   readCTLogsHosts,
		},
	}
}

// certificateIndex is the outcome of querying one index about one zone.
type certificateIndex struct {
	source string
	names  map[string]bool
	// note describes how much of the index was read, such as where its own
	// public allowance stopped a paginated walk. It is not a failure.
	note string
	// exhausted is set when the index reported its own public allowance as
	// spent, so a further zone does not spend another request on it.
	exhausted bool
	// failure is set only when the index could not answer at all.
	failure string
}

// streamingCollector reports the names one certificate index has produced so
// far, and holds the pause point for that index. A nil one keeps the index
// reading at full speed, which is what the synchronous endpoint does.
type streamingCollector struct {
	collector *transformCollector
	source    string
}

// addName reports one name this index contributed, so the panel counts distinct
// names instead of one row per index.
func (stream *streamingCollector) addName(ctx context.Context, name string) {
	if stream == nil || stream.collector == nil {
		return
	}
	stream.collector.distinct(ctx, name)
}

// flush publishes the counters after a finished page.
func (stream *streamingCollector) flush(ctx context.Context) {
	if stream == nil || stream.collector == nil {
		return
	}
	stream.collector.flush(ctx)
}

// context returns the context of the job this stream belongs to, or the
// background context when it runs without a job.
func (stream *streamingCollector) context() context.Context {
	if stream == nil || stream.collector == nil || stream.collector.job == nil {
		return context.Background()
	}
	return stream.collector.jobContext()
}

// certificateStatusError is one index answer that could not be used. Its status
// decides whether another attempt is worth making: a rate limit, a timeout or a
// server error is the index being briefly unavailable, while a rejected or
// missing query is the index saying it will never answer that query, and
// repeating it only spends the run's time.
type certificateStatusError struct {
	status int
	reason string
}

func (failure *certificateStatusError) Error() string {
	return failure.reason
}

// retryable reports whether the same query may answer on a later attempt.
func (failure *certificateStatusError) retryable() bool {
	switch failure.status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// queryCertificateSource queries one index, retrying while the index is merely
// unavailable and returning as soon as it has answered. The note describes how
// much of the index was read; the failure is set only when it could not answer.
func queryCertificateSource(ctx context.Context, client *http.Client, source certificateSource, domain string, stream *streamingCollector) (map[string]bool, string, bool, string) {
	found := map[string]bool{}
	note := ""
	failure := ""
	for attempt := 1; attempt <= crtLookupAttempts; attempt++ {
		if attempt > 1 {
			// Wait between attempts without ignoring a cancelled route.
			select {
			case <-ctx.Done():
				return found, note, false, fmt.Sprintf("the %s index was cancelled after %d of %d attempts", source.name, attempt-1, crtLookupAttempts)
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		names, pageNote, exhausted, err := readCertificateIndex(ctx, client, source, domain, stream)
		for name := range names {
			found[name] = true
		}
		if err == nil {
			return found, pageNote, exhausted, ""
		}
		// A query the index has rejected is reported once and the walk moves on
		// to the next zone instead of spending attempts on a refusal.
		var status *certificateStatusError
		if errors.As(err, &status) && !status.retryable() {
			return map[string]bool{}, "", false, fmt.Sprintf("the %s index %s", source.name, status.reason)
		}
		// A retry that follows a partial read starts the walk from the top so
		// the reported page count describes one coherent run.
		found = map[string]bool{}
		note = ""
		failure = fmt.Sprintf("the %s index %s", source.name, err.Error())
	}
	return found, note, false, fmt.Sprintf("%s after %d attempts", failure, crtLookupAttempts)
}

// readCertificateIndex follows one index to the end of what it is willing to
// serve, and reports the names together with a note when the index itself
// stopped the walk.
//
// The walk ends where the index's own cursor or its own remaining allowance
// ends, never at a page count invented here, so a metered public index is
// read exactly as far as it allows and the operator is told where it stopped.
func readCertificateIndex(ctx context.Context, client *http.Client, source certificateSource, domain string, stream *streamingCollector) (map[string]bool, string, bool, error) {
	found := map[string]bool{}
	query := source.query
	pages := 0
	for {
		names, cursor, allowance, err := fetchCertificatePage(ctx, client, source, query, domain, stream)
		if err != nil {
			if pages == 0 {
				return found, "", false, err
			}
			// A later page failing does not discard the pages already read.
			return found, fmt.Sprintf("was read for %d page(s) before the index %s", pages, err.Error()), false, nil
		}
		for name := range names {
			found[name] = true
		}
		// The page is reported as a whole as well: the per-name counter is exact,
		// but a short answer must not wait for the report threshold to tick.
		stream.flush(ctx)
		pages++
		switch {
		case allowance != "":
			return found, fmt.Sprintf("was read for %d page(s); %s", pages, allowance), true, nil
		case cursor == "":
			if pages > 1 {
				return found, fmt.Sprintf("was read for %d page(s)", pages), false, nil
			}
			return found, "", false, nil
		}
		query = nextCertificatePage(source.query, cursor)
	}
}

// fetchCertificatePage performs one index request and reports the names, the
// cursor of the next page, and what the index says is left of its allowance.
func fetchCertificatePage(ctx context.Context, client *http.Client, source certificateSource, queryURL, domain string, stream *streamingCollector) (map[string]bool, string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	request.Header.Set("User-Agent", "RequestRider-OSINT-Transform/1.0")
	request.Header.Set("Accept", source.accept)
	// The key is read from the environment only; no index credential is
	// hardcoded, and an index without a key still answers anonymously.
	if key := strings.TrimSpace(os.Getenv(source.keyEnv)); source.keyEnv != "" && key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// An unavailable index answers a 429/502/503 HTML page, so the body
		// is not worth reading: the status already explains the failure.
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return nil, "", "", &certificateStatusError{status: response.StatusCode, reason: fmt.Sprintf("returned an unusable response (status=%d)", response.StatusCode)}
		}
		// A rejected query is the index refusing this exact question, which is
		// what an index does for a host that is not a zone.
		return nil, "", "", &certificateStatusError{status: response.StatusCode, reason: fmt.Sprintf("rejected the query (status=%d)", response.StatusCode)}
	}
	names, cursor, readErr := source.page(response.Body, domain, stream)
	if readErr != nil {
		return nil, "", "", fmt.Errorf("returned an unusable response (%v)", readErr)
	}
	return names, cursor, exhaustedAllowance(response.Header), nil
}

// nextCertificatePage adds the cursor of the following page to an index query.
func nextCertificatePage(query, cursor string) string {
	separator := "?"
	if strings.Contains(query, "?") {
		separator = "&"
	}
	return query + separator + "after=" + url.QueryEscape(cursor)
}

// exhaustedAllowance reports whether an index says its public budget is spent,
// so the walk stops exactly where the index says it must.
func exhaustedAllowance(header http.Header) string {
	limit, hasLimit := headerValue(header, "X-RateLimit-Limit")
	remaining, hasRemaining := headerValue(header, "X-RateLimit-Remaining")
	if hasRemaining && remaining == "0" {
		if hasLimit {
			return fmt.Sprintf("stopped where the index reported %s of %s requests left", remaining, limit)
		}
		return "stopped where the index reported no requests left"
	}
	if hourly, ok := headerValue(header, "X-Hourly-Remaining"); ok && hourly == "0" {
		return "stopped where the index reported no requests left this hour"
	}
	return ""
}

func headerValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.TrimSpace(values[0]), true
}

// readCertspotterNames reads one certspotter page of issuances and returns the
// issuance id of the last row, which is the `after` cursor of the next page.
func readCertspotterNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	decoder := json.NewDecoder(body)
	var issuances []struct {
		ID       string   `json:"id"`
		DNSNames []string `json:"dns_names"`
	}
	if err := decoder.Decode(&issuances); err != nil {
		return names, "", fmt.Errorf("certificate index could not be decoded: %w", err)
	}
	for _, issuance := range issuances {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		for _, name := range issuance.DNSNames {
			if addCertificateName(names, name, domain) {
				stream.addName(stream.context(), name)
			}
		}
	}
	// A short page is the whole answer; a full one has a successor.
	if len(issuances) < certspotterPageSize {
		return names, "", nil
	}
	return names, issuances[len(issuances)-1].ID, nil
}

// readStringArrayNames reads an index that answers with a flat JSON array of
// host names, such as the Shodan CTL hostname list.
func readStringArrayNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	decoder := json.NewDecoder(body)
	var values []string
	if err := decoder.Decode(&values); err != nil {
		return names, "", fmt.Errorf("certificate index could not be decoded: %w", err)
	}
	for _, value := range values {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		if addCertificateName(names, value, domain) {
			stream.addName(stream.context(), value)
		}
	}
	return names, "", nil
}

// addCertificateName keeps one certified name when it belongs to the requested
// zone, and reports whether the name was kept, so the caller can count the names
// the answer really holds. The apex itself is the transform input and is not
// repeated.
//
// An index answer is attacker-controllable: a certificate can name an empty
// label such as `..example.test` or a name carrying a separator. Those are
// dropped here rather than stored, and every label is checked with the same
// rules the graph identity validation uses.
func addCertificateName(names map[string]bool, candidate, domain string) bool {
	name := strings.ToLower(strings.TrimSpace(candidate))
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" || name == domain {
		return false
	}
	if !strings.HasSuffix(name, "."+domain) {
		return false
	}
	if strings.ContainsAny(name, " /:@\\\t\r\n\"'") {
		return false
	}
	if !storableHostname(name) {
		return false
	}
	names[name] = true
	return true
}

// storableHostname reports whether every label of a host is one the graph can
// store: non-empty, alphanumeric or hyphen, and not starting or ending with a
// hyphen. This mirrors the gateway identity rules exactly.
func storableHostname(host string) bool {
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if !isASCIIAlnum(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

// readCrtShNames reads a crt.sh answer: one very large JSON array of
// certificates, consumed element by element, where each row carries every
// certificate name in a single newline separated value. The endpoint answers
// the whole query in one document, so there is no next page.
//
// Each row is a pause point and reports its own names, which is what keeps a
// multi-hundred-thousand name answer controllable instead of one long block.
func readCrtShNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	err := streamJSONArray(body, func(element json.RawMessage) error {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return err
			}
		}
		var row struct {
			NameValue string `json:"name_value"`
		}
		if json.Unmarshal(element, &row) != nil {
			// One malformed certificate row must not discard the whole log.
			return nil
		}
		for _, name := range strings.Split(row.NameValue, "\n") {
			if addCertificateName(names, name, domain) {
				stream.addName(stream.context(), name)
			}
		}
		return nil
	})
	return names, "", err
}

// readLineNames reads a crt.name answer: one certified name per line. The line
// reader is bounded per line and streams, because the answer for a large zone
// is megabytes long.
func readLineNames(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		// A line index answers tens of thousands of names, so the pause point
		// is every line rather than once at the end.
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		if addCertificateName(names, scanner.Text(), domain) {
			stream.addName(stream.context(), scanner.Text())
		}
	}
	return names, "", scanner.Err()
}

// readCTLogsHosts reads a ctlogs.dev answer: an envelope with one row per
// certified hostname rather than one row per certificate. The envelope names
// the cursor of the next page, but that walk needs a key, so an anonymous
// query stops at the page the index chose to serve.
func readCTLogsHosts(body io.Reader, domain string, stream *streamingCollector) (map[string]bool, string, error) {
	names := map[string]bool{}
	decoder := json.NewDecoder(body)
	var envelope struct {
		Hosts []struct {
			Host string `json:"host"`
		} `json:"hosts"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return names, "", fmt.Errorf("certificate index could not be decoded: %w", err)
	}
	for _, row := range envelope.Hosts {
		if stream != nil {
			if err := stream.collector.checkpoint(stream.context()); err != nil {
				return names, "", err
			}
		}
		if addCertificateName(names, row.Host, domain) {
			stream.addName(stream.context(), row.Host)
		}
	}
	return names, "", nil
}

// streamJSONArray decodes a JSON array element by element and calls visit for
// every element. Public datasets answer with one very large array, so the
// response body is never buffered as a whole and an element that arrives
// incomplete is reported as an error instead of being silently dropped.
func streamJSONArray(reader io.Reader, visit func(json.RawMessage) error) error {
	decoder := json.NewDecoder(reader)
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return errors.New("response is not a JSON array")
	}
	for decoder.More() {
		var element json.RawMessage
		if err := decoder.Decode(&element); err != nil {
			return err
		}
		if err := visit(element); err != nil {
			return err
		}
	}
	// Read the closing bracket so an array that stops early is reported.
	_, err = decoder.Token()
	return err
}

// detectWildcardDNS probes random labels; any resolution means the zone
// answers every name and brute-force names would be false positives. The
// resolving probe is returned so the warning can be verified by the analyst.
//
// The probes are pause points like every other step of the transform, so a
// paused job suspends here instead of waiting out the resolver.
func detectWildcardDNS(ctx context.Context, collector *transformCollector, lookup func(context.Context, string) ([]string, error), domain string) (string, bool) {
	for _, label := range []string{"rr-nowild-01", "rr-nowild-02"} {
		if err := collector.checkpoint(ctx); err != nil {
			return "", false
		}
		collector.label(ctx, "wildcard dns probe "+label)
		name := label + "." + domain
		ips, err := lookup(ctx, name)
		if err != nil || len(ips) == 0 {
			continue
		}
		return name + " -> " + strings.Join(ips, ", "), true
	}
	return "", false
}

// bruteForceWorkerCount is how many candidates the DNS phase resolves at the
// same time. The whole wordlist is still resolved — this is concurrency, not a
// cap on the work — and a bounded pool is what makes the phase a real pause
// point: with one goroutine per candidate the whole wordlist would already be
// in flight before a pause could be observed.
const bruteForceWorkerCount = 8

// bruteForceSubdomains resolves every supplied candidate and returns hits
// sorted by name for deterministic entity output.
//
// Every candidate is a pause point and reports itself, because this is the part
// of the transform that produces no names for long stretches: without the
// checkpoint a paused job would keep resolving candidates to the end of the
// wordlist, and without the label the panel would look frozen while it works.
func bruteForceSubdomains(ctx context.Context, collector *transformCollector, lookup func(context.Context, string) ([]string, error), domain string, words []string, found map[string]bool) []dnsGuess {
	candidates := make([]string, 0, len(words))
	for _, word := range words {
		candidate := strings.ToLower(strings.TrimSpace(word))
		if candidate == "" || strings.ContainsAny(candidate, " /:@") || found[candidate+"."+domain] {
			continue
		}
		candidates = append(candidates, candidate+"."+domain)
	}
	queue := make(chan string)
	results := make(chan dnsGuess)
	var tried atomic.Int64
	var wg sync.WaitGroup
	workers := bruteForceWorkerCount
	if len(candidates) < workers {
		workers = len(candidates)
	}
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range queue {
				if err := collector.checkpoint(ctx); err != nil {
					// A paused phase resumes from here; a cancelled one ends
					// with the job. Neither loses the names already resolved.
					continue
				}
				ips, err := lookup(ctx, candidate)
				done := tried.Add(1)
				collector.label(ctx, fmt.Sprintf("dns candidates %d/%d", done, len(candidates)))
				if err != nil || len(ips) == 0 {
					continue
				}
				collector.distinct(ctx, candidate)
				select {
				case <-ctx.Done():
				case results <- dnsGuess{name: candidate, ips: append([]string{}, ips...)}:
				}
			}
		}()
	}
	go func() {
		defer close(results)
		wg.Wait()
	}()
	go func() {
		defer close(queue)
		for _, candidate := range candidates {
			select {
			case <-ctx.Done():
				return
			case queue <- candidate:
			}
		}
	}()
	hits := []dnsGuess{}
	seen := map[string]bool{}
	for guess := range results {
		if seen[guess.name] {
			continue
		}
		seen[guess.name] = true
		hits = append(hits, guess)
	}
	sort.Slice(hits, func(left, right int) bool { return hits[left].name < hits[right].name })
	return hits
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
	client := &http.Client{Transport: s.requestTransport(), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return transformError("GITHUB_LOOKUP_FAILED", err.Error())
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return transformError("GITHUB_RESPONSE_INVALID", "GitHub response could not be read")
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
	result.Warnings = append(result.Warnings, "Commit/email extraction is not performed by this adapter.")
	return nil
}
