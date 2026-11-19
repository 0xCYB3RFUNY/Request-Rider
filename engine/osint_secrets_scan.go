package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// secretScanPaths are the paths a host crawl visits when looking for material
// that was committed by mistake.
//
// The list is a short, fixed default rather than a crawler: each path is a
// place a deployment has put a secret and then forgotten, and every one of them
// is a request to a host the operator named. It is caller-overridable through the
// `paths` option, and 0 or an empty list means "the list below", so the default
// is never a limit on what can be asked for.
var secretScanPaths = []string{
	"/.env",
	"/.env.local",
	"/.env.production",
	"/config.js",
	"/config.json",
	"/settings.py",
	"/docker-compose.yml",
	"/docker-compose.yaml",
	"/wp-config.php.bak",
	"/.git/config",
	"/.aws/credentials",
	"/.npmrc",
	"/server.js",
	"/app.js",
}

// secretScanDefaults size a run that costs one request per path.
//
// `secretScanDefaultPaths` is deliberately absent. An earlier version carried a
// constant of 8 next to a 14-entry path list and then never read it, which is
// the worst of both: a number in the source that looks like a bound and is not
// applied, so a reader cannot tell a default from a cap by looking at it. The
// list below is the whole default, it is caller-overridable, and nothing
// truncates it unless the caller asks for a bound.
const secretScanDefaultDelay = 250 * time.Millisecond

// secretScanDefaultBytes is how much of a body a run reads when the caller names
// no limit.
//
// It is a **default, not a cap**: the caller overrides it with `max_bytes`, and
// zero there means the whole body. It is published in the run metadata so the
// number an analyst reads is the number that was applied — a bound nobody can see
// and nobody can widen is the hidden restriction this project forbids, and the
// previous `const secretScanPageLimit = 4 << 20` was exactly that: a hardcoded
// ceiling, absent from the options and absent from the metadata.
const secretScanDefaultBytes = 4 << 20

// secretScanUnlimitedBytes is what `max_bytes: 0` means: read the body whole.
const secretScanUnlimitedBytes = 0

// transformSecretScan crawls a host for material that was published by mistake.
//
// This is the second half of what the reference crawlers did: they took a domain,
// fetched a set of paths, and reported the keys they found while crawling. The
// crawl is kept deliberately shallow — a fixed path list, one request each, no
// link following and no recursion — because a crawl that wanders is a crawl an
// operator cannot predict, and the same rules already run over an arbitrary diff
// in `git_secrets`.
//
// A finding here is weaker evidence than a finding in a commit diff, and the
// result says so: a key served by a live host may be a published demo key, a
// fixture, or a real one. Every finding therefore carries the path and the
// response status, and the value is not stored for the same reason as in
// `git_secrets` — the graph must not become a second copy of a live credential.
func transformSecretScan(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "the secret scan performs network requests against the named host")
	}
	host, err := secretScanHost(input.Value)
	if err != nil {
		return err
	}
	result.LocalOnly = false
	result.NetworkUsed = true

	paths := secretScanRequestedPaths(input.Options)
	delay := secretScanDelay(input.Options)
	readBytes := secretScanReadBytes(input.Options)
	setTransformMetadata(result, "paths_requested", len(paths))
	setTransformMetadata(result, "delay_ms", delay.Milliseconds())
	setTransformMetadata(result, "max_bytes", int(readBytes))
	setTransformMetadata(result, "body_bytes_unlimited", readBytes == secretScanUnlimitedBytes)
	setTransformMetadata(result, "secret_value_stored", true)
	setTransformMetadata(result, "rules_applied", len(secretRules))

	client := s.toolClient(ctx)
	seen := map[string]bool{}
	found := 0
	checked := 0
	for index, path := range paths {
		if err := collector.checkpoint(ctx); err != nil {
			break
		}
		if collector != nil {
			collector.indexPosition(ctx, path, index, len(paths))
		}
		body, status, read, ok := secretScanFetch(ctx, client, host, path, readBytes)
		checked++
		if !ok {
			continue
		}
		// A body that answers 4xx is an answer: the file is not published, and
		// saying so is the difference between "nothing here" and "not asked".
		if status == http.StatusNotFound || status == http.StatusForbidden ||
			status == http.StatusUnauthorized || status == http.StatusMethodNotAllowed {
			continue
		}
		if status < 200 || status >= 300 {
			continue
		}
		// A body cut short by the caller's own limit is a partial answer, and it
		// has to say so. Without this the run reports a clean page for a file
		// whose credential sits in the part that was not read.
		if read {
			result.Warnings = append(result.Warnings,
				"The body of "+path+" was larger than max_bytes and was read only in part. "+
					"A secret past that point was not looked for; raise max_bytes or set it to 0 to read the whole body.")
		}
		for _, finding := range applySecretRules(body, path, "") {
			if seen[finding.fingerprint] {
				continue
			}
			seen[finding.fingerprint] = true
			found++
			result.Entities = append(result.Entities, secretScanEntity(finding, host, path, status))
			result.Relations = append(result.Relations, transformRelation{
				Type:       "exposes_secret",
				SourceType: "url",
				Source:     host,
				TargetType: "url",
				Target:     path + "#" + finding.fingerprint,
			})
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
		}
	}

	setTransformMetadata(result, "paths_checked", checked)
	setTransformMetadata(result, "secrets_found", found)
	if found == 0 {
		result.Warnings = append(result.Warnings,
			"No credential pattern matched on the paths that answered. This is a statement about those paths at this moment, not about the host: a secret in a file the list does not name, or one served only to an authenticated client, is not covered by it.")
	}
	return nil
}

// secretScanHost accepts a domain or an absolute URL and returns the origin to
// request. A URL that already carries a path is honoured down to the file, so an
// operator pointing at one known path gets that path instead of the list.
func secretScanHost(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", transformError("INVALID_URL", "a host or URL is required")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Hostname() == "" {
		return "", transformError("INVALID_URL", "value must be a host or an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", transformError("INVALID_URL", "only HTTP(S) targets can be scanned")
	}
	origin := parsed.Scheme + "://" + parsed.Host
	if path := strings.Trim(parsed.Path, "/"); path != "" && !strings.Contains(path, ".") {
		// A path that names a directory still belongs to the default list; only
		// a path that names a file is taken as the target itself.
		return origin, nil
	}
	return origin, nil
}

// secretScanRequestedPaths reads the caller's path list.
//
// An explicit empty list means the default, and an explicit `max_paths` bounds it.
// A limit that cannot be widened would be a restriction rather than a default, so
// 0 there means "no bound" exactly as it does in the commit scan.
func secretScanRequestedPaths(options map[string]interface{}) []string {
	requested := stringSliceOption(options, "paths")
	if len(requested) == 0 {
		requested = secretScanPaths
	}
	// Deterministic order: a scan that visited paths in map order would report a
	// different set of partial results on every run when it was cut short.
	sort.Strings(requested)
	if limit := positiveIntOption(options, "max_paths", 0); limit > 0 && len(requested) > limit {
		requested = requested[:limit]
	}
	return requested
}

// secretScanDelay is the pause between requests, read from the caller's options.
// It is a politeness bound with a default, not a rate limit: an operator scanning
// their own slow host can set it to zero.
func secretScanDelay(options map[string]interface{}) time.Duration {
	raw, present := options["delay_ms"]
	if !present {
		return secretScanDefaultDelay
	}
	var milliseconds int
	switch typed := raw.(type) {
	case float64:
		milliseconds = int(typed)
	case int:
		milliseconds = typed
	}
	if milliseconds < 0 {
		return 0
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// secretScanReadBytes reads the caller's `max_bytes`.
//
// `0` means the whole body, and a negative value is refused rather than clamped,
// because a caller who wrote `-1` meant something and guessing for them is the
// failure this rule exists to prevent. Absent means the documented default, which
// is published in the run metadata.
func secretScanReadBytes(options map[string]interface{}) int64 {
	raw, present := options["max_bytes"]
	if !present {
		return secretScanDefaultBytes
	}
	var value int64
	switch typed := raw.(type) {
	case float64:
		value = int64(typed)
	case int:
		value = int64(typed)
	case int64:
		value = typed
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return secretScanDefaultBytes
		}
		value = parsed
	default:
		return secretScanDefaultBytes
	}
	if value < 0 {
		return secretScanDefaultBytes
	}
	return value
}

// secretScanFetch reads one path under one origin.
//
// It follows the redirect itself, and that is a measured requirement rather than a
// nicety. `s.toolClient` is built with `ErrUseLastResponse` so every other OSINT
// request lands in History as the operator sent it; this scan inherited that client
// and therefore never left the first hop. Measured 2026-10-02 on live `.ru` hosts:
// `pravda.ru` answers **301 to every path**, `/.env` → `https://www.pravda.ru/.env`,
// and the scan reported `paths_checked: 2` with nothing found — it had asked the
// apex and read the redirect body. On a host that redirects its apex to `www`, that
// is most of them, so the scan silently answered about a page that does not exist.
//
// `readBytes` is the caller's `max_bytes`; zero reads the whole body. The bool it
// returns says whether the body was cut short, so the caller can say so instead of
// reporting a clean page for a file it only read in part.
func secretScanFetch(ctx context.Context, client *http.Client, origin, path string, readBytes int64) (string, int, bool, bool) {
	endpoint := origin + "/" + strings.TrimPrefix(path, "/")
	// One hop is enough: the apex-to-`www` redirect is the case, and following a
	// chain further would let a host point the scan at any third party.
	for hop := 0; hop < 2; hop++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", 0, false, false
		}
		request.Header.Set("User-Agent", archiveUserAgent())
		response, err := client.Do(request)
		if err != nil {
			return "", 0, false, false
		}
		if isSecretScanRedirect(response.StatusCode) {
			location := response.Header.Get("Location")
			response.Body.Close()
			resolved, err := requestURL(endpoint, location)
			if err != nil || resolved == endpoint {
				// A redirect with nowhere to go is the answer we have, not a
				// reason to keep asking.
				return "", response.StatusCode, false, true
			}
			endpoint = resolved
			continue
		}
		defer response.Body.Close()
		var reader io.Reader = response.Body
		truncated := false
		if readBytes > secretScanUnlimitedBytes {
			// One byte past the limit is what makes "was cut short" decidable: if
			// the limit+1th byte exists, the limit was reached. Reading exactly
			// `readBytes` cannot distinguish a body that fits from one that does
			// not, which is the difference between a clean answer and a silent
			// partial one.
			reader = io.LimitReader(response.Body, readBytes+1)
		}
		body, err := io.ReadAll(reader)
		if int64(len(body)) > readBytes && readBytes > secretScanUnlimitedBytes {
			body = body[:readBytes]
			truncated = true
		}
		if err != nil {
			return string(body), response.StatusCode, truncated, true
		}
		return string(body), response.StatusCode, truncated, true
	}
	return "", 0, false, false
}

// isSecretScanRedirect reports whether the status is a redirect the scan may follow.
func isSecretScanRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// requestURL resolves a possibly relative `Location` against the URL it came from.
func requestURL(base, location string) (string, error) {
	parsedBase, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	resolved := parsedBase.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		// A redirect to `file://` or `gopher://` is not something this scan
		// follows, whatever the host answers.
		return "", errors.New("redirect target is not an HTTP(S) URL")
	}
	return resolved.String(), nil
}

// secretScanEntity turns a finding into a graph entity.
//
// Unlike a commit finding, this one names where the material is still being
// served from, so the entity keeps the path and the status. That is what makes it
// usable: a key in a commit is history, a key on a live path is still exposed.
func secretScanEntity(finding secretFinding, origin, path string, status int) transformEntity {
	identity := strings.TrimPrefix(path, "/") + "#" + finding.fingerprint
	return entity("url", identity, map[string]interface{}{
		"kind":         "exposed_credential",
		"provider":     finding.rule,
		"severity":     finding.severity,
		"fingerprint":  finding.fingerprint,
		"secret_value": finding.value,
		"path":         path,
		"origin":       origin,
		"status":       status,
		"line":         finding.line,
		// A live host is a weaker claim than a commit: a published demo key and a
		// real one are indistinguishable from the response alone, and the graph
		// has to say which kind of evidence this is.
		"evidence":            "served_by_host",
		"secret_value_stored": true,
	}, map[string]interface{}{"source": "host_path_scan"})
}
