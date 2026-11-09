// `http_probe`: an httpx run as an OSINT graph transform.
//
// # What this is
//
// httpx answers one question — "what is actually serving this host" — with
// fields a graph can hold: the URL that answered, the status, the address the
// host resolved to, the technologies it announces, the CDN in front of it. This
// file turns one httpx run into entities and relations, so the answer lands in
// the Project graph next to everything else the graph already knows.
//
// # Why a binary and not a library import
//
// The decision is recorded in `reconciliation/httpx_reconciliation.md` and was
// measured, not assumed: importing `runner` drags in `dit` (an external ML
// classifier), `asnmap`, `mapcidr`, `wappalyzergo`, `pdcp` (which uploads to a
// cloud bucket) and `internal/db` (mongo, postgres, mysql). None of that
// belongs anywhere near `/api/*`, the passive proxy, SSE or the broker
// consumer.
//
// # Why the passive proxy is not optional
//
// AGENTS.md requires every tool's traffic to be recorded by the same passive
// proxy, so the evidence from a probe reaches Traffic and History exactly as a
// Repeater request does. Measured 2026-10-03: `-http-proxy` sends httpx through
// our MITM with no extra configuration and its exchanges appear in the Traffic
// Store.
//
// # What is deliberately not claimed
//
// httpx reports what the host answered at the moment of the run. A `200` here
// is not evidence the host is up now, and a `failed` probe is not evidence it
// was ever down. Both are recorded with `observed_at` and the status httpx
// gave, so a later probe can contradict an earlier one instead of overwriting
// it silently.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// httpxBinary resolves the httpx binary.
//
// The lookup is done relative to the engine executable, not from `PATH`, because
// `bin/` is where the project keeps tool binaries and a `PATH` lookup would
// silently pick up a different httpx from the system. A missing binary is named
// with the path that was tried, so the operator does not have to guess which of
// the two failure modes happened.
func httpxBinary() (string, error) {
	if override := strings.TrimSpace(os.Getenv("RR_HTTPX_BIN")); override != "" {
		return override, nil
	}
	// Four places, in the order they are most likely to be right.
	//
	// The parent-directory candidates are not defensive padding: the engine
	// binary is built into `engine/` and is routinely run from there, while the
	// project's tool binaries live in `bin/` at the repository root. Without them
	// a transform that works from the root fails from `engine/`, and the failure
	// reads as "the tool was never installed".
	candidates := []string{filepath.Join("bin", "httpx")}
	if working, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(working, "bin", "httpx"),
			filepath.Join(working, "..", "bin", "httpx"))
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		candidates = append([]string{
			filepath.Join(directory, "bin", "httpx"),
			filepath.Join(directory, "..", "bin", "httpx"),
		}, candidates...)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	// The message names what to run, not only where it looked. `bin/` is
	// gitignored, so a fresh checkout genuinely has no httpx, and "not found at
	// these four paths" leaves the operator to guess that the answer is a build.
	return "", transformError("HTTPX_BINARY_MISSING",
		"httpx binary not found; looked at "+strings.Join(candidates, ", ")+
			". Build it with ./start.sh (step 4b), or put the binary at bin/httpx, "+
			"or point RR_HTTPX_BIN at one")
}

// runHTTPProbe probes the operator's host with httpx and records what answered.
//
// The transform is a `network: true` one, so `transformApplicabilityError` has
// already refused the run without `ConfirmNetwork` by the time this is called.
// The check is repeated here anyway, for the same reason
// `runTechnologyProbe` repeats it: a direct call, a background job and the
// synchronous endpoint must all refuse the same values.
func (s *server) runHTTPProbe(ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "a host probe reaches the host")
	}
	target := strings.TrimSpace(input.Value)
	if target == "" {
		return transformError("INVALID_HOST", "the host to probe must not be empty")
	}
	// The registry says this transform accepts `url` as well as `domain`, so a URL
	// has to be accepted — including one with a path. Rejecting the slash threw
	// away a capability the same file declares; measured, because the end-to-end
	// test passes `http://localhost:PORT/` and got `INVALID_HOST` back.
	//
	// What is still refused is a bare path with no host (`/etc/passwd`) and
	// anything carrying whitespace or a backslash, because neither names a host
	// and both are how a value turns into something the probe was not asked for.
	if !validProbeTarget(target) {
		return transformError("INVALID_HOST",
			"the probe takes a host such as www.example.test, or a URL such as https://www.example.test/")
	}

	binary, err := httpxBinary()
	if err != nil {
		return err
	}
	result.LocalOnly, result.NetworkUsed = false, true

	arguments := httpxArguments(target, s.passiveProxyURL())
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return transformError("HTTPX_START_FAILED", err.Error())
	}
	if err := command.Start(); err != nil {
		return transformError("HTTPX_START_FAILED",
			fmt.Sprintf("%s could not start: %s", binary, err.Error()))
	}

	// httpx is terminated by the context, but a tool that ignores SIGTERM would
	// leave the job running forever, and the operator's only way out would be to
	// kill the engine. SIGKILL after a grace period is what makes cancellation
	// real rather than advisory.
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = command.Wait()
	}()
	defer func() {
		select {
		case <-finished:
		case <-time.After(httpxShutdownGrace):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			<-finished
		}
	}()

	observed, streamErr := applyHTTPProbeStream(ctx, result, stdout, collector)
	if streamErr != nil {
		result.Warnings = append(result.Warnings, "httpx output ended early: "+streamErr.Error())
	}
	if observed == 0 {
		// An empty run is not a result. httpx answering nothing means the host
		// was not reached or produced no JSON line, and reporting an empty
		// success would read as "the host has no web service", which the probe
		// never established.
		return transformError("HTTPX_NO_RESULT", "httpx produced no result for "+target)
	}

	setTransformMetadata(result, "http_probe_binary", binary)
	setTransformMetadata(result, "http_probe_records", observed)
	setTransformMetadata(result, "http_probe_args", strings.Join(arguments, " "))
	return nil
}

// # Why one host can produce several records, and why they are merged
//
// Measured against a live `.ru` target 2026-10-03: a single probe of
// `https://ria.ru/` returns **two** JSONL records — `https://ria.ru/` and
// `https://ria.ru` — and both carry the same host, the same status and the same
// technologies. httpx probes the URL as given and the URL after the redirect
// chain normalises the empty path away.
//
// Left alone, that is two `domain` entities with one identity in one result. The
// graph upsert is idempotent per identity, so nothing breaks and nothing is
// visible — which is exactly why it is worth fixing: the second write silently
// decides which of the two records the graph keeps, and the operator has no way
// to know that a choice was made for them.
//
// Merging is by identity, not by URL: the URL is a property, and two probes that
// differ only in a trailing slash are the same host.
func mergeProbeEntities(result *osintTransformResult) {
	merged := make([]transformEntity, 0, len(result.Entities))
	index := make(map[string]int, len(result.Entities))
	for _, item := range result.Entities {
		key := item.Type + "\x00" + item.Identity
		if at, seen := index[key]; seen {
			merged[at].Properties = mergeProbeProperties(merged[at].Properties, item.Properties)
			continue
		}
		index[key] = len(merged)
		merged = append(merged, item)
	}
	result.Entities = merged

	relations := make([]transformRelation, 0, len(result.Relations))
	seenRelation := make(map[string]bool, len(result.Relations))
	for _, relation := range result.Relations {
		key := relation.Type + "\x00" + relation.SourceType + "\x00" + relation.Source +
			"\x00" + relation.TargetType + "\x00" + relation.Target
		if seenRelation[key] {
			continue
		}
		seenRelation[key] = true
		relations = append(relations, relation)
	}
	result.Relations = relations
}

// mergeProbeProperties folds a second record's properties into the first.
//
// The first record wins for any key both carry, because it is the answer to the
// URL the operator typed and the later one is a normalised repeat of it. Lists
// are unioned instead, because `addresses` and `technologies` from two probes of
// the same host are two observations of one host rather than a disagreement.
func mergeProbeProperties(into, from map[string]interface{}) map[string]interface{} {
	if into == nil {
		return from
	}
	if from == nil {
		return into
	}
	for key, value := range from {
		existing, present := into[key]
		if !present {
			into[key] = value
			continue
		}
		existingList, existingOK := existing.([]string)
		valueList, valueOK := value.([]string)
		if existingOK && valueOK {
			for _, item := range valueList {
				if !slices.Contains(existingList, item) {
					existingList = append(existingList, item)
				}
			}
			into[key] = existingList
		}
	}
	return into
}

// applyHTTPProbeStream reads httpx's JSONL and records every record it finds.
//
// The merge is the last step of this function rather than of `runHTTPProbe`, and
// that placement is what makes it testable: httpx returns two records for one
// host only over https, so an end-to-end test against a local http fixture never
// sees the case, and a merge that lived in the caller would go untested. Here it
// is part of "consume the stream", which a test can drive with two records.
//
// Measured on a live `.ru` target 2026-10-03: `https://ria.ru/` returned
// `https://ria.ru/` and `https://ria.ru`, both carrying the same host, status and
// technologies. Without the merge that is two `domain` entities with one
// identity, and the graph upsert silently decides which record survives.
func applyHTTPProbeStream(ctx context.Context, result *osintTransformResult, stream io.Reader, collector *transformCollector) (int, error) {
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	observed := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var record runner.Result
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			// A line that is not JSON is not a failure of the probe: httpx writes
			// banners and progress lines to the same stream on some builds. It is
			// reported so a run is never reported as having read nothing at all.
			result.Warnings = append(result.Warnings, "httpx wrote a line that is not JSON: "+truncateForWarning(line))
			continue
		}
		if collector != nil {
			if err := collector.checkpoint(ctx); err != nil {
				return observed, err
			}
		}
		observed++
		appendHTTPProbeRecord(ctx, result, record, collector)
	}
	mergeProbeEntities(result)
	return observed, scanner.Err()
}

// httpxShutdownGrace is how long httpx is given to exit on its own after the
// context is cancelled before it is killed.
const httpxShutdownGrace = 5 * time.Second

// httpxArguments builds the httpx invocation.
//
// The flags are chosen for evidence rather than for speed:
//
//   - `-json` so the answer is machine-readable rather than a table for a human
//     to read off a terminal;
//   - `-silent` so the banner does not arrive on the stream this code parses;
//   - `-no-color` so a redirected stream carries no escape sequences into JSON;
//   - `-follow-redirects` because a redirect that is never followed answers a
//     different question than "what is serving this host";
//   - `-tls-probe` and `-tech-detect` because the TLS certificate and the
//     announced technologies are half of what the transform exists to record;
//   - `-http-proxy` so the exchange is recorded by the same passive proxy every
//     other tool's traffic goes through.
func httpxArguments(target, proxyURL string) []string {
	arguments := []string{
		"-u", target,
		"-json",
		"-silent",
		"-no-color",
		"-follow-redirects",
		"-tls-probe",
		"-tech-detect",
		// httpx retries a host twice by default, and a retry is a second exchange
		// recorded as if it were the first. One attempt per run keeps the
		// evidence count equal to the number of hosts the operator asked about.
		"-retries", "0",
	}
	if proxyURL != "" {
		arguments = append(arguments, "-http-proxy", proxyURL)
	}
	return arguments
}

// passiveProxyURL returns the address of our own passive proxy.
//
// It is read from the same variable the engine binds its proxy to, so a stack
// on non-default ports probes through its own proxy rather than a hard-coded
// 8080 that belongs to another session's stack.
func (s *server) passiveProxyURL() string {
	// `RR_PASSIVE_PROXY_URL` wins over `PROXY_LISTEN_ADDR` because it can say
	// "this is a complete URL" in one variable, which is what a stack on a
	// non-default port and a test both need. Without it a stack whose proxy
	// listens on `127.0.0.1:8180` still has to be expressed as a bare address,
	// and the probe has to guess the scheme.
	if override := strings.TrimSpace(os.Getenv("RR_PASSIVE_PROXY_URL")); override != "" {
		return override
	}
	address := strings.TrimSpace(envOrDefault("PROXY_LISTEN_ADDR", "127.0.0.1:8080"))
	if address == "" {
		return ""
	}
	if strings.HasPrefix(address, "http://") || strings.HasPrefix(address, "https://") {
		return address
	}
	return "http://" + address
}

// appendHTTPProbeRecord turns one httpx record into entities and relations.
//
// Everything the record claims is copied with its own evidence rather than
// flattened: a technology is only as good as the fact that produced it, so the
// host it was announced on, the URL that answered and the moment are all kept on
// the entity.
func appendHTTPProbeRecord(ctx context.Context, result *osintTransformResult, record runner.Result, collector *transformCollector) {
	provenance := map[string]interface{}{"source": "http_probe"}

	// # Which field is the host, and why the order matters
	//
	// httpx fills `Host` with the address it actually reached, not with the name
	// that was asked for: a probe of `www.example.test` that resolved to
	// 93.184.216.34 reports `"host":"93.184.216.34"` and `"input":"www.example.test"`.
	//
	// Taking `Host` first therefore produced a `domain` entity whose identity was
	// an IP address, and a `resolves_to` relation from that IP to itself. Measured
	// on captured output before this fix; caught by
	// `TestHTTPProbeTurnsARecordIntoGraphFacts`, which asks for the entity by the
	// name the operator typed.
	//
	// The order is: the name the operator gave, then the name in the URL that
	// answered, and only then `Host` — and an address is never written into a
	// `domain` entity, because it is already an `ip` entity in the same record.
	// `Input` is what the operator typed: a bare host when they typed one, and a
	// whole URL when they typed that. A URL is reduced to its host, so a probe of
	// `https://example.test/a/b` still produces the entity `example.test`.
	host := strings.ToLower(strings.TrimSpace(firstNonEmptyString(record.Input, record.SNI)))
	if strings.Contains(host, "://") {
		host = hostFromProbeURL(host)
	}
	if host == "" {
		host = hostFromProbeURL(record.URL)
	}
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(record.Host))
	}
	host = probeDomainName(host)
	if isProbeAddress(host) {
		// The only identity left is an address. It is recorded as an address by
		// the addresses loop below, so there is no domain to attach properties to.
		//
		// The port has to come off before the check: `net.ParseIP("198.51.100.7:8443")`
		// is nil, so a probe of a bare address on a non-default port used to produce
		// a `domain` entity whose identity was `198.51.100.7:8443`. Measured, and
		// caught by `TestHTTPProbeRecordsAnEndpointWhenThereIsNoHost`.
		host = ""
	}

	addresses := append([]string{}, record.A...)
	addresses = append(addresses, record.AAAA...)
	uniqueAddresses := make([]string, 0, len(addresses))
	seenAddress := map[string]bool{}
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" || seenAddress[address] {
			continue
		}
		seenAddress[address] = true
		uniqueAddresses = append(uniqueAddresses, address)
	}

	properties := map[string]interface{}{"source": "http_probe"}
	if probed := strings.TrimSpace(record.URL); probed != "" {
		properties["url"] = probed
	}
	if record.StatusCode != 0 {
		properties["status"] = record.StatusCode
	}
	if record.WebServer != "" {
		properties["webserver"] = record.WebServer
	}
	if record.ContentType != "" {
		properties["content_type"] = record.ContentType
	}
	if record.Title != "" {
		properties["title"] = record.Title
	}
	// `CDN` is a bool in httpx ("was a CDN matched"), `CDNName` is which one.
	// Recording the bool alone would say "yes, a CDN" without saying which, and
	// the name is the whole point of running a CDN classifier.
	if record.CDNName != "" {
		properties["cdn"] = record.CDNName
	}
	if record.CDNType != "" {
		properties["cdn_type"] = record.CDNType
	}
	if len(record.Technologies) > 0 {
		properties["technologies"] = record.Technologies
	}
	if record.ResponseTime != "" {
		properties["response_time"] = record.ResponseTime
	}
	if record.ContentLength != 0 {
		properties["content_length"] = record.ContentLength
	}
	if record.Words != 0 || record.Lines != 0 {
		properties["words"] = record.Words
		properties["lines"] = record.Lines
	}
	if record.FinalURL != "" {
		properties["final_url"] = record.FinalURL
	}
	if record.Location != "" {
		properties["location"] = record.Location
	}
	if record.JarmHash != "" {
		properties["jarm"] = record.JarmHash
	}
	// The TLS answer is the point of `-tls-probe`; whether it was read at all is
	// recorded so a host without a certificate is not read as a host whose
	// certificate was checked and found interesting.
	//
	// `TLSData.Chain` is leaf-first, so `Chain[0]` is the certificate the server
	// presented and the rest is the chain it presented it with. Only the leaf is
	// recorded: the intermediate certificates are a property of the CA's
	// deployment, not of this host, and copying them into the graph would make
	// every host look as though it carried its own CA chain.
	if record.TLSData != nil {
		properties["tls_read"] = true
		if record.TLSData.Version != "" {
			properties["tls_version"] = record.TLSData.Version
		}
		if record.TLSData.Cipher != "" {
			properties["tls_cipher"] = record.TLSData.Cipher
		}
		if record.TLSData.KeyExchange != "" {
			properties["tls_key_exchange"] = record.TLSData.KeyExchange
		}
		if record.TLSData.ServerName != "" {
			properties["tls_server_name"] = record.TLSData.ServerName
		}
		if record.TLSData.JarmHash != "" {
			properties["tls_jarm"] = record.TLSData.JarmHash
		}
		if record.TLSData.Ja3Hash != "" {
			properties["tls_ja3"] = record.TLSData.Ja3Hash
		}
		if !record.TLSData.ProbeStatus {
			properties["tls_probe_status"] = false
		}
		if record.TLSData.Error != "" {
			properties["tls_error"] = record.TLSData.Error
		}
		// The leaf certificate is `Chain[0]`, with the embedded copy as the
		// fallback for a response that carries the certificate but not the chain.
		var leaf *clients.CertificateResponse
		if len(record.TLSData.Chain) > 0 {
			leaf = record.TLSData.Chain[0]
		} else {
			leaf = record.TLSData.CertificateResponse
		}
		if leaf != nil {
			properties["tls_expired"] = leaf.Expired
			properties["tls_self_signed"] = leaf.SelfSigned
			properties["tls_mismatched"] = leaf.MisMatched
			if leaf.WildCardCert {
				properties["tls_wildcard"] = true
			}
			if leaf.SubjectCN != "" {
				properties["tls_subject_cn"] = leaf.SubjectCN
			}
			if leaf.IssuerCN != "" {
				properties["tls_issuer_cn"] = leaf.IssuerCN
			}
			if len(leaf.Domains) > 0 {
				properties["tls_domains"] = leaf.Domains
			}
			if len(leaf.Emails) > 0 {
				properties["tls_emails"] = leaf.Emails
			}
			if !leaf.NotBefore.IsZero() {
				properties["tls_not_before"] = leaf.NotBefore.UTC().Format(time.RFC3339)
			}
			if !leaf.NotAfter.IsZero() {
				properties["tls_not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
			}
		}
	}
	if len(uniqueAddresses) > 0 {
		properties["addresses"] = uniqueAddresses
	}
	if len(record.CNAMEs) > 0 {
		properties["cname"] = record.CNAMEs
	}
	if record.HostIP != "" {
		properties["host_ip"] = record.HostIP
	}
	if chain := record.ChainStatusCodes; len(chain) > 0 {
		properties["redirect_status_codes"] = chain
	}
	if record.Failed {
		properties["failed"] = true
		if record.Error != "" {
			properties["error"] = record.Error
		}
	}

	// The properties are attached to the domain when there is one. When httpx
	// answered for a bare address there is no domain, and the facts still have to
	// land somewhere: they go on an `endpoint` entity keyed by the URL, so a probe
	// of a raw address is not reported as an empty success.
	// `record.URL` is trimmed before it can become an identity: a value of "  "
	// is not empty, and an entity the graph cannot address is worse than no
	// entity. Caught by `TestHTTPProbeNeverEmitsAnEmptyIdentity`.
	probedURL := strings.TrimSpace(record.URL)
	if host == "" && probedURL != "" {
		result.Entities = append(result.Entities, entity("endpoint", probedURL, properties, provenance))
	}
	if host != "" {
		result.Entities = append(result.Entities, entity("domain", host, properties, provenance))
		for _, address := range uniqueAddresses {
			result.Entities = append(result.Entities, entity("ip", address, nil, provenance))
			result.Relations = append(result.Relations, transformRelation{
				Type: "resolves_to", SourceType: "domain", Source: host,
				TargetType: "ip", Target: address,
				Provenance: provenance,
			})
			if collector != nil {
				collector.distinct(ctx, address)
			}
		}
		for _, technology := range record.Technologies {
			technology = strings.TrimSpace(technology)
			if technology == "" {
				continue
			}
			result.Entities = append(result.Entities, entity("technology", technology,
				map[string]interface{}{"source": "http_probe", "host": host, "url": strings.TrimSpace(record.URL)},
				provenance))
			result.Relations = append(result.Relations, transformRelation{
				Type: "uses", SourceType: "domain", Source: host,
				TargetType: "technology", Target: technology,
				Provenance: provenance,
			})
		}
	}
}

// isProbeAddress answers whether an httpx host identity is an address rather
// than a name.
//
// The port is stripped first, with IPv6 brackets honoured, because httpx reports
// a bare address with its port when the port is not the scheme default.
// validProbeTarget answers whether a value names a host or a URL.
//
// A value with a scheme is parsed rather than pattern-matched, because that is
// the only way to tell `https://example.test/a/b` (a URL, and accepted) from
// `example.test/a/b` (a path with no host, and refused).
func validProbeTarget(value string) bool {
	if value == "" || strings.ContainsAny(value, " \t\n\\") {
		return false
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		return err == nil && parsed.Host != ""
	}
	if strings.HasPrefix(value, "/") {
		return false
	}
	// A bare value is a host, so a slash in it means a path was typed without a
	// scheme. `example.test/admin` is one: httpx accepts it, runs against it, and
	// answers nothing, so the operator would get `HTTPX_NO_RESULT` for a value
	// that was never a host. Measured by `TestHTTPProbeRefusesAValueThatIsNotAHost`.
	if strings.Contains(value, "/") {
		return false
	}
	// A bare host may carry a port, and an IPv6 literal is written in brackets.
	if strings.HasPrefix(value, "[") {
		return strings.Contains(value, "]")
	}
	return !strings.Contains(value, " ")
}

// probeDomainName strips the port from a host identity.
//
// httpx fills `Input` with the normalised target, port included, so a probe of
// `http://localhost:44841/` reports `input: "localhost:44841"`. Written into a
// `domain` entity unchanged, the port makes the identity a different host from
// the one the operator means, and the graph then holds `localhost` and
// `localhost:44841` as two domains. Measured in the end-to-end test.
//
// An IPv6 literal is left alone: stripping its last segment would turn
// `[::1]:8443` into `[::1]` by accident and `2001:db8::1` into nothing useful,
// and it is already recognised as an address rather than a name.
func probeDomainName(host string) string {
	if host == "" || strings.HasPrefix(host, "[") {
		return host
	}
	if colon := strings.LastIndex(host, ":"); colon > 0 && strings.Count(host, ":") == 1 {
		return host[:colon]
	}
	return host
}

func isProbeAddress(host string) bool {
	if host == "" {
		return false
	}
	candidate := host
	if strings.HasPrefix(candidate, "[") {
		if end := strings.Index(candidate, "]"); end > 0 {
			candidate = candidate[1:end]
		}
	} else if colon := strings.LastIndex(candidate, ":"); colon > 0 && strings.Count(candidate, ":") == 1 {
		candidate = candidate[:colon]
	}
	return net.ParseIP(candidate) != nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// hostFromProbeURL extracts a host from a URL httpx reported.
func hostFromProbeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	index := strings.Index(trimmed, "://")
	rest := trimmed[index+3:]
	if slash := strings.IndexAny(rest, "/?#"); slash >= 0 {
		rest = rest[:slash]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return strings.ToLower(rest)
}

func truncateForWarning(value string) string {
	const limit = 160
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
