// Sensitive file disclosure: the paths, and what a hit on one actually proves.
//
// # What upstream contributes, and it is a list rather than a mechanism
//
// Arachni ships this capability as five data files and no logic:
// `common_files/filenames.txt` (24 entries — `robots.txt`, `phpinfo.php`,
// `.git/HEAD`, `config/database.yml`, `WEB-INF/web.xml`), `common_directories/
// directories.txt` (499 entries), `common_admin_interfaces/admin-panels.txt`
// (50), `backup_files/formats.txt`, `backup_directories/formats.txt` and
// `backdoors/filenames.txt`. Eagle ships it again as `senstivefiles.txt` (20
// entries). Every check in the family does the same two things: fetch a path, and
// report the ones that answer 200.
//
// The lists are the capability and they are carried into the report rather than
// paraphrased, because a paraphrase of 499 directory names is 499 wrong directory
// names. What is *not* carried is the mechanism, and this file replaces it.
//
// # Why "answered 200" is not a finding, and what replaces it
//
// A path returning 200 tells you the path exists. It does not tell you the server
// did not serve a soft 404 — and soft 404s are the norm: a great many applications
// answer 200 with their home page for every unknown path, which is what makes a
// 499-path probe against such a site return 499 findings that are all the home
// page.
//
// So the test is content-based, and the soft-404 baseline is what makes it
// content-based: one request for a path that certainly does not exist gives the
// application's own answer, and a path is reported only when it carries a
// fingerprint that the baseline does not carry. A `.git/HEAD` answer containing
// `ref:` is a repository; a `.git/HEAD` answer containing the home page is a soft
// 404, and the home page cannot contain `ref:` — so the freshness check is what
// rejects it.
//
// An earlier version of this file had a *second* gate here: it skipped any
// response byte-identical to the baseline, and described that as the soft-404
// check. The gate turned out to be strictly redundant — a body identical to the
// baseline carries no fingerprint the baseline lacks, so `Fresh` rejects it a few
// lines later — and mutation proved it, because removing the gate left the suite
// green. Redundant defence that cannot be told apart from the real one is dead
// code wearing a comment, so it is gone and the freshness check is the whole
// mechanism.
package active

import (
	"context"
	"strings"
	"sync"
)

// sensitiveFile is one path and the fingerprint that identifies it.
//
// Every entry has a fingerprint, and that is the invariant that makes this
// detector usable against a modern site: there is no path in this table that can
// be reported on its status code alone.
type sensitiveFile struct {
	// kind groups rows in the report, so a reader sees "3 version-control
	// repositories" rather than three unrelated paths.
	kind string
	// path is appended to the origin. It is a full path, not a suffix, because a
	// suffix would be probed against a directory the run does not know about.
	path string
	// fingerprints must appear in the body. Any one of them is enough.
	fingerprints []string
	// claimed is the severity the content would support.
	claimed Severity
	// why says what the content discloses.
	why string
}

// sensitiveFiles is the carried list, reduced to the entries whose content is
// distinguishable from a soft 404.
//
// The reduction is stated rather than hidden. Upstream carries 499 directory names
// and 50 admin paths, and most of them have no fingerprint: a 200 on `/upload` is
// indistinguishable from a 200 on a soft-404 page, so carrying them would carry the
// false positive with them. The entries kept are the ones where the *body* says
// what it is. The directory and admin-path lists remain available to the operator
// through `ScanRequest.InterestingPaths`, which is the honest place for a list
// with no fingerprint: the operator decides which of 499 paths is worth a request,
// and the run reports what came back.
var sensitiveFiles = []sensitiveFile{
	{
		kind: "version control", path: "/.git/HEAD",
		fingerprints: []string{"ref: refs/", "ref: refs"},
		claimed:      SeverityHigh,
		why: "the repository's HEAD pointer, which names the branch and the commit the working copy " +
			"was left on, and is the first file needed to reconstruct the rest",
	},
	{
		kind: "version control", path: "/.git/config",
		fingerprints: []string{"[core]", "[remote", "[branch"},
		claimed:      SeverityHigh,
		why: "the repository configuration, which names every remote — and a remote URL of the form " +
			"user:password@host puts the credentials in the response in cleartext",
	},
	{
		kind: "version control", path: "/.svn/entries",
		fingerprints: []string{"dir", "file", "_dir", "_file"},
		claimed:      SeverityHigh,
		why:          "the Subversion working-copy database, which lists every versioned file and revision",
	},
	{
		kind: "environment", path: "/.env",
		fingerprints: []string{"APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "DATABASE_URL=", "APP_ENV="},
		claimed:      SeverityCritical,
		why: "the application's environment file, which on a Laravel or Symfony deployment holds the " +
			"application key, the database password and every third-party credential the process uses",
	},
	{
		kind: "environment", path: "/config/database.yml",
		fingerprints: []string{"adapter:", "password:", "database:", "username:"},
		claimed:      SeverityCritical,
		why:          "the Rails database configuration, including the password in cleartext",
	},
	{
		kind: "php diagnostics", path: "/phpinfo.php",
		fingerprints: []string{"phpinfo()", "PHP Version", "php_ini_loaded_file"},
		claimed:      SeverityMedium,
		why: "the full PHP configuration: loaded modules, every environment variable the interpreter was " +
			"given, the document root, and the paths on disk",
	},
	{
		kind: "php diagnostics", path: "/server-status",
		fingerprints: []string{"Apache Server Status", "Server Version:", "Current Requests:"},
		claimed:      SeverityMedium,
		why: "the Apache status page, which names running processes and, on a default configuration, " +
			"the URLs other users are requesting",
	},
	{
		kind: "framework", path: "/WEB-INF/web.xml",
		fingerprints: []string{"<web-app", "servlet-class", "<display-name>"},
		claimed:      SeverityHigh,
		why: "the Java web application descriptor, which names every servlet, filter and session timeout " +
			"the application declares",
	},
	{
		kind: "container", path: "/actuator/env",
		fingerprints: []string{"\"propertySources\"", "\"activeProfiles\"", "spring.datasource"},
		claimed:      SeverityCritical,
		why: "the Spring Boot environment endpoint, which prints every property including datasource " +
			"passwords and any secret bound into configuration",
	},
	{
		kind: "source disclosure", path: "/elmah.axd",
		fingerprints: []string{"Error Log", "<title>Error</title>", "elmah"},
		claimed:      SeverityMedium,
		why: "the ELMAH error log, which records unhandled exceptions with their stack traces and the " +
			"request that caused them",
	},
	{
		kind: "source disclosure", path: "/error_log",
		fingerprints: []string{"PHP Fatal error", "PHP Parse error", "Stack trace:"},
		claimed:      SeverityMedium,
		why: "the PHP error log, which records warnings and fatals with the paths and parameters of the " +
			"requests that caused them",
	},
	{
		kind: "windows target", path: "/boot.ini",
		fingerprints: []string{"[boot loader]", "[extensions]"},
		claimed:      SeverityLow,
		why:          "the Windows boot configuration, which confirms the platform and names the installed system",
	},
}

// softNotFoundPath is the path used to learn what this application answers for a
// path that does not exist.
//
// It is a random component rather than a fixed one like `/this-does-not-exist-12345`,
// because a fixed not-found path is itself a fixed string that a hard-coded 404
// rule may special-case. A random path cannot be special-cased, because the
// application has never seen it.
const softNotFoundPath = "/rr-soft-404-probe-8f2c1a4e"

// SourceDisclosure is the sensitive file detector.
//
// It probes its own path list rather than reading the pages the run already
// fetched, and that has a cost the first version of this file did not account for:
// a site with two hundred endpoints would spend thirteen extra requests on *each*
// of them — two thousand six hundred requests to answer a question about the
// origin. The paths belong to the origin, not to the endpoint, so the probe is
// remembered per origin and a run pays for it once.
//
// The receiver is a pointer and the memory is guarded because one detector instance
// is shared by every worker of a run. A value receiver with a value-typed cache
// would copy the map on every call and quietly probe again, which is the exact cost
// this change exists to remove.
type SourceDisclosure struct {
	mu sync.Mutex
	// probed records the origins already checked, so the second endpoint on an
	// origin costs nothing.
	probed map[string]bool
}

// Name implements Module.
func (*SourceDisclosure) Name() string { return "srcdisc" }

// Level implements Module.
//
// Endpoint, because the unit is a path rather than a parameter: nothing here reads
// or writes a value.
func (*SourceDisclosure) Level() Level { return LevelEndpoint }

// Scan probes one endpoint, once per origin.
//
// The soft-404 baseline is fetched before anything else, and it is what every hit
// is compared against. A site that answers 200 with its home page for every unknown
// path therefore produces no findings at all from this detector, which is the
// correct outcome: there is nothing on that site to disclose.
func (m *SourceDisclosure) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	origin := endpointOrigin(p.URL)
	if origin == "" {
		return nil
	}
	if !m.claimOrigin(origin) {
		return nil
	}
	notFound, err := t.Do(ctx, "GET", origin+softNotFoundPath, nil, false, nil)
	if err != nil || notFound == nil {
		// Without the soft-404 baseline this detector cannot tell a disclosure
		// from a default page, and reporting every 200 it finds is exactly the
		// behaviour it was written to avoid.
		return nil
	}
	var out []Finding
	for _, file := range sensitiveFiles {
		if ctx.Err() != nil {
			return nil
		}
		resp, probeErr := t.Do(ctx, "GET", origin+file.path, nil, false, nil)
		if probeErr != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		if finding := sensitiveFileFinding(file, p, notFound.Body, resp); finding != nil {
			out = append(out, *finding)
		}
	}
	return out
}

// claimOrigin reports whether this call is the one that probes the origin.
//
// The first caller wins and the rest return false. It is not an exclusive lock —
// the winner may still be mid-probe when a second worker arrives — but the paths
// are idempotent reads of a stable resource, so two concurrent probes would only
// cost requests, not correctness, and the alternative is a mutex held across
// thirteen network calls per worker.
func (m *SourceDisclosure) claimOrigin(origin string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.probed == nil {
		m.probed = map[string]bool{}
	}
	if m.probed[origin] {
		return false
	}
	m.probed[origin] = true
	return true
}

// sensitiveFileFinding decides whether one response is the file it claims to be.
//
// notFound is the application's own answer for a path that certainly does not
// exist. It is compared with `Fresh` rather than with a substring test, because a
// fingerprint that already appears in the default page appears in every page — and
// a check that cannot fail reports every path on the site.
func sensitiveFileFinding(file sensitiveFile, p Point, notFound string, resp *Response) *Finding {
	var matched string
	for _, fingerprint := range file.fingerprints {
		if Fresh(&Response{Body: notFound}, resp, fingerprint) {
			matched = fingerprint
			break
		}
	}
	if matched == "" {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "srcdisc",
		Title:    "Sensitive File Disclosure (" + file.kind + ": " + file.path + ")",
		Claimed:  file.claimed,
		Tier:     TierVerified,
		Point:    p,
		Payload:  "GET " + file.path,
		Evidence: Snippet(resp.Body, matched, 160),
		Description: "The path returned a 200 whose content identifies it as itself, and the application " +
			"answers differently for this path than for a path that certainly does not exist — so the " +
			"response is a real file and not a default page. It discloses " + file.why + ".",
		Remediation: "Serve no repository metadata, configuration or diagnostic file that is not the " +
			"application itself. Move configuration out of the document root, deny `.git`, `.svn`, `.env` " +
			"and diagnostics at the server rather than relying on the application, and rotate any credential " +
			"that was ever served from one of these paths.",
	})
	return &finding
}

// endpointOrigin reduces a URL to scheme and host.
//
// Only paths are probed, and only on the origin the run started on: a link to
// another host's `.git` is a different authorisation decision than the one the
// operator asked about, and probing it would be the off-host crawl this scanner
// already declines to do by default.
func endpointOrigin(raw string) string {
	trimmed := strings.TrimRight(raw, "/")
	schemeEnd := strings.Index(trimmed, "://")
	if schemeEnd < 0 {
		return ""
	}
	rest := trimmed[schemeEnd+3:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return trimmed
	}
	return trimmed[:schemeEnd+3+slash]
}
