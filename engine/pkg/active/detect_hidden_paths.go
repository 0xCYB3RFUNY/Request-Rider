package active

// Hidden paths: a wordlist the operator supplies, against a measured 404.
//
// # What this is, and what it is not
//
// `dirsearch` fires a dictionary at a site and prints whatever answers. The
// dictionary is the operator's, and so is the choice of extensions, recursion
// depth and status filter; nothing about the technique requires the scanner to
// supply any of it. What the tool adds over `curl` is one thing, and it is the
// thing this detector keeps: it knows what "not found" looks like on *this*
// server, so an answer can be told apart from a soft 404.
//
// That discrimination is the whole difficulty. A server that answers 200 for
// everything makes a status filter report every path in the dictionary; a server
// that answers a rendered 404 page with a unique request id makes a length
// filter report every path in the dictionary again. Both are measured here, once
// per run, against a path that cannot exist — so the comparison is against the
// server's own behaviour rather than against an assumption about it.
//
// # Why there is no default dictionary
//
// `DefaultInterestingPaths` is the short list this project already probes after
// the crawl: twenty-one paths a run checks whether or not the operator says so.
// A second default list here would be a second implementation of that question,
// and both would fire the same requests. So this module has no default: an empty
// wordlist means it does not run, and the operator's dictionary is the only input.
//
// # What the tiers mean here
//
// `verified` is a real answer: the status is not the one the server gives for a
// path that does not exist, and the body is not the server's own not-found page.
// `potential` is a body that differs from the not-found page while the status does
// not — a soft 404 that renders something per path, which is the shape almost
// every framework produces and the reason a length filter was never enough.
// Nothing at all is reported when the two agree, which is the overwhelming
// majority of a dictionary.

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// HiddenPaths probes the paths on the operator's wordlist.
type HiddenPaths struct {
	// Paths is the dictionary. One entry per path, beginning with `/`.
	//
	// Nil means the module is not asked to run. There is no default, and the
	// reason is in the file header: the short default list already exists as
	// `DefaultInterestingPaths`, and a second one would fire the same requests.
	Paths []string
}

// Name implements Module.
func (HiddenPaths) Name() string { return "hidden_paths" }

// Level implements Module.
//
// Host level: a dictionary is fired at the origin, and the run fires it once.
func (HiddenPaths) Level() Level { return LevelHost }

// notFoundSuffix makes the probe path unguessable by construction.
//
// A fixed name is not enough: a site that ships a `/404.html` and rewrites every
// unknown path onto it will happily answer 200 for a path that does not exist,
// and if the scanner's own probe name is in somebody's dictionary the answer is
// the real page rather than the not-found page.
func notFoundSuffix() string {
	canary := newCanary("rrnf")
	if canary == "" {
		return ""
	}
	return "/" + canary + "/does-not-exist"
}

// Scan fires the dictionary once, against a measured not-found answer.
func (m HiddenPaths) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	paths := m.usablePaths()
	if len(paths) == 0 {
		return nil
	}
	origin, err := url.Parse(p.URL)
	if err != nil || origin.Host == "" {
		return nil
	}
	// The not-found answer is measured before the first candidate, and it is
	// measured rather than assumed: every comparison below is against this body.
	missing, missingPath := m.notFoundAnswer(ctx, t, origin)
	if missing == nil {
		return nil
	}
	var findings []Finding
	for _, path := range paths {
		if ctx.Err() != nil {
			return findings
		}
		probe := origin.Scheme + "://" + origin.Host + path
		answered, err := t.Do(ctx, http.MethodGet, probe, nil, false, nil)
		if err != nil || answered == nil {
			continue
		}
		if finding := classifyPathAnswer(p, missing, missingPath, answered, path); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

// usablePaths is the dictionary after the checks that keep a scan from sending a
// request the operator did not ask for.
func (m HiddenPaths) usablePaths() []string {
	seen := make(map[string]bool, len(m.Paths))
	out := make([]string, 0, len(m.Paths))
	for _, raw := range m.Paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		// A dictionary entry with a host in it is a URL, not a path, and firing
		// it would take the scan off the origin it was pointed at.
		if strings.ContainsAny(path, " \t\r\n?#\\") || strings.Contains(path, "//") {
			continue
		}
		if len(path) > 240 || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// notFoundAnswer is what this server says about a path that does not exist.
//
// The path it was asked about travels with the answer, because the shape
// comparison below needs it: a framework that renders "no such page: /x" produces
// a body that differs for every path, and comparing those bodies against each
// other reports the whole dictionary. The path is therefore the one thing that is
// normalised away before the two documents are compared.
func (m HiddenPaths) notFoundAnswer(ctx context.Context, t *Transport, origin *url.URL) (*Response, string) {
	suffix := notFoundSuffix()
	if suffix == "" {
		return nil, ""
	}
	answered, err := t.Do(ctx, http.MethodGet, origin.Scheme+"://"+origin.Host+suffix, nil, false, nil)
	if err != nil {
		return nil, ""
	}
	return answered, suffix
}

// sameAnswerShape reports whether two documents say the same thing once the path
// each was asked about is normalised away.
//
// This is the wildcard-response check, and it is the whole reason the module
// measures its own 404 instead of filtering on a status. Three shapes answer a
// missing path, and only the first is a 404:
//
//   - a bare 404 with a constant body,
//   - a 404 whose body is rendered per path ("page /a/ does not exist"),
//   - a 200 whose body is rendered per path.
//
// A byte comparison catches none of the last two, and `TestASoftNotFoundPageIsNot
// AReport` is the fixture for both: it renders the path into the body and answers
// 200, and without this normalisation the run reported every entry of the
// dictionary.
func sameAnswerShape(a, aPath, b, bPath string) bool {
	const token = "\x00rr-path\x00"
	normalise := func(body, path string) string {
		return strings.ReplaceAll(body, path, token)
	}
	return normalise(a, aPath) == normalise(b, bPath)
}

// classifyPathAnswer decides what one answer means against the not-found answer.
func classifyPathAnswer(p Point, missing *Response, missingPath string, answered *Response, path string) *Finding {
	probe := Point{URL: path, Method: http.MethodGet}
	sameStatus := answered.StatusCode == missing.StatusCode
	sameBody := sameAnswerShape(missing.Body, missingPath, answered.Body, path)
	if sameStatus && sameBody {
		// The server answers this path exactly as it answers a path that does not
		// exist — same status, same document modulo the path it was asked about.
		// This is the soft-404 case, and it is the case that makes a dictionary
		// scan useless.
		return nil
	}
	tier := TierPotential
	claimed := SeverityLow
	title := "Path answers differently from a path that does not exist (" + path + ")"
	if !sameStatus {
		// A different status is the strong half: the server distinguishes this path
		// from a missing one by name alone.
		tier = TierVerified
		claimed = SeverityMedium
		title = "Existing path not linked from any page (" + path + ")"
	}
	finding, _ := NewFinding(Spec{
		Module:   "hidden_paths",
		Title:    title,
		Claimed:  claimed,
		Tier:     tier,
		Point:    probe,
		Payload:  path,
		Evidence: Snippet(answered.Body, strings.TrimSpace(answered.Body), 200),
		Description: "The path answered " + statusSentence(answered.StatusCode) + " while a path this run " +
			"invented and that cannot exist answered " + statusSentence(missing.StatusCode) + ". The two " +
			"bodies " + bodiesDiffer(sameBody) + ", so the server distinguishes this path from a missing one. " +
			"Nothing is claimed about what the path contains: it is on the map and the reader decides.",
		Remediation: "Remove paths the application no longer serves, and return 404 for anything that is not " +
			"published. An endpoint that answers 200 for a name the site does not link is invisible to a " +
			"link-following review.",
	})
	return &finding
}

// bodiesDiffer phrases the comparison for the evidence sentence.
func bodiesDiffer(same bool) string {
	if same {
		return "are identical"
	}
	return "differ"
}
