package bypass

// The live measurement, and why it is not a test that runs by itself.
//
// A fixture proves the ladder reaches a resource the target refused, and that is
// necessary and not sufficient: the fixture refuses a *shape* it was written to
// refuse, so it cannot disagree about whether the ladder is asking the right
// questions. Only a target that refuses for reasons we did not write can do that,
// which is what this file is for.
//
// It is skipped unless `RR_BYPASS_LIVE` names hosts. That is not caution about
// the network, it is the project's rule: a check that reaches a third party
// without being asked is a check nobody agreed to run.
//
// # What it reports, and what it does not claim
//
// It reports, per host: the status the plain request got, the status each form
// got, which form reached the resource if one did, and how many requests the
// whole thing cost.
//
// It does not claim the ladder works because a live target said so. Two things
// make a live answer ambiguous and both are recorded rather than argued about:
//
//   - this machine's egress is a Tor exit (measured 2026-10-03: every egress
//     address in `torbulkexitlist`), so a refusal from a news site is at least as
//     likely to be IP reputation as anything the ladder tries. A block page is
//     therefore read for its vendor markers and reported, because "the target
//     refused" and "the edge refused our address" are different facts;
//   - a target that answers 200 to the plain request never enters the ladder at
//     all. That is a real measurement — it says nothing about the ladder, and
//     reporting it as a success would be exactly the mistake the live-target rule
//     exists to prevent.

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// liveEnv names the hosts to measure. Empty means "do not reach the network".
const liveEnv = "RR_BYPASS_LIVE"

// blockMarkers are the strings that say the refusal came from an edge rather
// than from the resource.
//
// They are read, not matched against a status code. A 403 is a 403 and a 503 is
// a 503, and reading a vendor out of a status is a guess with a name attached.
var blockMarkers = []struct {
	Vendor string
	Marker string
}{
	{Vendor: "cloudflare", Marker: "Just a moment"},
	{Vendor: "cloudflare", Marker: "cf-chl-"},
	{Vendor: "cloudflare", Marker: "Attention Required"},
	{Vendor: "cloudflare", Marker: "Enable JavaScript and cookies to continue"},
	{Vendor: "yandex", Marker: "SmartCaptcha"},
	{Vendor: "yandex", Marker: "Show more"},
	{Vendor: "qrator", Marker: "qrator"},
	{Vendor: "radware", Marker: "radware"},
	{Vendor: "akamai", Marker: "Access Denied"},
	{Vendor: "sucuri", Marker: "Sucuri"},
}

// liveURLEnv names full URLs, paths included.
//
// It is separate from `liveEnv` because a home page is the wrong measurement:
// the interesting refusal is a *path* refusal on a host that otherwise serves
// normally, and `https://host/` can never show it. Measured 2026-10-03 on
// `liveinternet.ru`: `/.git/config` answers 403 while `/robots.txt` answers 200
// from the same nginx — that is a refusal scoped to the request's shape, which
// is the only class in which a ladder can be measured at all.
const liveURLEnv = "RR_BYPASS_LIVE_URLS"

// liveFormsEnv narrows the walk to named forms.
//
// It exists because of a measurement, not a preference: the live host answers
// roughly one request per three minutes, so a full forty-five-form walk takes
// hours and the run dies before it finishes. When the question is "does the
// traversal reach anything", the walk is the nine traversal forms and nothing
// else, and the answer arrives inside the host's budget.
const liveFormsEnv = "RR_BYPASS_LIVE_FORMS"

// liveSelectedForms is the operator's narrowing for this measurement, or nil for
// the whole ladder.
func liveSelectedForms() []string {
	raw := strings.TrimSpace(os.Getenv(liveFormsEnv))
	if raw == "" {
		return nil
	}
	names := make([]string, 0, 4)
	for _, name := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

// TestTheLadderAgainstALiveTarget is the live half of the port's evidence.
//
// Run: RR_BYPASS_LIVE=ria.ru,pravda.ru go test ./pkg/bypass/ -run Live -v -count=1
func TestTheLadderAgainstALiveTarget(t *testing.T) {
	hosts := strings.TrimSpace(os.Getenv(liveEnv))
	if hosts == "" {
		t.Skipf("%s is unset, so nothing reaches the network; a fixture cannot stand in here", liveEnv)
	}
	for _, host := range strings.Split(hosts, ",") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		t.Run(host, func(t *testing.T) {
			measureOne(t, host, "https://"+host+"/")
		})
	}
}

// TestTheLadderAgainstALivePath is the same measurement aimed at a specific
// resource rather than a home page.
//
// It exists because the home-page form produced a measured zero that proved
// nothing: on a news host behind an edge that refuses by address, every form is
// refused and the zero says only that the edge does not care about request
// shape. Naming the resource removes that ambiguity, because a host that serves
// `/robots.txt` with 200 and refuses `/.git/config` with 403 has refused by
// shape, and the ladder is then answering the right question.
//
//	Run: RR_BYPASS_LIVE_URLS=https://liveinternet.ru/.git/config \
//	     go test ./pkg/bypass/ -run LivePath -v -count=1
func TestTheLadderAgainstALivePath(t *testing.T) {
	targets := strings.TrimSpace(os.Getenv(liveURLEnv))
	if targets == "" {
		t.Skipf("%s is unset, so nothing reaches the network", liveURLEnv)
	}
	for _, target := range strings.Split(targets, ",") {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		t.Run(target, func(t *testing.T) {
			measureOne(t, target, target)
		})
	}
}

// liveClient is the client the live measurement uses, and it exists because the
// default one cannot measure anything.
//
// Measured 2026-10-04: `curl` fetched `https://www.liveinternet.ru/` in a single
// request from this machine, while an `http.Client{Timeout: 45 * time.Second}`
// timed out three times in a row, four attempts out of four. The difference is not
// the host and not the timeout on the client: `net/http` applies its own
// `TLSHandshakeTimeout` of **10 s** inside the transport, and a handshake that
// stalls longer dies there no matter what the client timeout says. `curl` has no
// such separate cap, which is why the same host answered for one tool and not the
// other.
//
// So the transport is built here with a handshake budget long enough to see a slow
// host, rather than inheriting a ten-second ceiling that quietly turns a
// measurement into a statement about the client.
//
// Keep-alive stays **on**, and that is measured rather than preferred: an earlier
// version of this file set `DisableKeepAlives: true`, which forces a fresh TCP and
// TLS handshake for every one of a walk's requests. On `www.liveinternet.ru` the
// walk then got **zero** form statuses out of four attempts — the plain probe
// succeeded and every form after it died in the handshake. The original tool that
// reported nine bypasses on this host used a keep-alive session and got 276
// requests answered on the same route. The measurement was failing on its own
// connection policy, not on the ladder.
func liveClient() *http.Client {
	transport := &http.Transport{
		TLSHandshakeTimeout:   liveTLSTimeout,
		ResponseHeaderTimeout: liveTLSTimeout,
		DialContext:           (&net.Dialer{Timeout: liveTLSTimeout}).DialContext,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: liveRequestBudget}
}

// liveTLSTimeout is how long one handshake or response head may take.
const liveTLSTimeout = 40 * time.Second

// liveRequestBudget is the ceiling on a whole request. It is not a bound on what
// the target accepts — it bounds one measurement of it.
const liveRequestBudget = 60 * time.Second

// measureOne asks one URL plainly, and walks the ladder only if the plain answer
// was a refusal. `label` is what the log lines name; it is the URL itself for the
// path form and the host for the home-page form.
func measureOne(t *testing.T, label, base string) {
	t.Helper()

	plain, attempts, err := getWithRetry(liveClient(), base)
	if err != nil {
		// A transport error is a fact about this machine's route, not about the
		// ladder — but only after the retry has had its say. One timed-out
		// handshake is not a fact about a route, and reporting it as one turns a
		// flaky target into a false conclusion about the ladder.
		t.Logf("plain GET %s failed after %d attempt(s): %v — this is a route fact, "+
			"not a ladder result", base, attempts, err)
		return
	}
	defer plain.Body.Close()
	plainBody := readCapped(plain)

	vendor := vendorOf(plain.Header, plainBody)
	t.Logf("%s: plain GET answered %d%s", base, plain.StatusCode, vendorSuffix(vendor))
	for _, marker := range blockMarkers {
		if strings.Contains(plainBody, marker.Marker) || strings.Contains(
			headerDump(plain.Header), marker.Marker) {
			t.Logf("%s: the plain answer carries %s's block marker %q — the refusal is at the edge, "+
				"and no request shape changes that", label, marker.Vendor, marker.Marker)
		}
	}

	if !refusedStatus(plain.StatusCode) {
		// The honest report: the ladder was never entered. Reporting this as a
		// ladder win would be the failure the live-target rule was written about.
		t.Logf("%s: the plain request was answered %d, so the ladder was never entered; "+
			"this target measures nothing about it", label, plain.StatusCode)
		return
	}

	ctx := context.Background()
	selected := liveSelectedForms()
	driver := New(selected)
	if selected != nil {
		t.Logf("%s: walk narrowed to %d form(s): %v", label, len(selected), selected)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, attempt, err := driver.Attempt(ctx, liveClient(), req)
	if err != nil {
		// A live target stalls, so every form's transport call can fail while the
		// plain request succeeded. That is a fact about the route, and it used to
		// arrive as a nil response with a nil error and crash the next line.
		t.Logf("%s: the walk reached nothing because every request failed on the wire: %v "+
			"(tried: %s)", label, err, attempt.TriedSummary())
		return
	}
	defer resp.Body.Close()

	t.Logf("%s: walked %d form(s) in %d request(s); final status %d",
		label, len(attempt.Tried), attempt.Requests(), resp.StatusCode)
	if !attempt.Bypassed() {
		t.Logf("%s: no form reached the resource", label)
	}
	for _, tried := range attempt.Tried {
		t.Logf("  %-28s %s %s -> %d", tried.Form, tried.Method, truncate(tried.URL, 90), tried.Status)
	}
	if attempt.Bypassed() {
		t.Logf("%s: reached by %s as %s", label, attempt.SucceededBy, truncate(attempt.SucceededURL, 90))
		if attempt.ServedSiteRoot {
			t.Logf("%s:   BUT the body is the site's root page, not the resource — %s",
				label, attempt.Note)
		} else {
			t.Logf("%s:   and the body is not the root page, so this is the named resource",
				label)
		}
	}
}

// plainProbeAttempts is how many times the plain request is sent before a
// transport error is called a fact about the route.
//
// Four, not three, and the fourth exists because three were not enough: measured
// 2026-10-04, three consecutive handshakes to `www.liveinternet.ru` stalled and
// the run recorded the target as unmeasurable — four attempts out of four — while
// `curl` was answering for the same host minutes later. A burst that outlives the
// whole budget is not evidence about the target.
const plainProbeAttempts = 4

// getWithRetry sends the plain request until it gets an HTTP answer or the
// attempts run out, and says how many it spent.
//
// It retries only transport errors. A status — including a refusal — is an
// answer, and asking again would change the very thing being measured.
//
// The pause between attempts is not politeness, it is what makes the retry work.
// Measured 2026-10-03 on `www.liveinternet.ru`: three consecutive handshakes
// timed out at ~10.1 s each, then the next three answered `403` in under 800 ms.
// The stalls come in bursts, so three retries fired back to back all land inside
// the same burst and lose the measurement — which is what happened on the first
// two runs before the pause existed.
func getWithRetry(client *http.Client, url string) (*http.Response, int, error) {
	var lastErr error
	for attempt := 1; attempt <= plainProbeAttempts; attempt++ {
		resp, err := client.Get(url)
		if err == nil {
			return resp, attempt, nil
		}
		lastErr = err
		if attempt < plainProbeAttempts {
			time.Sleep(time.Duration(attempt) * plainProbePause)
		}
	}
	return nil, plainProbeAttempts, lastErr
}

// plainProbePause is the gap before the next plain attempt, multiplied by the
// attempt number.
const plainProbePause = 4 * time.Second

// readCapped reads a body for markers only. A live home page is megabytes and
// the measurement needs a few hundred bytes of it.
func readCapped(resp *http.Response) string {
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

// headerDump is the response's headers as one string, so a marker in a header is
// found the same way a marker in a body is.
func headerDump(header http.Header) string {
	var out strings.Builder
	for name := range header {
		out.WriteString(name)
		out.WriteString(": ")
		out.WriteString(strings.Join(header[name], " "))
		out.WriteString("\n")
	}
	return out.String()
}

// vendorOf names the edge from the headers a challenge is published in, and only
// from those.
func vendorOf(header http.Header, body string) string {
	for name, value := range header {
		lowered := strings.ToLower(name + ": " + strings.Join(value, " "))
		switch {
		case strings.Contains(lowered, "cf-mitigated"), strings.Contains(lowered, "server: cloudflare"):
			return "cloudflare"
		case strings.Contains(lowered, "x-datadome"):
			return "datadome"
		case strings.Contains(lowered, "x-akamai-transformed"):
			return "akamai"
		case strings.Contains(lowered, "x-px-"):
			return "perimeterx"
		}
	}
	for _, marker := range blockMarkers {
		if strings.Contains(body, marker.Marker) {
			return marker.Vendor
		}
	}
	return ""
}

// vendorSuffix renders the vendor for the log line, and nothing when it is
// unknown.
func vendorSuffix(vendor string) string {
	if vendor == "" {
		return ""
	}
	return " (edge: " + vendor + ")"
}

// truncate shortens a URL for a log line.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit-1] + "…"
}
