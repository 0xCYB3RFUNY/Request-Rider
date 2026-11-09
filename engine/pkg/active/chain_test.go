package active

// Tests for the exploit-chain correlation.
//
// Every rule here is written against the way the upstream rules fail, so the
// tests are mostly pairs: a case where the composition holds and the rule fires,
// and a case where the composition looks plausible from a URL's spelling or a
// response's length and the rule must stay quiet.
//
// The upstream rules, for reference, in the order they are wrong:
//
//	chainSQLitoAuthBypass     → critical if the URL contains login/user/auth/pass/email
//	chainSSTItoRCE            → critical, with no request at all
//	chainOpenRedirectwithOAuth → critical if the URL contains oauth/next/return
//	chainLFItoRCE             → critical if the response was longer than 200 bytes
//	chainXSStoAccountTakeover → critical if any Set-Cookie lacks HttpOnly

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// chainSite is a server the chain rules may probe, with behaviour set per test.
type chainSite struct {
	// handler decides the response for a request, by path.
	handler func(w http.ResponseWriter, r *http.Request)
	// seen records the Referer headers the site received, which is how the
	// log-poisoning rule's planted marker is observed.
	seen []string
}

func newChainSite(t *testing.T, site *chainSite) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ref := r.Header.Get("Referer"); ref != "" {
			site.seen = append(site.seen, ref)
		}
		site.handler(w, r)
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"1"}},
	}
}

// finding makes a detector finding of a given module and tier.
func finding(t *testing.T, module string, tier Tier, endpoint, param, title string) Finding {
	t.Helper()
	f, _ := NewFinding(Spec{
		Module: module, Title: title, Claimed: SeverityHigh, Tier: tier,
		Point: Point{URL: endpoint, Method: http.MethodGet, Param: param},
	})
	return f
}

func chainTitles(findings []Finding) string {
	var out []string
	for _, f := range findings {
		out = append(out, f.Title)
	}
	return strings.Join(out, " | ")
}

// --- XSS to account takeover -----------------------------------------------

// A demonstrated injection plus a session cookie script can read is account
// takeover, and both halves come from the same exchange.
func TestChainXSSAndScriptReadableCookieIsAccountTakeover(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
			_, _ = io.WriteString(w, "<html><body>ok</body></html>")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS (html-body)"),
	}}
	found := Chains(context.Background(), in)
	var chain *Finding
	for i := range found {
		if found[i].Module == "chain" {
			chain = &found[i]
		}
	}
	if chain == nil {
		t.Fatalf("no chain finding: %s", chainTitles(found))
	}
	if chain.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: both halves are demonstrated", chain.Tier, TierVerified)
	}
	if chain.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", chain.Severity)
	}
	if !strings.Contains(chain.Evidence, "HttpOnly") {
		t.Errorf("evidence = %q, want the missing attribute named", chain.Evidence)
	}
	if len(chain.ChainOf) == 0 {
		t.Error("chain_of is empty; a chain row that names nothing is not a chain")
	}
}

// A hardened cookie ends the composition. The upstream rule reports critical
// for any Set-Cookie lacking HttpOnly, which includes a cookie that has it.
func TestChainIgnoresXSSWhenTheCookieIsHardened(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name: "session", Value: "abc", Path: "/", HttpOnly: true, Secure: true,
			})
			_, _ = io.WriteString(w, "<html><body>ok</body></html>")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS"),
	}}
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Account Takeover") {
			t.Fatalf("reported account takeover with a hardened cookie: %q", f.Title)
		}
	}
}

// Secure alone is not enough. A cookie without HttpOnly is still readable by
// script on the same origin, which is the half that matters here.
func TestChainNamesBothMissingAttributes(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "abc", Path: "/", Secure: true})
			_, _ = io.WriteString(w, "<html><body>ok</body></html>")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS"),
	}}
	found := Chains(context.Background(), in)
	if !strings.Contains(chainTitles(found), "Account Takeover") {
		t.Fatalf("findings = %s, want the composition", chainTitles(found))
	}
	for _, f := range found {
		if strings.Contains(f.Title, "Account Takeover") && !strings.Contains(f.Evidence, "HttpOnly") {
			t.Errorf("evidence = %q, want HttpOnly named as absent", f.Evidence)
		}
	}
}

// A cookie that is not a session does not compose. The name decides, not the
// value.
func TestChainIgnoresNonSessionCookies(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "t", Path: "/"})
			_, _ = io.WriteString(w, "<html><body>ok</body></html>")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS"),
	}}
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Account Takeover") {
			t.Fatalf("reported account takeover from a CSRF cookie: %q", f.Title)
		}
	}
}

// An unproven ingredient is left out. Correlating a verified finding with a
// potential one produces a row whose strength is its weakest part, and the
// reader cannot see which part that was.
func TestChainIgnoresUnverifiedIngredients(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
			_, _ = io.WriteString(w, "<html><body>ok</body></html>")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierPotential, point.URL, "q", "User Input Reflected"),
	}}
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Account Takeover") {
			t.Fatalf("correlated an unproven ingredient: %q", f.Title)
		}
	}
}

// --- SQLi to auth bypass ----------------------------------------------------

// A tautology and a contradiction that answer with different statuses show the
// condition deciding the outcome, and the tautology arm is then the successful
// one.
func TestChainSQLiAuthBypassProvenByStatusDifference(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("q")
			if strings.Contains(value, "1'='2") || strings.Contains(value, "AND '1'='2") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "invalid credentials")
				return
			}
			if strings.Contains(value, "OR '1'='1") {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "welcome, administrator")
				return
			}
			_, _ = io.WriteString(w, "login page")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "sqli", TierVerified, point.URL, "q", "SQL Injection (Error-Based)"),
	}}
	found := Chains(context.Background(), in)
	var chain *Finding
	for i := range found {
		if strings.Contains(found[i].Title, "Authentication Bypass") {
			chain = &found[i]
		}
	}
	if chain == nil {
		t.Fatalf("findings = %s, want the composition", chainTitles(found))
	}
	if chain.Tier != TierVerified {
		t.Errorf("tier = %q, want verified: the statuses differ", chain.Tier)
	}
	if chain.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical when proven", chain.Severity)
	}
}

// Two 200 pages that differ in text do not say which one is the successful
// outcome, so the composition is reported as unverified and capped.
func TestChainSQLiAuthBypassUnverifiedWhenStatusesMatch(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("q")
			if strings.Contains(value, "'") {
				if strings.Contains(value, "1'='2") {
					_, _ = io.WriteString(w, strings.Repeat("error: no such user. ", 20))
					return
				}
				_, _ = io.WriteString(w, strings.Repeat("dashboard contents. ", 20))
				return
			}
			_, _ = io.WriteString(w, "login page")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "sqli", TierVerified, point.URL, "q", "SQL Injection (Error-Based)"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Authentication Bypass") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatalf("findings: want the composition reported as unverified")
	}
	if chain.Tier != TierPotential {
		t.Errorf("tier = %q, want potential", chain.Tier)
	}
	if chain.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, want at most medium", chain.Severity)
	}
	if !strings.Contains(chain.Evidence, "not established") {
		t.Errorf("evidence = %q, want the missing proof named", chain.Evidence)
	}
}

// Both arms landing on the same page is not a condition deciding anything, and
// the rule says nothing rather than reporting a guess.
func TestChainSQLiAuthBypassSilentWhenBothArmsMatch(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "same page for every value of q")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "sqli", TierVerified, point.URL, "q", "SQL Injection (Error-Based)"),
	}}
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Authentication Bypass") {
			t.Fatalf("reported a bypass where both arms answer identically: %q", f.Title)
		}
	}
}

// The upstream rule decides this from the spelling of the URL. A parameter
// called `login` that belongs to a search page is not an authentication bypass.
func TestChainSQLiAuthBypassIgnoresTheParameterName(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "same page") },
	})
	point.Param = "login"
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "sqli", TierVerified, point.URL, "login", "SQL Injection (Error-Based)"),
	}}
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Authentication Bypass") {
			t.Fatalf("a parameter named login produced a bypass: %q", f.Title)
		}
	}
}

// --- SSTI to RCE -----------------------------------------------------------

// Command output coming back is the difference between an engine that
// evaluates expressions and one that executes commands, and it is the claim.
func TestChainSSTIToRCEProvenByCommandOutput(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("tpl")
			if strings.Contains(value, "popen") {
				_, _ = io.WriteString(w, "uid=33(www-data) gid=33(www-data) groups=33(www-data)")
				return
			}
			_, _ = io.WriteString(w, "hello")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "ssti", TierVerified, point.URL, "tpl", "Server-Side Template Injection"),
	}}
	found := Chains(context.Background(), in)
	var chain *Finding
	for i := range found {
		if strings.Contains(found[i].Title, "code execution") {
			chain = &found[i]
		}
	}
	if chain == nil {
		t.Fatalf("findings = %s, want the composition", chainTitles(found))
	}
	if chain.Tier != TierVerified {
		t.Errorf("tier = %q, want verified when a command ran", chain.Tier)
	}
	if !strings.Contains(chain.Evidence, "uid=") {
		t.Errorf("evidence = %q, want the command output quoted", chain.Evidence)
	}
}

// The upstream rule reports critical with no request at all. Where the engine
// evaluates arithmetic and nothing more — which is a real configuration — the
// composition is unverified and capped.
func TestChainSSTIToRCEUnverifiedWithoutCommandOutput(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("tpl")
			if strings.Contains(value, "{{") {
				// A locked-down engine: it evaluates the arithmetic and drops
				// everything it does not recognise.
				_, _ = io.WriteString(w, "49")
				return
			}
			_, _ = io.WriteString(w, "hello")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "ssti", TierVerified, point.URL, "tpl", "Server-Side Template Injection"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "code execution") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatal("want the composition reported as unverified")
	}
	if chain.Tier != TierPotential {
		t.Errorf("tier = %q, want potential", chain.Tier)
	}
	if chain.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, want at most medium", chain.Severity)
	}
}

// --- CORS with XSS ---------------------------------------------------------

// Two demonstrated findings on the same host compose.
func TestChainCORSWithXSSProvenOnTheSameHost(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") },
	})
	cors := finding(t, "misconfig", TierVerified, point.URL, "q",
		"CORS Misconfiguration with credentials (origin reflected)")
	cors.Evidence = "Access-Control-Allow-Origin: https://probe | Access-Control-Allow-Credentials: true"
	in := ChainInput{Transport: transport, Findings: []Finding{
		cors, finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "cross-origin data exfiltration") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatalf("findings: want the composition")
	}
	if chain.Tier != TierVerified {
		t.Errorf("tier = %q, want verified on one host", chain.Tier)
	}
}

// Two findings in the same run on different hosts are not a composition: a
// browser enforces origin across hosts, so an injection on one site cannot read
// a CORS hole on another.
func TestChainCORSWithXSSUnverifiedAcrossHosts(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") },
	})
	cors := finding(t, "misconfig", TierVerified, "https://api.other-host.test/v1/me", "q",
		"CORS Misconfiguration with credentials (origin reflected)")
	cors.Evidence = "Access-Control-Allow-Origin: https://probe | Access-Control-Allow-Credentials: true"
	in := ChainInput{Transport: transport, Findings: []Finding{
		cors, finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "cross-origin data exfiltration") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatal("want the composition reported as unverified")
	}
	if chain.Tier != TierPotential {
		t.Errorf("tier = %q, want potential across hosts", chain.Tier)
	}
	if !strings.Contains(chain.Evidence, "different hosts") {
		t.Errorf("evidence = %q, want the reason named", chain.Evidence)
	}
}

// --- redirect token theft ---------------------------------------------------

// A demonstrated redirect on an endpoint that carries both a credential
// parameter and a destination parameter is the interception path.
func TestChainRedirectTokenTheftOnACredentialFlow(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") },
	})
	redirect := finding(t, "redirect", TierVerified, point.URL, "redirect_uri", "Open Redirect (Location header, plain)")
	redirect.Evidence = "Location: https://rr-redirect-probe.invalid/landed"
	in := ChainInput{Transport: transport, Findings: []Finding{redirect}}
	// The surface carries both: the finding's own param plus a sibling.
	in.Findings[0].Payload = "redirect_uri,code"
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "code interception") {
			copied := f
			chain = &copied
		}
	}
	// A single redirect finding names one parameter, which is not a flow.
	if chain != nil {
		t.Fatalf("one parameter is not a credential flow: %q", chain.Title)
	}
}

// A path that says "callback" with no credential parameter is not a flow, and a
// credential flow is decided by the parameters rather than by the spelling.
func TestChainRedirectTokenTheftIgnoresThePathName(t *testing.T) {
	transport, _ := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") },
	})
	redirect := finding(t, "redirect", TierVerified, "https://target.test/oauth/callback", "state", "Open Redirect")
	in := ChainInput{Transport: transport, Findings: []Finding{redirect}}
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "code interception") {
			t.Fatalf("a path called oauth/callback composed: %q", f.Title)
		}
	}
}

func TestChainParameterNamesAndMatching(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") },
	})
	redirect := finding(t, "redirect", TierVerified, point.URL, "state", "Open Redirect")
	in := ChainInput{Transport: transport, Findings: []Finding{redirect}}
	chain := (&ChainRedirectTokenTheft{}).Apply(context.Background(), in)
	if chain != nil {
		t.Fatalf("a lone state parameter composed: %q", chain.Title)
	}
	if !hasAny([]string{"code", "state"}, []string{"code"}) {
		t.Error("hasAny missed an exact match")
	}
	if hasAny([]string{"codestatus"}, []string{"code"}) {
		t.Error("hasAny matched a name that merely contains the wanted one")
	}
	if got := hostOf("https://api.example.test:8443/v1/me"); got != "api.example.test" {
		t.Errorf("hostOf = %q, want the host without the port", got)
	}
	if !sameHostOf("https://a.test/x", "https://a.test:443/y") {
		t.Error("sameHostOf disagreed about the same host on two ports")
	}
}

// --- log poisoning ---------------------------------------------------------

// A read that returns this scan's own unique marker proves the log is readable
// and writable, which is what the chain claims. The upstream rule accepts a
// response longer than 200 bytes.
func TestChainLogPoisoningProvenByReadingBackTheMarker(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("file")
			if strings.Contains(value, "access.log") {
				// The log contains every Referer the site has seen.
				written := strings.Join(siteReferers(r), "\n")
				_, _ = io.WriteString(w, "127.0.0.1 - - [x] \"GET / HTTP/1.1\"\n"+written)
				return
			}
			_, _ = io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\n")
		},
	})
	shared := &chainSite{}
	shared.handler = func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("file")
		if strings.Contains(value, "access.log") {
			_, _ = io.WriteString(w, "log contents:\n"+strings.Join(shared.seen, "\n"))
			return
		}
		_, _ = io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\n")
	}
	// The marker request goes to the same server, whose handler records the
	// Referer it was given.
	transport, point = newChainSite(t, shared)
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "lfi", TierVerified, point.URL, "file", "Local File Inclusion (path traversal)"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "code execution") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatal("want the composition reported")
	}
	if chain.Tier != TierVerified {
		t.Errorf("tier = %q, want verified when the marker came back", chain.Tier)
	}
	if !strings.Contains(chain.Evidence, "writable") {
		t.Errorf("evidence = %q, want the writable conclusion stated", chain.Evidence)
	}
	// The marker request is an ordinary GET, so the site must have logged it.
	if len(shared.seen) == 0 {
		t.Fatal("no request carrying a marker was made")
	}
	if !strings.HasPrefix(shared.seen[0], "rrlog") {
		t.Errorf("planted marker = %q, want the run's canary", shared.seen[0])
	}
}

// A long log read that contains none of this run's requests is a log read.
func TestChainLogPoisoningUnverifiedWhenTheMarkerIsAbsent(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("file")
			if strings.Contains(value, "access.log") {
				// A long log, and none of it from this scan.
				_, _ = io.WriteString(w, strings.Repeat("127.0.0.1 - - [x] \"GET /old HTTP/1.1\" 200\n", 40))
				return
			}
			_, _ = io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\n")
		},
	})
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "lfi", TierVerified, point.URL, "file", "Local File Inclusion (path traversal)"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "code execution") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatal("want the composition reported as unverified")
	}
	if chain.Tier != TierPotential {
		t.Errorf("tier = %q, want potential when the marker is absent", chain.Tier)
	}
	if chain.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, want at most medium", chain.Severity)
	}
}

// The helper the log fixture uses.
func siteReferers(r *http.Request) []string { return []string{r.Header.Get("Referer")} }

// Uniqueness is what makes the read-back attributable to this run, so it is
// asserted across runs rather than inside one. A fixed marker would let a log
// line left by an earlier run prove poisoning for this one, which is the same
// class of error as accepting any long body.
func TestChainLogPoisoningMarkerIsUniquePerRun(t *testing.T) {
	shared := &chainSite{}
	shared.handler = func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("file")
		if strings.Contains(value, "access.log") {
			_, _ = io.WriteString(w, "log contents:\n"+strings.Join(shared.seen, "\n"))
			return
		}
		_, _ = io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\n")
	}
	transport, point := newChainSite(t, shared)
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "lfi", TierVerified, point.URL, "file", "Local File Inclusion (path traversal)"),
	}}
	Chains(context.Background(), in)
	Chains(context.Background(), in)
	if len(shared.seen) < 2 {
		t.Fatalf("markers = %v, want one per run", shared.seen)
	}
	if shared.seen[0] == shared.seen[1] {
		t.Errorf("both runs planted %q; a shared marker cannot be attributed to a run", shared.seen[0])
	}
}

// The rule reads the cookie from the page the injection was found on, not from
// the site root. A cookie the application only issues on the page that logs you
// in is the one that matters, and a request to the root never sees it.
func TestChainXSSAccountTakeoverReadsTheCookieFromTheReportedPage(t *testing.T) {
	site := &chainSite{}
	site.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		}
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}
	transport, point := newChainSite(t, site)
	login := point.URL + "/app/login"
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierVerified, login, "q", "Reflected XSS"),
	}}
	var chain *Finding
	for _, f := range Chains(context.Background(), in) {
		if strings.Contains(f.Title, "Account Takeover") {
			copied := f
			chain = &copied
		}
	}
	if chain == nil {
		t.Fatal("the cookie is set on the page that carries the injection; not reading it there is the upstream defect")
	}
}

// --- the engine itself -----------------------------------------------------

func TestChainsReportsNothingWithoutATransport(t *testing.T) {
	in := ChainInput{Findings: []Finding{
		finding(t, "xss", TierVerified, "https://target.test/a", "q", "Reflected XSS"),
	}}
	if found := Chains(context.Background(), in); len(found) != 0 {
		t.Fatalf("findings = %s, want none without a transport to probe with", chainTitles(found))
	}
}

func TestChainsStopsOnCancellation(t *testing.T) {
	transport, point := newChainSite(t, &chainSite{
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "a"})
			_, _ = io.WriteString(w, "ok")
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := ChainInput{Transport: transport, Findings: []Finding{
		finding(t, "xss", TierVerified, point.URL, "q", "Reflected XSS"),
	}}
	if found := Chains(ctx, in); len(found) != 0 {
		t.Fatalf("findings = %s, want none on a cancelled run", chainTitles(found))
	}
}

// Every rule declares a claim and an impact, and a rule that produced nothing
// has to be the reason rather than a silent skip.
func TestEveryChainRuleIsRegisteredAndDescribed(t *testing.T) {
	rules := AllChains()
	if len(rules) == 0 {
		t.Fatal("no rules registered")
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Name() == "" {
			t.Error("a rule has no name")
		}
		if seen[rule.Name()] {
			t.Errorf("rule %q is registered twice", rule.Name())
		}
		seen[rule.Name()] = true
		if rule.Claim() == "" {
			t.Errorf("rule %q has no claim", rule.Name())
		}
		if rule.Impact().Rank() < SeverityHigh.Rank() {
			t.Errorf("rule %q impacts at %q; a chain rule that fires is at least high", rule.Name(), rule.Impact())
		}
		// A rule that fires without proof would be a rule that can produce a
		// critical row from a guess, so its unproven path must be a potential.
		chain := chainFinding(rule, ChainInput{}, false, "e", "m", []Finding{{
			Module: "xss", Endpoint: "https://t.test/a", Method: "GET", Param: "q",
		}})
		if chain.Tier != TierPotential {
			t.Errorf("rule %q produces %q without proof", rule.Name(), chain.Tier)
		}
		if chain.Severity.Rank() > SeverityMedium.Rank() {
			t.Errorf("rule %q produces %q without proof, above the cap", rule.Name(), chain.Severity)
		}
		if !strings.HasPrefix(chain.Title, "Potential ") {
			t.Errorf("rule %q unproven title = %q, want it marked Potential", rule.Name(), chain.Title)
		}
	}
}

func TestChainFindingNamesItsMembers(t *testing.T) {
	rule := &ChainXSSToAccountTakeover{}
	a := finding(t, "xss", TierVerified, "https://t.test/a", "q", "one")
	b := finding(t, "xss", TierVerified, "https://t.test/b", "q", "two")
	got := chainFinding(rule, ChainInput{}, true, "evidence", "", []Finding{a, b})
	if len(got.ChainOf) != 2 {
		t.Fatalf("chain_of = %v, want both members", got.ChainOf)
	}
	if !strings.Contains(got.Payload, got.ChainOf[0]) {
		t.Errorf("payload = %q, want it to carry the member ids", got.Payload)
	}
}
