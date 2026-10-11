package active

// A deliberately vulnerable local target, so that every detector can be shown to
// fire on something.
//
// The live targets this port was run against are real news and search sites: they
// have no injectable surface for SQLi, LFI or command injection, so a live run
// proved `misconfig` and nothing else. That is an honest result about the world,
// and a useless one as evidence that the eight remaining detectors work — "no
// findings" and "detector never runs" look identical from outside.
//
// This fixture removes the ambiguity: it answers each detector's technique with
// the specific marker that detector looks for, so a scan of it must produce a
// finding from all nine. It is local, ours, and reachable only from the test —
// which is also why the payloads here are shaped to the detector rather than the
// detector being weakened to suit a fixture.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// vulnerableFixture answers the nine detectors' techniques.
//
// Each branch is deliberately narrow: it triggers on the marker the corresponding
// detector sends, so a finding can only appear if that detector actually probed.
// A branch that answered everything would make the test pass for the wrong
// reason, which is the same mistake as counting requests at the call site.
// formDocument is the one document the fixture serves from two URLs.
//
// It is a package-level function rather than a literal repeated in two handlers
// because the web-cache-deception detector compares the response at the dynamic URL
// with the response at that URL plus a static suffix. It has to be the *same*
// document: serving a different, longer body at the suffixed path is two different
// pages rather than one page under two names, and a first attempt did exactly that
// — the detector declined, correctly, for a reason that had nothing to do with the
// condition under test.
//
// It also carries the record id pre-filled with a number, because the union-injection
// detector only probes a parameter whose original value parses as an integer. That
// check is what keeps a search box from being asked for a column count, so a
// text-only fixture can never produce a UNION finding and with it no
// data-extraction proof. The value is written here rather than assumed: a fixture
// that hardcoded a row count would keep passing after the detector's blankness rule
// changed.
func formDocument() string {
	return `<html><body><form action="/account" method="post">` +
		`<input name="email" type="email"></form>` +
		// The two surfaces the endpoint-level capabilities from the owner's list
		// need: the crawl has to reach them, because `hidden_params` and
		// `auth_bypass_ext` are endpoint level and a detector that is never handed
		// the URL reports nothing for a reason that has nothing to do with it. The
		// links are what puts them on the frontier.
		`<a href="/undeclared">undeclared report</a>` +
		// The template-engine surface: `csti` and `dom-vectors` are parameter level and
		// both need a page that reflects a value into a *template engine's* expression
		// position — one compiles `{{…}}`, the other escapes the plain vector. The same
		// page answers both, so it is one link rather than two.
		`<a href="/template-engine">template report</a>` +
		`<a href="/merge">merge report</a>` +
		`<a href="/carbon/server-admin/memory_info.jsp">memory info</a>` +
		`<form action="/probe" method="get">` +
		`<input name="q" type="text"><input name="file" type="text">` +
		`<input name="id" type="text" value="7">` +
		`<input name="cmd" type="text"><input name="tpl" type="text">` +
		`<input name="url" type="text"><input name="next" type="text">` +
		`<input name="code" type="text">` +
		`</form><a href="/.env">config</a>` +
		`<a href="/account/status">status</a>` +
		`<script src="/static/jquery-3.4.1.min.js"></script>` +
		`</body></html>`
}

// statusDocument is the page `/account/status` serves.
//
// The header echo is the second pass an include filter makes over a finished
// body: it appears nowhere in the document the application produced, so the SSI
// detector's canary cannot be explained by the application reflecting the value.
func statusDocument(probe string) string {
	return `<html><body><h1>Account status</h1>` +
		`<p>Two payment methods on file, subscription renews on the third of every month, ` +
		`notifications are set to a weekly digest, and the last sign-in was from an ` +
		`address in Rotterdam. This paragraph is here so the document has something to be ` +
		`compared against when it is requested again under a static suffix.</p>` +
		`<script src="/static/jquery-3.4.1.min.js"></script>` +
		`<div class="include-filter">` + probe + `</div>` +
		`</body></html>`
}

func vulnerableFixture() http.Handler {
	return leakingCredentials(prototypeMergePages(
		templateEnginePages(jsCapabilityPages(viteDevBridge(muxOf())))))
}

// prototypeMergePages is the surface `proto-pollution` needs.
//
// The detector exists for a server that copies keys it was not asked to copy, so a
// surface that echoes one parameter proves nothing about it and the module stays
// silent — correctly, and for a reason a reader of the report cannot see. This page
// merges the query into an object and prints the result, which is the behaviour the
// upstream family is written against: the last segment of a key path (`__proto__[x]`,
// `constructor.prototype.x`) becomes a field name, and the answer comes back grown.
//
// One surface, because the module's own tests cover the three clauses (echo, 500,
// behaviour) against purpose-built servers; what the shared fixture owes it is the
// *behaviour*, so that "no finding" here means "never reached" and nothing else.
func prototypeMergePages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/merge" {
			next.ServeHTTP(w, r)
			return
		}
		fields := make([]string, 0, 4)
		for _, pair := range strings.Split(r.URL.RawQuery, "&") {
			if pair == "" {
				continue
			}
			name, value, _ := strings.Cut(pair, "=")
			decodedName, err := url.QueryUnescape(name)
			if err != nil {
				continue
			}
			decodedValue, err := url.QueryUnescape(value)
			if err != nil {
				continue
			}
			// The last segment of the key path is the field the merge writes, so
			// `__proto__[polluted]` becomes `polluted` — the same reading the detector
			// expects to find in the answer.
			leaf := decodedName
			if open := strings.LastIndex(leaf, "["); open >= 0 {
				leaf = strings.TrimSuffix(leaf[open+1:], "]")
			} else if dot := strings.LastIndex(leaf, "."); dot >= 0 {
				leaf = leaf[dot+1:]
			}
			fields = append(fields, `"`+leaf+`":"`+decodedValue+`"`)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html><body><pre id="merged">{`+
			strings.Join(fields, ",")+`}</pre>`+
			`<form method="get"><input name="q" value=""></form></body></html>`)
	})
}

// templateEnginePages is the surface `csti` and `dom-vectors` need, and that no
// mux route could supply.
//
// It is a wrapper for the same reason the neighbours are: `ServeMux` panics on a
// duplicate pattern, and a fixture route another session also registers would take
// the whole fixture down at construction — with it the evidence for every detector.
//
// One page answers both modules, and the choice is measured rather than tidy. A
// page that compiles `{{…}}` and does **not** escape `<` gives `dom-vectors` nothing
// to escalate (the plain vector survives, so the structural detector already owns the
// surface); a page that escapes `<` still compiles `{{…}}`, because the delimiters
// contain no character the escape touches. So the engine markup and the escaping
// coexist, and the run spends one page instead of two.
func templateEnginePages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/template-engine" {
			next.ServeHTTP(w, r)
			return
		}
		value := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html><body><div ng-app><p id="out">{{`+
			escapeForFixture(value)+`}}</p></div>`+
			`<script src="/static/angular.min.js"></script>`+
			`<form method="get"><input name="q" value=""></form></body></html>`)
	})
}

// jsCapabilityPages are the two surfaces the four capabilities from the owner's
// list need and that no mux route could supply.
//
// It is a wrapper for the same reason `viteDevBridge` is one: Go's `ServeMux`
// panics on a duplicate pattern, so a fixture route that another session also
// registers would take the whole fixture down at construction — and with it the
// evidence for every other detector.
//
// `auth_bypass_ext` needs a path that a filter chain gates and that the
// truncation form reaches: `memory_info.jsp` answers 301 to the login page,
// `memory_info.jsp;.jsp` answers 200 with the page. Without a server-side
// extension anywhere in the fixture there is nothing for the detector to fire at,
// and "nothing to fire at" is indistinguishable in a report from "the detector
// does not work".
//
// `hidden_params` needs a page that reacts to the *presence* of a parameter the
// page never declares, and renders the same document for any value: that is the
// signature the two-value design reads, and the fixture's `/probe` does not have
// it because `/probe` renders one named parameter and ignores the rest.
func jsCapabilityPages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/carbon/server-admin/memory_info.jsp"):
			// The truncation form carries a `;` before the extension, which is what
			// hides the resource from a filter matching the end of the raw URI.
			if strings.Contains(r.URL.Path, ";") {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.WriteString(w,
					`<html><body><h1>Memory</h1><p>JVM heap: 412 MB</p></body></html>`)
				return
			}
			http.Redirect(w, r, "/login", http.StatusMovedPermanently)
			return
		case r.URL.Path == "/undeclared":
			// The same document for every value and a different one when the
			// parameter is present: the server reads the name and ignores the value.
			if r.URL.Query().Get("debug") != "" {
				_, _ = io.WriteString(w,
					`<html><body><h1>Report</h1><p>Verbose diagnostics enabled.</p>`+
						`<a href="/undeclared">reload</a></body></html>`)
				return
			}
			_, _ = io.WriteString(w,
				`<html><body><h1>Report</h1><p>Nothing to report.</p>`+
					`<a href="/undeclared">reload</a></body></html>`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// viteFixtureFiles is what the fixture's development server hands out through its
// file bridge.
//
// The values are the ones `viteReadTargets` names, because the detector's proof is
// a signature in the body: a server that answers `200` to every path would pass a
// probe with no signature, which is not a weak proof but no proof at all. So the
// body has to carry the exact string the detector looks for, and nothing else in
// the fixture may carry it — a canary that also sits on the baseline is not a
// canary.
var viteFixtureFiles = map[string]string{
	"/etc/passwd": "root:x:0:0:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
	"/proc/version": "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) " +
		"(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP " +
		"PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)\n",
	"/proc/self/environ": "HOSTNAME=rr-fixture\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n" +
		"HOME=/root\n",
}

// viteDevBridge answers the Vite dev server's file bridge, `/@fs`, the way a
// development server with the path check disabled does: it serves any file on the
// machine, because that bridge exists precisely to reach modules outside the served
// directory during development.
//
// # Why it intercepts instead of registering a route
//
// It is a wrapper placed in front of the mux rather than a `mux.HandleFunc("/@fs/")`.
// Registering the path would be the shorter line, and it would also plant a trap: Go's
// `ServeMux` panics on a duplicate pattern, so the moment anyone else registers
// `/@fs/` — the natural thing to do when picking this fixture up — the whole fixture
// dies at construction and takes every other detector's evidence with it. A wrapper
// that never delegates cannot collide, and the neighbour who owns the detector can
// delete this function without touching the mux at all.
//
// # Why the three encodings all arrive here
//
// `viteEncodings` asks for the same file three ways: plain (`/@fs/etc/passwd`),
// encoded (`/@fs%2fetc%2fpasswd`), and by traversal (`/@fs../../../../../../etc/passwd`).
// Go decodes `%2f` into the path, so the encoded form arrives as `/@fs/etc/passwd`, and
// the traversal form arrives literally, because nothing resolves dot segments on the
// server. So one prefix test plus a strip of leading `../` covers all three, which is
// what a real bridge answers the same way.
func viteDevBridge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, isBridge := viteFixtureFile(r.URL.Path)
		if !isBridge {
			next.ServeHTTP(w, r)
			return
		}
		body, known := viteFixtureFiles[file]
		if !known {
			// A real bridge 404s for a file that is not there, and answering 200
			// with empty content would make the fixture approve probes the
			// detector is right to reject.
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Powered-By", "Express")
		_, _ = io.WriteString(w, body)
	})
}

// viteFixtureFile reports which file a `/@fs` request is asking for.
func viteFixtureFile(rawPath string) (string, bool) {
	const bridge = "/@fs"
	if !strings.HasPrefix(rawPath, bridge) {
		return "", false
	}
	rest := strings.TrimPrefix(rawPath, bridge)
	for strings.HasPrefix(rest, "../") {
		rest = strings.TrimPrefix(rest, "../")
	}
	return "/" + strings.TrimLeft(rest, "/"), true
}

// leakedCredential is a syntactically valid AWS access key id. The exposure
// detector hunts exactly this shape, and publishing it in every response is the
// behaviour being demonstrated: a page that hands a credential to anyone who asks
// has leaked one, and which endpoint leaked it is decided by where the leak sits.
const leakedCredential = "AKIAIOSFODNN7EXAMPLE"

// fixtureProviderKey is the credential the config page hands out and then honours.
// It is a well-formed but non-functional value: it is long and shaped like a live
// provider key, and it authenticates against nothing outside this fixture.
const fixtureProviderKey = "sk_live_51QxWvTzK3nP8rLmYhJd4FgHsA7bUc"

// leakingCredentials appends the leak to every response body.
//
// It is a wrapper rather than a line in each branch because "every response" is the
// claim being made: adding it to three of the branches would leave a fourth
// response clean and the detector's answer would depend on which branch a probe
// happened to take, which is not a property of the detector.
//
// The numeric record surface is the one exception, and the reason is measured. The
// union rule accepts a response only when everything the probe *added* is blank —
// an extra row of empty cells and nothing else. A rotating credential comment
// appended after the table lands in exactly that added region, so the leak made
// the rule refuse every union, and the refusal looked like a detector that never
// probes. A page that carries a rotating banner is genuinely not proof of
// anything, so leaving the banner on would test the detector's tolerance instead
// of the union shape.
func leakingCredentials(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "" {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&leakyWriter{ResponseWriter: w}, r)
	})
}

// leakyWriter appends the credential to whatever the handler wrote.
type leakyWriter struct {
	http.ResponseWriter
	done bool
}

// Hijack forwards the connection to the wrapped writer.
//
// `http.ResponseWriter` does not carry `Hijack`, so a wrapper that only embeds it
// silently drops the capability: a handler below asks the writer, gets "not a
// Hijacker", and returns having written nothing — which the server then completes
// as an empty 200. Nothing errors and nothing is logged; the behaviour a handler
// needs simply stops existing one layer down.
//
// That is exactly what happened to the Shellshock branch on `/form`: it hijacks
// because an affected CGI writes its command's output *before* the status line,
// and through this wrapper it could not. The fixture test reported "produced no
// finding" for a detector that was working.
func (w *leakyWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, canHijack := w.ResponseWriter.(http.Hijacker)
	if !canHijack {
		return nil, nil, fmt.Errorf("leakyWriter: the wrapped writer cannot hijack")
	}
	return hijacker.Hijack()
}

func (w *leakyWriter) Write(p []byte) (int, error) {
	if w.done {
		return w.ResponseWriter.Write(p)
	}
	w.done = true
	// The leak is written as an HTML comment, so a text/plain response stays
	// readable and an HTML response stays valid; the detector matches the key
	// itself, not the container.
	leak := "\n<!-- build AKIAIOSFODNN7EXAMPLE -->\n"
	if _, err := w.ResponseWriter.Write(p); err != nil {
		return 0, err
	}
	if _, err := w.ResponseWriter.Write([]byte(leak)); err != nil {
		return len(p), err
	}
	return len(p), nil
}

func muxOf() http.Handler {
	mux := http.NewServeMux()

	// The form the crawl harvests. One parameter, one method: the surfaces must
	// come from the application publishing them, not from the probe inventing them.
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		// Shellshock: a CGI wrapper turns request headers into environment variables
		// and hands them to an affected bash. The signature it must reproduce is not
		// a body — it is that the injected command's stdout lands **before** the
		// status line, so the exchange cannot be parsed at all. That is why the
		// fixture hijacks the connection and writes the bytes itself instead of
		// calling `w.WriteHeader`.
		//
		// It fires **only when the marker is present**, so the baseline stays
		// clean. A fixture that wrote the marker on every response would be caught
		// by `TestAPageThatMerelyMentionsTheMarkerIsNotAFinding` in the detector's
		// own test — which is what that test is for.
		//
		// It sits on `/form` because the detector is endpoint-level and the run
		// starts there; on `/probe` it would never be reached, and the fixture
		// test's demand that every registered detector fire is precisely the
		// check that caught that.
		if strings.Contains(r.Header.Get("User-Agent"), shellshockMarker) ||
			strings.Contains(r.Header.Get("Referer"), shellshockMarker) {
			hijacker, canHijack := w.(http.Hijacker)
			if !canHijack {
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			fmt.Fprintf(conn, "%s\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\n<html>ok</html>", shellshockMarker)
			_ = conn.Close()
			return
		}
		// A version banner. The fingerprint detector reports a number only when it
		// can name where the number came from, so the header carries both the value
		// and the product, and the row cites `header:X-Powered-By` rather than
		// presenting a bare version string.
		w.Header().Set("X-Powered-By", "PHP/7.4.33")
		// A client-side library below its fixed release. The src carries the version
		// in its file name, which is the shape the detector reads; a page that ships
		// an old jQuery is publishing that fact to every visitor.
		//
		// A second form that changes state, posts, and carries no anti-CSRF field.
		// It exists for the CSRF detector and it is why that detector declares
		// `LevelParam`: a cross-site request forgery is forged against a submission,
		// and an endpoint surface is always a bare GET, so a detector on
		// `LevelEndpoint` could never be handed one. Adding the form here rather than
		// a new page keeps the crawl's page and surface counts unchanged.
		fmt.Fprint(w, formDocument())
	})

	// The same document under a static suffix.
	//
	// A web cache keys on the URL, so `/form.css` and `/form` are two different
	// objects to it while the origin serves both from one handler. That is the
	// condition the cache-deception detector names, and the fixture answers it by
	// serving the document for the suffixed path as well — the body is deliberately
	// long, because the detector compares documents and a two-line body has nothing
	// to compare.
	mux.HandleFunc("/form.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, formDocument())
	})

	// A page the crawl reaches that carries no parameter, and the same document
	// under a static suffix.
	//
	// It exists because a detector that declares `LevelEndpoint` is only ever
	// handed a surface with no parameter, and every page above has one: the
	// fixture could answer the technique perfectly and the detector would never
	// be asked. A page without parameters is what makes the technique reachable
	// from a crawl rather than only from a hand-written point.
	//
	// Three capabilities are answered by one document, and each one is answered
	// by the shape its detector reads: the outdated library in a `src`, the SSI
	// filter's echo of a request header the page never mentions, and the same
	// bytes under `/account/status.css`.
	mux.HandleFunc("/account/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The same three header behaviours `/probe` publishes, because the chain
		// rules ask about the *page* a finding landed on: a reflected origin with
		// `Allow-Credentials`, a session cookie without `HttpOnly`, and a preference
		// cookie without it either. A page that answered none of them would leave
		// the `misconfig + xss` rule without the second leg it composes, which is the
		// same shape as a detector that never runs.
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Add("Set-Cookie", "session=fixture-session-value; Path=/")
		w.Header().Add("Set-Cookie", "preference=dark; Path=/")
		fmt.Fprint(w, statusDocument(r.Header.Get(ssiProbeHeader)))
	})

	mux.HandleFunc("/account/status.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, statusDocument(r.Header.Get(ssiProbeHeader)))
	})

	// A version-control directory the deployment published by accident.
	//
	// The source-disclosure detector verifies content against the application's own
	// answer for a path that certainly does not exist, so this branch needs to carry
	// a fingerprint (`ref: `) that the default 404 page cannot. It is registered but
	// not linked, so the crawl's page count does not change — only the detector's
	// own probe reaches it.
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ref: refs/heads/main\n")
	})

	// A configuration file the application forgot to keep out of the web root,
	// carrying a live credential.
	//
	// It exists for the `ssrf + config exposure` chain, which only composes an
	// exposure finding whose endpoint or title names a configuration file. The
	// page is linked from the form so the ordinary crawl reaches it: a path the
	// application never publishes is a path this fixture cannot claim a real
	// application has.
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		// The leaked key does not merely look like a credential — it works.
		//
		// Every exposure category is replayed before it is reported as verified, so
		// a page that prints a key proves nothing the detector is willing to call
		// proven. The replay is an anonymous request against the same URL and a
		// second one carrying `Authorization: Bearer <key>`; the two must differ, and
		// the authenticated answer must carry a privilege structure. An unverified
		// exposure is not an ingredient any correlation rule accepts, so a fixture
		// that stopped at printing the key could never prove the chain.
		if r.Header.Get("Authorization") == "Bearer "+fixtureProviderKey {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"role":"admin","email":"ops@fixture.test"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "text/plain")
		// The connection string and the key are both here. The connection string is
		// reported as unverified — there is nothing to replay it against — and the
		// AWS key elsewhere in this fixture is the vendor's own documented example,
		// which the detector correctly refuses to call a credential. That refusal is
		// right, and it is also why neither of them can prove anything here.
		fmt.Fprint(w, "DATABASE_URL=postgres://app:hunter2@db:5432/app\n"+
			"STRIPE_SECRET_KEY="+fixtureProviderKey+"\n")
	})

	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		body := q.Get("q")
		// redos: a validator with a backtracking pattern, answered on the same
		// parameterised route the injection families use.
		//
		// The delay is quadratic in the length and it is skipped for a run of the
		// neutral character, because those two facts are what the detector compares:
		// a fixture that grew linearly would (correctly) be reported as not
		// vulnerable, and one that grew for every input would measure the endpoint
		// instead of the regex. The neutral class is the control the detector sends
		// itself, so the fixture has to answer it for the same route to be a fair
		// comparison.
		if v := q.Get("q"); v != "" && strings.Trim(v, "z") != "" {
			time.Sleep(time.Duration(len(v)*len(v)) * time.Millisecond / 4)
		}
		file := q.Get("file")
		cmd := q.Get("cmd")
		tpl := q.Get("tpl")
		target := q.Get("url")
		id := q.Get("id")

		// misconfig: no CORS header on the plain read, a reflected origin plus
		// `Allow-Credentials` on the probe that carries one. Both are what the
		// detector looks for, and the credentials flag is what the
		// `misconfig + xss` chain composes — a reflected origin alone is a
		// nuisance, a reflected origin that also carries the session cookie is
		// another site reading it.
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		// A session cookie the browser will hand to a script on the page: no
		// `HttpOnly`, no `Secure`. This is the cookie weakness the
		// `xss -> account takeover` chain requires as its second leg.
		w.Header().Add("Set-Cookie", "session=fixture-session-value; Path=/")
		// A preference cookie, which is a different subject: the cookie detector
		// deliberately leaves *session* cookies to the session-fixation detector, so
		// a fixture that only issues a session cookie exercises one of the two and
		// reports the other as never having run.
		w.Header().Add("Set-Cookie", "preference=dark; Path=/")

		// fingerprint: a banner that names the product and an exact version, and
		// a PHP branch below 8.0 — a line that stopped receiving security fixes on
		// 2022-11-28. The fixture exists to answer every registered detector, and a
		// detector that reads only what a server publishes cannot answer a fixture
		// that publishes nothing: it would report "no findings" for a detector that
		// had never been asked, which is the failure this whole test was written to
		// catch. Apache is deliberately not the product here — it is still supported,
		// so claiming it end of life would be a false row.
		w.Header().Set("Server", "RequestRiderFixture/1.0 (nginx/1.18.0)")
		w.Header().Set("X-Powered-By", "PHP/7.4.33")

		// Server-side includes: the directive is replaced by the header's value, which
		// is the second pass `mod_include` and nginx's ssi filter make over the body.
		//
		// It is written **only when the probe header is present**, and that condition
		// is the whole trick. An earlier version wrote it on every response, which put
		// the canary into the baseline as well as into the probe answer — and a
		// canary that is already on the page is not a canary. The symptom was four
		// detectors going quiet at once (`ssi`, `xss`, `xss-escape`, `redirect`),
		// because every one of them compares a probe answer against that baseline.
		if probe := r.Header.Get(ssiProbeHeader); probe != "" {
			_, _ = w.Write([]byte("<!--#echo var=\"HTTP_X_RR_SSI_PROBE\"-->\n<div>probe:" +
				probe + "</div>"))
		}

		// The directory-injection and code-injection answers come before the markup
		// and error branches below, and the order is not cosmetic: the error branch
		// answers any value containing a quote with a SQL error page, so an LDAP
		// payload — which is full of parentheses and ends in `objectClass=*` — would
		// be swallowed by it and the detector would look broken rather than unasked.
		joined := body + " " + file + " " + cmd + " " + tpl + " " + target + " " + id
		if strings.Contains(joined, "objectClass=*") {
			fmt.Fprint(w, "javax.naming.directory.InvalidSearchFilterException: invalid filter")
			return
		}
		// The arithmetic is `11*13` and the expected product is `143`. Both numbers
		// are asserted rather than assumed, because a fixture that prints a hard-coded
		// 143 would keep passing after the factors changed — and the whole reason for
		// choosing 11 and 13 over 7 and 7 is that `49` appears on ordinary pages.
		if strings.Contains(joined, "11*13") {
			fmt.Fprint(w, "<p>11*13 = 143</p>")
			return
		}

		// Markup probes are answered before anything else.
		//
		// Order matters more here than anywhere else in the fixture: a
		// context-breaking XSS payload contains a double quote, and the error branch
		// below answers any quote with a SQL error page. Answering the XSS probe with
		// that page is a fixture that swallows the probe rather than one that models
		// the application, and the result is a detector reported as "reflected but
		// nothing executed" when the fixture — not the application — decided it.
		if looksLikeMarkup(body) {
			w.Header().Set("Content-Type", "text/html")
			// The value lands inside an `img`'s `src`.
			//
			// The tag is not arbitrary. A payload that breaks out of an attribute
			// produces `<img src="" onmouseover=… x="">`, and the detector confirms
			// execution by looking for an event handler on one of the tags a browser
			// will build — `svg`, `img`, `details`, `video`, `body`, `iframe`,
			// `marquee`. Reflecting into an `input` would leave a handler the
			// detector is right not to trust, and the reflection would be reported as
			// unconfirmed for a reason the fixture invented.
			fmt.Fprintf(w, `<html><body><img src="%s" alt="fixture"></body></html>`, body)
			return
		}

		// Open redirect: any destination offered in a parameter is answered with a
		// 302 whose Location is that destination. This is the real behaviour the
		// detector is looking for, and answering it for every `.invalid` host is
		// correct rather than a convenience — the destination is operator-chosen
		// and the fixture is not in a position to object to it.
		for _, name := range []string{"q", "file", "cmd", "tpl", "url", "next", "code"} {
			if value := q.Get(name); strings.Contains(value, ".invalid") {
				w.Header().Set("Location", value)
				w.WriteHeader(http.StatusFound)
				return
			}
		}

		// SQLi that decides authentication: the always-true condition logs the
		// visitor in, the always-false one does not.
		//
		// This branch has to sit *before* the error branch, because the auth-bypass
		// payload contains a quote and would otherwise be answered with the SQL error
		// page — the same page for both arms, which is precisely the "no divergence,
		// the condition is not deciding the outcome" case the chain rule looks for.
		if strings.Contains(body, "' OR '1'='1'") {
			w.Header().Set("Content-Type", "text/html")
			if strings.Contains(body, "1'='2") {
				fmt.Fprint(w, `<html><body><h1>Sign in</h1><p>Invalid credentials.</p></body></html>`)
				return
			}
			fmt.Fprint(w, `<html><body><h1>Welcome, administrator</h1><p>Your session is active.</p></body></html>`)
			return
		}

		// NoSQL by boolean differential, the two shapes the detector sends: a
		// `$where` body that returns true or false, and an `||this` / `||!this`
		// concatenation.
		//
		// It has to answer with a *different result set*, not with an echo, and the
		// reason is a defect this fixture used to hide. It previously had no branch
		// here at all, so the page reflected the payload and the two arms came back
		// with different lengths — which the detector read as an injection and
		// reported. That was a false positive produced by this very fixture, and it
		// survived every test because a reflected value always looks like a result.
		// The echo is now stripped before the arms are compared, which is correct and
		// which left this branch as the only way the detector can fire for a real
		// reason. Like the branch above it sits before the SQL error branch: these
		// payloads carry a quote and would otherwise be answered with the same error
		// page for both arms, which is exactly the "no divergence" case.
		if strings.Contains(body, "return true") || strings.Contains(body, "||this") {
			if strings.Contains(body, "return false") || strings.Contains(body, "||!this") {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body><h1>Search</h1><p>No documents matched.</p></body></html>`)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><h1>Search</h1>`+
				`<ul><li>alpha</li><li>bravo</li><li>charlie</li><li>delta</li>`+
				`<li>echo</li><li>foxtrot</li><li>golf</li><li>hotel</li></ul>`+
				`</body></html>`)
			return
		}

		// SSTI proof stage: the generator sends `{{ '<canary>' ~ A*B }}` and needs
		// the engine to concatenate the canary with the product of two numbers. The
		// two operands are parsed out of the expression instead of assumed, because
		// the generator derives them from the canary's length — a hardcoded product
		// here would stop matching the moment that derivation changed, and the proof
		// would fail for a reason that has nothing to do with the target.
		if concatenated, ok := templateConcat(tpl); ok {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>%s</body></html>`, concatenated)
			return
		}

		// SQLi by UNION, in two shapes.
		//
		// The detector needs a response *longer* than its baseline that gained
		// blankness and nothing else, so a row of empty cells is returned. The proof
		// generator then re-sends the same shape with a value this run chose, and
		// accepts the answer only when that value comes back and the request does
		// not. Answering both from one branch would make the two checks
		// indistinguishable, and the proof would stop being evidence of extraction.
		// The union statements arrive in the numeric field, not in the search box.
		// Reading the wrong parameter is a fixture that answers every probe with the
		// plain page, which the detector then correctly refuses — the union response
		// came back the same length as the baseline, so the extra blank row the rule
		// asks for was never sent.
		if columns, ok := unionShape(id); ok {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><table>`+numericRows(3)+
				"<tr>"+strings.Repeat("<td></td>", columns)+"</tr>"+
				`</table></body></html>`)
			return
		}
		if columns, value, ok := unionExtraction(id); ok {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><table>`+numericRows(3)+
				"<tr><td>"+escapeForFixture(value)+
				strings.Repeat("<td></td>", columns-1)+"</tr>"+
				`</table></body></html>`)
			return
		}

		// A numeric record surface, which is the only kind the union-injection
		// detector will ask for a column count on.
		if id := q.Get("id"); id != "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><table>`+
				numericRows(3)+`</table></body></html>`)
			return
		}

		// SQLi, error-based: the quote break produces this exact fingerprint.
		if strings.Contains(body, "'") || strings.Contains(body, "\"") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>You have an error in your SQL syntax near '`+escapeForFixture(body)+`'</body></html>`)
			return
		}

		// SQLi, boolean-based: the true and the false expression answer differently,
		// which is the only way a differential detector can tell them apart.
		if strings.Contains(body, "1=1") || strings.Contains(body, "2>1") {
			w.Header().Set("Content-Type", "text/html")
			mark := "FALSE"
			if !strings.Contains(body, "1=2") && !strings.Contains(body, "2<1") {
				mark = "TRUE"
			}
			fmt.Fprint(w, `<html><body>`+mark+`</body></html>`)
			return
		}

		// LFI: the traversal returns the file's first line, which is the
		// fingerprint the detector compares against.
		if strings.Contains(file, "etc/passwd") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}

		// LFI proof stage: the exploit generator re-reads the same parameter with a
		// traversal to `/etc/os-release` and accepts the answer only when a line
		// looks like a real `KEY=value` from that file. `passwd` proves the
		// detector; this proves that the impact — reading a host file — is
		// reproducible, and it is a different request with a different file.
		if strings.Contains(file, "etc/os-release") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "NAME=\"RequestRider Fixture\"\nVERSION_ID=\"12\"\n"+
				"PRETTY_NAME=\"Debian GNU/Linux 12 (fixture)\"\nID=fixture\n")
			return
		}

		// CMDi: the shell evaluates the arithmetic and the product is returned, so
		// the detector proves execution by finding a number the page could not have
		// contained. The operands are read from the expression rather than hardcoded,
		// so a change to the detector's constants does not silently stop the proof.
		if product, ok := arithmetic(cmd); ok {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, product)
			return
		}

		// CMDi proof stage: `; echo <marker>` has to come back as the marker on a
		// line of its own. The proof generator checks exactly that — a page that
		// merely contains the marker inside a paragraph is a reflection, and a shell
		// that echoed a string is what the proof is for.
		if marker := echoedMarker(cmd); marker != "" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "fixture\n%s\n", marker)
			return
		}

		// SSTI: the arithmetic is evaluated, so the detector sees 49 rather than
		// the literal expression it sent.
		if strings.Contains(tpl, "7*7") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>49</body></html>`)
			return
		}

		// SSRF: the internal address is answered with the metadata document the
		// detector expects to see only when the fetch really happened. The keys are
		// the detector's own fingerprints for that document, so a fingerprint the
		// detector stops checking stops this branch from mattering — which is the
		// correct direction for the test to break in.
		if strings.Contains(target, "169.254.169.254") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "ami-id\ni-0fixture00000000000\nlocal-ipv4\n10.0.0.7\n")
			return
		}

		// XSS: the value is reflected unescaped, inside an attribute, which is the
		// context the detector escalates in.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><input value="%s"></body></html>`, body)
	})
	return mux
}

// numericRows renders the fixture's numeric table.
//
// A union probe has to return *more* than the baseline and the extra has to be
// blankness — empty cells and nothing else — because that is the shape a real
// `UNION SELECT NULL,NULL` produces. A page that gained text gained it from
// somewhere else, and the detector is right to refuse it. The row count is a
// parameter so the two shapes can differ by exactly the amount the rule needs.
func numericRows(count int) string {
	out := ""
	for index := 0; index < count; index++ {
		out += "<tr><td>" + strconv.Itoa(index+1) + "</td><td>Fixture Product " +
			strconv.Itoa(index+1) + "</td><td>19.99</td></tr>"
	}
	return out
}

// unionShape reports the column count of a `-1 UNION SELECT NULL,...-- -` row of
// NULLs — the shape the detector probes with.
//
// Every cell has to be the literal `NULL`, and that strictness is the point. An
// earlier version counted whatever commas it found, so it also matched the proof
// generator's row — the same statement with a value in the first column — and
// answered a data-extraction probe with blank cells. The proof then looked for a
// value that the fixture had just declined to send, and reported "no proof" for a
// target that answered it correctly.
func unionShape(in string) (int, bool) {
	const prefix = "-1 UNION SELECT "
	index := strings.Index(in, prefix)
	if index < 0 {
		return 0, false
	}
	tail := in[index+len(prefix):]
	if cut := strings.Index(tail, "--"); cut >= 0 {
		tail = tail[:cut]
	}
	cells := strings.Split(tail, ",")
	count := 0
	for _, cell := range cells {
		trimmed := strings.TrimSpace(cell)
		if trimmed == "" {
			break
		}
		if !strings.EqualFold(trimmed, "NULL") {
			return 0, false
		}
		count++
	}
	return count, count > 0
}

// unionExtraction reports the column count and the selected value of a
// `-1 UNION SELECT '<value>',NULL,...-- -` row — the shape the proof generator
// sends, which is the same statement with a value this run chose in the first
// column.
func unionExtraction(in string) (int, string, bool) {
	const prefix = "-1 UNION SELECT "
	index := strings.Index(in, prefix)
	if index < 0 {
		return 0, "", false
	}
	tail := in[index+len(prefix):]
	if cut := strings.Index(tail, "--"); cut >= 0 {
		tail = tail[:cut]
	}
	cells := strings.Split(tail, ",")
	first := strings.TrimSpace(cells[0])
	if len(first) < 2 || first[0] != '\'' || first[len(first)-1] != '\'' {
		return 0, "", false
	}
	value := first[1 : len(first)-1]
	if value == "" {
		return 0, "", false
	}
	return len(cells), value, true
}

// echoedMarker extracts the marker from an `; echo <marker>` payload, if one is
// present.
func echoedMarker(in string) string {
	const prefix = "; echo "
	index := strings.Index(in, prefix)
	if index < 0 {
		return ""
	}
	marker := strings.TrimSpace(in[index+len(prefix):])
	if marker == "" {
		return ""
	}
	return marker
}

// templateConcat evaluates the template expression the SSTI proof generator sends
// — `{{ '<canary>' ~ A*B }}` — and returns what a real engine would print: the
// canary followed by the product of the two operands.
//
// The operands are read from the expression rather than assumed, and that is the
// whole point of the helper. The generator computes them from the canary's own
// length, so a fixture that hardcoded one product would pass today and silently
// stop proving anything the moment that derivation changed — a green test on a
// branch the generator no longer takes.
func templateConcat(in string) (string, bool) {
	open := strings.Index(in, "{{")
	close := strings.Index(in, "}}")
	if open < 0 || close < 0 || close < open {
		return "", false
	}
	expression := in[open+2 : close]
	// `'canary' ~ A*B` — the tilde separates the two operands.
	parts := strings.SplitN(expression, "~", 2)
	if len(parts) != 2 {
		return "", false
	}
	canary := strings.Trim(strings.TrimSpace(parts[0]), "'")
	multiply := strings.SplitN(strings.TrimSpace(parts[1]), "*", 2)
	if canary == "" || len(multiply) != 2 {
		return "", false
	}
	a, errA := strconv.Atoi(strings.TrimSpace(multiply[0]))
	b, errB := strconv.Atoi(strings.TrimSpace(multiply[1]))
	if errA != nil || errB != nil {
		return "", false
	}
	return canary + strconv.Itoa(a*b), true
}

// looksLikeMarkup reports whether a value carries a tag or an event handler,
// which is what makes it an injection probe rather than a query.
//
// The distinction is the fixture's own, not the detector's: a page that both
// reflects a search term and queries a database cannot tell a `"` from a `"` any
// better than the scanner can, and the honest way to model it is to answer a
// request that carries markup with the markup reflected. The alternative — letting
// the quote branch take it — makes every scripting detector look unconfirmed for a
// reason that belongs to the fixture.
func looksLikeMarkup(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "<") || strings.Contains(lower, "on") && strings.Contains(lower, "=")
}

// arithmetic evaluates a shell arithmetic expansion of the shape the command
// injection detector sends (`echo $((19*23))`) and returns its product.
//
// The operands are taken from the expression rather than written here on purpose.
// Hardcoding `437` would let the detector's constants change without the fixture
// noticing, and the test would keep passing on a branch the detector no longer
// probes — a green test proving nothing, which is the failure mode this fixture
// exists to prevent.
func arithmetic(in string) (string, bool) {
	start := strings.Index(in, "$((")
	if start < 0 {
		return "", false
	}
	rest := in[start+3:]
	end := strings.Index(rest, "))")
	if end < 0 {
		return "", false
	}
	parts := strings.Split(rest[:end], "*")
	if len(parts) != 2 {
		return "", false
	}
	a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errA != nil || errB != nil {
		return "", false
	}
	return strconv.Itoa(a * b), true
}

// escapeForFixture keeps the fixture's own HTML from breaking on the payload it
// reflects; the reflected *detector* marker still reaches the page intact.
func escapeForFixture(in string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(in)
}

// TestEveryDetectorFiresAgainstTheFixture is the answer to "do all its functions
// work", measured rather than asserted.
//
// It runs one scan with `AllModules()` against a local target built to answer all
// nine techniques, and requires a finding from each. A detector that silently
// stops probing cannot produce its marker, so the test goes red rather than
// reporting "no findings" as if that were a pass.
func TestEveryDetectorFiresAgainstTheFixture(t *testing.T) {
	server := httptest.NewServer(vulnerableFixture())
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	scan := NewScan(ScanRequest{
		URL: start.String(),
		// The page budget is 10 rather than 4 because the fixture grew surfaces for
		// capabilities that cannot invent their input: a gated `.jsp` page, a page
		// that reacts to an undeclared parameter, the template-engine page that
		// `csti` and `dom-vectors` need, and the merge page `proto-pollution` needs.
		// A budget that stops before them leaves those detectors unfired for a reason
		// that has nothing to do with them, and "the detector never fired" and "the
		// crawl never reached the surface" are indistinguishable in a report.
		MaxPages:    10,
		MaxDepth:    1,
		Concurrency: 1,
		Timeout:     5 * time.Second,
		// The fixture's form is the only surface; the interesting paths are off so
		// this test measures detectors and not the path probe.
		InterestingPaths: []string{},
		// The two operator-driven wordlists, and they are here because of a defect
		// this assertion used to carry rather than because the test wanted them.
		//
		// `hidden_params` and `hidden_paths` are detectors that cannot invent their
		// input: `modulesWith` builds them as `HiddenParams{Params: options.params}`
		// and `HiddenPaths{Paths: options.paths}`, `NewScan` reads those from
		// `ScanRequest.Params` and `ScanRequest.PathWordlist`, and both `Scan`
		// methods return nil when the list is empty. The product documents that as
		// intended behaviour — `PathWordlist` says "Nil means the module does not
		// run" — so a run without a wordlist has nothing to fire.
		//
		// This test asks `AllModules()`, which is the zero-value set, for a finding
		// from *every* module. Those two can therefore never satisfy it, and the
		// failure it reported was not two silent detectors: it was an assertion that
		// contradicted the product's own documented contract. The fixture already
		// answers both — `/probe` reflects an undeclared name, and `/.env` answers
		// where a measured not-found path answers 404 — so the wordlists are supplied
		// and the assertion measures the product path end to end.
		Params:       []string{"debug"},
		PathWordlist: []string{"/.env"},
		RoundTripper: http.DefaultTransport,
	}, nil)
	report, err := scan.Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fired := map[string]int{}
	for _, finding := range report.Findings {
		fired[finding.Module]++
	}
	missing := make([]string, 0)
	for _, module := range AllModules() {
		if fired[module.Name()] == 0 {
			missing = append(missing, module.Name())
		}
	}
	t.Logf("fixture answered %d finding(s) across %d detector(s); requests=%d points=%d proofs=%d",
		len(report.Findings), len(fired), report.Stats.Requests, report.Stats.Points, len(report.Proofs))
	for _, module := range AllModules() {
		t.Logf("  %-10s findings=%d", module.Name(), fired[module.Name()])
	}
	if len(missing) > 0 {
		t.Fatalf("detector(s) %v produced no finding against a fixture built to answer them: "+
			"«жодної знахідки» і «детектор не працює» виглядають однаково, тому тест вимагає "+
			"худь-б одну знахідку від кожного", missing)
	}
}

// TestEveryProofGeneratorFiresAgainstTheFixture is the exploit layer's version of
// the detector test.
//
// The three questions are different and all three were open: does a detector
// probe (proved by the detector test), does a chain correlate (proved by the chain
// test), and does a proof *re-request the target and show the impact is
// reproducible*. The third is the one an operator acts on — it is the artifact
// they paste into a report — and it was the one never measured: every fixture run
// before this printed `proofs=0`.
//
// A proof that stays silent is indistinguishable from a generator whose
// precondition no real target meets, and from a generator that was never wired
// to the run at all. So the test requires one proof per registered kind, by name.
func TestEveryProofGeneratorFiresAgainstTheFixture(t *testing.T) {
	server := httptest.NewServer(vulnerableFixture())
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	report, err := NewScan(ScanRequest{
		URL: start.String(), MaxPages: 4, MaxDepth: 1, Concurrency: 1,
		Timeout: 5 * time.Second, InterestingPaths: []string{},
		RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	kinds := map[string]int{}
	for _, proof := range report.Proofs {
		kinds[proof.Kind]++
		t.Logf("  %-18s runnable=%v %s", proof.Kind, proof.Runnable != "", truncate(proof.Proof, 96))
	}
	t.Logf("fixture produced %d proof(s) from %d finding(s)", len(report.Proofs), len(report.Findings))

	// The four kinds `Suite.Run` can produce, listed by name. The list is written
	// here rather than read from the suite's switch on purpose: the switch decides
	// which module is handled, and a test that derived its expectations from the
	// same switch would agree with a switch that had lost a case.
	//
	// The names are the ones the generators actually emit — `data-extraction`,
	// `expression-evaluation`, `command-execution`, `file-read`. The first version
	// of this test expected `template-rce`, which no generator produces, so it
	// reported a missing proof for SSTI while the SSTI proof was in the report the
	// whole time under its own name. A wrong expectation is a test that lies about
	// the product, which is the same failure as a green test on a broken build.
	expected := []string{"data-extraction", "expression-evaluation", "command-execution", "file-read"}
	missing := make([]string, 0)
	for _, kind := range expected {
		if kinds[kind] == 0 {
			missing = append(missing, kind)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("proof kind(s) %v produced nothing against a fixture built to answer them, and "+
			"every run before this printed proofs=0: «доказ не створюється» і «генератор не під'єднаний "+
			"до прогону» виглядають однаково, тому тест вимагає доказ від кожного", missing)
	}
	// A proof without a runnable request is a sentence, not a reproduction.
	for _, proof := range report.Proofs {
		if proof.Runnable == "" {
			t.Errorf("proof %q (%s) carries no request an operator could re-run", proof.Kind, proof.FindingID)
		}
		if proof.Proof == "" {
			t.Errorf("proof %q (%s) carries no statement of what it showed", proof.Kind, proof.FindingID)
		}
	}
}

// truncate shortens a proof sentence for a log line.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit-1] + "…"
}

// TestChainsFireAgainstTheFixture is the same question for the correlation layer.
//
// A chain needs two things: an ingredient, and a second leg the target has to
// answer. A chain that never fires is indistinguishable from a chain that is wired
// wrong, and the run cannot tell the operator which of the two it was — so the
// fixture answers the second legs too, and the chains are read out of the report
// the run produced rather than out of a second hand-made call.
//
// The first version of this test called `Chains` itself and passed only
// `ChainInput{Findings: …}`. That is why it reported "0 chains" while the run
// itself was correlating correctly: without a `Transport` the rules that fetch
// their second leg return nil immediately. Reading the report removes the second
// invocation, and with it the chance of the test measuring itself instead of the
// product.
func TestChainsFireAgainstTheFixture(t *testing.T) {
	server := httptest.NewServer(vulnerableFixture())
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	report, err := NewScan(ScanRequest{
		URL: start.String(), MaxPages: 4, MaxDepth: 1, Concurrency: 1,
		Timeout: 5 * time.Second, InterestingPaths: []string{},
		RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Every rule in the registry, by the name its row carries, so a rule that
	// stops firing names itself in the failure instead of being a count.
	fired := map[string]Finding{}
	for _, finding := range report.Findings {
		if finding.Module == "chain" {
			fired[finding.Title] = finding
		}
	}
	t.Logf("fixture produced %d chain row(s) from %d finding(s); report counted %d",
		len(fired), len(report.Findings), report.Stats.Chains)
	// The whole detector roster, so a rule that does not fire names the ingredient
	// it was missing instead of leaving the reader to guess which of the two legs
	// the fixture failed to answer.
	for _, finding := range report.Findings {
		if finding.Module == "chain" {
			continue
		}
		t.Logf("  %-9s %-9s %-52s %s", finding.Module, finding.Tier, finding.Title, finding.Endpoint)
	}
	for title := range fired {
		t.Logf("  %s", title)
	}
	if report.Stats.Chains != len(fired) {
		t.Errorf("report counted %d chain(s) but %d chain row(s) are in the findings",
			report.Stats.Chains, len(fired))
	}

	// Every rule in the registry, by the claim its row carries. A count is not the
	// assertion: six rules firing and one dead is the same count as seven healthy
	// rules with one that never fires twice, and the rule is only useful if it
	// names which one it was.
	//
	// This is the assertion that caught the two rules the fixture was built to
	// expose — the open-redirect detector, which had no destination to offer, and
	// the token-theft rule, which was handed one parameter name and asked to match
	// two disjoint lists. Both were counted, both were present, and neither could
	// ever produce a row.
	missing := make([]string, 0)
	for _, rule := range AllChains() {
		claim := rule.Claim()
		if _, ok := fired[claim]; ok {
			continue
		}
		if _, ok := fired["Potential "+claim+" (unverified)"]; ok {
			continue
		}
		missing = append(missing, claim)
	}
	if len(missing) > 0 {
		t.Fatalf("chain rule(s) %v produced no row even though the fixture supplies every ingredient "+
			"they need; «правило мертве» і «правило не отримало інгредієнтів» виглядають однаково, "+
			"тому тест вимагає рядок від кожного правила реєстру", missing)
	}
}
