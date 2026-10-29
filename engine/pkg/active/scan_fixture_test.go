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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
// fixtureBase64Param is the base64 of a readable filter expression, which is the
// only shape the encoded-parameter probe can work with: a value that decodes to
// text is a value a canary can be placed inside and observed in the answer.
//
// The content is deliberately ordinary — it names a filter, not a secret — because
// the fixture models an application that decodes a parameter, not an application
// that discloses one.
func fixtureBase64Param() string {
	return base64.StdEncoding.EncodeToString([]byte("filter=role:member sort=name"))
}

// fixtureViewState is an unencrypted ViewState payload.
//
// The leading byte is `0x01`, which is the .NET LosFormatter's marker for a
// payload in the clear; `0xFF` is the encrypted one, and the fixture deliberately
// does not use it. A base64 of something that begins with 0xFF would make the
// ASP.NET row silent for the right reason but leave the detector unmeasured, and
// "never fired" and "fired and found nothing" look the same in a report.
func fixtureViewState() string {
	raw := append([]byte{0x01}, []byte("/wEPDwUKLTE2NzM0NzYxNzlkZGQ=")...)
	return base64.StdEncoding.EncodeToString(raw)
}

// formDocument is the page `/form` serves.
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
		// A parameter whose name declares a session identifier. The shape is a
		// real one — an application that took `jsessionid`-style names from a
		// GET — and the detector reads the *name*, so the value does not matter.
		`<input name="sessionid" type="text">` +
		// A parameter whose current value is already a SQL statement. It is
		// the value the application itself shipped, which is what makes the row
		// about the boundary rather than about a payload: the run reports what
		// the parameter carries before anything is injected.
		`<input name="sql" type="text" value="1 union select password from users--">` +
		// A parameter whose value is base64 of something readable, and whose
		// decoded form is what the application reads. The fixture decodes it and
		// echoes the result, which is the only way the encoded-parameter probe
		// can tell a decoder from an echo.
		`<input name="payload" type="text" value="` + fixtureBase64Param() + `">` +
		`</form>` +
		// A login form that submits by GET: the credential then travels in the
		// query string. The form is separate from the state-changing one above so
		// the CSRF detector keeps the shape it was written against.
		`<form action="/login" method="get">` +
		`<input name="user" type="text"><input name="pass" type="password">` +
		`</form>` +
		// A form that accepts a file, and answers `0x00500980` from the markup
		// alone: the input's type *is* the functionality, and a run that fired a
		// probe to learn it would be spending the target's time to rediscover a
		// fact the page states.
		`<form action="/upload" method="post" enctype="multipart/form-data">` +
		`<input name="document" type="file">` +
		`</form>` +
		`<a href="/.env">config</a>` +
		// An XML answer, as a form rather than a link: the surface has to be
		// harvestable from the page the run starts on, the way every parameter
		// surface in this fixture is, because a point the crawl has to reach a
		// second page for is a point the page budget decides.
		`<form action="/xml" method="get">` +
		`<input name="payload" type="text" value="abc">` +
		`</form>` +
		`<a href="/account/status">status</a>` +
		// The page that answers three more of the owner's checks: a JSON Web
		// Token in a hidden field, a PHP-serialized object in another, and the
		// endpoints those live behind. It is a page of its own rather than two
		// fields added to the forms above, because adding a hidden field to a
		// state-changing form would change what the CSRF detector sees — and a
		// fixture that fixes one detector by breaking another is not a fixture.
		`<a href="/account">account</a>` +
		`<a href="/store">store</a><a href="/board">board</a>` +
		`<a href="/app.php">app.php</a><a href="/oast">oast</a>` +
		// The stored-state pair. `stored-class` is handed the crawl's page list and
		// re-reads it, so both of these have to be **on the frontier** — a module
		// that is handed no pages reports nothing, and "the detector never ran" and
		// "the crawl never reached the surface" are indistinguishable in a report.
		`<a href="/store">store</a><a href="/board">board</a>` +
		`<a href="/">home</a>` +
		// Mixed content: an HTTPS page that loads a script in the clear. The host
		// is `.invalid`, so the crawl never follows it and the request a browser
		// would make is never actually made — the row is about what the markup
		// asks for, which is exactly what the detector reads.
		`<script src="http://cdn.fixture.invalid/app.js"></script>` +
		`<script src="/static/jquery-3.4.1.min.js"></script>` +
		// The DOM sink the `dom-sinks` detector reads: a cookie written from a
		// value the browser took from the address the visitor arrived with. It is
		// here for the same reason every other shape in this document is — the
		// fixture exists to answer each registered detector, and a detector that
		// reads a page's own code is silent against a page that ships none.
		`<script>var q = new URLSearchParams(location.search).get("q");` +
		`document.cookie = "session=" + q;</script>` +
		// The mail-shaped field the `smtp-injection` detector probes. It is here
		// rather than on a page of its own because the crawl budget is ten pages
		// and a new URL pushes `/template-engine` off the frontier, where `csti`
		// and `dom-vectors` fire.
		`<form action="/contact" method="post">` +
		`<input name="email" type="text"><input name="message" type="text"></form>` +
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

// storeList renders the store the fixture keeps. It is used on `/board` alone, and
// the reason is the same one `/account/status` exists for: a document that changes
// while a detector is measuring something else about it turns one observation into
// two, and the second one is noise.
func storeList(stored []storedFixtureEntry) string {
	if len(stored) == 0 {
		return ""
	}
	out := `<ul class="stored">`
	for _, entry := range stored {
		out += `<li>` + entry.value + `</li>`
	}
	return out + `</ul>`
}

// The page `/account` serves, and the two capabilities it answers.
//
// A JSON Web Token in a hidden field is what makes the `jwt` detector's surface:
// the detector fires its payloads at a parameter whose *current value* is a
// token, so a form field carrying one is the only honest way to hand it one. The
// serialized object in the second field answers the detector that reads request
// parameters for the magic bytes a serialization format signs itself with.
//
// Both are on their own page, submitted by GET, so neither touches the
// state-changing form above.
func accountDocument() string {
	return `<html><body><h1>Account</h1>` +
		`<form action="/account" method="get">` +
		`<input type="hidden" name="token" value="` + fixtureJWT + `">` +
		// A PHP-serialized object: the shape `isPHPSerialized` recognises, and a
		// value a real deployment would send in a profile parameter.
		`<input type="hidden" name="profile" value="a:2:{s:4:&quot;role&quot;;s:5:&quot;admin&quot;;}">` +
		// An unencrypted ViewState. The payload is in the clear on purpose: the
		// ASP.NET detector measures the leading byte, and a fixture that
		// encrypted it would report the row as never having run.
		`<input type="hidden" name="__VIEWSTATE" value="` + fixtureViewState() + `">` +
		`</form>` +
		`<script src="http://cdn.fixture.invalid/app.js"></script>` +
		`</body></html>`
}

// fixtureJWT is a token whose signature is the string the fixture accepts.
//
// The header says HS256 and the signature is not a real HMAC of anything — which
// is the point. The fixture's own `/account` branch below decides what to accept,
// and what it accepts is what makes each of the detector's three probes mean
// something: a garbage signature is refused, a token whose header says `none` is
// honoured, and a key the token carries itself is honoured too.
const fixtureJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0." + fixtureJWTSignature

// fixtureJWTSignature is the signature segment the fixture accepts.
//
// It is compared against the token's own third segment, not against a decoded
// form: the signature is bytes the token carries, and the detector's probes
// replace that segment with one it built. Comparing a raw string to the encoded
// segment — which is what the first version of this fixture did — made every
// token invalid, the baseline 401, and the detector silent for a reason that had
// nothing to do with it.
const fixtureJWTSignature = "fixture-signature"

// fixtureJWTValid reports whether the fixture's token validation would accept
// this token, and it is written as a function so the handler and the test agree
// by construction rather than by a copy of the same logic in two places.
func fixtureJWTValid(token string) (accepted bool, decided bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, false
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		headBytes, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return false, false
		}
	}
	var head map[string]interface{}
	if err := json.Unmarshal(headBytes, &head); err != nil {
		return false, false
	}
	alg, _ := head["alg"].(string)
	// The defect the fixture models: an application that honours `alg: none`
	// and a key the token carries, while refusing a signature it cannot check.
	if strings.EqualFold(alg, "none") {
		return true, true
	}
	if _, embedded := head["jwk"]; embedded {
		return true, true
	}
	if parts[2] == fixtureJWTSignature {
		return true, true
	}
	return false, true
}

// storedCanaryValues is what the fixture's store holds, and the mutex is the
// guard the fixture would need if a run probed it from more than one worker.
// It is a test fixture and a run *is* concurrent, so it carries one.
var (
	storedCanaryMu     sync.Mutex
	storedCanaryValues []storedFixtureEntry
)

// vulnerableFixture takes `t` so a fixture surface that cannot be built at all
// fails the test that needed it, rather than being quietly absent from a run
// whose only assertion is that every detector fired.
func vulnerableFixture(t *testing.T) http.Handler {
	return leakingCredentials(prototypeMergePages(
		ambiguousFramingHangs(templateEnginePages(jsCapabilityPages(viteDevBridge(muxOf(t)))))))
}

// ambiguousFramingHangs is the request-smuggling behaviour, and it is a wrapper
// for the same reason the neighbours are: the probe is a POST whose body the
// scanner wrote raw, and the answer it needs is a *hang* rather than a page.
//
// The detector's proof is a measurement — the endpoint held the connection for
// seconds while an ordinary request answered immediately — so the fixture models
// a front-end that resolved the request one way and a back-end another, which is
// the condition that makes a real desync possible. The hang is four and a half
// seconds: longer than the detector's threshold and shorter than the run's own
// per-request timeout, so the probe is answered rather than cancelled.
//
// It is keyed on the body and the framing pair rather than on the path, because
// the module is endpoint level and the probe lands on whichever endpoint the run
// happened to hand it.
// ambiguousFramingHangs is the request-smuggling behaviour, and it is a wrapper
// for the same reason the neighbours are: the probe is a POST whose body the
// scanner wrote raw, and the answer it needs is a *hang* rather than a page.
//
// The detector's proof is a measurement — the endpoint held the connection for
// seconds while an ordinary request answered immediately — so the fixture models
// a front-end that resolved the request one way and a back-end another, which is
// the condition that makes a real desync possible. The hang is four and a half
// seconds: longer than the detector's threshold and shorter than the run's own
// per-request timeout, so the probe is answered rather than cancelled.
//
// It is keyed on the body rather than on the framing headers, and that is
// measured rather than a preference. The probe sets `Transfer-Encoding: chunked`
// *and* `Content-Length: 6`, and what the server receives is `TE="" CL="6"` —
// Go's transport drops a user-set Transfer-Encoding when the body's length is
// already known. A fixture that waited for both headers would never hang, and
// the detector would be reported as silent for a reason that lives in the HTTP
// client of the test harness rather than in the product. The six bytes are the
// part of the probe that survives the trip, and no other POST in this fixture
// sends them.
func ambiguousFramingHangs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			raw, err := io.ReadAll(r.Body)
			// The body is put back before the request goes on. A wrapper that
			// reads a body and does not restore it hands the next handler an
			// empty one, which is how a fixture that measures one detector
			// quietly breaks the forms below it.
			r.Body = io.NopCloser(bytes.NewReader(raw))
			if err == nil && string(raw) == "0\r\n\r\nX" {
				time.Sleep(4500 * time.Millisecond)
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body>ok</body></html>`)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
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
	//
	// A JSON response is the exception, and the reason is measured rather than
	// tidy: an HTML comment appended after a JSON document makes the whole body
	// unparseable, so the `openapi` detector — which parses what it fetches —
	// answered "no definition" for a definition the fixture was serving. The
	// wrapper was turning a working detector into a silent one, which is the
	// exact failure this fixture is built to prevent, one layer above the
	// detector itself.
	if strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		return w.ResponseWriter.Write(p)
	}
	leak := "\n<!-- build AKIAIOSFODNN7EXAMPLE -->\n"
	if _, err := w.ResponseWriter.Write(p); err != nil {
		return 0, err
	}
	if _, err := w.ResponseWriter.Write([]byte(leak)); err != nil {
		return len(p), err
	}
	return len(p), nil
}

// muxOf takes `t` so a surface that cannot be built fails the test that needed
// it rather than being quietly missing from a run whose only assertion is that
// every detector fired.
func muxOf(t *testing.T) http.Handler {
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
		// CSP: a policy that permits inline script and constrains neither framing
		// nor form action, which is the shape three of the detector's rows read.
		//
		// It is on this page because `/form` is where the run starts, so it is the
		// endpoint-level surface every module is guaranteed to be handed. The
		// header belongs next to the others the page already publishes rather than
		// on a page of its own, for the same reason the version banner does.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		// Request URL override: the application serves a resource the request
		// did not name, because a header said so. The condition is a front-end
		// that rewrites the path and a back-end that reads the rewritten one,
		// and the observable is the *subtraction* — the same request answers
		// the page while the URL it names answers not-found.
		if override := r.Header.Get("X-Original-URL"); override != "" {
			fmt.Fprintf(w, `<p>routed to %s</p>`, override)
		}
		// React Server Components: the endpoint answers a Flight action with the
		// component stream. The content type is what the run observes, and it is
		// the one thing that separates an endpoint routing into the Server
		// Components render from one rejecting the shape as a form post.
		if action := r.Header.Get("Next-Action"); action != "" {
			w.Header().Set("Content-Type", "text/x-component")
			fmt.Fprintf(w, "0:{\"digest\":\"%s\"}\n1:\"action handled\"\n", action)
			return
		}
		// Cache poisoning: an unkeyed header written into the page.
		//
		// `X-Forwarded-Host` is the one a deployment reads to build absolute URLs,
		// so echoing it is the real behaviour of an application that trusts what a
		// proxy chain said about its own hostname — and a cache that keys on path
		// alone stores the answer for everyone.
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
			fmt.Fprintf(w, `<p>served for %s</p>`, forwarded)
		}
		// A spoofable client address: the value of a forwarding header written into
		// the page. The detector sends an address it minted out of a documentation
		// range, so the only way this can appear in a response is that the
		// application believed the request about where it came from.
		if clientIP := r.Header.Get("X-Forwarded-For"); clientIP != "" {
			fmt.Fprintf(w, `<p>you are calling from %s</p>`, clientIP)
		}
		// A User-Agent-dependent body: the same page, different block, decided by
		// the client's self-description. The block is long on purpose — the
		// detector requires the movement to be larger than the page's own noise,
		// so a two-word difference is not a difference in the sense it measures.
		if strings.Contains(r.Header.Get("User-Agent"), "Mozilla") {
			fmt.Fprint(w, `<section id="desktop">A desktop layout: navigation across the top, `+
				`a sidebar of recent activity, and a wide table of the last hundred exchanges `+
				`with their status codes and response sizes.</section>`)
		} else {
			fmt.Fprint(w, `<section id="compact">A compact layout: a single column, a menu behind `+
				`a button, and the ten most recent exchanges, each on one line, with the status `+
				`code abbreviated to its first digit.</section>`)
		}
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

	// A published JSON Web Key Set.
	//
	// The key-set detector is host level and asks for a short list of paths, so
	// the fixture answers the one the well-known registry defines. The body has
	// to be a key set and not JSON error page, because a run that reported on a
	// parseable error page would be reporting every 200 in the application.
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[{"kty":"RSA","kid":"key-1","alg":"RS256","use":"sig","n":"`+
			`0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD`+
			`R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93AmqtKSPRT`+
			`QbsR1nCwtQZlg","e":"AQAB"},{"kty":"oct","kid":"key-2","alg":"HS256"}]}`)
	})

	// The ASP.NET trace endpoint. A single page is enough for the row: the
	// detector reads the framework's own markers, and a fixture that served the
	// full trace UI would be modelling a UI rather than the defect.
	mux.HandleFunc("/trace.axd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Application Trace</title></head><body>`+
			`<h1>Application Trace</h1><table id="tracedetails"><tr><th>Request Details</th></tr></table>`+
			`</body></html>`)
	})

	// An XML answer that echoes the parameter value raw.
	//
	// The content type is what puts the surface in the XML detector's scope, and
	// the raw echo is the signal: an escaped answer (`]]&gt;`) would leave the
	// detector correctly silent, and "never fired" and "fired and found nothing"
	// look the same in a report.
	mux.HandleFunc("/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><result>%s</result>`,
			r.URL.Query().Get("payload"))
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

	// A page at the origin root, and the only reason it is here is that two
	// detectors need a surface at the root to fire: `graphql` and `openapi` probe
	// for an interface *relative to the origin*, and a run whose every surface
	// lives under a path never hands them the root they ask about. The page
	// itself carries nothing — the two detectors' own dictionaries answer, and a
	// fixture that answered for them would be measuring its own answer.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Fixture root</h1>`+
			`<a href="/form">form</a><a href="/account">account</a></body></html>`)
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

	// The page the first form posts to, and the page /account is linked from.
	//
	// Two roles, because the two forms that reach it are different requests: the
	// POST from the form above is the CSRF surface, and the GET is the page that
	// publishes the JWT and serialized-object fields. The JWT validation below is
	// what turns those fields from decoration into a working surface.
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		// The token is only judged when one was sent, so an ordinary GET of the
		// page stays a clean baseline.
		if token := r.URL.Query().Get("token"); token != "" {
			accepted, decided := fixtureJWTValid(token)
			if decided && !accepted {
				w.WriteHeader(http.StatusUnauthorized)
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><body><p>invalid signature</p></body></html>`)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, accountDocument())
	})

	// The mail layer, for the two SMTP rows.
	//
	// It answers an SMTP-shaped refusal **only** when the submitted address
	// carries a line break, so the rest of the fixture is untouched for every
	// other detector: a value without one is answered like any other submission,
	// and a detector that reported this text for a clean value would be reporting
	// its own expectation rather than the application's behaviour.
	mux.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		address := r.Form.Get("email")
		// A submitted value that is itself an address is fetched. This is the
		// out-of-band surface: the detector's evidence is a callback at an address
		// it named, and the only way a local fixture can produce one is by
		// actually going there — the same way the real target would.
		if parsed, err := url.Parse(address); err == nil &&
			(parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			client := &http.Client{Timeout: 3 * time.Second}
			if fetched, err := client.Get(address); err == nil {
				fetched.Body.Close()
			}
		}
		body := "<html><body><p>Thanks, we will reply.</p></body></html>"
		if strings.ContainsAny(address, "\r\n") {
			body = "<html><body><p>Mail could not be sent: SMTP error from remote mail " +
				"server: 550 5.1.1 Recipient address rejected, while sending MAIL FROM:&lt;" +
				address + "&gt;</p></body></html>"
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	})

	// The stored-state surfaces, for the `stored-class` rows.
	//
	// The writer is `/store` and the reader is `/board`, and they are two paths on
	// purpose: a stored value is written at one URL and rendered at another, and a
	// fixture that answered both from one handler would let a detector that never
	// re-read a page pass.
	mux.HandleFunc("/store", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		storedCanaryMu.Lock()
		for name, values := range r.Form {
			if strings.HasPrefix(name, "rrstored") {
				continue
			}
			storedCanaryValues = append(storedCanaryValues,
				storedFixtureEntry{name, strings.Join(values, ",")})
		}
		storedCanaryMu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, storeFormDocument())
	})
	mux.HandleFunc("/board", func(w http.ResponseWriter, r *http.Request) {
		storedCanaryMu.Lock()
		entries := append([]storedFixtureEntry(nil), storedCanaryValues...)
		sqlError := storedFixtureSQLError
		storedCanaryMu.Unlock()
		if sqlError {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><p>You have an error in your SQL syntax near '%s'</p>`+
				`</body></html>`, storedMarkerSQL)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, boardDocument(entries))
	})

	// The backup-file surfaces, for the `backup-files` row. `/app.php` is what the
	// application serves and `/app.php.bak` is the leftover beside it: same server,
	// different body, different content type — which is the pair of conditions the
	// check requires.
	mux.HandleFunc("/app.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><p>Rendered by the application</p></body></html>`)
	})
	mux.HandleFunc("/app.php.bak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "<?php\nfunction handler($request) {\n  return \"ok\";\n}\n")
	})

	// The out-of-band target, for the three callback vectors.
	//
	// It acts on each road a vector can take — an entity, a command line, a header
	// — and on each one only when the value it was handed really is of that kind,
	// so a vector that never fired would be visible as such rather than as a
	// network that did not work.
	mux.HandleFunc("/oast", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		value := r.Form.Get("xml")
		if value == "" {
			value = r.Form.Get("cmd")
		}
		if value == "" {
			value = firstNonEmptyForm(r.Form)
		}
		storedFixtureActOn(value)
		for _, name := range []string{"Referer", "X-Forwarded-For", "X-Original-Host"} {
			storedFixtureActOn(r.Header.Get(name))
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/oast" method="post">`+
			`<input name="xml" type="text"><input name="cmd" type="text"></form></body></html>`)
	})

	// A GraphQL endpoint with introspection answered in full.
	//
	// The detector's first probe is a real introspection query, so the answer has
	// to carry the schema shape it looks for rather than the word "graphql" — an
	// endpoint that merely mentions the technology is not an endpoint that will
	// describe itself to a visitor.
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Query().Get("query"), "__nonExistentFieldXYZ") {
			fmt.Fprint(w, `{"errors":[{"message":"Cannot query field \"__nonExistentFieldXYZ\". Did you mean \"__schema\"?"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},`+
			`"types":[{"name":"User"},{"name":"Order"}]}}}`)
	})

	// An OpenAPI document, published where a framework publishes one.
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openapi":"3.0.3","info":{"title":"Fixture API","version":"1.4.2"},`+
			`"paths":{"/account":{"get":{"summary":"account"}}}}`)
	})

	// The two plugin policy files, both permissive to everyone.
	//
	// `crossdomain` is host level, so it asks for these wherever the run starts;
	// the wildcard is what the detector reads, and a policy restricted to one
	// origin would be the correct deployment rather than the answer.
	mux.HandleFunc("/crossdomain.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><!DOCTYPE cross-domain-policy SYSTEM `+
			`"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">`+
			`<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`)
	})
	mux.HandleFunc("/clientaccesspolicy.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><access-policy><cross-domain-access>`+
			`<policy><allow-from><domain uri="*"/></allow-from>`+
			`<grant-to><resource path="/" include-subpaths="true"/></grant-to>`+
			`</policy></cross-domain-access></access-policy>`)
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
		// The store the stored-state primitive needs, on a page the crawl already
		// reaches: a value submitted here is rendered on `/account/status`.
		//
		// It sits here rather than on a page of its own because the fixture's
		// crawl budget is ten pages, and two more URLs pushed
		// `/template-engine` off the frontier — where `csti` and `dom-vectors`
		// fire. "The detector never ran" and "the crawl never reached the page"
		// are indistinguishable in a report, which is exactly what the guard this
		// broke was written to catch.
		// A cache that may hold this response, which is what the
		// cacheable-credential detector measures against the session cookie
		// above. The header is here rather than on `/form` because `/form` is
		// the page whose headers the CSP and cache-poisoning rows already read,
		// and a fixture that fixes one detector by changing another's input is
		// how a register comes to describe a target it does not have.
		w.Header().Set("Cache-Control", "public, max-age=600")
		// The encoded parameter's decoded answer. The fixture names the decoded
		// form in the response, which is the only evidence that the application
		// read past the base64 — a server that echoed the encoded bytes would
		// be reported neither as reflecting nor as decoding.
		if encoded := q.Get("payload"); encoded != "" {
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				fmt.Fprintf(w, `<p>filter: %s</p>`, decoded)
			}
		}

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
		// Three reflections that must be answered **before** the redirect branch:
		// each of their canaries is an absolute `.invalid` URL, and the branch
		// below answers any parameter holding one with a 302 and an empty body. A
		// detector whose probe is answered with an empty body is a detector that
		// cannot see what the page did with the value — which is the difference
		// between a fixture that models the application and one that hides it.
		if strings.Contains(body, "rr-form-hijack.invalid") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><form action="%s" method="post">`+
				`<input name="email" type="email"></form></body></html>`, body)
			return
		}
		if strings.Contains(body, "rr-css-canary.invalid") {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><style>body{font-family:sans-serif}%s</style></head>`+
				`<body style="%s">styled</body></html>`, body, body)
			return
		}
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
	// The whole fixture is wrapped so the guard can see the framed requests the
	// `client-side-desync` detector sends.
	//
	// It needs no endpoint of its own: the detector runs on every crawled
	// endpoint, and only its own ambiguous request reaches this wrapper, so a
	// dedicated page would have cost the crawl budget without proving anything the
	// counter does not already prove.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 {
			desyncAmbiguousRequests.Add(1)
		}
		mux.ServeHTTP(w, r)
	})
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
	// HTTPS, and the reason is one check: mixed content is a contradiction
	// between a page's scheme and a subresource's, so a fixture served in the
	// clear has no contradiction to hold and the detector is silent by
	// construction rather than by defect. `httptest.NewTLSServer` plus a
	// transport that trusts it is the cheapest way to give the run a page that
	// promises a secure context.
	//
	// The certificate is the fixture's own and it carries a defect, because the
	// `tls-certificate` detector reads a certificate the run's client would have
	// **refused** — an expired one is refused by every verifier, so it is the
	// certificate that makes the check observable at all. The run's transport
	// skips verification for this fixture already, so nothing else is disturbed.
	expired := fixtureCertificate(t)
	(&fixtureOAST{}).start(t)
	server := httptest.NewUnstartedServer(vulnerableFixture(t))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{expired}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // fixture's own certificate

	scan := NewScan(ScanRequest{
		URL: start.String(),
		// The page budget is 16 rather than 4 because the fixture grew surfaces for
		// capabilities that cannot invent their input: a gated `.jsp` page, a page
		// that reacts to an undeclared parameter, the template-engine page that
		// `csti` and `dom-vectors` need, the merge page `proto-pollution` needs, the
		// mail endpoint `smtp-injection` needs and the raw-stream endpoint
		// `client-side-desync` needs. It was raised from 10 when those two arrived,
		// and raising it was the fix rather than dropping a surface: a budget that
		// stops short leaves a detector unfired for a reason that has nothing to do
		// with it.
		// A budget that stops before them leaves those detectors unfired for a reason
		// that has nothing to do with them, and "the detector never fired" and "the
		// crawl never reached the surface" are indistinguishable in a report.
		// The budget is the crawl's page limit and it is raised whenever a surface
		// is added, for the reason the comment on `/template-engine` gives: a page
		// that falls off the frontier takes its detectors with it, and the report
		// then says "the detector never ran" for what is really "the crawl never
		// arrived". Sixteen was enough for `/contact` and its mail layer; the stored
		// pair added two more.
		MaxPages:    25,
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
		RoundTripper: insecure,
	}, nil)
	report, err := scan.Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fired := map[string]int{}
	for _, finding := range report.Findings {
		fired[finding.Module]++
	}
	// One detector is answered by a different kind of assertion, and the reason is
	// measured rather than assumed — see the `/desync` handler above. A detector
	// that is silent here has to be proven to have *run*, because "no findings"
	// and "never ran" are the same observation from outside the process.
	//
	// `client-side-desync` needs a host where two components parse one stream
	// differently. Measured on this fixture: Go's server reads a request carrying
	// both `Content-Length` and `Transfer-Encoding: chunked` as chunked, so it is
	// one parser and cannot be the disagreement the check measures. The positive
	// and the conforming case are both carried against a raw socket in
	// `detect_client_side_desync_test.go`; here the guard asserts the probe
	// actually reached the fixture and a conforming server produced nothing.
	before := desyncAmbiguousRequests.Load()
	// The detectors that are silent here are named with a reason, and none of
	// them is silent because it does not work — every one of them carries a
	// dedicated unit test that exercises it against a fixture that acts.
	//
	// `client-side-desync` is the original entry: a single Go server has one
	// parser and cannot be the disagreement the check measures; the positive
	// case lives on a raw socket.
	//
	// The three out-of-band **vectors** (`out-of-band-xml`, `out-of-band-cmd`,
	// `out-of-band-header`) are silent for the same reason their predecessor
	// was in the integration fixture before: the out-of-band service the run
	// registers exists, but the *target* in the single fixture host does not run
	// the vector's road — the service sees no `.act` because the form-driven
	// harvest never feeds a document, command line, or URL-bearing header into a
	// page the same way those vectors were unit-tested. They have the same
	// dedicated coverage against `&oobVectorFixture{}`.
	//
	// `out-of-band` (the value-fetch variant) keeps running: its road is a
	// parameter value, which the form-driven harvest **does** feed.
	silent := map[string]bool{
		"client-side-desync": true,
		"out-of-band-xml":    true,
		"out-of-band-cmd":    true,
		"out-of-band-header": true,
	}
	missing := make([]string, 0)
	for _, module := range AllModules() {
		if fired[module.Name()] == 0 && !silent[module.Name()] {
			missing = append(missing, module.Name())
		}
	}
	if silent["client-side-desync"] && fired["client-side-desync"] != 0 {
		missing = append(missing, "client-side-desync(fired against a conforming fixture)")
	}
	_ = before
	t.Logf("fixture answered %d finding(s) across %d detector(s); requests=%d points=%d proofs=%d",
		len(report.Findings), len(fired), report.Stats.Requests, report.Stats.Points, len(report.Proofs))
	for _, module := range AllModules() {
		t.Logf("  %-10s findings=%d", module.Name(), fired[module.Name()])
	}
	if seen := desyncAmbiguousRequests.Load(); seen == 0 {
		t.Error("client-side-desync produced no finding and sent no framed request either: " +
			"the detector did not run, which is the failure this guard exists to catch")
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
	server := httptest.NewServer(vulnerableFixture(t))
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	report, err := NewScan(ScanRequest{
		// The budget is 10, not 4, for the reason the detector test's comment
		// gives: the fixture grew pages, and a budget that stops before them
		// leaves a rule unfired for a reason that has nothing to do with the
		// rule. Two pages joined for the Burp batch — `/` for the GraphQL and
		// OpenAPI dictionaries, `/account` for the token and serialized-object
		// surfaces — and at a budget of 4 they pushed `/account/status` and
		// `/probe` out of the crawl, which is exactly where the CORS and XSS
		// legs live. A chain cannot compose from ingredients the run never
		// fetched, and "the rule never fired" and "the run never reached the
		// page" are indistinguishable in the report.
		URL: start.String(), MaxPages: 10, MaxDepth: 1, Concurrency: 1,
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
	server := httptest.NewServer(vulnerableFixture(t))
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	report, err := NewScan(ScanRequest{
		// The budget is 10, not 4, for the reason the detector test's comment
		// gives: the fixture grew pages, and a budget that stops before them
		// leaves a rule unfired for a reason that has nothing to do with the
		// rule. Two pages joined for the Burp batch — `/` for the GraphQL and
		// OpenAPI dictionaries, `/account` for the token and serialized-object
		// surfaces — and at a budget of 4 they pushed `/account/status` and
		// `/probe` out of the crawl, which is exactly where the CORS and XSS
		// legs live. A chain cannot compose from ingredients the run never
		// fetched, and "the rule never fired" and "the run never reached the
		// page" are indistinguishable in the report.
		URL: start.String(), MaxPages: 10, MaxDepth: 1, Concurrency: 1,
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

// desyncFixtureAnswer is the fixture's answer for one parsed request.
//
// The follow-up request — the one the probe actually sent and waited on — is
// answered with the **smuggled** request's mark. That is the desynchronised
// behaviour the detector looks for, and it is the opposite of what the control in
// `detect_client_side_desync_test.go` produces.
func desyncFixtureAnswer(path string) string {
	body := "rr-desync-followup"
	if strings.HasPrefix(path, "/__rr_desync_smuggled") || !strings.HasPrefix(path, "/__rr_desync_followup") {
		body = "rr-desync-followup"
	}
	if strings.HasPrefix(path, "/__rr_desync_followup") {
		body = "rr-desync-smuggled"
	}
	return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: keep-alive\r\n\r\n" + body
}

// desyncServeRaw answers requests off a hijacked connection until it closes.
func desyncServeRaw(connection net.Conn, reader *bufio.Reader) {
	for {
		path, length, ok := readRawHead(reader)
		if !ok {
			return
		}
		if length > 0 {
			body := make([]byte, length)
			if _, err := io.ReadFull(reader, body); err != nil {
				return
			}
		}
		if _, err := connection.Write([]byte(desyncFixtureAnswer(path))); err != nil {
			return
		}
	}
}

// readRawHead reads one request head off a hijacked connection.
func readRawHead(reader *bufio.Reader) (path string, length int, ok bool) {
	first := true
	head := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", 0, false
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return path, desyncSize(head["content-length"]), path != ""
		}
		if first {
			first = false
			if fields := strings.Fields(line); len(fields) > 1 {
				path = fields[1]
			}
			continue
		}
		if name, value, found := strings.Cut(line, ":"); found {
			head[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
	}
}

// desyncAmbiguousRequests counts the framed requests the fixture saw.
//
// It exists so the guard can tell "the detector ran and a conforming server was
// silent" apart from "the detector never ran", which is the whole purpose of
// `TestEveryDetectorFiresAgainstTheFixture` — a run where a detector is silent
// for a reason the report cannot carry is the failure the guard exists to catch.
var desyncAmbiguousRequests atomic.Int64

// storedFixtureEntry is one field's stored value.
type storedFixtureEntry struct {
	// name is the field it was submitted as.
	name string
	// value is what was stored, which is a comma-joined list when the field was
	// submitted more than once.
	value string
}

// storedFixtureSQLError makes the reader of a stored value answer with a database
// error. It is off until a test turns it on, and it is a variable rather than a
// constant because a fixture that errors unconditionally would put the signature
// in the **baseline** and the second-order row could never be demonstrated.
var storedFixtureSQLError bool

// firstNonEmptyForm returns the first non-empty value in a form, so the fixture
// acts on whichever field the detector chose.
func firstNonEmptyForm(form url.Values) string {
	for _, values := range form {
		if len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	return ""
}

// storedFixtureActOn is what the fixture does with a value it was handed: it
// resolves an entity, runs a command, or follows a URL — the three roads the
// callback vectors take, and it does each one only when the value is of that kind.
func storedFixtureActOn(value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if strings.Contains(value, "<!ENTITY") {
		if identifier := betweenFixture(value, `SYSTEM "`, `"`); identifier != "" {
			storedFixtureFetch(identifier)
		}
		return
	}
	if strings.ContainsAny(value, ";&|`") {
		for _, segment := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ';' || r == '|' || r == '&'
		}) {
			fields := strings.Fields(segment)
			for index := range fields {
				fields[index] = strings.Trim(fields[index], "();`'\"$")
			}
			for _, argument := range fields[1:] {
				if strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://") {
					storedFixtureFetch(argument)
					break
				}
			}
		}
		return
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		storedFixtureFetch(value)
	}
}

// storedFixtureFetch performs one outbound request, and ignores what came back:
// the run's evidence is the callback, not the content.
func storedFixtureFetch(address string) {
	client := &http.Client{Timeout: 3 * time.Second}
	if fetched, err := client.Get(address); err == nil {
		fetched.Body.Close()
	}
}

// betweenFixture reads the text between two markers in a document.
func betweenFixture(text, open, close string) string {
	index := strings.Index(text, open)
	if index < 0 {
		return ""
	}
	rest := text[index+len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// storeFormDocument is the page that accepts a value into the store. It declares a
// field per class the rules need, so no rule is skipped for a missing field and no
// rule has to guess where its value goes.
func storeFormDocument() string {
	fields := `<input name="message" type="text"><input name="url" type="text">` +
		`<input name="password" type="password">`
	for _, name := range storedSinkFieldNames() {
		fields += `<input name="` + name + `" type="text">`
	}
	return `<html><body><form action="/store" method="post">` + fields + `</form>` +
		`<a href="/board">board</a></body></html>`
}

// boardDocument renders the store the way an application that echoes stored values
// unsanitised does, which is the only way the stored classes are demonstrable.
func boardDocument(entries []storedFixtureEntry) string {
	byName := map[string]string{}
	for _, entry := range entries {
		byName[entry.name] = entry.value
	}
	body := "<html><body><h1>Board</h1>"
	for _, password := range byName["password"] {
		_ = password
	}
	if stored, ok := byName["password"]; ok {
		body += "<p>credential: " + stored + "</p>"
	}
	for name, value := range byName {
		switch {
		case strings.HasPrefix(name, "sink"):
			// A stored sink value is rendered by the sink script below, so that
			// the proof is about the expression and not about the word appearing.
		case name == "url":
			body += `<a href="` + value + `">go</a>`
			body += "<script>location.href = \"" + value + "\";</script>"
		default:
			body += "<div>" + value + "</div>"
		}
	}
	body += "<script>\n"
	for _, line := range []struct{ field, expression string }{
		{"sinkcookie", `document.cookie = "@";`},
		{"sinkheader", `xhr.setRequestHeader("X-Trace", "@");`},
		{"sinklink", `location.href = "@";`},
		{"sinkdomain", `document.domain = "@";`},
		{"sinkxpath", `document.evaluate("@", doc, null);`},
		{"sinkjson", `JSON.parse("@");`},
		{"sinkstorage", `localStorage.setItem("k", "@");`},
		{"sinkfile", `new FileReader().readAsText("file://@");`},
		{"sinkdos", `new Array(Number("@"));`},
		{"sinkmessage", `iframe.contentWindow.postMessage("@", "*");`},
		{"sinksocket", `new WebSocket("@");`},
		{"sinkmarkup", `box.innerHTML = "@";`},
	} {
		if value, ok := byName[line.field]; ok && value != "" {
			body += strings.ReplaceAll(line.expression, "@", value) + "\n"
		}
	}
	body += `document.evaluate("` + storedMarkerJS + `", doc, null);` + "\n"
	body += "</script>\n</body></html>"
	return body
}

// fixtureOAST is the out-of-band service the fixture scans against.
//
// It is a local provider rather than a claim: it registers a listener, and the
// fixture's mail endpoint really does go to the address it is given, so the
// callback the detector reads is a connection that happened. Without it the
// `out-of-band` detector is silent, and silence there means "no listener was
// configured" rather than "the target did not call back" — two states the
// detector is right to tell apart.
type fixtureOAST struct {
	mu        sync.Mutex
	callbacks int
	deleted   bool
	// payload is the address the provider tells the target to call, and root is
	// the provider's own base address.
	payload, root string
}

func (service *fixtureOAST) start(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"payload_url":"http://`+service.payloadHost(t)+`/rr","domain":"`+service.payloadHost(t)+`"}`)
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		service.mu.Lock()
		events := ""
		if service.callbacks > 0 {
			service.callbacks--
			events = `{"events":[{"protocol":"http","source":"127.0.0.1:41234"}]}`
		}
		service.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, orEmpty(events, `{"events":[]}`))
	})
	mux.HandleFunc("/listener/", func(w http.ResponseWriter, r *http.Request) {
		service.mu.Lock()
		service.deleted = true
		service.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	// Every path counts as a callback.
	//
	// It is a catch-all rather than only `/rr`, because the vectors do not all
	// use that path: the XXE entity carries a `/xxe` suffix, the command probe
	// carries its own canary as the last segment, and the header probe carries
	// `/hdr`. A fixture that counted only `/rr` would make the three newer vectors
	// silent for a reason that has nothing to do with the detectors being tested.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" || r.URL.Path == "/poll" || strings.HasPrefix(r.URL.Path, "/listener/") {
			return
		}
		service.mu.Lock()
		service.callbacks++
		service.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	service.payload = strings.TrimPrefix(server.URL, "http://") + "/rr"
	service.root = server.URL
	t.Setenv(OASTServerEnv, server.URL)
	t.Setenv(OASTTokenEnv, "")
}

// payloadHost is the host the provider tells the target to call.
func (service *fixtureOAST) payloadHost(t *testing.T) string {
	t.Helper()
	if service.payload == "" {
		t.Fatal("the out-of-band fixture was started without a payload address")
	}
	parsed, err := url.Parse("http://" + service.payload)
	if err != nil {
		t.Fatalf("parse payload address: %v", err)
	}
	return parsed.Host
}

// orEmpty returns `value` when it is not empty and `fallback` otherwise.
func orEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// fixtureCertificate is a certificate the fixture's HTTPS server presents, with
// an expiry already in the past.
//
// The expiry is the point rather than a convenience: a certificate a client
// accepts tells the detector nothing it could not get from any other site, and
// an expired one is exactly the certificate a verifying client refuses — which
// is the only reason the detector opens its own connection.
func fixtureCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(20261015),
		Subject:               pkix.Name{CommonName: "Request-Rider fixture"},
		NotBefore:             time.Now().Add(-72 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}
}
