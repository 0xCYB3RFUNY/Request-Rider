package main

// Capabilities glued onto the JavaScript analyser from the operator's list.
//
// # What this is, and why it is here rather than in a tool of its own
//
// The operator's list is not one tool: it is a scanner's memory of what a
// JavaScript file gives away that a human misses on the tenth bundle. A route
// manifest lists every page of a Next.js application including the ones nothing
// links to. A config object names a service that only answers on the loopback
// interface. An admin-creating endpoint ships with the token that authorises it.
// A bundler dev server leaves `/@fs/` in the code that talks to it. A variable
// name is a parameter name nobody wrote down.
//
// All five are properties of the bytes the crawler already read, and the crawler
// already parses those bytes with tree-sitter (`target_javascript.go` explains
// why the analyser is a library and not a process). So these five read the same
// parse tree the endpoints, secrets and sinks read, and their results travel in
// the same `page["js"]` record, the same project bundle and the same export as
// everything else the analyser found. A separate tool would have meant a second
// fetch of the same asset and a second place where a finding could be lost.
//
// # What each capability is, and what it is worth
//
//	route               `__BUILD_MANIFEST.sortedPages` and the webpack route keys of a
//	                    Next.js pages-router build: the routes the application has and
//	                    nothing links to. These join the crawl frontier, so the map
//	                    grows by the pages the site hides rather than only by the ones
//	                    it advertises.
//	internal_service    a loopback host or a `host:`/`port:` pair named in the code.
//	                    The analyst who has an SSRF and needs an internal target reads
//	                    this list; nothing else in the tool points at one.
//	privileged_endpoint an endpoint whose path names a privileged action. This is the
//	                    "find the sensitive path in the JS" step, kept as data so the
//	                    active scanner can probe the same paths instead of rediscovering
//	                    them.
//	hardcoded_auth_token a credential bound to an authentication-shaped name, in a file
//	                    that also names a privileged endpoint. The value is not reported
//	                    twice: `collectJSSecrets` already reports every credential it
//	                    recognises, and a value that is in `secrets` is skipped here.
//	vite_dev_server     a marker of a Vite dev server, which is the precondition of the
//	                    arbitrary file read in GHSA-x574-m823-4x7w: `/@fs/` serves files
//	                    outside the project root.
//	parameter candidates every parameter name the program uses, plus every variable
//	                    name it binds — GAP's "get all parameters", which is a fuzzing
//	                    wordlist and not a finding, and is therefore a list of its own
//	                    for the same reason `variables` is.
//
// # Two decisions that are measured rather than stylistic
//
// **One tree walk.** Five categories would be five `QueryMulti` calls, and a
// call is a walk of the whole parse tree: the measurements in
// `target_js_findings.go` put seven queries at 280-344 ms on a 150 KB minified
// bundle from ria.ru. The queries here are joined into one, which is the same
// decision that file already made for its own seven, and the Vite pass is a byte
// scan of the body the analyser already holds rather than a walk.
//
// **Findings before secrets are not duplicated, and are not guessed.** The
// authentication-token category asks the name and the value to look like a
// credential rather than asking the name to be one of a maintained list, because
// a maintained list is a second place to forget to update — which is exactly how
// the generic secret rule ended up not knowing a bare `token`. And a value the
// secret pass already reported produces no row here, so one leaked key is one
// row rather than two rows in two vocabularies.

import (
	"bytes"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/jsluice"
)

// The finding kinds this pass adds. They are a separate vocabulary from the
// sink/comment/email categories because they answer a different question: not
// "what does this file do to the page" but "what does this file give away".
const (
	// jsFindingRoute is one route the application serves.
	jsFindingRoute = "route"
	// jsFindingInternalService is a service addressable only from inside.
	jsFindingInternalService = "internal_service"
	// jsFindingPrivilegedEndpoint is an endpoint whose path names a privileged action.
	jsFindingPrivilegedEndpoint = "privileged_endpoint"
	// jsFindingHardcodedAuthToken is a credential bound to an authentication-shaped name.
	jsFindingHardcodedAuthToken = "hardcoded_auth_token"
	// jsFindingViteDevServer is a marker of a Vite development server.
	jsFindingViteDevServer = "vite_dev_server"
	// jsFindingElectronExposure is an Electron surface that turns a script
	// injection into code execution or a file read on the desktop.
	jsFindingElectronExposure = "electron_exposure"
)

// jsRoute is one path the application serves, as its build manifest names it.
//
// Resolved is the same route as a browser would request it, and it is absent
// when that would say nothing new — the same rule `jsEndpoint.Resolved` follows,
// and for the same reason: the unresolved form is the evidence, the resolved one
// is what to open.
type jsRoute struct {
	// Route is the path as the manifest writes it. A dynamic segment survives as
	// written (`/blog/[slug]`), because the shape is what the manifest says and
	// the crawler will refuse to request it rather than guess a value for it.
	Route string `json:"route"`
	// Source names where the route was read from: `sorted_pages` for the array of
	// route strings, `next_page_key` for a webpack route key.
	Source string `json:"source"`
	// Line is the 1-based line the route string starts on, or 0 when it was not
	// found in the file verbatim.
	Line int `json:"line"`
	// Resolved is the absolute URL the route resolves to.
	Resolved string `json:"resolved,omitempty"`
}

// jsParamCandidate is one name worth firing a payload at.
//
// Sources is a list rather than a single value because the three origins answer
// different questions: a query parameter is a parameter the program sends, a
// body parameter is one it posts, and a variable name is a name it binds — the
// last is a guess, which is what the whole point of the technique is, and it is
// reported as a separate source so a reader can see which rows are evidence and
// which are a hypothesis.
type jsParamCandidate struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
}

// The sources a candidate can come from.
const (
	jsParamSourceQuery    = "query"
	jsParamSourceBody     = "body"
	jsParamSourceVariable = "variable"
)

// jsCapabilities is everything this pass contributes to one file.
type jsCapabilities struct {
	// Findings are the four categories that are evidence of something, folded in
	// the same way the analyser's own findings are.
	Findings []jsFinding
	// Routes are the paths the build manifest names.
	Routes []jsRoute
	// Params is the fuzzing wordlist: every parameter name the program uses,
	// plus every variable name it binds.
	Params []jsParamCandidate
	// Links are the crawlable routes, resolved and absolute. They join the crawl
	// frontier, which is the whole value of finding them: a route nothing links to
	// is only useful if the crawler then goes there.
	Links []string
}

// The tree queries, joined into one walk.
//
// The route array is a pair whose value is an array of strings, because that is
// the shape both Next.js writes: `self.__BUILD_MANIFEST_CB.push([{sortedPages:[
// …], …}])` in a production build and `self.__BUILD_MANIFEST={sortedPages:[…]}`
// in development. The key is captured rather than assumed, so a bundle that has
// twenty other arrays of strings does not contribute twenty route lists.
//
// The webpack route keys are captured on their own because a production
// `__BUILD_MANIFEST` stores the same information as object keys
// (`"/_next/static/<build>/pages/about": …`) and a pages router that only ever
// shipped that shape would report no routes at all.
const (
	jsRouteArrayPattern = `(pair
  key: (_) @rrjsroutekey
  value: (array (string) @rrjsroute)) @rrjsroutestmt`

	jsRouteKeyPattern = `(pair key: (string) @rrjsrouteonly) @rrjsroutekeystmt`

	// The three assignment shapes a credential can be bound in are the same three
	// `jsAssignmentShapes` names, and they are asked here with `_` where that file
	// asks for `identifier`/`string` specifically: this pass decides what a name
	// means, not whether it is a node of a particular kind, and `window.token = "…"`
	// and `{"token": "…"}` are both worth reading.
	jsAuthTokenPairPattern = `(pair
  key: (_) @rrjsauthkey
  value: (string) @rrjsauthval) @rrjsauthstmt`

	jsAuthTokenDeclaratorPattern = `(variable_declarator
  name: (_) @rrjsauthkey
  value: (string) @rrjsauthval) @rrjsauthstmt`

	jsAuthTokenAssignmentPattern = `(assignment_expression
  left: (_) @rrjsauthkey
  right: (string) @rrjsauthval) @rrjsauthstmt`

	// Every string literal, for the internal services. The alternative — matching
	// a host pattern in the source text — would report a hostname written inside a
	// comment or a dead branch, which is the false positive this analyser's whole
	// design is against.
	jsStringLiteralPattern = `(string) @rrjsliteral`

	jsCapabilityQuery = jsRouteArrayPattern + "\n" +
		jsRouteKeyPattern + "\n" +
		jsAuthTokenPairPattern + "\n" +
		jsAuthTokenDeclaratorPattern + "\n" +
		jsAuthTokenAssignmentPattern + "\n" +
		jsStringLiteralPattern
)

// jsRouteKeys are the object keys whose array value is a list of routes.
//
// `sortedPages` and `pages` are Next.js. The rest are the spellings the other
// routers use for the same array, and the list is a set of names rather than a
// pattern: a name is the only thing that distinguishes a route list from any
// other array of strings, and a pattern broad enough to catch an unknown router
// also catches `allowedOrigins` and `mimeTypes`.
var jsRouteKeys = map[string]bool{
	"sortedPages":  true,
	"sortedRoutes": true,
	"pages":        true,
	"routes":       true,
	"staticRoutes": true,
	"appRoutes":    true,
	"routeList":    true,
}

// jsNextPageKey turns a webpack route key into a route.
//
// A Next.js pages-router key is `/_next/static/<buildId>/pages/<route>`, and the
// build id is a hash that changes on every deploy, so it is matched as a segment
// rather than spelled out. The two tail cases are the framework's own files and
// are not routes anybody navigates to: `index` is the page the site root serves
// and `_app`/`_document`/`_error`/`_middleware` are compiled into the bundle
// rather than requested.
var jsNextPageKey = regexp.MustCompile(`^/_next/static/[^/]+/pages/(.+)$`)

// jsNextPageNonRoutes are the manifest entries that are build files.
var jsNextPageNonRoutes = map[string]bool{
	"_app": true, "_document": true, "_error": true, "_middleware": true, "404": true, "500": true,
}

// jsRouteShape is what a manifest entry has to look like to be a route.
//
// The check is deliberately narrow, because the cost of accepting everything is
// a frontier full of dictionary paths and the cost of rejecting something is one
// missed route. A route starts with `/`, has no space, no backslash and no
// interpolation marker left in it, and is short enough to be a path rather than
// a sentence.
var jsRouteShape = regexp.MustCompile(`^/[A-Za-z0-9\-._~%!$&'()*+,;=:@/?#\[\]]*$`)

// jsInternalHost finds a loopback address in a string literal.
//
// The four loopback spellings are the four a JavaScript program actually uses:
// `localhost`, the IPv4 loopback, the IPv4 "any" address a dev server binds to
// and publishes, and the IPv6 loopback in either bracketed or bare form. The
// Docker host name is here because a compose network is the other place an
// "internal" service is reachable from, and it is the one that looks like an
// ordinary hostname to a filter.
var jsInternalHost = regexp.MustCompile(
	`(?i)\b(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1|host\.docker\.internal)(:\d{1,5})?`)

// jsHostPortAssignment is the second half of the same capability: the keyword
// search. The technique this ports is "look at the file for localhost, 127.0.0.1,
// host, port", and the keyword form is not covered by a host pattern because the
// two halves are in different places — `{host: "10.0.0.5", port: 8080}` names a
// service and neither half matches a loopback pattern.
//
// It runs over the body rather than the tree, deliberately: the value of the
// keyword form is precisely that it does not care where in the file the pair is,
// and a whole object of dev-server settings is exactly what it is meant to find.
var jsHostPortAssignment = regexp.MustCompile(
	`(?i)["']?(host|hostname|api_?host|api_?base|base_?url|port|host_?port|db_?host)["']?\s*[:=]\s*["']?([A-Za-z0-9._:\[\]-]{2,80})["']?`)

// jsViteMarkers are the strings and expressions that only a Vite build carries.
//
// `/@fs/` and `/@vite/client` are the dev server's own protocol: `/@fs/` is the
// endpoint that serves files outside the project root, and its presence is the
// precondition of the arbitrary file read in GHSA-x574-m823-4x7w. `import.meta.env`
// is replaced by the bundler at build time and exists in no hand-written program.
// The rest are paths a Vite project writes into its own output.
var jsViteMarkers = []struct {
	marker   string
	subject  string
	severity string
}{
	{"/@fs/", "vite dev server file bridge (/@fs/)", jsSeverityHigh},
	{"/@vite/client", "vite dev client (/@vite/client)", jsSeverityMedium},
	{"import.meta.env", "vite build (import.meta.env)", jsSeverityMedium},
	{"node_modules/.vite/", "vite dependency cache path", jsSeverityInfo},
	{"__vite", "vite runtime marker", jsSeverityInfo},
	{"vite.svg", "vite project asset", jsSeverityInfo},
}

// jsElectronMarkers are the strings that only an Electron application's bundle
// carries, and each one is named here with what it turns a script injection into.
//
// The source list for this is `doyensec/awesome-electronjs-hacking`, and the
// common thread of every write-up in it is the same: an XSS in the renderer is
// boring until the renderer has `nodeIntegration` or no context isolation, at
// which point the same injection is remote code execution or an arbitrary file
// read. So these markers are not "Electron is present" — the presence of the
// word proves nothing — they are the configuration flags that decide what an
// injection is worth, which is exactly what a bundle can be read for.
var jsElectronMarkers = []struct {
	pattern *regexp.Regexp
	subject string
	// literal is the exact text the pattern is built from, so the row can quote it
	// back to the analyst. A regular expression that found the flag at line 40 and
	// reported only "one match" would be a row about itself rather than about the
	// bundle.
	literal  string
	severity string
}{
	{regexp.MustCompile(`nodeIntegration\s*:\s*true`),
		"nodeIntegration: true — renderer scripts can require() node", "nodeIntegration: true", jsSeverityHigh},
	{regexp.MustCompile(`contextIsolation\s*[:=]\s*false`),
		"contextIsolation: false — preload globals reach page scripts", "contextIsolation: false", jsSeverityHigh},
	{regexp.MustCompile(`sandbox\s*:\s*false`),
		"sandbox:false — renderer runs unsandboxed", "sandbox:false", jsSeverityHigh},
	{regexp.MustCompile(`webSecurity\s*:\s*false`),
		"webSecurity:false — same-origin policy off", "webSecurity:false", jsSeverityHigh},
	{regexp.MustCompile(`nodeIntegrationInSubFrames\s*:\s*true`),
		"nodeIntegrationInSubFrames — node reaches every subframe", "nodeIntegrationInSubFrames: true", jsSeverityHigh},
	{regexp.MustCompile(`enableRemoteModule`),
		"enableRemoteModule — the remote module is enabled", "enableRemoteModule", jsSeverityHigh},
	{regexp.MustCompile(`remote\.getGlobal`),
		"remote.getGlobal — node globals through the remote module", "remote.getGlobal", jsSeverityHigh},
	{regexp.MustCompile(`allowRunningInsecureContent\s*:\s*true`),
		"allowRunningInsecureContent — insecure content allowed", "allowRunningInsecureContent: true", jsSeverityHigh},
	{regexp.MustCompile(`asar\.unpack`),
		"asar.unpack — package contents read from disk", "asar.unpack", jsSeverityMedium},
	{regexp.MustCompile(`readFileSync`),
		"readFileSync — a file read from the renderer", "readFileSync", jsSeverityMedium},
	{regexp.MustCompile(`shell\.openExternal`),
		"shell.openExternal — a URL opened outside the sandbox", "shell.openExternal", jsSeverityMedium},
	{regexp.MustCompile(`allowDisplayingInsecureContent\s*:\s*true`),
		"allowDisplayingInsecureContent — insecure content displayable", "allowDisplayingInsecureContent: true", jsSeverityMedium},
	{regexp.MustCompile(`setAsDefaultProtocolClient`),
		"setAsDefaultProtocolClient — a scheme handed in by the OS", "setAsDefaultProtocolClient", jsSeverityMedium},
	{regexp.MustCompile(`registerFileProtocol`),
		"registerFileProtocol — a file protocol handler", "registerFileProtocol", jsSeverityMedium},
	{regexp.MustCompile(`registerHttpProtocol`),
		"registerHttpProtocol — an http protocol handler", "registerHttpProtocol", jsSeverityMedium},
	{regexp.MustCompile(`webviewTag\s*:\s*true`),
		"webviewTag — the webview tag is enabled", "webviewTag: true", jsSeverityMedium},
	{regexp.MustCompile(`app\.asar`),
		"app.asar — the packaged archive itself", "app.asar", jsSeverityInfo},
	{regexp.MustCompile(`__dirname`),
		"__dirname — a directory inside the bundle", "__dirname", jsSeverityInfo},
	{regexp.MustCompile(`preload\.js`),
		"preload.js — the preload script", "preload.js", jsSeverityInfo},
}

// jsPrivilegedPath names an endpoint whose path says it does something
// privileged.
//
// This is the "find the sensitive path in the JS file that requires
// authentication" step, and it is a pattern over paths rather than a tree query
// because the path has already been extracted: what is being asked here is about
// the string `/dashboard/addAdmin.php`, which no parse tree can say more about.
var jsPrivilegedPath = regexp.MustCompile(
	`(?i)(add[-_]?admin|create[-_]?admin|super[-_]?admin|delete[-_]?admin|/admin|admin[-_/]|` +
		`panel|dashboard|new[-_]?user|create[-_]?user|add[-_]?user|invite|register[-_]?user|` +
		`set[-_]?role|assign[-_]?role|change[-_]?role|user[-_]?role|roles?|permissions?|privileges?|` +
		`promote|elevat|impersonat|api[-_]?keys?|apikeys?|access[-_]?token|refresh[-_]?token|` +
		`reset[-_]?password|forgot[-_]?password|change[-_]?password|password|passwd|` +
		`/token|/grant|/sudo)`)

// jsAuthTokenName is the shape of a name that carries an authentication secret.
//
// It is a shape and not a list of names on purpose. `secretRules` already answers
// "is this value a credential" for the values it knows, and this pass answers
// "is this name about authentication" — two different questions, and the second
// one has to keep working for a name nobody listed. It therefore matches on
// fragments (`token`, `secret`, `password`, `key`) rather than on whole names, and
// the shape check on the value does the rest.
var jsAuthTokenName = regexp.MustCompile(
	`(?i)(token|secret|password|passwd|credential|api[-_]?key|apikey|access[-_]?key|` +
		`private[-_]?key|client[-_]?key|bearer|auth)`)

// jsVariableNames are the identifiers a program binds that are not parameter
// candidates.
//
// The variable list is a fuzzing wordlist, so an entry that cannot be a
// parameter name in a URL makes it noise the operator has to read past: `let`,
// `const`, `if`, `return` and the rest of the language are bound names in a
// bundle and are not names anybody sends as `?let=`.
var jsNotParameterNames = map[string]bool{
	"var": true, "let": true, "const": true, "function": true, "return": true,
	"if": true, "else": true, "for": true, "while": true, "do": true, "switch": true,
	"case": true, "break": true, "continue": true, "new": true, "this": true,
	"typeof": true, "instanceof": true, "delete": true, "void": true, "in": true,
	"of": true, "try": true, "catch": true, "finally": true, "throw": true,
	"class": true, "extends": true, "super": true, "import": true, "export": true,
	"default": true, "from": true, "as": true, "async": true, "await": true,
	"yield": true, "static": true, "get": true, "set": true, "null": true,
	"true": true, "false": true, "undefined": true, "arguments": true,
	"require": true, "module": true, "exports": true, "window": true,
	"document": true, "console": true, "prototype": true, "constructor": true,
	"length": true, "toString": true, "valueOf": true,
}

// jsRequestOptionNames are the keys of a `fetch` init object and of an Axios
// config.
//
// They are bound names in the tree — `{method: "POST", body: …}` is a pair, and
// the variable pass reads pairs — so without this list the wordlist of every
// bundle that calls `fetch` begins with `method` and `body`, which are options
// of the request rather than names the server accepts. Measured on the fixture
// below: they were the first two rows, ahead of the parameter the file actually
// uses.
var jsRequestOptionNames = map[string]bool{
	"method": true, "body": true, "headers": true, "credentials": true,
	"mode": true, "cache": true, "redirect": true, "referrerPolicy": true,
	"referrer": true, "integrity": true, "keepalive": true, "signal": true,
	"window": true, "withCredentials": true, "params": true, "data": true,
	"baseURL": true, "timeout": true, "responseType": true, "onUploadProgress": true,
	"validateStatus": true, "transformRequest": true, "transformResponse": true,
}

// collectJSCapabilities reads the five categories off the parse tree the analyser
// already built.
//
// analyzer and body are the same arguments `collectJSFindings` takes, and for the
// same reason: a second parse of a multi-megabyte bundle is the most expensive
// thing this file could do. base is the URL the bytes came from, needed to turn a
// manifest route into something the crawl can request. endpoints and variables
// are what the analyser already produced, and they are inputs here rather than
// being recomputed — the endpoint list is the authoritative one, the merged and
// deduplicated one, and a second pass over the matchers would produce a different
// answer whenever the two folds disagree.
//
// secrets is passed only so a credential the secret pass already reported is not
// reported a second time here under a second name.
func collectJSCapabilities(
	analyzer *jsluice.Analyzer,
	body []byte,
	base *url.URL,
	endpoints []jsEndpoint,
	variables []jsVariable,
	secrets []jsSecret,
) jsCapabilities {
	c := newJSFindingCollector(body)
	capabilities := jsCapabilities{
		Findings: []jsFinding{},
		Routes:   []jsRoute{},
		Params:   []jsParamCandidate{},
		Links:    []string{},
	}
	reported := make(map[string]bool, len(secrets))
	for _, secret := range secrets {
		reported[secret.Value] = true
	}
	seenRoutes := make(map[string]bool)
	// The routes are gathered in the walk because that is where they are: a
	// route is a string literal, and reading it out of the text afterwards would
	// lose the difference between a string and a comment.
	analyzer.QueryMulti(jsCapabilityQuery, func(matches jsluice.QueryResult) {
		// A manifest route: the array form, keyed by a name that says what the
		// array is.
		if entry := matches.Get("rrjsroute"); entry != nil {
			key := matches.Get("rrjsroutekey")
			if key == nil || !jsRouteKeys[jsRouteKeyName(key)] {
				return
			}
			if route, ok := jsRouteOf(entry.DecodedString()); ok {
				c.addRoute(route, "sorted_pages", entry.Content(), seenRoutes, &capabilities)
			}
			return
		}
		// A webpack route key: the same information stored as an object key.
		if only := matches.Get("rrjsrouteonly"); only != nil {
			if route, ok := jsRouteOfWebpackKey(only.DecodedString()); ok {
				c.addRoute(route, "next_page_key", only.Content(), seenRoutes, &capabilities)
			}
			return
		}
		// A credential bound to an authentication-shaped name.
		if value := matches.Get("rrjsauthval"); value != nil {
			key := matches.Get("rrjsauthkey")
			if key == nil {
				return
			}
			c.reportAuthToken(key.Content(), value.DecodedString(), reported)
			return
		}
		// A string literal, for the services that answer only from inside.
		if literal := matches.Get("rrjsliteral"); literal != nil {
			c.reportInternalServices(literal.DecodedString(), literal.Content())
		}
	})
	// The Vite pass is a byte scan and not a walk: the markers are markers, and
	// a marker written in a comment still tells the analyst which bundler
	// produced the file. Reporting it is the point, so the walk would only cost.
	c.collectViteMarkers()
	c.collectElectronMarkers()
	// The keyword half of the internal-service category. It is a byte scan for
	// the same reason: a `host:`/`port:` pair is a property of the configuration
	// the program was built with, and it has to be found wherever it was written.
	c.collectHostPortKeywords()
	// The privileged endpoints and the wordlist are read from what the analyser
	// already produced rather than from the tree, because both are questions
	// about names the analyser has already extracted.
	c.collectPrivilegedEndpoints(endpoints)
	// The pair: an endpoint whose file also ships a credential near it. It runs
	// after both passes so it can see the secrets, not only the token rows.
	c.promotePairedPrivilegedEndpoints(secrets)
	capabilities.Findings = c.result()
	capabilities.Params = collectJSParamCandidates(endpoints, variables)
	capabilities.Links = resolveJSRoutes(base, capabilities.Routes)
	return capabilities
}

// addRoute folds one route into the record.
//
// The fold is on the route itself: a Next.js manifest names the same page in
// both shapes in some builds, and a route that appears twice is one page.
func (c *jsFindingCollector) addRoute(route, source, needle string, seen map[string]bool, out *jsCapabilities) {
	if seen[route] {
		return
	}
	seen[route] = true
	line := c.lineOf(jsFindingNeedle(needle))
	out.Routes = append(out.Routes, jsRoute{Route: route, Source: source, Line: line})
	c.add(jsFindingRoute, jsSeverityInfo, route, "", source+": "+route, jsFindingNeedle(needle))
}

// jsRouteKeyName reads the key of a manifest array, whether it was written as an
// identifier or as a quoted string.
func jsRouteKeyName(node *jsluice.Node) string {
	if node == nil {
		return ""
	}
	if name, ok := jsDecodedStringLiteral(node); ok {
		return name
	}
	return strings.TrimSpace(node.Content())
}

// jsRouteOf decides whether a manifest entry is a route.
//
// A Next.js pages-router manifest writes its routes as build paths
// (`/_next/static/<build>/pages/about`), so the first question is whether the
// entry is one of those and has to be rewritten into the route the browser
// requests. Answering that later produced a record in which every route was a
// path to a webpack chunk, which is neither a route nor requestable as one: the
// frontier carried `https://shop.example/_next/static/a1b2c3/pages/admin/
// settings` and the map grew by a file rather than by a page.
//
// An entry in any other spelling is taken as written, because that is what a
// router other than Next.js writes.
func jsRouteOf(entry string) (string, bool) {
	entry = strings.TrimSpace(entry)
	if len(entry) < 2 || len(entry) > 200 {
		return "", false
	}
	if route, mapped := jsRouteOfWebpackKey(entry); mapped {
		return route, true
	}
	if !jsRouteShape.MatchString(entry) {
		return "", false
	}
	// An interpolated entry is a shape, not a path, and the crawl refuses it too.
	// It stays in `routes` because "the application has a route with a parameter
	// in it" is information; it does not join the frontier because there is
	// nothing to request until the program runs.
	return entry, true
}

// jsRouteOfWebpackKey turns `/_next/static/<build>/pages/about` into `/about`.
func jsRouteOfWebpackKey(key string) (string, bool) {
	match := jsNextPageKey.FindStringSubmatch(strings.TrimSpace(key))
	if match == nil {
		return "", false
	}
	tail := strings.Trim(match[1], "/")
	if jsNextPageNonRoutes[tail] {
		return "", false
	}
	if tail == "" || tail == "index" {
		return "/", true
	}
	return "/" + tail, true
}

// reportInternalServices reports one loopback service named by a string literal.
//
// The report is the host with its port, not the whole literal, because the
// literal is usually a longer URL and the host is the part an SSRF probe needs.
// When the literal carries no port — `"http://localhost/admin"` — the host alone
// is still the finding, because "this program talks to localhost" is the fact
// that no single host-level check on the response could have produced.
func (c *jsFindingCollector) reportInternalServices(value, needle string) {
	if len(value) > 512 {
		return
	}
	match := jsInternalHost.FindString(value)
	if match == "" {
		return
	}
	// A bare version string or a UA comment that happens to contain "localhost"
	// is not a service. What separates them is whether the match stands alone as
	// a host or is embedded in one: the host pattern already requires a word
	// boundary, so what is left to check is that the rest of the literal still
	// looks like an address rather than like prose.
	service := jsInternalServiceName(match, value)
	if service == "" {
		return
	}
	c.add(jsFindingInternalService, jsSeverityMedium, service, "",
		jsFindingEvidence(value), jsFindingNeedle(needle))
}

// jsInternalServiceName normalises the matched address into the form a probe
// takes, and refuses a match that is prose rather than an address.
//
// The rule is positional, and it is positional because the looser version was
// measured to be wrong: a literal reading `run this on localhost first` reported
// `localhost` as a service, because the match stands somewhere inside a sentence
// and the earlier version treated "somewhere" as "at the start". A hostname is
// an address when what precedes it begins one — nothing, a scheme separator, a
// slash, an `@`, or the dot in `dev.localhost` — and when what follows it either
// continues the address or ends the literal: a slash, a port marker, a query, a
// fragment, or a comma. A space on either side is prose, and prose is not a
// service an SSRF probe can reach.
func jsInternalServiceName(match, value string) string {
	index := strings.Index(value, match)
	if index < 0 {
		return ""
	}
	if index > 0 {
		switch value[index-1] {
		case '/', ':', '@', '.', '[', '=', ',':
		default:
			return ""
		}
	}
	if rest := value[index+len(match):]; rest != "" {
		switch rest[0] {
		case '/', ':', '?', '#', '.', ',':
		default:
			return ""
		}
	}
	return strings.TrimSuffix(match, ".")
}

// collectHostPortKeywords reports the services named by a `host:`/`port:` pair.
//
// The literal pass above cannot see this shape, and the reason is worth stating
// rather than leaving as a gap: `{host: "10.0.0.5", port: 8080}` names a service
// without either half matching a loopback pattern, because the address is an
// internal one that is not a loopback — which is the more valuable case, since a
// `127.0.0.1` a client can already reach is a fact and a `10.x` reachable only
// through an SSRF is a target.
//
// The two halves are reported as one service when they sit next to each other,
// because a host and a port that are 400 bytes apart in a minified object are
// not a pair anybody can act on. Each half is reported on its own when it is
// alone, because a host with no port is still an internal service.
func (c *jsFindingCollector) collectHostPortKeywords() {
	matches := jsHostPortAssignment.FindAllSubmatchIndex(c.body, -1)
	// Pairs are read first so that a host and the port beside it are one row
	// rather than two, and so the walk over the matches below is not repeated
	// per match.
	type pair struct{ key, value string }
	hostAt := -1
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}
		key := string(c.body[match[2]:match[3]])
		value := string(c.body[match[4]:match[5]])
		switch strings.ToLower(key) {
		case "host", "hostname", "api_host", "api_hostname", "api_base", "base_url", "db_host":
			if jsInternalHost.MatchString(value) || jsPrivateHost.MatchString(value) {
				service := jsServiceName(value)
				if service != "" {
					c.add(jsFindingInternalService, jsSeverityMedium, service, "",
						jsFindingEvidence(key+" = "+value), jsFindingNeedle(key))
					hostAt = match[1]
					continue
				}
			}
			// A `host` that is an ordinary public name is the ordinary case and is
			// not a finding. A port with no host beside it is not either, because
			// `port: 443` is every default in the world.
		case "port", "host_port":
			if hostAt >= 0 && match[0]-hostAt < jsHostPortProximity {
				hostAt = -1
			}
		}
	}
}

// jsHostPortProximity is how far apart a host and a port may sit and still be one
// service. It is measured in bytes because the source is what the pair was read
// from, and a minified object literal puts the two within a handful of bytes of
// each other while a 400-byte gap is two unrelated declarations.
const jsHostPortProximity = 64

// jsPrivateHost is an address that is not on the loopback interface but is not
// public either.
//
// The four private ranges are the ones RFC 1918 defines plus the link-local
// range, and they are in this file because the technique the operator's list
// describes is "find the internal services", and the internal services on a real
// deployment are not `localhost` — they are the database and the cache, which
// answer on `10.x`, `172.16-31.x` and `192.168.x`.
//
// The address may be followed by a port, and the earlier `$` anchor refused that:
// `host: "10.0.4.7:5432"` is how a connection string is written, and the pattern
// stopped matching before the port. `(?:$|:)` accepts the port and still refuses
// `10.0.0.1.example.com`, which a bare `\b` would have accepted — the difference
// between a private service and a public host whose name begins with one.
var jsPrivateHost = regexp.MustCompile(
	`(?i)\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|` +
		`172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|` +
		`[a-z0-9-]+\.(internal|local|localdomain|lan|home|test))(?:$|:)`)

// jsServiceName normalises an address into the form a probe takes, refusing
// anything that is not one.
func jsServiceName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 80 {
		return ""
	}
	if strings.ContainsAny(trimmed, " \t\r\n\"'<>()[]{}") {
		return ""
	}
	if !jsInternalHost.MatchString(trimmed) && !jsPrivateHost.MatchString(trimmed) {
		return ""
	}
	return trimmed
}

// collectViteMarkers reports the bundler markers.
// One finding per marker with a count, folded by the collector's own key, so a
// bundle that mentions `/@fs/` in forty places is one row that says forty rather
// than forty rows.
func (c *jsFindingCollector) collectViteMarkers() {
	for _, entry := range jsViteMarkers {
		occurrences := bytes.Count(c.body, []byte(entry.marker))
		if occurrences == 0 {
			continue
		}
		c.add(jsFindingViteDevServer, entry.severity, entry.subject, "",
			entry.marker+" appears "+strconv.Itoa(occurrences)+" time(s)", entry.marker)
	}
}

// jsProbeWordsLimit is how many fuzzing words one endpoint contributes.
//
// It exists because the arithmetic does: a bundle with 40 request sites and 600
// variable names produces 24 000 combinations, of which the analyst reads none.
// The limit is therefore a **presentation** bound, not a scope one — every
// endpoint is still represented, and `probe_words_truncated` says how many
// combinations were dropped, so the number of what was left out is visible
// rather than implied.
const jsProbeWordsLimit = 40

// fuzzablePath turns an endpoint reference into a path a request can carry.
//
// The analyser's `URL` keeps the program as written, and that is right: it is
// the evidence, and `/api/v1/users/EXPR` says the program builds the path where a
// resolved URL would have hidden it. A fuzzing wordlist wants the opposite — a
// path that can be sent. So the placeholder is replaced with a value that keeps
// the shape and can travel, and the substitution is stated here rather than left
// for the analyst to discover on the first 404.
//
// The result is a *starting point*, not a working request: a path built from an
// expression may still need an identifier the program takes from somewhere else.
// That is what fuzzing is for, and it is why these are words and not findings.
func fuzzablePath(path string) string {
	if !strings.Contains(path, "EXPR") {
		return path
	}
	return strings.ReplaceAll(path, "EXPR", "1")
}

// collectTargetSpecificWordlist builds the list GAP calls a "target specific
// wordlist": the endpoints this bundle names, each carrying a parameter this
// same bundle names.
//
// The pairing is what makes it useful rather than merely large. `params` on its
// own is a list of names the program uses somewhere; `endpoints` on its own is
// a list of paths it calls. The word `path` next to the name `campaign_id` is
// the only thing that says "this program sends that value here", and it is the
// sentence the fuzzing needs to start from.
//
// The source is `xnl-h4ck3r/GAP-Burp-Extension` at commit
// f223016fa347776aff59dd610da8f1e2ffee3260, read from its README. What it does
// not do — and this deliberately does not either — is decide that any of these
// words is a vulnerability. They are hypotheses to send, not findings.
func collectTargetSpecificWordlist(endpoints []jsEndpoint, params []jsParamCandidate) ([]string, int) {
	words := make([]string, 0, 64)
	dropped := 0
	seen := make(map[string]bool, 64)

	// A parameter the endpoint already declares is not news: the analyst can see
	// that one in the request. Only names the endpoint does not carry yet are
	// worth proposing.
	for _, endpoint := range endpoints {
		path := endpointPathOf(endpoint.URL)
		if path == "" {
			continue
		}
		declared := make(map[string]bool, len(endpoint.Query))
		for _, name := range endpoint.Query {
			declared[strings.ToLower(name)] = true
		}
		for _, name := range endpoint.Body {
			declared[strings.ToLower(name)] = true
		}
		added := 0
		for _, candidate := range params {
			if added >= jsProbeWordsLimit {
				dropped++
				continue
			}
			name := strings.TrimSpace(candidate.Name)
			if name == "" || declared[strings.ToLower(name)] {
				continue
			}
			word := fuzzablePath(path) + "?" + name + "=1"
			if seen[word] {
				continue
			}
			seen[word] = true
			words = append(words, word)
			declared[strings.ToLower(name)] = true
			added++
		}
	}
	return words, dropped
}

// collectElectronMarkers reports the Electron configuration a bundle carries.
//
// One finding per marker with a count, folded by the collector's own key, exactly
// like the bundler markers above: a bundle that names `nodeIntegration` in six
// places is one row that says six, not six rows that say the same thing.
func (c *jsFindingCollector) collectElectronMarkers() {
	for _, entry := range jsElectronMarkers {
		occurrences := len(entry.pattern.FindAll(c.body, -1))
		if occurrences == 0 {
			continue
		}
		c.add(jsFindingElectronExposure, entry.severity, entry.subject, "",
			entry.literal+" appears "+strconv.Itoa(occurrences)+" time(s)", entry.literal)
	}
}

// collectPrivilegedEndpoints reports the endpoints whose path names a privileged
// action, and the file's own authentication tokens.
//
// The two are collected in one function because they are one finding to a
// reader: an admin-creating endpoint is interesting on its own, and a token in
// the same file is interesting on its own, and the pair is the vulnerability the
// technique actually describes — a shipped credential that authorises a
// privileged action.
func (c *jsFindingCollector) collectPrivilegedEndpoints(endpoints []jsEndpoint) {
	for _, endpoint := range endpoints {
		path := endpointPathOf(endpoint.URL)
		if path == "" || !jsPrivilegedPath.MatchString(path) {
			continue
		}
		method := endpoint.Method
		if method == "" {
			method = "GET"
		}
		evidence := method + " " + endpoint.URL
		c.add(jsFindingPrivilegedEndpoint, jsSeverityMedium, endpoint.URL, "", evidence, endpoint.URL)
	}
}

// jsTokenProximity is how many lines apart a credential and a privileged
// endpoint may sit and still be one finding.
//
// The technique this ports is "read the JS, find the token and the endpoint it
// authorises" — and in the file the technique was reported on, the two were four
// lines apart in one bundled config object. A bundle is one long line in the
// general case, so a byte distance would say nothing there and a line distance
// says "the same line". The window is a judgement, and it is stated here rather
// than buried in a constant: too wide and a file that ships an unrelated
// credential pairs every privileged endpoint with it, which is the same row
// repeated and reads as noise.
const jsTokenProximity = 5

// promotePairedPrivilegedEndpoints raises an endpoint whose file also carries a
// credential near it.
//
// The two rows exist without this — a privileged path and a hardcoded token are
// each worth reading. What this adds is the pair, which is the vulnerability the
// technique actually describes: a shipped credential that authorises a
// privileged action is one step from an account takeover, while either row alone
// is a lead. The severity goes up only when the credential is near the endpoint,
// because proximity is the only evidence the file offers that the two belong
// together.
//
// The credential may come from either pass. A value `collectJSSecrets` already
// reported is a credential too, and it is the common case: a bare `token = "…"`
// is matched by the generic secret rule and therefore produces a `jsSecret` row
// rather than a `hardcoded_auth_token` one, and pairing only the second kind
// would miss exactly the shape the technique describes. Measured on the fixture
// below: pairing only the `hardcoded_auth_token` rows left an `addAdmin.php`
// with a credential one line away at `medium`, which is the row a reader scans
// past.
func (c *jsFindingCollector) promotePairedPrivilegedEndpoints(secrets []jsSecret) {
	type credential struct {
		rule string
		line int
	}
	var credentials []credential
	for _, secret := range secrets {
		credentials = append(credentials, credential{rule: secret.Rule, line: secret.Line})
	}
	for _, finding := range c.folded {
		if finding.Kind == jsFindingHardcodedAuthToken {
			credentials = append(credentials, credential{rule: finding.Subject, line: finding.Line})
		}
	}
	if len(credentials) == 0 {
		return
	}
	for _, endpoint := range c.folded {
		if endpoint.Kind != jsFindingPrivilegedEndpoint || endpoint.Line == 0 {
			continue
		}
		for _, held := range credentials {
			if held.line == 0 {
				continue
			}
			distance := endpoint.Line - held.line
			if distance < 0 {
				distance = -distance
			}
			if distance > jsTokenProximity {
				continue
			}
			endpoint.Severity = jsSeverityHigh
			endpoint.Evidence = endpoint.Evidence + "; a credential is declared " +
				strconv.Itoa(distance) + " line(s) away (" + held.rule + ")"
			break
		}
	}
}

// endpointPathOf returns the path of a reference the analyser recorded, so the
// privileged-path pattern is asked about the path rather than about the whole
// URL. A host name that happens to contain "admin" is not an admin endpoint.
func endpointPathOf(reference string) string {
	trimmed := strings.TrimSpace(reference)
	if trimmed == "" {
		return ""
	}
	if index := strings.Index(trimmed, "?"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if index := strings.Index(trimmed, "#"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if scheme := strings.Index(trimmed, "://"); scheme >= 0 {
		rest := trimmed[scheme+3:]
		slash := strings.Index(rest, "/")
		if slash < 0 {
			return ""
		}
		return rest[slash:]
	}
	return trimmed
}

// reportAuthToken reports one credential bound to an authentication-shaped name.
//
// Three checks, in this order, and each of them exists because a looser version
// reports a row a reader has to disprove. The name must be about authentication;
// the value must look like a value rather than like a word; and the value must
// not be one the secret pass already reported, because one leaked key is one row.
func (c *jsFindingCollector) reportAuthToken(name, value string, alreadyReported map[string]bool) {
	if name == "" || value == "" {
		return
	}
	if !jsAuthTokenName.MatchString(name) {
		return
	}
	if !jsAuthTokenValueUsable(value) {
		return
	}
	if alreadyReported[value] {
		return
	}
	alreadyReported[value] = true
	c.add(jsFindingHardcodedAuthToken, jsSeverityHigh, strings.TrimSpace(name), "",
		jsFindingEvidence(name+": "+jsRedactTokenValue(value)), jsFindingNeedle(name))
}

// jsAuthTokenValueUsable is the shape check on the value.
//
// The floor is a length, because a token is not `true` and not `undefined`; the
// mixed-character rule is what keeps a flag and a constant out; and the
// placeholder filter is the same one every other credential path in this project
// applies, so `YOUR_TOKEN_HERE` is not reported here and is not reported there
// either.
func jsAuthTokenValueUsable(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 8 || len(trimmed) > 512 {
		return false
	}
	if isPlaceholderValue(trimmed) {
		return false
	}
	letters, digits := 0, 0
	for _, character := range trimmed {
		switch {
		case character >= '0' && character <= '9':
			digits++
		case (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z'):
			letters++
		}
	}
	if letters == 0 || digits == 0 {
		// A value made only of letters is a word or a flag; only letters is the
		// shape of `password`, and that is a `secretRules` row, not this one.
		return false
	}
	return true
}

// jsRedactTokenValue shortens a credential for the evidence column.
//
// The full value is already in `secrets` for every key a rule recognises, and the
// point of this row is that a name holds a credential — not a second copy of the
// credential in a column a table renders. The first and last four characters
// survive because two keys that share a prefix and a suffix are the same key.
func jsRedactTokenValue(value string) string {
	if len(value) <= 12 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + "…" + value[len(value)-4:]
}

// collectJSParamCandidates is GAP's "get all parameters", as a wordlist.
//
// The three sources are the analyser's own query and body parameter names — read
// off the call sites, so `?redirect=` and the `redirect` in a `URLSearchParams`
// constructor are both in it — and the variable names, which is the technique
// the one-liner in the operator's list performs and the reason this list is worth
// building: a name the program binds is a name the server may accept.
//
// A name is reported once, with every source that produced it, so a name that is
// both a query parameter and a variable is one row that says both rather than two
// rows that look like two parameters.
func collectJSParamCandidates(endpoints []jsEndpoint, variables []jsVariable) []jsParamCandidate {
	sources := make(map[string]map[string]bool)
	record := func(name, source string) {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 80 {
			return
		}
		// A name that cannot be sent as a parameter name is not a candidate, and
		// the check is on the name rather than on the value: `?` and `=` in a
		// parameter name are a URL that has to be encoded before it is a request,
		// and a name with a space in it is a sentence.
		if strings.ContainsAny(name, " \t\r\n?#&\"'\\{}[]<>") {
			return
		}
		if !jsParameterNameShape.MatchString(name) {
			return
		}
		entry, seen := sources[name]
		if !seen {
			entry = make(map[string]bool, 3)
			sources[name] = entry
		}
		entry[source] = true
	}
	for _, endpoint := range endpoints {
		for _, name := range endpoint.Query {
			record(name, jsParamSourceQuery)
		}
		for _, name := range endpoint.Body {
			record(name, jsParamSourceBody)
		}
	}
	for _, variable := range variables {
		if jsNotParameterNames[variable.Name] || jsRequestOptionNames[variable.Name] {
			continue
		}
		record(variable.Name, jsParamSourceVariable)
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	candidates := make([]jsParamCandidate, 0, len(names))
	for _, name := range names {
		entry := sources[name]
		list := make([]string, 0, len(entry))
		for _, source := range []string{jsParamSourceQuery, jsParamSourceBody, jsParamSourceVariable} {
			if entry[source] {
				list = append(list, source)
			}
		}
		candidates = append(candidates, jsParamCandidate{Name: name, Sources: list})
	}
	return candidates
}

// jsParameterNameShape is what a name has to look like to be sent as a parameter.
//
// `$` is in it because half the identifiers a minifier keeps start with it, and
// `.` because a namespaced name (`config.debug`) is what an application
// flattens into `config.debug` on the wire often enough that dropping it would
// drop real candidates.
var jsParameterNameShape = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.-]*$`)

// resolveJSRoutes turns the routes into crawl frontier entries.
//
// Only routes a browser could follow are enqueued, and the gate is the same
// `jsCrawlableReference` the endpoint frontier uses: a dynamic segment is a
// shape rather than a path, and requesting it would send a request nobody asked
// for. The route stays in `routes` either way, because "the application has
// `/blog/[slug]`" is information the analyst reads even when the crawler cannot
// go there.
func resolveJSRoutes(base *url.URL, routes []jsRoute) []string {
	if base == nil {
		return nil
	}
	seen := make(map[string]bool, len(routes))
	links := make([]string, 0, len(routes))
	for index := range routes {
		route := routes[index].Route
		if !jsCrawlableReference(route) {
			continue
		}
		resolved := mustResolveURL(base, route).String()
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		links = append(links, resolved)
		routes[index].Resolved = resolved
	}
	sort.Strings(links)
	return links
}

// mergeJSFindings folds the capability findings into the analyser's own.
//
// The fold is on kind, subject and function, which is the collector's own key,
// so a category both passes can report is one row. It is applied here rather than
// inside the collector because the two passes build their own collectors: the
// capabilities pass needs the endpoint and variable lists, which are computed
// after the analyser's own findings exist.
func mergeJSFindings(existing, extra []jsFinding) []jsFinding {
	if len(extra) == 0 {
		return existing
	}
	index := make(map[string]int, len(existing)+len(extra))
	merged := make([]jsFinding, 0, len(existing)+len(extra))
	add := func(finding jsFinding) {
		key := finding.Kind + "\x00" + finding.Subject + "\x00" + finding.Function
		if at, seen := index[key]; seen {
			merged[at].Count += finding.Count
			if finding.Line > 0 && (merged[at].Line == 0 || finding.Line < merged[at].Line) {
				merged[at].Line = finding.Line
			}
			if jsSeverityRank(finding.Severity) > jsSeverityRank(merged[at].Severity) {
				merged[at].Severity = finding.Severity
			}
			return
		}
		index[key] = len(merged)
		merged = append(merged, finding)
	}
	for _, finding := range existing {
		add(finding)
	}
	for _, finding := range extra {
		add(finding)
	}
	sort.SliceStable(merged, func(left, right int) bool {
		if rank, other := jsFindingRank(merged[left].Kind), jsFindingRank(merged[right].Kind); rank != other {
			return rank < other
		}
		if merged[left].Severity != merged[right].Severity {
			return jsSeverityRank(merged[left].Severity) > jsSeverityRank(merged[right].Severity)
		}
		if merged[left].Line != merged[right].Line {
			return merged[left].Line < merged[right].Line
		}
		return merged[left].Subject < merged[right].Subject
	})
	return merged
}
