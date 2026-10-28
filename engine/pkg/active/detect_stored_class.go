package active

// StoredClass proves the **class** of a stored vulnerability, not its
// precondition.
//
// # The precondition is this module's own row, not a separate detector's
//
// An earlier version split this in two: a `stored-probe` detector wrote a fixed
// token and reported that it came back on another page, and twenty-three register
// rows were written against **it** — stored XSS, stored CSS, stored parameter
// pollution, stored form hijacking, stored redirect, second-order SQL, both
// password rows, and the twelve stored DOM-sink variants. None of those rows had
// any code that submitted a payload of its class. They had a precondition and a
// symbol, and the register's mechanical guard checked for the symbol, so all
// twenty-three passed.
//
// So the precondition is reported here, at `info`, in the row built for values that
// came back in no context any rule recognises — which is the honest reading of
// them: the application stores a value the client controls, and nothing about
// where it rendered it is wrong yet. One detector for the family, one row per
// class, and the precondition no longer reported twenty-three times by a weaker
// instrument.
//
// What makes any of this a vulnerability is **what** the value does where it
// lands. An application that renders a customer's name back to them is doing its
// job; one that renders their `<img onerror>` back to them is not.
//
// # Why one write pass and one read pass
//
// Reading the run's pages twice — once before the writes and once after — is what
// makes freshness measurable, and doing it once per class would cost nine passes
// over the same pages for one answer. So the module takes its baselines first,
// writes every class's payload once, re-reads each page once, and then applies
// every rule to every body it fetched.
//
// # Why a rule that needs a field it cannot find is skipped, loudly
//
// Three of the eleven rules need a particular field: the password rules need a
// password field and the redirect rules need a URL-shaped one. A form without
// them is not a target for those rules, and a module that wrote a password-shaped
// value into an `email` field would be manufacturing the very finding it reports.
// So the rule is skipped and the reason is in the module's evidence on the page —
// not silently absent.
//
// # What each rule actually proves
//
// The proofs are deliberately narrow, and each is narrow in the way its class
// needs:
//
//   - **HTML injection** requires the submitted payload to come back byte for
//     byte and to land outside the contexts where markup is inert (`textarea`,
//     `title`, a comment). Escaped output does not match, because the `<` is gone.
//   - **DOM / JavaScript injection** requires the payload inside a `<script>`
//     block, which is the context the HTML rule explicitly does not claim.
//   - **CSS injection** requires the payload's `</style>` to be unescaped, which
//     is the only part of a stylesheet payload that means anything.
//   - **Parameter pollution** requires both values to appear *adjacent*, because
//     a server that kept one of them is not concatenating them and concatenation
//     is the primitive that bypasses a filter.
//   - **Form-action hijacking** requires a form whose action points off this
//     origin **and** carries this run's marker, so the module is not reporting a
//     pre-existing third-party form.
//   - **Open redirect** requires the off-site address in a navigation context,
//     and the DOM variant requires it in a JavaScript navigation specifically.
//   - **Second-order SQL injection** requires an SQL signature that was not on the
//     page before the write. A fresh signature is the evidence; the absence of one
//     proves nothing and is not claimed.
//   - **The two password rows** require the submitted value in a later page's body
//     and in a later page's cookie respectively.
//
// # What is not proven
//
// Nothing here proves exploitation. A stored HTML injection is proven as an
// injection — the client chose markup the server rendered — and what a visitor's
// browser then does with it is the ordinary consequence, not an additional claim
// this module could make from the outside.

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// StoredClass is the class-level stored reader.
type StoredClass struct {
	// pages are the URLs the crawl fetched, handed in by the run after the crawl
	// and before any detector runs. A module cannot re-read a page it was not
	// told about, and the run is the only place that knows the list.
	pages []string
}

// PagesKnown implements crawledPagesAware.
func (s *StoredClass) PagesKnown(pages []string) { s.pages = pages }

// Name implements Module.
func (StoredClass) Name() string { return "stored-class" }

// Level implements Module.
//
// Host level, and the reason is the shape of the question: the value is written at
// one URL and demonstrated at another, so a surface-level call could only ever see
// one half of the exchange.
func (StoredClass) Level() Level { return LevelHost }

// storedClassMarkers are the fixed tokens this module writes.
//
// They are fixed for the reason every other canary in the package is fixed: a
// finding's identity hashes its payload, so a random token would make two runs of
// the same target produce two different reports. Freshness against the pre-write
// baseline is what the token is measured by, and that is not randomness.
const (
	storedMarkerHTML     = "rrstoredhtml"
	storedMarkerJS       = "rrstoredjs"
	storedMarkerCSS      = "rrstoredcss"
	storedMarkerHPPA     = "rrstoredhppa"
	storedMarkerHPPB     = "rrstoredhppb"
	storedMarkerAction   = "rrstoredaction"
	storedMarkerRedirect = "rr-redirect.invalid/rrstoredredirect"
	storedMarkerSQL      = "rrstoredsql"
	storedMarkerPassword = "rrstoredpassword"
	storedRedirectHost   = "rr-redirect.invalid"
	storedActionHost     = "rr-action.invalid"
	storedMaxClassWrites = 23
	storedClassMaxPages  = 24
)

// storedClassRule is one class: the payload that carries it, and the proof that it
// landed where it means something.
type storedClassRule struct {
	// class is the name the report prints.
	class string
	// typeIndex is the original check's identifier, carried in the title so a
	// register row and a report row are the same row.
	typeIndex string
	// claimed is the severity the proof supports.
	claimed Severity
	// field is the fragment a form's field name must contain for this rule to run.
	// Empty means any non-file field will do.
	field string
	// payload is the submitted value. It is built from the fixed markers so two
	// runs produce the same request and the same finding identity.
	payload string
	// marker is the substring whose fresh appearance the proof is about.
	marker string
	// proves reads the response the value came back in and reports whether this
	// class is demonstrated there.
	proves func(resp *Response) bool
	// repeated is the parameter list a rule submits, when submitting it once would
	// not produce the condition the rule is about.
	//
	// It exists for parameter pollution and for nothing else. The pollution claim
	// is that a **duplicated** parameter is concatenated, and the only way to
	// produce a duplicate is to send the same name twice — a first version
	// submitted one value containing an `&`, which the encoder turned into a
	// literal character and which therefore tested nothing at all.
	repeated []string
	// evidence names where on the page the value landed, for the evidence line.
	evidence func(body string) string
	// description says what the proof means, in the class's own terms.
	description string
	// remediation is what the class's fix is.
	remediation string
}

// storedClassRules are the classes, in report order.
//
// The order is the order a reader triages in: a credential and a redirect are
// things a user loses, then the contexts a browser executes, then the contexts a
// browser only styles.
var storedClassRules = []storedClassRule{
	{
		class: "Password Returned in Later Response", typeIndex: "0x00400200",
		claimed: SeverityHigh, field: "password",
		payload: storedMarkerPassword, marker: storedMarkerPassword,
		proves: func(resp *Response) bool { return strings.Contains(resp.Body, storedMarkerPassword) },
		evidence: func(body string) string {
			return Snippet(body, storedMarkerPassword, 160)
		},
		description: "A value submitted into a password field was rendered again on another page " +
			"of the same application. Whatever that page shows it to is now visible to every " +
			"reader of that page, which for a password field means the credential left the form " +
			"it was typed into.",
		remediation: "Never render a submitted password back. Clear the field on submission, " +
			"never store the plaintext, and render a mask that cannot be reversed into the " +
			"original value.",
	},
	{
		class: "Password Value Set in Cookie", typeIndex: "0x00500900",
		claimed: SeverityHigh, field: "password",
		payload: storedMarkerPassword, marker: storedMarkerPassword,
		proves: func(resp *Response) bool { return storedCookieCarries(resp, storedMarkerPassword) },
		evidence: func(string) string {
			return "the value came back in a `Set-Cookie` header, not in the page body"
		},
		description: "A value submitted into a password field was set back in a cookie. A cookie " +
			"is sent with every request to the origin and is readable by script on it, so a " +
			"credential in a cookie is a credential in every log, every proxy and every " +
			"referrer between here and wherever the request goes.",
		remediation: "Do not put credentials in cookies. Use a session identifier that means " +
			"nothing on its own, mark it `HttpOnly` and `Secure`, and keep the credential on " +
			"the server side.",
	},
	{
		class: "Open Redirection (stored)", typeIndex: "0x00500101",
		claimed: SeverityMedium, field: "url",
		payload: "https://" + storedMarkerRedirect, marker: storedRedirectHost,
		proves:   func(resp *Response) bool { return storedNavigationHas(resp.Body, storedRedirectHost, false) },
		evidence: func(body string) string { return Snippet(body, storedRedirectHost, 160) },
		description: "A value submitted into a URL-shaped field came back and is used as the " +
			"target of a navigation on the page. A link or form on this origin therefore points " +
			"at an address the client chose, which is what a phishing link wearing this site's " +
			"name is.",
		remediation: "Allow-list the destinations a stored URL may point at, or resolve it " +
			"server-side to a path on this origin before it reaches the markup.",
	},
	{
		class: "Open Redirection (stored DOM-based)", typeIndex: "0x00500112",
		claimed: SeverityMedium, field: "url",
		payload: "https://" + storedMarkerRedirect, marker: storedRedirectHost,
		proves:   func(resp *Response) bool { return storedNavigationHas(resp.Body, storedRedirectHost, true) },
		evidence: func(body string) string { return Snippet(body, storedRedirectHost, 160) },
		description: "The same stored value, used as the target of a **scripted** navigation — " +
			"`location.href`, `location.replace`, `location.assign`. The destination is chosen " +
			"by the client and the departure happens in script, so no link is ever rendered for " +
			"a reader to inspect and a link-checking filter sees nothing.",
		remediation: "Validate the destination before assigning it to `location`, and prefer a " +
			"server-side redirect over a scripted one so the destination is decided where the " +
			"request can be validated.",
	},
	{
		class: "Form Action Hijacking (stored)", typeIndex: "0x00501501",
		claimed: SeverityHigh,
		payload: `"><form action="https://` + storedActionHost + `/` + storedMarkerAction +
			`"><input name="x" value="` + storedMarkerAction + `"`,
		marker:   storedActionHost,
		proves:   func(resp *Response) bool { return storedFormPointsOffOrigin(resp.Body, storedActionHost) },
		evidence: func(body string) string { return Snippet(body, storedActionHost, 200) },
		description: "A stored value was rendered inside a form's markup and closed the form " +
			"that was there, replacing it with one whose action points at " + storedActionHost +
			". A form is where a visitor types a credential, so the credential goes to that " +
			"host instead of this one — and the form is indistinguishable from the site's own.",
		remediation: "Render stored values with the encoder for their context and never as raw " +
			"markup. A form's `action` must come from configuration, not from anything a visitor " +
			"supplied.",
	},
	{
		class: "HTML Injection (stored)", typeIndex: "0x00200100",
		claimed:  SeverityHigh,
		payload:  `<img src=x onerror="` + storedMarkerHTML + `">`,
		marker:   storedMarkerHTML,
		proves:   func(resp *Response) bool { return storedVerbatimOutsideInertContext(resp.Body) },
		evidence: func(body string) string { return Snippet(body, storedMarkerHTML, 200) },
		description: "A submitted value came back byte for byte, as the markup that was " +
			"submitted, and it landed where markup is live. The client chose HTML and the server " +
			"rendered it as HTML, so every later reader of that page parses the client's " +
			"elements — which is stored cross-site scripting.",
		remediation: "Encode the value for the context it is rendered in. In element content " +
			"that means escaping `<`, `>`, `&` and the quotes; in an attribute it means not " +
			"letting the value introduce one.",
	},
	{
		class: "DOM Cross-Site Scripting (stored)", typeIndex: "0x00200312",
		claimed:  SeverityHigh,
		payload:  `rrstoredjs";var rr=1//`,
		marker:   storedMarkerJS,
		proves:   func(resp *Response) bool { return storedInsideScript(resp.Body, storedMarkerJS) },
		evidence: func(body string) string { return Snippet(body, storedMarkerJS, 200) },
		description: "A submitted value was rendered inside a `<script>` block. The value " +
			"contains a string terminator followed by a statement, so the script the server " +
			"served is not the script its author wrote — and a script block runs wherever the " +
			"page is opened, with the page's own origin and cookies.",
		remediation: "Never interpolate a stored value into a script block. Put it in a data " +
			"attribute or a JSON island and read it from the script, or escape it for the " +
			"script context.",
	},
	{
		class: "JavaScript Injection (stored DOM-based)", typeIndex: "0x00200322",
		claimed:  SeverityHigh,
		payload:  `rrstoredjs";var rr=1//`,
		marker:   storedMarkerJS,
		proves:   func(resp *Response) bool { return storedInsideScript(resp.Body, storedMarkerJS) },
		evidence: func(body string) string { return Snippet(body, storedMarkerJS, 200) },
		description: "The same stored value in the same script context as the DOM-XSS row, and " +
			"named separately because the two differ in **where** the payload has to come " +
			"from: this one needs the value to have been stored by an earlier request and read " +
			"by a later page load, which is what a run that writes then re-reads demonstrates " +
			"and a reflected check never can.",
		remediation: "Escape for the script context, or keep stored values out of script " +
			"blocks entirely — a data attribute read through `textContent` cannot be closed " +
			"with a quote the application supplied.",
	},
	{
		class: "CSS Injection (stored)", typeIndex: "0x00501301",
		claimed: SeverityMedium,
		payload: storedMarkerCSS + `}</style><img src=x onerror="` + storedMarkerCSS + `">`,
		marker:  storedMarkerCSS,
		proves: func(resp *Response) bool {
			return strings.Contains(resp.Body, "</style><img src=x onerror=\""+storedMarkerCSS)
		},
		evidence: func(body string) string { return Snippet(body, storedMarkerCSS, 200) },
		description: "A submitted value carried a `</style>` that was not escaped, so it closed " +
			"the stylesheet it was rendered into and everything after it was parsed as markup " +
			"rather than as CSS. That is stylesheet injection: the client chose markup on a page " +
			"whose surrounding content is supposed to be styles.",
		remediation: "Escape the value for the CSS context, and never render user data inside a " +
			"`<style>` block — a stylesheet link with parameters, or a CSS class chosen from a " +
			"fixed set, does not have this problem.",
	},
	{
		class: "HTTP Parameter Pollution (stored)", typeIndex: "0x00501401",
		claimed: SeverityMedium,
		payload: storedMarkerHPPA + "&" + storedMarkerHPPB,
		marker:  storedMarkerHPPA,
		// The duplicated parameter is what the rule is about, so it is submitted
		// as two values of one name rather than as one value containing a `&`.
		repeated: []string{storedMarkerHPPA, storedMarkerHPPB},
		proves:   func(resp *Response) bool { return storedValuesAdjacent(resp.Body) },
		evidence: func(body string) string { return Snippet(body, storedMarkerHPPA, 200) },
		description: "One field was submitted twice and the server rendered **both** values, " +
			"next to each other, rather than keeping one. A filter that inspects the value it " +
			"reads sees the first and blocks on it, while the backend acts on the pair — so the " +
			"same request carries an allowed and a rejected value at once.",
		remediation: "Reject a request that carries the same parameter more than once instead " +
			"of picking a winner, and make the front end and the backend agree on which one " +
			"wins if duplicates are genuinely expected.",
	},
	{
		class: "SQL Injection (second order)", typeIndex: "0x00100210",
		claimed:  SeverityHigh,
		payload:  storedMarkerSQL + `' OR '1'='1`,
		marker:   storedMarkerSQL,
		proves:   func(resp *Response) bool { return storedSQLSignaturePresent(resp.Body) },
		evidence: func(body string) string { return Snippet(body, "sql", 200) },
		description: "A value containing SQL syntax was stored, and a page that read it back " +
			"now answers with a database error it did not answer with before. The application " +
			"stored a client-supplied string and used it in a query later, which is the whole " +
			"of second-order injection: the injection happens on a request that never carried " +
			"the payload.",
		remediation: "Parameterise the query that reads the stored value, exactly as you would " +
			"the one that stores it. Sanitising on the way in does not help when the dangerous " +
			"use is somewhere else entirely.",
	},
}

// Scan takes its baselines, writes one payload per rule, and proves each class.
func (s StoredClass) Scan(ctx context.Context, t *Transport, p Point, _ *Response) []Finding {
	if len(s.pages) == 0 {
		return nil
	}
	if _, _, ok := originOf(p.URL); !ok {
		return nil
	}

	pages := s.readPages()
	if len(pages) == 0 {
		return nil
	}
	// The pre-write baselines. Without them "the marker is on the page" cannot be
	// told from "the marker was always on the page", and the whole module would be
	// reporting its own memory of an earlier run.
	before := make(map[string]*Response, len(pages))
	forms := make([]storedTargetForm, 0, len(pages))
	for _, page := range pages {
		resp, err := t.Do(ctx, http.MethodGet, page, nil, false, nil)
		if err != nil || resp == nil || resp.StatusCode >= 400 {
			continue
		}
		before[page] = resp
		if !strings.Contains(strings.ToLower(resp.HeaderValue("Content-Type")), "text/html") {
			continue
		}
		for _, form := range formsOf(resp.Body) {
			if form.hasFile {
				// A multipart upload is a write to the target's disk. Creating
				// files on somebody's server is not what these checks ask for.
				continue
			}
			forms = append(forms, storedTargetForm{
				form:   form,
				page:   page,
				parsed: pageURL(page),
			})
		}
	}
	if len(forms) == 0 {
		return nil
	}

	writes := s.write(ctx, t, forms)
	if len(writes) == 0 {
		return nil
	}

	var out []Finding
	// `unclaimed` collects the writes whose value came back but in no context any
	// rule recognises. It is what the precondition row is built from, and the reason
	// this module owns the precondition at all: a separate detector for "the
	// application stores what a client sends" would be a second, weaker account of
	// what this one already measured.
	unclaimed := map[string]storedUnclaimed{}
	for _, page := range pages {
		resp, err := t.Do(ctx, http.MethodGet, page, nil, false, nil)
		if err != nil || resp == nil || resp.StatusCode >= 400 {
			continue
		}
		for _, write := range writes {
			if !Fresh(before[page], resp, write.rule.marker) {
				continue
			}
			if write.landedOn(before[page], resp) {
				out = append(out, storedClassFinding(write, page, resp))
				continue
			}
			unclaimed[write.field] = storedUnclaimed{write: write, page: page, response: resp}
		}
	}
	if len(unclaimed) > 0 {
		out = append(out, storedPreconditionFinding(p, unclaimed))
	}
	return out
}

// storedUnclaimed is one write that came back without landing in a context any
// rule recognises.
type storedUnclaimed struct {
	write    storedClassWrite
	page     string
	response *Response
}

// storedPreconditionFinding renders the precondition row.
//
// It is `info` and it is not a finding about a class, and the two are different
// enough to say so in the row itself: the application stores a value the client
// controls and renders it again, and nothing about **where** it rendered it is
// wrong yet. That is a fact about the application that every class rule reads
// from, and reporting it once here is what keeps it from being reported once per
// class by a weaker detector.
func storedPreconditionFinding(p Point, unclaimed map[string]storedUnclaimed) Finding {
	fields := make([]string, 0, len(unclaimed))
	var example storedUnclaimed
	for _, entry := range unclaimed {
		fields = append(fields, entry.write.field)
		example = entry
	}
	sort.Strings(fields)
	finding, _ := NewFinding(Spec{
		Module:  "stored-class",
		Title:   "Stored Value Reappears on Another Page (no class context): stored-state precondition",
		Claimed: SeverityInfo,
		Tier:    TierVerified,
		Point:   Point{URL: example.page, Method: http.MethodGet, Origin: example.page},
		Payload: example.write.method + " " + example.write.endpoint + " " + example.write.field +
			"=" + example.write.rule.payload,
		Evidence: "submitted to " + example.write.endpoint + " from " + example.write.page +
			"\nrendered on: " + example.page +
			"\nfields: " + strings.Join(fields, ", ") +
			"\n" + Snippet(example.response.Body, example.write.rule.marker, 160),
		Description: "Values this run submitted were rendered again on another page of the same " +
			"application. The application therefore stores a value the client controls and renders " +
			"it later to another visitor — which is the precondition every stored finding needs.\n\n" +
			"Not a finding about a class: none of them landed in a context where the value means " +
			"anything beyond its own text. What the application does with stored values decides " +
			"that, and this run reports it as the fact it is.",
		Remediation: "Treat a stored value as untrusted everywhere it is rendered. The value is " +
			"the client's, and every later reader of it is a reader of what the client wrote.",
	})
	return finding
}

// storedTargetForm is a form this run may submit to.
type storedTargetForm struct {
	form   pageForm
	page   string
	parsed *url.URL
}

// storedClassWrite is one submitted payload and the rule that asked for it.
type storedClassWrite struct {
	rule storedClassRule
	// page is the page the form was found on.
	page string
	// endpoint is where it was submitted.
	endpoint string
	// method is how, upper-cased.
	method string
	// field is the form field the value went into.
	field string
	// values is the whole submitted set, because a form that needs a password
	// field needs its other fields too.
	values url.Values
}

// write submits one payload per rule, to the first form that carries a field the
// rule can use.
func (s StoredClass) write(ctx context.Context, t *Transport, forms []storedTargetForm) []storedClassWrite {
	var out []storedClassWrite
	for _, rule := range append(storedClassRules[:len(storedClassRules):len(storedClassRules)],
		storedDOMSinkClassRules()...) {
		if len(out) >= storedMaxClassWrites || ctx.Err() != nil {
			return out
		}
		chosen, field, ok := storedFormForRule(forms, rule)
		if !ok {
			continue
		}
		endpoint := chosen.form.action
		if endpoint == "" {
			endpoint = chosen.page
		}
		absolute, err := chosen.parsed.Parse(endpoint)
		if err != nil || absolute.Host == "" {
			continue
		}
		// Only the rule's own field is submitted, and that is deliberate. A first
		// version filled every declared field with a placeholder so that a form
		// with required inputs would accept the submission — and because these
		// writes are separate requests to the same form, each one overwrote the
		// markers the earlier rules had stored, so exactly one sink rule ever saw
		// its value. An application that rejects an incomplete submission is
		// telling the module something, and the honest reading of that is "this
		// rule did not run", not "write a placeholder into twelve fields".
		values := url.Values{}
		if len(rule.repeated) > 0 {
			// A duplicated parameter: the encoder turns two values of one name
			// into `name=a&name=b`, which is what makes the server read two.
			values[field] = append([]string(nil), rule.repeated...)
		} else {
			values.Set(field, rule.payload)
		}
		verb := http.MethodGet
		if chosen.form.method != http.MethodGet {
			verb = http.MethodPost
		}
		if _, err := t.Do(ctx, verb, absolute.String(), values, false, nil); err != nil {
			continue
		}
		out = append(out, storedClassWrite{
			rule:     rule,
			page:     chosen.page,
			endpoint: absolute.String(),
			method:   verb,
			field:    field,
			values:   values,
		})
	}
	return out
}

// storedFormForRule picks the form a rule submits to.
//
// A rule that needs a particular field gets a form that has it, and a rule that
// needs none gets the first form with any field to fill. The rule that this
// selection exists for is the opposite failure: putting a password-shaped value
// into an `email` field would manufacture the finding the module reports.
func storedFormForRule(forms []storedTargetForm, rule storedClassRule) (storedTargetForm, string, bool) {
	for _, candidate := range forms {
		name, ok := formHasNamedField(candidate.form, rule.field)
		if !ok {
			continue
		}
		return candidate, name, true
	}
	return storedTargetForm{}, "", false
}

// landedOn reports whether this write's payload came back on this page **and was
// not there before the write**.
//
// Freshness is checked against the body's own marker rather than against the
// rule's proof, because the two answer different questions: the proof says the
// value is in a context that means something, and freshness says the value is
// this run's. A rule whose proof reads headers instead — the cookie row — is
// compared against the headers, for the same reason.
func (write storedClassWrite) landedOn(before, after *Response) bool {
	if before == nil || after == nil {
		return false
	}
	if write.rule.proves(after) == false {
		return false
	}
	if storedCookieCarries(before, write.rule.marker) && !strings.Contains(before.Body, write.rule.marker) {
		return storedCookieCarries(after, write.rule.marker)
	}
	return Fresh(before, after, write.rule.marker)
}

// storedClassFinding renders one row.
func storedClassFinding(write storedClassWrite, page string, resp *Response) Finding {
	payload := write.method + " " + write.endpoint + " " + write.field + "=" + write.rule.payload
	finding, _ := NewFinding(Spec{
		Module:  "stored-class",
		Title:   write.rule.class + ": " + write.rule.typeIndex,
		Claimed: write.rule.claimed,
		Tier:    TierVerified,
		Point:   Point{URL: page, Method: http.MethodGet, Origin: page},
		Payload: payload,
		Evidence: "submitted to " + write.endpoint + " from " + write.page +
			"\nfield:  " + write.field +
			"\nvalue:  " + write.rule.payload +
			"\nrendered on: " + page +
			"\n" + write.rule.evidence(resp.Body),
		Description: write.rule.description,
		Remediation: write.rule.remediation,
	})
	return finding
}

// readPages is the run's page list reduced to distinct URLs of this origin.
func (s StoredClass) readPages() []string {
	var out []string
	seen := map[string]bool{}
	for _, page := range s.pages {
		if len(out) >= storedClassMaxPages {
			break
		}
		parsed, err := url.Parse(strings.TrimSpace(page))
		if err != nil || parsed.Host == "" {
			continue
		}
		parsed.Fragment, parsed.RawFragment = "", ""
		target := parsed.String()
		if seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

// storedInertTags are the elements inside which markup is text, so a value that
// comes back byte for byte inside one of them has not been injected.
var storedInertTags = []string{"textarea", "title", "pre", "code", "xmp"}

// storedVerbatimOutsideInertContext is the HTML-injection proof.
//
// Two halves, and both are needed. The payload must come back **byte for byte**,
// which is what separates an injection from output that merely contains the same
// letters — an escaped `<` is not the `<` the payload was, and the browser does
// not parse it as a tag. And it must land outside the contexts where markup is
// text, because a value echoed inside a `<textarea>` is displayed, not executed,
// and reporting that as stored XSS would be the most common false positive in
// this whole family.
func storedVerbatimOutsideInertContext(body string) bool {
	lower := strings.ToLower(body)
	for offset := 0; ; {
		index := strings.Index(body[offset:], "<img src=x onerror=\"")
		if index < 0 {
			return false
		}
		index += offset
		if !storedInsideInertContext(lower, index) {
			return true
		}
		offset = index + 1
	}
}

// storedInsideInertContext reports whether an index sits inside an element where
// markup is text, or inside a comment.
func storedInsideInertContext(lower string, index int) bool {
	open := lower[:index]
	if strings.LastIndex(open, "<!--") > strings.LastIndex(open, "-->") {
		return true
	}
	for _, tag := range storedInertTags {
		marker := "<" + tag
		if strings.LastIndex(open, marker) > strings.LastIndex(open, "</"+tag+">") {
			return true
		}
	}
	return false
}

// storedInsideScript reports whether a marker sits inside a `<script>` block.
func storedInsideScript(body, marker string) bool {
	lower := strings.ToLower(body)
	for offset := 0; ; {
		index := strings.Index(body[offset:], marker)
		if index < 0 {
			return false
		}
		index += offset
		open := lower[:index]
		if strings.LastIndex(open, "<script") > strings.LastIndex(open, "</script>") {
			return true
		}
		offset = index + 1
	}
}

// storedNavigationHas reports whether a host appears as the target of a
// navigation, and — when `scripted` is set — whether that navigation happens in
// script rather than in markup.
//
// The two are separate claims and the second is the DOM variant's whole content:
// a `href` is a link a reader can see and a filter can read, while
// `location.href =` moves the visitor without anything on the page changing.
func storedNavigationHas(body, host string, scripted bool) bool {
	if scripted {
		for _, call := range []string{"location.href", "location.replace", "location.assign", "window.location"} {
			if storedAssignsNavigation(body, host, call) {
				return true
			}
		}
		return false
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, host) {
		return false
	}
	for _, attribute := range []string{`href="`, `action="`, `src="`, "url=", `content="`} {
		for offset := 0; ; {
			index := strings.Index(lower[offset:], attribute)
			if index < 0 {
				break
			}
			window := lower[offset+index : min(offset+index+400, len(lower))]
			if strings.Contains(window, host) {
				return true
			}
			offset += index + 1
		}
	}
	return false
}

// storedAssignsNavigation reports whether a JavaScript navigation call names this
// host as its destination.
func storedAssignsNavigation(body, host, call string) bool {
	lower := strings.ToLower(body)
	for offset := 0; ; {
		index := strings.Index(lower[offset:], call)
		if index < 0 {
			return false
		}
		index += offset
		window := lower[index:min(index+300, len(lower))]
		if strings.Contains(window, host) {
			return true
		}
		offset = index + 1
	}
}

// storedFormPointsOffOrigin reports whether a form on the page submits somewhere
// this origin does not own.
//
// It exists for the hijacking row rather than for an open redirect, and the
// difference is what makes it a separate check: a form's action is where a
// visitor types a credential, so the claim is about credentials leaving, not
// about a link.
func storedFormPointsOffOrigin(body, host string) bool {
	lower := strings.ToLower(body)
	for offset := 0; ; {
		index := strings.Index(lower[offset:], "<form")
		if index < 0 {
			return false
		}
		index += offset
		// The start tag is what carries the action, so the scan stops at the
		// first `>` after it — reading past that would let one form's action be
		// taken from a later element's markup.
		rest := lower[index:]
		if end := strings.IndexByte(rest, '>'); end > 0 {
			element := rest[:end]
			if action, ok := storedAttribute(element, "action"); ok && strings.Contains(action, host) {
				return true
			}
		}
		offset = index + 1
	}
}

// storedAttribute reads one attribute out of a start tag.
func storedAttribute(element, name string) (string, bool) {
	marker := name + "=\""
	index := strings.Index(element, marker)
	if index < 0 {
		marker = name + "='"
		index = strings.Index(element, marker)
		if index < 0 {
			return "", false
		}
	}
	rest := element[index+len(marker):]
	end := strings.IndexAny(rest, "\"'")
	if end < 0 {
		return "", false
	}
	return strings.ToLower(rest[:end]), true
}

// storedValuesAdjacent reports whether the two pollution values came back next to
// each other.
//
// Adjacency is the whole claim. A server that kept one value has not polluted
// anything; a server that rendered both separated by a delimiter has, and the
// delimiter is what a filter and a backend disagree about.
func storedValuesAdjacent(body string) bool {
	index := strings.Index(body, storedMarkerHPPA)
	if index < 0 {
		return false
	}
	window := body[index:min(index+len(storedMarkerHPPA)+16, len(body))]
	return strings.Contains(window, storedMarkerHPPB)
}

// storedSQLSignatures are the phrases a database says when a statement it was
// given does not parse.
//
// They are the evidence for second-order injection and nothing else, so they are
// read as a whole list rather than as one marker: an application behind one
// database stack says one of these, and a check that only knew one vendor's
// message would report nothing against the other five.
var storedSQLSignatures = []string{
	"sql syntax", "sqlstate", "mysql_", "mysqli_", "ora-", "oracle error",
	"postgresql", "pg_query", "pg_exec", "sqlite_", "sqlite3",
	"system.data.sqlclient", "unclosed quotation mark", "odbc sql",
	"syntax error at or near", "warning: mysql", "you have an error in your sql",
}

// storedSQLSignaturePresent reports whether the body carries a database error.
func storedSQLSignaturePresent(body string) bool {
	lower := strings.ToLower(body)
	for _, signature := range storedSQLSignatures {
		if strings.Contains(lower, signature) {
			return true
		}
	}
	return false
}

// storedCookieCarries reports whether a response sets a cookie whose value holds
// the marker.
//
// It is separate from the body proof because the two password rows are different
// findings: one says the credential is rendered to a reader, the other says it
// rides along on every subsequent request to the origin.
func storedCookieCarries(resp *Response, marker string) bool {
	for _, cookie := range resp.SetCookies() {
		if strings.Contains(cookie, marker) {
			return true
		}
	}
	return false
}
