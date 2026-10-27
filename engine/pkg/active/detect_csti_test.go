package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cstiPage boots one of the engines the way the fixture pages do: the real
// script tag, the real mount, and the parameter inside an interpolation.
//
// The version is not in these pages unless a test states it, so the default
// findings carry no version — which is the case worth testing, because a row that
// depends on a version and shows none must not claim one.
func cstiPage(engine, version, expression string) string {
	switch engine {
	case "angularjs":
		body := `<html><body><div ng-app><p id="out">{{` + expression + `}}</p></div>` +
			`<script src="/fixtures/frameworks/angular.min.js"></script>`
		if version != "" {
			body += `<script>angular.version={full:"` + version + `"}</script>`
		}
		return body
	case "vue3":
		body := `<html><body><div id="app"><p id="out">{{` + expression + `}}</p></div>` +
			`<script src="/fixtures/frameworks/vue.global.js"></script>` +
			`<script>Vue.createApp({}).mount('#app')</script>`
		if version != "" {
			// The one form a page states inline: a versioned app config, which is what
			// a build without a separate version endpoint leaves behind.
			body = strings.Replace(body, "Vue.createApp({})", "Vue.createApp({version:'"+version+"'})", 1)
		}
		return body
	default:
		body := `<html><body><div id="app"><p id="out">{{` + expression + `}}</p></div>` +
			`<script src="/fixtures/frameworks/vue.js"></script>` +
			`<script>new Vue({el:'#app'})</script>`
		if version != "" {
			body += `<script>Vue.version="` + version + `"</script>`
		}
		return body
	}
}

// cstiPoint is the surface every CSTI probe runs on.
// cstiPlaceholder is where the fixture page puts the parameter. It is an explicit
// token rather than `{{q}}` because one of the control pages writes the parameter
// inside `{{{…}}}`, and a placeholder that is itself an interpolation would be
// rewritten by the substitution that is supposed to leave it alone.
const cstiPlaceholder = "__Q__"

func cstiPoint(target string) Point {
	return Point{URL: target, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}}, Source: "query"}
}

func serveCSTI(t *testing.T, body string) (*httptest.Server, *Transport) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.ReplaceAll(body, cstiPlaceholder, value)))
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return server, transport
}

// TestClientTemplateFiresOnEachEngineItBoots is the detector's whole claim: a
// parameter written into a live interpolation is reported, once per engine, with
// the engine named.
func TestClientTemplateFiresOnEachEngineItBoots(t *testing.T) {
	for _, tc := range []struct{ engine, version string }{
		// Vue 3's version lives inside its own bundle, which the page loads as a
		// separate file, so a page that boots it usually states nothing — and the
		// row then carries no version rather than a guessed one.
		{"angularjs", "1.8.3"}, {"vue2", "2.7.16"}, {"vue3", ""},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			server, transport := serveCSTI(t, cstiPage(tc.engine, tc.version, cstiPlaceholder))
			findings := (ClientTemplate{}).Scan(context.Background(), transport,
				cstiPoint(server.URL), &Response{Body: cstiPage(tc.engine, tc.version, cstiPlaceholder)})
			if len(findings) != 1 {
				t.Fatalf("findings = %d, want 1: the page boots %s and interpolates the parameter",
					len(findings), tc.engine)
			}
			row := findings[0]
			if !strings.Contains(row.Title, tc.engine) {
				t.Errorf("title = %q, want it to name the engine %q", row.Title, tc.engine)
			}
			if row.Payload != cstiProbe {
				t.Errorf("payload = %q, want the probe the reader can re-fetch: %q", row.Payload, cstiProbe)
			}
			if row.Tier != TierPotential {
				t.Errorf("tier = %v, want potential: an unevaluated expression is not yet an execution",
					row.Tier)
			}
			if tc.version == "" {
				if row.Version != "" {
					t.Errorf("version = %q, want none: the page never stated one", row.Version)
				}
				if row.PatchState != "" {
					t.Errorf("patch state = %q, want none: the row does not depend on a version "+
						"it never read", row.PatchState)
				}
				return
			}
			if !strings.Contains(row.Version, tc.version) {
				t.Errorf("version = %q, want the page's own %q", row.Version, tc.version)
			}
			if row.PatchState == "" {
				t.Error("a row that depends on a version carries no patch state")
			}
		})
	}
}

// TestClientTemplateStaysSilentWhereThereIsNothingToCompile is the half that keeps
// the detector quiet on the rest of the web.
func TestClientTemplateStaysSilentWhereThereIsNothingToCompile(t *testing.T) {
	cases := []struct{ name, body string }{
		{"no framework at all", `<html><body><p>` + cstiPlaceholder + `</p></body></html>`},
		{"library linked but never booted",
			`<html><body><p>` + cstiPlaceholder + `</p><script src="/app.bundle.js"></script></body></html>`},
		{"the parameter is not reflected at all",
			`<html><body><div id="app"><p>{{user.name}}</p></div>` +
				`<script src="/fixtures/frameworks/vue.js"></script>` +
				`<script>new Vue({el:'#app'})</script></html>`},
		{"baseline could not be read", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The served page and the baseline are the same page on purpose. A
			// control that only works because the baseline differs from what the
			// server answers is testing the harness, not the detector.
			var baseline *Response
			served := tc.body
			if served == "" {
				served = `<html><body><p>` + cstiPlaceholder + `</p></body></html>`
			} else {
				baseline = &Response{Body: tc.body}
			}
			server, transport := serveCSTI(t, served)
			if findings := (ClientTemplate{}).Scan(context.Background(), transport,
				cstiPoint(server.URL), baseline); len(findings) != 0 {
				t.Fatalf("findings = %d, want none: %+v", len(findings), findings)
			}
		})
	}
}

// TestAPayloadBringsItsOwnInterpolation is the case that looks like a control and
// is not: the application writes the value into ordinary text, far from any
// interpolation, and the payload's own delimiters are what create one. A detector
// that required the value to land inside the page's existing `{{…}}` would miss
// exactly this, which is the attack.
func TestAPayloadBringsItsOwnInterpolation(t *testing.T) {
	body := `<html><body><p>hello ` + cstiPlaceholder + `</p><div id="app"><p>{{user.name}}</p></div>` +
		`<script src="/fixtures/frameworks/vue.js"></script>` +
		`<script>new Vue({el:'#app'})</script></html>`
	server, transport := serveCSTI(t, body)
	findings := (ClientTemplate{}).Scan(context.Background(), transport, cstiPoint(server.URL),
		&Response{Body: body})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the payload closes and opens its own interpolation, "+
			"which is how this injection works in the first place", len(findings))
	}
}

// TestAnEscapedInterpolationIsAPotentialAndNotASilence is the case where the
// structural layer cannot know the answer and the browser is the answer.
//
// `{{{q}}}` is Vue's *raw* interpolation: the delimiters reach the page as text
// and the engine prints them instead of compiling what is inside. Whether the
// payload reached the compiler therefore depends on the engine, and the response
// body cannot tell it — the response looks identical either way. So the row is
// reported as a potential and the browser stage is what settles it, and a target
// that escaped the value is distinguished from one that compiled it by whether
// the marker comes back.
func TestAnEscapedInterpolationIsAPotentialAndNotASilence(t *testing.T) {
	body := `<html><body><div id="app"><p>{{{__Q__}}}</p></div>` +
		`<script src="/fixtures/frameworks/vue.js"></script>` +
		`<script>new Vue({el:'#app'})</script></html>`
	server, transport := serveCSTI(t, body)
	findings := (ClientTemplate{}).Scan(context.Background(), transport, cstiPoint(server.URL),
		&Response{Body: body})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the response cannot tell a raw interpolation from a "+
			"compiled one, so the row is a potential and the browser decides", len(findings))
	}
	if findings[0].Tier != TierPotential {
		t.Errorf("tier = %v, want potential: nothing here shows the engine ran it", findings[0].Tier)
	}
	// And the stage that can tell: an escaped page answers nothing, so no proof
	// and no upgrade.
	silent := &silentRenderer{}
	suite := &Suite{Transport: testTransport(t, nil), Renderer: silent, MarkerHost: "rr.invalid"}
	if proofs := suite.Run(context.Background(), findings); len(proofs) != 0 {
		t.Fatalf("proofs = %+v, want none from a page that executed nothing", proofs)
	}
}

// TestClientTemplateNeedsTheProbeToBeNewToThePage. A page whose own template
// carries an interpolation reports every parameter on that page if the check is
// `contains` instead of `Fresh`, and this is the fixture that proves which one it
// is: the baseline below already holds the probe, so the reflection is not new.
func TestClientTemplateNeedsTheProbeToBeNewToThePage(t *testing.T) {
	body := cstiPage("vue2", "2.7.16", cstiPlaceholder)
	server, transport := serveCSTI(t, body)
	findings := (ClientTemplate{}).Scan(context.Background(), transport, cstiPoint(server.URL),
		&Response{Body: strings.ReplaceAll(body, cstiPlaceholder, cstiProbe)})
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want none: the baseline already carries the probe, so its "+
			"reflection proves nothing about the parameter", len(findings))
	}
}

// TestEachEngineGetsItsOwnGadget pins the three expressions, and pins that they
// differ where the engines differ. A shared gadget for Vue 3 would be a claim
// about an engine it was never measured on.
func TestEachEngineGetsItsOwnGadget(t *testing.T) {
	marker := "http://rr.invalid/rrxe/row"
	seen := map[string]string{}
	for _, engine := range []string{"angularjs", "vue2", "vue3"} {
		payload, ok := cstiProofPayload(Finding{Module: "csti", Version: engine + " 1.0"}, marker)
		if !ok {
			t.Fatalf("no gadget for %s", engine)
		}
		// The page supplies the outer delimiters, so a gadget is the *middle* of the
		// measured shape, not a whole `{{…}}`: that is what makes the reflected value
		// compile instead of nesting.
		if !strings.HasPrefix(payload, cstiWrapStart) || !strings.HasSuffix(payload, cstiWrapEnd) {
			t.Errorf("%s payload = %q, want the measured shape %q…%q",
				engine, payload, cstiWrapStart, cstiWrapEnd)
		}
		if strings.Contains(payload, cstiExpressionStart+cstiExpressionStart) {
			t.Errorf("%s payload = %q, want no empty interpolation: an empty expression aborts "+
				"the 2.x render, and the gadget beside it never runs", engine, payload)
		}
		if !strings.Contains(payload, marker) {
			t.Errorf("%s gadget = %q, want it to request the marker", engine, payload)
		}
		seen[engine] = payload
	}
	// Vue 3 compiles the expression into a render function, so the `with`-scope
	// reachability the 1.x/2.x engines share does not exist there — and a borrowed
	// gadget would be a claim about an engine nobody measured. AngularJS and Vue 2
	// are *expected* to coincide: both evaluate through a function whose scope holds
	// `this`, which is the same escape written once.
	if seen["vue3"] == seen["vue2"] || seen["vue3"] == seen["angularjs"] {
		t.Errorf("vue3 reuses a 1.x/2.x gadget %q: its expression scope differs and so must the escape",
			seen["vue3"])
	}
	// A row that names no engine gets every engine's expressions to try, and a row
	// with no marker at all gets nothing — a marker is the whole of the evidence.
	//
	// Five, not six: AngularJS and Vue 2 both open with the same
	// `constructor.constructor`, and trying it twice would spend a browser load to
	// learn what the first one already answered. The other four are distinct
	// expressions upstream ships, each measured running on its own bundle.
	if got := cstiProofPayloads(Finding{Module: "csti"}, marker); len(got) != 5 {
		t.Errorf("a row with no named engine offered %d expressions, want 5: 2 angular + 3 vue2 "+
			"+ 1 vue3, less the one expression both 1.x-style engines share", len(got))
	}
	if got := cstiProofPayloads(Finding{Module: "csti", Version: "vue3 3.4.21"}, ""); got != nil {
		t.Errorf("a row with no marker offered %v, want nothing to try", got)
	}
	// And the engine a row names is tried first, so a versioned page settles in one
	// load rather than three.
	named := cstiProofPayloads(Finding{Module: "csti", Version: "vue3 3.4.21"}, marker)
	if len(named) == 0 || !strings.Contains(named[0], "$props") {
		t.Errorf("named engine's expression = %v, want the vue3 gadget first", named)
	}
	// A bundled application states no version, and the row says so — but it still
	// knows which engine the page booted, and that is what decides the order. This
	// is the case measured live: a Vue 3 row whose version is empty spent six
	// browser attempts instead of two until the row's own engine went first.
	fromSource := cstiProofPayloads(Finding{Module: "csti", VersionSource: "script:vue3"}, marker)
	if len(fromSource) == 0 || !strings.Contains(fromSource[0], "$props") {
		t.Errorf("engine named only by VersionSource = %v, want the vue3 gadget first: the row "+
			"knows the engine even when the page states no version number", fromSource)
	}
	// And a source that names nothing leaves the order alone rather than guessing.
	if guessed := cstiProofPayloads(Finding{Module: "csti", VersionSource: "header:X-Powered-By"}, marker); len(guessed) != 5 {
		t.Errorf("a row whose version source names no engine offered %d expressions, want the "+
			"unordered 5", len(guessed))
	}
}

// TestEachEngineCarriesExactlyTheGadgetsMeasuredOnItsBundle. The list is a
// measurement, so the table is asserted as one: a dropped entry is an upstream
// capability lost, and an extra entry is a candidate that costs a navigation and
// proves nothing — Vue 3's two upstream expressions are exactly that case.
func TestEachEngineCarriesExactlyTheGadgetsMeasuredOnItsBundle(t *testing.T) {
	marker := "http://rr.invalid/rrxe/row"
	want := map[string]int{"angularjs": 2, "vue2": 3, "vue3": 1}
	for i := range cstiFrameworks {
		engine := cstiFrameworks[i]
		expected, known := want[engine.product]
		if !known {
			t.Fatalf("engine %q is not in the measured table; the measurement has to be redone "+
				"for it before it is offered to a browser", engine.product)
		}
		if len(engine.gadgets) != expected {
			t.Errorf("%s carries %d gadgets, want %d measured ones", engine.product,
				len(engine.gadgets), expected)
		}
		seen := map[string]bool{}
		for _, gadget := range engine.gadgets {
			expression := gadget(marker)
			if seen[expression] {
				t.Errorf("%s lists the same expression twice: %q", engine.product, expression)
			}
			seen[expression] = true
			if !strings.Contains(expression, marker) {
				t.Errorf("%s gadget %q does not carry the marker: a proof without it proves nothing",
					engine.product, expression)
			}
			// The delimiter count is the part that is easy to get wrong and invisible
			// in a screenshot: one `{` too few and the page renders the payload as
			// text — measured, because the nine-candidate run that produced this table
			// reported zero executions until the shape was corrected.
			if strings.Count(expression, "{{") != 0 || strings.Contains(expression, "{{") {
				t.Errorf("%s gadget %q writes its own interpolation: the page supplies the "+
					"delimiters, so the gadget is the middle of the shape", engine.product, expression)
			}
			payload := cstiWrapStart + expression + cstiWrapEnd
			if strings.Count(payload, "{{") != 2 || strings.Count(payload, "}}") != 2 {
				t.Errorf("%s payload %q has %d `{{` and %d `}}`, want 2 and 2: an unbalanced "+
					"shape renders as text instead of compiling",
					engine.product, payload, strings.Count(payload, "{{"), strings.Count(payload, "}}"))
			}
		}
	}
	// Vue 3's own two upstream expressions are named in the code as measured NOT
	// executing; a future change that adds them must be a re-measurement, not a
	// transcription, and this test is where that difference shows.
	for _, expression := range cstiFrameworks[2].gadgets {
		if strings.Contains(expression(marker), "_c") || strings.Contains(expression(marker), "this.") {
			t.Errorf("vue3 offers a Vue-2 expression %q: both were measured on Vue 3.4.21 and "+
				"neither runs there", expression(marker))
		}
	}
}

// TestTheCSTIProofLoadsTheExpressionNotTheProbe. The reported payload is `{{7*7}}`
// and the executed one is the gadget; a proof that quietly loaded the probe would
// render `49` and settle nothing, which looks exactly like a page that refused.
func TestTheCSTIProofLoadsTheExpressionNotTheProbe(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "csti", Title: "client-side template injection", Claimed: SeverityHigh,
		Tier: TierPotential, Point: Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
		Payload: cstiProbe, Evidence: "the page wrote the probe into an expression",
		Version: "vue2 2.7.16",
	})
	rowMarker := xsseMarkerURL("rr.invalid", row.ID)
	renderer := &stubRenderer{page: BrowserPage{Network: []string{rowMarker}}}
	payload, ok := cstiProofPayload(row, rowMarker)
	if !ok {
		t.Fatal("no gadget for a row that names its engine")
	}
	target := proofURL(row, payload)
	if strings.Contains(target, "7%2A7") {
		t.Errorf("proof url %q carries the arithmetic probe, so the browser would render 49 and settle nothing",
			target[:60])
	}
	if !strings.Contains(target, "constructor") {
		t.Errorf("proof url %q does not carry the engine's gadget", target[:80])
	}
	// The proof and the upgrade are two steps: the stage produces the evidence and
	// `applyProofUpgrades` is what raises the row. Testing the stage's output for
	// `Upgrades` would test a field the stage does not set.
	suite := &Suite{Transport: testTransport(t, nil), Renderer: renderer, MarkerHost: "rr.invalid"}
	proofs := suite.Run(context.Background(), []Finding{row})
	if len(proofs) != 1 || proofs[0].Kind != "browser-execution" {
		t.Fatalf("proofs = %+v, want one browser-execution proof", proofs)
	}
	if !proofs[0].Upgrades {
		t.Error("proof.Upgrades = false: the row this proof came from was not verified")
	}
	findings := []Finding{row}
	applyProofUpgrades(findings, proofs)
	if findings[0].Tier != TierVerified {
		t.Errorf("tier = %v, want verified: the page requested the expression's marker", findings[0].Tier)
	}
	if len(renderer.got) != 1 || renderer.got[0] != target {
		t.Errorf("renderer loaded %v, want the gadget url %q", renderer.got, target)
	}
}

// TestTheShapeLeavesNoEmptyInterpolation is the property the measured shape buys,
// written without naming the constants so that changing them cannot silently
// change the test with them.
//
// The page supplies its own delimiters, so what the engine sees is
// `{{PAYLOAD}}`. An empty expression anywhere in that text aborts Vue 2's render
// (measured: the gadget beside it never runs), and a payload that only nested its
// own interpolation would compile nothing at all. So the test checks the text the
// engine receives: three interpolations, all with an expression, the middle one
// being the engine's own gadget.
func TestTheShapeLeavesNoEmptyInterpolation(t *testing.T) {
	payload, ok := cstiProofPayload(Finding{Module: "csti", Version: "vue2 2.7.16"},
		"http://rr.invalid/rrxe/row")
	if !ok {
		t.Fatal("no gadget for vue2")
	}
	text := "{{" + payload + "}}"
	if strings.Contains(text, "{{}}") {
		t.Errorf("text %q carries an empty interpolation: Vue 2 aborts its render on one, "+
			"so the gadget beside it never runs", text)
	}
	expressions := cstiInterpolations(text)
	if len(expressions) != 3 {
		t.Fatalf("text %q holds %d interpolations, want 3: the page's, the payload's and the "+
			"page's again", text, len(expressions))
	}
	for _, expression := range expressions {
		if strings.TrimSpace(expression) == "" {
			t.Errorf("text %q holds an empty interpolation", text)
		}
	}
	if !strings.Contains(expressions[1], "constructor") {
		t.Errorf("middle interpolation = %q, want the engine's gadget", expressions[1])
	}
	// And the same property for the structural probe: a reader who re-fetches it
	// must see the same shape the browser will compile.
	if text := "{{" + cstiProbe + "}}"; strings.Contains(text, "{{}}") {
		t.Errorf("probe text %q carries an empty interpolation", text)
	}
}

// cstiInterpolations returns every `{{…}}` expression in a text.
func cstiInterpolations(text string) []string {
	var out []string
	for offset := 0; offset < len(text); {
		start := strings.Index(text[offset:], "{{")
		if start < 0 {
			return out
		}
		start += offset
		end := strings.Index(text[start:], "}}")
		if end < 0 {
			return out
		}
		end += start
		out = append(out, text[start+2:end])
		offset = end + 2
	}
	return out
}

// TestTheBrowserStageCoversEveryRegisteredModule. A module added to the registry
// and forgotten in the proof stage produces rows nobody settles and a report that
// says the browser was there; this compares the registry with the stage that
// dispatches on it.
func TestTheBrowserStageCoversEveryRegisteredModule(t *testing.T) {
	for module, provable := range browserProofPayloads {
		if provable == nil {
			t.Errorf("module %q is registered with no payload builder", module)
		}
	}
	// And the count is pinned, because a registry that grows is a claim about new
	// browser-provable modules that has to be made deliberately.
	if len(browserProofPayloads) != 3 {
		t.Errorf("registered modules = %d, want 3: %v", len(browserProofPayloads), browserProofPayloads)
	}
	for _, module := range []string{"xss-escape", "csti", "dom-vectors"} {
		if _, ok := browserProofPayloads[module]; !ok {
			t.Errorf("module %q has no browser proof registered, so its rows are never settled "+
				"in a browser however willing the browser is", module)
		}
	}
}
