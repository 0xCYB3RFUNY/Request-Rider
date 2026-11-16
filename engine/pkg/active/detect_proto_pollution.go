package active

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// ProtoPollution detects the parameter shapes that make a server merge an
// attacker-controlled object into something it later trusts.
//
// The upstream scanner (lonkero `src/scanners/prototype_pollution.rs`, 592 lines)
// sends four families of probes — query, JSON body, path and form — and reads three
// signals off the answer: this run's marker echoed back, a 500 whose message names
// something prototype-shaped, and a 200 that grew a pollution key.
//
// Two of the four families are expressible here and two are not, and the reason is
// worth stating rather than leaving to the reader: this package's request model
// builds a form-encoded body from a harvested surface, so a JSON body is a request
// mode that does not exist here, and the path family is a different URL rather than
// a parameter — the path probes are sent, because a `Point` can carry a different
// path, and the JSON family is recorded as not ported with its reason.
type ProtoPollution struct{}

// Name implements Module.
func (ProtoPollution) Name() string { return "proto-pollution" }

// Level implements Module.
//
// Parameter, like every other injection family here: the query and form probes both
// ride one parameter of a harvested surface.
func (ProtoPollution) Level() Level { return LevelParam }

// ppProbe is one shape from the upstream table.
type ppProbe struct {
	// name is the family the shape belongs to, as upstream names it.
	name string
	// shape is the parameter name, or the path suffix, the shape writes into.
	shape string
	// value is what it writes. A shape that pollutes rather than marks carries the
	// key name and no marker, which is why the answer for those is a behaviour
	// change and not an echo.
	value func(marker string) string
	// inPath is true for the three shapes upstream sends as a path suffix.
	inPath bool
	// behaviourOnly marks the shapes whose effect is a polluted key appearing in the
	// answer rather than this run's marker coming back. They cannot be settled by
	// `Fresh`, and pretending otherwise would report every application that echoes
	// its own query string.
	behaviourOnly bool
}

// ppProbes is upstream's query and path tables, in upstream's order.
//
// The JSON family is absent here and the reason is in `ppNotPorted`; the form family
// upstream sends is the same three shapes with the same keys and is folded into this
// table, because a query parameter and a form field are the same request to a server
// that merges either.
var ppProbes = []ppProbe{
	{"query", "__proto__[polluted]", func(m string) string { return m }, false, false},
	{"query", "__proto__.polluted", func(m string) string { return m }, false, false},
	{"query", "__proto__[toString]", func(string) string { return "polluted" }, false, true},
	{"query", "__proto__[constructor]", func(string) string { return "polluted" }, false, true},
	{"query", "constructor[prototype][polluted]", func(m string) string { return m }, false, false},
	{"query", "constructor.prototype.polluted", func(m string) string { return m }, false, false},
	{"query", "a].__proto__[polluted", func(m string) string { return m }, false, false},
	{"query", "a[__proto__][polluted]", func(m string) string { return m }, false, false},
	{"query", "__proto__%5Bpolluted%5D", func(m string) string { return m }, false, false},
	{"query", "__proto__\\x00[polluted]", func(m string) string { return m }, false, false},
	{"form", "data[__proto__][polluted]", func(m string) string { return m }, false, false},
	{"path", "/__proto__/polluted", func(m string) string { return m }, true, false},
	{"path", "/constructor/prototype/polluted", func(m string) string { return m }, true, false},
	{"path", "/__proto__", func(string) string { return "" }, true, true},
}

// ppNotPorted names what this module does not send, and why.
//
// It is a sentence in the code rather than a line in a report because a reader who
// counts the probes against upstream's four families has to be able to find the
// answer where the probes are.
//
// The JSON family **is** sent (see `ppJSONProbes`), so what remains unported is the
// discovery that feeds it: upstream scans a list of API endpoints it found on the
// page and posts the merge to each, while this package posts to the one surface it
// harvested. A target that only merges on `/api/…` gets no JSON row here, and the
// reason it is not finding that endpoint is stated rather than implied by silence.
const ppNotPorted = "the JSON family is sent, but only to the harvested surface: upstream " +
	"discovers API endpoints on the page and posts the merge to each of them, and this package " +
	"has no API-endpoint discovery, so a target that merges only under /api/… produces no JSON row"

// ppJSONProbes is upstream's JSON table, transcribed.
//
// The bodies are upstream's shapes with this run's marker where upstream writes
// `PAYLOAD`-style values; the two that pollute a built-in carry the key name and
// settle on the behaviour clause rather than on an echo, for the reason the query
// table documents.
var ppJSONProbes = []struct {
	// name is the family label upstream gives the shape.
	name string
	// body carries `%s` for the marker.
	body string
	// behaviourOnly marks the two shapes whose answer is a polluted key rather than
	// this run's own value coming back.
	behaviourOnly bool
}{
	{"json_proto_object", `{"__proto__": {"polluted": "%s"}}`, false},
	{"json_nested_proto", `{"user": {"__proto__": {"isAdmin": true, "marker": "%s"}}}`, false},
	{"json_constructor", `{"constructor": {"prototype": {"polluted": "%s"}}}`, false},
	{"json_array_proto", `[{"__proto__": {"polluted": "%s"}}]`, false},
	{"json_deep_proto", `{"a": {"b": {"__proto__": {"polluted": "%s"}}}}`, false},
}

// ppJSONPoint is where a JSON probe is sent.
//
// Upstream posts to every API endpoint it discovered; this module posts to the
// surface it harvested, which is the one request the run knows is reachable. The
// difference is stated rather than papered over: a surface that ignores a JSON body
// answers with the page it would have sent anyway, and the marker never comes back,
// so the probe costs one request and produces no row.
const ppJSONPoint = "query"

// ppErrorWords are the words upstream looks for in a 500, transcribed from
// `analyze_response`.
//
// They are read only when the *baseline* answered 200, which is the clause upstream
// does not have: a server that answers 500 to everything would otherwise produce a
// prototype-pollution row on every parameter of the site.
var ppErrorWords = []string{
	"prototype", "__proto__", "cannot read property", "undefined is not",
	"typeerror", "object.prototype", "constructor.prototype", "polluted",
}

// ppPollutionKeys are the keys upstream looks for in a 200 answer.
var ppPollutionKeys = []string{`"polluted"`, `"isadmin":true`, `"isadmin": true`}

// Scan probes one surface with the whole table.
func (m ProtoPollution) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	// Upstream skips a target that is neither a single-page application nor
	// injectable. The second half of that rule is the package's own: a surface with
	// no parameter has nothing to write into, and a request that merges query
	// strings into objects is a server with a JSON or form parser at all.
	marker := newCanary("rrpp")
	if marker == "" {
		return nil
	}
	var findings []Finding
	for _, probe := range ppJSONProbes {
		body := strings.ReplaceAll(probe.body, "%s", marker)
		injected, err := t.DoBody(ctx, http.MethodPost, p.URL, []byte(body),
			"application/json", false, nil)
		if err != nil || injected == nil {
			continue
		}
		finding := ppJudge(probe.name, body, probe.behaviourOnly, p, marker, injected, baseline)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	for _, probe := range ppProbes {
		target := p
		if probe.inPath {
			target.URL = strings.TrimRight(p.URL, "/") + probe.shape
		}
		value := probe.value(marker)
		injected, err := t.Fire(ctx, target, probe.shape, value, false, nil)
		if err != nil || injected == nil {
			continue
		}
		// The surface this probe walks is a different URL from the baseline's, so the
		// baseline is fetched for it rather than assumed: a marker already on the
		// page would otherwise make every probe look like an echo.
		reference := baseline
		if probe.inPath {
			if original, err := t.Baseline(ctx, target, false); err == nil && original != nil {
				reference = original
			}
		}
		payload := probe.shape + "=" + probe.value(marker)
		finding := ppJudge(probe.name, payload, probe.behaviourOnly, target, marker,
			injected, reference)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

// ppJudge is `analyze_response`, with the two clauses upstream's lacks.
// The probe arrives as the two strings a finding has to carry rather than as the
// table row it came from: the JSON family's row has no key-path shape at all, and a
// judge that rebuilt the payload from the shape would call a nil builder on it — a
// panic on the third family, found by the test that fires it. The payload is written
// once, by the caller that knows it, and read here.
func ppJudge(name, payload string, behaviourOnly bool, target Point, marker string,
	injected, reference *Response) *Finding {
	body, status := injected.Body, injected.StatusCode
	fact := func(severity Severity, evidence, description string) *Finding {
		finding, _ := NewFinding(Spec{
			Module:   "proto-pollution",
			Title:    fmt.Sprintf("prototype pollution: %s merges a key path", name),
			Claimed:  severity,
			Tier:     TierVerified,
			Point:    target,
			Payload:  payload,
			Evidence: evidence,
			Description: description + " A prototype pollution is only reachable through a merge " +
				"that copies keys it was not asked to copy, so the row names the key path that " +
				"was written rather than a payload on its own.",
			Remediation: "Reject `__proto__`, `constructor` and `prototype` in any key path that " +
				"reaches a recursive merge or a deep clone, and merge into a null-prototype " +
				"object (`Object.create(null)`) where the language allows it. Lodash's " +
				"`merge`, `defaultsDeep` and every hand-written `deepMerge` are the usual place.",
		})
		return &finding
	}
	// Clause one, upstream's strongest: this run's marker came back and was not on the
	// page before.
	if behaviourOnly {
		if status == http.StatusOK && ppAnyKey(body, ppPollutionKeys) {
			return fact(SeverityHigh,
				"the answer grew a pollution key this run's probe writes: "+ppFirstKey(body, ppPollutionKeys),
				"The probe wrote a key the application then read back.")
		}
		return nil
	}
	if Fresh(reference, injected, marker) {
		return fact(SeverityCritical,
			"this run's marker came back in the answer and was not on the page before: "+marker,
			"The probe's own value was reflected, so the key path reached a merge that copied it.")
	}
	// Clause two, upstream's server-error read — and the clause is gated on the
	// baseline answering 200, so a server that fails on everything produces no row
	// here at all.
	if reference != nil && reference.StatusCode == http.StatusOK &&
		status == http.StatusInternalServerError {
		for _, word := range ppErrorWords {
			if strings.Contains(strings.ToLower(body), word) {
				return fact(SeverityHigh,
					"the request failed with "+statusText(status)+" and the message names "+
						quoted(word)+", which the same surface did not do without the probe",
					"The probe made the application fail while naming a prototype-shaped value.")
			}
		}
	}
	return nil
}

// quoted names a word for an evidence sentence, so a message that names `__proto__`
// cannot be read as this sentence's own markup.
func quoted(word string) string { return "`" + word + "`" }

func statusText(status int) string { return fmt.Sprintf("HTTP %d", status) }

func ppAnyKey(body string, keys []string) bool {
	return ppFirstKey(body, keys) != ""
}

func ppFirstKey(body string, keys []string) string {
	lower := strings.ToLower(body)
	for _, key := range keys {
		if strings.Contains(lower, strings.ToLower(key)) {
			return key
		}
	}
	return ""
}
