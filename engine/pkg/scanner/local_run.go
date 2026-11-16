package scanner

// Local template runner: the project's own nuclei.
//
// The binary is not the only way to run a nuclei template, and for a plain
// `http` template it is not even the best way — a template that sends one
// request and matches its response is a pure function of (template, exchange),
// and we already have both halves:
//
//   - `ScorePassiveTemplate` builds the DSL map and runs nuclei's own
//     `pkg/operators`, so the verdict is nuclei's verdict, not a reimplementation;
//   - the engine's `requestTransport()` is the recording transport every other
//     tool uses, so the request lands in History in the order it was sent.
//
// What this deliberately does NOT do: execute `code`, `javascript` or
// `headless` blocks, follow `flow:` chains, or generate payloads. Those need a
// template engine, not a request, and pretending otherwise is how a scanner
// reports a verdict it never earned. Such a template is refused with the reason
// named, exactly as the capability check already does.
//
// One rule from the project applies here and is why the transport is injected
// rather than built: traffic of any tool goes through the same passive proxy.
// A second HTTP client built inside this package would produce a scanner whose
// requests are invisible in History — evidence that does not exist is worse
// than a scan that did not run.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LocalRun is one template executed against one target, with the evidence the
// verdict rests on.
type LocalRun struct {
	// ExtractLists is every value each extracted name matched, in order.
	//
	// Kept beside `Dynamic` because the two answer different questions: a request
	// may only carry a name that matched once, while a `flow:` loop iterates all
	// of them. Merging them would either break iteration or put ambiguous text on
	// the wire.
	ExtractLists map[string][]string
	// Skipped marks a request that could not be built at all: a placeholder in it
	// names a value nothing defines.
	//
	// It is neither a verdict nor a failure. The document's other requests may
	// still produce one — which is what nuclei does, measured on `CVE-2011-4640`
	// — and when none can, the run reports the refusal instead of claiming that
	// a check happened.
	Skipped bool
	// TemplateID, Name and Severity identify the template.
	TemplateID string
	Name       string
	Severity   string
	// Matched is the verdict, computed by nuclei's own operators.
	Matched bool
	// MatcherNames are the matchers that fired.
	MatcherNames []string
	// Extracts are the values the template pulled out of the response.
	Extracts []string
	// SkippedNote says which requests of this block were not sent and why.
	//
	// It is separate from `Reason` because a block that sent two of its three
	// requests and matched is still a match. Folding "something was not sent"
	// into the reason would turn a finding into a refusal, which is the opposite
	// of what happened.
	SkippedNote string
	// Dynamic is the same extractions keyed by the extractor's `name:`, which is
	// what a later request block reads. A name that produced more than one
	// value is absent rather than collapsed — see `singleValuedExtractions`.
	Dynamic map[string]string
	// Request and Response are the raw bytes as they went over the wire, kept
	// because a match is meaningless without the exchange it rests on.
	Request  string
	Response string
	// StatusCode is the response status, or 0 when no response arrived.
	StatusCode int
	// Elapsed is the measured round trip.
	Elapsed time.Duration
	// Reason names why nothing was scored. Empty on a scored template.
	Reason string
}

// baseURLPattern is nuclei's own placeholder for the target.
var baseURLPattern = regexp.MustCompile(`\{\{BaseURL\}\}`)

// hostnamePattern is nuclei's spelling of the target host without scheme.
var hostnamePattern = regexp.MustCompile(`(?i)\{\{Hostname\}\}`)

// RunTemplateLocally sends one template's request to the target and scores the
// response with nuclei's own operators.
//
// `transport` is the engine's recording transport. Passing nil is an error
// rather than a silent fallback to a bare client: a scan that runs outside the
// recording path produces evidence the project cannot show.
func RunTemplateLocally(
	ctx context.Context,
	content string,
	target string,
	transport httpTransport,
) LocalRun {
	if transport == nil {
		return LocalRun{Reason: "no transport: a scan outside the recording proxy would leave no evidence in History"}
	}
	document, capability := parsePassiveDocument(content)
	if document == nil {
		// The parse refused the document and said why. Reading the document
		// anyway is a nil dereference, and dropping the reason would turn a
		// refused template into a crash of the whole scan.
		return LocalRun{Reason: capability.Reason}
	}
	if strings.TrimSpace(document.Flow) != "" {
		return runFlow(ctx, document, target, transport)
	}
	// The passive band's own capability check answers a different question —
	// whether one stored exchange can judge this document — so it is not asked
	// here. This runner makes its own requests, which is exactly what a
	// multi-block document needs, so the question it asks is whether the
	// requests can be built at all.
	if reason := localJudgeability(document, content); reason != "" {
		return LocalRun{Reason: reason}
	}
	requests := allPassiveRequests(document)
	// A document made only of `code:` blocks has no request at all, so it is
	// dispatched here rather than refused below for declaring no path.
	//
	// It used to be dispatched whenever any `code:` block was present, which
	// silently dropped the `http:` blocks of the 14 documents that declare both —
	// measured over the corpus: 953 code-only, 14 with `http:` beside it, 0 with
	// `file:`. Losing 14 requests quietly is the same hole this runner exists to
	// close, so `code:` became a phase after the request phase instead of a
	// replacement for it.
	if len(requests) == 0 && len(document.CodeBlocks) > 0 {
		return runCodeDocument(ctx, document, document.CodeBlocks, target)
	}
	// A document made only of `file:` blocks has no request either; its subject is
	// the local filesystem, and the run's target has to be a local path.
	if len(requests) == 0 && len(document.File) > 0 {
		return runFileDocument(ctx, document, document.File, target)
	}
	// `tcp:` speaks to the target's own host and port rather than through HTTP, so
	// it has no request block either.
	if len(requests) == 0 && len(document.Tcp) > 0 {
		return runTcpDocument(ctx, document, document.Tcp, target)
	}
	if len(requests) == 0 && len(document.JavaScriptBlocks) > 0 {
		return runJavaScriptDocument(ctx, document, document.JavaScriptBlocks, target, nil)
	}
	// `headless:` drives a browser, so it has no request block either.
	if len(requests) == 0 && len(document.HeadlessBlocks) > 0 {
		return runHeadlessDocument(ctx, document, document.HeadlessBlocks, target, nil)
	}
	// A callback address is taken once for the whole document, not once per
	// block: a listener is state on an external service, so asking twice would
	// open two and leave the first to the provider's retention.
	// `variables:` is filled in before anything else, because a request may use a
	// name that no block extracts.
	declared, variablesReason := readVariables(document.Variables)
	if variablesReason != "" {
		return LocalRun{Reason: variablesReason}
	}
	_ = declared

	oast, oastReason := documentOAST(ctx, requests)
	if oastReason != "" {
		return LocalRun{Reason: oastReason}
	}
	for _, request := range requests {
		if len(request.Raw) > 0 {
			continue
		}
		if len(request.Path) == 0 {
			return LocalRun{Reason: "the template declares no path, so there is no request to send"}
		}
	}
	var phase LocalRun
	if len(requests) == 1 && !blockGeneratesRequests(requests[0]) {
		phase = runOneRequest(ctx, document, requests[0], target, transport, mergedValues(declared, oast))
		phase.TemplateID = strings.TrimSpace(document.ID)
		phase.Name = strings.TrimSpace(document.Info.Name)
		phase.Severity = strings.ToUpper(strings.TrimSpace(document.Info.Severity))
		// The script phase runs here too. It used not to, because this path
		// returned straight away — and a document with exactly one `http:` block
		// beside a `code:` or `javascript:` block is the commonest shape there is:
		// the script silently never ran.
		phase = withCodePhase(ctx, document, target, phase, mergedValues(declared, oast))
		return phase
	} else {
		phase = runRequestSequence(ctx, document, target, transport, mergedValues(declared, oast))
	}
	return withCodePhase(ctx, document, target, phase, mergedValues(declared, oast))
}

// withCodePhase runs the `code:` blocks of a document that also made requests.
//
// The order is requests first, then code, and the reason is that a script can read
// a name an earlier block extracted — `{{token}}` from a login, for instance — which
// only resolves if the request already went. This is this project's choice about its
// own order, and it is stated here rather than presented as nuclei's; the corpus's
// 14 mixed documents are what the choice has to be right for.
//
// A request phase that already matched ends the document: a template that found its
// vulnerability does not then run a local script, and a script that fails afterwards
// would otherwise replace a real finding with a local failure.
func withCodePhase(ctx context.Context, document *passiveDocument, target string, phase LocalRun,
	carried map[string]string) LocalRun {
	// A phase that already matched ends the document: a template that found its
	// vulnerability does not then run a local script, and a script that fails
	// afterwards would replace a real finding with a local failure.
	if phase.Matched {
		return phase
	}
	// The script phases run in the order the document declares them, and each is
	// judged on the values the request phase produced.
	//
	// They used to be skipped when the other one was absent — a document with only
	// `javascript:` beside its request ran nothing at all, and said nothing about
	// it. The guard is therefore one condition for both, not two.
	if len(document.CodeBlocks) > 0 {
		code := runCodeDocumentWith(ctx, document, document.CodeBlocks, target, carried)
		phase = mergeScriptPhase(phase, code)
		if phase.Matched {
			return phase
		}
	}
	if len(document.JavaScriptBlocks) > 0 {
		phase = mergeScriptPhase(phase,
			runJavaScriptDocument(ctx, document, document.JavaScriptBlocks, target, phase.Dynamic))
	}
	return phase
}

// mergeScriptPhase folds one local phase's evidence into the run so far.
//
// The transcript of a script is kept: a verdict without the code that produced it is
// not evidence, and a report that shows an HTTP exchange and then a verdict has
// explained nothing.
func mergeScriptPhase(phase LocalRun, script LocalRun) LocalRun {
	phase.Extracts = append(phase.Extracts, script.Extracts...)
	for name, values := range script.ExtractLists {
		phase.ExtractLists[name] = append(phase.ExtractLists[name], values...)
	}
	if script.Request != "" {
		phase.Request += "\n--- local phase\n" + script.Request
	}
	if script.Response != "" {
		phase.Response += "\n--- local phase\n" + script.Response
	}
	if script.Matched {
		phase.Matched = true
		phase.MatcherNames = script.MatcherNames
		phase.Reason = ""
		phase.Skipped = false
		return phase
	}
	if script.Reason != "" {
		// Only joined when the request phase actually said something. Otherwise the
		// reason begins with "; …", which reads as a missing first half.
		if phase.Reason == "" {
			phase.Reason = script.Reason
			phase.Skipped = script.Skipped
		} else {
			phase.Reason += "; then " + script.Reason
		}
	}
	return phase
}

// runOneRequest sends one request block to the target and scores the response.
// It is shared by the single-request path and by a flow step, so a step of a
// flow and a plain template are judged by exactly the same code.
// dynamic carries what earlier blocks of the same template extracted, so a
// later block can read `{{token}}` and a matcher can read `template["token"]`.
// nil means the document has only this one request.
func runOneRequest(ctx context.Context, document *passiveDocument, request passiveRequest, target string, transport httpTransport, dynamic map[string]string) LocalRun {
	// Every request in a document passes through here, single-block or chained,
	// so this is the one place that decides whether a placeholder can be
	// substituted. Checked here and not before the run, because whether
	// `{{token}}` is known depends on whether an earlier block extracted it.
	if len(request.Path) > 0 {
		usable, dropped := usablePaths(request, dynamic)
		if len(usable) == 0 {
			return LocalRun{Skipped: true, Reason: dropped}
		}
		request.Path = usable
	}
	parsedTarget, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsedTarget.Host == "" || (parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https") {
		return LocalRun{Reason: fmt.Sprintf("target %q must be an absolute http or https URL", target)}
	}
	run := LocalRun{}
	started := time.Now()
	if len(request.Raw) > 0 {
		usable, dropped := usableRaw(request, dynamic)
		if len(usable) == 0 {
			// Nothing could be built. That is not a verdict and not a match: it is
			// the document saying it could not ask its question.
			return LocalRun{Skipped: true, Reason: dropped}
		}
		request.Raw = usable
		run := runRawRequest(ctx, document, request, target, transport, dynamic)
		if dropped != "" {
			// The note is separate from `Reason` on purpose: a block that sent two
			// of three requests and matched is still a match, so folding "something
			// was not sent" into the reason would turn a finding into a refusal.
			run.SkippedNote = dropped
		}
		return run
	}
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		method = http.MethodGet
	}
	var lastReason string
	for _, path := range request.Path {
		requestURL := expandDynamic(path, parsedTarget, dynamic)
		absolute, parseErr := url.Parse(requestURL)
		if parseErr != nil || absolute.Host == "" {
			lastReason = fmt.Sprintf("path %q does not resolve to an absolute URL for the target", path)
			continue
		}
		body := strings.NewReader(expandDynamic(request.Body, parsedTarget, dynamic))
		httpRequest, buildErr := http.NewRequestWithContext(ctx, method, absolute.String(), body)
		if buildErr != nil {
			lastReason = "cannot build the request: " + oneLine(buildErr.Error())
			continue
		}
		for name, value := range request.Headers {
			// `Content-Length` belongs to whoever writes the body. A template
			// that spells it out while sending none makes Go's transport refuse
			// the request outright — `http: ContentLength=55 with Body length 0`
			// — which was measured on 40 of 4 000 templates and would otherwise
			// read as a target that refused to answer.
			if strings.EqualFold(name, "Content-Length") {
				continue
			}
			httpRequest.Header.Set(name, expandDynamic(value, parsedTarget, dynamic))
		}
		if httpRequest.Header.Get("User-Agent") == "" {
			httpRequest.Header.Set("User-Agent", "RequestRider")
		}
		httpRequest.Header.Set("Accept-Encoding", "identity")

		response, doErr := transport.RoundTrip(httpRequest)
		if doErr != nil {
			lastReason = "request failed: " + oneLine(doErr.Error())
			continue
		}
		payload, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			lastReason = "cannot read the response: " + oneLine(readErr.Error())
			continue
		}
		elapsed := time.Since(started)
		run.Elapsed = elapsed
		run.StatusCode = response.StatusCode
		run.Response = localRawResponse(response, payload)
		run.Request = localRawRequest(method, absolute, httpRequest, request.Body)

		exchange := PassiveExchange{
			Method:      method,
			URL:         absolute.String(),
			Host:        parsedTarget.Scheme + "://" + parsedTarget.Host,
			RawRequest:  run.Request,
			RawResponse: run.Response,
			StatusCode:  response.StatusCode,
			Body:        string(payload),
			Header:      response.Header.Clone(),
			Duration:    elapsed,
			// A stored response carries the length the server sent; -1 is
			// nuclei's spelling of "the header was absent", and the DSL map
			// falls back to the body length.
			ContentLength: response.ContentLength,
			Dynamic:       dynamic,
		}
		verdict := scoreCompiled(document, request, exchange)
		run.Matched = verdict.Matched
		run.MatcherNames = verdict.MatcherNames
		run.Extracts = verdict.Extracts
		run.Dynamic = verdict.Dynamic
		run.ExtractLists = verdict.ExtractLists
		// An `interactsh-url` template has no response matcher to satisfy: its
		// answer is whether the target called the address this request named. That
		// can only be known after the request went out, so it is asked here and
		// nowhere earlier.
		if hit, hitErr := settleOAST(ctx, request, dynamic); hitErr != "" {
			run.Reason = hitErr
			return run
		} else if hit {
			run.Matched = true
			run.Dynamic = withOASTHit(run.Dynamic)
		}
		return run
	}
	run.Reason = lastReason
	if run.Reason == "" {
		run.Reason = "the template produced no request that reached the target"
	}
	return run
}

// scoreCompiled runs one already-parsed request block against an exchange.
// Split out from ScorePassiveTemplate so the local runner does not re-parse the
// document it just parsed, which is the same double-decode cost the capability
// check already paid once.
func scoreCompiled(document *passiveDocument, request passiveRequest, exchange PassiveExchange) PassiveMatch {
	block := request
	if err := block.Compile(); err != nil {
		return PassiveMatch{Reason: "nuclei cannot compile this template's operators: " + oneLine(err.Error())}
	}
	data := responseToDSLMap(exchange, document.ID, document.ID)
	result, matched := block.Execute(data, passiveMatchFunc, passiveExtractFunc, false)
	if result == nil {
		// `Execute` returns a nil result when nothing matched and nothing was
		// output, and the extracts went with it. That is fatal for this project's
		// chains: a step whose job is to *produce* a value for the next one reports
		// no finding, and the next one then has nothing to substitute.
		//
		// Measured: a block whose matcher looked for an absent word extracted
		// nothing at all — `dynamic=map[] lists=map[]` — and the document silently
		// reported a negative for a check it could not make.
		//
		// So the extracts are taken here, with the same callback `Execute` was given.
		// There is no second extractor: `passiveExtractFunc` is nuclei's own, called
		// by us instead of by the loop we did not get to see.
		lists := extractWithoutMatch(block, data)
		// The single-valued map as well: without it the next block has nothing to
		// substitute and the extract is invisible exactly where it was needed.
		return PassiveMatch{ExtractLists: lists, Dynamic: singleValuedExtractions(lists)}
	}
	verdict := PassiveMatch{}
	// Extractors are read whether the matcher matched or not, because a flow's
	// whole point is to walk what a step found on its way to a later request:
	// `for (let p of iterate(template["matchedpath"]))` consumes the output of a
	// step that reported no finding at all.
	//
	// It used to return early on `!matched` and drop them, so a detection step
	// that succeeded in finding the path and failed its matcher handed the next
	// statement an empty list — and the flow then reported a negative for a branch
	// it never took.
	// A matcher marked `internal: true` is a means, not a finding, and it must not
	// put the template's name on the report.
	//
	// Measured against nuclei v3.11.1 on a template whose only matcher is an
	// internal one carrying a `name:`:
	//
	//	nuclei -ms …  →  [internal-capture-probe] [failed]
	//
	// and this runner reported a match — a false positive produced by the very
	// change that made 366 flow templates runnable. `operators.Execute` keeps an
	// internal matcher in `result.Matches`, and the protocol layer is what drops it
	// from the output; that layer is not imported here, so the filter is applied
	// where the verdict is built.
	if matched && !onlyInternalMatchers(block) {
		verdict.Matched = true
		verdict.MatcherNames = sortedKeys(nonInternalMatches(block, result.Matches))
		verdict.Extracts = append(verdict.Extracts, result.OutputExtracts...)
	}
	verdict.Dynamic = singleValuedExtractions(result.Extracts)
	verdict.ExtractLists = result.Extracts
	// A matcher with a `name:` and `internal: true` is how a large part of the
	// corpus captures a value: it is written as a matcher because that is the
	// shape the value comes from, and `internal: true` is what hides it from the
	// output.
	//
	// nuclei does this on the protocol layer (`pkg/protocols/http`), which this
	// project does not import — it imports the narrow `pkg/operators` rung. So the
	// capture is done here, against the very same data the matchers were scored on.
	// Measured on a 700-template `flow:` sample: 366 refusals, every one of them a
	// raw block carrying `{{token}}` that nothing had produced, because the value
	// lived in an internal matcher and nowhere else.
	//
	// These matches are deliberately not part of the verdict: `internal: true`
	// means the matcher is a means, not a finding, and reporting it as one would
	// turn every capture into a false positive.
	for name, values := range internalMatcherCaptures(block, data) {
		verdict.ExtractLists[name] = append(verdict.ExtractLists[name], values...)
	}
	verdict.Dynamic = singleValuedExtractions(verdict.ExtractLists)
	return verdict
}

// internalMatcherCaptures runs the block's own named internal matchers and returns
// what each captured.
//
// It reuses `passiveMatchFunc`, so a capture is exactly what the same matcher would
// have matched — there is no second implementation of word, regex, dsl or status
// matching to drift from the first.
func internalMatcherCaptures(block passiveRequest, data map[string]interface{}) map[string][]string {
	captured := map[string][]string{}
	for _, matcher := range block.Matchers {
		if matcher.Name == "" || !matcher.Internal {
			continue
		}
		matched, values := passiveMatchFunc(data, matcher)
		if !matched || len(values) == 0 {
			continue
		}
		captured[matcher.Name] = append(captured[matcher.Name], values...)
	}
	if len(captured) == 0 {
		return nil
	}
	return captured
}

// singleValuedExtractions keeps the names that produced exactly one value.
//
// A name that matched several times is dropped rather than collapsed: joining
// them with a comma would put text on the wire that the template never wrote,
// and picking the first would pick arbitrarily. The chain then refuses that
// block by name, which is a state the operator can see.
func singleValuedExtractions(extracts map[string][]string) map[string]string {
	if len(extracts) == 0 {
		return nil
	}
	out := make(map[string]string, len(extracts))
	for name, values := range extracts {
		if len(values) != 1 {
			continue
		}
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		out[trimmed] = values[0]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// localExpandPath substitutes nuclei's target placeholders. Only the two that
// identify the target are handled: the rest (`{{randstr}}`, `{{interactsh-url}}`,
// fuzzing markers) mean the template generates something this runner does not
// generate, and silently leaving them in place would send a literal
// `{{randstr}}` to the target and call the answer a verdict.
func localExpandPath(value string, target *url.URL) string {
	replaced := baseURLPattern.ReplaceAllString(value, strings.TrimSuffix(target.String(), "/"))
	replaced = hostnamePattern.ReplaceAllString(replaced, target.Host)
	return replaced
}

// localRawRequest renders the request as it went on the wire, which is what the
// DSL variable `request` resolves to and what the report shows as evidence.
func localRawRequest(method string, target *url.URL, request *http.Request, body string) string {
	var builder strings.Builder
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&builder, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&builder, "Host: %s\r\n", request.Host)
	// Header order is sorted so two runs of one template render identically and
	// two reports can be compared by eye.
	names := make([]string, 0, len(request.Header))
	for name := range request.Header {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		for _, value := range request.Header[name] {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	builder.WriteString("\r\n")
	builder.WriteString(body)
	return builder.String()
}

// localRawResponse renders the response as it came off the wire.
func localRawResponse(response *http.Response, payload []byte) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %s\r\n", response.Status)
	names := make([]string, 0, len(response.Header))
	for name := range response.Header {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		for _, value := range response.Header[name] {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	builder.WriteString("\r\n")
	builder.Write(payload)
	return builder.String()
}

// sortStrings sorts in place; a tiny helper keeps the two renderers above from
// each carrying its own copy of the same three lines.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// onlyInternalMatchers reports whether the block has no matcher a reader may see.
//
// This is the rule, and it was measured rather than assumed: nuclei on a document
// whose only matcher is `internal: true` prints `[failed]`, so a block made purely
// of internal matchers produces no finding however well it matched.
//
// It could not be decided by filtering `result.Matches` — in this rung `Execute`
// returns `matched: true` with an **empty** matches map, so "drop the internal
// names" left nothing and silently turned every real code-block finding into a
// negative. Two `code:` tests caught it.
func onlyInternalMatchers(block passiveRequest) bool {
	if len(block.Matchers) == 0 {
		return false
	}
	for _, matcher := range block.Matchers {
		if !matcher.Internal {
			return false
		}
	}
	return true
}

// nonInternalMatches drops the names that came from `internal: true` matchers, so a
// document that mixes both kinds does not name the internal one in its report.
func nonInternalMatches(block passiveRequest, matches map[string][]string) map[string][]string {
	internal := map[string]bool{}
	for _, matcher := range block.Matchers {
		if matcher.Internal && matcher.Name != "" {
			internal[matcher.Name] = true
		}
	}
	if len(internal) == 0 {
		return matches
	}
	finding := make(map[string][]string, len(matches))
	for name, values := range matches {
		if internal[name] {
			continue
		}
		finding[name] = values
	}
	if len(finding) == 0 {
		return nil
	}
	return finding
}

// extractWithoutMatch collects a block's extractions when no matcher matched.
//
// It mirrors what nuclei does inside `Execute` for the case where it does return a
// result: a named, non-internal extractor fills the extraction list, an internal one
// is a dynamic value, and either way the name is written back into the data so a
// later matcher or extractor in the same block can read it.
func extractWithoutMatch(block passiveRequest, data map[string]interface{}) map[string][]string {
	collected := map[string][]string{}
	if len(block.Extractors) == 0 {
		return collected
	}
	working := make(map[string]interface{}, len(data))
	for name, value := range data {
		working[name] = value
	}
	for _, extractor := range block.Extractors {
		// nuclei's extractor callback answers a set, not an ordered slice, so the
		// order inside one extractor's own output is not this project's to promise.
		// What it does promise is the set, and that is what a request may carry.
		found := passiveExtractFunc(working, extractor)
		if len(found) == 0 {
			continue
		}
		values := make([]string, 0, len(found))
		for value := range found {
			values = append(values, value)
		}
		sort.Strings(values)
		if extractor.Name != "" && !extractor.Internal {
			collected[extractor.Name] = append(collected[extractor.Name], values...)
		}
		if extractor.Name != "" {
			working[extractor.Name] = values[len(values)-1]
		}
	}
	return collected
}
