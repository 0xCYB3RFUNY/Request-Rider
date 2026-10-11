package bypass

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"intruder/engine/pkg/intruder"
)

// # The fixture, and why it is shaped this way
//
// A bypass form is proven by a target that refuses one request and serves
// another. The obvious fixture — a handler that recognises each shape by name —
// proves nothing, because it would serve a form whose rewrite sends something
// other than what the form claims.
//
// So this fixture refuses a *shape*: the set of every property a form may change,
// and nothing else. Go's client adds `User-Agent`, `Accept` and `Accept-Encoding`
// to every request, so a signature built from those would not match the plain
// request the test builds by hand and the server would answer `200` to
// everything. The signature is therefore built from the method, the escaped
// path, the protocol major version, whether a body was sent, and exactly the
// headers a form adds.
//
// The consequence is the property the whole suite rests on: a form whose
// `Rewrite` returns the request unchanged produces the plain shape, is refused,
// and fails its own subtest. There is no way for a broken form to be green here.

var watchedHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "Client-IP", "X-Forwarded-Host",
	"X-Forwarded-Proto", "X-Remote-Addr", "Forwarded",
	"X-Original-URL", "X-Rewrite-URL", "Referer",
	// The families added after the first fixture: a form that changes
	// something the signature does not name is a form the fixture cannot tell
	// apart from the plain request, and it would be reported as one that never
	// worked for a reason that belongs to the test rather than to the code.
	//
	// `Connection` used to be here for the `strip-*` forms. It is not any more:
	// HTTP/2 forbids that header, so those forms left the ladder and nothing in
	// it carries the header. Leaving the name in would be dead configuration that
	// still reads as if a form depended on it.
	"X-HTTP-Method-Override", "X-Method-Override",
}

// shape is everything a form is allowed to change, and nothing else.
func shape(req *http.Request) string {
	parts := make([]string, 0, len(watchedHeaders)+4)
	parts = append(parts, req.Method, req.URL.EscapedPath(), strconv.Itoa(req.ProtoMajor))
	if req.ContentLength > 0 {
		parts = append(parts, "body="+strconv.FormatInt(req.ContentLength, 10))
	}
	for _, name := range watchedHeaders {
		parts = append(parts, name+"="+req.Header.Get(name))
	}
	return strings.Join(parts, "|")
}

// mustRequest builds the plain request the fixture refuses.
func mustRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", rawURL, err)
	}
	return req
}

// refuse builds a target that answers 403 to the listed shapes and serves every
// other one.
//
// The set is built after the server starts, because the plain request needs the
// server's own address. A `sync.Mutex` guards it: the driver sends concurrently
// only when a caller makes it, but a fixture that is not safe to read while a
// test writes to it is a fixture that fails for a reason unrelated to the code.
func refuse(t *testing.T) (*httptest.Server, *shapeSet) {
	t.Helper()
	shapes := &shapeSet{set: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shapes.has(shape(r)) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>the resource</body></html>"))
	}))
	t.Cleanup(server.Close)
	return server, shapes
}

type shapeSet struct {
	mu  sync.Mutex
	set map[string]bool
}

func (s *shapeSet) add(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set[value] = true
}

func (s *shapeSet) has(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set[value]
}

func (s *shapeSet) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.set)
}

// resourcePath is the URL every form applies to.
//
// It has ten segments and a server-side extension, so the verb forms, all six
// path forms, the double-encoded form, all eight segment forms and every header
// form have something to change. The segment count is the reason it is this long:
// a form that had nothing to do with this path would be reported as "skipped",
// which is a different statement from "works", and eight shorter would leave six
// of the thirty-one subtests asserting nothing at all.
const resourcePath = "/one/two/three/four/five/six/seven/eight/nine/admin/memory_info.jsp"

// TestEveryFormReachesAResourceThePlainRequestIsRefused is the core proof, one
// subtest per form.
//
// Each subtest selects exactly one form, so the walk has nothing else to fall
// back on: if the form does not reach the resource, the walk reports nothing and
// the subtest fails with the form's own name in the message.
func TestEveryFormReachesAResourceThePlainRequestIsRefused(t *testing.T) {
	server, shapes := refuse(t)
	target := server.URL + resourcePath
	shapes.add(shape(mustRequest(t, target)))

	names := Forms()
	if len(names) == 0 {
		t.Fatal("the ladder is empty, so nothing can be proven about it")
	}

	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			req := mustRequest(t, target)
			if len(Candidates(req, []string{name})) == 0 {
				t.Fatalf("form %q produced no request for %s, so the walk never asks it", name, resourcePath)
			}
			driver := New([]string{name})
			resp, attempt, err := driver.Attempt(context.Background(), server.Client(), req)
			if err != nil {
				t.Fatalf("attempt: %v", err)
			}
			if resp == nil {
				t.Fatal("Attempt returned no response and no error")
			}
			defer resp.Body.Close()
			if attempt.SucceededBy != name {
				t.Fatalf("form %q did not reach the resource: SucceededBy=%q, %d request(s), status %d, tried %+v",
					name, attempt.SucceededBy, attempt.Requests(), resp.StatusCode, attempt.Tried)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("form %q reported success with status %d", name, resp.StatusCode)
			}
			if attempt.Requests() != 2 {
				t.Fatalf("form %q took %d requests, want exactly the refused one and the form's own",
					name, attempt.Requests())
			}
		})
	}
}

// TestNoFormRewritesIntoThePlainRequest says where a broken form breaks, rather
// than only that it did.
//
// The subtest above proves each form reaches the resource. This one proves the
// reason: a form whose rewrite is a no-op produces the plain shape, and naming
// that at the rewrite turns "the walk failed" into "this form changes nothing".
func TestNoFormRewritesIntoThePlainRequest(t *testing.T) {
	req := mustRequest(t, "http://127.0.0.1"+resourcePath)
	before := shape(req)
	for _, form := range Ladder() {
		rewritten, ok := form.Rewrite(req)
		if !ok {
			continue
		}
		if shape(rewritten) == before {
			t.Errorf("form %q rewrote the request into the plain shape, so it asks the target again", form.Name)
		}
	}
}

// TestARefusalEveryFormSharesIsStillARefusal is the negative case, and it is the
// one that keeps the package honest.
//
// A walk that answered with the last form's refusal instead of the original 403
// would report a refused resource as one it had reached. A walk that reported a
// form as successful when every form was refused would claim coverage of a
// resource it never got.
func TestARefusalEveryFormSharesIsStillARefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	driver := New(nil)
	resp, attempt, err := driver.Attempt(context.Background(), server.Client(),
		mustRequest(t, server.URL+resourcePath))
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("the walk answered %d where the target refuses everything, want the original 403", resp.StatusCode)
	}
	if attempt.Bypassed() {
		t.Errorf("the walk reported form %q as reaching a resource that refused every form", attempt.SucceededBy)
	}
	if attempt.Tried == nil {
		t.Error("the walk recorded no attempt at all, so the report could not say what was tried")
	}
	t.Logf("%d requests spent, %d forms tried, none reached", attempt.Requests(), len(attempt.Tried))
}

// TestAnEmptySelectionSendsTheOriginalRequestOnly separates the two readings of
// an empty list.
//
// `nil` means "every form". An empty, non-nil list means "the operator selected
// nothing". Reading them the same way would make an empty selection behave like
// a full one, which is the difference between spending one request and spending
// twenty-four.
func TestAnEmptySelectionSendsTheOriginalRequestOnly(t *testing.T) {
	server, shapes := refuse(t)
	target := server.URL + resourcePath
	shapes.add(shape(mustRequest(t, target)))

	driver := New([]string{})
	resp, attempt, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, target))
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()
	if attempt.Requests() != 1 {
		t.Errorf("an empty selection spent %d requests, want the refused one only", attempt.Requests())
	}
	if len(attempt.Tried) != 0 {
		t.Errorf("an empty selection tried %d form(s): %+v", len(attempt.Tried), attempt.Tried)
	}
	if attempt.Bypassed() {
		t.Error("an empty selection reported a bypass, which it cannot have asked for")
	}
}

// TestANilSelectionWalksTheWholeLadder is the other half of the same pair.
func TestANilSelectionWalksTheWholeLadder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	driver := New(nil)
	resp, attempt, err := driver.Attempt(context.Background(), server.Client(),
		mustRequest(t, server.URL+resourcePath))
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()
	// Every form in the ladder applies to this path, and the ladder is what the
	// walk sends. It is deliberately *not* compared against `Candidates`: that
	// list walks every segment position of the path while the ladder carries a
	// fixed number of them, so on a path with eleven segments `Candidates` names
	// three more forms than the driver will ever ask. That divergence is the
	// point of the two functions and it is asserted by
	// `TestEverySegmentOfALongPathGetsItsOwnCandidate`.
	want := len(Forms())
	if len(attempt.Tried) != want {
		t.Errorf("a nil selection tried %d form(s), want every one of the %d the ladder carries: %+v",
			len(attempt.Tried), want, attempt.Tried)
	}
}

// TestTheFormThatWorkedIsAskedFirstNextTime is what the driver remembers, and
// the reason it exists.
//
// The second attempt costs one request rather than a refusal plus a walk. It is
// also the reason the learned form *replaces* the original instead of being
// appended after it: a form is the shape that reached the resource, so asking
// for the plain shape first would spend the refusal that made the walk necessary.
func TestTheFormThatWorkedIsAskedFirstNextTime(t *testing.T) {
	server, shapes := refuse(t)
	target := server.URL + resourcePath
	shapes.add(shape(mustRequest(t, target)))

	driver := New([]string{"verb-post"})
	first, firstAttempt, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, target))
	if err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	first.Body.Close()
	if firstAttempt.SucceededBy != "verb-post" {
		t.Fatalf("the first attempt reported %q", firstAttempt.SucceededBy)
	}

	second, secondAttempt, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, target))
	if err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	defer second.Body.Close()
	if secondAttempt.Requests() != 1 {
		t.Errorf("the second attempt spent %d requests, want the learned form alone", secondAttempt.Requests())
	}
	if len(secondAttempt.Tried) != 0 {
		t.Errorf("the second attempt walked the ladder anyway: %+v", secondAttempt.Tried)
	}
	if secondAttempt.SucceededBy != "verb-post" {
		t.Errorf("the second attempt reported %q, want the learned form", secondAttempt.SucceededBy)
	}
	if driver.LearnedForm(http.MethodGet, target) != "verb-post" {
		t.Error("the driver did not remember the form that worked")
	}
}

// TestForgettingDropsWhatWasLearned is the route generation's half of the
// contract.
//
// `Apply route` opens a new generation, and a form that reached a resource on the
// previous route says nothing about the next one. Without this, a driver would
// keep applying an old answer to a new network path.
func TestForgettingDropsWhatWasLearned(t *testing.T) {
	server, shapes := refuse(t)
	target := server.URL + resourcePath
	shapes.add(shape(mustRequest(t, target)))

	driver := New([]string{"verb-post"})
	resp, attempt, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, target))
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	resp.Body.Close()
	if !attempt.Bypassed() {
		t.Fatal("nothing was learned, so there is nothing to forget")
	}

	driver.Forget()
	if learned := driver.LearnedForm(http.MethodGet, target); learned != "" {
		t.Errorf("the driver still remembers %q after Forget", learned)
	}
	after, afterAttempt, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, target))
	if err != nil {
		t.Fatalf("attempt after Forget: %v", err)
	}
	defer after.Body.Close()
	if afterAttempt.Requests() == 1 {
		t.Error("after Forget the attempt cost one request, so the learned form was still applied")
	}
}

// TestWhatWasLearnedIsNotAppliedToAnotherResource keeps the learning narrow.
//
// The key is method, host and path. A form that reached `/admin` on a host says
// nothing about `/api` on that same host: the filter that refused the second is a
// different filter, and applying the first answer to it is a request shaped for
// one page sent to another.
func TestWhatWasLearnedIsNotAppliedToAnotherResource(t *testing.T) {
	server, shapes := refuse(t)
	admin := server.URL + "/admin/memory_info.jsp"
	api := server.URL + "/api/v1/records.jsp"
	shapes.add(shape(mustRequest(t, admin)))
	shapes.add(shape(mustRequest(t, api)))

	driver := New(nil)
	resp, first, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, admin))
	if err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	resp.Body.Close()
	if !first.Bypassed() {
		t.Fatal("nothing was learned from /admin")
	}

	_, second, err := driver.Attempt(context.Background(), server.Client(), mustRequest(t, api))
	if err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if second.Requests() == 1 {
		t.Error("/api was answered on its first request, so /admin's learned form was applied to it")
	}
	if len(shapes.set) != 2 {
		t.Errorf("the fixture refused %d shapes, want the two plain ones", shapes.count())
	}
}

// TestTheEncodedSeparatorIsSentEncodedNotDoubled is the regression guard for the
// detail this package was most likely to get wrong.
//
// `url.URL.String()` escapes a `%` in `Path` back to `%25`. A form that wrote
// `%3b` into `Path` would therefore put `%253b` on the wire — a doubly encoded
// separator, which is a different request and would look like the form did
// nothing.
func TestTheEncodedSeparatorIsSentEncodedNotDoubled(t *testing.T) {
	req := mustRequest(t, "http://127.0.0.1/admin/memory_info.jsp")
	rewritten, ok := rewriteVia(t, "path-encoded-semicolon", req)
	if !ok {
		t.Fatal("path-encoded-semicolon produced no request for this path")
	}
	sent := rewritten.URL.EscapedPath()
	if sent != "/admin/memory_info.jsp%3b" {
		t.Errorf("the wire carries %q, want the separator encoded once", sent)
	}
	if strings.Contains(sent, "%253b") {
		t.Errorf("the separator was encoded twice: %q", sent)
	}
}

// TestTheDoubleEncodedFormIsWhatTheIntruderEncoderProduces is the anti-drift
// guard between this package and the Intruder.
//
// The bypass asks the project's own encoder to encode twice rather than writing
// its own second round. That is the point of using it, and the test is what keeps
// the two from answering "what does double-encoding produce" differently.
func TestTheDoubleEncodedFormIsWhatTheIntruderEncoderProduces(t *testing.T) {
	const path = "/admin/memory_info.jsp"
	req := mustRequest(t, "http://127.0.0.1"+path)
	rewritten, ok := rewriteVia(t, "path-double-encoded", req)
	if !ok {
		t.Fatal("path-double-encoded produced no request for this path")
	}
	// The expectation is the project's own encoder applied to everything but the
	// leading separator, which is the rule the form implements. Encoding the slash
	// as well would produce a request target with no leading `/`, and a server
	// answers that with 400 — which this package counts as a refusal, so the test
	// that failed to catch it was the one asserting the bypass had succeeded.
	encoded, err := intruder.TransformPayload(strings.TrimPrefix(path, "/"), doubleEncode())
	if err != nil {
		t.Fatalf("the Intruder encoder failed: %v", err)
	}
	want := "/" + encoded
	if got := rewritten.URL.EscapedPath(); got != want {
		t.Errorf("the bypass sent %q, the Intruder's own encoder produces %q", got, want)
	}
	if !strings.Contains(rewritten.URL.EscapedPath(), "%25") {
		t.Error("nothing was encoded, so this is not the double-encoded form")
	}
	if !strings.HasPrefix(rewritten.URL.EscapedPath(), "/") {
		t.Errorf("the request target %q has no leading separator, so no server can route it",
			rewritten.URL.EscapedPath())
	}
}

// TestFormNamesAreUnique guards the identifier the attempt record is keyed by.
//
// Two forms sharing a name would make `SucceededBy` ambiguous, and the learned
// form's name would select both or neither depending on which came first.
func TestFormNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range Forms() {
		if seen[name] {
			t.Errorf("form %q appears twice in the ladder", name)
		}
		seen[name] = true
	}
}

// TestTheLadderOrderIsVerbsThenPathsThenHeaders is the cost contract.
//
// Every form is a real request against a real target, so the order decides how
// many requests a refusal costs. Verbs first because they change nothing about
// the target being asked for; paths next because that is what a filter chain
// actually matches on; headers last because they change who is asking rather
// than what.
func TestTheLadderOrderIsVerbsThenPathsThenHeaders(t *testing.T) {
	group := func(name string) int {
		switch {
		case strings.HasPrefix(name, "verb-"):
			return 0
		// `encoded-traversal-` is a path form whose name does not start with
		// `path-`, so it has to be named here. Left to the default it landed in
		// the trailing group and the ladder failed its own ordering rule.
		case strings.HasPrefix(name, "path-"), strings.HasPrefix(name, "encoded-traversal-"):
			return 1
		case strings.HasPrefix(name, "header-"):
			return 2
		default:
			return 3
		}
	}
	names := Forms()
	last := -1
	for _, name := range names {
		current := group(name)
		if current < last {
			t.Errorf("form %q (group %d) comes after a form of group %d: %v", name, current, last, names)
		}
		last = current
	}
	if group(names[0]) != 0 {
		t.Errorf("the ladder starts with a %s form, want a verb form", []string{"path", "header"}[group(names[0])])
	}
}

// TestEverySegmentOfALongPathGetsItsOwnCandidate is the PortSwigger permutation,
// and the place the ladder and the candidate list are allowed to disagree.
//
// The ladder carries a fixed number of segment forms; `Candidates` walks every
// position of the path it is given. A path with more segments than the ladder has
// forms must still get a candidate for each, because a filter that normalises one
// segment is not one that normalises all of them.
func TestEverySegmentOfALongPathGetsItsOwnCandidate(t *testing.T) {
	const path = "/a/b/c/d/e/f/g/h/i/j/k"
	req := mustRequest(t, "http://127.0.0.1"+path)

	segments := len(splitPath(path))
	before, after := 0, 0
	for _, name := range Forms() {
		switch {
		case name == "path-segment-lead":
			// Counted separately: it starts with the same prefix but names no
			// position, so counting it as one would make the ladder look like it
			// walks a ninth segment.
		case strings.HasPrefix(name, "path-segment-after-"):
			after++
		case strings.HasPrefix(name, "path-segment-"):
			before++
		}
	}
	if before != segmentPositionLimit || after != segmentPositionLimit {
		t.Errorf("the ladder carries %d before-slash and %d after-slash segment forms, want %d of each",
			before, after, segmentPositionLimit)
	}

	got := map[string]bool{}
	for _, candidate := range Candidates(req, nil) {
		got[candidate.Form] = true
	}
	for position := 0; position < segments; position++ {
		// Both placements, at every position, ladder-limited or not: the two
		// shapes are different requests and a report that shows only one of
		// them reads as if the other was never tried.
		for _, name := range []string{
			SegmentFormName(position),
			"path-segment-after-" + strconv.Itoa(position+1),
		} {
			if !got[name] {
				t.Errorf("no candidate for position %d of %d (%q), want one", position, segments, name)
			}
		}
	}
}

// TestCandidatesFollowTheOperatorsSelection reads the selection from both sides,
// because a form that ignored it would walk forms the operator turned off — and
// each of those is a request against a real target.
func TestCandidatesFollowTheOperatorsSelection(t *testing.T) {
	req := mustRequest(t, "http://127.0.0.1"+resourcePath)

	all := Candidates(req, nil)
	chosen := Candidates(req, []string{"verb-post", "header-forwarded-for"})
	if len(chosen) != 2 {
		t.Fatalf("selecting two forms produced %d candidates: %+v", len(chosen), chosen)
	}
	for _, candidate := range chosen {
		if candidate.Form != "verb-post" && candidate.Form != "header-forwarded-for" {
			t.Errorf("form %q was asked for but not selected", candidate.Form)
		}
	}
	if len(all) <= len(chosen) {
		t.Errorf("a nil selection produced %d candidates and a two-form selection %d; the first must be the larger",
			len(all), len(chosen))
	}
	if len(Candidates(req, []string{})) != 0 {
		t.Error("an empty selection produced candidates, want none")
	}
}

// TestAttemptRefusesToRunWithoutARequestOrClient keeps the driver from inventing
// a transport.
//
// The client is the caller's because it holds the recording transport; a driver
// that built its own would produce exchanges that never reach History, and an
// unrecorded exchange is worse than a missing one.
func TestAttemptRefusesToRunWithoutARequestOrClient(t *testing.T) {
	driver := New(nil)
	if _, _, err := driver.Attempt(context.Background(), nil, nil); err == nil {
		t.Error("Attempt(nil, nil) succeeded, want an error rather than a guess")
	}
	req := mustRequest(t, "http://127.0.0.1"+resourcePath)
	if _, _, err := driver.Attempt(context.Background(), nil, req); err == nil {
		t.Error("Attempt with no client succeeded, want an error rather than a default client")
	}
}

// rewriteVia runs one form and returns what it produced.
func rewriteVia(t *testing.T, name string, req *http.Request) (*http.Request, bool) {
	t.Helper()
	for _, form := range Ladder() {
		if form.Name != name {
			continue
		}
		rewritten, ok := form.Rewrite(req)
		if !ok {
			return nil, false
		}
		return rewritten, true
	}
	t.Fatalf("the ladder has no form named %q", name)
	return nil, false
}
