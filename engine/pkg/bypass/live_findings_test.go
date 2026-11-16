package bypass

// What the live run found, kept as regressions.
//
// Measured 2026-10-03 against `www.liveinternet.ru/.git/config`, whose plain
// answer is `403` from nginx while the same host serves `/robots.txt` with `200` —
// a refusal scoped to the request's shape, which is the only class in which a
// ladder can be measured at all.
//
// Two defects came out of it, and both are the same mistake wearing different
// clothes: deciding by what the status was *not* instead of by what it was.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOnlyAServedStatusIsASuccess is the first defect.
//
// `OPTIONS` and `DELETE` against that host answer **501**, which is the server
// saying it does not implement the method. The resource was never read. But 501 is
// not 403, so the walk's "not refused" test called it success and the report named
// `reached by verb-options` — a form that reached nothing.
//
// The rule is therefore positive: the target served the resource when it answered
// `2xx`, and nothing else counts.
func TestOnlyAServedStatusIsASuccess(t *testing.T) {
	for _, status := range []int{200, 201, 204, 206, 299} {
		if !servedStatus(status) {
			t.Errorf("status %d is a 2xx and the target served the resource", status)
		}
	}
	// Every one of these came back or could come back from a real target, and
	// every one of them is not access.
	for _, status := range []int{
		http.StatusBadRequest,          // 400 — a target the server cannot read
		http.StatusUnauthorized,        // 401 — an authentication wall
		http.StatusForbidden,           // 403 — the refusal this package exists for
		http.StatusNotFound,            // 404 — nothing there
		http.StatusMethodNotAllowed,    // 405 — not for this method
		http.StatusTooManyRequests,     // 429 — rate limited
		http.StatusNotImplemented,      // 501 — the verb does not exist here
		http.StatusBadGateway,          // 502 — upstream broke
		http.StatusServiceUnavailable,  // 503 — overloaded
		http.StatusGatewayTimeout,      // 504 — timed out
		http.StatusLoopDetected,        // 521 — CDN-level refusal
		http.StatusLoopDetected + 100,  // 621 — the odd private-use range some CDNs send
		http.StatusInternalServerError, // 500 — the server broke
		http.StatusMovedPermanently,    // 301 — the client follows these
		http.StatusFound,               // 302 — the client follows these
		http.StatusTemporaryRedirect,   // 307
		http.StatusPermanentRedirect,   // 308
	} {
		if servedStatus(status) {
			t.Errorf("status %d is not a served resource, and a walk that counts it "+
				"claims access to a page it never read", status)
		}
	}
}

// TestAWalkDoesNotCallAnUnimplementedMethodASuccess is the same defect measured
// end to end, against a server that behaves like the live one did.
func TestAWalkDoesNotCallAnUnimplementedVerbASuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusForbidden)
		case http.MethodOptions, http.MethodDelete:
			// What nginx answered on the live target.
			w.WriteHeader(http.StatusNotImplemented)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)

	req := mustRequest(t, server.URL+"/.git/config")
	resp, attempt, err := New(nil).Attempt(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()

	if attempt.Bypassed() {
		t.Errorf("the walk reported %q as a bypass, but the target answered 501 — "+
			"the resource was never read", attempt.SucceededBy)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("the caller received %d; the truthful answer is the 403 the plain "+
			"request already got", resp.StatusCode)
	}
}

// TestAMethodTheResourceDoesNotOfferIsARefusal pins the trigger side of the same
// rule: a walk should still be spent on a 405, because that is a statement about
// the method rather than about the resource existing.
func TestAMethodTheResourceDoesNotOfferIsARefusal(t *testing.T) {
	if !Refused(http.StatusMethodNotAllowed) {
		t.Error("405 is a refusal of access; treating it as one would end the walk " +
			"and report a page the target never served")
	}
	if !Refused(http.StatusUnauthorized) {
		t.Error("401 is an authentication wall, not access")
	}
	if Refused(http.StatusTooManyRequests) {
		t.Error("429 is a statement about how much was asked, not about the shape of " +
			"this request; answering it with a walk is the wrong answer to it")
	}
	if Refused(http.StatusNotFound) {
		t.Error("404 means the resource is not there, so there is nothing to bypass")
	}
}

// TestAWalkThatReachesNothingReturnsAnErrorNotANilResponse is the second defect.
//
// When every form's request failed on the wire there was no response to hand
// back, and the walk returned `(nil, record, nil)`. Every caller of a walk ends in
// `resp.Body.Close()`, and that dereferences nil: measured as SIGSEGV in 2 of 9
// answered live runs.
//
// An error is the honest answer, and it is the one a caller can actually check.
func TestAWalkThatReachesNothingReturnsAnErrorNotANilResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)

	// A transport that always fails, so every form's request dies on the wire and
	// the plain request's own answer is the only one that ever existed.
	dead := &http.Client{Transport: failingTransport{}}

	_, attempt, err := New(nil).Walk(context.Background(), dead, mustRequest(t, server.URL+"/x"), http.StatusForbidden)
	if !errors.Is(err, ErrNoFormReached) {
		t.Fatalf("err = %v, want ErrNoFormReached: a caller handed a nil response with a "+
			"nil error dereferences it on the very next line", err)
	}
	if attempt == nil {
		t.Fatal("the attempt record was dropped; the caller needs to know what was tried")
	}
	if attempt.Bypassed() {
		t.Errorf("a walk where every request failed reported a bypass: %q", attempt.SucceededBy)
	}
	if len(attempt.Tried) == 0 {
		t.Error("no form is recorded as tried, so the log cannot say the walk happened")
	}
}

// failingTransport refuses every request, which is what a dead route looks like
// to the walk.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport is down")
}
