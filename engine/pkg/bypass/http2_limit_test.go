package bypass

// What the live run found, kept as a regression.
//
// Measured 2026-10-03 against `tass.ru`: the four `strip-*` forms produced no HTTP
// status at all — the request never completed — while every other form was
// answered 403. The unit fixture could not show this, because `httptest` without
// `EnableHTTP2` negotiates HTTP/1.1.
//
// The cause is the protocol, not the target. Go's HTTP/2 client refuses a
// request carrying `Connection`: that header is hop-by-hop and has no meaning on
// h2, so the client returns an error before the request is written. The form's
// entire mechanism *is* a `Connection` header, which means the form is not
// "a technique that failed to bypass here" — it is a request this client cannot
// send at all on any HTTP/2 target.
//
// So the form is refused on purpose rather than walked, and the reason is that
// four requests per refusal that can never produce an answer are four requests
// the operator did not agree to spend. This file proves both halves: that the
// refusal happens, and that the ladder stops offering a form that cannot work.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheStripFormsCannotBeSentOverHTTP2 records why they are not offered.
//
// The measurement is the point: without it, "the form did not bypass anything"
// and "the client refused to send the request" look the same in a report, and the
// second is a defect in this package while the first is a fact about the target.
func TestTheStripFormsCannotBeSentOverHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	if server.Client().Transport == nil {
		t.Fatal("the fixture has no transport, so it cannot prove which protocol was used")
	}
	client := server.Client()

	// Prove the connection really is h2, or the measurement below proves nothing.
	resp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("the h2 fixture did not answer: %v", err)
	}
	proto := resp.Proto
	resp.Body.Close()
	if !strings.HasPrefix(proto, "HTTP/2") {
		t.Fatalf("the fixture negotiated %q, so a refusal below would prove nothing about h2", proto)
	}

	// The forms are walked directly, not looked up in the ladder: they are not in
	// the ladder, which is the other half of what this file is about, and a lookup
	// there would make this measurement fail for the wrong reason the moment that
	// decision took effect.
	for _, form := range ConnectionStrippingForms() {
		t.Run(form.Name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			rewritten, ok := form.Rewrite(req)
			if !ok {
				t.Fatalf("form %q produced no request", form.Name)
			}
			answer, err := client.Do(rewritten)
			if err == nil {
				answer.Body.Close()
				t.Fatalf("form %q was sent over %s and answered %d; this test exists because it "+
					"cannot be, and if it now can be the reasoning above is out of date",
					form.Name, proto, answer.StatusCode)
			}
			t.Logf("form %q cannot be sent over %s: %v", form.Name, proto, err)
		})
	}
}

// TestTheLadderDoesNotOfferAFormThatCannotBeSent is the behaviour half.
//
// A form the client will refuse is a request the operator's target sees as
// nothing and the operator's budget sees as spent. Walking four of them on every
// refusal is the hidden cost the project's own rule about visible limits exists
// to prevent, so they are not in the ladder.
func TestTheLadderDoesNotOfferAFormThatCannotBeSent(t *testing.T) {
	unsendable := map[string]bool{}
	for _, name := range stripFormNames(t) {
		unsendable[name] = true
	}
	for _, form := range Ladder() {
		if unsendable[form.Name] {
			t.Errorf("form %q is in the ladder but cannot be sent over HTTP/2; "+
				"it would spend a request per refusal and answer nothing", form.Name)
		}
	}
}

// TestTheStripFormsAreStillReachableOnHTTP1 is the other half of the decision.
//
// Not offering a form by default and losing it are different things, and only one
// of them is acceptable. The forms are exported, so a caller that knows it is on
// HTTP/1.1 can name them in `BypassForms`; this test is what makes that a fact
// rather than a claim, because a rename or a deletion would leave the guard above
// still green while the capability quietly disappeared.
func TestTheStripFormsAreStillReachableOnHTTP1(t *testing.T) {
	for _, form := range ConnectionStrippingForms() {
		t.Run(form.Name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			rewritten, ok := form.Rewrite(req)
			if !ok {
				t.Fatalf("form %q declined to rewrite anything", form.Name)
			}
			if rewritten.Header.Get("Connection") == "" {
				t.Errorf("form %q is reachable but sets no Connection header, so it is not the "+
					"technique it claims to be", form.Name)
			}
			// A refused connection is the expected answer on a closed port. What
			// must NOT appear is a transport complaint about `Connection` — that
			// would mean even on HTTP/1.1 the form cannot go out.
			if _, err := (&http.Client{}).Do(rewritten); err != nil && strings.Contains(err.Error(), "nvalid Connection") {
				t.Errorf("form %q was refused by the transport for a Connection reason: %v", form.Name, err)
			}
		})
	}
}

// stripFormNames is the set the live measurement found unsendable.
//
// It is read off `ConnectionStrippingForms` rather than off the ladder, and it
// fails loudly when that set is empty. Deriving the names from the ladder would
// have made both tests here pass the moment the forms left the ladder — including
// the measurement that is the reason they left it. A guard that goes green
// because the thing it guards was deleted is not a guard.
func stripFormNames(t *testing.T) []string {
	t.Helper()
	forms := ConnectionStrippingForms()
	if len(forms) == 0 {
		t.Fatal("ConnectionStrippingForms is empty, so nothing is being measured: either the " +
			"capability was lost, or this file stopped testing it")
	}
	names := make([]string, 0, len(forms))
	for _, form := range forms {
		names = append(names, form.Name)
	}
	return names
}
