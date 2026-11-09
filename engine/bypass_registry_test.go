package main

// The 403-ladder registry endpoint, and the name list behind it.
//
// The claim being pinned is that the browser is offered the engine's own ladder.
// A copy of the names kept anywhere else would make every one of these tests pass
// while the operator could not switch on a form that the engine can walk — the
// failure mode is invisible from the browser, so it has to be asserted from here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"intruder/engine/pkg/bypass"
)

// TestTheFormNamesAreTheLadderItself is the anti-copy test.
//
// `FormNames` is compared against `Ladder()` on every run rather than against a
// written-out list of names, so a form added to the ladder cannot be added
// silently and a name invented for it cannot pass either.
func TestTheFormNamesAreTheLadderItself(t *testing.T) {
	ladder := bypass.Ladder()
	names := bypass.FormNames()
	if len(names) != len(ladder) {
		t.Fatalf("FormNames() has %d names, the ladder has %d forms: the two are different lists",
			len(names), len(ladder))
	}
	for index, form := range ladder {
		if names[index] != form.Name {
			t.Errorf("name %d is %q, the ladder's form is %q", index, names[index], form.Name)
		}
	}
}

// TestTheFormNamesOfferTheCheapestShapesFirst pins what the order is for.
//
// `TestTheFormNamesAreTheLadderItself` already proves the list is the ladder's
// order. What is worth saying at this boundary is a property of that order, because
// it is what the browser shows: the first thing offered is a verb change, which
// leaves the path and the query untouched. Somebody reading the list is deciding
// what to switch on, and the ladder's advice is cheapest-first.
//
// Comparing against a sorted copy would not do this — a ladder order is not
// alphabetical by design, so that comparison fails on every correct build.
func TestTheFormNamesOfferTheCheapestShapesFirst(t *testing.T) {
	names := bypass.FormNames()
	if len(names) < 2 {
		t.Fatalf("the ladder reports %d form(s); there is no order to check", len(names))
	}
	if !strings.HasPrefix(names[0], "verb-") {
		t.Errorf("the list starts at %q, not a verb form: the shapes that leave the path alone "+
			"are the cheapest to try and belong first", names[0])
	}
	lastVerb := -1
	firstOther := len(names)
	for index, name := range names {
		if strings.HasPrefix(name, "verb-") {
			lastVerb = index
		} else if index < firstOther {
			firstOther = index
		}
	}
	if lastVerb > firstOther {
		t.Errorf("a verb form sits at %d and a path-shaped form at %d: the verb family is "+
			"supposed to be spent before any path shape is tried", lastVerb, firstOther)
	}
}

// TestTheFormNamesAreACopy proves the list cannot be used to reach into the ladder.
func TestTheFormNamesAreACopy(t *testing.T) {
	names := bypass.FormNames()
	if len(names) == 0 {
		t.Fatal("the ladder reported no forms")
	}
	names[0] = "mutated-by-the-caller"
	if again := bypass.FormNames(); again[0] == "mutated-by-the-caller" {
		t.Fatal("FormNames() handed out its own slice: writing to the returned list changed the next call")
	}
}

// TestTheFormNamesAreNotEmpty is the button's precondition.
//
// An empty list reaching the browser is indistinguishable from an engine that
// cannot be reached, and in both cases the operator's button quietly does nothing.
func TestTheFormNamesAreNotEmpty(t *testing.T) {
	if len(bypass.FormNames()) == 0 {
		t.Fatal("the ladder reports no forms, so the Target control would have nothing to switch on")
	}
}

// TestTheRegistryEndpointReportsTheLadder drives the handler the mux exposes.
func TestTheRegistryEndpointReportsTheLadder(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&server{}).bypassForms(recorder, httptest.NewRequest(http.MethodGet, "/proxy/bypass/forms", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; the browser is told the ladder is unreadable and the button does nothing",
			recorder.Code)
	}
	var payload struct {
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("the answer is not the JSON the browser parses: %v -- %s", err, recorder.Body.String())
	}
	names := bypass.FormNames()
	if len(payload.Items) != len(names) {
		t.Fatalf("the endpoint reported %d form(s) and the ladder has %d", len(payload.Items), len(names))
	}
	for index := range names {
		if payload.Items[index] != names[index] {
			t.Errorf("form %d reported as %q, the ladder says %q", index, payload.Items[index], names[index])
		}
	}
}

// TestTheRegistryEndpointRefusesAWritingMethod guards the endpoint against being
// used as one. It reports what exists; nothing about it changes anything.
func TestTheRegistryEndpointRefusesAWritingMethod(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&server{}).bypassForms(recorder, httptest.NewRequest(http.MethodPost, "/proxy/bypass/forms", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST answered %d, want 405: this endpoint only lists what exists", recorder.Code)
	}
}
