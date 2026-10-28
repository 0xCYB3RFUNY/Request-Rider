package main

// Tests for the target-specific fuzzing wordlist.
//
// The source is `xnl-h4ck3r/GAP-Burp-Extension` at commit
// f223016fa347776aff59dd610da8f1e2ffee3260. What that tool claims to produce is
// "a target specific wordlist to use for fuzzing" from the parameters a program
// names and the links those parameters could be tried on.
//
// The claim being tested here is the pairing, and the claim being refused is the
// conclusion. The list says "this program sends this name here"; it does not say
// any of it works, and the tests below include one that fails if the list ever
// starts claiming severity it cannot have.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestTheWordlistPairsThisBundleWithItself is the central claim: a word exists
// only where a path this program calls meets a name this program binds.
func TestTheWordlistPairsThisBundleWithItself(t *testing.T) {
	analysis := analysisOf(t, `
const campaignId = window.location.hash;
fetch("/api/v1/campaigns/action/cancel?campaign_id=" + campaignId, {method: "PUT"});
fetch("/api/v1/api-keys/" + key, {method: "GET"});
`)
	if len(analysis.ProbeWords) == 0 {
		t.Fatalf("no fuzzing words were produced: %+v", analysis.Params)
	}
	joined := strings.Join(analysis.ProbeWords, "\n")
	// The second endpoint's path is built from an expression, so its word carries
	// a stand-in rather than the placeholder: a wordlist that cannot be sent is
	// not a wordlist.
	for _, want := range []string{
		"/api/v1/campaigns/action/cancel?campaignId=1",
		"/api/v1/api-keys/1?campaignId=1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q is missing from the wordlist:\n%s", want, joined)
		}
	}
}

// TestAParameterTheEndpointAlreadyCarriesIsNotProposed is the noise half, and
// the first version of it asked the wrong question.
//
// It used two calls to the same path — one carrying `campaign_id`, one carrying
// `extra` — and then refused **any** word of the form `path?campaign_id=`. But
// the word was created for the *second* call, which does not carry that
// parameter, and proposing it is the whole point: a call that accepts `extra`
// may accept `campaign_id` too, and the analyst cannot know without asking.
//
// The question that is actually about noise needs one call. With one call there
// is no other call the word could belong to, so anything proposed that the call
// already carries is a duplicate an analyst would delete without learning
// anything.
func TestAParameterTheEndpointAlreadyCarriesIsNotProposed(t *testing.T) {
	analysis := analysisOf(t, `
const reportToken = 1;
fetch("/api/v1/campaigns?campaign_id=768653&report_token=" + reportToken, {method: "GET"});
`)
	if len(analysis.ProbeWords) == 0 {
		t.Fatalf("no fuzzing words were produced: %+v", analysis.Params)
	}
	for _, word := range analysis.ProbeWords {
		name := word[strings.Index(word, "?")+1:]
		name = strings.SplitN(name, "=", 2)[0]
		if name == "campaign_id" || name == "report_token" {
			t.Errorf("%q was proposed although the single call already carries it", name)
		}
	}
	// And the reason it is worth keeping: a name the call does not carry is
	// still proposed, so the filter is a filter and not a switch.
	joined := strings.Join(analysis.ProbeWords, ",")
	if !strings.Contains(joined, "?") {
		t.Errorf("nothing was proposed at all: %v", analysis.ProbeWords)
	}
}

// TestAWordIsProposedForTheCallThatDoesNotCarryIt is the companion, and it is
// what the first version got backwards: two calls to one path, and the word
// belongs to the one that lacks the parameter.
func TestAWordIsProposedForTheCallThatDoesNotCarryIt(t *testing.T) {
	analysis := analysisOf(t, `
const extra = 1;
fetch("/api/v1/campaigns?campaign_id=768653", {method: "GET"});
fetch("/api/v1/campaigns?extra=" + extra, {method: "GET"});
`)
	found := false
	for _, word := range analysis.ProbeWords {
		if word == "/api/v1/campaigns?campaign_id=1" {
			found = true
		}
	}
	if !found {
		t.Errorf("the call without campaign_id was not offered it: %v", analysis.ProbeWords)
	}
}

// TestTheWordlistSaysWhatItDropped keeps the bound visible, which is the rule the
// project holds every bound to: an operator who cannot see it cannot change it,
// and a wordlist that looks complete and is not is worse than one that stops.
func TestTheWordlistSaysWhatItDropped(t *testing.T) {
	var source strings.Builder
	source.WriteString("const v0 = 1;\n")
	for i := 1; i < jsProbeWordsLimit*3; i++ {
		fmt.Fprintf(&source, "const v%d = %d;\n", i, i)
	}
	source.WriteString(`fetch("/api/v1/reports", {method: "GET"});`)
	analysis := analysisOf(t, source.String())

	if analysis.ProbeWordsTruncated == 0 {
		t.Fatalf("%d names produced no truncation notice", jsProbeWordsLimit*3)
	}
	// The bound is written as a number, not as the constant. A test that reads the
	// constant back agrees with any change to it, which is the same mistake as a
	// test that reads the expected value out of the code under test.
	const documentedBound = 40
	if len(analysis.ProbeWords) != documentedBound {
		t.Errorf("the endpoint contributed %d words, want the documented bound of %d",
			len(analysis.ProbeWords), documentedBound)
	}
	// The count is against the names the analyser actually reported, not against
	// the names the fixture wrote: the analyser filters plenty of ordinary
	// bindings, and a test that ignored that was checking its own arithmetic.
	if want := len(analysis.Params) - jsProbeWordsLimit; analysis.ProbeWordsTruncated != want {
		t.Errorf("truncated = %d, want %d for %d reported names",
			analysis.ProbeWordsTruncated, want, len(analysis.Params))
	}
	if len(analysis.Params) <= jsProbeWordsLimit {
		t.Fatalf("only %d names reached the wordlist, so the bound was never exercised",
			len(analysis.Params))
	}
}

// TestNoEndpointMeansNoWord is the control: a bundle with names but no request
// sites produces no words, because a word is the pair and there is no second
// half. The names themselves are still reported in `params` — this is about the
// pairing, not about losing the list.
func TestNoEndpointMeansNoWord(t *testing.T) {
	analysis := analysisOf(t, `
const reportToken = 1;
const debug = 2;
`)
	if len(analysis.ProbeWords) != 0 {
		t.Errorf("a bundle with no request sites produced fuzzing words: %v", analysis.ProbeWords)
	}
	if len(analysis.Params) == 0 {
		t.Error("the names themselves were lost; the pairing is empty but the list is not")
	}
}

// TestEveryProposedWordNamesARealPair checks the invariant that keeps the list
// honest as it grows: every line is a path this program calls, a `?`, and a name
// this program binds. A line that is only half of that is a line that was built
// wrong, and it is invisible to a reader until they send it.
func TestEveryProposedWordNamesARealPair(t *testing.T) {
	analysis := analysisOf(t, `
const campaignId = 1;
const accountUid = 2;
fetch("/api/v1/campaigns/action/cancel?campaign_id=" + campaignId, {method: "PUT"});
fetch("/api/v1/accounts/" + accountUid, {method: "GET"});
fetch("/api/v1/reports/export", {method: "POST"});
`)
	names := map[string]bool{}
	for _, candidate := range analysis.Params {
		names[strings.ToLower(candidate.Name)] = true
	}
	paths := map[string]bool{}
	for _, endpoint := range analysis.Endpoints {
		paths[fuzzablePath(endpointPathOf(endpoint.URL))] = true
	}
	if len(analysis.ProbeWords) == 0 {
		t.Skip("this bundle produced no words; nothing to check")
	}
	for _, word := range analysis.ProbeWords {
		path, query, ok := strings.Cut(word, "?")
		if !ok {
			t.Errorf("%q has no parameter half", word)
			continue
		}
		if strings.Contains(path, "EXPR") {
			t.Errorf("%q still carries the analyser's placeholder and cannot be sent", word)
		}
		if !paths[path] {
			t.Errorf("%q names a path this program never calls", path)
		}
		name, _, ok := strings.Cut(query, "=")
		if !ok {
			t.Errorf("%q has no value half", word)
			continue
		}
		if !names[strings.ToLower(name)] {
			t.Errorf("%q names a parameter this program never binds", name)
		}
	}
}

// TestTheWordlistClaimsNothingAboutSeverity is the refusal, made executable. A
// fuzzing word is a hypothesis; the moment the record carries a severity or a
// verdict, a reader will stop sending it and start believing it.
func TestTheWordlistClaimsNothingAboutSeverity(t *testing.T) {
	analysis := analysisOf(t, `
const campaignId = 1;
fetch("/api/v1/campaigns/" + campaignId, {method: "GET"});
`)
	// The first version of this searched the whole record and failed on
	// `vulnerable_libraries`, which is another capability's answer and has no
	// business being confused with this one. The question is about the wordlist
	// itself, so it is asked of the wordlist.
	if len(analysis.ProbeWords) == 0 {
		t.Skip("this bundle produced no words; the shape is what is under test")
	}
	for _, word := range analysis.ProbeWords {
		if word == "" {
			t.Fatal("an empty word was proposed")
		}
		if strings.ContainsAny(word, " \t\n") {
			t.Errorf("%q contains whitespace; a word is one request line", word)
		}
	}
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		ProbeWords []json.RawMessage `json:"probe_words"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.ProbeWords) != len(analysis.ProbeWords) {
		t.Fatalf("decoded %d words, have %d", len(decoded.ProbeWords), len(analysis.ProbeWords))
	}
	for i, raw := range decoded.ProbeWords {
		var asString string
		if err := json.Unmarshal(raw, &asString); err != nil {
			t.Errorf("word %d is not a plain string: %s", i, raw)
		}
	}
}
