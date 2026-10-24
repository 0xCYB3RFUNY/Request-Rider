package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// `email_recon` was registered `network: false` while its body already contained
// a sixty-platform probe. That flag is the only thing the page reads before it
// asks (`osintTransformIsNetwork` answers from the registry), so `network: false`
// meant the confirmation dialog never appeared, the page sent
// `confirm_network: false`, and the function returned above the probe having sent
// nothing — while reporting "External social-profile verification is disabled".
//
// The operator read that message and was told a capability that is written forty
// lines below them had been switched off. These tests pin the three links of the
// chain that has to hold for the probe to be reachable:
//
//  1. the registry says it reaches the network, so the page asks;
//  2. the engine refuses an unconfirmed run, so the gate is not advisory;
//  3. a confirmed run actually queries a platform and reports what answered.
//
// Each is asserted separately because the failure that mattered was the one where
// all three looked fine to the reader and the run still did nothing.

// The catalogue is a table of real platforms, so a probe of it from a test is a
// network request to somebody's server. The entry point is therefore measured
// through the transport the project already injects for a tool run
// (`withToolTransport`), with every host rewritten onto a fixture — the same
// route `osint_github_test.go` and `osint_secrets_test.go` take, rather than a
// second mechanism invented here.
type emailProbeTransport struct {
	probed *[]string
	// found is the host substring that answers 200; every other host answers 404.
	found string
	base  *url.URL
}

func (t emailProbeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	*t.probed = append(*t.probed, request.URL.Host)
	status := http.StatusNotFound
	if strings.Contains(request.URL.Host, t.found) {
		status = http.StatusOK
	}
	rewritten := request.Clone(request.Context())
	rewritten.URL.Scheme = t.base.Scheme
	rewritten.URL.Host = t.base.Host
	rewritten.Host = ""
	response, err := http.DefaultTransport.RoundTrip(rewritten)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}, nil
}

// emailProbeContext builds a context whose every outbound request is answered by
// the fixture, and returns the slice the probed hosts are recorded in.
func emailProbeContext(t *testing.T, found string) (context.Context, *[]string) {
	t.Helper()
	probed := &[]string{}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fixture.Close)
	base, err := url.Parse(fixture.URL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	transport := emailProbeTransport{probed: probed, found: found, base: base}
	return withToolTransport(context.Background(), transport), probed
}

func TestEmailReconIsRegisteredAsANetworkTransform(t *testing.T) {
	entry := transformRegistryEntry("email_recon")
	if entry == nil {
		t.Fatal("email_recon is not in the registry, so the menu can never offer it")
	}
	if entry["network"] != true {
		t.Fatal("email_recon performs network requests and must be registered network: true; " +
			"with the flag false the page never asks and the probe is unreachable")
	}
	if accepts, _ := entry["accepts"].([]string); len(accepts) == 0 || accepts[0] != "email" {
		t.Fatalf("email_recon accepts = %v, want email", accepts)
	}
	description, _ := entry["description"].(string)
	for _, required := range []string{"confirmation", "platform"} {
		if !strings.Contains(strings.ToLower(description), required) {
			t.Errorf("description must say %q before the operator confirms: %q", required, description)
		}
	}
	// The sentence that reached the operator claimed the capability was off. A
	// description that says so is the half of the defect the registry now removed,
	// and it must not come back in prose.
	for _, forbidden := range []string{"intentionally disabled", "no mass profile enumeration", "verification is disabled"} {
		if strings.Contains(strings.ToLower(description), forbidden) {
			t.Errorf("description claims the probe is unavailable (%q): %q", forbidden, description)
		}
	}
}

func TestEmailReconRefusesAnUnconfirmedRun(t *testing.T) {
	// `validateTransformInput` is the single entry point every run passes through,
	// and it is where the confirmation requirement lives. Asking
	// `transformApplicabilityError` instead would test a function that has no
	// opinion on confirmation and would pass for the wrong reason.
	code, message, ok := validateTransformInput(&osintTransformInput{
		Transform: "email_recon", Value: "analyst@example.com",
	})
	if ok {
		t.Fatal("email_recon ran without confirmation, so the page could skip the dialog")
	}
	if code != "NETWORK_CONFIRMATION_REQUIRED" || message == "" {
		t.Fatalf("email_recon without confirmation = %q %q, want NETWORK_CONFIRMATION_REQUIRED", code, message)
	}

	// And the run entry point refuses it too, not only the applicability helper:
	// the helper is one caller, and the gate has to hold on the path the page
	// actually takes.
	result, err := (&server{}).runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "email_recon", Value: "analyst@example.com",
	})
	if err == nil {
		t.Fatalf("an unconfirmed email_recon answered %#v instead of refusing", result)
	}
	if !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Fatalf("unconfirmed email_recon = %v, want NETWORK_CONFIRMATION_REQUIRED", err)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("a refused run must not carry warnings that read as an answer: %#v", result.Warnings)
	}
}

// A confirmed run must reach the network and report what answered. The claim this
// pins is the operator's: the transform says social-profile verification is
// disabled while the code that performs it never runs. Here it runs, and the
// platform that answered is named with the status it gave.
func TestConfirmedEmailReconProbesAndReportsThePlatformThatAnswered(t *testing.T) {
	ctx, probed := emailProbeContext(t, "github.com")

	result := osintTransformResult{Transform: "email_recon"}
	err := (&server{}).transformEmailRecon(ctx, &result, osintTransformInput{
		Transform: "email_recon", Value: "analyst@example.com", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("confirmed email_recon: %v", err)
	}
	if result.LocalOnly || !result.NetworkUsed {
		t.Fatalf("a confirmed run reported local_only=%v network_used=%v, want a network run",
			result.LocalOnly, result.NetworkUsed)
	}
	if len(*probed) == 0 {
		t.Fatal("no platform was probed, so the verification did not happen")
	}
	// The local half still runs: the address and its domain are what the operator
	// started from, and the probe adds to them rather than replacing them.
	var emailFound, domainFound bool
	for _, item := range result.Entities {
		switch item.Type {
		case "email":
			emailFound = strings.EqualFold(item.Identity, "analyst@example.com")
		case "domain":
			domainFound = strings.EqualFold(item.Identity, "example.com")
		}
	}
	if !emailFound || !domainFound {
		t.Fatalf("the local normalization was lost: email=%v domain=%v in %#v",
			emailFound, domainFound, result.Entities)
	}

	// The profile the platform claimed to hold is reported as a `profile` entity
	// with the status it answered. Before the gateway learned this type the row
	// was refused with "unsupported OSINT entity type: profile" and the whole
	// answer was discarded on the way into the graph.
	var profile *transformEntity
	for index := range result.Entities {
		if result.Entities[index].Type == "profile" {
			profile = &result.Entities[index]
			break
		}
	}
	if profile == nil {
		t.Fatalf("no profile entity among %#v", result.Entities)
	}
	if status, _ := profile.Properties["status"].(int); status != http.StatusOK {
		t.Errorf("profile status = %v, want 200 — the status is the evidence, not a claim of ownership",
			profile.Properties["status"])
	}

	// The relation is what makes the finding usable: the address accounts for it.
	var linked bool
	for _, relation := range result.Relations {
		if relation.Type == "accounts_for" && relation.SourceType == "email" &&
			strings.EqualFold(relation.Source, "analyst@example.com") && relation.TargetType == "profile" {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("the email->profile relation is missing from %#v", result.Relations)
	}
}

// A run that reached the network and found nothing says so. The warning that
// reached the operator was the opposite: it claimed nothing was sent.
func TestConfirmedEmailReconReportsNothingFoundAsAProbeNotAsADisabledFeature(t *testing.T) {
	// A `found` host that is in no catalogue entry, so every platform answers 404.
	ctx, _ := emailProbeContext(t, "nothing-matches-this-host.example")
	result := osintTransformResult{Transform: "email_recon"}
	if err := (&server{}).transformEmailRecon(ctx, &result, osintTransformInput{
		Transform: "email_recon", Value: "analyst@example.com", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("confirmed email_recon: %v", err)
	}
	joined := strings.ToLower(strings.Join(result.Warnings, " "))
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one that names an empty result", result.Warnings)
	}
	if strings.Contains(joined, "disabled") || strings.Contains(joined, "no mass http checks") {
		t.Fatalf("warning claims the verification is switched off after it ran: %q", result.Warnings[0])
	}
	if !strings.Contains(joined, "no public social accounts matched") {
		t.Fatalf("warning does not name what the probe actually found: %q", result.Warnings[0])
	}
	if !result.NetworkUsed {
		t.Error("a run that probed every platform reported network_used=false")
	}
}

// The type is only usable if the graph can store it. This is the half of the
// defect that lived in the gateway rather than the engine, and it is why the
// registry change alone would have been a green test and a broken feature: the
// rows arrived and were refused on the way in.
func TestProfileIsAKnownEntityKind(t *testing.T) {
	if !knownEntityKinds["profile"] {
		t.Error("profile is not a known entity kind, so the gateway has nowhere to store the probe's answer")
	}
	entry := transformRegistryEntry("email_recon")
	if entry == nil {
		t.Fatal("email_recon is not registered")
	}
	// `profile` is emitted, not accepted as input, so it must not be added to a
	// transform's `accepts`: there is no "search for profiles" transform, and
	// offering one would be the dead control the project's own rules forbid.
	for _, item := range transformRegistry {
		for _, accepted := range transformAccepts(item) {
			if accepted == "profile" {
				t.Errorf("%v accepts profile, so the kind would be offered as an input it cannot investigate",
					item["id"])
			}
		}
	}
}

// The engine's own answer has to survive the JSON round trip the gateway reads it
// through. A profile entity whose properties carried a byte the database refuses
// would reintroduce the target-crawler failure on the OSINT side, where
// `upsert_graph` writes into a JSONField.
func TestEmailReconResultSurvivesTheJSONRoundTrip(t *testing.T) {
	ctx, _ := emailProbeContext(t, "github.com")
	result := osintTransformResult{Transform: "email_recon"}
	if err := (&server{}).transformEmailRecon(ctx, &result, osintTransformInput{
		Transform: "email_recon", Value: "analyst@example.com", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("confirmed email_recon: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal the result the way the HTTP handler does: %v", err)
	}
	var decoded osintTransformResult
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal the result the way the gateway does: %v", err)
	}
	if len(decoded.Entities) != len(result.Entities) {
		t.Fatalf("entities changed across the wire: %d -> %d", len(result.Entities), len(decoded.Entities))
	}
	if len(decoded.Relations) != len(result.Relations) {
		t.Fatalf("relations changed across the wire: %d -> %d", len(result.Relations), len(decoded.Relations))
	}
}