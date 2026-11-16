package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDefaultInterestingParamsHasFullPatternsCount verifies that the imported Gf-Patterns
// interestingparams.json dataset contains exactly 218 patterns as measured in the reconciliation registry.
func TestDefaultInterestingParamsHasFullPatternsCount(t *testing.T) {
	if got := len(GfInterestingParamsPatterns); got != 218 {
		t.Errorf("want exactly 218 patterns in GfInterestingParamsPatterns, got %d", got)
	}
	if got := len(DefaultInterestingParams); got != 132 {
		t.Errorf("want 132 deduplicated unique parameters in DefaultInterestingParams, got %d", got)
	}
}

// TestHiddenParamsWithDefaultInterestingParamsFiresProbes verifies that HiddenParams executes
// correctly when configured with DefaultInterestingParams against a target endpoint.
func TestHiddenParamsWithDefaultInterestingParamsFiresProbes(t *testing.T) {
	server := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	transport := transportFor(t, server.Server)
	point := Point{URL: server.URL + "/api/v1", Method: http.MethodGet}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	// Test subset of DefaultInterestingParams
	subset := DefaultInterestingParams[:5]
	detector := HiddenParams{Params: subset}
	names := detector.usableNames()
	if len(names) != len(subset) {
		t.Errorf("usableNames() filtered out valid default params: got %d, want %d", len(names), len(subset))
	}

	findings := detector.Scan(context.Background(), transport, point, baseline)
	// Server responds with static "ok" so no hidden parameter finding is reported (clean response)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on inert server, got %d", len(findings))
	}
}

func TestHiddenParamsBinaryBatchFindsNeedleInLargeWordlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("secret_debug_flag") != "" {
			_, _ = w.Write([]byte("debug mode enabled"))
			return
		}
		_, _ = w.Write([]byte("normal page"))
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{URL: srv.URL + "/home", Method: http.MethodGet}
	baseline, err := tr.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	params := make([]string, 0, 64)
	for i := 0; i < 63; i++ {
		params = append(params, "unused_param_"+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	params = append(params, "secret_debug_flag")

	mod := HiddenParams{Params: params}
	findings := mod.Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 || findings[0].Param != "secret_debug_flag" {
		t.Fatalf("expected 1 finding for secret_debug_flag, got %+v", findings)
	}
	if tr.Requests() > 30 {
		t.Fatalf("expected binary batching to use <= 30 requests, used %d", tr.Requests())
	}
}

func TestHiddenParamsMassAssignmentPoolOptIn(t *testing.T) {
	if len((HiddenParams{}).usableNames()) != 0 {
		t.Fatal("expected empty usableNames when Params is empty and EnableMassAssignmentPool is false")
	}
	names := (HiddenParams{EnableMassAssignmentPool: true}).usableNames()
	if len(names) != len(DefaultMassAssignmentParams) {
		t.Fatalf("expected %d mass assignment params, got %d", len(DefaultMassAssignmentParams), len(names))
	}
}
