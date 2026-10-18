package active

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// A Report is what leaves the engine: the job wrapper publishes it, the browser
// reads it and the project journal stores it. If it cannot be marshalled then a
// finished run cannot be delivered at all, and the failure appears only at the
// edge — the scan itself looks perfect.
//
// This test exists because that was exactly the defect it catches: `ScanRequest`
// carried an exported clock and an exported RoundTripper, so every
// `json.Marshal` of a report failed with "unsupported type: func() time.Time"
// while the whole scan test suite stayed green — nothing inside the package ever
// serialised a report.
func TestAReportIsSerialisable(t *testing.T) {
	report := &Report{
		Target: "http://target.test/",
		Plan: ScanRequest{
			URL:          "http://target.test/",
			MaxPages:     3,
			MaxDepth:     1,
			Concurrency:  4,
			Delay:        10 * time.Millisecond,
			Timeout:      5 * time.Second,
			Now:          time.Now,
			RoundTripper: http.DefaultTransport,
		},
		Findings: []Finding{{
			ID: "VXR-1", Module: "sqli", Title: "SQL injection, verified",
			Severity: SeverityHigh, Tier: TierVerified,
			Endpoint: "http://target.test/item", Method: "GET", Param: "id",
		}},
		Proofs: []Proof{{FindingID: "VXR-1", Kind: "sqli-extract", Proof: "ok"}},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("a report must be serialisable, got: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("a marshalled report must parse back: %v", err)
	}
	// The run's own bounds are data and belong in the report; the clock and the
	// transport are not, and their absence has to be deliberate rather than a
	// marshal that happens to succeed today. The bounds serialise under their Go
	// field names, because `ScanRequest` carries no json tags and a report that
	// renamed them would change a contract the browser already reads.
	plan, ok := decoded["plan"].(map[string]interface{})
	if !ok {
		t.Fatalf("the report carries no plan: %s", encoded)
	}
	if plan["URL"] != "http://target.test/" || plan["MaxPages"] != float64(3) {
		t.Fatalf("the plan lost the bounds the operator set: %v", plan)
	}
	if _, present := plan["Now"]; present {
		t.Fatalf("the clock leaked into the report: %v", plan)
	}
	if _, present := plan["RoundTripper"]; present {
		t.Fatalf("the transport leaked into the report: %v", plan)
	}
}
