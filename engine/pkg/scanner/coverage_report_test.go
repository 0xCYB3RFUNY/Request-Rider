package scanner

import (
	"testing"
)

func TestBuildNucleiCoverageReportSeparatesExecutedAndBlindSpots(t *testing.T) {
	run := NucleiRun{
		Templates: []TemplateResult{
			{TemplateID: "cve-2024-1", Path: "a.yaml", Status: TemplateMatched, Matches: 1},
			{TemplateID: "cve-2024-2", Path: "b.yaml", Status: TemplateNotMatched},
			{TemplateID: "cve-2024-3", Path: "c.yaml", Status: TemplateNotMatched},
			{TemplateID: "cve-2024-4", Path: "d.yaml", Status: TemplateSkipped, Reason: "timeout"},
		},
	}

	report := BuildNucleiCoverageReport(run)
	if report.TotalPlanned != 4 {
		t.Fatalf("TotalPlanned = %d, want 4", report.TotalPlanned)
	}
	if report.Executed != 3 {
		t.Fatalf("Executed = %d, want 3", report.Executed)
	}
	if report.Matched != 1 || report.NotMatched != 2 || report.SkippedOrUnverified != 1 {
		t.Fatalf("unexpected counts: %+v", report)
	}
	if report.CoveragePercent != 75.0 {
		t.Fatalf("CoveragePercent = %.2f, want 75.00", report.CoveragePercent)
	}
	if len(report.BlindSpots) != 1 || report.BlindSpots[0].ID != "cve-2024-4" || report.BlindSpots[0].Reason != "timeout" {
		t.Fatalf("BlindSpots = %+v, want cve-2024-4 timeout", report.BlindSpots)
	}
}

func TestBuildCorpusCoverageReportHandlesTruncation(t *testing.T) {
	res := CorpusRunResult{
		Checks:    80,
		Skipped:   20,
		Findings:  4,
		Truncated: true,
	}

	report := BuildCorpusCoverageReport(res)
	if report.TotalPlanned != 100 || report.CoveragePercent != 80.0 || report.HitRatePercent != 5.0 {
		t.Fatalf("unexpected corpus report: %+v", report)
	}
	if len(report.BlindSpots) != 1 || report.BlindSpots[0].Status != "truncated" {
		t.Fatalf("expected truncated blind spot, got %+v", report.BlindSpots)
	}
}
