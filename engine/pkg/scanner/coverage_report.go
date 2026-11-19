package scanner

import (
	"fmt"
	"math"
)

// CoverageGap identifies one check or template that was part of the planned
// scan scope but did not produce an executed verdict.
type CoverageGap struct {
	ID     string `json:"id"`
	Path   string `json:"path,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// CoverageReport answers the vulncov question: "what did we find" versus
// "what could we have found and missed or skipped".
type CoverageReport struct {
	TotalPlanned        int           `json:"total_planned"`
	Executed            int           `json:"executed"`
	Matched             int           `json:"matched"`
	NotMatched          int           `json:"not_matched"`
	SkippedOrUnverified int           `json:"skipped_or_unverified"`
	CoveragePercent     float64       `json:"coverage_percent"`
	HitRatePercent      float64       `json:"hit_rate_percent"`
	BlindSpots          []CoverageGap `json:"blind_spots,omitempty"`
	Summary             string        `json:"summary"`
}

// BuildNucleiCoverageReport summarizes executed vs skipped templates from a NucleiRun.
func BuildNucleiCoverageReport(run NucleiRun) CoverageReport {
	report := CoverageReport{
		TotalPlanned: len(run.Templates),
	}
	for _, tmpl := range run.Templates {
		switch tmpl.Status {
		case TemplateMatched:
			report.Executed++
			report.Matched++
		case TemplateNotMatched:
			report.Executed++
			report.NotMatched++
		default:
			report.SkippedOrUnverified++
			report.BlindSpots = append(report.BlindSpots, CoverageGap{
				ID:     tmpl.TemplateID,
				Path:   tmpl.Path,
				Status: tmpl.Status,
				Reason: tmpl.Reason,
			})
		}
	}
	if report.TotalPlanned > 0 {
		report.CoveragePercent = round2(float64(report.Executed) * 100.0 / float64(report.TotalPlanned))
	}
	if report.Executed > 0 {
		report.HitRatePercent = round2(float64(report.Matched) * 100.0 / float64(report.Executed))
	}
	report.Summary = fmt.Sprintf(
		"Executed %d/%d planned checks (%.2f%% coverage); matched %d (%.2f%% hit rate); %d skipped/unverified.",
		report.Executed, report.TotalPlanned, report.CoveragePercent,
		report.Matched, report.HitRatePercent, report.SkippedOrUnverified,
	)
	return report
}

// BuildCorpusCoverageReport summarizes executed vs skipped checks from a CorpusRunResult.
func BuildCorpusCoverageReport(res CorpusRunResult) CoverageReport {
	total := res.Checks + res.Skipped
	report := CoverageReport{
		TotalPlanned:        total,
		Executed:            res.Checks,
		Matched:             res.Findings,
		NotMatched:          max(0, res.Checks-res.Findings),
		SkippedOrUnverified: res.Skipped,
	}
	if total > 0 {
		report.CoveragePercent = round2(float64(report.Executed) * 100.0 / float64(total))
	}
	if report.Executed > 0 {
		report.HitRatePercent = round2(float64(report.Matched) * 100.0 / float64(report.Executed))
	}
	if res.Truncated {
		report.BlindSpots = append(report.BlindSpots, CoverageGap{
			ID:     "corpus_truncated",
			Status: "truncated",
			Reason: "run stopped early due to configured bound",
		})
	}
	report.Summary = fmt.Sprintf(
		"Evaluated %d/%d corpus checks (%.2f%% coverage); %d findings (%.2f%% hit rate); %d skipped.",
		report.Executed, report.TotalPlanned, report.CoveragePercent,
		report.Matched, report.HitRatePercent, report.SkippedOrUnverified,
	)
	return report
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
