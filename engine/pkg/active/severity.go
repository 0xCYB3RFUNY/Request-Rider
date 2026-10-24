// Severity, evidence tiers, and the rule that connects them.
//
// # The problem this file exists to solve
//
// A scanner that reports a pattern match as a vulnerability sends the analyst
// hunting for something that is not there. A scanner that reports nothing until
// impact is proven sends them hunting for very little. Both failures come from
// the same place: severity and evidence are the same field, so a module has to
// pick one number and hope it means both.
//
// Here they are separate. A detector states what it observed and how strong
// that observation is; the tier decides the strongest severity that observation
// is allowed to carry. A module cannot name a severity — it has no way to. The
// only way to reach `critical` is to arrive with evidence, because the tier is
// what gates it.
//
// # The tiers
//
//	verified          an exchange on the record demonstrates the impact
//	potential         the pattern is real, the impact is not demonstrated
//	public_by_design  a value the application hands to every visitor on purpose
//
// # Why `potential` is capped rather than dropped
//
// A capped tier is a deliberate decision and it is the one that makes an
// unconfirmed finding worth reading. "Vulnerable version present, exploit
// unconfirmed" is a real and common state: the version banner says 5.4.12, the
// patch that closes the hole landed in 5.4.13, and nobody has confirmed which
// one is running. That finding deserves to be in the report — it is the exact
// thing a triager is paid to resolve — and it does not deserve a severity that
// says the impact was demonstrated. The cap is the whole mechanism: `medium`
// is the loudest an unproven observation is allowed to speak, and the evidence
// field beside it says what was actually tried.
//
// Dropping the finding instead would lose the surface. Raising it instead would
// be a claim nobody made. Capping is the third option and it is the honest one.
package active

import (
	"fmt"
	"sort"
	"strings"
)

// Tier is how much a finding has actually demonstrated.
type Tier string

const (
	// TierVerified means an exchange on the record demonstrates the impact: a
	// database answered, a file came back, a shell echoed a marker. Only this
	// tier may reach high or critical.
	TierVerified Tier = "verified"
	// TierPotential means the pattern is real and the impact is not proven.
	// The finding is reported, because the surface is worth a triager's time,
	// and its severity is capped.
	TierPotential Tier = "potential"
	// TierPublic means the value is published to every visitor by design. A
	// chat widget's site key is not a vulnerability, and reporting it as one
	// is how a report gets dismissed.
	TierPublic Tier = "public_by_design"
)

// Severity is the reported weight of a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank orders severities. Never compare Severity values as strings: "critical"
// sorts before "high" lexically, which is exactly the bug that once left
// unverified findings sitting at the top of a report.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

// atLeast reports whether s is as severe as other.
func (s Severity) atLeast(other Severity) bool { return s.Rank() >= other.Rank() }

// tierCeiling is the loudest severity each tier may carry. It is the single
// place the rule lives, so there is no second copy to drift out of step with
// this one.
//
// `verified` has no ceiling below critical: a proven pre-auth RCE is critical
// and nothing in this package should argue otherwise.
var tierCeiling = map[Tier]Severity{
	TierVerified:  SeverityCritical,
	TierPotential: SeverityMedium,
	TierPublic:    SeverityInfo,
}

// SeverityFor applies the cap.
//
// A requested severity *above* the tier's ceiling is lowered to the ceiling and
// the caller is told, because a module that asked for high and received medium
// has learned something it should act on rather than silently accept.
//
// A request that already equals the ceiling is not a cap. Nothing was lowered,
// and counting it as one would inflate the "capped" figure in the status line
// with rows that were exactly as severe as their evidence allowed.
func SeverityFor(tier Tier, requested Severity) (Severity, bool) {
	ceiling, known := tierCeiling[tier]
	if !known {
		// An unknown tier is refused rather than defaulted. Defaulting would
		// make a typo in a module name read as "verified" somewhere upstream,
		// and the whole point of the table is that a finding's weight is
		// earned by an explicitly named tier.
		return SeverityInfo, false
	}
	if requested.Rank() > ceiling.Rank() {
		return ceiling, true
	}
	return requested, false
}

// PatchState records whether the operator has established that the target still
// carries the defect.
//
// A detector never sets this to anything but UnverifiedPatch, and that is not
// laziness: establishing it requires a patch history the project does not have
// and must not guess at. The value of the field is that it makes the gap
// explicit. A version-gated finding marked `patch_state: unverified` tells the
// triager the one question that decides the report, instead of leaving them to
// wonder whether anyone looked.
type PatchState string

const (
	// UnverifiedPatch means nobody has established whether the target is
	// patched. This is the only state a detector produces.
	UnverifiedPatch PatchState = "unverified"
)

// Spec is what a detector knows. It is the only input to NewFinding, and it has
// no Severity field on purpose: a detector does not get to choose one.
type Spec struct {
	// Module names the detector that produced this observation.
	Module string
	// Title is the one-line claim, phrased so its strength matches the tier.
	// "Potential X (unverified)" and "X, verified by ..." are both correct
	// titles; "X" on its own is not, because it claims more than the tier
	// supports.
	Title string
	// Claimed is the severity the evidence would support if it were proven.
	// The cap is applied to it, so a detector that can only show a pattern may
	// still state that a pattern plus the version would be critical.
	Claimed Severity
	// Tier is what the detector actually demonstrated.
	Tier Tier
	// Point is the surface the observation was made on.
	Point Point
	// Payload is the exact input that produced the observation. It is
	// reproduced verbatim in the report and in the curl, because a triager who
	// cannot rerun the exact bytes cannot confirm or dismiss the finding.
	Payload string
	// Evidence is the observed excerpt, not a description of one. It is what
	// makes the finding checkable instead of asserted.
	Evidence string
	// Description explains the mechanism.
	Description string
	// Remediation names the fix.
	Remediation string
	// Version is the version the target reported, when the finding's existence
	// depends on one. Empty means the finding does not depend on a version and
	// the field is omitted from the report.
	Version string
	// VersionSource names where that version came from, so a number is never
	// presented without its origin: "banner:Server", "meta:generator",
	// "cms-recon".
	VersionSource string
}

// Finding is one reported observation.
type Finding struct {
	ID       string   `json:"id"`
	Module   string   `json:"module"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Tier     Tier     `json:"tier"`
	Endpoint string   `json:"endpoint"`
	Method   string   `json:"method"`
	Param    string   `json:"param,omitempty"`
	Payload  string   `json:"payload,omitempty"`
	// Evidence is the excerpt the tier rests on. It is the field a triager
	// reads first and the field a reviewer reads to decide whether the tier was
	// honest.
	Evidence    string `json:"evidence"`
	PoCCurl     string `json:"poc_curl,omitempty"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	// Capped is true when the tier lowered the claimed severity. It is
	// reported rather than hidden so the count of downgrades is visible: a scan
	// where everything was capped is a scan where nothing was proven, and an
	// operator should be able to see that without reading every row.
	Capped bool `json:"capped"`
	// ChainOf holds the IDs of the findings a chain rule combined. A chain
	// finding without it is a plain finding that happens to say "chain".
	ChainOf []string `json:"chain_of,omitempty"`
	// Version is the version-gated observation, empty when the finding does not
	// depend on one.
	Version string `json:"version,omitempty"`
	// VersionSource is where that version came from.
	VersionSource string `json:"version_source,omitempty"`
	// PatchState is always "unverified" for a detector's output. It is
	// reported so the question that decides the report is visible on the row
	// rather than inferred from its absence.
	PatchState PatchState `json:"patch_state,omitempty"`
}

// ClaimedTooHigh reports whether this finding's severity exceeds what its tier
// permits. It is a self-check for a row: a value that reports a severity its own
// tier forbids is a defect in the row, not a fact about the target.
func (f Finding) ClaimedTooHigh() bool {
	ceiling, known := tierCeiling[f.Tier]
	if !known {
		return f.Severity.Rank() > SeverityMedium.Rank()
	}
	return f.Severity.Rank() > ceiling.Rank()
}

// NeedsVersion reports whether this finding's existence depends on a version.
func (f Finding) NeedsVersion() bool { return f.Version != "" }

// NewFinding turns a detector's observation into a reportable finding.
//
// This is the only constructor, and it is why the tier cannot be bypassed: a
// detector has no other way to produce a Finding, and this function applies the
// cap on its way in. The returned flag says whether the cap bit, so a caller
// that wants to log a downgrade can and a caller that does not can ignore it.
//
// The ID is derived from the surface and the observation rather than from a
// counter, so the same defect found in two consecutive runs has the same ID and
// the two reports diff cleanly. A counter would make every run look like a new
// set of defects.
func NewFinding(spec Spec) (Finding, bool) {
	severity, capped := SeverityFor(spec.Tier, spec.Claimed)
	finding := Finding{
		Module:   spec.Module,
		Title:    spec.Title,
		Severity: severity,
		Tier:     spec.Tier,
		Endpoint: spec.Point.URL,
		Method:   spec.Point.Method,
		Param:    spec.Point.Param,
		Payload:  spec.Payload,
		Evidence: spec.Evidence,
		// The reproduction is the request the detector sent, rebuilt from the
		// same surface and the same payload. It is not a description of it.
		PoCCurl:       CurlPoint(spec.Point, spec.Point.Param, spec.Payload),
		Description:   spec.Description,
		Remediation:   spec.Remediation,
		Capped:        capped,
		Version:       spec.Version,
		VersionSource: spec.VersionSource,
	}
	if finding.NeedsVersion() {
		finding.PatchState = UnverifiedPatch
	}
	finding.ID = FindingID(spec.Module, spec.Point, spec.Payload)
	return finding, capped
}

// FindingID is a stable, content-addressed identity for one observation.
//
// It hashes the module, the surface and the payload, so re-running a scan
// produces the same ID for the same defect and a different ID for a different
// one. That is what makes a run-to-run diff meaningful: an ID that vanished
// means the defect stopped reproducing, and an ID that appeared means it started.
func FindingID(module string, p Point, payload string) string {
	// FNV-1a, 32 bit. A finding ID is a label for deduplication, not a
	// security boundary, and a cryptographic digest here would cost a
	// dependency to defend against nothing.
	var hash uint32 = 2166136261
	write := func(s string) {
		for i := 0; i < len(s); i++ {
			hash ^= uint32(s[i])
			hash *= 16777619
		}
		hash ^= 0
		hash *= 16777619
	}
	write(module)
	write(p.Method)
	write(p.URL)
	write(p.Param)
	write(payload)
	return fmt.Sprintf("ACT-%08X", hash)
}

// SortFindings orders findings so a report is readable and two runs diff.
//
// The order is severity, then tier, then where the finding is, then its ID. The
// first key is what a reader scans; the second is what keeps a chain row above
// the detector rows it was built from, because a chain is a conclusion and its
// ingredients are not; the third groups a report by endpoint, which is how it is
// triaged; the fourth makes it total, so a diff between two reports shows a
// change and not a reshuffle.
//
// Every key after the first is there for the same reason: two findings of equal
// severity must come out in the same order on every run, or a diff shows
// reordering and the analyst cannot tell a fix from a shuffle.
func SortFindings(findings []Finding) {
	rank := func(f Finding) int {
		switch f.Tier {
		case TierVerified:
			return 0
		case TierPotential:
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		if a.Param != b.Param {
			return a.Param < b.Param
		}
		return a.ID < b.ID
	})
}

// Counts summarises a run by severity and tier.
//
// It is reported in the scan's status line rather than left for the operator to
// count, because "12 findings" and "12 findings, none of them proven" are very
// different sentences and only one of them is what the second number is for.
type Counts struct {
	BySeverity map[Severity]int `json:"by_severity"`
	ByTier     map[Tier]int     `json:"by_tier"`
	Total      int              `json:"total"`
	Capped     int              `json:"capped"`
}

// Count summarises findings.
func Count(findings []Finding) Counts {
	counts := Counts{
		BySeverity: map[Severity]int{},
		ByTier:     map[Tier]int{},
	}
	for _, finding := range findings {
		counts.BySeverity[finding.Severity]++
		counts.ByTier[finding.Tier]++
		if finding.Capped {
			counts.Capped++
		}
		counts.Total++
	}
	return counts
}

// Tally renders the counts as one status line.
//
// The capped count is printed even when it is zero when nothing at all was
// verified, because "nothing was proven" is the single most important thing a
// scan can say and it must not require a subtraction to notice.
func (c Counts) Tally() string {
	parts := []string{
		fmt.Sprintf("total %d", c.Total),
		fmt.Sprintf("critical %d", c.BySeverity[SeverityCritical]),
		fmt.Sprintf("high %d", c.BySeverity[SeverityHigh]),
		fmt.Sprintf("medium %d", c.BySeverity[SeverityMedium]),
		fmt.Sprintf("low %d", c.BySeverity[SeverityLow]),
		fmt.Sprintf("info %d", c.BySeverity[SeverityInfo]),
		fmt.Sprintf("verified %d", c.ByTier[TierVerified]),
		fmt.Sprintf("potential %d", c.ByTier[TierPotential]),
		fmt.Sprintf("capped %d", c.Capped),
	}
	return strings.Join(parts, " · ")
}
