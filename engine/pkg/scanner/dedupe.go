package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file removes byte-identical template copies before the scan plans a
// single run, and records what it removed so the report can say so.
//
// The comparison is over content, never over a name. A merged community
// template tree is mostly copies: measured on 734 748 files (6.5 GB) there were
// 382 396 unique documents and 564 857 duplicates, so 77 % of the work the
// scanner would otherwise do was loading the same template under a different
// file name. Comparing names would miss every one of those, because the copies
// live in different folders with different names.

// DuplicateGroup is one set of files whose contents are identical. The first
// member is the one that will be executed; the rest are the copies.
type DuplicateGroup struct {
	// Digest is the SHA-256 of the shared content and the group's identity.
	Digest string
	// Kept is the uploaded path of the file that will be executed.
	Kept string
	// Copies are the uploaded paths that collapse into Kept.
	Copies []string
}

// Size reports how many files the group covers in total.
func (g DuplicateGroup) Size() int { return len(g.Copies) + 1 }

// DuplicateReport is the whole deduplication result for one staged set.
type DuplicateReport struct {
	// Files is how many files were examined.
	Files int
	// Unique is how many distinct documents they contained.
	Unique int
	// Groups lists the duplicate sets, largest first, so the report can name
	// them without listing hundreds of thousands of aliases.
	Groups []DuplicateGroup
	// GroupLimit is how many groups are retained in Groups.
	GroupLimit int
	// TotalCollapsed is how many files were removed by deduplication.
	TotalCollapsed int
}

// Collapsed returns how many duplicate files were removed.
func (r DuplicateReport) Collapsed() int { return r.TotalCollapsed }

// duplicateGroupLimit is how many duplicate sets a report names. A 6.5 GB
// collection can hold hundreds of thousands of groups, and a report that lists
// all of them is neither readable nor useful; the real counters are reported
// separately and never rounded down.
const duplicateGroupLimit = 200

// DedupeStaged collapses byte-identical staged files, keeping the first
// occurrence of every document. The returned files keep their original order, so
// a folder's reading order is unchanged, and every removed file is attributed to
// the file that replaced it.
//
// The digest comes from the document as it was parsed, which is the same bytes
// the binary reads from the staged path — so a 6.5 GB collection is hashed once,
// while it is being staged, instead of a second time here.
func DedupeStaged(staged []StagedFile) ([]StagedFile, DuplicateReport) {
	report := DuplicateReport{Files: len(staged), GroupLimit: duplicateGroupLimit}
	byDigest := make(map[string]int, len(staged))
	groupIndex := map[string]int{}
	kept := make([]StagedFile, 0, len(staged))
	duplicates := make([]StagedFile, 0)
	for _, file := range staged {
		// A file that never reached the disk has no content to compare, and it
		// is already reported as invalid, so it passes through untouched.
		if file.StagedPath == "" || file.Meta == nil || file.Meta.Digest == "" {
			kept = append(kept, file)
			continue
		}
		digest := file.Meta.Digest
		if first, seen := byDigest[digest]; seen {
			group, tracked := groupIndex[digest]
			if !tracked {
				group = len(report.Groups)
				report.Groups = append(report.Groups, DuplicateGroup{
					Digest: digest,
					Kept:   reportPath(kept[first]),
				})
				groupIndex[digest] = group
			}
			report.Groups[group].Copies = append(report.Groups[group].Copies, reportPath(file))
			report.TotalCollapsed++
			duplicates = append(duplicates, file)
			continue
		}
		// Unique counts distinct documents, so it moves on the first sighting only:
		// a folder of 734 748 files that holds 382 396 templates has to say
		// 382 396 here, not 734 748.
		report.Unique++
		byDigest[digest] = len(kept)
		kept = append(kept, file)
	}
	sort.SliceStable(report.Groups, func(i, j int) bool {
		return len(report.Groups[i].Copies) > len(report.Groups[j].Copies)
	})
	if len(report.Groups) > duplicateGroupLimit {
		report.Groups = report.Groups[:duplicateGroupLimit]
	}
	// The removed copies are returned as their own results rather than dropped:
	// the operator uploaded them and has to be told what became of each one.
	return append(kept, duplicates...), report
}

func reportPath(file StagedFile) string {
	return displayRelativePath(file.RelativePath, file.UploadName)
}

// duplicateReason names a removed copy and the file that took its place, so a
// folder report can group it instead of losing it.
func duplicateReason(copy string, group DuplicateGroup) string {
	extra := ""
	if total := group.Size() - 1; total > 1 {
		extra = fmt.Sprintf(" %d identical copies collapse into that file.", total)
	}
	return fmt.Sprintf(
		"Not run separately: this file is byte-identical to %s (SHA-256 %s…), so it is the same template "+
			"under a different name and one copy is enough.%s",
		group.Kept, shortDigest(group.Digest), extra)
}

func shortDigest(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:16]
}

// summariseDuplicates renders the deduplication result for the run statistics.
func summariseDuplicates(report DuplicateReport) map[string]interface{} {
	summary := map[string]interface{}{
		"files_uploaded": report.Files,
		"unique_content": report.Unique,
		"collapsed":      report.TotalCollapsed,
	}
	if len(report.Groups) == 0 {
		return summary
	}
	// A group can hold a hundred thousand aliases, and a report that lists all of
	// them is unreadable and enormous, so the head is shown with the real
	// remainder named behind it.
	const shown = 10
	groups := make([]map[string]interface{}, 0, len(report.Groups))
	for _, group := range report.Groups {
		copies := make([]string, 0, shown+1)
		for index, copy := range group.Copies {
			if index >= shown {
				copies = append(copies, fmt.Sprintf("… and %d more", len(group.Copies)-shown))
				break
			}
			copies = append(copies, copy)
		}
		groups = append(groups, map[string]interface{}{
			"digest": group.Digest,
			"kept":   group.Kept,
			"copies": len(group.Copies),
			"paths":  copies,
		})
	}
	summary["groups"] = groups
	return summary
}

// relativeStagePath is the path of a staged file inside the staging directory,
// in slash form. A batch directory receives that relative path, so a batch
// keeps the uploaded folder layout and a report path can be traced back to it.
func relativeStagePath(stagingDir, stagedPath string) string {
	relative, err := filepath.Rel(stagingDir, stagedPath)
	if err != nil {
		return filepath.ToSlash(stagedPath)
	}
	return filepath.ToSlash(relative)
}

// linkOrCopy puts a staged template into a batch directory. A hard link is used
// when the filesystem allows it so a large corpus is not written twice, and the
// bytes are copied when it does not — the batch must hold real content, because
// the binary reads it by path.
func linkOrCopy(source, target string) error {
	if err := os.Link(source, target); err == nil {
		return nil
	}
	payload, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(target, payload, 0o600)
}

// batchDirName renders a stable directory name for one batch of the plan.
func batchDirName(index int, key capabilityKey) string {
	name := fmt.Sprintf("batch-%05d", index)
	if key != "" {
		name += "-" + sanitizeCapabilityKey(string(key))
	}
	return name
}

func sanitizeCapabilityKey(raw string) string {
	var builder strings.Builder
	for _, symbol := range raw {
		switch {
		case symbol >= 'a' && symbol <= 'z', symbol >= 'A' && symbol <= 'Z',
			symbol >= '0' && symbol <= '9', symbol == '-':
			builder.WriteRune(symbol)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}
