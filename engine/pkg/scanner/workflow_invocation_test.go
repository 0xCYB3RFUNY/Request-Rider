package scanner

import (
	"strings"
	"testing"
)

// A workflow is not a template, and nuclei loads the two through different
// flags. This file pins the argument that makes a staged workflow executable at
// all, because the failure it prevents is invisible from the outside: the
// template is parsed, staged, planned, batched and reported as a row — and then
// the binary exits 1 with "no templates provided for scan" and executes nothing.
//
// What the binary says, measured on v3.11.1 against this corpus:
//
//	$ nuclei -t <dir of 207 workflow templates> -u https://example.ru/
//	[FTL] Could not run nuclei: no templates provided for scan
//	$ nuclei -w <same dir> -u https://example.ru/
//	[INF] Scan completed in 5.099974283s. No results found.        exit 0
//
// and the flag is not additive noise — on 458 http templates, `-t` alone and
// `-t -w` together both produced exactly 330 matches.
//
// The capability measurement behind this is in DEVELOPMENT_LOG.md.

func TestTheInvocationNamesTheDirectoryAsAWorkflowSourceToo(t *testing.T) {
	args, err := buildNucleiArgs("https://example.ru/", t.TempDir(), NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	joined := strings.Join(args, " ")

	templateDir := valueAfter(args, "-t")
	workflowDir := valueAfter(args, "-w")
	if workflowDir == "" {
		t.Fatalf("the invocation has no -w flag: %s", joined)
	}
	if workflowDir != templateDir {
		t.Fatalf("-w names %q but -t names %q; a workflow staged in one directory and read from another is never executed",
			workflowDir, templateDir)
	}
	// `-pt` is never a substitute. It *replaces* the whole type set, so
	// `-pt workflow` on a mixed folder yields zero templates, which is the same
	// empty run this file exists to prevent.
	for _, arg := range args {
		if arg == "-pt" || arg == "-type" {
			t.Fatalf("args carry %s: it replaces the type set rather than adding a workflow source: %s", arg, joined)
		}
	}
}

// Category selection is performed on staged paths before planning; capability
// flags do not replace either source directory.
func TestTheWorkflowSourceSurvivesTemplateCapabilityFlags(t *testing.T) {
	args, err := buildNucleiArgs("https://example.ru/", t.TempDir(), NucleiRequest{
		Protocols: []Capability{CapabilityCode},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if valueAfter(args, "-w") == "" {
		t.Fatalf("a capability flag dropped the workflow source: %s", strings.Join(args, " "))
	}
	if valueAfter(args, "-w") != valueAfter(args, "-t") {
		t.Fatalf("workflow and template sources diverged: %s", strings.Join(args, " "))
	}
	if !containsString(args, "-code") {
		t.Fatalf("selected template capability was not added: %s", strings.Join(args, " "))
	}
}

// valueAfter returns the argument following `flag`, or "" when the flag is
// absent. The flag may also be written in its long form, so both spellings are
// accepted — the argument vector is a report artefact, and a test that only
// understood the short spelling would pass on a regression that kept the long
// one and lost the effect.
func valueAfter(args []string, flag string) string {
	for index, arg := range args {
		if arg == flag && index+1 < len(args) {
			return args[index+1]
		}
		if arg == "-workflows" && flag == "-w" && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}
