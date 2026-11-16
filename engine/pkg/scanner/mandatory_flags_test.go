package scanner

import (
	"testing"
)

// The operator's rule, 2026-10-05: `-t`, `-esc` and `-nss` are mandatory for a
// template run, and the capability flags are added on top for the templates that
// need them.
//
// `-esc` used to be reachable only through `capabilityFlag[CapabilitySelfContained]`,
// so it travelled only with a batch whose documents declared `self-contained:
// true`. A run over a folder with no such document therefore went out without
// it, and any self-contained template the binary chose to load on its own was a
// template the run had not declared — the same class of quiet loss the file's
// other flag decisions are written against.
//
// `-nss` is nuclei's `-no-strict-syntax`, "disable strict syntax check on
// templates" on v3.11.1. Without it the binary can refuse a document and drop it
// from the run while the report counts it as planned: the plan lists the file,
// the run produces no row for it, and nothing in `stats` says why.
//
// `-as` is measured and deliberately absent. It rewrites template tags from
// target technology detection, which changes *which* templates run; it is not a
// flag that makes a template executable, so it is not one of the mandatory ones.

func TestEveryInvocationCarriesTheMandatoryTemplateFlags(t *testing.T) {
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	for _, flag := range []string{"-t", "-esc", "-nss"} {
		if !hasArg(args, flag) {
			t.Fatalf("%s is mandatory for a template run and is missing from %v", flag, args)
		}
	}
	if hasArg(args, "-as") {
		t.Fatalf("-as rewrites tags from target technology detection and was measured out: %v", args)
	}
}

func TestMandatoryEscIsNotEmittedTwiceForASelfContainedBatch(t *testing.T) {
	// `-esc` is on every invocation now, so the capability pass must not add it
	// a second time for the batch that declares `self-contained: true`. A
	// repeated boolean flag is harmless to the binary and wrong in the run
	// diagnostics the operator reads.
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []Capability{CapabilityCode, CapabilitySelfContained},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	for _, flag := range []string{"-esc", "-nss"} {
		if got := countArg(args, flag); got != 1 {
			t.Fatalf("%s appears %d times in %v, want exactly 1", flag, got, args)
		}
	}
	// The other capability flags still travel: `-esc` becoming mandatory is not
	// a reason to drop `-code`.
	if !hasArg(args, "-code") {
		t.Fatalf("-code is still needed by a code batch and is missing from %v", args)
	}
}

func TestLegacyTypeFilterIsRejectedAndCapabilityFlagsRemainAutomatic(t *testing.T) {
	if _, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Options: NucleiOptions{Types: []string{"http"}},
	}); err == nil {
		t.Fatal("legacy types filter was accepted")
	}

	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		Protocols: []Capability{CapabilityCode, CapabilitySelfContained},
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if !hasArg(args, "-esc") || !hasArg(args, "-nss") || !hasArg(args, "-code") {
		t.Fatalf("mandatory or template capability flags are missing: %v", args)
	}
	if hasArg(args, "-pt") {
		t.Fatalf("folder-category selection must not emit -pt: %v", args)
	}
	if got := countArg(args, "-esc"); got != 1 {
		t.Fatalf("-esc was emitted %d times: %v", got, args)
	}
}

func countArg(args []string, flag string) int {
	count := 0
	for _, arg := range args {
		if arg == flag {
			count++
		}
	}
	return count
}
