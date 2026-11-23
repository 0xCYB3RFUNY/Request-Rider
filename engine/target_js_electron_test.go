package main

// Tests for the Electron exposure category.
//
// The source list is `doyensec/awesome-electronjs-hacking`. What the category is
// for is narrower than "this bundle mentions Electron": every write-up in that
// list runs the same chain — an injection into the renderer is unremarkable on
// its own, and becomes remote code execution or an arbitrary file read once the
// renderer has `nodeIntegration`, no context isolation, or a disabled sandbox.
// The flags are what decide what an injection is worth, and they are readable in
// the bundle, which is what makes them worth a row.
//
// Two things are therefore tested that the marker tables above do not need: that
// the chain is reported, and that the *configuration* is reported separately
// from the mere presence of the word, because a bundle can name Electron in a
// comment and be configured correctly.

import (
	"strings"
	"testing"
)

// TestAnElectronBundleReportsWhatAnInjectionBecomes is the positive claim, and
// it is stated as the write-ups state it: the flags that turn a renderer
// injection into code execution are named in the bundle and come back.
func TestAnElectronBundleReportsWhatAnInjectionBecomes(t *testing.T) {
	analysis := analysisOf(t, `
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,
    contextIsolation: false,
    sandbox: false,
    preload: __dirname + "/preload.js"
  }
});
shell.openExternal(link);
`)
	for _, marker := range []string{"nodeIntegration", "contextIsolation: false", "sandbox:false"} {
		if _, ok := findingOf(analysis.Findings, jsFindingElectronExposure, marker); !ok {
			t.Errorf("the %q exposure is missing: %+v", marker, analysis.Findings)
		}
	}
}

// TestTheNodeIntegrationFlagIsHighAndThePathIsNot checks that the category
// carries a judgement rather than a list: the flag that makes an injection run
// as Node is worth more than the fact that the app has a preload file, and a
// table that ranked them the same would tell the reader nothing.
func TestTheNodeIntegrationFlagIsHighAndThePathIsNot(t *testing.T) {
	analysis := analysisOf(t, `
const win = new BrowserWindow({webPreferences: {nodeIntegration: true, preload: __dirname + "/preload.js"}});
`)
	flag, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "nodeIntegration")
	if !ok {
		t.Fatalf("nodeIntegration is missing: %+v", analysis.Findings)
	}
	if flag.Severity != jsSeverityHigh {
		t.Errorf("nodeIntegration severity = %q, want %q", flag.Severity, jsSeverityHigh)
	}
	path, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "__dirname")
	if !ok {
		t.Fatalf("__dirname is missing: %+v", analysis.Findings)
	}
	if path.Severity != jsSeverityInfo {
		t.Errorf("__dirname severity = %q, want %q: a path inside the bundle is inventory, not evidence",
			path.Severity, jsSeverityInfo)
	}
}

// TestTheSpacesAroundFalseAreStillTheDisabledFlag is the control for a real
// minifier: `contextIsolation: false` and `contextIsolation:false` are the same
// statement to a reader and different byte sequences, and a bundle built by any
// of them carries one or the other. Reading only one form would miss half of the
// bundles the category exists for.
func TestTheSpacesAroundFalseAreStillTheDisabledFlag(t *testing.T) {
	// The four spellings a formatter actually produces. The value on its own line
	// is the one that a hand-written source has and that a substring search never
	// matched; it is listed first because it is the case the first version of
	// this table was blind to.
	for name, source := range map[string]string{
		"value on the next line":  "const w = new BrowserWindow({webPreferences:{\n  contextIsolation:\n    false\n}});",
		"one space":               `new BrowserWindow({webPreferences:{contextIsolation: false}});`,
		"no space":                `new BrowserWindow({webPreferences:{contextIsolation:false}});`,
		"spaces around the colon": "new BrowserWindow({webPreferences:{contextIsolation : false}});",
	} {
		analysis := analysisOf(t, source)
		finding, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "contextIsolation: false")
		if !ok {
			t.Errorf("%s: the disabled flag is missing: %+v", name, analysis.Findings)
			continue
		}
		if finding.Severity != jsSeverityHigh {
			t.Errorf("%s: severity = %q, want %q", name, finding.Severity, jsSeverityHigh)
		}
	}
	// Two occurrences of the same flag, written differently, are two findings of
	// one risk, so the row says two.
	both := analysisOf(t, `
new BrowserWindow({webPreferences:{contextIsolation:false}});
other({contextIsolation: false});
`)
	finding, ok := findingOf(both.Findings, jsFindingElectronExposure, "contextIsolation: false")
	if !ok {
		t.Fatalf("neither form was found: %+v", both.Findings)
	}
	if !strings.Contains(finding.Evidence, "2 time") {
		t.Errorf("evidence = %q, want both occurrences counted", finding.Evidence)
	}
}

// TestTheEnabledFormIsNotTheDisabledFlag is the other side of the same rule: a
// pattern wide enough to see every spacing of the flag must not read
// `contextIsolation: true` as the flag being off. A category that fires on the
// secure configuration is worse than no category.
func TestTheEnabledFormIsNotTheDisabledFlag(t *testing.T) {
	analysis := analysisOf(t, `new BrowserWindow({webPreferences:{contextIsolation: true, nodeIntegration: false}});`)
	if finding, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "contextIsolation: false"); ok {
		t.Errorf("the secure configuration produced a disabled-flag row: %+v", finding)
	}
	if _, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "nodeIntegration"); ok {
		t.Errorf("nodeIntegration: false produced an exposure row: %+v", analysis.Findings)
	}
}

// TestAWebBundleIsNotAccusedOfElectron is the control that keeps the category
// usable: an ordinary web bundle is not an Electron application, and a category
// that fires on everything is a category nobody reads.
func TestAWebBundleIsNotAccusedOfElectron(t *testing.T) {
	analysis := analysisOf(t, `
const config = {api: "https://api.example.com"};
async function load(id) {
  const r = await fetch("/api/v1/users/" + id);
  document.getElementById("out").textContent = await r.text();
}
`)
	if finding, ok := findingOf(analysis.Findings, jsFindingElectronExposure, ""); ok {
		t.Errorf("an ordinary web bundle produced an Electron row: %+v", finding)
	}
}

// TestTheFileReadPathIsReportedSeparatelyFromTheFlag pins the other half of the
// chain the write-ups use: the payload of most of them is reading a file, and a
// renderer that can `require('fs')` needs something to point it at. `asar.unpack`
// is the pointer that appears in a shipped bundle, so it is reported on its own.
func TestTheFileReadPathIsReportedSeparatelyFromTheFlag(t *testing.T) {
	analysis := analysisOf(t, `
const win = new BrowserWindow({webPreferences:{nodeIntegration:true}});
const lib = path.join(app.asar, "unpacked", "lib");
fs.readFileSync(lib);
`)
	if _, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "nodeIntegration"); !ok {
		t.Fatalf("nodeIntegration is missing: %+v", analysis.Findings)
	}
	if _, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "readFileSync"); !ok {
		t.Errorf("the renderer file read is missing: %+v", analysis.Findings)
	}
	// The path itself is not a finding: `app.asar` is where every packaged app
	// keeps its own code, and reporting it would drown the two rows above.
	if finding, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "app.asar"); ok &&
		finding.Severity == jsSeverityHigh {
		t.Errorf("app.asar was raised above info: %+v", finding)
	}
}

// TestTheElectronRowIsReadBeforeTheInventory checks where the row lands in the
// record.
//
// The categories are ordered by what a reader has to act on, and the Electron
// flags answer the same question the Vite markers answer — "what does an
// injection into this page become" — so they belong next to them and above the
// rows that are inventory. A row that sorts below the emails is a row nobody
// reads, and the table exists to be read.
func TestTheElectronRowIsReadBeforeTheInventory(t *testing.T) {
	analysis := analysisOf(t, `
const owner = "security@corp-internal.test";
new BrowserWindow({webPreferences:{nodeIntegration:true}});
`)
	electron, ok := findingOf(analysis.Findings, jsFindingElectronExposure, "nodeIntegration")
	if !ok {
		t.Fatalf("nodeIntegration is missing: %+v", analysis.Findings)
	}
	mail, ok := findingOf(analysis.Findings, jsFindingEmail, "corp-internal.test")
	if !ok {
		t.Fatalf("the email row is missing, so the ordering cannot be checked: %+v", analysis.Findings)
	}
	if jsFindingRank(electron.Kind) >= jsFindingRank(mail.Kind) {
		t.Errorf("electron rank %d is not above the email rank %d",
			jsFindingRank(electron.Kind), jsFindingRank(mail.Kind))
	}
	vite := jsFindingRank(jsFindingViteDevServer)
	if jsFindingRank(electron.Kind) <= vite {
		t.Errorf("electron rank %d should sit below the bundler markers at %d",
			jsFindingRank(electron.Kind), vite)
	}
}

// TestTheCategoriesDoNotShareARank keeps the ordering total.
//
// Two kinds with the same rank means their relative order in the record is
// whatever the sort's stability happens to produce, and the two rows then swap
// places between runs of the same file. That is invisible in a test that checks
// one category and maddening in a report that is compared against the previous
// one.
func TestTheCategoriesDoNotShareARank(t *testing.T) {
	seen := map[int]string{}
	for _, kind := range []string{
		jsFindingSink, jsFindingFunction, jsFindingHardcodedAuthToken,
		jsFindingPrivilegedEndpoint, jsFindingViteDevServer, jsFindingElectronExposure,
		jsFindingInternalService, jsFindingEmail, jsFindingSuspicious, jsFindingRoute,
	} {
		rank := jsFindingRank(kind)
		if other, ok := seen[rank]; ok {
			t.Errorf("%q and %q both rank %d; their order in the record is unstable",
				other, kind, rank)
		}
		seen[rank] = kind
	}
}
