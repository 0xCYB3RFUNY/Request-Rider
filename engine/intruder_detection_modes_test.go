package main

// Every attack mode and every transformation has to work with login detection,
// not only Sniper with no transformations. These tests drive the whole runner —
// `intruder.Generate`, the marker replacement, the outbound request and the
// verdict — against a live HTTP login form, because a test of the comparison
// alone stays green if the calibration captured a request the run never sends,
// which is exactly what a transformation chain or an empty marker causes.

import (
	"context"
	"net/http/httptest"
	"testing"

	"intruder/engine/pkg/intruder"
)

func resolvedPayloadSets(t *testing.T, sets [][]string, transforms []intruder.Transform) [][]string {
	t.Helper()
	resolved := make([][]string, len(sets))
	for setIndex, values := range sets {
		resolved[setIndex] = make([]string, len(values))
		for valueIndex, value := range values {
			transformed, err := intruder.TransformPayload(value, transforms)
			if err != nil {
				t.Fatalf("transform %q: %v", value, err)
			}
			resolved[setIndex][valueIndex] = transformed
		}
	}
	return resolved
}

type runOutcome struct {
	run     *attack
	results []map[string]interface{}
	shapes  []string
}

// runIntruderAgainstLoginForm is the whole engine path for one attack: job
// generation, per-shape calibration, execution and verdicts. The form is the only
// thing it takes from the outside, and it is a real HTTP server.
func runIntruderAgainstLoginForm(t *testing.T, form *loginPageForm, mode intruder.AttackMode, sets [][]string, transforms []intruder.Transform, config intruder.DetectionConfig) runOutcome {
	t.Helper()
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "50")
	target := httptest.NewServer(form)
	defer target.Close()

	srv := &server{}
	normalized := normalizedDetectionConfig(&config)
	base := loginRequestInput(target.URL)
	resolved := resolvedPayloadSets(t, sets, transforms)
	jobs, err := intruder.Generate(mode, len(requestPositions(base)), resolved)
	if err != nil {
		t.Fatalf("generate %s: %v", mode, err)
	}
	shapes := ShapesOf(jobs)
	run := &attack{status: "running", total: len(jobs), detection: normalized}
	run.baselines = srv.calibrateLoginBaselines(context.Background(), base, *normalized, transforms, shapes, 1)
	for _, shape := range shapes {
		if run.baselines[shape].Samples == 0 {
			t.Fatalf("no calibration sample for shape %q", shape)
		}
	}
	srv.runAttack(1, run, context.Background(), base, jobs, 0, 1)
	results, count, readErr := run.resultsFrom(0, 0)
	if readErr != nil {
		t.Fatalf("read results: %v", readErr)
	}
	if count != len(jobs) {
		t.Fatalf("results = %d, want %d", count, len(jobs))
	}
	return runOutcome{run: run, results: results, shapes: shapes}
}

func matchedRows(results []map[string]interface{}) ([]map[string]interface{}, bool) {
	var matched []map[string]interface{}
	for _, result := range results {
		verdict, ok := result["detection"].(map[string]interface{})
		if !ok {
			// A row with no verdict cannot be told apart from a row nobody looked
			// at, which is the one outcome this column exists to rule out.
			return nil, false
		}
		if verdict["matched"] == true {
			matched = append(matched, result)
		}
	}
	return matched, true
}

func TestDetectionAcrossEveryAttackMode(t *testing.T) {
	// The honest expectation differs per mode: Sniper and Battering Ram fill the
	// second marker from the first dictionary alone, so on a two-field login form
	// they cannot produce the right pair and the correct verdict is "no match and
	// no noise". Pitchfork and Cluster Bomb pair both dictionaries and find it.
	users := []string{"nobody", "admin"}
	passwords := []string{"nope", adminPassword}
	cases := []struct {
		mode        intruder.AttackMode
		wantMatched int
	}{
		{intruder.Sniper, 0},
		{intruder.BatteringRam, 0},
		{intruder.Pitchfork, 1},
		{intruder.ClusterBomb, 1},
	}
	for _, item := range cases {
		item := item
		t.Run(string(item.mode), func(t *testing.T) {
			outcome := runIntruderAgainstLoginForm(t, newFakeLoginTarget(), item.mode,
				[][]string{users, passwords}, nil, intruder.DetectionConfig{Enabled: true})
			matched, complete := matchedRows(outcome.results)
			if !complete {
				t.Fatal("a result carried no verdict at all")
			}
			if outcome.run.matched != item.wantMatched {
				for _, result := range outcome.results {
					t.Logf("payloads=%q detection=%v", result["payloads"], result["detection"])
				}
				t.Fatalf("mode %s matched %d rows, want %d", item.mode, outcome.run.matched, item.wantMatched)
			}
			if item.wantMatched == 1 {
				values := matched[0]["payloads"].([]string)
				if values[0] != "admin" || values[1] != adminPassword {
					t.Fatalf("the matched row is %v, want the real credential", values)
				}
			}
			// Sniper and Battering Ram send rows with an empty marker. Those rows
			// used to be reported as matches, because one baseline cannot describe
			// both a filled and an empty form; each shape now has its own.
			for _, shape := range outcome.shapes {
				if strings_ContainsRune(shape, 'x') && outcome.run.matched != 0 {
					t.Fatalf("empty-marker shape %q produced matches", shape)
				}
			}
		})
	}
}

func strings_ContainsRune(shape string, target rune) bool {
	for _, symbol := range shape {
		if symbol == target {
			return true
		}
	}
	return false
}

// The transformation chains that leave a credential intact must still find it.
// A chain that rewrites the value (`base64Encode`, `prepend`, `hexEncode`) cannot
// produce the real credential, so the honest assertion for those is the opposite
// one and no less strict: not a single row is flagged. That is the assertion that
// catches a calibration taken without the chain, because the baseline then
// describes a different request and every row differs from it.
func TestDetectionWithCredentialPreservingTransformations(t *testing.T) {
	chains := []struct {
		name         string
		transforms   []intruder.Transform
		wantPassword string
	}{
		{"url encode", []intruder.Transform{{Operation: "urlEncode"}}, adminPassword},
		{"trim", []intruder.Transform{{Operation: "trim"}}, adminPassword},
		{"whitespace", []intruder.Transform{{Operation: "whitespaceNormalize"}}, adminPassword},
		{"html entity", []intruder.Transform{{Operation: "htmlEntityEncode"}}, adminPassword},
		{"url encode then trim", []intruder.Transform{{Operation: "urlEncode"}, {Operation: "trim"}}, adminPassword},
		{"lowercase", []intruder.Transform{{Operation: "lowercase"}}, "correcthorsebattery9!"},
		{"json escape", []intruder.Transform{{Operation: "jsonEscape"}}, adminPassword},
	}
	for _, item := range chains {
		item := item
		t.Run(item.name, func(t *testing.T) {
			form := &loginPageForm{password: item.wantPassword}
			outcome := runIntruderAgainstLoginForm(t, form, intruder.Pitchfork,
				[][]string{{"nobody", "admin"}, {"nope", item.wantPassword}},
				item.transforms, intruder.DetectionConfig{Enabled: true, Tolerance: 0})
			if outcome.run.matched != 1 {
				for _, result := range outcome.results {
					t.Logf("payloads=%q detection=%v", result["payloads"], result["detection"])
				}
				t.Fatalf("matched %d rows, want exactly the one real credential", outcome.run.matched)
			}
		})
	}
}

func TestDetectionWithLengthChangingTransformations(t *testing.T) {
	// These chains rewrite the payload, so the real credential never reaches the
	// form and no row may be flagged. With a zero tolerance even a one-byte
	// difference would flag every row, which is what makes this the check that a
	// calibration taken without the chain cannot survive.
	chains := []struct {
		name       string
		transforms []intruder.Transform
	}{
		{"prepend", []intruder.Transform{{Operation: "prepend", Value: "x"}}},
		{"append", []intruder.Transform{{Operation: "append", Value: "yy"}}},
		{"base64 encode", []intruder.Transform{{Operation: "base64Encode"}}},
		{"hex encode", []intruder.Transform{{Operation: "hexEncode"}}},
		{"unicode escape", []intruder.Transform{{Operation: "unicodeEscape"}}},
		{"uppercase", []intruder.Transform{{Operation: "uppercase"}}},
		{"base64 url encode", []intruder.Transform{{Operation: "base64UrlEncode"}}},
	}
	for _, item := range chains {
		item := item
		t.Run(item.name, func(t *testing.T) {
			outcome := runIntruderAgainstLoginForm(t, newFakeLoginTarget(), intruder.Pitchfork,
				[][]string{{"nobody", "admin"}, {"nope", adminPassword}},
				item.transforms, intruder.DetectionConfig{Enabled: true, Tolerance: 0})
			if outcome.run.matched != 0 {
				for _, result := range outcome.results {
					t.Logf("payloads=%q detection=%v", result["payloads"], result["detection"])
				}
				t.Fatalf("matched %d rows although the credential was rewritten and no row is a success", outcome.run.matched)
			}
		})
	}
}

func TestShapesOfCoverEveryGeneratedJob(t *testing.T) {
	sets := [][]string{{"a", "b"}, {"c", "d"}}
	cases := []struct {
		mode intruder.AttackMode
		want []string
	}{
		{intruder.Sniper, []string{"1x", "x1"}},
		{intruder.BatteringRam, []string{"11"}},
		{intruder.Pitchfork, []string{"11"}},
		{intruder.ClusterBomb, []string{"11"}},
	}
	for _, item := range cases {
		jobs, err := intruder.Generate(item.mode, 2, sets)
		if err != nil {
			t.Fatalf("generate %s: %v", item.mode, err)
		}
		got := ShapesOf(jobs)
		known := map[string]bool{}
		for _, shape := range got {
			known[shape] = true
		}
		if len(got) != len(item.want) {
			t.Fatalf("%s shapes = %v, want %v", item.mode, got, item.want)
		}
		for index, shape := range item.want {
			if got[index] != shape {
				t.Fatalf("%s shapes = %v, want %v", item.mode, got, item.want)
			}
		}
		// Every job must map to a shape calibration exists for, otherwise the
		// detector would silently compare against nothing.
		for _, job := range jobs {
			if !known[ShapeOf(job.Values)] {
				t.Fatalf("%s produced a job with no calibrated shape: %q", item.mode, job.Values)
			}
		}
	}
}

func TestCalibrationStopsOnAnUnusableChain(t *testing.T) {
	t.Setenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS", "50")
	target := httptest.NewServer(newFakeLoginTarget())
	defer target.Close()
	srv := &server{}
	config := normalizedDetectionConfig(&intruder.DetectionConfig{Enabled: true})
	baselines := srv.calibrateLoginBaselines(context.Background(), loginRequestInput(target.URL), *config,
		[]intruder.Transform{{Operation: "no_such_operation"}}, []string{"11"}, 1)
	if len(baselines) != 0 {
		t.Fatalf("baselines = %+v, want nothing rather than a differently-shaped request", baselines)
	}
}

// A blank line in a dictionary is an ordinary thing an operator ends up with,
// and it produces a job whose markers are not all filled. Such a job must be
// compared with the baseline captured for the same shape, not with the fully
// filled one: the page that echoes an empty username is shorter, and against the
// wrong baseline that difference reads as a match. Every expectation here is "no
// match", which is what makes it a check on the lookup rather than on detection.
func TestBlankDictionaryLineIsNotAMatch(t *testing.T) {
	outcome := runIntruderAgainstLoginForm(t, newFakeLoginTarget(), intruder.Pitchfork,
		[][]string{{"nobody", ""}, {"nope", "second-wrong"}},
		nil, intruder.DetectionConfig{Enabled: true, Tolerance: 0})
	if outcome.run.matched != 0 {
		for _, result := range outcome.results {
			t.Logf("payloads=%q detection=%v", result["payloads"], result["detection"])
		}
		t.Fatalf("a job with a blank dictionary line was flagged: %d matches", outcome.run.matched)
	}
	// Both shapes have to be calibrated for that verdict to be about the lookup.
	if len(outcome.shapes) != 2 {
		t.Fatalf("shapes = %v, want one per filled/empty arrangement", outcome.shapes)
	}
}
