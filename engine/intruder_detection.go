package main

// Wiring between the Intruder runner and the login-success detector lives here
// rather than in main.go for the same reason the Python side has separate view
// modules: main.go is shared with every other session, and this feature needs
// four call sites, not a new subsystem in the middle of the file. The decision
// logic itself is in pkg/intruder/detection.go and is pure, so it is tested
// without a server.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"

	"intruder/engine/pkg/intruder"
)

// calibrationToken returns a value that cannot be a real credential. It is
// 32 hexadecimal characters, which is why the target answers a failed login
// rather than anything else: no account is named by it and no password can be
// it. The alternative — reusing the first payload of the run — would make the
// baseline depend on the dictionary and could capture a *successful* login,
// which would invert the comparison the whole feature rests on.
func calibrationToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// buildDetectionSample reduces one executed result to the parts that decide a
// login. Body and headers stay out of the sample on purpose: the sample is
// stored in the attack snapshot and in every result's context, and a copy of
// the target's page in each of them is not a decision, it is a second copy of
// the evidence that already travels with the result.
func buildDetectionSample(result map[string]interface{}, injected []string) intruder.Sample {
	headers := stringMapValue(result["headers"])
	body := stringValue(result["body"])
	binary := body == "" && result["body_base64"] != nil
	sample := intruder.Sample{Status: intValue(result["status"])}
	if binary {
		// A binary body has no fingerprint worth comparing and no length worth
		// measuring: every mask would hit it at once and report a difference
		// that says nothing. The raw size is kept so a binary answer is still
		// told apart from another binary answer of another size, and the empty
		// fingerprint keeps it out of the body comparison instead of turning the
		// signal into noise.
		sample.Length = intValue(result["size"])
	} else {
		sample.Length = intruder.NormalizedBodyLength(body, injected)
		sample.Fingerprint = intruder.FingerprintBody(body, injected)
	}
	sample.Location = headerLookup(headers, "Location")
	for _, name := range cookieNames(headers) {
		sample.Cookies = append(sample.Cookies, name)
	}
	if errValue, ok := result["error"]; ok && errValue != nil {
		// A failed request is not a deviation of the login page, it is a
		// missing one. Reporting it as a difference would make every network
		// error look like a successful login.
		sample.Status = 0
	}
	return sample
}

func headerLookup(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// cookiePart matches one `name=value` pair at the start of a Set-Cookie part.
// It is the rule that tells a cookie apart from the rest of the header, and it
// matters more than it looks: a Set-Cookie carries an `Expires` attribute whose
// value contains a comma of its own, so splitting the flattened header on every
// comma cuts `expires=Wed, 11 Jan 1984 05:00:00 GMT` in half.
//
// Measured on a live Django admin: the naive split produced cookie names such as
// "30 Sep 2027 21:19:36 GMT", a name that exists in no response but the one being
// compared, so the cookie signal fired on every row of the run and every login
// read as a match.
var cookiePart = regexp.MustCompile(`^\s*([A-Za-z0-9!#$%&'*+\-._^` + "`" + `|~]+)=`)

// cookieNames reads the cookie names out of a flattened Set-Cookie header. The
// engine joins repeated headers with ", ", so each cookie carries its own
// name=value; values are dropped because a session id changes on every login and
// comparing it would flag the target's own housekeeping.
func cookieNames(headers map[string]string) []string {
	raw := headerLookup(headers, "Set-Cookie")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var names []string
	for _, part := range splitCookieHeader(raw) {
		if match := cookiePart.FindStringSubmatch(part); match != nil {
			names = append(names, match[1])
		}
	}
	return names
}

// splitCookieHeader cuts the flattened header on the commas that separate
// cookies and leaves the one inside an `Expires` date alone.
func splitCookieHeader(raw string) []string {
	var parts []string
	start := 0
	for index := 0; index < len(raw); index++ {
		if raw[index] != ',' {
			continue
		}
		// Look at what follows: a cookie starts with a name and an `=`, and a date
		// continues with a day number or a month name, neither of which can be a
		// cookie name followed by `=`.
		rest := strings.TrimLeft(raw[index+1:], " \t")
		if rest == "" || rest[0] == ';' {
			continue
		}
		parts = append(parts, raw[start:index])
		start = index + 1
	}
	parts = append(parts, raw[start:])
	return parts
}

// calibrateLoginBaselines captures one failed-login baseline per *shape* the run
// will actually send, where a shape is which marker positions carry a value.
//
// One baseline for the whole run is not enough, and this is a measured defect
// rather than a guess. A login page usually echoes the submitted username, so
// Sniper's jobs — which leave every other marker empty — send an empty username
// and get a genuinely shorter page back. Compared against a baseline captured
// with a value in every position, every one of those rows reads as a deviation
// and the run flags its own dictionary shape instead of a successful login.
// Measured on the login fixture: Sniper reported 2 matches out of 4, both of
// them rows with an empty username.
//
// So the calibration is taken per shape. For Sniper and Battering Ram that is at
// most two shapes per marker; for Pitchfork and Cluster Bomb there is one, which
// is why those modes worked from the start.
//
// The token goes through the run's own transformation chain first. Skipping that
// would be a second measured defect: `base64Encode` makes the submitted value
// three times longer and `prepend` adds a fixed prefix, so a baseline captured
// without the chain describes a request the run never sends — the same
// whole-corpus noise, from the other direction.
//
// The calibration traffic is published like any other exchange, so it appears in
// Traffic and History next to the run instead of being invisible extra requests,
// and every count is reported in the log and in the snapshot.
func (s *server) calibrateLoginBaselines(ctx context.Context, base requestInput, config intruder.DetectionConfig, transforms []intruder.Transform, shapes []string, attackID uint64) map[string]intruder.Baseline {
	positions := requestPositions(base)
	baselines := map[string]intruder.Baseline{}
	if len(positions) == 0 {
		log.Printf("[INTRUDER %d] calibration_skipped reason=no_markers", attackID)
		return baselines
	}
	token, err := calibrationToken()
	if err != nil {
		log.Printf("[INTRUDER %d] calibration_skipped reason=%v", attackID, logError(err))
		return baselines
	}
	token, err = intruder.TransformPayload(token, transforms)
	if err != nil {
		// The handler already rejected an unusable chain before any job was
		// generated, so this is defensive. Calibration stops rather than compare
		// against a differently-shaped request, and the snapshot then says the
		// baseline is missing instead of reporting verdicts nobody can check.
		log.Printf("[INTRUDER %d] calibration_skipped reason=transform_error error=%v", attackID, logError(err))
		return baselines
	}
	count := config.CalibrationRequests()
	for _, shape := range shapes {
		values := shapeValues(shape, token, len(positions))
		samples := make([]intruder.Sample, 0, count)
		for attempt := 0; attempt < count; attempt++ {
			req := cloneRequest(base)
			position := 0
			req.URL, position = intruder.ReplaceAt(req.URL, values, position)
			for _, key := range sortedHeaderKeys(req.Headers) {
				req.Headers[key], position = intruder.ReplaceAt(req.Headers[key], values, position)
			}
			req.Body, _ = intruder.ReplaceAt(req.Body, values, position)
			result, execErr := s.executeContext(ctx, req)
			if result == nil {
				result = map[string]interface{}{}
			}
			s.publishIntruderTraffic(attackID, req, result, execErr)
			if execErr != nil {
				log.Printf("[INTRUDER %d] calibration_error shape=%s attempt=%d/%d error=%v", attackID, shape, attempt+1, count, logError(execErr))
				continue
			}
			samples = append(samples, buildDetectionSample(result, values))
		}
		baselines[shape] = intruder.CaptureBaseline(samples)
		log.Printf("[INTRUDER %d] calibration shape=%s samples=%d status=%d lengths=%v fingerprints=%d",
			attackID, shape, baselines[shape].Samples, baselines[shape].Status, baselines[shape].Lengths, len(baselines[shape].Fingerprints))
	}
	log.Printf("[INTRUDER %d] calibration_shapes=%d requests_per_shape=%d", attackID, len(shapes), count)
	return baselines
}

// ShapeOf names which marker positions a job fills, so a result can be compared
// with the baseline captured for the same shape. `x` marks an empty position and
// `1` a filled one; the name is stable for a given mode and dictionary layout,
// which is what makes it usable as a map key.
func ShapeOf(values []string) string {
	shape := make([]byte, len(values))
	for index, value := range values {
		if value == "" {
			shape[index] = 'x'
		} else {
			shape[index] = '1'
		}
	}
	return string(shape)
}

// ShapesOf lists the distinct shapes a job list will send, in first-seen order.
// It is derived from the jobs themselves rather than guessed from the mode, so a
// mode or a dictionary that produces an unexpected shape is still compared
// against a baseline captured for exactly that shape.
func ShapesOf(jobs []intruder.Job) []string {
	seen := map[string]bool{}
	var shapes []string
	for _, job := range jobs {
		shape := ShapeOf(job.Values)
		if seen[shape] {
			continue
		}
		seen[shape] = true
		shapes = append(shapes, shape)
	}
	return shapes
}

// shapeValues expands a shape name back into the values a job of that shape
// would carry: the token where the shape says filled, and an empty string where
// it says empty.
func shapeValues(shape, token string, positions int) []string {
	values := make([]string, positions)
	for index := range values {
		if index < len(shape) && shape[index] == '1' {
			values[index] = token
		}
	}
	return values
}

// detectionSummary is what the browser reads once per poll: whether the run is
// comparing at all, what it compared with, and how many results the verdict
// marked. The baselines are sent once here instead of on every result, because a
// hundred thousand rows repeating them would dwarf the findings.
func detectionSummary(config *intruder.DetectionConfig, baselines map[string]intruder.Baseline, matched, checked int) map[string]interface{} {
	summary := map[string]interface{}{"enabled": false}
	if config == nil || !config.Enabled {
		return summary
	}
	shapes := make([]string, 0, len(baselines))
	for shape := range baselines {
		shapes = append(shapes, shape)
	}
	sort.Strings(shapes)
	entries := make([]map[string]interface{}, 0, len(shapes))
	captured := 0
	for _, shape := range shapes {
		baseline := baselines[shape]
		if baseline.Samples > 0 {
			captured++
		}
		entries = append(entries, map[string]interface{}{
			"shape":        shape,
			"status":       baseline.Status,
			"min_length":   baseline.MinLength,
			"max_length":   baseline.MaxLength,
			"lengths":      baseline.Lengths,
			"fingerprints": baseline.Fingerprints,
			"location":     baseline.Location,
			"cookie_names": baseline.CookieNames,
			"samples":      baseline.Samples,
		})
	}
	summary["enabled"] = true
	summary["baselines"] = entries
	// The fully-filled shape is the one an operator reads first, so it is also
	// exposed on its own rather than making the page pick one out of the list.
	// A run whose mode leaves markers empty has no such shape, and then the first
	// entry stands in — the list itself is still complete. With no entry at all
	// the field is simply absent, which is the honest state of a calibration that
	// captured nothing.
	if len(entries) > 0 {
		summary["baseline"] = entries[0]
		for _, entry := range entries {
			shape, _ := entry["shape"].(string)
			if shape == strings.Repeat("1", len(shape)) {
				summary["baseline"] = entry
				break
			}
		}
	}
	summary["signals"] = config.UseSignals()
	summary["tolerance"] = config.ToleranceBytes()
	summary["calibration_requests"] = config.CalibrationRequests()
	summary["rules"] = len(config.Rules)
	summary["matched"] = matched
	summary["checked"] = checked
	if captured == 0 {
		summary["warning"] = "calibration_unavailable"
	}
	if len(config.Rules) > 0 {
		summary["decides"] = "rules"
	} else {
		summary["decides"] = "signals"
	}
	return summary
}

func detectionVerdictJSON(verdict intruder.Verdict) map[string]interface{} {
	payload := map[string]interface{}{"matched": verdict.Matched}
	if len(verdict.Signals) > 0 {
		payload["signals"] = verdict.Signals
	}
	if len(verdict.Reasons) > 0 {
		payload["reasons"] = verdict.Reasons
	}
	if verdict.Delta != 0 {
		payload["delta"] = verdict.Delta
	}
	return payload
}

// normalizedDetectionConfig resolves everything the operator left implicit
// before the run starts, so the values that decide a match are the same in the
// log, in the snapshot and in every verdict instead of being re-derived at each
// of those places.
func normalizedDetectionConfig(config *intruder.DetectionConfig) *intruder.DetectionConfig {
	normalized := *config
	normalized.Signals = config.UseSignals()
	normalized.Tolerance = config.ToleranceBytes()
	normalized.Calibration = config.CalibrationRequests()
	return &normalized
}

// evaluateIntruderResult attaches the verdict for one exchange and advances the
// run counters the browser polls. The baseline is chosen by the shape of the
// job's own values, so a run whose mode leaves markers empty is compared against
// a request with the same markers empty. The baselines are read under the lock
// and the counters written back under it, which is what makes `-race` meaningful
// here: a run with a hundred workers evaluates concurrently.
func (s *server) evaluateIntruderResult(job *attack, config intruder.DetectionConfig, result map[string]interface{}, injected []string) {
	job.mu.RLock()
	baselines := job.baselines
	job.mu.RUnlock()
	shape := ShapeOf(injected)
	baseline := baselines[shape]
	sample := buildDetectionSample(result, injected)
	verdict := intruder.Evaluate(config, baseline, sample, stringValue(result["body"]), stringMapValue(result["headers"]))
	verdictJSON := detectionVerdictJSON(verdict)
	// The shape travels with the verdict so the report and the table can say which
	// reference a row was compared with, instead of leaving a row that differs only
	// because its mode left a marker empty looking like a match.
	verdictJSON["shape"] = shape
	result["detection"] = verdictJSON
	job.mu.Lock()
	job.evaluated++
	if verdict.Matched {
		job.matched++
	}
	job.mu.Unlock()
}

// describeDetection is the one-line summary the engine log carries, so an
// operator reading engine.log can tell what the run considered a match without
// opening the browser.
func describeDetection(config *intruder.DetectionConfig, baselines map[string]intruder.Baseline) string {
	if config == nil || !config.Enabled {
		return "off"
	}
	if len(baselines) == 0 {
		return "enabled baseline=missing rules=" + fmt.Sprint(len(config.Rules))
	}
	shapes := make([]string, 0, len(baselines))
	for shape := range baselines {
		shapes = append(shapes, shape)
	}
	sort.Strings(shapes)
	parts := make([]string, 0, len(shapes))
	for _, shape := range shapes {
		baseline := baselines[shape]
		parts = append(parts, fmt.Sprintf("%s:status=%d length=%d..%d samples=%d",
			shape, baseline.Status, baseline.MinLength, baseline.MaxLength, baseline.Samples))
	}
	return fmt.Sprintf("enabled shapes=%d rules=%d %s", len(shapes), len(config.Rules), strings.Join(parts, " "))
}
