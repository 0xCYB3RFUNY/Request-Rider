// Package intruder contains marker parsing, payload transformation and job
// generation logic used by the Go execution engine.
package intruder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"
)

// AttackMode controls how payload lists are combined into generated jobs.
type AttackMode string

const (
	Sniper       AttackMode = "sniper"
	BatteringRam AttackMode = "batteringRam"
	Pitchfork    AttackMode = "pitchfork"
	ClusterBomb  AttackMode = "clusterBomb"
)

// Request is the engine-independent representation of an HTTP request.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Job contains one replacement value for each marker position.
type Job struct {
	Values []string
}

// Transform describes one operation in the payload transformation chain.
type Transform struct {
	Operation string `json:"operation"`
	Value     string `json:"value"`
}

// TransformPayload applies the UI-selected transformation chain in order.
func TransformPayload(value string, transforms []Transform) (string, error) {
	// Apply operations left-to-right so chains are deterministic.
	for _, transform := range transforms {
		var err error
		switch transform.Operation {
		case "urlEncode":
			// Encode a payload for use in a URL or query component.
			value = url.QueryEscape(value)
		case "urlDecode":
			// Decode a URL-escaped payload and propagate malformed input.
			value, err = url.QueryUnescape(value)
		case "base64Encode":
			// Encode arbitrary UTF-8 bytes using standard Base64.
			value = base64.StdEncoding.EncodeToString([]byte(value))
		case "base64Decode":
			// Decode standard Base64 back into a string.
			var data []byte
			data, err = base64.StdEncoding.DecodeString(value)
			value = string(data)
		case "base64UrlEncode":
			// Encode using the URL-safe alphabet without padding.
			value = base64.RawURLEncoding.EncodeToString([]byte(value))
		case "base64UrlDecode":
			// Decode the unpadded URL-safe Base64 form.
			var data []byte
			data, err = base64.RawURLEncoding.DecodeString(value)
			value = string(data)
		case "htmlEntityEncode":
			// Escape characters that have meaning in HTML markup.
			value = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;").Replace(value)
		case "jsonEscape":
			// Escape characters that have meaning inside a JSON string.
			value = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t").Replace(value)
		case "unicodeEscape":
			// Represent UTF-16 code units as Unicode escape sequences.
			var builder strings.Builder
			for _, codeUnit := range utf16.Encode([]rune(value)) {
				fmt.Fprintf(&builder, "\\u%04x", codeUnit)
			}
			value = builder.String()
		case "hexEncode":
			// Encode the payload bytes as lowercase hexadecimal.
			value = hex.EncodeToString([]byte(value))
		case "hexDecode":
			// Decode hexadecimal input and report invalid digits.
			var data []byte
			data, err = hex.DecodeString(value)
			value = string(data)
		case "whitespaceNormalize":
			// Collapse all whitespace runs to one ASCII space.
			value = strings.Join(strings.Fields(value), " ")
		case "trim":
			// Remove leading and trailing Unicode whitespace.
			value = strings.TrimSpace(value)
		case "lowercase":
			// Normalize letters to lowercase.
			value = strings.ToLower(value)
		case "uppercase":
			// Normalize letters to uppercase.
			value = strings.ToUpper(value)
		case "prepend":
			// Add the configured value before the payload.
			value = transform.Value + value
		case "append":
			// Add the configured value after the payload.
			value += transform.Value
		default:
			return "", fmt.Errorf("unsupported payload transformation %q", transform.Operation)
		}
		// Decoding operations can fail and must stop the chain explicitly.
		if err != nil {
			return "", fmt.Errorf("%s: %w", transform.Operation, err)
		}
	}
	// Go strings preserve arbitrary bytes so binary payloads can be sent in the
	// outbound request body or headers. JSON serialization may escape them, but
	// the HTTP request itself retains the decoded bytes.
	return value, nil
}

func Positions(text string) []string {
	// Return marker names in wire order for dictionary resolution.
	var positions []string
	for {
		start, end, value := nextMarker(text)
		if start < 0 {
			break
		}
		positions = append(positions, value)
		text = text[end:]
	}
	return positions
}

func Replace(text string, values []string) string {
	// Preserve the simple public API for callers that replace one text field.
	result, _ := ReplaceAt(text, values, 0)
	return result
}

func ReplaceAt(text string, values []string, offset int) (string, int) {
	// offset lets URL, headers and body share one global marker index.
	var out strings.Builder
	position := offset
	for i := 0; i < len(text); {
		start, end, _ := nextMarker(text[i:])
		if start < 0 {
			out.WriteString(text[i:])
			break
		}
		start += i
		end += i
		out.WriteString(text[i:start])
		if position < len(values) {
			out.WriteString(values[position])
		}
		position++
		i = end
	}
	return out.String(), position
}

func nextMarker(text string) (int, int, string) {
	// Choose the earliest complete marker among the supported syntaxes.
	type marker struct {
		start, end, name int
	}
	candidates := make([]marker, 0, 3)
	if start := strings.Index(text, "§"); start >= 0 {
		if end := strings.Index(text[start+len("§"):], "§"); end >= 0 {
			end += start + len("§") + len("§")
			candidates = append(candidates, marker{start, end, start + len("§")})
		}
	}
	if start := strings.Index(text, "{{"); start >= 0 {
		if end := strings.Index(text[start+2:], "}}"); end >= 0 {
			end += start + 2 + 2
			candidates = append(candidates, marker{start, end, start + 2})
		}
	}
	if start := strings.Index(text, "%"); start >= 0 {
		if end := strings.Index(text[start+1:], "%"); end > 0 {
			end += start + 1 + 1
			candidates = append(candidates, marker{start, end, start + 1})
		}
	}
	if len(candidates) == 0 {
		return -1, -1, ""
	}
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.start < selected.start {
			selected = candidate
		}
	}
	nameEnd := selected.end - 1
	if text[selected.start:selected.start+1] == "§" {
		nameEnd = selected.end - len("§")
	} else if text[selected.start:selected.start+2] == "{{" {
		nameEnd = selected.end - 2
	}
	return selected.start, selected.end, text[selected.name:nameEnd]
}

func Generate(mode AttackMode, positionCount int, payloadSets [][]string) ([]Job, error) {
	// Reject incomplete attack definitions before selecting a mode.
	if positionCount == 0 || len(payloadSets) == 0 {
		return nil, fmt.Errorf("at least one marked position and payload list are required")
	}
	switch mode {
	case Sniper:
		// Sniper changes one position at a time and clears the others.
		var jobs []Job
		for position := 0; position < positionCount; position++ {
			for _, payload := range payloadSets[0] {
				values := make([]string, positionCount)
				for i := range values {
					values[i] = ""
				}
				values[position] = payload
				jobs = append(jobs, Job{Values: values})
			}
		}
		return jobs, nil
	case BatteringRam:
		// Battering Ram reuses each payload across every marked position.
		return mapJobs(payloadSets[0], positionCount), nil
	case Pitchfork:
		// Pitchfork pairs values by index and stops at the shortest list.
		n := len(payloadSets[0])
		for _, set := range payloadSets[1:] {
			if len(set) < n {
				n = len(set)
			}
		}
		jobs := make([]Job, 0, n)
		for i := 0; i < n; i++ {
			values := make([]string, positionCount)
			for p := range values {
				values[p] = payloadSets[min(p, len(payloadSets)-1)][i]
			}
			jobs = append(jobs, Job{Values: values})
		}
		return jobs, nil
	case ClusterBomb:
		// Cluster Bomb walks the Cartesian product of all payload lists.
		var jobs []Job
		var walk func(int, []string)
		walk = func(index int, values []string) {
			if index == len(payloadSets) {
				for len(values) < positionCount {
					values = append(values, values[len(values)%len(values)])
				}
				jobs = append(jobs, Job{Values: append([]string(nil), values[:positionCount]...)})
				return
			}
			for _, payload := range payloadSets[index] {
				walk(index+1, append(values, payload))
			}
		}
		walk(0, nil)
		return jobs, nil
	default:
		return nil, fmt.Errorf("unsupported attack mode %q", mode)
	}
}

func mapJobs(payloads []string, count int) []Job {
	// Reuse each payload at every marker position for Battering Ram.
	jobs := make([]Job, 0, len(payloads))
	for _, payload := range payloads {
		values := make([]string, count)
		for i := range values {
			values[i] = payload
		}
		jobs = append(jobs, Job{Values: values})
	}
	return jobs
}

func SortResults(results []map[string]interface{}) {
	// Keep the helper available for callers that need status ordering.
	sort.SliceStable(results, func(i, j int) bool {
		return fmt.Sprint(results[i]["status"]) < fmt.Sprint(results[j]["status"])
	})
}

func min(a, b int) int {
	// Return the smaller list length for Pitchfork pairing.
	if a < b {
		return a
	}
	return b
}
