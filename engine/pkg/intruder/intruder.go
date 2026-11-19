// Package intruder contains marker parsing, payload transformation and job
// generation logic used by the Go execution engine.
package intruder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
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
	if start, end, name := percentMarker(text); start >= 0 {
		candidates = append(candidates, marker{start, end, name})
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
	// `§` is two bytes in UTF-8, so the rune has to be matched by prefix. A
	// one-byte slice can never equal "§", which left every name carrying the
	// first byte of the closing rune: `§pass§` parsed as `pass\xC2`, and the
	// position was tied to a payload list the operator never named.
	if strings.HasPrefix(text[selected.start:], "§") {
		nameEnd = selected.end - len("§")
	} else if strings.HasPrefix(text[selected.start:], "{{") {
		nameEnd = selected.end - 2
	}
	return selected.start, selected.end, text[selected.name:nameEnd]
}

// percentMarker returns the earliest `%name%` marker that is not part of
// percent-encoded data. Encoding applies to a payload, never to a marker, so a
// `%` followed by two hexadecimal digits is an escape belonging to the field it
// sits in and must not open a marker. Reading it as one marker turned a single
// login parameter into four attack positions, and every payload after the first
// landed in the wrong field.
func percentMarker(text string) (int, int, int) {
	for index := 0; index < len(text); index++ {
		if text[index] != '%' {
			continue
		}
		if isPercentEscape(text, index) {
			// The escape belongs to its field, and the two digits that follow
			// are not a `%`, so the loop steps over them on its own. No second
			// escape can be opened inside one.
			continue
		}
		offset := strings.Index(text[index+1:], "%")
		// `offset <= 0` also rules out an empty name: `%%` is not a marker.
		if offset <= 0 {
			continue
		}
		if !isMarkerName(text[index+1 : index+1+offset]) {
			continue
		}
		return index, index + 1 + offset + 1, index + 1
	}
	return -1, -1, -1
}

// isPercentEscape reports whether the `%` at index opens a `%XX` escape.
func isPercentEscape(text string, index int) bool {
	return index+2 < len(text) &&
		isHexDigit(text[index+1]) && isHexDigit(text[index+2])
}

func isHexDigit(char byte) bool {
	switch {
	case char >= '0' && char <= '9':
		return true
	case char >= 'a' && char <= 'f':
		return true
	case char >= 'A' && char <= 'F':
		return true
	}
	return false
}

// isMarkerName keeps a `%name%` marker to the shape an operator can actually
// type. Prose such as `50% off %today%` contains a percent sign, two spaces and
// a word, and it is data, not a marker.
func isMarkerName(name string) bool {
	for index := 0; index < len(name); index++ {
		char := name[index]
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '_', char == '-', char == '.':
		default:
			return false
		}
	}
	return true
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

func min(a, b int) int {
	// Return the smaller list length for Pitchfork pairing.
	if a < b {
		return a
	}
	return b
}
