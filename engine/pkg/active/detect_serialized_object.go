package active

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// SerializedObject detects serialized objects in request parameters and cookies.
// Corresponds to Burp Suite check:
// 0x00400900 (Serialized object in HTTP message)
type SerializedObject struct{}

// Name implements Module.
func (SerializedObject) Name() string { return "serialized-object" }

// Level implements Module.
func (SerializedObject) Level() Level { return LevelParam }

type serializationSignature struct {
	platform string
	magic    string
	b64Magic string
	// shape is the recogniser for a format that has no fixed magic. PHP's
	// `serialize()` writes a length-prefixed value whose opening type letter
	// varies — `a` for an array, `O` for an object, `s` for a string — so there
	// is no byte sequence to look for and a shape test is the only honest one.
	// A nil shape means the row is matched by its magic bytes only.
	shape func(string) bool
}

var serializationSignatures = []serializationSignature{
	{"Java Object Serialization", "\xac\xed\x00\x05", "rO0AB", nil},
	{".NET BinaryFormatter", "\x00\x01\x00\x00\x00\xff\xff\xff\xff", "AAEAAAD/////", nil},
	{"Python Pickle", "\x80\x03", "gAM", nil},
	{"Python Pickle v4", "\x80\x04", "gAQ", nil},
	{"Ruby Marshal", "\x04\x08", "BAg", nil},
	{"Node.js node-serialize", "_$$ND_FUNC$$_ ", "", nil},
	{"PHP serialize()", "", "", isPHPSerialized},
}

func (s SerializedObject) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	val := p.Values.Get(p.Param)
	if val == "" {
		return nil
	}

	decodedVal, _ := url.QueryUnescape(val)
	b64Decoded, _ := base64.StdEncoding.DecodeString(decodedVal)

	var out []Finding
	for _, sig := range serializationSignatures {
		detected := false
		evidence := ""

		if sig.shape != nil {
			if sig.shape(decodedVal) {
				detected = true
				evidence = fmt.Sprintf("Value matches the %s shape: %s", sig.platform, trimEvidence(decodedVal))
			}
		} else if sig.b64Magic != "" && strings.HasPrefix(decodedVal, sig.b64Magic) {
			detected = true
			evidence = fmt.Sprintf("Base64 prefix %q matches %s signature.", sig.b64Magic, sig.platform)
		} else if sig.magic != "" && strings.Contains(decodedVal, sig.magic) {
			detected = true
			evidence = fmt.Sprintf("Raw magic bytes match %s signature.", sig.platform)
		} else if len(b64Decoded) > 0 && sig.magic != "" && strings.Contains(string(b64Decoded), sig.magic) {
			detected = true
			evidence = fmt.Sprintf("Base64-decoded content matches %s signature (%q).", sig.platform, sig.magic)
		}

		if detected {
			finding, _ := NewFinding(Spec{
				Module:      "serialized-object",
				Title:       fmt.Sprintf("Serialized Object in HTTP Parameter (%s)", sig.platform),
				Claimed:     SeverityMedium,
				Tier:        TierVerified,
				Point:       p,
				Payload:     p.Param + "=" + val,
				Evidence:    evidence,
				Description: fmt.Sprintf("The parameter carries a serialized object (%s). Untrusted deserialization allows remote code execution, memory corruption, or unauthorized state tampering.", sig.platform),
				Remediation: "Do not accept serialized objects from untrusted sources. Use safe data interchange formats such as JSON or Protocol Buffers with strict schema validation.",
			})
			out = append(out, finding)
			break
		}
	}

	return out
}

func isPHPSerialized(val string) bool {
	if len(val) < 4 {
		return false
	}
	return (val[0] == 'O' || val[0] == 'a' || val[0] == 'C') && val[1] == ':' && val[2] >= '0' && val[2] <= '9'
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
