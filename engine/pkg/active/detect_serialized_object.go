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
}

var serializationSignatures = []serializationSignature{
	{"Java Object Serialization", "\xac\xed\x00\x05", "rO0AB"},
	{".NET BinaryFormatter", "\x00\x01\x00\x00\x00\xff\xff\xff\xff", "AAEAAAD/////"},
	{"Python Pickle", "\x80\x03", "gAM"},
	{"Python Pickle v4", "\x80\x04", "gAQ"},
	{"Ruby Marshal", "\x04\x08", "BAg"},
	{"Node.js node-serialize", "_$$ND_FUNC$$_ ", ""},
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

		if sig.b64Magic != "" && strings.HasPrefix(decodedVal, sig.b64Magic) {
			detected = true
			evidence = fmt.Sprintf("Base64 prefix %q matches %s signature.", sig.b64Magic, sig.platform)
		} else if strings.Contains(decodedVal, sig.magic) {
			detected = true
			evidence = fmt.Sprintf("Raw magic bytes match %s signature.", sig.platform)
		} else if len(b64Decoded) > 0 && strings.Contains(string(b64Decoded), sig.magic) {
			detected = true
			evidence = fmt.Sprintf("Base64-decoded content matches %s signature (%q).", sig.platform, sig.magic)
		} else if sig.platform == "PHP" && isPHPSerialized(decodedVal) {
			detected = true
			evidence = fmt.Sprintf("PHP serialized object signature detected: %s", decodedVal[:min(len(decodedVal), 50)])
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
