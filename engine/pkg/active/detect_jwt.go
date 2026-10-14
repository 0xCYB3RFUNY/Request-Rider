package active

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// JWT probes parameters for JSON Web Tokens and verifies whether
// the application properly validates token signatures or accepts
// "none" algorithm and stripped signatures.
// Corresponds to Burp Suite checks:
// 0x00200900 (JWT signature not verified)
// 0x00200901 (JWT none algorithm supported)
type JWT struct{}

// Name implements Module.
func (JWT) Name() string { return "jwt" }

// Level implements Module.
func (JWT) Level() Level { return LevelParam }

func (j JWT) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 {
		return nil
	}

	val := p.Values.Get(p.Param)
	if val == "" {
		return nil
	}

	headerJSON, payloadB64, sigB64, isJWT := parseJWT(val)
	if !isJWT {
		return nil
	}

	var out []Finding

	// Control probe: send token with an obviously invalid signature
	invalidSigToken := val[:strings.LastIndexByte(val, '.')+1] + base64.RawURLEncoding.EncodeToString([]byte("invalid_sig_probe"))
	invalidResp, err := t.Fire(ctx, p, p.Param, invalidSigToken, false, nil)
	if err != nil || invalidResp == nil {
		return nil
	}

	// If the server rejects the invalid signature (e.g. 401/403 or error body),
	// but accepts "none" or stripped signature, we have definitive proof!
	invalidRejected := invalidResp.StatusCode == http.StatusUnauthorized ||
		invalidResp.StatusCode == http.StatusForbidden ||
		strings.Contains(strings.ToLower(invalidResp.Body), "signature") ||
		strings.Contains(strings.ToLower(invalidResp.Body), "invalid token") ||
		strings.Contains(strings.ToLower(invalidResp.Body), "unauthorized")

	// Attack 1: alg: "none" (0x00200901)
	noneHeaders := []string{
		`{"alg":"none","typ":"JWT"}`,
		`{"alg":"None","typ":"JWT"}`,
		`{"alg":"NONE","typ":"JWT"}`,
	}

	for _, nHead := range noneHeaders {
		headB64 := base64.RawURLEncoding.EncodeToString([]byte(nHead))
		noneToken := headB64 + "." + payloadB64 + "."
		noneResp, err := t.Fire(ctx, p, p.Param, noneToken, false, nil)
		if err == nil && noneResp != nil {
			if noneResp.StatusCode == baseline.StatusCode && !isAuthError(noneResp.Body) {
				if invalidRejected || noneResp.StatusCode == http.StatusOK {
					evidence := fmt.Sprintf("Token with alg:none accepted by server. Status: %d, Response length: %d (Baseline: %d)",
						noneResp.StatusCode, len(noneResp.Body), len(baseline.Body))
					finding, _ := NewFinding(Spec{
						Module:      "jwt",
						Title:       "JWT 'none' Algorithm Supported",
						Claimed:     SeverityHigh,
						Tier:        TierVerified,
						Point:       p,
						Payload:     noneToken,
						Evidence:    evidence,
						Description: "The server accepted a JSON Web Token with the algorithm set to 'none' and an empty signature. An attacker can forge arbitrary tokens and bypass authentication.",
						Remediation: "Configure the JWT verification library to explicitly reject tokens with 'alg': 'none' and enforce a strict list of allowed cryptographic algorithms.",
					})
					out = append(out, finding)
					break
				}
			}
		}
	}

	// Attack 2: Stripped signature with original header (0x00200900)
	if len(sigB64) > 0 {
		strippedToken := val[:strings.LastIndexByte(val, '.')+1]
		stripResp, err := t.Fire(ctx, p, p.Param, strippedToken, false, nil)
		if err == nil && stripResp != nil {
			if stripResp.StatusCode == baseline.StatusCode && !isAuthError(stripResp.Body) {
				if invalidRejected {
					evidence := fmt.Sprintf("Token with stripped signature accepted by server. Status: %d, Response length: %d (Baseline: %d)",
						stripResp.StatusCode, len(stripResp.Body), len(baseline.Body))
					finding, _ := NewFinding(Spec{
						Module:      "jwt",
						Title:       "JWT Signature Not Verified",
						Claimed:     SeverityHigh,
						Tier:        TierVerified,
						Point:       p,
						Payload:     strippedToken,
						Evidence:    evidence,
						Description: "The server accepted a JSON Web Token whose cryptographic signature was removed entirely. The application decodes the token claims without verifying their integrity.",
						Remediation: "Ensure the backend verifies JWT signatures using a cryptographically secure key before consuming token claims.",
					})
					out = append(out, finding)
				}
			}
		}
	}

	_ = headerJSON
	return out
}

func parseJWT(token string) (header map[string]interface{}, payloadB64, sigB64 string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", "", false
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		headBytes, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, "", "", false
		}
	}
	var head map[string]interface{}
	if err := json.Unmarshal(headBytes, &head); err != nil {
		return nil, "", "", false
	}
	if _, hasAlg := head["alg"]; !hasAlg {
		return nil, "", "", false
	}
	return head, parts[1], parts[2], true
}

func isAuthError(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "invalid signature") ||
		strings.Contains(lower, "signature verification failed") ||
		strings.Contains(lower, "jwt malformed") ||
		strings.Contains(lower, "invalid token") ||
		strings.Contains(lower, "token expired") ||
		strings.Contains(lower, "unauthorized")
}
