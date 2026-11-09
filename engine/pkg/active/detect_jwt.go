package active

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

// JWT probes parameters for JSON Web Tokens and verifies whether
// the application properly validates token signatures or accepts
// "none" algorithm and stripped signatures.
// Corresponds to Burp Suite checks:
// 0x00200900 (JWT signature not verified)
// 0x00200901 (JWT none algorithm supported)
// 0x00200902 (JWT self-signed JWK header supported)
// 0x00200903 (JWT weak HMAC secret)
//
// The two checks added here are the two that do not need a special transport:
// the weak secret is a computation over the token the operator already holds,
// and the self-signed JWK is one ordinary request carrying a key this run minted.
// The remaining two of Burp's five — an arbitrary `jku` or `x5u` header — are
// absent on purpose and are recorded in `burp_reconciliation.md` with the reason:
// both require the detector to observe the server *fetching* its key from an
// attacker-controlled host, and this package has no OAST listener to observe it
// with. Without that observation a token naming a foreign jku is indistinguishable
// from one the server could not reach at all, so the row would be a guess.
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

	// Attack 3: a weak HMAC secret (0x00200903)
	//
	// Offline, and that is the point: the token the operator already holds is
	// signed, so the question "is the key a dictionary word" is answered by
	// computing the signature ourselves. No request is spent, nothing is fired
	// at the target, and a match is proof rather than inference — the signature
	// on the token is HMAC over its own bytes under that exact key.
	if finding := jwtWeakSecretFinding(p, val, headerJSON); finding != nil {
		out = append(out, *finding)
	}

	// Attack 4: a self-signed key embedded in the token's own header
	// (0x00200902).
	//
	// The control decides whether this probe means anything: a server that
	// cannot tell a valid signature from an invalid one accepts every token
	// ever built, and the row that matters is the one above. A server that
	// *did* reject the garbage signature and accepts a key the token carries
	// itself has been proven to take its trust from the token.
	if invalidRejected {
		if finding := jwkHeaderProbe(ctx, t, p, baseline, payloadB64); finding != nil {
			out = append(out, *finding)
		}
	}

	_ = headerJSON
	return out
}

// jwtWeakSecrets is the dictionary a token's HMAC key is checked against.
//
// It is short on purpose. The row it produces claims "the signing key is one of
// these words", so every entry is a word a deployment actually ships — the
// examples in a framework's own documentation, the default in a tutorial, the
// placeholder a developer forgot. A dictionary padded to look thorough would
// produce a row that sounds more broken than the target is.
var jwtWeakSecrets = []string{
	"secret", "Secret", "SECRET", "secretkey", "secret_key", "jwtsecret", "jwt_secret",
	"your-256-bit-secret", "your-secret-key", "your_jwt_secret", "changeme", "changeit",
	"password", "123456", "1234567890", "qwerty", "admin", "letmein", "default",
	"test", "testing", "key", "private", "token", "supersecret", "topsecret",
	"mysecret", "s3cr3t", "1234", "0000",
}

// hmacHashFor maps a JWT header's algorithm to the hash it names.
//
// Only the HMAC family is here: RS/ES/PS keys are asymmetric, so "guessing the
// key" is not the attack and the row would be a different claim. An algorithm
// this function does not know returns false and the probe does nothing.
func hmacHashFor(alg string) (func() hash.Hash, bool) {
	switch alg {
	case "HS256":
		return sha256.New, true
	case "HS384":
		return sha512.New384, true
	case "HS512":
		return sha512.New, true
	}
	return nil, false
}

// jwtWeakSecretFinding checks the token's own signature against the dictionary,
// without spending a request.
func jwtWeakSecretFinding(p Point, token string, header map[string]interface{}) *Finding {
	alg, _ := header["alg"].(string)
	hashFn, ok := hmacHashFor(alg)
	if !ok {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		provided, err = base64.URLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil
		}
	}
	signingInput := parts[0] + "." + parts[1]
	for _, secret := range jwtWeakSecrets {
		mac := hmac.New(hashFn, []byte(secret))
		_, _ = mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), provided) {
			finding, _ := NewFinding(Spec{
				Module:  "jwt",
				Title:   "JWT Weak HMAC Secret",
				Claimed: SeverityHigh,
				Tier:    TierVerified,
				Point:   p,
				Payload: token,
				Evidence: "the token's signature is HMAC-" + alg + " of its own claims under the key \"" +
					secret + "\"; recomputed offline and equal byte for byte",
				Description: "The signing key is a dictionary word, so anyone holding one token can sign " +
					"any other: an administrator claim, another user's subject, a token that never " +
					"expires. The proof is local — the signature on the operator's own token was " +
					"recomputed under this key and matched.",
				Remediation: "Use a key from a cryptographic random source, at least as long as the " +
					"hash output, and store it where the code does not carry it. Rotate any key this " +
					"row names.",
			})
			return &finding
		}
	}
	return nil
}

// selfSignedJWKToken builds a token whose header carries the public key that
// verifies it, signed by the freshly generated private half.
//
// The key is generated per probe and discarded: the row proves the application
// accepts *a key it was handed*, so which key it was handed does not matter as
// long as the attacker could have made it. Generating one rather than shipping
// a test fixture is what keeps the row honest — a fixed key would prove the
// server trusts one particular key, which is a fact about a fixture.
func selfSignedJWKToken(payloadB64 string) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	head := fmt.Sprintf(`{"alg":"RS256","typ":"JWT","jwk":{"e":"AQAB","kty":"RSA","n":"%s"}}`,
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()))
	headB64 := base64.RawURLEncoding.EncodeToString([]byte(head))
	signingInput := headB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// jwkHeaderProbe sends the self-signed token and reports the acceptance.
func jwkHeaderProbe(ctx context.Context, t *Transport, p Point, baseline *Response, payloadB64 string) *Finding {
	token, err := selfSignedJWKToken(payloadB64)
	if err != nil {
		// A run that cannot mint a key reports nothing rather than guessing: the
		// absence of a row here means "not proven", which is the truth.
		return nil
	}
	resp, err := t.Fire(ctx, p, p.Param, token, false, nil)
	if err != nil || resp == nil {
		return nil
	}
	if resp.StatusCode != baseline.StatusCode || isAuthError(resp.Body) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "jwt",
		Title:   "JWT Self-Signed JWK Header Supported",
		Claimed: SeverityHigh,
		Tier:    TierVerified,
		Point:   p,
		Payload: token,
		Evidence: fmt.Sprintf("a token signed by a key minted for this probe and carried inside its own "+
			"jwk header was accepted: status %d, %d bytes (baseline %d, %d bytes)",
			resp.StatusCode, len(resp.Body), baseline.StatusCode, len(baseline.Body)),
		Description: "The verifier took its key material from the token it was verifying. An attacker " +
			"mints a key pair, embeds the public half in the jwk header, signs any claims they like " +
			"with the private half, and the application accepts the result — no secret of the " +
			"application's was ever needed.",
		Remediation: "Resolve keys from a fixed JWKS the server owns, pinned per issuer and algorithm, " +
			"and reject any token that carries key material of its own.",
	})
	return &finding
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
