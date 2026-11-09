package active

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func makeTestJWT(alg string, signature string) string {
	head := `{"alg":"` + alg + `","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"Alice","admin":false}`
	h64 := base64.RawURLEncoding.EncodeToString([]byte(head))
	p64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return h64 + "." + p64 + "." + signature
}

func TestJWTNoneAlgorithmVulnerable(t *testing.T) {
	origToken := makeTestJWT("HS256", "valid_real_signature_123")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		headBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		head := string(headBytes)

		// Vulnerable backend logic: accepts valid signature OR alg:none!
		if strings.Contains(strings.ToLower(head), `"none"`) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok","user":"Alice"}`)
			return
		}

		if parts[2] == "valid_real_signature_123" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok","user":"Alice"}`)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid signature"}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := JWT{}
	p := Point{
		URL:    server.URL + "/api/profile",
		Method: http.MethodGet,
		Param:  "token",
		Values: url.Values{"token": {origToken}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `{"status":"ok","user":"Alice"}`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) == 0 {
		t.Fatalf("expected JWT 'none' algorithm finding, got 0")
	}

	foundNone := false
	for _, f := range findings {
		if strings.Contains(f.Title, "none") {
			foundNone = true
		}
	}
	if !foundNone {
		t.Errorf("expected JWT 'none' finding in: %+v", findings)
	}
}

func TestJWTSecureBackendDoesNotReport(t *testing.T) {
	origToken := makeTestJWT("HS256", "valid_real_signature_123")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		parts := strings.Split(token, ".")
		if len(parts) == 3 && parts[2] == "valid_real_signature_123" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid signature"}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := JWT{}
	p := Point{
		URL:    server.URL + "/api/profile",
		Method: http.MethodGet,
		Param:  "token",
		Values: url.Values{"token": {origToken}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `{"status":"ok"}`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secure backend, got %d: %+v", len(findings), findings)
	}
}

// A dictionary key is proven by recomputation, not by a request: the signature
// on the operator's own token is HMAC of the token's own bytes, so a match is a
// fact the row can carry at TierVerified.
func TestJWTWeakHMACSecret(t *testing.T) {
	const weakKey = "secret"
	head := `{"alg":"HS256","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"Alice","admin":false}`
	h64 := base64.RawURLEncoding.EncodeToString([]byte(head))
	p64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, []byte(weakKey))
	_, _ = mac.Write([]byte(h64 + "." + p64))
	weakToken := h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// A backend that really checks the signature: the control probe is rejected,
	// which is what makes the weak-secret row a signature problem rather than a
	// missing-verification one.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		headBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if strings.Contains(strings.ToLower(string(headBytes)), `"none"`) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"alg none is refused"}`)
			return
		}
		mac := hmac.New(sha256.New, []byte(weakKey))
		_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
		provided, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || !hmac.Equal(mac.Sum(nil), provided) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid signature"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok","user":"Alice"}`)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := JWT{}
	p := Point{
		URL:    server.URL + "/api/profile",
		Method: http.MethodGet,
		Param:  "token",
		Values: url.Values{"token": {weakToken}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `{"status":"ok","user":"Alice"}`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Weak HMAC Secret") {
			found = true
			if !strings.Contains(f.Evidence, `"`+weakKey+`"`) {
				t.Errorf("the row should name the key it recomputed: %q", f.Evidence)
			}
			if f.Tier != TierVerified {
				t.Errorf("a recomputed signature is verified, got tier %v", f.Tier)
			}
		}
	}
	if !found {
		t.Fatalf("expected a weak-HMAC row, got: %+v", findings)
	}
}

// A verifier that takes its key from the token it is verifying accepts a token
// this run minted itself — and rejects the control with a garbage signature,
// which is what separates "trusts the token" from "checks nothing".
func TestJWTSelfSignedJWKHeader(t *testing.T) {
	// The backend's own key, used only when the token carries no jwk of its own.
	ownKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the server key: %v", err)
	}

	verify := func(token string) bool {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return false
		}
		headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return false
		}
		var head map[string]interface{}
		if err := json.Unmarshal(headBytes, &head); err != nil {
			return false
		}
		provided, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return false
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		// The defect: the key comes from the header when the header carries one.
		if embedded, ok := head["jwk"].(map[string]interface{}); ok {
			nBytes, err := base64.RawURLEncoding.DecodeString(embedded["n"].(string))
			if err != nil {
				return false
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(embedded["e"].(string))
			if err != nil {
				return false
			}
			modulus := new(big.Int).SetBytes(nBytes)
			exponent := new(big.Int).SetBytes(eBytes)
			return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: modulus, E: int(exponent.Int64())},
				crypto.SHA256, digest[:], provided) == nil
		}
		return rsa.VerifyPKCS1v15(&ownKey.PublicKey, crypto.SHA256, digest[:], provided) == nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verify(r.URL.Query().Get("token")) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid signature"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok","user":"Alice"}`)
	}))
	defer server.Close()

	// A token the backend accepts, so the baseline is a working request.
	head := `{"alg":"RS256","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"Alice","admin":false}`
	h64 := base64.RawURLEncoding.EncodeToString([]byte(head))
	p64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(h64 + "." + p64))
	signature, err := rsa.SignPKCS1v15(rand.Reader, ownKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing the baseline token: %v", err)
	}
	validToken := h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(signature)

	transport := mustTransport(t)
	detector := JWT{}
	p := Point{
		URL:    server.URL + "/api/profile",
		Method: http.MethodGet,
		Param:  "token",
		Values: url.Values{"token": {validToken}},
	}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Body:       `{"status":"ok","user":"Alice"}`,
	}

	findings := detector.Scan(context.Background(), transport, p, baseline)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Self-Signed JWK") {
			found = true
			if f.Tier != TierVerified {
				t.Errorf("an accepted attacker-minted key is verified, got tier %v", f.Tier)
			}
		}
	}
	if !found {
		t.Fatalf("expected a self-signed-JWK row, got: %+v", findings)
	}
}
