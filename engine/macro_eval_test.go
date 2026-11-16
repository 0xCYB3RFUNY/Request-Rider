package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMacroFastPathNoTags(t *testing.T) {
	plain := "GET /api/v1/search?q=test HTTP/1.1\r\nHost: target.test\r\n\r\nregular body"
	evaluated := EvaluateMacroText(plain, nil)
	if evaluated != plain {
		t.Fatalf("expected exact identity on fast path, got %q", evaluated)
	}

	req := requestInput{
		Method:  "POST",
		URL:     "http://example.com/test",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"name":"john"}`,
	}
	out := EvaluateRequestMacros(req, nil)
	if out.URL != req.URL || out.Body != req.Body || out.Headers["Content-Type"] != "application/json" {
		t.Fatalf("expected exact requestInput equality on fast path")
	}
}

func TestMacroEncodingAndHashing(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"{{b64(hello world)}}", "aGVsbG8gd29ybGQ="},
		{"{{b64url(hello world)}}", "aGVsbG8gd29ybGQ"},
		{"{{url_enc(a b&c=d)}}", "a+b%26c%3Dd"},
		{"{{hex(admin)}}", "61646d696e"},
		{"{{html_enc(<script>alert(1)</script>)}}", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"{{sha256(admin)}}", "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"},
		{"{{md5(admin)}}", "21232f297a57a5a743894a0e4a801fc3"},
	}

	for _, tc := range tests {
		got := EvaluateMacroText(tc.input, nil)
		if got != tc.expected {
			t.Errorf("input %s: got %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestMacroHMACSHA256(t *testing.T) {
	key := "mysecret"
	data := "important_message"
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))

	input := "{{hmac_sha256(" + key + ", " + data + ")}}"
	got := EvaluateMacroText(input, nil)
	if got != expected {
		t.Fatalf("hmac_sha256: got %q, want %q", got, expected)
	}
}

func TestMacroDynamicGenerators(t *testing.T) {
	// UUIDv4
	uuidStr := EvaluateMacroText("{{uuid4()}}", nil)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(uuidStr) {
		t.Errorf("uuid4() output %q does not match RFC 4122 v4 regex", uuidStr)
	}

	// ts_sec
	secStr := EvaluateMacroText("{{ts_sec()}}", nil)
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil || sec < time.Now().Unix()-5 || sec > time.Now().Unix()+5 {
		t.Errorf("ts_sec() %q is out of range", secStr)
	}

	// ts_ms
	msStr := EvaluateMacroText("{{ts_ms()}}", nil)
	ms, err := strconv.ParseInt(msStr, 10, 64)
	if err != nil || ms < time.Now().UnixMilli()-5000 || ms > time.Now().UnixMilli()+5000 {
		t.Errorf("ts_ms() %q is out of range", msStr)
	}

	// rand_int
	for i := 0; i < 20; i++ {
		intStr := EvaluateMacroText("{{rand_int(50, 100)}}", nil)
		n, err := strconv.Atoi(intStr)
		if err != nil || n < 50 || n > 100 {
			t.Fatalf("rand_int(50, 100) produced %q outside [50, 100]", intStr)
		}
	}

	// rand_str
	str32 := EvaluateMacroText("{{rand_str(32)}}", nil)
	if len(str32) != 32 {
		t.Errorf("rand_str(32) length = %d, want 32", len(str32))
	}

	// nonce
	nonce8 := EvaluateMacroText("{{nonce(8)}}", nil)
	if len(nonce8) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("nonce(8) length = %d hex chars, want 16", len(nonce8))
	}
}

func TestMacroNestedFunctions(t *testing.T) {
	// Nested base64 of sha256
	input := "{{b64({{sha256(admin)}})}}"
	h := sha256.Sum256([]byte("admin"))
	expected := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h[:])))

	got := EvaluateMacroText(input, nil)
	if got != expected {
		t.Fatalf("nested macro: got %q, want %q", got, expected)
	}

	// Nested with prefixes and suffixes
	input2 := "prefix-{{b64({{hex(test)}})}}-suffix"
	got2 := EvaluateMacroText(input2, nil)
	expected2 := "prefix-" + base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte("test")))) + "-suffix"
	if got2 != expected2 {
		t.Fatalf("nested macro with affixes: got %q, want %q", got2, expected2)
	}
}

func TestMacroSecretsAndJWT(t *testing.T) {
	secrets := map[string]string{
		"API_KEY":  "sk-prod-99881122",
		"JWT_SALT": "super-duper-secret",
	}

	secVal := EvaluateMacroText("Bearer {{$secret.API_KEY}}", secrets)
	if secVal != "Bearer sk-prod-99881122" {
		t.Errorf("secret lookup: got %q", secVal)
	}

	// JWT sign
	jwtToken := EvaluateMacroText("{{jwt_sign({\"alg\":\"HS256\",\"typ\":\"JWT\"}, {\"user\":\"admin\"}, {{$secret.JWT_SALT}})}}", secrets)
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT token, got %d: %q", len(parts), jwtToken)
	}
	if parts[0] != base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) {
		t.Errorf("JWT header mismatch: %s", parts[0])
	}
}

func TestMacroEvaluateRequestMacros(t *testing.T) {
	secrets := map[string]string{"TOKEN": "secret123"}
	req := requestInput{
		Method: "POST",
		URL:    "http://target.test/api/order?ref={{rand_str(8)}}",
		Headers: map[string]string{
			"Authorization": "Bearer {{$secret.TOKEN}}",
			"X-Request-ID":  "{{uuid4()}}",
		},
		Body: `{"timestamp": {{ts_sec()}}, "hash": "{{sha256(payload)}}"}`,
	}

	evaluated := EvaluateRequestMacros(req, secrets)

	if strings.Contains(evaluated.URL, "{{") {
		t.Errorf("unexpanded macro in URL: %s", evaluated.URL)
	}
	if evaluated.Headers["Authorization"] != "Bearer secret123" {
		t.Errorf("expected secret in Authorization header, got %s", evaluated.Headers["Authorization"])
	}
	if strings.Contains(evaluated.Headers["X-Request-ID"], "{{") {
		t.Errorf("unexpanded UUID in X-Request-ID: %s", evaluated.Headers["X-Request-ID"])
	}
	if strings.Contains(evaluated.Body, "{{") {
		t.Errorf("unexpanded macro in Body: %s", evaluated.Body)
	}
	if !strings.Contains(evaluated.Body, "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5") {
		t.Errorf("expected sha256(payload) in Body: %s", evaluated.Body)
	}
}
