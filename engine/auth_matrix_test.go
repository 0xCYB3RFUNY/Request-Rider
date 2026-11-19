package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMatrixHeaderCloningAndStripAuth(t *testing.T) {
	base := map[string]string{
		"Authorization": "Bearer owner-token",
		"Cookie":        "session=owner-sid",
		"X-Custom":      "keep-me",
	}

	// Role overriding Authorization case-insensitively
	roleUserB := authMatrixRoleInput{
		Name: "User_B",
		Headers: map[string]string{
			"authorization": "Bearer user-b-token",
		},
	}
	resB := cloneAndApplyRoleHeaders(base, roleUserB)
	if resB["authorization"] != "Bearer user-b-token" {
		t.Fatalf("expected user-b-token, got %q", resB["authorization"])
	}
	if _, exists := resB["Authorization"]; exists {
		t.Fatalf("expected old Authorization key to be replaced")
	}
	if resB["X-Custom"] != "keep-me" {
		t.Fatalf("expected X-Custom to remain")
	}

	// Anonymous role with StripAuth
	roleAnon := authMatrixRoleInput{
		Name:      "Anonymous",
		RoleType:  "anon",
		StripAuth: true,
	}
	resAnon := cloneAndApplyRoleHeaders(base, roleAnon)
	if _, ok := resAnon["Authorization"]; ok {
		t.Fatalf("expected Authorization stripped")
	}
	if _, ok := resAnon["Cookie"]; ok {
		t.Fatalf("expected Cookie stripped")
	}
	if resAnon["X-Custom"] != "keep-me" {
		t.Fatalf("expected non-auth header X-Custom preserved")
	}
}

func TestAuthMatrixJSONFingerprintAndClassification(t *testing.T) {
	keysA := extractJSONKeysFingerprint(`{"id": 1, "user": {"email": "a@test", "role": "admin"}}`)
	keysB := extractJSONKeysFingerprint(`{"id": 2, "user": {"email": "b@test", "role": "user"}}`)
	keysPartial := extractJSONKeysFingerprint(`{"id": 2, "user": {"email": "b@test"}}`)

	if jaccard := jsonKeysJaccard(keysA, keysB); jaccard != 1.0 {
		t.Fatalf("expected jaccard 1.0, got %f", jaccard)
	}
	if jaccard := jsonKeysJaccard(keysA, keysPartial); jaccard <= 0 || jaccard >= 1.0 {
		t.Fatalf("expected partial jaccard between 0 and 1, got %f", jaccard)
	}

	baseline := authMatrixRoleResult{
		Status:   200,
		Body:     `{"id":1,"secret":"top"}`,
		JSONKeys: extractJSONKeysFingerprint(`{"id":1,"secret":"top"}`),
	}
	if v := classifyAuthMatrixVerdict(baseline, authMatrixRoleResult{Status: 403}); v != "ENFORCED" {
		t.Fatalf("expected ENFORCED for 403, got %s", v)
	}
	if v := classifyAuthMatrixVerdict(baseline, authMatrixRoleResult{Status: 401}); v != "ENFORCED" {
		t.Fatalf("expected ENFORCED for 401, got %s", v)
	}
	if v := classifyAuthMatrixVerdict(baseline, authMatrixRoleResult{
		Status:   200,
		Body:     `{"id":1,"secret":"top"}`,
		JSONKeys: baseline.JSONKeys,
	}); v != "BYPASSED_IDENTICAL" {
		t.Fatalf("expected BYPASSED_IDENTICAL, got %s", v)
	}
	if v := classifyAuthMatrixVerdict(baseline, authMatrixRoleResult{
		Status:   200,
		Body:     `{"id":1}`,
		JSONKeys: extractJSONKeysFingerprint(`{"id":1}`),
	}); v != "BYPASSED_PARTIAL" {
		t.Fatalf("expected BYPASSED_PARTIAL, got %s", v)
	}
}

func TestAuthMatrixEndToEndConcurrentRoles(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch auth {
		case "Bearer admin-token":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":100,"owner":"admin","ssn":"999-00-1111"}`))
		case "Bearer manager-token":
			// Vulnerable BOLA: manager gets identical response
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":100,"owner":"admin","ssn":"999-00-1111"}`))
		case "Bearer user-b-token":
			// Partial leak: user B gets partial fields
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":100,"owner":"admin"}`))
		default:
			// Enforced for anonymous
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	}))
	defer targetSrv.Close()

	s := &server{}
	payload := authMatrixInput{
		BaseRequest: requestInput{
			Method: http.MethodGet,
			URL:    targetSrv.URL + "/api/v1/account/100",
			Headers: map[string]string{
				"Authorization": "Bearer admin-token",
			},
		},
		Roles: []authMatrixRoleInput{
			{
				ID:         1,
				Name:       "Admin",
				RoleType:   "admin",
				IsBaseline: true,
				Headers:    map[string]string{"Authorization": "Bearer admin-token"},
			},
			{
				ID:       2,
				Name:     "Manager",
				RoleType: "manager",
				Headers:  map[string]string{"Authorization": "Bearer manager-token"},
			},
			{
				ID:       3,
				Name:     "User_B",
				RoleType: "user",
				Headers:  map[string]string{"Authorization": "Bearer user-b-token"},
			},
			{
				ID:        4,
				Name:      "Anonymous",
				RoleType:  "anon",
				StripAuth: true,
			},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/proxy/repeater/auth-matrix", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	s.repeaterAuthMatrix(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		OK      bool                   `json:"ok"`
		Count   int                    `json:"count"`
		Results []authMatrixRoleResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || len(resp.Results) != 4 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	verdicts := map[string]string{}
	for _, r := range resp.Results {
		verdicts[r.RoleName] = r.Verdict
	}
	if verdicts["Admin"] != "BASELINE" {
		t.Fatalf("expected Admin BASELINE, got %s", verdicts["Admin"])
	}
	if verdicts["Manager"] != "BYPASSED_IDENTICAL" {
		t.Fatalf("expected Manager BYPASSED_IDENTICAL, got %s", verdicts["Manager"])
	}
	if verdicts["User_B"] != "BYPASSED_PARTIAL" {
		t.Fatalf("expected User_B BYPASSED_PARTIAL, got %s", verdicts["User_B"])
	}
	if verdicts["Anonymous"] != "ENFORCED" {
		t.Fatalf("expected Anonymous ENFORCED, got %s", verdicts["Anonymous"])
	}
}
