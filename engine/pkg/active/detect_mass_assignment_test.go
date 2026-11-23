package active

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMassAssignmentDetectsAcceptedPrivilegeField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"id":1,"username":"alice","role":"user","is_admin":false}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		role := "user"
		if v, ok := body["role"].(string); ok && v != "" {
			role = v
		}
		isAdmin := false
		if v, ok := body["is_admin"].(bool); ok {
			isAdmin = v
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":       1,
			"username": "alice",
			"role":     role,
			"is_admin": isAdmin,
		})
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{URL: srv.URL + "/api/profile", Method: http.MethodGet}
	baseline, err := tr.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	findings := (MassAssignment{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 mass_assignment finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Module != "mass_assignment" || findings[0].Tier != TierVerified {
		t.Fatalf("unexpected finding metadata: %+v", findings[0])
	}
}

func TestMassAssignmentSkipsNonJSONNonAPISurface(t *testing.T) {
	p := Point{URL: "http://target.test/about", Method: http.MethodGet}
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: "<html>About</html>"}
	findings := (MassAssignment{}).Scan(context.Background(), nil, p, baseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on static HTML page, got %d", len(findings))
	}
}
