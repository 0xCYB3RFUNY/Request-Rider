package active

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestBusinessLogicMetadata(t *testing.T) {
	bl := BusinessLogic{}
	if bl.Name() != "business-logic" {
		t.Errorf("expected module name 'business-logic', got %q", bl.Name())
	}
	if bl.Level() != LevelHost {
		t.Errorf("expected level LevelHost, got %v", bl.Level())
	}
}

func TestBusinessLogicTOTP(t *testing.T) {
	code := generateTOTP("IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH")
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	if _, err := strconv.Atoi(code); err != nil {
		t.Fatalf("expected numeric TOTP code, got %q", code)
	}
}

func TestBusinessLogicScan(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/user/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authentication": map[string]any{
					"token": "fake_admin_jwt_token",
					"bid":   1,
				},
			})
		case "/api/Users":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
		case "/rest/user/reset-password":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
		case "/api/BasketItems/":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
		case "/rest/basket/1/checkout":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
		case "/rest/deluxe-membership":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
		case "/api/Feedbacks":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success"})
		case "/rest/track-order/' || true || '":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[{"orderId":"1"},{"orderId":"2"}]}`))
		case "/ftp/eastere.gg%2500.md":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("congratulations, easter egg!"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	bl := BusinessLogic{}
	point := Point{URL: ts.URL, Origin: ts.URL}

	findings := bl.Scan(context.Background(), transport, point, nil)
	if len(findings) == 0 {
		t.Fatalf("expected business-logic findings against vulnerable test server, got 0")
	}

	foundSQLi := false
	foundEmptyReg := false
	foundNegOrder := false
	foundDeluxe := false
	for _, f := range findings {
		if f.Module != "business-logic" {
			t.Errorf("finding module = %q, expected 'business-logic'", f.Module)
		}
		if f.Title == "Authentication Bypass via SQL Injection in Login API" {
			foundSQLi = true
		}
		if f.Title == "Improper Input Validation: Empty Credentials Registration Permitted" {
			foundEmptyReg = true
		}
		if f.Title == "Business Logic Flaw: Negative Quantity In Basket Leads To Order Total Deduction" {
			foundNegOrder = true
		}
		if f.Title == "Privilege Escalation: Free Premium / Deluxe Membership via Parameter Manipulation" {
			foundDeluxe = true
		}
	}

	if !foundSQLi {
		t.Errorf("expected SQLi login finding")
	}
	if !foundEmptyReg {
		t.Errorf("expected Empty Registration finding")
	}
	if !foundNegOrder {
		t.Errorf("expected Negative Order finding")
	}
	if !foundDeluxe {
		t.Errorf("expected Deluxe Escalation finding")
	}
}
