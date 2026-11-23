package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKnownCVEsDetectsNextJSMiddlewareBypassCVE202529927(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-middleware-subrequest") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"admin_dashboard":true,"secret":"admin-data"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{URL: srv.URL + "/admin", Method: http.MethodGet}
	baseline, err := tr.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	findings := (KnownCVEs{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 known_cves finding, got %d", len(findings))
	}
	if findings[0].CVE != "CVE-2025-29927" || findings[0].CWE != "CWE-287" || findings[0].Tier != TierVerified {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestGenericFindingDoesNotHallucinateCVE(t *testing.T) {
	f, _ := NewFinding(Spec{
		Module:   "sqli",
		Title:    "SQL injection via q",
		Claimed:  SeverityCritical,
		Tier:     TierVerified,
		Point:    Point{URL: "http://target.test/search", Method: http.MethodGet, Param: "q"},
		Payload:  "'",
		Evidence: "sqlite_error",
	})
	if f.CWE != "CWE-89" {
		t.Fatalf("expected CWE-89, got %q", f.CWE)
	}
	if f.CVE != "" || len(f.CVEs) != 0 {
		t.Fatalf("expected empty CVE/CVEs on generic SQLi finding, got CVE=%q CVEs=%v", f.CVE, f.CVEs)
	}
}
