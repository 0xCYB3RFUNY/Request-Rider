package active

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCrossDomainPoliciesDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crossdomain.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`)
			return
		}
		if r.URL.Path == "/clientaccesspolicy.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `<access-policy><cross-domain-access><policy><allow-from><domain uri="*"/></allow-from></policy></cross-domain-access></access-policy>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	transport := mustTransport(t)
	detector := CrossDomain{}
	p := Point{URL: server.URL + "/index.html", Method: http.MethodGet}

	findings := detector.Scan(context.Background(), transport, p, nil)
	if len(findings) < 2 {
		t.Fatalf("expected 2 crossdomain findings, got %d: %+v", len(findings), findings)
	}

	foundFlash := false
	foundSL := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Flash") {
			foundFlash = true
		}
		if strings.Contains(f.Title, "Silverlight") {
			foundSL = true
		}
	}

	if !foundFlash {
		t.Errorf("missing Flash crossdomain finding")
	}
	if !foundSL {
		t.Errorf("missing Silverlight crossdomain finding")
	}
}
