package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestErrorDisclosureDetectsStackTraceOnMalformedInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "[]" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Traceback (most recent call last):\n  File \"/app/views.py\", line 42\nValueError: bad id"))
			return
		}
		_, _ = w.Write([]byte("item 1"))
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{
		URL:    srv.URL + "/item",
		Method: http.MethodGet,
		Param:  "id",
		Source: SourceQuery,
		Values: url.Values{"id": {"1"}},
	}
	baseline, err := tr.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	findings := (ErrorDisclosure{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 error_disclosure finding, got %d", len(findings))
	}
	if findings[0].CWE != "CWE-209" || findings[0].Tier != TierVerified {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}
