package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestArgumentInjectionDetectsCLIUsageOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repo := r.URL.Query().Get("repo")
		if repo == "--help" {
			_, _ = w.Write([]byte("usage: git [--version] [--help] <command> [<args>]"))
			return
		}
		_, _ = w.Write([]byte("cloned repository ok"))
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{
		URL:    srv.URL + "/clone",
		Method: http.MethodGet,
		Param:  "repo",
		Source: SourceQuery,
		Values: url.Values{"repo": {"myrepo"}},
	}
	baseline, err := tr.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	findings := (ArgumentInjection{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 arg_injection finding, got %d", len(findings))
	}
	if findings[0].CWE != "CWE-88" || findings[0].Tier != TierVerified {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}
