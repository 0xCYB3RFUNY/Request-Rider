package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func overrideTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport
}

// The two override shapes are separate claims and the fixture answers both: the
// host header is echoed into an absolute URL, and the rewriting header makes the
// request answer as a resource it did not name.
func overrideFixture(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/" {
			// A canary path the application does not have answers not-found,
			// and that is the precondition for the subtraction below. Without
			// it the header request's 200 says nothing a direct request did not
			// already say.
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<html><body>no such page</body></html>`))
			return
		}
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			w.Write([]byte(`<html><body><a href="http://` + host + `/reset">reset</a></body></html>`))
			return
		}
		if override := r.Header.Get("X-Original-URL"); override != "" {
			w.Write([]byte(`<html><body>served ` + override + `</body></html>`))
			return
		}
		w.Write([]byte(`<html><body>home</body></html>`))
	})
	server := httptest.NewServer(mux)
	return server
}

func TestURLOverrideReportsBothOverrideShapes(t *testing.T) {
	server := overrideFixture(t)
	defer server.Close()

	point := Point{URL: server.URL + "/", Method: http.MethodGet, Origin: server.URL + "/"}
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body>home</body></html>"}

	findings := (URLOverride{}).Scan(context.Background(), overrideTransport(t), point, baseline)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (the host override and the path override)", len(findings))
	}
	hostedOverridden := false
	rewritten := false
	for _, finding := range findings {
		switch {
		case strings.Contains(finding.Title, "Absolute URL Built From"):
			hostedOverridden = true
		case strings.Contains(finding.Title, "Request URL Override Honoured"):
			rewritten = true
		}
	}
	if !hostedOverridden {
		t.Error("no host-override row; the injected hostname is the proof and it was in the response")
	}
	if !rewritten {
		t.Error("no path-override row")
	}
}

// The control: a server that answers the same page for every header and 404 for
// the canary path is a server that honours neither, and reporting it would be
// reporting the run's own probe rather than the target's behaviour.
func TestURLOverrideIsSilentOnAServerThatHonoursNothing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>home</body></html>`))
	}))
	defer server.Close()

	point := Point{URL: server.URL + "/", Method: http.MethodGet, Origin: server.URL + "/"}
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body>home</body></html>"}
	findings := (URLOverride{}).Scan(context.Background(), overrideTransport(t), point, baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: %+v", len(findings), findings[0].Title)
	}
}
