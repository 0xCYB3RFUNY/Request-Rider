package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func rscTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport
}

// rscFixture answers a Flight action with the component stream. The content type
// is the signal, and it is the one thing that separates a server that routed the
// request into the Server Components render from one that rejected the shape as
// a form post.
const rscFlightAnswer = "0:{\"digest\":\"rr-rsc\"}\n1:\"handled\"\n"

func rscFixtureServer(t *testing.T, answer bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Next-Action") == "" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body>home</body></html>`))
			return
		}
		if !answer {
			// The control: a server that treats the body as an ordinary form
			// post and answers with the page it would have answered anyway.
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body>home</body></html>`))
			return
		}
		w.Header().Set("Content-Type", "text/x-component")
		w.Write([]byte(rscFlightAnswer))
	}))
}

func TestReactServerFlightReportsAnActionThatWasHandled(t *testing.T) {
	server := rscFixtureServer(t, true)
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body>home</body></html>"}
	findings := (ReactServerFlight{}).Scan(context.Background(), rscTransport(t),
		Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the component stream is the signal", len(findings))
	}
	if findings[0].Tier != TierPotential {
		t.Errorf("tier = %q, want potential: an error envelope is not execution", findings[0].Tier)
	}
	if strings.Contains(findings[0].Title, "RCE") {
		t.Errorf("title claims execution: %q", findings[0].Title)
	}
}

// The control is a server that never routes into the render. Nothing here claims
// what a Flight endpoint did with a body it never treated as Flight.
func TestReactServerFlightIsSilentOnAEndpointThatIsNotFlight(t *testing.T) {
	server := rscFixtureServer(t, false)
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body>home</body></html>"}
	findings := (ReactServerFlight{}).Scan(context.Background(), rscTransport(t),
		Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
