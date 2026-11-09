package active

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// oastFixture is the same protocol the engine's own OAST tool speaks: register,
// poll, delete. It is served by the test rather than by an external service so
// the whole exchange is observable — "the callback arrived" has to be something
// this test can make happen, not something it has to be told about.
type oastFixture struct {
	mu        sync.Mutex
	domain    string
	callbacks int
	deleted   bool
	// fireOnRegister makes the service report one callback the moment a probe
	// registers, which is how "the target called back" is simulated.
	fireOnRegister bool
}

func (fixture *oastFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		domain := fixture.domain
		fire := fixture.fireOnRegister
		if fire {
			fixture.callbacks++
		}
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"payload_url": "http://" + domain + "/rr",
			"domain":      domain,
		})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		events := []map[string]interface{}{}
		if fixture.callbacks > 0 {
			fixture.callbacks--
			events = append(events, map[string]interface{}{
				"protocol": "http",
				"source":   "203.0.113.9:41234",
			})
		}
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
	})
	mux.HandleFunc("/listener/", func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.deleted = true
		fixture.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	// Every other path counts as a callback.
	//
	// It is a catch-all rather than the one path the register hands out, because
	// the probes do not all use that path: an XXE entity carries a `/xxe` suffix,
	// a command probe carries its own canary as the last segment, and a header
	// probe carries `/hdr`. The specific patterns above win over it, so
	// `/register` and `/poll` are not counted as callbacks.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.callbacks++
		fixture.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func (fixture *oastFixture) wasDeleted() bool {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.deleted
}

// The callback is the evidence: the application was handed a watched address
// and the address was contacted.
func TestOutOfBandReportsACallback(t *testing.T) {
	fixture := &oastFixture{domain: "canary.oast.example", fireOnRegister: true}
	server := fixture.server(t)

	client, err := NewOASTClient(context.Background(), OASTSettings{ServerURL: server.URL, PollInterval: 10 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("NewOASTClient: %v", err)
	}
	defer client.Close(context.Background())

	findings := (OutOfBand{}.withClient(client)).Scan(context.Background(), mustTransport(t),
		Point{URL: "http://example.com/fetch", Method: http.MethodGet, Param: "url",
			Values: map[string][]string{"url": {"http://example.com/"}}},
		&Response{StatusCode: 200})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the watched address was contacted", len(findings))
	}
	if !strings.Contains(findings[0].Title, "0x00100A00") {
		t.Errorf("title = %q, want the original's identifier in it", findings[0].Title)
	}
	if !strings.Contains(findings[0].Evidence, "203.0.113.9") {
		t.Errorf("the evidence does not name where the callback came from: %s", findings[0].Evidence)
	}
}

// The control: a service that reports no callback. "The target did not call
// back" is the negative answer the row needs, and a detector that invented one
// would be the worst kind of scanner.
func TestOutOfBandIsSilentWithoutACallback(t *testing.T) {
	fixture := &oastFixture{domain: "canary.oast.example"}
	server := fixture.server(t)

	client, err := NewOASTClient(context.Background(), OASTSettings{ServerURL: server.URL, PollInterval: 10 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("NewOASTClient: %v", err)
	}
	findings := (OutOfBand{}.withClient(client)).Scan(context.Background(), mustTransport(t),
		Point{URL: "http://example.com/fetch", Method: http.MethodGet, Param: "url",
			Values: map[string][]string{"url": {"http://example.com/"}}},
		&Response{StatusCode: 200})
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// A run with no out-of-band service is silent, and that is a state the register
// names rather than a silent downgrade.
func TestOutOfBandIsSilentWithoutAService(t *testing.T) {
	t.Setenv(OASTServerEnv, "")
	t.Setenv(OASTTokenEnv, "")
	findings := (OutOfBand{}).Scan(context.Background(), mustTransport(t),
		Point{URL: "http://example.com/fetch", Method: http.MethodGet, Param: "url"},
		&Response{StatusCode: 200})
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// The JWT probe has to rewrite the header and keep a signature the run cannot
// have produced: a server that verified before fetching must reject the token,
// so the callback is the only thing that can prove it did not.
func TestJWTKeyURLProbeRewritesTheHeaderAndKeepsTheSignature(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.fixture-signature"
	rewritten, err := jwtWithHeader(token, "jku", "http://canary.oast.example/rr")
	if err != nil {
		t.Fatalf("jwtWithHeader: %v", err)
	}
	parts := strings.Split(rewritten, ".")
	if len(parts) != 3 {
		t.Fatalf("rewritten token has %d segments, want 3", len(parts))
	}
	if parts[2] != "fixture-signature" {
		t.Errorf("the signature changed to %q; a server that verifies first must still reject it", parts[2])
	}
	if !strings.Contains(rewritten, "p") || !strings.Contains(rewritten, "ku") {
		t.Errorf("the header does not carry jku: %s", rewritten)
	}
}

func TestJWTKeyURLProbeOnlyRunsOnAToken(t *testing.T) {
	for _, value := range []string{"", "plain", "a.b", "a.b.c.d"} {
		if looksLikeJWT(value) {
			t.Errorf("%q accepted as a token", value)
		}
	}
	if !looksLikeJWT("aGVhZGVy.cGF5bG9hZA.c2ln") {
		t.Error("a three-segment value was refused as a token")
	}
}

// The listener is released, so the service stops watching an address no run is
// offering any more.
func TestOASTClientReleasesItsListener(t *testing.T) {
	fixture := &oastFixture{domain: "canary.oast.example"}
	server := fixture.server(t)
	client, err := NewOASTClient(context.Background(), OASTSettings{ServerURL: server.URL, PollInterval: 10 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("NewOASTClient: %v", err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fixture.wasDeleted() {
		t.Fatal("the listener was not released")
	}
}
