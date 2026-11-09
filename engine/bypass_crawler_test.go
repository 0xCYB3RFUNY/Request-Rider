package main

// The crawler's 403 walk, tested through the crawler client and not through
// `pkg/bypass` directly.
//
// The reason it is a separate file: the package tests prove the ladder reaches a
// resource a fixture refuses, and they cannot prove the *crawl* uses it. Those are
// different claims. This file makes the second one falsifiable — if the transport
// stopped consulting the ladder, every test here goes red, which is what a
// "connected" that never happened looks like from the outside.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"intruder/engine/pkg/bypass"
)

// shapeRefusingServer refuses a plain request and answers a request whose path
// carries the traversal trick, which is the shape `path-segment-1` produces for
// the path used below.
type shapeRefusingServer struct {
	mu       sync.Mutex
	requests []string
}

// ServeHTTP answers 403 for a plain `/admin/report` and 200 once the path hides a
// segment behind `..;`. Counting matters: the walk spends a request per form, and
// a test that only checks the final status cannot tell a walk from a single lucky
// request.
func (s *shapeRefusingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.URL.RequestURI())
	s.mu.Unlock()

	if strings.Contains(r.URL.Path, "..;") {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached"))
		return
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("denied"))
}

func (s *shapeRefusingServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// TestTheCrawlWalksTheLadderWhenTheEdgeRefuses is the positive half: with the
// walk on, a page the plain crawl cannot read is read.
func TestTheCrawlWalksTheLadderWhenTheEdgeRefuses(t *testing.T) {
	fixture := &shapeRefusingServer{}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)

	var (
		mu        sync.Mutex
		reachedBy []string
	)
	// `path-segment-1` names exactly one form on purpose: this test is about the
	// crawl consulting a ladder, not about which forms a ladder contains. A nil
	// selection would mean "off" — see `newCrawlerClientWithBypass` — and the walk
	// would correctly not run, so the test would be measuring nothing.
	client, err := newCrawlerClientWithBypass(
		server.Client().Transport, crawlerRequestShape{}, []string{"path-segment-1"},
		func(_, _, form string, _ int) {
			mu.Lock()
			reachedBy = append(reachedBy, form)
			mu.Unlock()
		},
	)
	if err != nil {
		t.Fatalf("build the crawl client: %v", err)
	}

	resp, err := client.Get(server.URL + "/admin/report")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the walk did not reach the page: status %d after %d request(s) %v",
			resp.StatusCode, len(fixture.seen()), fixture.seen())
	}
	mu.Lock()
	notified := len(reachedBy)
	mu.Unlock()
	if notified != 1 {
		t.Errorf("the bypass callback fired %d times, want exactly 1: a page reached "+
			"only through a walk has to say so once, not silently and not repeatedly", notified)
	}
}

// TestTheCrawlWithoutTheWalkIsUnchanged is the negative half, and it is the one
// that matters for the default.
//
// With the walk off, the crawl must send exactly the request it sent before this
// existed. A change that quietly turns the walk on would make a thousand-page
// crawl cost thousands more requests for a feature nobody asked for.
func TestTheCrawlWithoutTheWalkIsUnchanged(t *testing.T) {
	fixture := &shapeRefusingServer{}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)

	client, err := newCrawlerClient(server.Client().Transport, crawlerRequestShape{})
	if err != nil {
		t.Fatalf("build the crawl client: %v", err)
	}
	resp, err := client.Get(server.URL + "/admin/report")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the default crawl answered %d; without the walk the edge's refusal is the answer",
			resp.StatusCode)
	}
	if seen := fixture.seen(); len(seen) != 1 {
		t.Errorf("the default crawl sent %d requests (%v), want exactly 1: the walk must be off by default",
			len(seen), seen)
	}
}

// TestTheCrawlSpendsNothingWhenThePageIsNotRefused is the cost rule.
//
// A site that answers the plain request has refused nothing, so the ladder must
// not be walked at all. This is the difference between a bound the operator can
// see and a bound that quietly takes a thousand extra requests.
func TestTheCrawlSpendsNothingWhenThePageIsNotRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fine"))
	}))
	t.Cleanup(server.Close)

	// A populated selection, so a ladder exists and its request counter can be read.
	// The assertion is about that counter, so a client with no ladder would fail
	// on the setup rather than prove the cost rule.
	client, err := newCrawlerClientWithBypass(
		server.Client().Transport, crawlerRequestShape{}, []string{"path-segment-1"}, nil,
	)
	if err != nil {
		t.Fatalf("build the crawl client: %v", err)
	}
	resp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if driver := crawlerDriverOf(t, client); driver.Requests() != 0 {
		t.Errorf("the driver counted %d request(s); a page that was not refused must not "+
			"enter the walk at all", driver.Requests())
	}
}

// TestTheCrawlKeepsTheRefusalWhenNothingReachesIt is the honesty half.
//
// When every form is refused, the caller gets the 403 the edge actually sent —
// with its body — not the last probe's answer and not an error. A crawler that
// published the shape of a probe as the state of a page would make the map lie.
func TestTheCrawlKeepsTheRefusalWhenNothingReachesIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("home"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied by the edge"))
	}))
	t.Cleanup(server.Close)

	notified := make([]string, 0, 1)
	client, err := newCrawlerClientWithBypass(
		server.Client().Transport, crawlerRequestShape{}, []string{"path-segment-1"},
		func(_, _, form string, _ int) {
			notified = append(notified, form)
		},
	)
	if err != nil {
		t.Fatalf("build the crawl client: %v", err)
	}

	resp, err := client.Get(server.URL + "/never-reached")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d; nothing reached the page, so the edge's refusal is the answer", resp.StatusCode)
	}
	body := make([]byte, 64)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "denied by the edge") {
		t.Errorf("body %q; the refusal's own body was discarded, so the caller cannot tell "+
			"a refused page from an empty one", string(body[:n]))
	}
	if len(notified) == 0 {
		t.Error("no bypass callback: a page that the walk could not reach has to be reported " +
			"as tried-and-refused, or a map that is missing pages has no explanation")
	}
	if len(notified) == 1 && notified[0] == "" {
		t.Error("the callback fired with an empty form name, which names nothing")
	}
}

// crawlerDriverOf reaches the transport's driver and checks the two structural
// facts the walk depends on.
//
// Both checks are here rather than only at the call site because they are the
// failure mode that looks like success: a walk whose client used this transport
// would work — pages would be reached — while every form went out decorated
// twice and re-entered the walk it was sent from. A passing test with a walk
// wired that way proves nothing, so the wiring itself is asserted.
func crawlerDriverOf(t *testing.T, client *http.Client) *bypass.Driver {
	t.Helper()
	transport, ok := client.Transport.(crawlerTransport)
	if !ok {
		t.Fatalf("the crawl client carries %T, not a crawlerTransport", client.Transport)
	}
	if transport.ladder == nil {
		t.Fatal("the client was built without a ladder, so there is no counter to read")
	}
	if transport.walk == nil {
		t.Fatal("the ladder has no client of its own; the walk would recurse into the decorator")
	}
	if _, isDecorator := transport.walk.Transport.(crawlerTransport); isDecorator {
		t.Fatal("the walk's client uses a crawlerTransport, so a form would be decorated twice " +
			"and would re-enter the walk it was sent from")
	}
	return transport.ladder
}
