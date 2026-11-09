package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every request of a run goes through one transport, so that is the only place
// where the count can be correct. This test exists because it was not: the count
// lived at the call sites, which cover the crawl and the per-surface baseline but
// nothing a detector sent, so a live run against a real target reported
// "requests: 2" after nine modules had spent a minute and a half hitting it.
//
// The number is not decoration. It is what an operator reads to judge how hard a
// scan pressed a target, so under-reporting it by an order of magnitude is the
// difference between an honest report and a reassuring one.
func TestEveryRequestTheRunMakesIsCounted(t *testing.T) {
	var seen int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/s" method="get"><input name="q"></form></body></html>`)
	}))
	defer server.Close()

	request := ScanRequest{
		URL:          server.URL + "/",
		MaxPages:     1,
		MaxDepth:     0,
		Concurrency:  1,
		RoundTripper: http.DefaultTransport,
	}
	// A Scan needs its transport to count, and Run builds one internally, so the
	// count is read from the transport the run actually used.
	scan := NewScan(request, nil)
	report, err := scan.Run(context.Background())
	if err != nil {
		t.Fatalf("the run failed: %v", err)
	}
	if report.Stats.Requests <= 0 {
		t.Fatalf("a run that fetched a page reports %d requests", report.Stats.Requests)
	}
	if seen == 0 {
		t.Fatal("the target was never called, so the count cannot mean anything")
	}
	// The count must not exceed what the target actually received, and it must not
	// be a small fraction of it: a detector's probes are the bulk of a run.
	if report.Stats.Requests < seen {
		t.Fatalf("the run reports %d requests but the target received %d: probes are uncounted",
			report.Stats.Requests, seen)
	}
}

// A request that fails still counts. It reached for the target, and a counter
// that hid the failures would under-report the run's footprint rather than
// describe it.
func TestAFailedRequestStillCounts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The connection is closed without a response, which is the shape of a
		// target that accepts and then stalls.
		hj, _ := w.(http.Hijacker)
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer server.Close()

	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	_, _ = transport.Do(context.Background(), http.MethodGet, server.URL+"/", nil, false, nil)
	if transport.Requests() != 1 {
		t.Fatalf("a request that failed counts as %d, want 1", transport.Requests())
	}
	_, _ = transport.Do(context.Background(), http.MethodGet, server.URL+"/", nil, false, nil)
	if transport.Requests() != 2 {
		t.Fatalf("two requests count as %d, want 2", transport.Requests())
	}
}

// A run that fails after spending requests still reports them. The counter is
// the one number that describes what the scan did to the target, so reporting
// zero on a failed run describes it wrongly.
//
// The target has to actually refuse the connection. A start page that answers but
// carries no links and no form still counts as a fetched page, so the run walks
// past the failure path and the counter would be set by the ordinary end-of-run
// assignment — which is exactly what made an earlier version of this test pass on
// the defect it exists to catch.
func TestAFailedRunStillReportsTheRequestsItSpent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer server.Close()

	report, err := NewScan(ScanRequest{
		URL: server.URL + "/", MaxPages: 1, MaxDepth: 0,
		RoundTripper: http.DefaultTransport,
	}, nil).Run(context.Background())
	if err == nil {
		t.Fatal("a target that closes the connection must fail the run, not report a clean scan")
	}
	if len(report.Visited) != 0 {
		t.Fatalf("a failed crawl visited %v", report.Visited)
	}
	if report.Stats.Requests < 1 {
		t.Fatalf("a failed run that reached for the target reports %d requests, want at least 1",
			report.Stats.Requests)
	}
}
