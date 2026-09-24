package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type closeSignalConn struct {
	net.Conn
	closed chan<- struct{}
}

func (c *closeSignalConn) Close() error {
	err := c.Conn.Close()
	select {
	case c.closed <- struct{}{}:
	default:
	}
	return err
}

func TestRouteResolverUsesConfiguredDialer(t *testing.T) {
	const dialError = "route dialer invoked"
	var dialMu sync.Mutex
	var networks []string
	var targets []string
	manager := &routeManager{
		config: routeConfig{Address: "127.0.0.1:9050"},
		dialer: func(_ context.Context, network, target string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			networks = append(networks, network)
			targets = append(targets, target)
			return nil, errors.New(dialError)
		},
	}

	_, err := manager.resolver().LookupHost(context.Background(), "route-only.invalid")
	if err == nil || !strings.Contains(err.Error(), dialError) {
		t.Fatalf("LookupHost() error = %v, want configured dialer error", err)
	}
	if len(networks) == 0 {
		t.Fatal("configured route dialer was not invoked")
	}
	if networks[0] != "tcp" {
		t.Fatalf("DNS network = %q, want tcp through SOCKS5 route", networks[0])
	}
	if targets[0] == "" {
		t.Fatal("DNS dial target is empty")
	}
}

func TestSitemapReferencesIgnoreRobotsDirectives(t *testing.T) {
	body := "User-agent: *\nDisallow: /private\nAllow: /\nSitemap: https://example.test/sitemap.xml\n"
	links := extractSitemapReferences(body)
	if len(links) != 1 || links[0] != "https://example.test/sitemap.xml" {
		t.Fatalf("extractSitemapReferences() = %#v, want only sitemap URL", links)
	}
}

func TestTargetMapVisitsURLListedInRobotsDisallow(t *testing.T) {
	var visitedMu sync.Mutex
	var visited []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visitedMu.Lock()
		visited = append(visited, r.URL.Path)
		visitedMu.Unlock()
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private/\n"))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="/private/">private</a>`))
		case "/private/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("private fixture"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()

	job := &targetMap{status: "running", startURL: target.URL, maxPages: 10}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &server{}
	s.runTargetMap(1, job, ctx, targetMapInput{
		URL:        target.URL,
		MaxPages:   10,
		MaxDepth:   2,
		SameOrigin: true,
	})

	job.mu.RLock()
	status := job.status
	pages := append([]map[string]interface{}(nil), job.pages...)
	job.mu.RUnlock()
	if status != "completed" {
		t.Fatalf("target map status = %q, want completed", status)
	}
	foundPrivate := false
	for _, page := range pages {
		if page["url"] == target.URL+"/private/" {
			foundPrivate = true
			break
		}
	}
	if !foundPrivate {
		t.Fatalf("target map pages = %#v, want robots-disallowed URL", pages)
	}
	visitedMu.Lock()
	defer visitedMu.Unlock()
	if !slices.Contains(visited, "/private/") {
		t.Fatalf("server paths = %#v, want /private/ request", visited)
	}
}

func TestRouteManagerSwitchUsesNewTransportAndClosesOldIdleConnection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	manager, err := newRouteManager()
	if err != nil {
		t.Fatalf("newRouteManager() error = %v", err)
	}
	var dials atomic.Int32
	closed := make(chan struct{}, 1)
	setDialer := func() {
		manager.mu.Lock()
		manager.dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &closeSignalConn{Conn: conn, closed: closed}, nil
		}
		manager.mu.Unlock()
	}
	setDialer()
	old := manager.transport()

	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := manager.roundTripper().RoundTrip(req)
	if err != nil {
		t.Fatalf("first RoundTrip() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	if err := manager.set(routeConfig{}); err != nil {
		t.Fatalf("routeManager.set() error = %v", err)
	}
	setDialer()
	if manager.transport() == old {
		t.Fatal("route switch retained the old transport")
	}
	if manager.transport().TLSClientConfig == nil || manager.transport().TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("route switch did not preserve TLS 1.2 minimum")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("old transport did not close its idle connection")
	}

	req, err = http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = manager.roundTripper().RoundTrip(req)
	if err != nil {
		t.Fatalf("second RoundTrip() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if got := dials.Load(); got != 2 {
		t.Fatalf("dial count = %d, want 2 after transport switch", got)
	}
}

type sourceIPRoundTripper struct {
	calls int
}

func (r *sourceIPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	ip := "198.51.100.10"
	if r.calls > 1 {
		ip = "198.51.100.11"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"IP":"` + ip + `"}`)),
		Request:    req,
	}, nil
}

type sourceIPErrorRoundTripper struct {
	calls int
}

func (r *sourceIPErrorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	if r.calls > 1 {
		return nil, errors.New("source IP lookup failed")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"IP":"198.51.100.12"}`)),
		Request:    req,
	}, nil
}

func TestEnsureSourceIPAlwaysRefreshes(t *testing.T) {
	transport := &sourceIPRoundTripper{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}

	first := engine.ensureSourceIP(context.Background())
	second := engine.ensureSourceIP(context.Background())

	if first != "198.51.100.10" || second != "198.51.100.11" {
		t.Fatalf("source IPs = %q, %q; want two fresh values", first, second)
	}
	if transport.calls != 2 {
		t.Fatalf("source IP endpoint calls = %d, want 2", transport.calls)
	}
}

func TestEnsureSourceIPDoesNotReturnStaleValueOnError(t *testing.T) {
	transport := &sourceIPErrorRoundTripper{}
	engine := &server{transport: &http.Transport{}, sourceIPTransport: transport}

	if got := engine.ensureSourceIP(context.Background()); got != "198.51.100.12" {
		t.Fatalf("first source IP = %q, want 198.51.100.12", got)
	}
	if got := engine.ensureSourceIP(context.Background()); got != "" {
		t.Fatalf("source IP after failed refresh = %q, want empty", got)
	}
}

func TestExecuteContextBase64EncodesBinaryResponses(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47, 0x00, 0xff})
	}))
	defer target.Close()

	engine := &server{}
	result, err := engine.executeContext(context.Background(), requestInput{Method: "GET", URL: target.URL})
	if err != nil {
		t.Fatalf("executeContext() error = %v", err)
	}

	if result["body_encoding"] != "base64" || result["body"] != "" || result["body_content_type"] != "image/png" {
		t.Fatalf("binary result = %#v", result)
	}
	if result["body_base64"] != "iVBORwD/" {
		t.Fatalf("body_base64 = %v", result["body_base64"])
	}
}

func TestReadAnalysisBodyReportsTruncation(t *testing.T) {
	body := strings.NewReader(strings.Repeat("x", maxAnalysisBodyBytes+10))
	data, truncated, err := readAnalysisBody(body)
	if err != nil {
		t.Fatalf("readAnalysisBody() error = %v", err)
	}
	if !truncated || len(data) != maxAnalysisBodyBytes {
		t.Fatalf("readAnalysisBody() length=%d truncated=%v", len(data), truncated)
	}
}

func TestExecuteContextPreservesHTTPErrorResponses(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("RequestDataTooBig"))
	}))
	defer target.Close()

	engine := &server{}
	result, err := engine.executeContext(context.Background(), requestInput{Method: "GET", URL: target.URL})
	if err != nil {
		t.Fatalf("executeContext() error = %v", err)
	}

	if result["status"] != http.StatusBadRequest || result["status_text"] != "400 Bad Request" {
		t.Fatalf("HTTP error metadata = %#v", result)
	}
	if result["body"] != "RequestDataTooBig" || result["size"] != len("RequestDataTooBig") {
		t.Fatalf("HTTP error body = %#v", result)
	}
}

func TestIntruderLifecycle(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	engine := &server{attacks: make(map[uint64]*attack)}
	payload := []byte(`{"base_request":{"method":"GET","url":"` + target.URL + `/?id=§id§","headers":{},"body":""},"mode":"batteringRam","payloads":[["one","two"]],"transformations":[]}`)
	request := httptest.NewRequest(http.MethodPost, "/proxy/intruder", bytes.NewReader(payload))
	response := httptest.NewRecorder()
	engine.intruder(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("intruder() status = %d, want %d", response.Code, http.StatusAccepted)
	}

	var started map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	attackID := uint64(started["attack_id"].(float64))
	path := "/proxy/intruder/" + strconv.FormatUint(attackID, 10)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		statusRequest := httptest.NewRequest(http.MethodGet, path, nil)
		statusResponse := httptest.NewRecorder()
		engine.intruderStatus(statusResponse, statusRequest)
		if statusResponse.Code != http.StatusOK {
			t.Fatalf("intruderStatus() status = %d, want %d", statusResponse.Code, http.StatusOK)
		}
		var status map[string]interface{}
		if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
			t.Fatalf("decode status response: %v", err)
		}
		if status["status"] == "completed" {
			if int(status["completed"].(float64)) != 2 {
				t.Fatalf("completed = %v, want 2", status["completed"])
			}
			results := status["results"].([]interface{})
			request := results[0].(map[string]interface{})["request"].(map[string]interface{})
			if request["url"] == "" || request["method"] != "GET" {
				t.Fatalf("generated request missing from result: %v", request)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("attack did not complete before deadline")
}

func TestNormalizeIntruderMarkers(t *testing.T) {
	input := requestInput{
		URL:  "http://127.0.0.1:3000/?one=%C2%A7a%C2%A7&two=%25C2%25A7b%25C2%25A7",
		Body: "value=%C2%A7c%C2%A7",
		Headers: map[string]string{
			"X-Test": "%C2%A7d%C2%A7",
		},
	}

	normalizeIntruderMarkers(&input)
	if input.URL != "http://127.0.0.1:3000/?one=§a§&two=§b§" {
		t.Fatalf("unexpected URL: %q", input.URL)
	}
	if input.Body != "value=§c§" || input.Headers["X-Test"] != "§d§" {
		t.Fatalf("markers were not restored: body=%q headers=%q", input.Body, input.Headers["X-Test"])
	}
}

func TestRunOSINTCollectsPassiveMetadata(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "test", HttpOnly: true, Secure: true})
		_, _ = w.Write([]byte(`<html><script src="/app.js"></script><a href="/login">login</a></html>`))
	}))
	defer target.Close()

	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	result, err := runOSINT(parsed, true)
	if err != nil {
		t.Fatalf("runOSINT() error = %v", err)
	}
	httpResult := result["http"].(map[string]interface{})
	if httpResult["status"] != http.StatusOK {
		t.Fatalf("status = %v, want %d", httpResult["status"], http.StatusOK)
	}
	if len(result["redirect_chain"].([]string)) != 1 {
		t.Fatalf("redirect chain = %#v", result["redirect_chain"])
	}
	if len(result["technologies"].([]string)) == 0 {
		t.Fatalf("technology hints were empty: %#v", result)
	}
	wafCheck := result["waf_check"].(map[string]interface{})
	if wafCheck["status"] != "completed" {
		t.Fatalf("waf check = %#v", wafCheck)
	}
}

func TestDetectTechnologiesFindsWebCheckStyleSignals(t *testing.T) {
	response := map[string]interface{}{
		"headers": map[string]string{},
		"body": `<html><head>
			<meta property="og:title" content="Example">
			<link rel="manifest" href="/manifest.webmanifest">
			<link rel="alternate" type="application/rss+xml" href="/feed.xml">
			<script>window.React = React; ReactDOM.render();</script>
			<script src="/assets/react@19.2.4.js"></script>
		</head></html>`,
		"cookies": []map[string]interface{}{},
	}
	target, err := url.Parse("https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	found := strings.Join(detectTechnologies(response, target), "\n")
	for _, expected := range []string{"Open Graph", "PWA", "RSS", "React 19.2.4"} {
		if !strings.Contains(found, expected) {
			t.Fatalf("technology %q missing from %q", expected, found)
		}
	}
}

func TestRunSafeScannerProducesFindings(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-admin/" || r.URL.Path == "/xmlrpc.php" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}

		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress"></head><body>site</body></html>`))
	}))
	defer target.Close()

	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	result, err := runSafeScanner(parsed)
	if err != nil {
		t.Fatalf("runSafeScanner() error = %v", err)
	}
	if result["status"] != "completed" {
		t.Fatalf("status = %v, want completed", result["status"])
	}
	findings := result["findings"].([]map[string]interface{})
	if len(findings) == 0 {
		t.Fatal("safe scanner returned no findings")
	}
	if _, ok := findings[0]["severity"].(string); !ok {
		t.Fatalf("finding severity missing: %#v", findings[0])
	}
}

func TestRunSafeScannerSuppressesSPAHTMLFallbackProbes(t *testing.T) {
	const shell = `<html><head><script src="/main.js"></script></head><body><app-root></app-root></body></html>`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(shell))
	}))
	defer target.Close()
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runSafeScanner(parsed)
	if err != nil {
		t.Fatalf("runSafeScanner() error = %v", err)
	}
	for _, finding := range result["findings"].([]map[string]interface{}) {
		if finding["title"] == "Environment file exposure" ||
			finding["title"] == "Git metadata exposure" ||
			finding["title"] == "WordPress admin surface" {
			t.Fatalf("SPA fallback produced false positive: %#v", finding)
		}
	}
	probes := result["details"].(map[string]interface{})["probes"].([]map[string]interface{})
	for _, probe := range probes {
		if probe["same_as_baseline"] != true {
			t.Fatalf("probe was not marked as SPA fallback: %#v", probe)
		}
	}
}

func TestValidMapReferenceFiltersJavaScriptFragments(t *testing.T) {
	valid := []string{"/api/Products", "/rest/data?x=1", "https://example.test/path"}
	for _, reference := range valid {
		if !validMapReference(reference) {
			t.Errorf("validMapReference(%q) = false, want true", reference)
		}
	}
	invalid := []string{"/[\\-\\[\\]\\/\\{\\}]", "/g,`-`", "/foo\\bar", "/x;alert(1)"}
	for _, reference := range invalid {
		if validMapReference(reference) {
			t.Errorf("validMapReference(%q) = true, want false", reference)
		}
	}
}
