// Package main starts the HTTP execution engine and passive MITM proxy.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"

	"intruder/engine/pkg/enrich"
	"intruder/engine/pkg/intruder"
	"intruder/engine/pkg/passive"
	"intruder/engine/pkg/scanner"
)

// scannerStreamHeartbeat is how often a job stream writes an SSE comment while
// the run is quiet. It is shorter than the browser-side read window and than any
// ordinary intermediary timeout, so a paused or slow run keeps its connection
// without the client being able to tell the difference.
//
// It is a variable rather than a constant only so the stream test can shorten
// it; production always uses the value below.
var scannerStreamHeartbeat = 10 * time.Second

// randomSequenceBase draws the starting value of one job-id counter.
//
// The low 20 bits stay zero so the process has room for about a million ids
// before touching the next base, exactly as the old time-derived base did. The
// high 32 bits come from the OS CSPRNG, which gives about 2^32 possible bases
// instead of one per second.
//
// The result always fits a JavaScript safe integer: at most (2^32-1)<<20, below
// 2^53, so the ids survive the JSON round trip to the browser without losing
// precision. That bound is load-bearing — a full 64-bit random base would
// silently corrupt lookups on the UI side.
//
// On the essentially-impossible CSPRNG failure the function falls back to the
// old time-derived base rather than refusing to start: an engine that will not
// boot is worse than one whose first ids of that boot are time-ordered.
func randomSequenceBase() uint64 {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return uint64(binary.BigEndian.Uint32(raw[:])) << 20
	}
	return uint64(time.Now().Unix()) << 20
}

// server owns process-wide state shared by the HTTP handlers.
func withRouteGenerationContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get(routeGenerationHeader))
		if raw == "" {
			next.ServeHTTP(w, r)
			return
		}
		generation, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_ROUTE_GENERATION", fmt.Errorf("route generation must be a non-negative integer"))
			return
		}
		ctx := withExpectedRouteGeneration(r.Context(), generation)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type server struct {
	// attackSequence provides a readable identifier for each Intruder run.
	// The starting value is drawn from the OS CSPRNG once per process
	// (randomSequenceBase) rather than from the wall clock: the previous
	// `time.Now().Unix() << 20` base made every attack, listener, burst and
	// last-byte id predictable to the second, so any local process could
	// enumerate the range and read or delete another run through
	// `GET|DELETE /proxy/intruder/<attack_id>`. Within a process the counter
	// still increments by one, so ordering is preserved; across restarts the
	// base differs with overwhelming probability, which is also what keeps a
	// restarted engine from colliding with older History rows.
	attackSequence uint64
	attacks        map[uint64]*attack
	attacksMu      sync.RWMutex
	// corpusJobs holds running and finished corpus enumerations. A corpus run is
	// thousands of requests, so it cannot be one blocking HTTP call: the browser's
	// connection would be the ceiling, and that ceiling is invisible to the
	// operator. Measured on a live target: 361 s and a NetworkError.
	corpusJobs       map[string]*corpusJob
	corpusJobsMu     sync.RWMutex
	store            *passive.Store
	targetMaps       map[uint64]*targetMap
	targetMapsMu     sync.RWMutex
	oastListeners    map[uint64]*oastListener
	oastListenersMu  sync.RWMutex
	oastSequence     uint64
	bursts           map[uint64]*repeaterBurst
	burstsMu         sync.RWMutex
	burstSequence    uint64
	lastByteJobs     map[uint64]*lastByteJob
	lastByteJobsMu   sync.RWMutex
	lastByteSequence uint64
	// activeScans holds the background active-scanner runs. The key is a
	// readable identifier rather than a sequence number because the browser
	// keeps that identifier in local storage and resumes polling after a reload.
	activeScans        map[string]*activeScanJob
	activeScansMu      sync.RWMutex
	activeScanSequence uint64
	routes             *routeManager
	transport          *http.Transport
	sourceIPTransport  http.RoundTripper
	// archiveIndexBase is the Internet Archive index host used by the
	// wayback_urls transform. It is empty for the public archive and is only
	// pointed at a local fixture by the transform tests.
	archiveIndexBase string
	// osintJobSequence provides a readable identifier for each background
	// OSINT transform.
	osintJobSequence uint64
	// crawlIndexBase is the host that publishes the crawl collections. It is empty
	// for the public index and is only pointed at a local fixture by the transform
	// tests, so a test transform never reaches the public network.
	crawlIndexBase string
	// archiveIndexList replaces the archive index chain of the wayback_urls
	// transform. It is nil in production, where the chain is the Internet Archive
	// followed by the published crawl collections, and is only pointed at local
	// fixtures by the transform tests, so a test transform never reaches the
	// public network.
	archiveIndexList func(ctx context.Context, domain string) ([]archiveEndpoint, error)
	// certificateIndexList replaces the certificate transparency index chain.
	// It is nil in production and is only pointed at local fixtures by the
	// transform tests, so a test transform never reaches the public network.
	certificateIndexList func(domain string) []certificateSource
	// urlscanBase is the urlscan.io search API host used by the urlscan_search
	// transform. It is empty for the public index and is only pointed at a local
	// fixture by the transform tests, so a test transform never reaches the
	// public network.
	urlscanBase string
	// robtexBase is the free passive-DNS index host used by the `subdomains`
	// transform. It is empty for the public index and is only pointed at a local
	// fixture by the transform tests, so a test transform never reaches the
	// public network. The free tier allows ten requests per hour per IP, so the
	// tests are also the only reason this is ever short of the public host.
	robtexBase string
	// passiveIntelBase overrides the host of each threat-intelligence subdomain
	// index by name, so a test points all of them at one local fixture. An empty
	// entry means the public host for that index.
	passiveIntelBase map[string]string
	// filescanBase is the filescan.io API host used by the filescan_reputation
	// transform. It is empty for the public API and is only pointed at a local
	// fixture by the transform tests, so a test transform never reaches the
	// public network.
	filescanBase string
	// sharedHostBase is the shared-hosting index used by reverse_dns. It is
	// empty for the public index and is only pointed at a local fixture by the
	// transform tests, so a test transform never reaches the public network.
	sharedHostBase string
	// rdapBase is the RDAP bootstrap used by dns_records, and networkRecordBase
	// the public network record it enriches an ASN through. Both are empty in
	// production and only pointed at local fixtures by the transform tests.
	rdapBase          string
	networkRecordBase string
	// resolverOverride replaces the resolver a transform asks, and is nil in
	// production. It exists because a reverse-lookup transform cannot be tested
	// against the real resolver: the test would ask a public DNS server about
	// addresses in a documentation range and assert on whatever came back. Every
	// other injectable base in this struct has the same purpose.
	resolverOverride routeResolver
	// gcpBucketBase is the per-bucket Google Storage host `s3_buckets` asks when
	// a 403 has to be told apart from "no such bucket". It is empty in
	// production and only pointed at a local fixture by the transform tests.
	gcpBucketBase string
	// announcedPrefixBase is the BGP statistics service asn_lookup reads the
	// announced ranges from. It is empty in production and only pointed at a
	// local fixture by the transform tests, so a test transform never reaches
	// the public network.
	announcedPrefixBase string
	// sweeper releases finished jobs after the retention window. It is one
	// goroutine for the process, not one timer per job.
	sweeper *finishedJobSweeper
}

type targetMap struct {
	mu     sync.RWMutex
	cancel context.CancelFunc
	status string
	// error is why a job that never crawled is not "completed". A crawl that
	// cannot start has to say so; reporting it as finished with zero pages is
	// how a broken job reads as an empty site.
	error string
	// finishedAt is when the crawl reached a terminal state. It is what makes a
	// finished job collectable without guessing from a status string.
	finishedAt time.Time
	startURL   string
	maxPages   int
	visited    int
	pages      []map[string]interface{}
}

type targetMapInput struct {
	URL        string `json:"url"`
	MaxPages   int    `json:"max_pages"`
	MaxDepth   int    `json:"max_depth"`
	DelayMS    int    `json:"delay_ms"`
	SameOrigin bool   `json:"same_origin"`
	// AcceptLanguage is the analyst's language preference. It is identity, so
	// it is never invented: empty means the header is not sent, which is what
	// the crawl did before the field existed.
	AcceptLanguage string `json:"accept_language"`
	// RetryAttempts is how many extra tries a 429 or 503 earns. 0 records the
	// first response as it is, exactly as before.
	RetryAttempts int `json:"retry_attempts"`
	// RetryDelayMS is added to a server-requested pause, so a Retry-After is
	// never shortened by the crawler.
	RetryDelayMS int `json:"retry_delay_ms"`
	// BypassForms is the operator's selection from the 403 ladder.
	//
	// The three states are three states, which is why the field is a slice and
	// not a bool: `nil` means the ladder was not asked for at all, an empty
	// non-nil slice means "asked for, chose nothing", and a populated one names
	// the forms. A bool could not say "asked, chose nothing" apart from "not
	// asked", and the crawl would then walk a ladder nobody selected.
	//
	// It is nil unless the operator set it, because a walk sends one request per
	// form and a crawl of a thousand pages behind a shape-refusing edge would
	// cost thousands more.
	BypassForms []string `json:"bypass_forms"`
}

// osintInput is one recon request. toolRunRoute is embedded rather than
// repeated: every recording tool run needs the same two values, and a run that
// omits them is simply not recorded.
type osintInput struct {
	URL      string `json:"url"`
	WAFCheck bool   `json:"waf_check"`
	toolRunRoute
}

type scannerInput struct {
	URL     string `json:"url"`
	Profile string `json:"profile"`
	toolRunRoute
}

type routeCheckInput struct {
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
}

var mapURLPattern = regexp.MustCompile(`(?i)(?:["'(\s]|^)((?:https?://|/)[^"'()\s<>]+)`)

var osintHTTPClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type attack struct {
	mu        sync.RWMutex
	cancel    context.CancelFunc
	resumeCh  chan struct{}
	paused    bool
	status    string
	total     int
	completed int
	failed    int
	// store keeps the findings on disk so a long run does not hold its whole
	// report in memory. It is nil when the file could not be created, in which
	// case results is used instead so evidence is never lost.
	store *intruderResultStore
	// results is the in-memory fallback, also used for the first results of a
	// run that is still filling its store.
	results []map[string]interface{}
	// finishedAt is when the run reached a terminal state, so a finished run can
	// be released without guessing from a status string.
	finishedAt time.Time
	// detection asks the run to tell a successful login from a failed one, and
	// carries the operator's configuration for that comparison.
	detection *intruder.DetectionConfig
	// baselines is what a failed login answered, one entry per marker shape the
	// run will send. Sniper and Battering Ram leave markers empty, and a page
	// that echoes the submitted username answers those rows with a genuinely
	// shorter page, so one baseline for the whole run would flag the run's own
	// dictionary shape. Written once, before any worker starts, read by all.
	baselines map[string]intruder.Baseline
	// calibrating is true between the run starting and the baseline being ready.
	// The browser shows it instead of an empty baseline, because "no baseline"
	// and "baseline still being taken" are different states for the operator.
	calibrating bool
	// matched and evaluated count the verdicts the run has produced so far.
	matched   int
	evaluated int
}

// addResult records one finding. A run with a spill file keeps only a small
// recent window in memory; a run without one keeps everything, as before.
func (a *attack) addResult(result map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		if err := a.store.Append(result); err == nil {
			return
		}
		// The spill failed mid-run, so this and every later result stay in memory
		// rather than being lost. The store is closed but deliberately not removed:
		// the findings it already holds stay on disk and stay readable, because
		// Read reopens a closed store by path. Removing it here would throw away
		// every result the run had produced up to the failure, which is exactly the
		// moment they are hardest to reproduce.
		a.store.Close()
		a.store = nil
	}
	a.results = append(a.results, result)
}

// resultCount is how many findings the run holds.
func (a *attack) resultCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.store != nil {
		if count := a.store.Len(); count > 0 {
			return count
		}
	}
	return len(a.results)
}

// resultsFrom returns the findings from the given offset, which is the
// incremental read the browser performs.
func (a *attack) resultsFrom(since int) ([]map[string]interface{}, int, error) {
	a.mu.RLock()
	store := a.store
	memory := a.results
	a.mu.RUnlock()
	if store != nil {
		results, err := store.Read(since)
		return results, store.Len(), err
	}
	if since < 0 {
		since = 0
	}
	if since > len(memory) {
		since = len(memory)
	}
	return append([]map[string]interface{}{}, memory[since:]...), len(memory), nil
}

type suppressRequestLogsKey struct{}

const sourceIPCheckURL = "https://check.torproject.org/api/ip"

// Per-request bound for the external-IP courtesy lookup. It is a transport
// deadline for one GET, not a limit on what the operator can do, and it is
// overridable with RR_SOURCE_IP_LOOKUP_TIMEOUT_MS so a slow but working route
// can raise it without a rebuild.
const sourceIPLookupTimeoutDefault = 5 * time.Second

func sourceIPLookupTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RR_SOURCE_IP_LOOKUP_TIMEOUT_MS"))
	if raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return time.Duration(value) * time.Millisecond
		}
	}
	return sourceIPLookupTimeoutDefault
}

func readAnalysisBody(body io.Reader) ([]byte, bool, error) {
	data, err := io.ReadAll(body)
	return data, false, err
}

// requestInput is the common wire format for Repeater and generated jobs.
type requestInput struct {
	// Method is the HTTP verb sent to the target.
	Method string `json:"method"`
	// URL is the absolute target URL.
	URL string `json:"url"`
	// Headers contains request header names and values.
	Headers map[string]string `json:"headers"`
	// Body contains the request payload as text.
	Body string `json:"body"`
}

// intruderInput describes one complete Intruder attack submitted by Django.
type intruderInput struct {
	// BaseRequest is copied and modified for every generated job.
	BaseRequest requestInput `json:"base_request"`
	// Mode selects the payload-combination algorithm.
	Mode intruder.AttackMode `json:"mode"`
	// Payloads is the positional fallback representation used by the UI.
	Payloads [][]string `json:"payloads"`
	// Dictionaries optionally maps marker names or indexes to payload lists.
	Dictionaries map[string][]string `json:"dictionaries"`
	// Transforms are applied to payloads before request generation.
	Transforms []intruder.Transform `json:"transformations"`
	// DelayMS spaces sequential requests by this many milliseconds.
	DelayMS int `json:"delay_ms"`
	// Concurrency controls the number of concurrent workers. Zero selects the
	// engine default for ordinary UI requests.
	Concurrency int `json:"concurrency"`
	// Detection asks the engine to tell a successful login from a failed one
	// when both answer the same status. Nil or disabled keeps every attack that
	// predates the feature byte-identical.
	Detection *intruder.DetectionConfig `json:"detection,omitempty"`
}

func main() {
	// Discover the project CA before the proxy starts intercepting HTTPS.
	configureDefaultCAPath()
	if err := passive.ConfigureCA(); err != nil {
		log.Fatalf("configure passive proxy CA: %v", err)
	}
	log.Printf("passive MITM CA active cert=%s key=%s", os.Getenv("CA_CERT"), os.Getenv("CA_KEY"))
	routes, err := newRouteManager()
	if err != nil {
		log.Fatalf("configure route manager: %v", err)
	}
	if address := strings.TrimSpace(os.Getenv("ROUTE_ADDRESS")); address != "" {
		if err := routes.setInitial(routeConfig{Address: address}); err != nil {
			log.Fatalf("configure initial route: %v", err)
		}
	}
	transport := routes.transport()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	osintHTTPClient.Transport = routes.roundTripper()

	// Store is shared by the proxy snapshot endpoint and the SSE stream.
	store := passive.NewStore()
	// Create the shared HTTP server state.
	// Include a process epoch so persisted attack IDs remain unique after
	// engine restarts and cannot collide with older History rows.
	s := &server{
		attackSequence:   randomSequenceBase(),
		attacks:          make(map[uint64]*attack),
		store:            store,
		targetMaps:       make(map[uint64]*targetMap),
		oastListeners:    make(map[uint64]*oastListener),
		oastSequence:     randomSequenceBase(),
		bursts:           make(map[uint64]*repeaterBurst),
		burstSequence:    randomSequenceBase(),
		lastByteJobs:     make(map[uint64]*lastByteJob),
		lastByteSequence: randomSequenceBase(),
		routes:           routes,
		transport:        transport,
	}
	// Finished jobs are released after the retention window. Without this the
	// process keeps every attack, crawl, burst, listener and last-byte job it has
	// ever run, along with the results each of them holds.
	s.startFinishedJobSweeper()
	defer s.stopFinishedJobSweeper()
	// Register engine endpoints on a private mux instead of using global handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/proxy/request", s.request)
	mux.HandleFunc("/proxy/intruder", s.intruder)
	mux.HandleFunc("/proxy/intruder/", s.intruderStatus)
	mux.HandleFunc("/proxy/target-map", s.targetMapStart)
	mux.HandleFunc("/proxy/target-js", s.targetJSAnalysisHandler)
	// The 403 ladder's own list, so the operator's choice is read from the ladder
	// rather than from a second table that could fall behind it.
	mux.HandleFunc("/proxy/bypass/forms", s.bypassForms)
	mux.HandleFunc("/proxy/target-map/", s.targetMapStatus)
	mux.HandleFunc("/proxy/oast", s.oastStart)
	mux.HandleFunc("/proxy/oast/", s.oastStatus)
	mux.HandleFunc("/proxy/repeater-burst", s.repeaterBurstStart)
	mux.HandleFunc("/proxy/repeater-burst/", s.repeaterBurstStatus)
	mux.HandleFunc("/proxy/last-byte", s.lastByteStart)
	mux.HandleFunc("/proxy/last-byte/", s.lastByteStatus)
	mux.HandleFunc("/proxy/osint", s.osint)
	mux.HandleFunc("/proxy/osint/transforms", s.osintTransformRegistry)
	mux.HandleFunc("/proxy/osint/transform", s.osintTransform)
	mux.HandleFunc("/proxy/osint/transform/jobs", s.osintTransformJob)
	mux.HandleFunc("/proxy/osint/transform/jobs/", s.osintTransformJobStatus)
	mux.HandleFunc("/proxy/scanner", s.scanner)
	mux.HandleFunc("/proxy/scanner/nuclei", s.scannerNuclei)
	mux.HandleFunc("/proxy/scanner/nuclei/stage", s.scannerNucleiStage)
	mux.HandleFunc("/proxy/scanner/nuclei/run", s.scannerNucleiRun)
	mux.HandleFunc("/proxy/scanner/nuclei/dirs", s.scannerNucleiTemplateDirs)
	mux.HandleFunc("/proxy/scanner/nuclei/inspect", s.scannerNucleiTemplateInspect)
	mux.HandleFunc("/proxy/scanner/nuclei/run-dir", s.scannerNucleiRunDir)
	mux.HandleFunc("/proxy/scanner/nuclei/jobs-dir", s.scannerNucleiTemplateDirJob)
	mux.HandleFunc("/proxy/scanner/nuclei/local", s.scannerLocalRun)
	mux.HandleFunc("/proxy/scanner/nuclei/jobs", s.scannerNucleiJob)
	mux.HandleFunc("/proxy/scanner/corpus/stats", s.scannerCorpusStats)
	mux.HandleFunc("/proxy/scanner/corpus/run", s.scannerCorpusRun)
	mux.HandleFunc("/proxy/scanner/corpus/jobs", s.scannerCorpusJobs)
	mux.HandleFunc("/proxy/scanner/corpus/jobs/", s.scannerCorpusJobs)
	mux.HandleFunc("/proxy/scanner/nuclei/jobs/", s.scannerNucleiJobStatus)
	mux.HandleFunc("/proxy/scanner/active/jobs", s.scannerActiveScan)
	mux.HandleFunc("/proxy/scanner/active/jobs/", s.scannerActiveJobStatus)
	mux.HandleFunc("/route", s.route)
	mux.HandleFunc("/route/check", s.routeCheck)
	// The snapshot endpoint hydrates the Traffic table before SSE starts.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			store.Clear()
			writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
			return
		}
		if r.Method == http.MethodPost {
			var input struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || strings.TrimSpace(input.Action) == "" {
				input.Action = strings.TrimSpace(r.URL.Query().Get("action"))
			}
			switch strings.ToLower(strings.TrimSpace(input.Action)) {
			case "pause":
				store.Pause()
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recording": false})
				return
			case "resume":
				store.Resume()
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recording": true})
				return
			case "status":
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recording": store.Recording()})
				return
			default:
				writeError(w, http.StatusBadRequest, "INVALID_TRAFFIC_ACTION", fmt.Errorf("action must be pause, resume or status"))
				return
			}
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
			return
		}
		// `detail=summary` leaves the captured payload out of the snapshot. It is
		// a transport choice, not a deletion: the Store keeps every body and
		// `/events/<id>` returns the complete event.
		switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("detail"))) {
		case "", "full":
			writeJSON(w, http.StatusOK, store.List())
		case "summary":
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"bodies_omitted": true,
				"events":         store.ListSummary(),
			})
		default:
			writeError(w, http.StatusBadRequest, "INVALID_TRAFFIC_DETAIL", fmt.Errorf("detail must be full or summary"))
		}
	})
	// One complete event, so the UI can read the payload of the row it opens
	// without asking the Store for every body it holds.
	mux.HandleFunc("/events/detail", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
			return
		}
		raw := strings.TrimSpace(r.URL.Query().Get("id"))
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || id == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_EVENT_ID", fmt.Errorf("id must be a positive integer"))
			return
		}
		event, ok := store.Get(id)
		if !ok {
			writeError(w, http.StatusNotFound, "EVENT_NOT_FOUND", fmt.Errorf("event %d not found", id))
			return
		}
		writeJSON(w, http.StatusOK, event)
	})
	mux.HandleFunc("/events/annotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
			return
		}
		var input struct {
			ID    uint64   `json:"id"`
			Tags  []string `json:"tags"`
			Notes string   `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ID == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_ANNOTATION", fmt.Errorf("id and valid JSON are required"))
			return
		}
		if !store.Annotate(input.ID, input.Tags, input.Notes) {
			writeError(w, http.StatusNotFound, "EVENT_NOT_FOUND", fmt.Errorf("event %d not found", input.ID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	})
	// SSE publishes both the pending request and its later response update.
	mux.HandleFunc("/events/stream", func(w http.ResponseWriter, r *http.Request) {
		// The response must support flushing so events reach the browser immediately.
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "STREAM_UNSUPPORTED", fmt.Errorf("streaming is not supported"))
			return
		}

		// These headers disable intermediary buffering for the live stream.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		cursor := parseEventCursor(r)
		backlog, events, unsubscribe := store.SubscribeSince(cursor)
		defer unsubscribe()
		send := func(event passive.Event) {
			data, err := json.Marshal(event)
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(w, "id: %d\nevent: traffic\ndata: %s\n\n", event.Cursor, data)
			flusher.Flush()
		}
		for _, event := range backlog {
			send(event)
		}
		// Go does not put the response headers on the wire until something is
		// written or explicitly flushed. An empty store therefore produced a
		// stream that looked dead: the client waited for a status line that never
		// arrived, and the gateway read timed out on the *headers* before it could
		// send a single event. The first flush acknowledges the subscription, and
		// the comment says the stream is live and simply has no traffic yet, so an
		// idle capture is distinguishable from a dead connection.
		if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
			return
		}
		flusher.Flush()
		for {
			select {
			// Stop listening when the browser closes the connection.
			case <-r.Context().Done():
				return
			case event := <-events:
				send(event)
			}
		}
	})
	// The proxy writes its lifecycle events into the same Store.
	proxy := passive.NewProxy(store, routes.sharedTransport(), func(ctx context.Context) string {
		return s.ensureSourceIP(ctx)
	})
	proxy.RouteContext = func(ctx context.Context) (context.Context, context.CancelFunc) {
		_, routeContext, release := s.bindSharedRouteContext(ctx)
		return routeContext, release
	}

	// The proxy and engine API use separate listeners in one process.
	go func() {
		proxyAddr := envOrDefault("PROXY_LISTEN_ADDR", "127.0.0.1:8080")
		requireLoopbackBind("passive MITM proxy", proxyAddr)
		log.Printf("passive MITM proxy listening on %s", proxyAddr)
		// The proxy used to be `http.ListenAndServe(addr, proxy.Handler())`, which
		// is the one server in this file with no bound of any kind — the engine
		// API below sets `ReadHeaderTimeout` and `IdleTimeout`, and this had
		// neither. A client that opened a socket and never finished its headers
		// held a goroutine forever, and a pooled connection that went idle between
		// exchanges was never reclaimed.
		//
		// This is only half the answer, and the honest half to say so: HTTPS
		// through this proxy is MITM'd, so the connection is `Hijack()`ed by
		// goproxy and from that moment none of these three settings reach it. The
		// tunnel bound lives on the connection itself —
		// `passive.MITMIdleTimeout` — because that is the only place it can.
		proxyServer := &http.Server{
			Addr:              proxyAddr,
			Handler:           proxy.Handler(),
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if err := proxyServer.ListenAndServe(); err != nil {
			log.Fatalf("passive proxy: %v", err)
		}
	}()

	engineAddr := envOrDefault("ENGINE_LISTEN_ADDR", "127.0.0.1:8081")
	requireLoopbackBind("engine", engineAddr)
	log.Printf("engine listening on %s", engineAddr)
	engineHandler := withInternalAccess(withRouteGenerationContext(mux))
	// No WriteTimeout: the SSE endpoints hold their connections open by design,
	// and a global write deadline would cut a live stream mid-flight. The read
	// side has no such excuse, so it is bounded (audit A10-04).
	engineServer := &http.Server{
		Addr:              engineAddr,
		Handler:           engineHandler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	rootContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	brokerURL := strings.TrimSpace(os.Getenv("ENGINE_BROKER_URL"))
	consumerDone := make(chan struct{})
	if brokerURL != "" {
		// The URL scheme picks the transport; the task contract, the queue names
		// and the handler are the same either way.
		go func() {
			defer close(consumerDone)
			var err error
			if brokerScheme(brokerURL) != "redis" {
				err = unsupportedBrokerError(brokerURL)
			} else {
				err = runRedisConsumer(rootContext, brokerURL, engineHandler)
			}
			if err != nil {
				log.Printf("broker consumer stopped: %s", err)
			}
		}()
	} else {
		close(consumerDone)
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- engineServer.ListenAndServe()
	}()
	select {
	case <-rootContext.Done():
		if err := engineServer.Shutdown(context.Background()); err != nil {
			log.Printf("engine graceful shutdown failed: %s", err)
		}
		<-consumerDone
	case err := <-serveResult:
		stop()
		<-consumerDone
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.routes.configSnapshot())
	case http.MethodPut, http.MethodPost:
		var config routeConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_ROUTE", err)
			return
		}
		if err := s.routes.set(config); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_ROUTE", err)
			return
		}
		writeJSON(w, http.StatusOK, s.routes.configSnapshot())
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
	}
}

func (s *server) routeCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input routeCheckInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ROUTE_CHECK", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_ROUTE_CHECK", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	timeout := time.Duration(0)
	if input.TimeoutMS > 0 {
		timeout = time.Duration(input.TimeoutMS) * time.Millisecond
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	route := s.routes.configSnapshot()
	result := map[string]interface{}{
		"route":      route,
		"target_url": target,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	}
	client := &http.Client{
		Transport: s.requestTransport(),
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetStarted := time.Now()
	targetRequest, requestErr := http.NewRequestWithContext(routeContext, http.MethodGet, target, nil)
	var targetResponse *http.Response
	var targetErr error
	if requestErr != nil {
		targetErr = requestErr
	} else {
		targetResponse, targetErr = client.Do(targetRequest)
	}
	targetLatency := time.Since(targetStarted).Milliseconds()
	targetResult := map[string]interface{}{"latency_ms": targetLatency}
	var targetTrafficID uint64
	if targetErr != nil {
		targetResult["status"] = "error"
		targetResult["error"] = targetErr.Error()
		targetTrafficID = s.publishRouteCheckTraffic(target, targetStarted, nil, targetErr)
	} else {
		targetResult["status"] = "ok"
		targetResult["status_code"] = targetResponse.StatusCode
		targetResult["status_text"] = targetResponse.Status
		targetBody, _ := io.ReadAll(targetResponse.Body)
		_ = targetResponse.Body.Close()
		targetTrafficID = s.publishRouteCheckTraffic(target, targetStarted, &routeCheckResponse{
			status:  targetResponse.StatusCode,
			header:  flattenHeaders(targetResponse.Header),
			body:    targetBody,
			content: targetResponse.Header.Get("Content-Type"),
		}, nil)
	}
	result["target"] = targetResult

	ipResult := map[string]interface{}{"status": "unavailable"}
	ipStarted := time.Now()
	ipRequest, requestErr := http.NewRequestWithContext(routeContext, http.MethodGet, sourceIPCheckURL, nil)
	var ipResponse *http.Response
	var ipErr error
	if requestErr != nil {
		ipErr = requestErr
	} else {
		ipResponse, ipErr = client.Do(ipRequest)
	}
	ipLatency := time.Since(ipStarted).Milliseconds()
	ipResult["latency_ms"] = ipLatency
	if ipErr != nil {
		ipResult["status"] = "error"
		ipResult["error"] = ipErr.Error()
		s.publishRouteCheckTraffic(sourceIPCheckURL, ipStarted, nil, ipErr)
	} else {
		var ipTrafficID uint64
		ipBody, _ := io.ReadAll(ipResponse.Body)
		_ = ipResponse.Body.Close()
		var payload struct {
			IP    string `json:"ip"`
			IsTor bool   `json:"IsTor"`
		}
		if err := json.Unmarshal(ipBody, &payload); err != nil {
			ipResult["status"] = "error"
			ipResult["error"] = "external IP response did not contain a valid IP"
		} else {
			payload.IP = strings.TrimSpace(payload.IP)
		}
		if payload.IP == "" || net.ParseIP(payload.IP) == nil {
			ipResult["status"] = "error"
			ipResult["error"] = "external IP response did not contain a valid IP"
		} else {
			ipResult["status"] = "ok"
			ipResult["ip"] = payload.IP
			ipResult["is_tor"] = payload.IsTor
			if targetTrafficID != 0 {
				s.store.Update(targetTrafficID, func(event *passive.Event) {
					event.SourceIP = payload.IP
				})
			}
		}
		ipResult["status_code"] = ipResponse.StatusCode
		ipTrafficID = s.publishRouteCheckTraffic(sourceIPCheckURL, ipStarted, &routeCheckResponse{
			status:  ipResponse.StatusCode,
			header:  flattenHeaders(ipResponse.Header),
			body:    ipBody,
			content: ipResponse.Header.Get("Content-Type"),
		}, nil)
		if payload.IP != "" {
			s.store.Update(ipTrafficID, func(event *passive.Event) {
				event.SourceIP = payload.IP
			})
		}
	}
	result["external_ip"] = ipResult
	if targetErr != nil {
		result["status"] = "error"
	} else {
		result["status"] = "ok"
	}
	writeJSON(w, http.StatusOK, result)
}

type routeCheckResponse struct {
	status  int
	header  map[string]string
	body    []byte
	content string
}

func (s *server) publishRouteCheckTraffic(rawURL string, started time.Time, response *routeCheckResponse, requestErr error) uint64 {
	if s.store == nil {
		return 0
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	event := passive.Event{
		Source:        "route-check",
		Timestamp:     started.UTC(),
		Method:        http.MethodGet,
		URL:           rawURL,
		Host:          parsed.Host,
		RequestHeader: map[string]string{"User-Agent": "RequestRider-RouteCheck/1.0"},
		Latency:       time.Since(started).Milliseconds(),
	}
	if requestErr != nil {
		event.Error = requestErr.Error()
	} else {
		event.Status = response.status
		event.ResponseHeader = response.header
		event.ResponseBody = string(response.body)
		event.ResponseContentType = response.content
		event.ResponseSize = len(response.body)
	}
	return s.store.Add(event)
}

func (s *server) ensureSourceIP(ctx context.Context) string {
	_, lookupContext, release := s.bindRouteContext(ctx)
	defer release()
	return s.lookupSourceIP(lookupContext)
}

func (s *server) startSourceIPLookup(parent context.Context) <-chan string {
	if parent == nil {
		parent = context.Background()
	}
	lookupContext := context.WithoutCancel(parent)
	release := func() {}
	if s.routes != nil {
		if _, bound := routeLeaseFromContext(lookupContext); !bound {
			_, lookupContext, release = s.bindRouteContext(lookupContext)
		}
	}
	result := make(chan string, 1)
	go func() {
		ip := s.lookupSourceIP(lookupContext)
		release()
		result <- ip
	}()
	return result
}

func sourceIPIfReady(lookup <-chan string) (string, bool) {
	select {
	case ip := <-lookup:
		return ip, true
	default:
		return "", false
	}
}

func (s *server) setTrafficSourceIP(eventID uint64, ip string) {
	if eventID == 0 || s.store == nil || ip == "" {
		return
	}
	s.store.Update(eventID, func(event *passive.Event) {
		event.SourceIP = ip
	})
}

func (s *server) updateTrafficSourceIP(eventID uint64, lookup <-chan string) {
	if eventID == 0 || s.store == nil {
		return
	}
	go func() {
		if ip, ready := <-lookup; ready {
			s.setTrafficSourceIP(eventID, ip)
		}
	}()
}

func (s *server) lookupSourceIP(ctx context.Context) string {
	if s.transport == nil && s.routes == nil {
		return ""
	}
	// The external-IP check is a courtesy lookup for one status field, and it
	// must never be the reason an operation waits. An endpoint that accepts the
	// connection and stalls — which is what an unreachable resolver looks like —
	// used to hold the caller for as long as the socket stayed open, so a run
	// sat in `running` with no error. The bound is per request, overridable, and
	// it never shortens a value the operator supplied.
	lookupContext, cancel := context.WithTimeout(ctx, sourceIPLookupTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(lookupContext, http.MethodGet, sourceIPCheckURL, nil)
	if err != nil {
		return ""
	}
	transport := http.RoundTripper(s.requestTransport())
	if s.sourceIPTransport != nil {
		transport = s.sourceIPTransport
	} else if s.routes != nil {
		transport = s.routes.ephemeralTransport()
	}
	var closeIdle func()
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closeIdle = closer.CloseIdleConnections
	}
	if closeIdle != nil {
		defer closeIdle()
	}
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, err := readControlPlaneBody(response.Body)
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return ""
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	ip := strings.TrimSpace(payload.IP)
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func configureDefaultCAPath() {
	// Respect an explicit CA_DIR supplied by the caller or Docker.
	if os.Getenv("CA_DIR") != "" || os.Getenv("CA_CERT") != "" || os.Getenv("CA_KEY") != "" {
		return
	}
	// ConfigureCA resolves and creates the project default from the current
	// working directory, so no environment variable is required locally.
}

func envOrDefault(key, fallback string) string {
	// Environment variables configure Docker and local development addresses.
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func routeResolverForContext(ctx context.Context) *net.Resolver {
	if lease, ok := routeLeaseFromContext(ctx); ok {
		return lease.resolver()
	}
	return net.DefaultResolver
}

func (s *server) bindRouteContext(parent context.Context) (*routeLease, context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if lease, ok := routeLeaseFromContext(parent); ok {
		if expected, hasExpected := expectedRouteGeneration(parent); hasExpected && lease.generation != expected {
			cancelled, release := canceledExpectedRouteContext(parent)
			return nil, cancelled, release
		}
		return lease, parent, func() {}
	}
	if s.routes == nil {
		return nil, parent, func() {}
	}
	if expected, hasExpected := expectedRouteGeneration(parent); hasExpected {
		return s.routes.acquireExpected(parent, expected)
	}
	return s.routes.acquire(parent)
}

func (s *server) bindSharedRouteContext(parent context.Context) (*routeLease, context.Context, context.CancelFunc) {
	if s.routes == nil {
		if parent == nil {
			parent = context.Background()
		}
		return nil, parent, func() {}
	}
	return s.routes.acquireShared(parent)
}

// bindBackgroundRouteContext binds work that must outlive the request that
// started it, such as an asynchronous template scan. The expected route
// generation is still enforced, and a route switch still cancels the job.
func (s *server) bindBackgroundRouteContext(parent context.Context) (*routeLease, context.Context, context.CancelFunc) {
	if s.routes == nil {
		return nil, context.Background(), func() {}
	}
	if expected, ok := expectedRouteGeneration(parent); ok {
		return s.routes.acquireExpectedBackground(expected)
	}
	return s.routes.acquireBackground(nil)
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	// Health is intentionally cheap so it can be used by smoke tests. The
	// transport bounds ride along because they are the values an operator has to
	// read to explain a request that failed on a timeout, and a bound that can
	// only be discovered in the source is a bound nobody can act on.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    true,
		"bound": loadTransportBounds().describe(),
	})
}

func (s *server) request(w http.ResponseWriter, r *http.Request) {
	// Decode the Repeater request submitted by Django.
	var input requestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	lookup := s.startSourceIPLookup(routeContext)
	eventID := s.addRequestTraffic(input, "")
	// Reuse the same execution path used by Intruder jobs while resolving the
	// source IP asynchronously so a slow metadata endpoint cannot consume the
	// target request budget.
	result, err := s.executeContextWithSourceIP(routeContext, input, "")
	if result == nil {
		result = exchangeErrorResult("")
	}
	if ip, ready := sourceIPIfReady(lookup); ready {
		result["source_ip"] = ip
		s.setTrafficSourceIP(eventID, ip)
	} else {
		result["source_ip_pending"] = true
		s.updateTrafficSourceIP(eventID, lookup)
	}
	result["traffic_event_id"] = eventID
	if err != nil {
		s.completeRequestTraffic(eventID, result, err)
		writeOperationError(w, http.StatusBadGateway, "REQUEST_FAILED", err)
		return
	}
	s.completeRequestTraffic(eventID, result, nil)
	writeJSON(w, http.StatusOK, result)
}

// execute is shared by Repeater and every generated Intruder job.
func (s *server) execute(r *http.Request, input requestInput) (map[string]interface{}, error) {
	return s.executeContext(r.Context(), input)
}

func (s *server) executeContext(ctx context.Context, input requestInput) (map[string]interface{}, error) {
	_, routeContext, release := s.bindRouteContext(ctx)
	defer release()
	lookup := s.startSourceIPLookup(routeContext)
	result, err := s.executeContextWithSourceIP(routeContext, input, "")
	if result == nil {
		result = exchangeErrorResult("")
	}
	if ip, ready := sourceIPIfReady(lookup); ready {
		result["source_ip"] = ip
	} else {
		result["source_ip_pending"] = true
		result[sourceIPLookupResultKey] = lookup
	}
	return result, err
}

const sourceIPLookupResultKey = "__requestrider_source_ip_lookup"

func exchangeErrorResult(sourceIP string) map[string]interface{} {
	return map[string]interface{}{"source_ip": sourceIP}
}

func (s *server) executeContextWithSourceIP(ctx context.Context, input requestInput, sourceIP string) (map[string]interface{}, error) {
	// Default an omitted method to the standard HTTP GET verb.
	method := input.Method
	if method == "" {
		method = http.MethodGet
	}
	// requestStart measures failures occurring before a response exists.
	requestStart := time.Now()
	logRequests := !requestLogsSuppressed(ctx)
	if logRequests {
		log.Printf("[REQUEST] start method=%s host=%s path=%s", sanitizeLogValue(method), logHost(input.URL), logPath(input.URL))
	}
	// Bind the outbound request to the inbound request context.
	req, err := http.NewRequestWithContext(ctx, method, input.URL, strings.NewReader(input.Body))
	if err != nil {
		if logRequests {
			log.Printf("[REQUEST] build_error method=%s host=%s error=%v", sanitizeLogValue(method), logHost(input.URL), logError(err))
		}
		return exchangeErrorResult(sourceIP), err
	}
	// Copy caller-supplied headers without exposing them in diagnostic logs.
	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	// start measures only the outbound request/response round trip.
	start := time.Now()
	resp, err := (&http.Client{
		Transport:     s.requestTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		if logRequests {
			log.Printf("[REQUEST] error method=%s host=%s duration_ms=%d error=%v", sanitizeLogValue(method), logHost(input.URL), time.Since(requestStart).Milliseconds(), logError(err))
		}
		return exchangeErrorResult(sourceIP), err
	}
	// Always release the response body, including read failures.
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if logRequests {
			log.Printf("[REQUEST] read_error method=%s host=%s status=%d duration_ms=%d error=%v", sanitizeLogValue(method), logHost(input.URL), resp.StatusCode, time.Since(requestStart).Milliseconds(), logError(err))
		}
		return exchangeErrorResult(sourceIP), err
	}
	// Flatten multi-value response headers for the JSON contract.
	headers := map[string]string{}
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	duration := time.Since(start).Milliseconds()
	if logRequests {
		log.Printf("[REQUEST] complete method=%s host=%s status=%d duration_ms=%d response_bytes=%d", sanitizeLogValue(method), logHost(input.URL), resp.StatusCode, duration, len(body))
	}
	result := map[string]interface{}{
		"status":      resp.StatusCode,
		"status_text": resp.Status,
		"time":        duration,
		"size":        len(body),
		"headers":     headers,
		"source_ip":   sourceIP,
	}
	if bodyIsStorableText(body) {
		result["body"] = string(body)
		result["body_encoding"] = "utf8"
	} else {
		result["body"] = ""
		result["body_encoding"] = "base64"
		result["body_base64"] = base64.StdEncoding.EncodeToString(body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		result["body_content_type"] = contentType
	}
	return result, nil
}

func (s *server) requestTransport() http.RoundTripper {
	if s.routes != nil {
		return s.routes.roundTripper()
	}
	if s.transport != nil {
		return s.transport
	}
	return http.DefaultTransport
}

func (s *server) targetMapStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input targetMapInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	start, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || start.Scheme == "" || start.Host == "" || (start.Scheme != "http" && start.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if input.MaxPages == 0 || input.MaxPages < 0 {
		input.MaxPages = 0
	}
	if input.MaxDepth < -1 {
		input.MaxDepth = -1
	}
	if input.DelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_DELAY", fmt.Errorf("delay_ms must not be negative"))
		return
	}
	// A negative retry count or delay is refused rather than clamped, because a
	// silently clamped bound is a cap the analyst never asked for. Zero is a
	// real value for all three: no language header, one try, no added delay.
	if input.RetryAttempts < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_RETRY_ATTEMPTS", fmt.Errorf("retry_attempts must not be negative"))
		return
	}
	if input.RetryDelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_RETRY_DELAY", fmt.Errorf("retry_delay_ms must not be negative"))
		return
	}
	if len(input.AcceptLanguage) > 120 {
		writeError(w, http.StatusBadRequest, "INVALID_ACCEPT_LANGUAGE", fmt.Errorf("accept_language must be at most 120 characters"))
		return
	}
	id := atomic.AddUint64(&s.attackSequence, 1)
	_, routeContext, releaseRoute := s.bindRouteContext(context.WithoutCancel(r.Context()))
	ctx, cancel := context.WithCancel(routeContext)
	job := &targetMap{
		cancel: func() { cancel(); releaseRoute() }, status: "running", startURL: normalizeMapURL(start),
		maxPages: input.MaxPages, pages: make([]map[string]interface{}, 0),
	}
	s.targetMapsMu.Lock()
	s.targetMaps[id] = job
	s.targetMapsMu.Unlock()
	writeJSON(w, http.StatusAccepted, targetMapSnapshot(id, job))
	go s.runTargetMap(id, job, ctx, input)
}

func (s *server) osint(w http.ResponseWriter, r *http.Request) {
	// OSINT is intentionally passive: the endpoint gathers public metadata and
	// never sends exploit payloads or attempts to bypass a real WAF.
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input osintInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	lease, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	resolver := net.DefaultResolver
	if lease != nil {
		resolver = lease.resolver()
	} else if s.routes != nil {
		resolver = s.routes.resolver()
	}
	sourceIP := s.ensureSourceIP(routeContext)
	transport, err := s.toolRouteTransport(input.toolRunRoute)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", err)
		return
	}
	result, err := runOSINTWithResolverContext(
		withToolTransport(routeContext, transport), parsed, input.WAFCheck, resolver, transport,
	)
	if err != nil {
		writeOperationError(w, http.StatusBadGateway, "OSINT_CHECK_FAILED", err)
		return
	}
	result["source_ip"] = sourceIP
	writeJSON(w, http.StatusOK, result)
}

func (s *server) scanner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input scannerInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	profile := strings.TrimSpace(input.Profile)
	if profile == "" {
		profile = "generic_web"
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	sourceIP := s.ensureSourceIP(routeContext)
	transport, err := s.toolRouteTransport(input.toolRunRoute)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", err)
		return
	}
	result, err := s.runSafeScannerContext(withToolTransport(routeContext, transport), parsed)
	if err != nil {
		writeOperationError(w, http.StatusBadGateway, "SCANNER_CHECK_FAILED", err)
		return
	}
	result["profile"] = profile
	result["source_ip"] = sourceIP
	writeJSON(w, http.StatusOK, result)
}

// scannerUploadFile is one Nuclei template document uploaded from the browser.
// Path keeps the folder layout of a directory upload so templates that share a
// file name across directories stay distinct.
type scannerUploadFile struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// nucleiStageRequest is one chunk of a chunked template upload. UploadID is
// empty for the first chunk and names the open session for every later chunk.
type nucleiStageRequest struct {
	UploadID string              `json:"upload_id"`
	Files    []scannerUploadFile `json:"files"`
}

// scannerNucleiStage validates and stages one chunk of uploaded templates and
// returns the upload id every later chunk must reuse. Chunks accumulate into
// one staged directory so a whole templates folder can be uploaded without a
// single oversized request.
func (s *server) scannerNucleiStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input nucleiStageRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	uploadID, staged, total, err := scanner.StageNucleiUpload(input.UploadID, inputFiles(input.Files))
	if err != nil {
		if strings.Contains(err.Error(), "is unknown or already consumed") {
			writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", err)
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"upload_id":  uploadID,
		"templates":  scanner.TemplatesReport(staged),
		"staged":     len(staged),
		"staged_all": total,
	})
}

// nucleiRunRequest runs a previously staged upload.
// nucleiRunRequest is one template run. toolRunRoute rides along because a
// nuclei run is recorded the same way a scan is: the binary sends through the
// local proxy and carries the correlation token, so each template's request
// lands in History in the order the binary sent it.
type nucleiRunRequest struct {
	URL          string                `json:"url"`
	UploadID     string                `json:"upload_id"`
	CategoryPath string                `json:"category_path"`
	Tags         []string              `json:"tags"`
	Severity     []string              `json:"severity"`
	Options      scanner.NucleiOptions `json:"options"`
	toolRunRoute
}

// scannerNucleiJob starts an asynchronous template run so the browser can show
// live progress instead of a single blocking request.
func (s *server) scannerNucleiJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input nucleiRunRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if strings.TrimSpace(input.UploadID) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", fmt.Errorf("upload_id is required"))
		return
	}
	// The job outlives this request, so it binds to the route generation rather
	// than to the request context. A route switch still cancels the scan.
	_, routeContext, release := s.bindBackgroundRouteContext(r.Context())
	s.ensureSourceIP(routeContext)
	// `{{interactsh-url}}` needs a real callback address, and this engine is an
	// OAST client rather than an interactsh server — so the address comes from the
	// same provider the engine's own listener registers with. No provider
	// configured means no source, and the run then refuses those templates by name
	// instead of putting the literal placeholder on the wire.
	routeContext = s.withOASTSource(routeContext)
	fallbackTransport, routeErr := s.toolRouteTransport(input.toolRunRoute)
	if routeErr != nil {
		release()
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", routeErr)
		return
	}
	// The gateway names the local recording proxy when it wants the run's
	// requests kept. Without it the binary keeps the direct route proxy it
	// always had, so an unrecorded run behaves exactly as it did before.
	proxy := input.proxyForRun(s.routes)
	job, err := scanner.StartNucleiJob(routeContext, input.UploadID, scanner.NucleiRequest{
		URL: parsed.String(), CategoryPath: input.CategoryPath, Tags: input.Tags, Severity: input.Severity,
		Proxy: proxy, Options: input.Options,
		Headers: input.captureHeaders(),
		// The recording transport, exactly as the two synchronous entry points
		// below already pass it. It was missing here and only here, and the browser
		// runs every long scan through **this** path — so on the path the operator
		// actually uses, `applyLocalFallback` returned 0 at its `transport == nil`
		// guard, this project's own runner never performed a single document, and a
		// `javascript:` template needing `nuclei/ssh` kept the binary's sentence
		// «Ran, but checked no URL». Measured in a live Firefox at 1356x652: 5 of 5
		// rows said "Template ran, no matches" and 0 named the module. The synchronous
		// paths were correct, which is why no test caught it: every test built its
		// own request instead of using this one.
		Transport: fallbackTransport,
	}, release)
	if err != nil {
		if errors.Is(err, scanner.ErrInvalidTemplateCategory) {
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_CATEGORY", err)
			return
		}
		if strings.Contains(err.Error(), "is unknown or already consumed") {
			writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", err)
			return
		}
		writeOperationError(w, http.StatusBadGateway, "SCANNER_NUCLEI_FAILED", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID, "state": scanner.JobQueued, "progress": job.Progress(),
	})
}

// scannerNucleiTemplateDirJob starts a background run of a template folder named
// on disk.
//
// The folder is a job rather than a blocking request for the same reason an
// upload is: a corpus is thousands of documents, and the browser follows live
// progress and per-template events through the same job routes the upload run
// uses. Sharing those routes is deliberate — one poll, one stream, one set of
// pause/cancel actions — so a folder run and an uploaded run cannot drift apart
// in how they are observed.
func (s *server) scannerNucleiTemplateDirJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input struct {
		URL          string                `json:"url"`
		Dir          string                `json:"dir"`
		CategoryPath string                `json:"category_path"`
		Tags         []string              `json:"tags"`
		Severity     []string              `json:"severity"`
		Options      scanner.NucleiOptions `json:"options"`
		toolRunRoute
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if strings.TrimSpace(input.Dir) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_DIR", fmt.Errorf("dir is required"))
		return
	}
	// The job outlives this request, so it binds to the route generation rather
	// than to the request context. A route switch still cancels the scan.
	_, routeContext, release := s.bindBackgroundRouteContext(r.Context())
	s.ensureSourceIP(routeContext)
	routeContext = s.withOASTSource(routeContext)
	fallbackTransport, routeErr := s.toolRouteTransport(input.toolRunRoute)
	if routeErr != nil {
		release()
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", routeErr)
		return
	}
	proxy := input.proxyForRun(s.routes)
	job, err := scanner.StartNucleiTemplateDirJob(routeContext, input.Dir, scanner.NucleiRequest{
		URL: parsed.String(), CategoryPath: input.CategoryPath, Tags: input.Tags, Severity: input.Severity,
		Proxy: proxy, Options: input.Options,
		Headers: input.captureHeaders(),
		// The recording transport, exactly as the upload job passes it, so a
		// document the binary will not execute still leaves an exchange in
		// History through this project's own runner.
		Transport: fallbackTransport,
	}, release)
	if err != nil {
		if errors.Is(err, scanner.ErrInvalidTemplateCategory) {
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_CATEGORY", err)
			return
		}
		if strings.Contains(err.Error(), "was not found") || strings.Contains(err.Error(), "no template documents") {
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_DIR", err)
			return
		}
		writeOperationError(w, http.StatusBadGateway, "SCANNER_NUCLEI_FAILED", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID, "state": scanner.JobQueued, "progress": job.Progress(),
	})
}

// scannerNucleiJobStatus returns the live progress and, once finished, the
// per-file report of an asynchronous run. A trailing action segment controls the
// run: "/cancel" stops it, "/pause" freezes it, "/resume" continues it.
func (s *server) scannerNucleiJobStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/proxy/scanner/nuclei/jobs/")
	if strings.HasSuffix(id, "/stream") {
		s.scannerNucleiJobStream(w, r)
		return
	}
	for _, action := range []string{"/cancel", "/pause", "/resume"} {
		if strings.HasSuffix(id, action) {
			s.scannerNucleiJobAction(w, r, strings.TrimSuffix(id, action), strings.TrimPrefix(action, "/"))
			return
		}
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	snapshot, ok := scanner.NucleiJobSnapshot(id)
	if !ok {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("job %q is unknown or already collected", id))
		return
	}
	payload := map[string]interface{}{
		"job_id": snapshot.ID, "state": snapshot.State, "progress": snapshot.Progress,
	}
	if snapshot.Result != nil {
		payload["result"] = map[string]interface{}{
			"url":       snapshot.Result.Stats["url"],
			"findings":  snapshot.Result.Findings,
			"templates": snapshot.Result.Templates,
			"stats":     snapshot.Result.Stats,
		}
	}
	if snapshot.Error != "" {
		payload["error"] = snapshot.Error
	}
	if snapshot.Reason != "" {
		payload["reason"] = snapshot.Reason
	}
	writeJSON(w, http.StatusOK, payload)
}

// scannerNucleiJobStream follows a running scan. Results are streamed as Nuclei
// writes them, so a folder scan fills the table while the binary is still
// working instead of appearing all at once at the end.
func (s *server) scannerNucleiJobStream(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxy/scanner/nuclei/jobs/"), "/stream")
	job, ok := scanner.NucleiJobStream(id)
	if !ok {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("job %q is unknown or already collected", id))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "STREAM_UNSUPPORTED", fmt.Errorf("streaming is not supported"))
		return
	}
	// These headers disable intermediary buffering for the live stream.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	cursor := int(parseEventCursor(r))
	backlog, updates, unsubscribe := job.SubscribeSince(cursor)
	defer unsubscribe()
	send := func(event scanner.TemplateEvent) {
		data, err := json.Marshal(event)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Cursor, event.Kind, data)
		flusher.Flush()
	}
	for _, event := range backlog {
		send(event)
		cursor = event.Cursor
	}
	// A quiet run still has to produce bytes. A paused scan sends no events at
	// all, and a single slow template can go minutes without one, so a stream
	// that only writes on real updates looks dead to every hop in between: an
	// intermediary read timeout closes it and the browser reports a transport
	// failure for a job that is still running. The comment line is ignored by
	// EventSource, so it costs the client nothing.
	heartbeat := time.NewTicker(scannerStreamHeartbeat)
	defer heartbeat.Stop()
	for {
		// The terminal event carries the authoritative report, so the stream
		// ends there and a client that only follows events still gets everything.
		if job.IsFinished() && len(job.EventsSince(cursor)) == 0 {
			return
		}
		select {
		// Stop streaming when the browser closes the connection.
		case <-r.Context().Done():
			return
		case <-updates:
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
		for _, event := range job.EventsSince(cursor) {
			send(event)
			cursor = event.Cursor
		}
	}
}

// scannerNucleiJobAction applies one control action to a running job.
func (s *server) scannerNucleiJobAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var err error
	switch action {
	case "cancel":
		if !scanner.CancelNucleiJob(id) {
			err = fmt.Errorf("job %q is unknown or already finished", id)
		}
	case "pause":
		err = scanner.PauseNucleiJob(id)
	case "resume":
		err = scanner.ResumeNucleiJob(id)
	default:
		err = fmt.Errorf("unknown job action %q", action)
	}
	if err != nil {
		status, code := http.StatusBadRequest, "INVALID_JOB_STATE"
		if errors.Is(err, scanner.ErrPauseUnsupported) {
			status, code = http.StatusNotImplemented, "PAUSE_UNSUPPORTED"
		} else if strings.Contains(err.Error(), "is unknown") {
			status, code = http.StatusNotFound, "UNKNOWN_JOB"
		}
		writeError(w, status, code, err)
		return
	}
	state := scanner.JobRunning
	if action == "cancel" {
		state = scanner.JobCancelled
	} else if action == "pause" {
		state = scanner.JobPaused
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job_id": id, "state": state})
}

// scannerNucleiTemplateDirs lists installed template folders and Nuclei's
// advertised template types for the inspection UI.
//
// It is a GET because it answers nothing the caller supplies: the folder list is
// what is installed on this machine and the type list is fixed by the binary,
// so neither depends on a target, a tag or a severity.
func (s *server) scannerNucleiTemplateDirs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"dirs":  scanner.ListTemplateDirs(),
		"types": scanner.TemplateTypes(),
	})
}

// scannerNucleiTemplateInspect reports what one folder contains: how many
// documents, which protocol types, which capabilities they need, and which
// documents cannot be used and why.
//
// It is separate from the listing because it reads and parses every document in
// the folder: on the official corpus that is 98 662 documents, so it is a call
// the operator makes for one folder rather than one the dropdown makes for all.
func (s *server) scannerNucleiTemplateInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	selection := r.URL.Query().Get("dir")
	if selection == "" && r.Method == http.MethodPost {
		var input struct {
			Dir string `json:"dir"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
			return
		}
		selection = input.Dir
	}
	report := scanner.InspectTemplateDir(selection)
	if report.Error != "" {
		writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_DIR", fmt.Errorf("%s", report.Error))
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// scannerNucleiRunDir executes a template folder named on disk and returns the
// per-file report.
//
// It is the folder counterpart of the upload run, and it is a separate route
// rather than a field on the upload one: an upload is a staged session this
// process owns and consumes, while a folder is the operator's own directory that
// this process only reads. Sharing the route would mean one request silently
// choosing between "delete the staged copy" and "read my corpus", and a field
// that decides that is a field an operator can get wrong without noticing.
func (s *server) scannerNucleiRunDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input struct {
		URL          string                `json:"url"`
		Dir          string                `json:"dir"`
		CategoryPath string                `json:"category_path"`
		Tags         []string              `json:"tags"`
		Severity     []string              `json:"severity"`
		Options      scanner.NucleiOptions `json:"options"`
		toolRunRoute
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if strings.TrimSpace(input.Dir) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_DIR", fmt.Errorf("dir is required"))
		return
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	sourceIP := s.ensureSourceIP(routeContext)
	fallbackTransport, routeErr := s.toolRouteTransport(input.toolRunRoute)
	if routeErr != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", routeErr)
		return
	}
	proxy := input.proxyForRun(s.routes)
	run, err := scanner.RunNucleiTemplateDir(routeContext, input.Dir, scanner.NucleiRequest{
		URL: parsed.String(), CategoryPath: input.CategoryPath, Tags: input.Tags, Severity: input.Severity,
		Proxy: proxy, Options: input.Options,
		Headers:   input.captureHeaders(),
		Transport: fallbackTransport,
	})
	if err != nil {
		if errors.Is(err, scanner.ErrInvalidTemplateCategory) {
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_CATEGORY", err)
			return
		}
		if strings.Contains(err.Error(), "was not found") || strings.Contains(err.Error(), "no template documents") {
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_DIR", err)
			return
		}
		writeOperationError(w, http.StatusBadGateway, "SCANNER_NUCLEI_FAILED", err)
		return
	}
	writeNucleiReport(w, parsed.String(), run, sourceIP)
}

// scannerNucleiRun executes the templates staged under an upload id and returns
// the per-file report. The staging directory is removed once the run finishes.
func (s *server) scannerNucleiRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input nucleiRunRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if strings.TrimSpace(input.UploadID) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", fmt.Errorf("upload_id is required"))
		return
	}
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	sourceIP := s.ensureSourceIP(routeContext)
	fallbackTransport, routeErr := s.toolRouteTransport(input.toolRunRoute)
	if routeErr != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", routeErr)
		return
	}
	// The gateway names the local recording proxy when it wants the run's
	// requests kept. Without it the binary keeps the direct route proxy it
	// always had, so an unrecorded run behaves exactly as it did before.
	proxy := input.proxyForRun(s.routes)
	run, err := scanner.RunNucleiUpload(routeContext, input.UploadID, scanner.NucleiRequest{
		URL: parsed.String(), CategoryPath: input.CategoryPath, Tags: input.Tags, Severity: input.Severity,
		Proxy: proxy, Options: input.Options,
		Headers: input.captureHeaders(),
		// The run performs every file the binary refuses through this project's
		// own runner, so it needs the recording transport. It is the same transport
		// the binary's own requests go through when `proxy` is set, so a runner row
		// and a binary row leave the same evidence in History.
		Transport: fallbackTransport,
	})
	if err != nil {
		if errors.Is(err, scanner.ErrInvalidTemplateCategory) {
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE_CATEGORY", err)
			return
		}
		if strings.Contains(err.Error(), "is unknown or already consumed") {
			writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", err)
			return
		}
		writeOperationError(w, http.StatusBadGateway, "SCANNER_NUCLEI_FAILED", err)
		return
	}
	writeNucleiReport(w, parsed.String(), run, sourceIP)
}

// writeNucleiReport renders one nuclei run. A run in which every file was
// rejected is a client error, but the per-file report is still returned so the
// operator sees which file failed and why.
func writeNucleiReport(w http.ResponseWriter, target string, run scanner.NucleiRun, sourceIP string) {
	report := map[string]interface{}{
		"url": target, "findings": run.Findings, "templates": run.Templates,
		"stats": run.Stats, "source_ip": sourceIP,
	}
	if invalid, total := run.CountStatus(scanner.TemplateInvalid); total > 0 && invalid == total {
		report["error"] = "no uploaded template is valid for nuclei"
		report["reason"] = "SCANNER_NUCLEI_NO_VALID_TEMPLATES"
		writeJSON(w, http.StatusBadRequest, report)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *server) scannerNuclei(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input struct {
		URL      string                `json:"url"`
		Files    []scannerUploadFile   `json:"files"`
		Tags     []string              `json:"tags"`
		Severity []string              `json:"severity"`
		Options  scanner.NucleiOptions `json:"options"`
		toolRunRoute
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	dir, staged, err := scanner.StageUploads(inputFiles(input.Files))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE", err)
		return
	}
	defer os.RemoveAll(dir)
	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	sourceIP := s.ensureSourceIP(routeContext)
	fallbackTransport, routeErr := s.toolRouteTransport(input.toolRunRoute)
	if routeErr != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", routeErr)
		return
	}
	// The gateway names the local recording proxy when it wants the run's
	// requests kept. Without it the binary keeps the direct route proxy it
	// always had, so an unrecorded run behaves exactly as it did before.
	proxy := input.proxyForRun(s.routes)
	run, err := scanner.RunNucleiDir(routeContext, dir, staged, scanner.NucleiRequest{
		URL: parsed.String(), Tags: input.Tags, Severity: input.Severity,
		Proxy: proxy, Options: input.Options,
		Headers: input.captureHeaders(),
		// The run performs every file the binary refuses through this project's
		// own runner, so it needs the recording transport. It is the same transport
		// the binary's own requests go through when `proxy` is set, so a runner row
		// and a binary row leave the same evidence in History.
		Transport: fallbackTransport,
	})
	if err != nil {
		writeOperationError(w, http.StatusBadGateway, "SCANNER_NUCLEI_FAILED", err)
		return
	}
	writeNucleiReport(w, parsed.String(), run, sourceIP)
}

func inputFiles(files []scannerUploadFile) []scanner.UploadFile {
	converted := make([]scanner.UploadFile, 0, len(files))
	for _, file := range files {
		converted = append(converted, scanner.UploadFile{
			Name: file.Name, Path: file.Path, Content: file.Content, Encoding: file.Encoding,
		})
	}
	return converted
}

func runOSINT(target *url.URL, wafCheck bool) (map[string]interface{}, error) {
	return runOSINTWithResolver(target, wafCheck, net.DefaultResolver, osintHTTPClient.Transport)
}

func runOSINTWithResolver(target *url.URL, wafCheck bool, resolver *net.Resolver, transport http.RoundTripper) (map[string]interface{}, error) {
	return runOSINTWithResolverContext(context.Background(), target, wafCheck, resolver, transport)
}

func runOSINTWithResolverContext(ctx context.Context, target *url.URL, wafCheck bool, resolver *net.Resolver, transport http.RoundTripper) (map[string]interface{}, error) {
	// Each section is collected independently so a DNS, TLS, or HTTP failure
	// can be reported as partial results instead of hiding all available data.
	hostname := target.Hostname()
	result := map[string]interface{}{
		"url":        target.String(),
		"host":       target.Host,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"errors":     []string{},
	}

	ips, dnsErr := lookupHostWithRetryWithResolverContext(ctx, hostname, resolver)
	sort.Strings(ips)
	result["dns"] = map[string]interface{}{
		"host": ips,
		"mx":   lookupMXWithResolverContext(ctx, hostname, resolver),
		"ns":   lookupNSWithResolverContext(ctx, hostname, resolver),
		"txt":  lookupTXTWithResolverContext(ctx, hostname, resolver),
	}
	if dnsErr != nil {
		result["errors"] = append(result["errors"].([]string), fmt.Sprintf("DNS lookup: %v", dnsErr))
	}

	response, chain, err := fetchOSINTPageWithTransportContext(ctx, target, transport)
	if err != nil {
		result["http"] = map[string]interface{}{"error": err.Error()}
		result["redirect_chain"] = chain
		result["technologies"] = []string{}
		result["security_headers"] = map[string]interface{}{}
		result["cookies"] = []map[string]interface{}{}
		result["discovery"] = discoverOSINTResources(target, map[string]interface{}{})
		result["waf"] = map[string]interface{}{
			"detected": false, "vendors": []string{}, "confidence": "none",
			"confidence_percent": 0, "evidence": []string{},
		}
		result["errors"] = append(result["errors"].([]string), err.Error())
		return result, nil
	}
	result["http"] = response
	result["redirect_chain"] = chain
	result["technologies"] = detectTechnologies(response, target)
	result["security_headers"] = securityHeaderChecks(response["headers"].(map[string]string))
	result["cookies"] = response["cookies"]
	result["discovery"] = discoverOSINTResources(target, response)
	result["waf"] = detectWAF(response)
	if wafCheck {
		result["waf_check"] = runWAFCanaryWithTransportContext(ctx, target, response, transport)
	}
	return result, nil
}

func lookupHostWithRetryWithResolverContext(ctx context.Context, hostname string, resolver *net.Resolver) ([]string, error) {
	return resolver.LookupHost(ctx, hostname)
}

func fetchOSINTPageWithTransportContext(ctx context.Context, target *url.URL, transport http.RoundTripper) (map[string]interface{}, []string, error) {
	// Redirects are followed manually so every hop remains visible to the UI.
	current := target.String()
	chain := []string{current}
	var response *http.Response
	for {
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if requestErr != nil {
			return nil, nil, requestErr
		}
		req.Header.Set("User-Agent", "RequestRider-OSINT/1.0")
		client := *osintHTTPClient
		client.Transport = transport
		var err error
		response, err = client.Do(req)
		if err != nil {
			return nil, chain, err
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			break
		}
		location := response.Header.Get("Location")
		response.Body.Close()
		if location == "" {
			break
		}
		next, err := target.Parse(location)
		if err != nil {
			break
		}
		current = next.String()
		chain = append(chain, current)
	}
	if response == nil {
		return nil, nil, fmt.Errorf("target returned no response")
	}
	defer response.Body.Close()
	body, truncated, err := readAnalysisBody(response.Body)
	if err != nil {
		return nil, nil, err
	}
	headers := flattenHeaders(response.Header)
	cookies := make([]map[string]interface{}, 0)
	for _, cookie := range response.Cookies() {
		cookies = append(cookies, map[string]interface{}{
			"name": cookie.Name, "secure": cookie.Secure, "http_only": cookie.HttpOnly,
			"same_site": fmt.Sprint(cookie.SameSite), "domain": cookie.Domain, "path": cookie.Path,
		})
	}
	page := map[string]interface{}{
		"status": response.StatusCode, "status_text": response.Status,
		"headers": headers, "content_type": response.Header.Get("Content-Type"),
		"size": len(body), "body_truncated": truncated, "cookies": cookies,
	}
	tlsInfo := map[string]interface{}{"enabled": response.TLS != nil}
	if response.TLS != nil {
		tlsInfo["version"] = tlsVersionName(response.TLS.Version)
		tlsInfo["cipher"] = tls.CipherSuiteName(response.TLS.CipherSuite)
		tlsInfo["negotiated_protocol"] = response.TLS.NegotiatedProtocol
	}
	page["tls"] = tlsInfo
	if bodyIsStorableText(body) {
		page["body"] = string(body)
	} else {
		page["body"] = ""
	}
	return page, chain, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func flattenHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func lookupMXWithResolverContext(ctx context.Context, hostname string, resolver *net.Resolver) []string {
	records, err := resolver.LookupMX(ctx, hostname)
	if err != nil {
		return []string{}
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(result)
	return result
}

func lookupNSWithResolverContext(ctx context.Context, hostname string, resolver *net.Resolver) []string {
	records, err := resolver.LookupNS(ctx, hostname)
	if err != nil {
		return []string{}
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(result)
	return result
}

func lookupTXTWithResolverContext(ctx context.Context, hostname string, resolver *net.Resolver) []string {
	records, err := resolver.LookupTXT(ctx, hostname)
	if err != nil {
		return []string{}
	}
	sort.Strings(records)
	return records
}

func securityHeaderChecks(headers map[string]string) map[string]interface{} {
	// These checks describe observable browser-facing protections; they do not
	// claim that a missing header alone proves a vulnerability.
	checks := map[string]interface{}{}
	for name, description := range map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Content-Type-Options":    "NoSniff",
		"X-Frame-Options":           "Clickjacking protection",
		"Referrer-Policy":           "Referrer policy",
		"Permissions-Policy":        "Permissions policy",
	} {
		value := ""
		for key, candidate := range headers {
			if strings.EqualFold(key, name) {
				value = candidate
				break
			}
		}
		checks[description] = map[string]interface{}{"present": value != "", "value": value}
	}
	return checks
}

func detectTechnologies(response map[string]interface{}, target *url.URL) []string {
	// Fingerprinting is based on static HTML, headers, cookies, and asset URLs.
	// Runtime-only frameworks require a browser/Wappalyzer worker and are not
	// inferred from speculation.
	headers := response["headers"].(map[string]string)
	body, _ := response["body"].(string)
	text := strings.ToLower(body)
	technologies := []string{}
	add := func(name, evidence string) {
		if evidence == "" {
			technologies = append(technologies, name)
			return
		}
		technologies = append(technologies, name+" · "+evidence)
	}
	for key, value := range headers {
		if strings.EqualFold(key, "server") && value != "" {
			add("Web server", "Server: "+value)
		}
		if strings.EqualFold(key, "x-powered-by") && value != "" {
			add("Runtime", "X-Powered-By: "+value)
		}
	}
	for marker, name := range map[string]string{
		"wp-content": "WordPress", "wp-includes": "WordPress",
		"woocommerce": "WooCommerce", "drupal-settings-json": "Drupal",
		"/sites/default/": "Drupal", "joomla": "Joomla", "shopify": "Shopify",
		"cdn.shopify.com": "Shopify", "wixstatic.com": "Wix",
		"squarespace.com": "Squarespace", "webflow.css": "Webflow",
		"ghost.org": "Ghost", "__next_data__": "Next.js",
		"_next/static": "Next.js", "__nuxt": "Nuxt.js", "webpack": "Webpack",
		"react": "React", "vue": "Vue.js", "ng-version": "Angular",
		"ng-app": "Angular", "svelte": "Svelte", "jquery": "jQuery",
		"bootstrap": "Bootstrap", "tailwind": "Tailwind CSS",
		"googletagmanager.com": "Google Tag Manager",
		"google-analytics.com": "Google Analytics", "gtag(": "Google Analytics",
		"laravel": "Laravel", "django": "Django", "rails": "Ruby on Rails",
		"magento": "Magento", "asp.net": "ASP.NET", "express": "Express",
	} {
		if strings.Contains(text, marker) {
			add(name, "HTML/script marker: "+marker)
		}
	}
	for key, value := range headers {
		lower := strings.ToLower(key + ": " + value)
		for marker, name := range map[string]string{
			"cf-ray": "Cloudflare", "x-vercel-id": "Vercel",
			"x-nf-request-id": "Netlify", "x-shopify-stage": "Shopify",
			"x-drupal-cache": "Drupal", "x-generator": "CMS generator",
		} {
			if strings.Contains(lower, marker) {
				add(name, "Header: "+key)
			}
		}
	}
	for _, cookie := range response["cookies"].([]map[string]interface{}) {
		name, _ := cookie["name"].(string)
		lower := strings.ToLower(name)
		for marker, technology := range map[string]string{
			"wordpress": "WordPress", "wp-settings": "WordPress",
			"laravel_session": "Laravel", "django": "Django",
			"phpsessid": "PHP", "asp.net": "ASP.NET",
		} {
			if strings.Contains(lower, marker) {
				add(technology, "Cookie: "+name)
			}
		}
	}
	for _, match := range regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`).FindAllStringSubmatch(body, -1) {
		add("Generator", strings.TrimSpace(match[1]))
	}
	if regexp.MustCompile(`(?is)<meta[^>]+(?:property|name)=["']og:`).MatchString(body) {
		add("Open Graph", "Meta tags: og:*")
	}
	if regexp.MustCompile(`(?is)<link[^>]+rel=["'][^"']*\bmanifest\b`).MatchString(body) ||
		strings.Contains(text, "serviceworker.register") {
		add("PWA", "Web app manifest or service worker")
	}
	if regexp.MustCompile(`(?is)<link[^>]+type=["']application/(?:rss|atom)\+xml["']`).MatchString(body) ||
		regexp.MustCompile(`(?is)<link[^>]+rel=["'][^"']*\balternate\b[^"']*["'][^>]+type=["']application/(?:rss|atom)\+xml["']`).MatchString(body) {
		add("RSS", "Alternate feed link")
	}
	reactVersion := regexp.MustCompile(`(?i)\breact(?:js)?[\/@ -]+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	if match := reactVersion.FindStringSubmatch(body); len(match) > 1 {
		add("JavaScript frameworks", "React "+match[1])
	} else if strings.Contains(text, "data-reactroot") ||
		strings.Contains(text, "__react_devtools_global_hook__") ||
		strings.Contains(text, "react.createelement") ||
		strings.Contains(text, "reactdom") {
		add("JavaScript frameworks", "React")
	}
	for _, match := range regexp.MustCompile(`(?is)<(?:script|link)[^>]+(?:src|href)=["']([^"']+)["']`).FindAllStringSubmatch(body, -1) {
		asset := strings.ToLower(match[1])
		for marker, name := range map[string]string{
			"cdn.jsdelivr.net": "jsDelivr", "unpkg.com": "unpkg",
			"cdnjs.cloudflare.com": "cdnjs", "fonts.googleapis.com": "Google Fonts",
			"recaptcha": "Google reCAPTCHA", "turnstile": "Cloudflare Turnstile",
		} {
			if strings.Contains(asset, marker) {
				add(name, "Asset URL: "+match[1])
			}
		}
	}
	if target.Scheme == "https" {
		add("HTTPS", "")
	}
	return uniqueStrings(technologies)
}

func detectWAF(response map[string]interface{}) map[string]interface{} {
	// Vendor scores combine independent clues so the report includes both a
	// confidence estimate and the evidence that produced it.
	headers := response["headers"].(map[string]string)
	body, _ := response["body"].(string)
	type signal struct {
		vendor   string
		evidence string
		score    int
	}
	signals := []signal{}
	for key, value := range headers {
		lower := strings.ToLower(key + " " + value)
		for marker, vendor := range map[string]string{
			"cloudflare": "Cloudflare", "cf-ray": "Cloudflare", "akamai": "Akamai",
			"imperva": "Imperva", "incap_ses": "Imperva", "sucuri": "Sucuri",
			"bunkerweb": "BunkerWeb", "mod_security": "ModSecurity",
		} {
			if strings.Contains(lower, marker) {
				signals = append(signals, signal{vendor, "Header: " + key, 30})
			}
		}
	}
	lowerBody := strings.ToLower(body)
	for marker, vendor := range map[string]string{
		"attention required": "Cloudflare", "access denied": "Generic WAF",
		"request rejected": "Generic WAF", "imperva incident": "Imperva",
	} {
		if strings.Contains(lowerBody, marker) {
			signals = append(signals, signal{vendor, "Body marker: " + marker, 25})
		}
	}
	scores := map[string]int{}
	evidence := map[string][]string{}
	for _, item := range signals {
		scores[item.vendor] += item.score
		evidence[item.vendor] = append(evidence[item.vendor], item.evidence)
	}
	vendors := []string{}
	bestScore := 0
	for vendor, score := range scores {
		vendors = append(vendors, vendor)
		if score > bestScore {
			bestScore = score
		}
	}
	sort.Strings(vendors)
	confidence := "none"
	if bestScore >= 50 {
		confidence = "high"
	} else if bestScore > 0 {
		confidence = "low"
	}
	return map[string]interface{}{
		"detected": len(vendors) > 0, "vendors": vendors, "confidence": confidence,
		"confidence_percent": bestScore, "evidence": evidence,
	}
}

func runWAFCanaryWithTransportContext(ctx context.Context, target *url.URL, baseline map[string]interface{}, transport http.RoundTripper) map[string]interface{} {
	// The canary changes only a harmless query parameter and compares the
	// response with the baseline; it is not a bypass or evasion test.
	clone := *target
	query := clone.Query()
	query.Set("rr_waf_canary", "requestrider-benign-check")
	clone.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clone.String(), nil)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	req.Header.Set("User-Agent", "RequestRider-OSINT/1.0")
	client := *osintHTTPClient
	client.Transport = transport
	response, err := client.Do(req)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	defer response.Body.Close()
	return map[string]interface{}{
		"status": "completed", "request_url": clone.String(), "http_status": response.StatusCode,
		"baseline_status": baseline["status"], "changed_status": response.StatusCode != osintIntValue(baseline["status"]),
		"note": "Benign canary only; this is not an exploit or bypass audit.",
	}
}

func osintIntValue(value interface{}) int {
	number, _ := value.(int)
	return number
}

func discoverOSINTResources(target *url.URL, response map[string]interface{}) map[string]interface{} {
	body, _ := response["body"].(string)
	return map[string]interface{}{
		"robots":      target.ResolveReference(&url.URL{Path: "/robots.txt"}).String(),
		"sitemap":     target.ResolveReference(&url.URL{Path: "/sitemap.xml"}).String(),
		"links_found": len(mapURLPattern.FindAllString(body, -1)),
	}
}

func (s *server) runSafeScanner(target *url.URL) (map[string]interface{}, error) {
	return s.runSafeScannerContext(context.Background(), target)
}

func (s *server) runSafeScannerContext(ctx context.Context, target *url.URL) (map[string]interface{}, error) {
	resolver := net.DefaultResolver
	if lease, ok := routeLeaseFromContext(ctx); ok {
		resolver = lease.resolver()
	} else if s.routes != nil {
		resolver = s.routes.resolver()
	}
	return runSafeScannerWithResolverContext(ctx, target, resolver, s.toolRunTransport(ctx))
}

// toolRunTransport is the transport of the current run: the recording proxy when
// the gateway asked for one, and the direct route transport when it did not.
func (s *server) toolRunTransport(ctx context.Context) http.RoundTripper {
	if transport := toolTransportFromContext(ctx); transport != nil {
		return transport
	}
	return s.requestTransport()
}

func runSafeScanner(target *url.URL) (map[string]interface{}, error) {
	return runSafeScannerWithResolver(target, net.DefaultResolver, osintHTTPClient.Transport)
}

func runSafeScannerWithResolver(target *url.URL, resolver *net.Resolver, transport http.RoundTripper) (map[string]interface{}, error) {
	return runSafeScannerWithResolverContext(context.Background(), target, resolver, transport)
}

func runSafeScannerWithResolverContext(ctx context.Context, target *url.URL, resolver *net.Resolver, transport http.RoundTripper) (map[string]interface{}, error) {
	base, err := runOSINTWithResolverContext(ctx, target, true, resolver, transport)
	if err != nil {
		return nil, err
	}
	findings := []map[string]interface{}{}
	statusCode := 0
	if httpSection, ok := base["http"].(map[string]interface{}); ok {
		if value, ok := httpSection["status"].(int); ok {
			statusCode = value
		}
	}
	securityHeaders, _ := base["security_headers"].(map[string]interface{})
	httpSection, _ := base["http"].(map[string]interface{})
	technologies := []string{}
	if items, ok := base["technologies"].([]string); ok {
		technologies = items
	}
	baselineFingerprint := responseFingerprint(httpSection)
	missing := []string{}
	if security, ok := securityHeaders["Strict-Transport-Security"].(map[string]interface{}); ok && !security["present"].(bool) {
		missing = append(missing, "Strict-Transport-Security")
	}
	if security, ok := securityHeaders["Content-Security-Policy"].(map[string]interface{}); ok && !security["present"].(bool) {
		missing = append(missing, "Content-Security-Policy")
	}
	if security, ok := securityHeaders["X-Frame-Options"].(map[string]interface{}); ok && !security["present"].(bool) {
		missing = append(missing, "X-Frame-Options")
	}
	if statusCode == 0 {
		findings = append(findings, map[string]interface{}{
			"severity":       "HIGH",
			"title":          "Target unreachable",
			"evidence":       "The target did not return a valid HTTP response during the passive scan.",
			"recommendation": "Verify the URL, ensure the service is running, and rerun the scan against an authorized target.",
		})
	} else {
		if statusCode >= 200 && statusCode < 400 {
			findings = append(findings, map[string]interface{}{
				"severity":       "INFO",
				"title":          "Public HTTP service reachable",
				"evidence":       fmt.Sprintf("HTTP %d response received from %s.", statusCode, target.String()),
				"recommendation": "Use the response as a baseline and verify access control, headers, and public surfaces.",
			})
		}
		if len(technologies) > 0 {
			findings = append(findings, map[string]interface{}{
				"severity":       "INFO",
				"title":          "Technology fingerprint detected",
				"evidence":       strings.Join(technologies[:min(len(technologies), 5)], ", "),
				"recommendation": "Confirm the technology stack in the app inventory and review framework-specific security settings.",
			})
		}
		if len(missing) > 0 {
			findings = append(findings, map[string]interface{}{
				"severity":       "MEDIUM",
				"title":          "Security headers missing",
				"evidence":       strings.Join(missing, ", "),
				"recommendation": "Add HSTS, CSP, and framing protections to reduce browser-side attack surface.",
			})
		}
		if tlsInfo, ok := httpSection["tls"].(map[string]interface{}); ok {
			if version, _ := tlsInfo["version"].(string); version == "TLS 1.0" || version == "TLS 1.1" {
				findings = append(findings, map[string]interface{}{
					"severity":       "MEDIUM",
					"title":          "Outdated TLS protocol negotiated",
					"evidence":       fmt.Sprintf("The target negotiated %s.", version),
					"recommendation": "Disable TLS 1.0 and TLS 1.1 and require TLS 1.2 or newer.",
				})
			}
		}
		if cookies, ok := httpSection["cookies"].([]map[string]interface{}); ok {
			// Cookie checks are reported once per check, not once per cookie: a
			// site that sets ten flagless cookies otherwise produced ten visually
			// identical result rows.
			var missingSecure, missingHTTPOnly, missingSameSite []string
			for _, cookie := range cookies {
				name, _ := cookie["name"].(string)
				if name == "" {
					continue
				}
				secure, _ := cookie["secure"].(bool)
				httpOnly, _ := cookie["http_only"].(bool)
				sameSite := fmt.Sprint(cookie["same_site"])
				if target.Scheme == "https" && !secure {
					missingSecure = append(missingSecure, name)
				}
				if !httpOnly {
					missingHTTPOnly = append(missingHTTPOnly, name)
				}
				if sameSite == "0" || sameSite == "SameSiteDefaultMode" {
					missingSameSite = append(missingSameSite, name)
				}
			}
			for _, check := range []struct {
				names          []string
				severity       string
				title          string
				reason         string
				recommendation string
			}{
				{missingSecure, "MEDIUM", "HTTPS cookie missing Secure flag", "was set without Secure", "Set Secure on cookies that are sent over HTTPS."},
				{missingHTTPOnly, "LOW", "Cookie missing HttpOnly flag", "was set without HttpOnly", "Use HttpOnly for session and other non-client-readable cookies."},
				{missingSameSite, "LOW", "Cookie SameSite policy is not explicit", "did not advertise an explicit SameSite policy", "Set SameSite=Lax or Strict where cross-site use is not required."},
			} {
				if len(check.names) == 0 {
					continue
				}
				findings = append(findings, map[string]interface{}{
					"severity":       check.severity,
					"title":          check.title,
					"category":       "cookie",
					"evidence":       fmt.Sprintf("Cookie %s %s.", joinQuoted(check.names), check.reason),
					"recommendation": check.recommendation,
					"cookies":        check.names,
					"cookie_count":   len(check.names),
				})
			}
		}
		if waf, ok := base["waf"].(map[string]interface{}); ok && waf["detected"] == true {
			vendors, _ := waf["vendors"].([]string)
			findings = append(findings, map[string]interface{}{
				"severity":       "INFO",
				"title":          "WAF or edge protection signal detected",
				"evidence":       fmt.Sprintf("WAF vendors: %s", strings.Join(vendors, ", ")),
				"recommendation": "Keep the network edge in the approved inventory and review platform-specific protections.",
			})
		}
	}

	commonPaths := []struct {
		path     string
		name     string
		category string
	}{
		{path: "/wp-admin/", name: "WordPress admin surface", category: "cms"},
		{path: "/wp-login.php", name: "WordPress login surface", category: "cms"},
		{path: "/wp-json/", name: "WordPress JSON API", category: "cms"},
		{path: "/xmlrpc.php", name: "XML-RPC endpoint", category: "cms"},
		{path: "/administrator/", name: "Joomla admin surface", category: "cms"},
		{path: "/api/", name: "Public API path", category: "api"},
		{path: "/admin/", name: "Admin panel path", category: "admin"},
		{path: "/phpmyadmin/", name: "phpMyAdmin exposure", category: "admin"},
		{path: "/.env", name: "Environment file exposure", category: "misconfiguration"},
		{path: "/.git/HEAD", name: "Git metadata exposure", category: "misconfiguration"},
		{path: "/backup.zip", name: "Backup archive exposure", category: "misconfiguration"},
		{path: "/db.sql", name: "Database dump exposure", category: "misconfiguration"},
		{path: "/server-status", name: "Server status exposure", category: "debug"},
		{path: "/debug/", name: "Debug endpoint", category: "debug"},
	}
	probes := []map[string]interface{}{}
	for _, candidate := range commonPaths {
		probeURL := target.ResolveReference(&url.URL{Path: candidate.path}).String()
		response, err := probeScannerPathWithTransportContext(ctx, probeURL, transport)
		if err != nil {
			continue
		}
		probeBody, probeTruncated, _ := readAnalysisBody(response.Body)
		response.Body.Close()
		probeFingerprint := fingerprintResponse(response, probeBody)
		isFallback := baselineFingerprint != "" && probeFingerprint == baselineFingerprint
		probes = append(probes, map[string]interface{}{
			"path": candidate.path, "category": candidate.category, "status": response.StatusCode,
			"content_type": response.Header.Get("Content-Type"), "fingerprint": probeFingerprint,
			"same_as_baseline": isFallback, "body_truncated": probeTruncated,
		})
		if response.StatusCode >= 200 && response.StatusCode < 400 && !isFallback {
			severity := "LOW"
			if response.StatusCode == http.StatusOK {
				severity = "MEDIUM"
			}
			if candidate.category == "misconfiguration" && response.StatusCode == http.StatusOK {
				severity = "HIGH"
			}
			findings = append(findings, map[string]interface{}{
				"severity":       severity,
				"title":          candidate.name,
				"category":       candidate.category,
				"evidence":       fmt.Sprintf("%s returned HTTP %d (read-only probe; content was not retained).", probeURL, response.StatusCode),
				"recommendation": "Review whether this endpoint is intentionally exposed; if not, restrict access and validate the deployment configuration.",
			})
		}
	}
	allow, optionsErr := scannerOptionsWithTransportContext(ctx, target, transport)
	if optionsErr == nil && allow != "" {
		findings = append(findings, map[string]interface{}{
			"severity":       "INFO",
			"title":          "HTTP methods advertised",
			"category":       "http",
			"evidence":       fmt.Sprintf("Allow header: %s", allow),
			"recommendation": "Disable methods that are not required by the application and verify write methods require authorization.",
		})
	}
	// Two checks can reach the same result row (for example the same public
	// path answered identically twice). Collapse identical title+evidence pairs
	// so the report never shows a duplicated result line.
	findings = dedupeScannerFindings(findings)
	if len(findings) == 0 {
		findings = append(findings, map[string]interface{}{
			"severity":       "INFO",
			"title":          "No passive findings",
			"evidence":       "The target did not surface obvious public exposures during the read-only scan.",
			"recommendation": "Continue with a controlled, authorized review of the application and network configuration.",
		})
	}
	summary := map[string]interface{}{
		"target":           target.String(),
		"status_code":      statusCode,
		"findings_count":   len(findings),
		"highest_severity": "INFO",
	}
	severityRank := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
	for _, item := range findings {
		severity := strings.ToUpper(item["severity"].(string))
		current := summary["highest_severity"].(string)
		if severityRank[severity] > severityRank[current] {
			summary["highest_severity"] = severity
		}
	}
	return map[string]interface{}{
		"url":      target.String(),
		"status":   "completed",
		"summary":  summary,
		"findings": findings,
		"details": map[string]interface{}{
			"dns":              base["dns"],
			"http":             base["http"],
			"security_headers": base["security_headers"],
			"technologies":     base["technologies"],
			"waf":              base["waf"],
			"probes":           probes,
		},
	}, nil
}

// joinQuoted renders a name list as `"a", "b", "c"` for evidence text.
func joinQuoted(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return strings.Join(quoted, ", ")
}

// dedupeScannerFindings keeps the first occurrence of every identical
// title+evidence pair so a result row is never repeated in the report.
func dedupeScannerFindings(findings []map[string]interface{}) []map[string]interface{} {
	seen := make(map[string]bool, len(findings))
	result := make([]map[string]interface{}, 0, len(findings))
	for _, item := range findings {
		key := fmt.Sprintf("%v\x00%v", item["title"], item["evidence"])
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, item)
	}
	return result
}

func responseFingerprint(httpSection map[string]interface{}) string {
	body, _ := httpSection["body"].(string)
	if body == "" {
		return ""
	}
	return fingerprintBytes([]byte(body))
}

func fingerprintResponse(response *http.Response, body []byte) string {
	if response == nil || len(body) == 0 {
		return ""
	}
	return fingerprintBytes(body)
}

func fingerprintBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}

func probeScannerPathWithTransportContext(ctx context.Context, rawURL string, transport http.RoundTripper) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RequestRider-Scanner/1.0")
	client := *osintHTTPClient
	client.Transport = transport
	return client.Do(req)
}

func scannerOptionsWithTransportContext(ctx context.Context, target *url.URL, transport http.RoundTripper) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, target.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "RequestRider-Scanner/1.0")
	client := *osintHTTPClient
	client.Transport = transport
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	return response.Header.Get("Allow"), nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func (s *server) targetMapStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/proxy/target-map/"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_MAP_ID", err)
		return
	}
	s.targetMapsMu.RLock()
	job, ok := s.targetMaps[id]
	s.targetMapsMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "TARGET_MAP_NOT_FOUND", fmt.Errorf("target map %d not found", id))
		return
	}
	if r.Method == http.MethodDelete {
		job.mu.Lock()
		job.cancel()
		job.status = "cancelling"
		job.mu.Unlock()
		writeJSON(w, http.StatusAccepted, targetMapSnapshot(id, job))
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, targetMapSnapshot(id, job))
}

func attachTargetPageSource(job *targetMap, page map[string]interface{}, lookup <-chan string) {
	if ip, ready := sourceIPIfReady(lookup); ready {
		page["source_ip"] = ip
		return
	}
	page["source_ip_pending"] = true
	go func() {
		if ip, ready := <-lookup; ready {
			job.mu.Lock()
			page["source_ip"] = ip
			page["source_ip_pending"] = false
			job.mu.Unlock()
		}
	}()
}

// responseSetsSameSite reports whether the response set a cookie whose SameSite
// attribute limits cross-site sending.
//
// The CSRF analyser sees a body, and a `Set-Cookie` header is not in a body, so
// the fact has to be read here and passed in. The attribute is read as an
// attribute rather than by substring: the header is attacker-shaped data, and a
// bare "samesite" anywhere inside a cookie value must not be able to decide that
// a site is protected.
func responseSetsSameSite(header http.Header) bool {
	for _, value := range header.Values("Set-Cookie") {
		if cookieHasSameSite(value) {
			return true
		}
	}
	return false
}

func cookieHasSameSite(setCookie string) bool {
	parts := strings.Split(setCookie, ";")
	for _, part := range parts[1:] {
		name, _, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "samesite") {
			return true
		}
	}
	return false
}

func (s *server) runTargetMap(id uint64, job *targetMap, ctx context.Context, input targetMapInput) {
	if job.cancel != nil {
		defer job.cancel()
	}
	// The crawler uses a breadth-first queue. Explicit user max_pages/max_depth
	// parameters are honored; zero/negative sentinels mean unlimited and bodies
	// are read without an application byte cap.
	start, _ := url.Parse(job.startURL)
	origin := start.Scheme + "://" + start.Host
	// The queue entry carries the page it was discovered on, because that page
	// is the Referer a browser would send and the Sec-Fetch-Site value that
	// goes with it. Both describe this request truthfully, which is the whole
	// point: the crawler states where it is, instead of looking like a client
	// that arrived from nowhere on every single request.
	queue := []struct {
		rawURL  string
		depth   int
		kind    string
		referer string
	}{{job.startURL, 0, "page", ""}}
	seen := map[string]bool{job.startURL: true}
	for _, suffix := range []string{"/robots.txt", "/sitemap.xml"} {
		resource := normalizeMapURL(mustResolveURL(start, suffix))
		if !seen[resource] {
			seen[resource] = true
			queue = append(queue, struct {
				rawURL  string
				depth   int
				kind    string
				referer string
			}{resource, 0, strings.TrimPrefix(suffix, "/"), ""})
		}
	}
	shape := crawlerRequestShape{
		acceptLanguage: strings.TrimSpace(input.AcceptLanguage),
		retryAttempts:  input.RetryAttempts,
		retryDelayMs:   input.RetryDelayMS,
	}
	// The ladder is attached only when the operator selected it, and the
	// selection is logged before the crawl starts rather than discovered in the
	// report: a map that is wider than it looks needs the reason at the point the
	// reason existed, not three minutes later when somebody asks why.
	if len(input.BypassForms) > 0 {
		log.Printf("[TARGET-MAP %d] 403 ladder selected: %v", id, input.BypassForms)
	}
	client, err := newCrawlerClientWithBypass(
		s.requestTransport(), shape, input.BypassForms,
		func(method, rawURL, form string, status int) {
			log.Printf("[TARGET-MAP %d] bypass %s %s via %s (plain answer %d)",
				id, method, rawURL, form, status)
		},
	)
	if err != nil {
		job.mu.Lock()
		job.status = "failed"
		job.error = "cookie jar: " + err.Error()
		job.finishedAt = time.Now().UTC()
		job.mu.Unlock()
		log.Printf("[TARGET-MAP %d] failed pages=%d error=%v", id, job.visited, err)
		return
	}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		req, err := http.NewRequestWithContext(
			withCrawlerKind(ctx, item.kind), http.MethodGet, item.rawURL, nil,
		)
		if err != nil {
			continue
		}
		if referer := refererFor(item.referer, item.kind); referer != "" {
			req.Header.Set("Referer", referer)
		}
		lookup := s.startSourceIPLookup(ctx)
		requestStart := time.Now()
		outcome, err := crawlOnce(ctx, client, req, shape)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			job.mu.Lock()
			page := map[string]interface{}{
				"url": item.rawURL, "depth": item.depth, "kind": item.kind,
				"error": err.Error(),
			}
			attachTargetPageSource(job, page, lookup)
			job.pages = append(job.pages, page)
			job.visited = len(job.pages)
			job.mu.Unlock()
			continue
		}
		resp := outcome.resp
		body, bodyTruncated, readErr := readAnalysisBody(resp.Body)
		resp.Body.Close()
		page := map[string]interface{}{
			"url": item.rawURL, "depth": item.depth, "status": resp.StatusCode, "kind": item.kind,
			"content_type": resp.Header.Get("Content-Type"), "time": time.Since(requestStart).Milliseconds(),
			"body_truncated": bodyTruncated,
		}
		// The retry is reported whether or not one happened. A crawler that
		// pauses for nine seconds on a Retry-After and says nothing about it
		// looks like a site that is slow, and the analyst would chase the
		// wrong thing.
		if outcome.retried > 0 || outcome.waitedMS > 0 {
			page["retried"] = outcome.retried
			page["attempts"] = outcome.attempts
			page["retry_waited_ms"] = outcome.waitedMS
			if outcome.retryAfter != "" {
				page["retry_after_s"] = outcome.retryAfter
			} else {
				page["retry_after_s"] = ""
			}
		}
		// A challenge is reported on the page it was found on, with the marker
		// that named the vendor. The static crawler cannot execute JavaScript,
		// so it never claims to have passed anything: what it can do is say the
		// body is a gate and not the site, which is the difference between an
		// empty map and an explained one.
		if findings := detectChallenge(
			resp.StatusCode, resp.Header, resp.Cookies(), body, bodyTruncated,
		); len(findings) > 0 {
			page["challenge"] = findings
		}
		// The hops a page took to arrive here are recorded next to it. Following
		// a redirect without saying so would publish `https://www.site/` under
		// the URL the analyst typed and lose the fact that the two differ.
		if chain := crawlRedirectChain(resp); len(chain) > 0 {
			page["redirects"] = chain
			page["final_url"] = resp.Request.URL.String()
		}
		// A `Location` header is a reference the crawler follows, and when the
		// client was told not to follow redirects it is the only evidence that the
		// hop exists at all. `crawlRedirectChain` records hops the client already
		// walked; these are the ones it was not allowed to, and losing them would
		// make a map look like the target had no redirect.
		if location := katanaHeaderReferences(resp.StatusCode, resp.Header, resp.Request.URL); len(location) > 0 {
			if existing, _ := page["header_references"].([]string); len(existing) == 0 {
				page["header_references"] = location
			} else {
				page["header_references"] = mergeCrawlReferences(existing, location)
			}
		}
		if readErr != nil {
			page["error"] = readErr.Error()
		}
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		// A JavaScript resource is read as a program before the page is
		// published, not after. The analysis belongs in the record the poller
		// receives on the first pass: attaching it once the page is already on
		// screen would make a fast client see a page with no findings and a slow
		// one see the same page with them, and which client saw what would depend
		// on timing.
		var jsLinks []string
		jsAnalysed := false
		if isJavaScriptResource(item.kind, contentType) {
			analysis := analyzeJavaScript(item.rawURL, body)
			page["js"] = analysis
			jsLinks = analysis.links
			jsAnalysed = true
		}
		// The enrichment pass reads the same bytes the JavaScript pass just read
		// and answers four questions the map could not answer before: which
		// discovered files are worth reading, what patterns the body carries,
		// what the page leaks about itself, and whether its forms are protected.
		// It runs before the page is published for the same reason the JavaScript
		// analysis does — a client that polls once must not see a page with half
		// of its findings.
		pageAnalysis := enrich.Analyse(item.rawURL, body, resp.Header, contentType, enrich.Options{
			SameSiteCookies: responseSetsSameSite(resp.Header),
			OriginHost:      start.Host,
		})
		if counts := pageAnalysis.Counts(); counts != (enrich.Counts{}) {
			page["enrich"] = pageAnalysis
			page["enrich_counts"] = counts
		}
		attachTargetPageSource(job, page, lookup)
		// Publish each page before discovering its links so polling clients can
		// render incremental progress while the crawl is still running.
		job.mu.Lock()
		job.pages = append(job.pages, page)
		job.visited = len(job.pages)
		job.mu.Unlock()
		// A gate is not the site, so its links are not a frontier: following the
		// "enable JavaScript" link of an interstitial would report coverage the
		// crawl never had. A page that merely *embeds* a captcha widget is the
		// opposite case — it is the site's own page, with its own scripts — so
		// only a finding that says `gate` stops the walk. Measured on a live
		// target 2026-10-03: reading `g-recaptcha` on a news homepage emptied
		// the map of every script, and Target then reported no endpoints, no
		// sinks and no secrets for a site that has all three.
		if challengeIsGate(page["challenge"]) {
			if input.DelayMS > 0 && len(queue) > 0 && !waitForDelay(ctx, time.Duration(input.DelayMS)*time.Millisecond) {
				break
			}
			continue
		}
		if input.MaxDepth < 0 || item.depth < input.MaxDepth || item.kind != "page" {
			// JavaScript brings its own frontier: the references it builds, already
			// resolved against the file they were written in. The regular
			// expression stays for HTML, CSS and JSON, where a reference is a
			// reference and there is no call site to read.
			var links []string
			if jsAnalysed {
				links = jsLinks
			} else {
				// # Katana's parsers run here, inside our crawl
				//
				// Before this, katana was reachable only as a second process with its
				// own crawl, its own result shape and its own place in the UI. That is a
				// separate tool, not an integration: the operator would have run two
				// crawls and merged two maps by hand, and the evidence from one would
				// not have reached History or the Project.
				//
				// Now the thirty upstream parsers read the same bytes we already hold,
				// in the same pass, and their references join the same queue. Everything
				// downstream — `kind` from `classifyMapURL`, the redirect chain, the
				// per-page source IP, `same_origin`, the Project ingest — is unchanged,
				// because from that point on the two finders are indistinguishable.
				//
				// The body parsers need a parsed document, so they only run where a
				// document exists. A redirect has no body, which is why the header
				// parsers are called separately below: they are the only thing that can
				// say where a redirect goes.
				ours := extractMapLinks(string(body), contentType)
				theirs := katanaReferences(resp.StatusCode, resp.Header, contentType, body, resp.Request.URL)
				links = mergeCrawlReferences(ours, theirs)
				// The four references upstream's parsers do not yield. See
				// `frontierLayerReferences` for the measurement behind each.
				links = mergeCrawlReferences(links, frontierLayerReferences(resp.StatusCode, resp.Request.URL, body))
			}
			if item.kind == "robots.txt" || strings.Contains(contentType, "xml") {
				links = append(links, extractSitemapReferences(string(body))...)
			}
			// Посилання з заголовків стають частиною того самого фронту: вони
			// приходять з того самого запиту, що й тіло, і мають бути в одній черзі
			// з рештою, інакше карта показує адресу, яку краулер ніколи не обійде.
			if headerReferences, _ := page["header_references"].([]string); len(headerReferences) > 0 {
				links = mergeCrawlReferences(links, headerReferences)
			}
			for _, link := range links {
				next, err := start.Parse(link)
				if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
					continue
				}
				next.Fragment = ""
				nextURL := normalizeMapURL(next)
				if input.SameOrigin && next.Scheme+"://"+next.Host != origin {
					continue
				}
				if !seen[nextURL] && (input.MaxPages <= 0 || len(seen) < input.MaxPages) {
					seen[nextURL] = true
					queue = append(queue, struct {
						rawURL  string
						depth   int
						kind    string
						referer string
					}{nextURL, item.depth + 1, classifyMapURL(nextURL), item.rawURL})
				}
			}
		}
		if input.DelayMS > 0 && len(queue) > 0 && !waitForDelay(ctx, time.Duration(input.DelayMS)*time.Millisecond) {
			break
		}
	}
	job.mu.Lock()
	if ctx.Err() != nil {
		job.status = "cancelled"
	} else {
		job.status = "completed"
	}
	job.finishedAt = time.Now().UTC()
	job.mu.Unlock()
	log.Printf("[TARGET-MAP %d] %s pages=%d", id, job.status, job.visited)
}

func targetMapSnapshot(id uint64, job *targetMap) map[string]interface{} {
	job.mu.RLock()
	defer job.mu.RUnlock()
	return map[string]interface{}{
		"map_id": id, "status": job.status, "start_url": job.startURL,
		"total": job.maxPages, "visited": job.visited,
		"pages": append([]map[string]interface{}{}, job.pages...),
		"error": job.error,
	}
}

func normalizeMapURL(value *url.URL) string {
	value.Path = strings.ReplaceAll(value.Path, "//", "/")
	if value.Path == "" {
		value.Path = "/"
	}
	return value.String()
}

func extractMapLinks(body, contentType string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	var links []string
	if err == nil && strings.Contains(contentType, "html") {
		var walk func(*html.Node)
		walk = func(node *html.Node) {
			if node.Type == html.ElementNode {
				for _, attr := range node.Attr {
					if (node.Data == "a" && attr.Key == "href") ||
						(node.Data == "form" && attr.Key == "action") ||
						(node.Data == "script" && attr.Key == "src") ||
						(node.Data == "link" && attr.Key == "href") {
						if attr.Val != "" {
							links = append(links, strings.TrimSpace(attr.Val))
						}
					}
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				walk(child)
			}
		}
		walk(doc)
	}
	if strings.Contains(contentType, "css") {
		for _, match := range mapURLPattern.FindAllStringSubmatch(body, -1) {
			if validMapReference(match[1]) {
				links = append(links, match[1])
			}
		}
	}
	if strings.Contains(contentType, "json") {
		// JSON is data, not code. A regular expression is the exact tool for it
		// and tree-sitter would be a slower way to read the same string literals.
		// JavaScript deliberately does not come through here: it is parsed
		// (`analyzeJavaScript` in target_javascript.go), which is both a wider net
		// and a source of endpoints and methods, and running both would be the
		// second path to the same answer.
		for _, match := range mapURLPattern.FindAllStringSubmatch(body, -1) {
			if validMapReference(match[1]) {
				links = append(links, match[1])
			}
		}
	}
	return links
}

// isJavaScriptResource decides whether a crawled resource is JavaScript and so
// whether it gets parsed.
//
// The name alone is not enough, because bundles are served from paths that end
// in nothing in particular — `/assets/main.chunk`, `/static/bundle?id=7` — and
// the content type alone is not enough either, because a server that answers a
// missing `.js` with an HTML shell still has a `text/html` body. Either signal
// is enough, and either one alone would have skipped a real bundle.
func isJavaScriptResource(kind, contentType string) bool {
	return kind == "javascript" ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "ecmascript")
}

func validMapReference(reference string) bool {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return false
	}
	if strings.ContainsAny(reference, `\{}[]|*^$`) {
		return false
	}
	if strings.Contains(reference, "://") && !strings.HasPrefix(strings.ToLower(reference), "http://") &&
		!strings.HasPrefix(strings.ToLower(reference), "https://") {
		return false
	}
	if strings.HasPrefix(reference, "/") {
		return !strings.ContainsAny(reference, `"',();<>`)
	}
	return strings.HasPrefix(strings.ToLower(reference), "http://") ||
		strings.HasPrefix(strings.ToLower(reference), "https://")
}

// extractSitemapReferences reads the URL-bearing directives out of robots.txt and
// sitemap.xml.
//
// `robots.txt` names two kinds of line, and reading only one of them is how the
// map ends up empty of a site that lists its paths plainly. `Sitemap:` points at a
// map; `Allow:` and `Disallow:` name paths on this very host.
//
// The second kind was not read before. Measured on the shared fixture: with only
// `Sitemap:` handled, the crawler's robots.txt yielded nothing, and `robots` read
// as a capability we did not have — while the file said the opposite, in a
// directive no analyst would call secret.
//
// `Disallow` is followed deliberately. It is a robots directive, not an access
// control: the server serves those paths to anyone who asks, and an analyst
// building a map needs to know they exist. Not following them would report a
// smaller site than the one that answers.
func extractSitemapReferences(body string) []string {
	var links []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "sitemap:"):
			links = append(links, strings.TrimSpace(line[len("sitemap:"):]))
		case strings.HasPrefix(lower, "allow:"):
			directive := strings.TrimSpace(line[len("allow:"):])
			// `Allow: /` is not a discovery. It names the site root, which is the
			// page the crawl started from, so enqueueing it would put a row in
			// the map that says the crawler went somewhere it was already.
			//
			// `Disallow:` is deliberately NOT read, and that is not an oversight.
			// A `Disallow` is the site naming a path it does not want crawled;
			// `main_test.go` (`TestSitemapReferencesIgnoreRobotsDirectives`) pins
			// that decision, and a map built by walking the paths a site asked
			// not to be walked is not a map of the site — it is a map of the
			// crawl policy. `Allow:` is the opposite instruction and is safe to
			// follow: the site is naming the paths it does want indexed.
			if directive == "" || directive == "/" || !strings.HasPrefix(directive, "/") {
				continue
			}
			links = append(links, directive)
		}
	}
	for _, match := range regexp.MustCompile(`(?i)<loc>\s*([^<]+)\s*</loc>`).FindAllStringSubmatch(body, -1) {
		links = append(links, strings.TrimSpace(match[1]))
	}
	return links
}

func mustResolveURL(base *url.URL, reference string) *url.URL {
	resolved, err := base.Parse(reference)
	if err != nil {
		return &url.URL{Scheme: base.Scheme, Host: base.Host, Path: reference}
	}
	return resolved
}

func classifyMapURL(rawURL string) string {
	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasSuffix(lower, ".js"):
		return "javascript"
	case strings.HasSuffix(lower, ".css"):
		return "stylesheet"
	case strings.HasSuffix(lower, ".xml"):
		return "sitemap"
	case strings.HasSuffix(lower, "/robots.txt"):
		return "robots.txt"
	default:
		return "page"
	}
}

func (s *server) intruder(w http.ResponseWriter, r *http.Request) {
	// Every attack gets an ID so concurrent logs can be correlated.
	attackID := atomic.AddUint64(&s.attackSequence, 1)
	var input intruderInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("[INTRUDER %d] invalid_json error=%v", attackID, logError(err))
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}

	normalizeIntruderMarkers(&input.BaseRequest)
	if input.DelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_DELAY", fmt.Errorf("delay_ms must not be negative"))
		return
	}
	// Resolve payload lists in marker order so replacement is deterministic.
	// Markers are discovered in URL, sorted headers, then body order.
	markers := requestPositions(input.BaseRequest)
	log.Printf("[INTRUDER %d] start mode=%s host=%s markers=%d dictionaries=%d transformations=%d", attackID, sanitizeLogValue(string(input.Mode)), logHost(input.BaseRequest.URL), len(markers), len(input.Payloads), len(input.Transforms))
	payloadSets := make([][]string, len(markers))
	// Resolve and transform one payload list for every marker position.
	for setIndex := range payloadSets {
		set := []string(nil)
		if values, ok := input.Dictionaries[markers[setIndex]]; ok {
			set = values
		} else if values, ok := input.Dictionaries[strconv.Itoa(setIndex)]; ok {
			set = values
		} else if len(input.Payloads) > 0 {
			payloadIndex := setIndex
			if payloadIndex >= len(input.Payloads) {
				payloadIndex = len(input.Payloads) - 1
			}

			set = input.Payloads[payloadIndex]
		}
		payloadSets[setIndex] = make([]string, len(set))
		for valueIndex, value := range set {
			transformed, transformErr := intruder.TransformPayload(value, input.Transforms)
			if transformErr != nil {
				log.Printf("[INTRUDER %d] transformation_error marker=%d payload_index=%d error=%v", attackID, setIndex, valueIndex, transformErr)
				writeError(w, http.StatusBadRequest, "INVALID_TRANSFORMATION", transformErr)
				return
			}
			payloadSets[setIndex][valueIndex] = transformed
		}
	}
	// Generate the complete job list before starting concurrent requests.
	jobs, err := intruder.Generate(input.Mode, len(markers), payloadSets)
	if err != nil {
		log.Printf("[INTRUDER %d] generation_error mode=%s error=%v", attackID, sanitizeLogValue(string(input.Mode)), logError(err))
		writeError(w, http.StatusBadRequest, "INVALID_INTRUDER", err)
		return
	}
	log.Printf("[INTRUDER %d] generated_jobs=%d payload_sizes=%v", attackID, len(jobs), payloadSizes(payloadSets))
	// Detection is opt-in per run. A nil config or a disabled one leaves every
	// existing attack path untouched: no calibration request, no verdict.
	detection := input.Detection
	if detection != nil && detection.Enabled {
		detection = normalizedDetectionConfig(detection)
		log.Printf("[INTRUDER %d] detection %s", attackID, describeDetection(detection, nil))
	}
	// Start the attack after the request returns so the browser can observe and cancel it.
	_, routeContext, releaseRoute := s.bindRouteContext(context.WithoutCancel(r.Context()))
	ctx, cancel := context.WithCancel(routeContext)
	job := &attack{cancel: func() { cancel(); releaseRoute() }, resumeCh: make(chan struct{}), status: "running", total: len(jobs), detection: detection}
	if detection != nil && detection.Enabled {
		job.calibrating = true
	}
	// Findings spill to disk, so a hundred thousand payload run does not hold
	// its whole report in memory. Without a store the attack keeps results in
	// memory, which is slower but never loses evidence.
	if store, storeErr := newIntruderResultStore(attackID); storeErr == nil {
		job.store = store
	} else {
		log.Printf("[INTRUDER %d] results_spill_unavailable error=%v", attackID, storeErr)
	}
	s.attacksMu.Lock()
	s.attacks[attackID] = job
	s.attacksMu.Unlock()
	writeJSON(w, http.StatusAccepted, s.attackSnapshot(attackID, job, 0))
	go func() {
		// Calibration happens inside the run goroutine, not inside the POST, so
		// a slow or hanging login form cannot hang the browser's start request.
		// The browser learns the baseline from the ordinary poll, which is why
		// the snapshot reports `calibrating` instead of an empty baseline.
		if detection != nil && detection.Enabled {
			baselines := s.calibrateLoginBaselines(ctx, input.BaseRequest, *detection, input.Transforms, ShapesOf(jobs), attackID)
			job.mu.Lock()
			job.baselines = baselines
			job.calibrating = false
			job.mu.Unlock()
			log.Printf("[INTRUDER %d] detection_ready %s", attackID, describeDetection(detection, baselines))
		}
		s.runAttack(attackID, job, ctx, input.BaseRequest, jobs, input.DelayMS, input.Concurrency)
		// A hundred thousand payload run grows the heap by hundreds of megabytes.
		// Go keeps that memory for reuse, which is right while the next run
		// starts immediately and wrong when the operator closes the tool: the
		// pages stay resident and starve everything else on the machine.
		releaseEngineMemory()
	}()
}

// releaseEngineMemory returns heap pages to the operating system after a heavy
// run. Nothing is limited and no result is touched: this only gives back memory
// the process no longer needs, so the app does not hold a gigabyte idle.
func releaseEngineMemory() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	// Only worth doing when the heap really is large, so a small run costs
	// nothing.
	if stats.HeapInuse < 128<<20 {
		return
	}
	debug.FreeOSMemory()
}

func normalizeIntruderMarkers(input *requestInput) {
	// Preserve section markers when a browser or gateway URL-encodes the UTF-8
	// representation of § before the request reaches the engine.
	restore := func(value string) string {
		value = strings.ReplaceAll(value, "%25C2%25A7", "§")
		return strings.ReplaceAll(value, "%C2%A7", "§")
	}
	input.URL = restore(input.URL)
	input.Body = restore(input.Body)
	for key, value := range input.Headers {
		input.Headers[key] = restore(value)
	}
}

func (s *server) runAttack(attackID uint64, attackJob *attack, ctx context.Context, base requestInput, jobs []intruder.Job, delayMS, concurrency int) {
	if attackJob.cancel != nil {
		defer attackJob.cancel()
	}
	ctx = context.WithValue(ctx, suppressRequestLogsKey{}, true)
	workers := concurrency
	if workers <= 0 {
		workers = len(jobs)
		if workers < 1 {
			workers = 1
		}
	}
	if delayMS > 0 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	var wg sync.WaitGroup
	jobIndexes := make(chan int)
	var lastRequest time.Time
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobIndexes {
				job := jobs[index]
				if !waitForAttack(ctx, attackJob) {
					return
				}
				if delayMS > 0 && !lastRequest.IsZero() {
					if !waitForDelay(ctx, time.Until(lastRequest.Add(time.Duration(delayMS)*time.Millisecond))) {
						return
					}
				}
				// Clone prevents one goroutine from mutating another job's headers.
				req := cloneRequest(base)
				// position tracks markers across URL, headers and body as one stream.
				position := 0
				req.URL, position = intruder.ReplaceAt(req.URL, job.Values, position)
				for _, key := range sortedHeaderKeys(req.Headers) {
					req.Headers[key], position = intruder.ReplaceAt(req.Headers[key], job.Values, position)
				}
				req.Body, _ = intruder.ReplaceAt(req.Body, job.Values, position)
				result, execErr := s.executeContext(ctx, req)
				if delayMS > 0 {
					lastRequest = time.Now()
				}
				if execErr != nil {
					if ctx.Err() != nil {
						if result == nil {
							result = exchangeErrorResult("")
						}
						result["error"] = ctx.Err().Error()
						result["payloads"] = job.Values
						s.publishIntruderTraffic(attackID, req, result, execErr)
						return
					}
					if result == nil {
						result = exchangeErrorResult("")
					}
					result["error"] = execErr.Error()
				}
				result["payloads"] = job.Values
				result["request"] = map[string]interface{}{
					"method":  req.Method,
					"url":     req.URL,
					"headers": req.Headers,
					"body":    req.Body,
				}
				// The verdict is attached before the result is published, so the
				// traffic event, the History row and the Intruder table all carry
				// the same answer about the same exchange. `job` is the Intruder
				// job inside this loop and `attackJob` is the run, which is why the
				// run is the one holding the configuration and the counters.
				attackJob.mu.RLock()
				detectionConfig := attackJob.detection
				attackJob.mu.RUnlock()
				if detectionConfig != nil && detectionConfig.Enabled {
					s.evaluateIntruderResult(attackJob, *detectionConfig, result, job.Values)
				}
				s.publishIntruderTraffic(attackID, req, result, execErr)
				attackJob.addResult(result)
				attackJob.mu.Lock()
				attackJob.completed++
				if execErr != nil {
					attackJob.failed++
				}
				attackJob.mu.Unlock()
			}
		}()
	}
dispatch:
	for index := range jobs {
		select {
		case jobIndexes <- index:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobIndexes)
	wg.Wait()
	attackJob.mu.Lock()
	if ctx.Err() != nil {
		attackJob.status = "cancelled"
	} else {
		attackJob.status = "completed"
	}
	attackJob.finishedAt = time.Now().UTC()
	attackJob.mu.Unlock()
	attackJob.mu.RLock()
	status := attackJob.status
	attackJob.mu.RUnlock()
	log.Printf("[INTRUDER %d] %s jobs=%d", attackID, status, len(jobs))
}

func waitForDelay(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func requestLogsSuppressed(ctx context.Context) bool {
	return ctx.Value(suppressRequestLogsKey{}) == true
}

func (s *server) publishIntruderTraffic(attackID uint64, req requestInput, result map[string]interface{}, execErr error) uint64 {
	// Intruder uses the active engine directly, so publish its completed
	// exchanges explicitly for the same Traffic stream as passive proxy events.
	if result == nil {
		result = exchangeErrorResult("")
	}
	lookup, hasLookup := result[sourceIPLookupResultKey]
	delete(result, sourceIPLookupResultKey)
	if s.store == nil {
		return 0
	}
	sourceIP := stringValue(result["source_ip"])
	event := passive.Event{
		Source:        "intruder",
		Session:       int64(attackID),
		Timestamp:     time.Now().UTC(),
		Method:        req.Method,
		URL:           req.URL,
		Host:          requestHost(req.URL),
		RequestHeader: req.Headers,
		RequestBody:   req.Body,
		SourceIP:      sourceIP,
	}
	if execErr != nil {
		event.Error = execErr.Error()
	} else {
		event.Status = intValue(result["status"])
		event.ResponseHeader = stringMapValue(result["headers"])
		event.ResponseBody = stringValue(result["body"])
		event.ResponseBodyEncoding = stringValue(result["body_encoding"])
		event.ResponseBodyBase64 = stringValue(result["body_base64"])
		event.ResponseContentType = stringValue(result["body_content_type"])
		event.ResponseSize = intValue(result["size"])
		event.Latency = int64Value(result["time"])
	}
	eventID := s.store.Add(event)
	result["traffic_event_id"] = eventID
	if hasLookup {
		if lookupChannel, ok := lookup.(<-chan string); ok {
			s.updateTrafficSourceIP(eventID, lookupChannel)
		}
	}
	return eventID
}

func (s *server) addRequestTraffic(req requestInput, sourceIP string) uint64 {
	// Publish the Repeater request immediately, then complete the same event
	// after the outbound response arrives.
	if s.store == nil {
		return 0
	}
	event := passive.Event{
		Source:        "repeater",
		Timestamp:     time.Now().UTC(),
		Method:        req.Method,
		URL:           req.URL,
		Host:          requestHost(req.URL),
		RequestHeader: req.Headers,
		RequestBody:   req.Body,
		SourceIP:      sourceIP,
	}
	return s.store.Add(event)
}

func (s *server) completeRequestTraffic(eventID uint64, result map[string]interface{}, execErr error) {
	if s.store == nil || eventID == 0 {
		return
	}
	if execErr != nil {
		s.store.Update(eventID, func(event *passive.Event) {
			event.Error = execErr.Error()
		})
		return
	}
	s.store.Update(eventID, func(event *passive.Event) {
		event.Status = intValue(result["status"])
		event.ResponseHeader = stringMapValue(result["headers"])
		event.ResponseBody = stringValue(result["body"])
		event.ResponseBodyEncoding = stringValue(result["body_encoding"])
		event.ResponseBodyBase64 = stringValue(result["body_base64"])
		event.ResponseContentType = stringValue(result["body_content_type"])
		event.ResponseSize = intValue(result["size"])
		event.Latency = int64Value(result["time"])
	})
}

func intValue(value interface{}) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func int64Value(value interface{}) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func stringValue(value interface{}) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func stringMapValue(value interface{}) map[string]string {
	if typed, ok := value.(map[string]string); ok {
		return typed
	}
	if typed, ok := value.(map[string]interface{}); ok {
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			if text, ok := item.(string); ok {
				result[key] = text
			}
		}
		return result
	}
	return nil
}

func (s *server) intruderStatus(w http.ResponseWriter, r *http.Request) {
	idText := strings.TrimPrefix(r.URL.Path, "/proxy/intruder/")
	attackID, err := strconv.ParseUint(idText, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ATTACK_ID", err)
		return
	}
	s.attacksMu.RLock()
	attackJob, ok := s.attacks[attackID]
	s.attacksMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "ATTACK_NOT_FOUND", fmt.Errorf("attack %d not found", attackID))
		return
	}
	if r.Method == http.MethodDelete {
		attackJob.mu.Lock()
		if attackJob.status == "pending" || attackJob.status == "running" {
			attackJob.cancel()
			if attackJob.paused {
				close(attackJob.resumeCh)
			}
			attackJob.status = "cancelled"
			attackJob.finishedAt = time.Now().UTC()
		}
		attackJob.mu.Unlock()
		writeJSON(w, http.StatusAccepted, s.attackSnapshot(attackID, attackJob, 0))
		return
	}
	if r.Method == http.MethodPost {
		var command struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&command)
		switch strings.ToLower(command.Action) {
		case "pause":
			attackJob.mu.Lock()
			if attackJob.status == "running" {
				attackJob.paused = true
				attackJob.status = "paused"
				attackJob.resumeCh = make(chan struct{})
			}
			attackJob.mu.Unlock()
		case "resume":
			attackJob.mu.Lock()
			if attackJob.status == "paused" {
				close(attackJob.resumeCh)
				attackJob.paused = false
				attackJob.status = "running"
				attackJob.resumeCh = make(chan struct{})
				close(attackJob.resumeCh)
			}
			attackJob.mu.Unlock()
		default:
			writeError(w, http.StatusBadRequest, "INVALID_ATTACK_ACTION", fmt.Errorf("action must be pause or resume"))
			return
		}
		writeJSON(w, http.StatusAccepted, s.attackSnapshot(attackID, attackJob, 0))
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}

	since, _ := strconv.Atoi(r.URL.Query().Get("since"))
	if since < 0 {
		since = 0
	}
	writeJSON(w, http.StatusOK, s.attackSnapshot(attackID, attackJob, since))
}

func waitForAttack(ctx context.Context, job *attack) bool {
	for {
		job.mu.RLock()
		paused := job.paused
		resumeCh := job.resumeCh
		job.mu.RUnlock()
		if !paused {
			select {
			case <-ctx.Done():
				return false
			default:
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-resumeCh:
		}
	}
}

func parseEventCursor(r *http.Request) uint64 {
	value := r.Header.Get("Last-Event-ID")
	if value == "" {
		value = r.URL.Query().Get("last_event_id")
	}
	cursor, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	return cursor
}

func (s *server) attackSnapshot(id uint64, attackJob *attack, since int) map[string]interface{} {
	attackJob.mu.RLock()
	status, total, completed, failed := attackJob.status, attackJob.total, attackJob.completed, attackJob.failed
	detection, baselines, calibrating := attackJob.detection, attackJob.baselines, attackJob.calibrating
	matched, evaluated := attackJob.matched, attackJob.evaluated
	attackJob.mu.RUnlock()
	// The read happens outside the lock: a hundred thousand result lines are
	// read from disk, and the run must stay observable while that happens.
	results, count, err := attackJob.resultsFrom(since)
	if err != nil {
		log.Printf("[INTRUDER %d] results_read_error offset=%d error=%v", id, since, logError(err))
	}
	if since > count {
		since = count
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	return map[string]interface{}{
		"attack_id":     id,
		"status":        status,
		"total":         total,
		"completed":     completed,
		"failed":        failed,
		"result_offset": since,
		"results":       results,
		"detection":     detectionSnapshot(detection, baselines, calibrating, matched, evaluated),
	}
}

// detectionSnapshot is the detection state as the browser reads it. It travels
// with every poll rather than only the first one, because the counters change
// while the run is going and the baseline is the evidence for the verdicts.
func detectionSnapshot(config *intruder.DetectionConfig, baselines map[string]intruder.Baseline, calibrating bool, matched, evaluated int) map[string]interface{} {
	summary := detectionSummary(config, baselines, matched, evaluated)
	if config != nil && config.Enabled && calibrating {
		summary["calibrating"] = true
	}
	return summary
}

func requestHost(rawURL string) string {
	// Logs use only the parsed host, not request bodies or credentials.
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "-"
	}
	return parsed.Host
}

func requestPath(rawURL string) string {
	// Keep logs useful without printing query values.
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

// --- log sanitising ----------------------------------------------------------
//
// A newline inside a logged value splits the entry, and a value is a log line
// nobody can trace afterwards. That is not theoretical here: RequestRider puts
// operator-supplied and target-supplied text into the log, so a URL carrying
// `%0d%0a` wrote a forged line into engine.log that read exactly like a recorded
// successful attack (`status=200 host=evil.example`) — measured in the security audit.
//
// Control characters are replaced by their escape spelling instead of being
// dropped, so the evidence survives visibly: an operator reading the line sees
// `path=/forged\r\n…` rather than a truncated path that looks legitimate.
//
// `requestHost` and `requestPath` are left alone on purpose — last_byte.go uses
// `requestHost` as a data field, and sanitising a stored value is a different
// decision from sanitising a log line. Only the log call sites go through here.
// bodyIsStorableText reports whether a body can be published as text at all.
//
// `utf8.Valid` alone is not that question, and answering it with `utf8.Valid` is
// what broke the durable archive. Measured 2026-10-02 on live traffic captured by
// `username_search`: `ameblo.jp` and `www.cda.pl` both answer `200` with
// `Content-Type: text/html; charset=utf-8` and a body that is **valid UTF-8 and
// contains a NUL byte**. `utf8.Valid` says yes — U+0000 is a well-formed code
// point — so the engine published it as `body_encoding: utf8` text, PostgreSQL
// answered `DataError: text fields cannot contain NUL (0x00) bytes`, and every poll
// of the transform job returned 500. The result existed and was unreachable.
//
// The two questions are different on purpose: "can this be decoded as UTF-8" and
// "can this be stored in a text column" are not the same, and a body that fails the
// second one has to be published as base64, where nothing is lost.
func bodyIsStorableText(body []byte) bool {
	return utf8.Valid(body) && !bytes.Contains(body, []byte{0})
}

func sanitizeLogValue(value string) string {
	if !strings.ContainsFunc(value, isLogControlByte) {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value) + 8)
	for _, symbol := range value {
		if isLogControlByte(symbol) {
			switch symbol {
			case '\n':
				builder.WriteString(`\n`)
			case '\r':
				builder.WriteString(`\r`)
			case '\t':
				builder.WriteString(`\t`)
			default:
				builder.WriteString(fmt.Sprintf(`\x%02x`, symbol))
			}
			continue
		}
		builder.WriteRune(symbol)
	}
	return builder.String()
}

// isLogControlByte reports the C0 range plus DEL: everything that can terminate or
// disguise a line in a terminal, in `less`, or in a log shipper's parser.
func isLogControlByte(symbol rune) bool {
	return symbol < 0x20 || symbol == 0x7f
}

func logHost(rawURL string) string {
	return sanitizeLogValue(requestHost(rawURL))
}

func logPath(rawURL string) string {
	return sanitizeLogValue(requestPath(rawURL))
}

// logError sanitises a Go error before it reaches a format string, and drops the
// part of it that carries the caller's secrets.
//
// A `*url.Error` embeds the **whole** request URL, query string included. On any
// DNS, connect or TLS failure the engine logged
// `Get "https://host/path?access_token=…": dial tcp: …` verbatim: `requestHost` and
// `requestPath` already drop userinfo and query for the structured fields, but the
// error string bypassed both, and that is where a token from the query had to be
// closed. Every `[REQUEST]` error line goes through here, so closing the helper
// closes all three sites.
//
// The wrapped cause is kept, because the cause is what makes the line useful — it is
// the URL that goes, not the diagnosis.
func logError(err error) string {
	if err == nil {
		return ""
	}
	return sanitizeLogValue(describeError(err))
}

// describeError renders an error chain with every URL reduced to host+path.
//
// It recurses rather than handling a single `*url.Error`, because Go nests them: a
// redirect or a dial failure wraps one error inside another, and the inner one
// carries its own URL. A non-`*url.Error` returns its own message unchanged — there is
// nothing URL-shaped to remove, and inventing a rewrite for every error type would
// make the log worse for no gain.
func describeError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err.Error()
	}
	inner := ""
	if urlErr.Err != nil {
		inner = ": " + describeError(urlErr.Err)
	}
	// An inner `dial` error has no URL of its own; printing `dial "-/":` would be
	// noise, so the quoted part is dropped when there is nothing to redact.
	if strings.TrimSpace(urlErr.URL) == "" {
		return urlErr.Op + inner
	}
	return fmt.Sprintf("%s %q%s", urlErr.Op, logHost(urlErr.URL)+logPath(urlErr.URL), inner)
}

func payloadSizes(payloadSets [][]string) []int {
	// Report dictionary sizes without logging their actual values.
	sizes := make([]int, len(payloadSets))
	for index, payloads := range payloadSets {
		sizes[index] = len(payloads)
	}
	return sizes
}

func requestPositions(input requestInput) []string {
	// Use the same ordering for discovery and replacement.
	values := intruder.Positions(input.URL)
	keys := sortedHeaderKeys(input.Headers)
	for _, key := range keys {
		values = append(values, intruder.Positions(input.Headers[key])...)
	}
	values = append(values, intruder.Positions(input.Body)...)
	return values
}

func sortedHeaderKeys(headers map[string]string) []string {
	// Map iteration is random; sorting makes marker order reproducible.
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneRequest(input requestInput) requestInput {
	// Copy the header map because maps are reference types in Go.
	headers := make(map[string]string, len(input.Headers))
	for key, value := range input.Headers {
		headers[key] = value
	}
	input.Headers = headers
	return input
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	// Keep all successful and error responses JSON encoded consistently.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func isRouteChangedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errRouteChanged) ||
		errors.Is(err, context.Canceled) ||
		strings.Contains(strings.ToLower(err.Error()), "route changed")
}

func writeOperationError(w http.ResponseWriter, status int, reason string, err error) {
	if isRouteChangedError(err) {
		reason = "ROUTE_CHANGED"
	}
	writeError(w, status, reason, err)
}

func writeError(w http.ResponseWriter, status int, reason string, err error) {
	// Expose a machine-readable reason together with the human-readable error.
	writeJSON(w, status, map[string]string{"error": err.Error(), "reason": reason})
}
