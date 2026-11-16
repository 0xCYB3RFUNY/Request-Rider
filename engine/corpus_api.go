package main

// The corpus enumeration endpoints.
//
// `RunCorpus` existed and worked, but nothing in the product could reach it: the
// corpus is 6521 checks drawn from a third-party database, and an operator had no
// way to run one. This file is the route to it, and it follows the shape of the
// nuclei run rather than inventing a second one — same method check, same target
// validation, same route context and source IP, same recording transport.
//
// Two endpoints, not one, because they answer two different questions. `stats`
// answers "what would this run evaluate" before anything leaves the machine, which
// is the question an operator has when a run is long. `run` answers "what did it
// find". A single endpoint cannot answer the first without already having answered
// the second.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"intruder/engine/pkg/scanner"
)

// scannerCorpusRequest is what an operator sends to run the corpus.
type scannerCorpusRequest struct {
	// URL is the absolute http or https target to enumerate.
	URL string `json:"url"`
	// Tags narrows the corpus to these tuning letters. Empty means all of it.
	Tags []string `json:"tags"`
	// MaxChecks takes a sample of the corpus instead of all of it. Zero means the
	// whole corpus, which is what an operator asking for it means.
	MaxChecks int `json:"max_checks"`
	// Concurrency is how many requests are in flight; zero takes the run default.
	Concurrency int `json:"concurrency"`
	// TimeoutMS bounds one request in milliseconds; zero takes the run default.
	TimeoutMS int `json:"timeout_ms"`
	// DelayMS pauses between requests, so a run against a fragile target can be
	// slowed by the operator rather than by us guessing a target's fragility.
	DelayMS int `json:"delay_ms"`
	toolRunRoute
}

// scannerCorpusRun enumerates the target against the corpus.
func (s *server) scannerCorpusRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input scannerCorpusRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL",
			fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if input.Concurrency < 0 || input.MaxChecks < 0 || input.TimeoutMS < 0 || input.DelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_BOUND",
			fmt.Errorf("concurrency, max_checks, timeout_ms and delay_ms must not be negative"))
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

	// Findings are collected through the callback rather than read back off the
	// result: the result carries counts, and a run whose report said "13 findings"
	// without showing them would leave the operator to go and find them elsewhere.
	findings := make([]scanner.CorpusFinding, 0, 128)
	result, err := scanner.RunCorpus(routeContext, scanner.CorpusRunRequest{
		Target:      parsed.String(),
		Tags:        input.Tags,
		MaxChecks:   input.MaxChecks,
		Concurrency: input.Concurrency,
		Timeout:     time.Duration(input.TimeoutMS) * time.Millisecond,
		Delay:       time.Duration(input.DelayMS) * time.Millisecond,
		// The capture transport keeps every completed exchange and network error
		// in the shared Traffic store, including when the run itself fails.
		RoundTripper: transport,
		OnFinding: func(finding scanner.CorpusFinding) {
			findings = append(findings, finding)
		},
	})
	if err != nil {
		writeOperationError(w, http.StatusBadGateway, "SCANNER_CORPUS_FAILED", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":           parsed.String(),
		"findings":      findings,
		"requests":      result.Requests,
		"checks":        result.Checks,
		"finding_count": result.Findings,
		"stats":         result.Stats,
		"duration_ms":   result.Duration.Milliseconds(),
		"truncated":     result.Truncated,
		"source_ip":     sourceIP,
	})
}

// scannerCorpusStats reports what a selection would evaluate, without sending
// anything. An operator who cannot see the size of a run before starting it has no
// basis for the bound to put on it.
func (s *server) scannerCorpusStats(w http.ResponseWriter, r *http.Request) {
	all, err := scanner.LoadDefaultCorpus()
	if err != nil {
		writeOperationError(w, http.StatusInternalServerError, "SCANNER_CORPUS_UNREADABLE", err)
		return
	}
	tags := []string{}
	if raw := strings.TrimSpace(r.URL.Query().Get("tags")); raw != "" {
		for _, tag := range strings.Split(raw, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	selected := scanner.FilterCorpus(all, tags)
	maxChecks := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("max_checks")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "INVALID_BOUND",
				fmt.Errorf("max_checks must be a non-negative integer"))
			return
		}
		maxChecks = parsed
	}
	stats := scanner.DescribeCorpus(selected)
	stats.Total = len(all)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats":      stats,
		"max_checks": maxChecks,
	})
}
