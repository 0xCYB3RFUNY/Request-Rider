package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultSubdomainWordsAreClean(t *testing.T) {
	words := defaultSubdomainWords()
	if len(words) == 0 {
		t.Fatalf("wordlist size = %d", len(words))
	}
	seen := map[string]bool{}
	for _, word := range words {
		if word == "" || strings.ContainsAny(word, " /:@") || seen[word] {
			t.Fatalf("bad wordlist entry %q", word)
		}
		seen[word] = true
	}
}

func TestDetectWildcardDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	NXLookup := func(context.Context, string) ([]string, error) {
		return nil, fmt.Errorf("NXDOMAIN")
	}
	sample, wildcard := detectWildcardDNS(ctx, nil, NXLookup, "example.test")
	if wildcard || sample != "" {
		t.Fatalf("clean zone flagged: sample=%q wildcard=%v", sample, wildcard)
	}
	sample, wild := detectWildcardDNS(ctx, nil, func(_ context.Context, name string) ([]string, error) {
		if name != "rr-nowild-01.example.test" {
			return nil, fmt.Errorf("NXDOMAIN")
		}
		return []string{"203.0.113.7"}, nil
	}, "example.test")
	if !wild {
		t.Fatalf("wildcard zone missed: sample=%q", sample)
	}
	// The resolving probe is reported so the analyst can verify the claim.
	if sample != "rr-nowild-01.example.test -> 203.0.113.7" {
		t.Fatalf("wildcard evidence = %q", sample)
	}
}

func TestBruteForceSubdomainsIsDeterministic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lookup := func(_ context.Context, candidate string) ([]string, error) {
		if strings.HasPrefix(candidate, "www.") || strings.HasPrefix(candidate, "api.") {
			return []string{"198.51.100.3"}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}
	found := map[string]bool{}
	first, _ := bruteForceSubdomains(ctx, nil, lookup, "example.test", []string{"www", "api", "nope", "www"}, found, bruteForceDefaultWorkers)
	second, _ := bruteForceSubdomains(ctx, nil, lookup, "example.test", []string{"www", "api", "nope", "www"}, found, bruteForceDefaultWorkers)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("hits = %#v %#v", first, second)
	}
	if first[0].name != "api.example.test" || first[1].name != "www.example.test" {
		t.Fatalf("unordered hits = %#v", first)
	}
}

// Concurrency is an explicit operator choice, not a constant in the loop, and it
// must change how much work is in flight without changing the result. Both
// halves are asserted: the pool really is used, and the pool size never trims
// the work.
func TestBruteForceConcurrencyIsExplicitAndDoesNotChangeResults(t *testing.T) {
	words := []string{"a1", "b2", "c3", "d4", "e5", "f6", "g7", "h8"}
	lookup := func(_ context.Context, candidate string) ([]string, error) {
		if strings.HasSuffix(candidate, ".hit") {
			return []string{"198.51.100.9"}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}

	// With one worker the lookups cannot overlap, so the peak stays at one; with
	// four it has to rise. That difference is what the operator is buying, and it
	// has to be observable rather than assumed.
	measure := func(workers int) (int, int) {
		var mu sync.Mutex
		inFlight, peak := 0, 0
		counting := func(ctx context.Context, candidate string) ([]string, error) {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()
			time.Sleep(15 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			return lookup(ctx, candidate)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		hits, _ := bruteForceSubdomains(ctx, nil, counting, "example.test", words, map[string]bool{}, workers)
		return peak, len(hits)
	}

	serialPeak, serialHits := measure(1)
	widePeak, wideHits := measure(4)
	if serialPeak != 1 {
		t.Fatalf("a pool of one must not overlap lookups, peak = %d", serialPeak)
	}
	if widePeak < 2 {
		t.Fatalf("a pool of four must overlap lookups, peak = %d", widePeak)
	}
	if serialHits != wideHits {
		t.Fatalf("pool size changed the result: %d vs %d hits", serialHits, wideHits)
	}
}

func TestPositiveIntOptionPrefersAnExplicitValue(t *testing.T) {
	cases := []struct {
		name     string
		options  map[string]interface{}
		fallback int
		want     int
	}{
		{"missing", map[string]interface{}{}, 8, 8},
		{"json number", map[string]interface{}{"dns_concurrency": float64(24)}, 8, 24},
		{"string", map[string]interface{}{"dns_concurrency": "16"}, 8, 16},
		{"zero falls back", map[string]interface{}{"dns_concurrency": float64(0)}, 8, 8},
		{"negative falls back", map[string]interface{}{"dns_concurrency": float64(-4)}, 8, 8},
		{"unreadable falls back", map[string]interface{}{"dns_concurrency": "many"}, 8, 8},
		{"wrong type falls back", map[string]interface{}{"dns_concurrency": true}, 8, 8},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := positiveIntOption(testCase.options, "dns_concurrency", testCase.fallback); got != testCase.want {
				t.Fatalf("positiveIntOption = %d, want %d", got, testCase.want)
			}
		})
	}
}
