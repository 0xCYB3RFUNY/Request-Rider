package main

import (
	"context"
	"fmt"
	"strings"
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
	first := bruteForceSubdomains(ctx, nil, lookup, "example.test", []string{"www", "api", "nope", "www"}, found)
	second := bruteForceSubdomains(ctx, nil, lookup, "example.test", []string{"www", "api", "nope", "www"}, found)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("hits = %#v %#v", first, second)
	}
	if first[0].name != "api.example.test" || first[1].name != "www.example.test" {
		t.Fatalf("unordered hits = %#v", first)
	}
}
