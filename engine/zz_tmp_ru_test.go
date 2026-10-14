package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestZZRuDump(t *testing.T) {
	list := os.Getenv("RR_JS_LIST")
	if list == "" {
		t.Skip("no RR_JS_LIST")
	}
	out := map[string]any{}
	for _, path := range strings.Split(strings.TrimSpace(list), "\n") {
		if strings.TrimSpace(path) == "" {
			continue
		}
		body, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			t.Fatal(err)
		}
		analysis := analyzeJavaScript("https://vk.com/app.js", body)
		kinds := map[string]int{}
		for _, finding := range analysis.Findings {
			kinds[finding.Kind]++
		}
		rules := map[string]int{}
		for _, secret := range analysis.Secrets {
			rules[secret.Rule]++
		}
		out[strings.TrimSpace(path)] = map[string]any{
			"bytes": analysis.Bytes, "ms": analysis.Millis,
			"endpoints": len(analysis.Endpoints), "frontier": len(analysis.links),
			"findings": len(analysis.Findings), "kinds": kinds,
			"secrets": len(analysis.Secrets), "rules": rules,
			"deferred": analysis.LinksWithExpression,
			"items":    analysis.Findings,
		}
	}
	encoded, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("RR_JS_OUT"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
