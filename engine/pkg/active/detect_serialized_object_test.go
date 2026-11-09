package active

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSerializedObjectDetected(t *testing.T) {
	detector := SerializedObject{}

	// Test 1: Java Base64 rO0AB...
	pJava := Point{
		URL:    "http://example.com/api",
		Method: http.MethodGet,
		Param:  "state",
		Values: url.Values{"state": {"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAU="}},
	}

	findings := detector.Scan(context.Background(), nil, pJava, nil)
	if len(findings) == 0 {
		t.Fatalf("expected Java serialized object finding, got 0")
	}
	if !strings.Contains(findings[0].Title, "Java") {
		t.Errorf("expected Java in title, got: %s", findings[0].Title)
	}

	// Test 2: .NET BinaryFormatter AAEAAAD...
	pDotNet := Point{
		URL:    "http://example.com/api",
		Method: http.MethodGet,
		Param:  "data",
		Values: url.Values{"data": {"AAEAAAD/////AQAAAAAAAAAMAgAAAF..."}},
	}
	findingsNet := detector.Scan(context.Background(), nil, pDotNet, nil)
	if len(findingsNet) == 0 {
		t.Fatalf("expected .NET serialized object finding, got 0")
	}
	if !strings.Contains(findingsNet[0].Title, ".NET") {
		t.Errorf("expected .NET in title, got: %s", findingsNet[0].Title)
	}
}
