package active

import (
	"net/http"
	"testing"
)

func TestStripDynamicNoiseNormalizesVolatileTokens(t *testing.T) {
	a := `{"ts":"2026-11-16T12:00:01Z","req":"550e8400-e29b-41d4-a716-446655440000","trace":"abcdef0123456789abcdef0123456789","epoch":1731758401,"msg":"blocked"}`
	b := `{"ts":"2026-11-16T12:05:99Z","req":"123e4567-e89b-12d3-a456-426614174000","trace":"99999999999999999999999999999999","epoch":1731758999,"msg":"blocked"}`
	if StripDynamicNoise(a) != StripDynamicNoise(b) {
		t.Fatalf("expected normalized bodies to match:\n%s\nvs\n%s", StripDynamicNoise(a), StripDynamicNoise(b))
	}
}

func TestResponseClustererGroupsWAFAndSeparatesDistinctBodies(t *testing.T) {
	cl := NewResponseClusterer(0.85)
	r1 := &Response{StatusCode: http.StatusForbidden, Body: "Access denied by WAF. Request ID 550e8400-e29b-41d4-a716-446655440000 at 2026-11-16T10:00:00Z"}
	r2 := &Response{StatusCode: http.StatusForbidden, Body: "Access denied by WAF. Request ID 123e4567-e89b-12d3-a456-426614174000 at 2026-11-16T10:01:00Z"}
	r3 := &Response{StatusCode: http.StatusOK, Body: "Welcome user profile dashboard settings account"}

	id1, cnt1 := cl.Observe(r1)
	id2, cnt2 := cl.Observe(r2)
	id3, cnt3 := cl.Observe(r3)

	if id1 != id2 {
		t.Fatalf("expected WAF responses to share cluster, got %d and %d", id1, id2)
	}
	if cnt1 != 1 || cnt2 != 2 {
		t.Fatalf("expected counts 1 and 2, got %d and %d", cnt1, cnt2)
	}
	if id3 == id1 || cnt3 != 1 {
		t.Fatalf("expected distinct 200 OK cluster with count 1, got id=%d count=%d", id3, cnt3)
	}
	if cl.ClusterCount() != 2 {
		t.Fatalf("expected 2 clusters, got %d", cl.ClusterCount())
	}
}
