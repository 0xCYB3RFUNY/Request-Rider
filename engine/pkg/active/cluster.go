package active

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

var (
	reISO8601   = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)
	reUUID      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reLongHex   = regexp.MustCompile(`(?i)\b[0-9a-f]{24,64}\b`)
	reUnixEpoch = regexp.MustCompile(`\b1[6-9]\d{8}(?:\d{3})?\b`)
	reSpaces    = regexp.MustCompile(`\s+`)
)

// StripDynamicNoise normalizes per-request volatile tokens (timestamps, UUIDs,
// request/trace hex IDs, unix epochs) so differential checks and response
// clustering compare application semantics rather than request-specific noise.
func StripDynamicNoise(body string) string {
	if body == "" {
		return ""
	}
	s := reISO8601.ReplaceAllString(body, "<TS>")
	s = reUUID.ReplaceAllString(s, "<UUID>")
	s = reLongHex.ReplaceAllString(s, "<HEX>")
	s = reUnixEpoch.ReplaceAllString(s, "<EPOCH>")
	s = reSpaces.ReplaceAllString(strings.TrimSpace(s), " ")
	return s
}

// ResponseCluster represents a group of structurally similar HTTP responses
// (for example, repeated WAF block pages, custom 404 templates, or generic errors).
type ResponseCluster struct {
	ID         int
	StatusCode int
	Count      int
	SampleHash string
	tokens     map[string]struct{}
}

// ResponseClusterer groups probe responses by status code and normalized body
// token similarity so detectors can recognize repeated boilerplate/WAF responses.
type ResponseClusterer struct {
	mu        sync.Mutex
	threshold float64
	clusters  []*ResponseCluster
}

// NewResponseClusterer creates a clusterer with the given Jaccard similarity
// threshold in (0, 1]. Values <= 0 default to 0.85.
func NewResponseClusterer(threshold float64) *ResponseClusterer {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.85
	}
	return &ResponseClusterer{threshold: threshold}
}

// Observe assigns resp to an existing cluster if its normalized token set
// meets the similarity threshold for the same status code, or creates a new
// cluster. Returns (clusterID, clusterCount).
func (c *ResponseClusterer) Observe(resp *Response) (int, int) {
	if c == nil || resp == nil {
		return 0, 0
	}
	norm := StripDynamicNoise(resp.Body)
	if len(norm) > 16384 {
		norm = norm[:16384]
	}
	sum := sha256.Sum256([]byte(norm))
	hash := hex.EncodeToString(sum[:8])
	tokens := tokenizeNormalized(norm)

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cl := range c.clusters {
		if cl.StatusCode != resp.StatusCode {
			continue
		}
		if cl.SampleHash == hash || jaccardSimilarity(cl.tokens, tokens) >= c.threshold {
			cl.Count++
			return cl.ID, cl.Count
		}
	}

	id := len(c.clusters) + 1
	c.clusters = append(c.clusters, &ResponseCluster{
		ID:         id,
		StatusCode: resp.StatusCode,
		Count:      1,
		SampleHash: hash,
		tokens:     tokens,
	})
	return id, 1
}

// ClusterCount returns the number of distinct response clusters observed.
func (c *ResponseClusterer) ClusterCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.clusters)
}

func tokenizeNormalized(s string) map[string]struct{} {
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) > 512 {
		fields = fields[:512]
	}
	out := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		out[f] = struct{}{}
	}
	return out
}

func jaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}
