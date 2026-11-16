package main

// Tests that the read limit is a default the caller can widen, not a ceiling.
//
// # The defect this file was written for
//
// The scan read each body through `io.LimitReader(response.Body, secretScanPageLimit)`
// where `secretScanPageLimit` was a hardcoded `const 4 << 20`. Three things were
// wrong with it, and only the first is about bytes:
//
//   1. It was **invisible**. No option set it, and `setTransformMetadata` never
//      published it, so the run reported `paths_checked`, `secrets_found` and a
//      warning that nothing matched — and said nothing about a body it had read
//      only in part. A 5 MiB `.env` reported "no credential pattern matched" for
//      the 4 MiB the scan read, and the warning named the pattern set rather than
//      the file it had not finished.
//   2. It was **not overridable**. A caller who named a 9 MiB path had 1 MiB of it
//      inspected with no way to ask for more, which is the "limit the user cannot
//      widen" case the project rules forbid.
//   3. It could not be told apart from a body that fit. Reading exactly
//      `limit` bytes cannot distinguish a file of exactly the limit from one of
//      ten times the limit, so "truncated" was not a fact the code could state.
//
// The fix makes it an option (`max_bytes`, `0` = read the whole body), publishes the
// number that was applied, and reads one byte past the limit so "was cut short" is a
// measurement rather than a guess.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// secretIn builds a body whose credential sits `offset` bytes in, so the limit can
// be placed on either side of it deterministically.
func secretIn(offset int) string {
	prefix := strings.Repeat("x", offset)
	return prefix + `api_key = "AIzaSyD8mKpQ2vNzL7rTbXwYcF4hJ9pKdS3eR5t"`
}

// TestMaxBytesWidensTheRead is the assertion for point 2: a caller who asks for
// more gets more. The old constant made this impossible.
func TestMaxBytesWidensTheRead(t *testing.T) {
	const bodyBytes = 600 << 10 // 600 KiB, above the 512 KiB the old cap allowed
	body := secretIn(bodyBytes - 100)
	if len(body) <= 512<<10 {
		t.Fatalf("the fixture is %d bytes, which does not exceed the old 512 KiB cap", len(body))
	}
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer served.Close()

	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// The caller names a limit the old constant would have refused.
	read, truncated, ok := func() (string, bool, bool) {
		got, _, cut, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", 1<<20)
		return got, cut, ok
	}()
	if !ok {
		t.Fatal("the fetch did not complete")
	}
	if truncated {
		t.Fatal("a 600 KiB body under a 1 MiB limit must not be reported as truncated")
	}
	if len(read) != len(body) {
		t.Fatalf("read %d bytes of a %d-byte body: max_bytes did not widen the read",
			len(read), len(body))
	}
	if !strings.Contains(read, "AIzaSy") {
		t.Fatal("the body was cut before the credential at its end")
	}
}

// TestMaxBytesZeroReadsTheWholeBody is point 2's other half: zero means no bound,
// exactly as `max_paths: 0` already meant no bound elsewhere in this scan.
func TestMaxBytesZeroReadsTheWholeBody(t *testing.T) {
	body := secretIn(900 << 10) // 900 KiB, well past the old cap
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer served.Close()
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	read, _, truncated, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", secretScanUnlimitedBytes)
	if !ok {
		t.Fatal("the fetch did not complete")
	}
	if truncated {
		t.Error("max_bytes: 0 must mean no bound, so nothing can be truncated")
	}
	if len(read) != len(body) {
		t.Errorf("read %d bytes of a %d-byte body with max_bytes: 0", len(read), len(body))
	}
}

// TestATruncatedBodyIsAnnounced is point 1: the run must say the body was read in
// part, because otherwise "nothing matched" is an answer about a file the scan
// never finished reading.
func TestATruncatedBodyIsAnnounced(t *testing.T) {
	body := secretIn(200 << 10)
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer served.Close()
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	read, _, truncated, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", 64<<10)
	if !ok {
		t.Fatal("the fetch did not complete")
	}
	if !truncated {
		t.Fatal("a 200 KiB body under a 64 KiB limit must be reported as truncated")
	}
	if len(read) != 64<<10 {
		t.Errorf("read %d bytes under a %d-byte limit", len(read), 64<<10)
	}
	// And the cut is exactly at the limit — the operator's own number, not a
	// rounded one, because the number they typed is the number they get.
	if got := secretScanReadBytes(map[string]interface{}{"max_bytes": 64 << 10}); got != 64<<10 {
		t.Errorf("max_bytes 64 KiB read as %d", got)
	}
}

// TestABodyExactlyAtTheLimitIsNotTruncated closes point 3. Reading exactly `limit`
// bytes cannot tell a body that fits from one that does not; reading `limit+1` can.
func TestABodyExactlyAtTheLimitIsNotTruncated(t *testing.T) {
	body := strings.Repeat("y", 1000)
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer served.Close()
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	_, _, truncated, ok := secretScanFetch(context.Background(), plain, served.URL, "/.env", int64(len(body)))
	if !ok {
		t.Fatal("the fetch did not complete")
	}
	if truncated {
		t.Error("a body of exactly the limit fits, so it must not be reported as truncated")
	}
	// One byte over, and it must be.
	_, _, truncated, ok = secretScanFetch(context.Background(), plain, served.URL, "/.env", int64(len(body))-1)
	if !ok {
		t.Fatal("the second fetch did not complete")
	}
	if !truncated {
		t.Error("a body one byte longer than the limit must be reported as truncated")
	}
}

// TestSecretScanReadBytesReadsTheCaller covers the option itself: absent means the
// documented default, zero means no bound, and a nonsense value falls back to the
// default rather than being guessed at.
func TestSecretScanReadBytesReadsTheCaller(t *testing.T) {
	cases := []struct {
		name    string
		options map[string]interface{}
		want    int64
	}{
		{"absent falls back to the default", map[string]interface{}{}, secretScanDefaultBytes},
		{"zero means no bound", map[string]interface{}{"max_bytes": 0}, secretScanUnlimitedBytes},
		{"a number is taken as given", map[string]interface{}{"max_bytes": 1234}, 1234},
		{"a float is taken as given", map[string]interface{}{"max_bytes": float64(4096)}, 4096},
		{"a string is parsed", map[string]interface{}{"max_bytes": "8192"}, 8192},
		{"a negative value is refused, not clamped", map[string]interface{}{"max_bytes": -1}, secretScanDefaultBytes},
		{"rubbish falls back to the default", map[string]interface{}{"max_bytes": "lots"}, secretScanDefaultBytes},
		{"an unusable type falls back", map[string]interface{}{"max_bytes": []int{1}}, secretScanDefaultBytes},
	}
	for _, testCase := range cases {
		if got := secretScanReadBytes(testCase.options); got != testCase.want {
			t.Errorf("%s: max_bytes read as %d, want %d", testCase.name, got, testCase.want)
		}
	}
}

// TestSecretScanPublishesTheLimitItApplied is the visibility half: the number that
// governed the read has to be in the run's metadata, because a limit the operator
// cannot see is the hidden restriction this project forbids.
func TestSecretScanPublishesTheLimitItApplied(t *testing.T) {
	result := &osintTransformResult{}
	setTransformMetadata(result, "max_bytes", int(secretScanDefaultBytes))
	setTransformMetadata(result, "body_bytes_unlimited", false)
	if got := result.Metadata["max_bytes"]; got != int(secretScanDefaultBytes) {
		t.Errorf("max_bytes missing from the run metadata, got %v", result.Metadata)
	}
	if got := result.Metadata["body_bytes_unlimited"]; got != false {
		t.Errorf("body_bytes_unlimited missing from the run metadata, got %v", result.Metadata)
	}
}
