package active

// JsonWebKeySet asks whether the application publishes its JSON Web Key Set.
//
// Burp's check is `0x00600700` (Json Web Key Set disclosed). It is the passive
// half of the JWT checks: a published JKWS is not a vulnerability, and reporting
// it as one would be wrong — it is the *map* of the keys the application signs
// with, and every consumer is meant to read it. What the row documents is what a
// reader of the same document can do with it: a public key that belongs in a key
// set has, by the algorithm, a matching private key somewhere, and the set tells
// an attacker exactly which algorithms and which key ids are worth attacking.
//
// The paths are a table rather than three literals for the same reason
// `crossDomainPaths` is: the interesting-path measurement subtracts what a
// detector asks for on its own account, and it reads that set from the
// package's own tables so a path added here is subtracted from the next run
// without a test being touched.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// JsonWebKeySet is the key-set reader.
type JsonWebKeySet struct{}

// Name implements Module.
func (JsonWebKeySet) Name() string { return "jwks" }

// Level implements Module.
// Runs once per host: the key set is a property of the origin.
func (JsonWebKeySet) Level() Level { return LevelHost }

// jwksPaths are the locations a key set is published under.
var jwksPaths = []string{
	"/.well-known/jwks.json",
	"/.well-known/keys.json",
	"/jwks.json",
	"/jwks",
	"/.well-known/openid-configuration/jwks",
}

// jwksDocument is the shape the run reads, and only the fields the row uses:
// the number of keys and the algorithms they declare. A key set whose entries
// carry neither is still a key set, and a run that refused to report one would
// be applying a rule the specification does not.
type jwksDocument struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
	} `json:"keys"`
}

// Scan probes the origin for a published key set.
func (JsonWebKeySet) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	parsed, hostURL, ok := originOf(p.URL)
	if !ok {
		return nil
	}
	var out []Finding
	for _, path := range jwksPaths {
		target := hostURL + path
		resp, err := t.Do(ctx, http.MethodGet, target, nil, false, http.Header{
			"Accept": {"application/json, */*"},
		})
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			continue
		}
		keys, ok := jwksKeys(resp.Body)
		if !ok {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:  "jwks",
			Title:   "Json Web Key Set Disclosed",
			Claimed: SeverityInfo,
			Tier:    TierVerified,
			Point:   Point{URL: target, Method: http.MethodGet, Origin: parsed},
			Payload: "GET " + target,
			Evidence: fmt.Sprintf("%d key(s) published at %s: %s",
				len(keys), path, jwksDescribe(keys)),
			Description: "The origin publishes its JSON Web Key Set. Publishing a key set is the " +
				"documented way for a consumer to learn the public keys it must verify a token " +
				"against, so the file itself is not the defect. What it does disclose is the exact " +
				"shape of the signing material: which algorithms the origin accepts, and which key " +
				"identifiers an attacker should aim a forged token at.",
			Remediation: "Leave the public keys published — a consumer has to read them — and make " +
				"sure the private material never travels alongside them. Review the key set for " +
				"algorithms you do not intend to support, and remove keys that are retired rather " +
				"than leaving them verifiable.",
		})
		out = append(out, finding)
		break
	}
	return out
}

// originOf splits a URL into the page it came from and the origin's base, so a
// host-level detector can ask for a path on the origin rather than on the page
// it was handed. A URL whose host is empty has no origin and returns ok=false,
// which every host-level detector treats as "this surface cannot answer".
func originOf(raw string) (origin, base string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", "", false
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "http"
	}
	return parsed.String(), parsed.Scheme + "://" + parsed.Host, true
}

// jwksKeys reads a body as a key set and reports whether it is one.
//
// The test is the array of keys rather than the JSON being parseable: every
// JSON error page parses, and a detector that reported on one of those would
// report on every 200 in the application.
func jwksKeys(body string) ([]struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}, bool) {
	if !strings.Contains(body, "\"keys\"") {
		return nil, false
	}
	var doc jwksDocument
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, false
	}
	if len(doc.Keys) == 0 {
		return nil, false
	}
	for _, key := range doc.Keys {
		if strings.TrimSpace(key.Kty) == "" {
			return nil, false
		}
	}
	return doc.Keys, true
}

// jwksDescribe summarises a key set for the evidence line.
func jwksDescribe(keys []struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}) string {
	shown := keys
	more := 0
	if len(shown) > 4 {
		more = len(shown) - 4
		shown = shown[:4]
	}
	parts := make([]string, 0, len(shown))
	for _, key := range shown {
		part := key.Kty
		if key.Alg != "" {
			part += "/" + key.Alg
		}
		if key.Kid != "" {
			part += " (" + key.Kid + ")"
		}
		if key.Use != "" {
			part += " use=" + key.Use
		}
		parts = append(parts, part)
	}
	summary := strings.Join(parts, ", ")
	if more > 0 {
		summary += fmt.Sprintf(", …and %d more", more)
	}
	return summary
}
