package active

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// base64Transport is the probe client the module fires through, built once per
// test the same way the other parameter-level tests build theirs.
func base64Transport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport
}

// The fixture decodes the parameter and echoes the decoded form, which is the
// only evidence that separates an application that reads past the base64 from
// one that echoes the encoded bytes.
func base64FixtureServer(t *testing.T, decodes bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		encoded := r.URL.Query().Get("payload")
		if decodes {
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				w.Write([]byte(`<html><body><p>filter: ` + string(decoded) + `</p></body></html>`))
				return
			}
		}
		w.Write([]byte(`<html><body><p>filter: ` + encoded + `</p></body></html>`))
	}))
}

func TestBase64ParameterReportsAServerThatDecodes(t *testing.T) {
	server := base64FixtureServer(t, true)
	defer server.Close()

	point := Point{
		URL:    server.URL + "/report",
		Method: http.MethodGet,
		Param:  "payload",
		Values: url.Values{"payload": {base64.StdEncoding.EncodeToString([]byte("role:member"))}},
	}
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body><p>filter: role:member</p></body></html>"}

	findings := (Base64Parameter{}).Scan(context.Background(), base64Transport(t), point, baseline)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: a canary inside the decoded half is the proof", len(findings))
	}
	if findings[0].Tier != TierVerified {
		t.Errorf("tier = %q, want verified", findings[0].Tier)
	}
}

// The control is a server that echoes the encoded bytes. The canary is then not
// readable in the response, and a run that reported it would be reporting a
// reflection it already reported elsewhere.
func TestBase64ParameterIsSilentOnAServerThatEchoesTheEncodedForm(t *testing.T) {
	server := base64FixtureServer(t, false)
	defer server.Close()

	point := Point{
		URL:    server.URL + "/report",
		Method: http.MethodGet,
		Param:  "payload",
		Values: url.Values{"payload": {base64.StdEncoding.EncodeToString([]byte("role:member"))}},
	}
	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: "<html><body><p>filter: role:member</p></body></html>"}

	findings := (Base64Parameter{}).Scan(context.Background(), base64Transport(t), point, baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// A value that is not base64 at all is out of scope, and so is one that decodes
// to binary — a canary inside it would be invisible in any response.
func TestBase64ParameterIgnoresValuesItCannotUse(t *testing.T) {
	for _, value := range []string{"not base64 at all", "abc", "mQ=="} {
		point := Point{
			URL:    "http://example.com/report",
			Method: http.MethodGet,
			Param:  "payload",
			Values: url.Values{"payload": {value}},
		}
		if len(value) < base64ParamMinLen {
			continue
		}
		if findings := (Base64Parameter{}).Scan(context.Background(), base64Transport(t), point, nil); len(findings) != 0 {
			t.Fatalf("value %q: findings = %d, want 0", value, len(findings))
		}
	}
}

// The spelling of the alphabet matters: a parameter that carries a URL is
// base64 with `-` and `_`, and re-encoding it in the standard alphabet would
// change the bytes the server sees.
func TestBase64ParameterReencodesInTheAlphabetTheSourceUsed(t *testing.T) {
	urlAlphabet := base64.URLEncoding.EncodeToString([]byte("role:member sort=name"))
	out, err := encodeLikeSource(urlAlphabet, "role:member-rrb64sort=name")
	if err != nil {
		t.Fatalf("encodeLikeSource: %v", err)
	}
	if strings.ContainsAny(out, "+/") {
		t.Errorf("re-encoded with the standard alphabet: %s", out)
	}
}
