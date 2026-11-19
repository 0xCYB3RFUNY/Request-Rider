package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"unicode/utf8"
)

// The predicate itself, with the two questions stated apart.
//
// `utf8.Valid` is the wrong question and this is the measurement that shows it:
// U+0000 is a well-formed UTF-8 code point, so `utf8.Valid` accepts a body that
// PostgreSQL cannot store in a text column at all.
func TestBodyIsStorableTextRejectsWhatUtf8ValidAccepts(t *testing.T) {
	withNUL := []byte("<html>ok\x00tail</html>")
	if !utf8.Valid(withNUL) {
		t.Fatal("the fixture premise is wrong: a NUL byte is valid UTF-8, so if this " +
			"fails the test is measuring something else")
	}
	if bodyIsStorableText(withNUL) {
		t.Fatal("a body holding NUL was accepted as text; PostgreSQL raises " +
			"DataError on exactly that and every poll of the job returns 500")
	}
	if !bodyIsStorableText([]byte("<html>ok</html>")) {
		t.Fatal("ordinary text must still publish as text")
	}
	if bodyIsStorableText([]byte{0xff, 0xfe}) {
		t.Fatal("invalid UTF-8 must not publish as text")
	}
}

// The real execution path, not only the helper.
//
// The helper being correct is not the same claim as the request executor using it:
// that is exactly the gap that let this reach production, so the test drives
// `executeContextWithSourceIP` against a server that answers the shape real
// traffic had — `200`, `text/html; charset=utf-8`, and a NUL byte in the body.
// Measured 2026-10-02 on `ameblo.jp` and `www.cda.pl` during `username_search`.
func TestExecutePublishesANulBodyAsBase64(t *testing.T) {
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>ok\x00tail</html>"))
	}))
	defer served.Close()

	s := &server{transport: served.Client().Transport.(*http.Transport)}
	result, err := s.executeContextWithSourceIP(context.Background(),
		requestInput{Method: http.MethodGet, URL: served.URL + "/adam"}, "")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := result["body_encoding"]; got != "base64" {
		t.Fatalf("body_encoding = %v, want base64; publishing utf8 for this body "+
			"is what made the durable archive raise DataError", got)
	}
	if body, _ := result["body"].(string); body != "" {
		t.Fatalf("a base64 body must not also carry a text copy, got %q", body)
	}
	if encoded, _ := result["body_base64"].(string); encoded == "" {
		t.Fatal("no base64 was published, so the evidence would be lost rather than encoded")
	}
}

// The other direction, so the fix is not a blunt "everything becomes base64": a
// normal text page must still be readable text in History and in the export.
func TestExecuteStillPublishesOrdinaryTextAsText(t *testing.T) {
	served := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer served.Close()

	s := &server{transport: served.Client().Transport.(*http.Transport)}
	result, err := s.executeContextWithSourceIP(context.Background(),
		requestInput{Method: http.MethodGet, URL: served.URL + "/adam"}, "")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := result["body_encoding"]; got != "utf8" {
		t.Fatalf("body_encoding = %v, want utf8 for an ordinary page", got)
	}
	if body, _ := result["body"].(string); body != "<html>ok</html>" {
		t.Fatalf("body = %q", body)
	}
}
