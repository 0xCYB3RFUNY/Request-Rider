package passive

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"
)

// The predicate, with the two questions stated apart. `utf8.Valid` accepts a body
// holding NUL — U+0000 is well-formed — and PostgreSQL refuses NUL in a text
// column, so the answer to "can this be text" is not the answer to "is this UTF-8".
//
// The measurement behind it: three live captures during `username_search` on
// 2026-10-02, each `text/html` with valid UTF-8 and one NUL byte, each of which
// made the durable write raise `DataError` and the transform poll return 500.
func TestEncodeBodySendsANulBodyAsBase64(t *testing.T) {
	body := []byte("<html>ok\x00tail</html>")
	if !utf8.Valid(body) {
		t.Fatal("fixture premise is wrong: a NUL byte is valid UTF-8")
	}
	text, encoding, encoded := encodeBody(body)
	if encoding != "base64" {
		t.Fatalf("encoding = %q, want base64", encoding)
	}
	if text != "" {
		t.Fatalf("a base64 body must not also publish a text copy, got %q", text)
	}
	if encoded == "" {
		t.Fatal("no base64 published, so the evidence would be lost rather than encoded")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if string(decoded) != string(body) {
		t.Fatalf("round trip lost bytes: got %q", decoded)
	}
}

// The other direction, so the fix is not "everything becomes base64": ordinary text
// is what History and the export read, and it must stay readable.
func TestEncodeBodyStillPublishesOrdinaryText(t *testing.T) {
	text, encoding, encoded := encodeBody([]byte("<html>ok</html>"))
	if encoding != "utf8" || text != "<html>ok</html>" || encoded != "" {
		t.Fatalf("text=%q encoding=%q base64=%q", text, encoding, encoded)
	}
}

// Invalid UTF-8 was already base64 before this change and must stay so.
func TestEncodeBodyPublishesInvalidUTF8AsBase64(t *testing.T) {
	_, encoding, encoded := encodeBody([]byte{0xff, 0xfe})
	if encoding != "base64" || encoded == "" {
		t.Fatalf("encoding=%q base64=%q", encoding, encoded)
	}
}

// A NUL on its own, with nothing around it: the smallest shape that broke it.
func TestEncodeBodyRejectsALoneNul(t *testing.T) {
	_, encoding, encoded := encodeBody([]byte{0})
	if encoding != "base64" || !strings.Contains(encoded, "AA==") {
		t.Fatalf("encoding=%q base64=%q", encoding, encoded)
	}
}
