package intruder

import (
	"strings"
	"testing"
)

func TestGenerateModes(t *testing.T) {
	tests := []struct {
		name string
		mode AttackMode
		sets [][]string
		want int
	}{
		{"sniper", Sniper, [][]string{{"a", "b"}}, 4},
		{"battering ram", BatteringRam, [][]string{{"a", "b"}}, 2},
		{"pitchfork", Pitchfork, [][]string{{"a", "b"}, {"1", "2"}}, 2},
		{"cluster bomb", ClusterBomb, [][]string{{"a", "b"}, {"1", "2", "3"}}, 6},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jobs, err := Generate(test.mode, 2, test.sets)
			if err != nil || len(jobs) != test.want {
				t.Fatalf("Generate() returned %d jobs, err=%v; want %d", len(jobs), err, test.want)
			}
		})
	}
}

func TestReplace(t *testing.T) {
	got := Replace("id=§one§&name=§two§", []string{"1", "alice"})
	if got != "id=1&name=alice" {
		t.Fatalf("Replace() = %q", got)
	}
}

func TestDoubleBraceMarkers(t *testing.T) {
	if got := Replace("q={{one}}&name=§two§", []string{"1", "alice"}); got != "q=1&name=alice" {
		t.Fatalf("Replace() = %q", got)
	}
}

func TestPercentMarkers(t *testing.T) {
	if got := Positions("/%payload%/%second%"); len(got) != 2 || got[0] != "payload" || got[1] != "second" {
		t.Fatalf("Positions() = %#v", got)
	}
	if got := Replace("/%payload%/", []string{"admin"}); got != "/admin/" {
		t.Fatalf("Replace() = %q", got)
	}
}

func TestTransformPayload(t *testing.T) {
	got, err := TransformPayload("Hello world", []Transform{{Operation: "urlEncode"}})
	if err != nil || got != "Hello+world" {
		t.Fatalf("TransformPayload() = %q, err=%v", got, err)
	}
}

func TestTransformPayloadOperations(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		transform Transform
		want      string
	}{
		{"url decode", "Hello+world", Transform{Operation: "urlDecode"}, "Hello world"},
		{"base64 encode", "hello", Transform{Operation: "base64Encode"}, "aGVsbG8="},
		{"base64 decode", "aGVsbG8=", Transform{Operation: "base64Decode"}, "hello"},
		{"base64 url encode", "hello?", Transform{Operation: "base64UrlEncode"}, "aGVsbG8_"},
		{"base64 url decode", "aGVsbG8_", Transform{Operation: "base64UrlDecode"}, "hello?"},
		{"html entity encode", "<tag>", Transform{Operation: "htmlEntityEncode"}, "&lt;tag&gt;"},
		{"json escape", "\"line\"\n", Transform{Operation: "jsonEscape"}, "\\\"line\\\"\\n"},
		{"unicode escape", "A", Transform{Operation: "unicodeEscape"}, "\\u0041"},
		{"hex encode", "hello", Transform{Operation: "hexEncode"}, "68656c6c6f"},
		{"hex decode", "68656c6c6f", Transform{Operation: "hexDecode"}, "hello"},
		{"whitespace normalize", " hello   world ", Transform{Operation: "whitespaceNormalize"}, "hello world"},
		{"trim", " hello ", Transform{Operation: "trim"}, "hello"},
		{"lowercase", "Hello", Transform{Operation: "lowercase"}, "hello"},
		{"uppercase", "Hello", Transform{Operation: "uppercase"}, "HELLO"},
		{"prepend", "value", Transform{Operation: "prepend", Value: "ID-"}, "ID-value"},
		{"append", "value", Transform{Operation: "append", Value: "-test"}, "value-test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := TransformPayload(test.value, []Transform{test.transform})
			if err != nil || got != test.want {
				t.Fatalf("TransformPayload() = %q, err=%v; want %q", got, err, test.want)
			}
		})
	}
}

func TestTransformPayloadRejectsUnknownOperation(t *testing.T) {
	if _, err := TransformPayload("value", []Transform{{Operation: "unknown"}}); err == nil {
		t.Fatal("TransformPayload() accepted an unknown operation")
	}
}

func TestTransformPayloadAllowsBinaryDecode(t *testing.T) {
	got, err := TransformPayload("00ff41", []Transform{{Operation: "hexDecode"}})
	if err != nil {
		t.Fatalf("TransformPayload() rejected binary payload: %v", err)
	}
	if len(got) != 3 || got[0] != 0x00 || got[1] != 0xff || got[2] != 'A' {
		t.Fatalf("TransformPayload() = %v, want bytes 00 ff 41", []byte(got))
	}
}

func TestTransformPayloadEncodingRoundTrips(t *testing.T) {
	tests := []struct {
		name   string
		encode string
		decode string
		value  string
	}{
		{"url", "urlEncode", "urlDecode", "a value/&?"},
		{"base64", "base64Encode", "base64Decode", "Привет\x00\xff"},
		{"base64 url", "base64UrlEncode", "base64UrlDecode", "Привет\x00\xff"},
		{"hex", "hexEncode", "hexDecode", "Привет\x00\xff"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := TransformPayload(test.value, []Transform{{Operation: test.encode}})
			if err != nil {
				t.Fatalf("%s failed: %v", test.encode, err)
			}
			decoded, err := TransformPayload(encoded, []Transform{{Operation: test.decode}})
			if err != nil {
				t.Fatalf("%s failed: %v", test.decode, err)
			}
			if decoded != test.value {
				t.Fatalf("round trip = %q, want %q", decoded, test.value)
			}
		})
	}
}

func TestTransformPayloadEncodingErrors(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		value     string
	}{
		{"invalid url escape", "urlDecode", "%zz"},
		{"invalid base64", "base64Decode", "not-base64"},
		{"invalid base64 url", "base64UrlDecode", "not_base64!"},
		{"invalid hex", "hexDecode", "0xz1"},
		{"odd hex length", "hexDecode", "abc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := TransformPayload(test.value, []Transform{{Operation: test.operation}})
			if err == nil {
				t.Fatalf("%s accepted invalid input %q", test.operation, test.value)
			}
			if !strings.Contains(err.Error(), test.operation) {
				t.Fatalf("error = %q, want operation %q", err, test.operation)
			}
		})
	}
}

func TestTransformPayloadUnicodeEscapeUsesUTF16(t *testing.T) {
	got, err := TransformPayload("A😀", []Transform{{Operation: "unicodeEscape"}})
	if err != nil {
		t.Fatalf("unicodeEscape failed: %v", err)
	}
	if got != `\u0041\ud83d\ude00` {
		t.Fatalf("unicodeEscape = %q, want %q", got, `\u0041\ud83d\ude00`)
	}
}
