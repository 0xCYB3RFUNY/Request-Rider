package intruder

import (
	"reflect"
	"strings"
	"testing"
)

// The operator inserts markers with a button, so what the engine has to read
// back is exactly what the application marked and nothing else. Percent-encoded
// data is full of `%20`-style triples; reading those as markers turned one login
// parameter into four attack positions and moved every payload into the wrong
// field.
func TestEncodedDataIsNeverAMarker(t *testing.T) {
	cases := []struct {
		label string
		text  string
		want  []string
	}{
		{
			"a percent-encoded marker is not a marker",
			"log=rradmin&pwd=%C2%A7pass%C2%A7&wp-submit=Log+In",
			nil,
		},
		{
			"a marker plus encoded values around it",
			"log=rradmin&pwd=%pass%&redirect_to=%2Fwp-admin%2F&a=%C2%A7user%C2%A7",
			[]string{"pass"},
		},
		{
			"an encoded query string",
			"redirect_to=%2Fwp-admin%2F&a=%20x%20",
			nil,
		},
		{
			"a bare encoded path",
			"q=%2Ffoo%20bar%",
			nil,
		},
		{
			"json escapes next to a real marker",
			`{"q":"%ff%22","page":"%payload%"}`,
			[]string{"payload"},
		},
		{
			"prose containing a percent sign",
			"50% off %payload% today",
			[]string{"payload"},
		},
		{
			"percent followed by a hex pair and a marker",
			"q=%20%payload%",
			[]string{"payload"},
		},
		{
			"an ffuf-style path with one marker",
			"/FUZZ/%payload%/",
			[]string{"payload"},
		},
		{
			"several real percent markers",
			"%user%:%pass%",
			[]string{"user", "pass"},
		},
		{
			"a marker name may start with one hex digit",
			"%1id%",
			[]string{"1id"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.label, func(t *testing.T) {
			got := Positions(testCase.text)
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("Positions(%q) = %q, want %q", testCase.text, got, testCase.want)
			}
		})
	}
}

// The button writes `§name§`. `§` is two bytes in UTF-8, and the name used to be
// cut with a one-byte slice, so the comparison against "§" was never true and
// every marker name carried the first byte of the closing rune. Names are what
// tie a position to a payload list, so the operator's list was matched under a
// name that was never typed.
func TestSectionMarkerNameIsExact(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"pwd=§pass§", []string{"pass"}},
		{"§user§:§pass§", []string{"user", "pass"}},
		{"log=rradmin&pwd=%C2%A7pass%C2%A7", nil},
		{"{{user}}:{{pass}}", []string{"user", "pass"}},
		{"§payload§ in a form body", []string{"payload"}},
	}
	for _, testCase := range cases {
		got := Positions(testCase.text)
		if !reflect.DeepEqual(got, testCase.want) {
			t.Fatalf("Positions(%q) = %q, want %q", testCase.text, got, testCase.want)
		}
		if !reflect.DeepEqual(got, testCase.want) {
			continue
		}
		// The name has to survive the round trip: replacing by position and
		// replacing by index are the same loop, and a wrong name moves the
		// payload into the wrong field.
		if len(testCase.want) == 0 {
			continue
		}
		values := make([]string, len(testCase.want))
		for index := range values {
			values[index] = "rrvalue" + string(rune('A'+index))
		}
		replaced := Replace(testCase.text, values)
		if strings.ContainsAny(replaced, "§{}") {
			t.Fatalf("Replace(%q, %q) = %q: a marker survived substitution", testCase.text, values, replaced)
		}
		for index, want := range testCase.want {
			if !strings.Contains(replaced, values[index]) {
				t.Fatalf("Replace(%q, %q) = %q: %q is missing for marker %q",
					testCase.text, values, replaced, values[index], want)
			}
		}
	}
}

// Markers live in the URL, in headers and in the body, and the three share one
// index. A field the operator did not mark must come through byte for byte.
func TestUnmarkedFieldsSurviveSubstitution(t *testing.T) {
	body := "log=rradmin&pwd=%C2%A7pass%C2%A7&redirect_to=%2Fwp-admin%2F&testcookie=1"
	got := Positions(body)
	if len(got) != 0 {
		t.Fatalf("Positions(%q) = %q, want none", body, got)
	}
	replaced, used := ReplaceAt(body, []string{"secret"}, 0)
	if replaced != body || used != 0 {
		t.Fatalf("ReplaceAt(%q, …) = (%q, %d), want (%q, 0)", body, replaced, used, body)
	}

	marked := "log=rradmin&pwd=§pass§&redirect_to=%2Fwp-admin%2F"
	if got := Positions(marked); !reflect.DeepEqual(got, []string{"pass"}) {
		t.Fatalf("Positions(%q) = %q, want [pass]", marked, got)
	}
	want := "log=rradmin&pwd=CorrectHorseBattery9!&redirect_to=%2Fwp-admin%2F"
	if replaced := Replace(marked, []string{"CorrectHorseBattery9!"}); replaced != want {
		t.Fatalf("Replace(%q, …) = %q, want %q", marked, replaced, want)
	}
}
