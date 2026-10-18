package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// Burp carries Perl code injection as its own check (`0x00100E00`), and the row in
// the register points at the `perl array interpolation` entry in
// `codeInjectionSyntaxes` as the reason it is covered. This test is what makes
// that row true, and it is written the same way the module's own table is: one
// syntax, one arithmetic product, one server that evaluates it.
func TestCodeInjectionReportsAPerlInterpolation(t *testing.T) {
	perl := false
	for _, syntax := range codeInjectionSyntaxes {
		if !strings.Contains(syntax.name, "perl") {
			continue
		}
		perl = true
		payload := syntax.build(codeExpression)
		if !strings.Contains(payload, "@{[") {
			t.Errorf("perl syntax builds %q, which carries no Perl interpolation", payload)
		}
		if syntax.product != codeInjectionFactorA*codeInjectionFactorB {
			t.Errorf("perl syntax claims product %d, want %d", syntax.product,
				codeInjectionFactorA*codeInjectionFactorB)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("code")
			if evaluated, ok := evaluatePerlInterpolation(value); ok {
				w.Write([]byte("<html><body>result: " + evaluated + "</body></html>"))
				return
			}
			w.Write([]byte("<html><body>result: " + value + "</body></html>"))
		}))
		defer server.Close()

		point := Point{URL: server.URL + "/x", Method: http.MethodGet, Param: "code",
			Values: url.Values{"code": {"plain"}}}
		findings := CodeInjection{}.Scan(context.Background(), mustTransport(t), point,
			&Response{StatusCode: 200, Body: "<html><body>result: plain</body></html>"})
		found := false
		for _, finding := range findings {
			if strings.Contains(strings.ToLower(finding.Title), "perl") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no Perl row against a page that interpolates; findings = %+v", findings)
		}
	}
	if !perl {
		t.Fatal("no perl entry in codeInjectionSyntaxes; the register row is wrong")
	}
}

// evaluatePerlInterpolation is the control server's own evaluation, and it
// refuses any shape that is not the Perl one. A server that echoed
// `@{[7*6]}` and printed the product anyway must not be reported.
func evaluatePerlInterpolation(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "@{[") || !strings.HasSuffix(trimmed, "]}") {
		return "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(trimmed, "@{["), "]}")
	parts := strings.Split(inner, "*")
	if len(parts) != 2 {
		return "", false
	}
	left, errLeft := strconv.Atoi(strings.TrimSpace(parts[0]))
	right, errRight := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errLeft != nil || errRight != nil {
		return "", false
	}
	return strconv.Itoa(left * right), true
}
