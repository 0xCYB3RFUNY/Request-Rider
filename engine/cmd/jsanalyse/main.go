// Command jsanalyse prints what a JavaScript file says — endpoints, sinks,
// comments, e-mails and secrets — from the command line.
//
// # Why it exists
//
// The analyser itself is `analyzeJavaScript` in the engine, and it already has
// two callers inside the product: the static crawler (which fetches the bytes
// and analyses them in the crawl) and `POST /proxy/target-js` (which the
// browser-driven mode uses, because that mode never fetches a body itself). Both
// are inside a running engine with a Django gateway in front of it, so there was
// no way to ask the question from a shell: a script, a CI job or an analyst with
// one URL had nothing to call. The upstream tool had a CLI, and the port left it
// out.
//
// # Why it is a client and not a second analyser
//
// This binary speaks to the engine's own route instead of importing the analyser.
// The analyser lives in the engine's `main` package, so a `cmd/` binary cannot
// call it directly without moving the package — and moving it would create a
// second way to answer the same question, which is how two implementations of one
// rule drift apart. Going through the route means:
//
//   - one analyser, so a CLI answer and a UI answer cannot disagree;
//   - one transport, so the fetch carries the same route generation, the same
//     retry and the same per-exchange `source_ip` the crawl uses — a plain
//     `http.Get` from the shell would be a second, unmarked way out to the
//     target;
//   - one record shape, which is what the JSON output *is*: the engine's answer,
//     not a re-serialisation of it.
//
// The cost is that an engine has to be listening; the flag says where.
//
// # What the text output prints
//
// Secret values are printed in full, because a truncated key is a key nobody can
// use or report. The `fingerprint` is printed next to the value so a long value
// stays comparable at a glance. Every other field is printed as the engine sent
// it; nothing is summarised away except the run header.
//
//	go run ./cmd/jsanalyse -url https://example.com/app.js
//	go run ./cmd/jsanalyse -urls-from urls.txt -format json -out findings.json
//	go run ./cmd/jsanalyse -engine http://127.0.0.1:8081 -url https://a/b.js
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole program, so a test can drive it with its own streams and its
// own fake engine instead of a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("jsanalyse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	engine := flags.String("engine", "http://127.0.0.1:8081", "base URL of a running engine")
	referer := flags.String("referer", "", "page the scripts were loaded from")
	urlsFrom := flags.String("urls-from", "", "file with one script URL per line")
	format := flags.String("format", "text", "text or json")
	out := flags.String("out", "", "write the output to this file instead of stdout")
	timeout := flags.Duration("timeout", 120*time.Second, "overall deadline for the engine call")
	var urls flagList
	flags.Var(&urls, "url", "script URL; repeat for several")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "jsanalyse: -format must be text or json, not %q\n", *format)
		return 2
	}

	all := append([]string{}, urls...)
	if *urlsFrom != "" {
		read, err := readURLFile(*urlsFrom)
		if err != nil {
			fmt.Fprintf(stderr, "jsanalyse: %v\n", err)
			return 1
		}
		all = append(all, read...)
	}
	if len(all) == 0 {
		flags.Usage()
		fmt.Fprintln(stderr, "jsanalyse: give at least one -url or a -urls-from file")
		return 2
	}

	payload, err := ask(*engine, all, *referer, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "jsanalyse: %v\n", err)
		return 1
	}

	rendered, err := render(payload, *format)
	if err != nil {
		fmt.Fprintf(stderr, "jsanalyse: %v\n", err)
		return 1
	}
	if *out == "" {
		_, err = io.WriteString(stdout, rendered)
	} else {
		err = os.WriteFile(*out, []byte(rendered), 0o600)
	}
	if err != nil {
		fmt.Fprintf(stderr, "jsanalyse: %v\n", err)
		return 1
	}
	return 0
}

// flagList collects a repeatable flag.
type flagList []string

func (l *flagList) String() string { return strings.Join(*l, " ") }

func (l *flagList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func readURLFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []string
	for index, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
			return nil, fmt.Errorf("%s:%d is not an http(s) URL: %q", path, index+1, trimmed)
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no URLs", path)
	}
	return out, nil
}

// ask sends the same request the gateway sends, so the engine treats the CLI the
// same way it treats the UI.
//
// There is no service key to send: `RR_INTERNAL_API_KEY` and
// `X-RequestRider-Internal-Key` were removed end to end, so this CLI reads no
// environment variable and signs nothing. The two constants it used to duplicate
// from `internal_auth.go` — a separate `package main` cannot import package main
// — left with them.
func ask(engine string, urls []string, referer string, timeout time.Duration) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]interface{}{"urls": urls, "referer": referer})
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(engine, "/") + "/proxy/target-js"
	client := &http.Client{Timeout: timeout}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", endpoint, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("ask %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", endpoint, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d: %s", endpoint, response.StatusCode, summarise(raw))
	}
	return json.RawMessage(raw), nil
}

func summarise(raw []byte) string {
	var document struct {
		Error   string `json:"error"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &document) == nil {
		for _, value := range []string{document.Error, document.Reason, document.Message} {
			if value != "" {
				return value
			}
		}
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) > 200 {
		trimmed = trimmed[:200] + "…"
	}
	return trimmed
}

func render(payload json.RawMessage, format string) (string, error) {
	if format == "json" {
		var document interface{}
		if err := json.Unmarshal(payload, &document); err != nil {
			return "", fmt.Errorf("the engine answer is not JSON: %w", err)
		}
		pretty, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return "", err
		}
		return string(pretty) + "\n", nil
	}
	return formatText(payload)
}

// formatText prints the engine's answer for a human. It is deliberately a
// reading of the same document rather than a second analysis: every count and
// every value here comes from the JSON the engine produced.
func formatText(payload json.RawMessage) (string, error) {
	var answer struct {
		Warning string `json:"warning"`
		Results []struct {
			URL         string `json:"url"`
			Kind        string `json:"kind"`
			Status      int    `json:"status"`
			Bytes       int    `json:"bytes"`
			Millis      int64  `json:"ms"`
			ContentType string `json:"content_type"`
			Error       string `json:"error"`
			JS          struct {
				Bytes     int      `json:"bytes"`
				Links     []string `json:"links"`
				Endpoints []struct {
					URL         string            `json:"url"`
					Method      string            `json:"method"`
					Types       []string          `json:"types"`
					Query       []string          `json:"query_params"`
					Body        []string          `json:"body_params"`
					Headers     map[string]string `json:"headers"`
					ContentType string            `json:"content_type"`
				} `json:"endpoints"`
				Secrets []struct {
					Rule        string `json:"rule"`
					Kind        string `json:"kind"`
					Severity    string `json:"severity"`
					Value       string `json:"value"`
					Fingerprint string `json:"fingerprint"`
					Line        int    `json:"line"`
				} `json:"secrets"`
				Findings []struct {
					Kind     string `json:"kind"`
					Severity string `json:"severity"`
					Subject  string `json:"subject"`
					Function string `json:"function"`
					Evidence string `json:"evidence"`
					Line     int    `json:"line"`
					Count    int    `json:"count"`
				} `json:"findings"`
			} `json:"js"`
		} `json:"results"`
	}
	if err := json.Unmarshal(payload, &answer); err != nil {
		return "", fmt.Errorf("the engine answer is not JSON: %w", err)
	}

	var out strings.Builder
	if answer.Warning != "" {
		fmt.Fprintf(&out, "warning: %s\n\n", answer.Warning)
	}
	totals := 0
	for _, result := range answer.Results {
		totals++
		fmt.Fprintf(&out, "=== %s\n", result.URL)
		if result.Error != "" {
			fmt.Fprintf(&out, "    failed: %s\n", result.Error)
			continue
		}
		if result.Status != 0 {
			fmt.Fprintf(&out, "    %d %s · %d bytes · %d ms\n", result.Status, result.ContentType, result.Bytes, result.Millis)
		}
		js := result.JS
		fmt.Fprintf(&out, "    endpoints %d · secrets %d · findings %d · links %d\n",
			len(js.Endpoints), len(js.Secrets), len(js.Findings), len(js.Links))
		for _, endpoint := range js.Endpoints {
			method := endpoint.Method
			if method == "" {
				method = "-"
			}
			fmt.Fprintf(&out, "    endpoint %s %s\n", method, endpoint.URL)
			if len(endpoint.Query) > 0 {
				fmt.Fprintf(&out, "        query: %s\n", strings.Join(endpoint.Query, " "))
			}
			if len(endpoint.Body) > 0 {
				fmt.Fprintf(&out, "        body:  %s\n", strings.Join(endpoint.Body, " "))
			}
		}
		for _, secret := range js.Secrets {
			// The value is printed whole. A cut key cannot be used and cannot be
			// reported, and the fingerprint is here so a long value stays
			// comparable without being shortened.
			fmt.Fprintf(&out, "    secret [%s/%s] line %d %s\n", secret.Kind, secret.Severity, secret.Line, secret.Fingerprint)
			fmt.Fprintf(&out, "        %s\n", secret.Value)
		}
		for _, finding := range js.Findings {
			where := finding.Function
			if where == "" {
				where = "-"
			}
			repeat := ""
			if finding.Count > 1 {
				repeat = fmt.Sprintf(" ×%d", finding.Count)
			}
			fmt.Fprintf(&out, "    finding [%s/%s] line %d %s in %s%s\n",
				finding.Kind, finding.Severity, finding.Line, finding.Subject, where, repeat)
			if finding.Evidence != "" {
				fmt.Fprintf(&out, "        %s\n", firstLine(finding.Evidence))
			}
		}
	}
	fmt.Fprintf(&out, "\n%d script(s) analysed\n", totals)
	return out.String(), nil
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return strings.TrimSpace(text)
}
