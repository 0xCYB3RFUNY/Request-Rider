package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// `javascript:` — 192 документи корпусу. Виміряно, що з них вони потребують:
//
//	nuclei/net 66, nuclei/ssh 17, nuclei/smb 14, nuclei/postgres 11,
//	nuclei/bytes 9, nuclei/redis 7, nuclei/mysql 7, nuclei/ldap 3, nuclei/mssql 3
//
// Тобто **138 з 192** вимагають протокольної бібліотеки nuclei всередині
// JavaScript, і жодного з цих протоколів проєкт не реалізує. Писати дев'ять
// протоколів у JS, щоб додати 138 шаблонів, — це інший проєкт, і видавати таку
// заглушку за виконання було б брехнею.
//
// **54 шаблони** не вимагають нічого, крім `template.*` (108 звернень) та `args:`
// (обидва — значення, які уже є в пам'яті). Вони виконуються повністю: `node`
// є на машині, а `vm.runInContext` повертає completion value останнього твердження —
// рівно те, що nuclei віддає як результат цього протоколу.

// javascriptResultMaxBytes bounds what one script's result may occupy.
const javascriptResultMaxBytes = 1 << 20

// javascriptDriver evaluates a flow's script and prints its value as JSON.
//
// It is written as a file rather than `-e` because the script under test is
// template-supplied: putting it on a command line would need quoting rules, and a
// second quoting language is a second way to be wrong.
const javascriptDriver = `
const vm = require('vm');
const fs = require('fs');

const script = fs.readFileSync(process.argv[2], 'utf8');
const injected = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const context = vm.createContext(Object.assign({console: console}, injected));

let value;
try {
  // runInContext returns the completion value of the whole program, which for a
  // a script ending in an expression is that expression's value. That is exactly what
  // nuclei's javascript protocol hands to its matchers, so no reimplementation of
  // the rule is needed here.
  value = vm.runInContext(script, context);
} catch (error) {
  process.stdout.write(JSON.stringify({__error: String(error && error.message ? error.message : error)}));
  process.exit(0);
}
if (value === undefined) {
  process.stdout.write(JSON.stringify({__error: 'the script produced no value; a javascript block must end with the expression it is judged on'}));
  process.exit(0);
}
process.stdout.write(JSON.stringify({__value: value}));
`

// runJavaScriptDocument executes each `javascript:` block of a document.
func runJavaScriptDocument(ctx context.Context, document *passiveDocument, blocks []passiveRequest,
	target string, dynamic map[string]string) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	for index, block := range blocks {
		source := strings.TrimSpace(block.JavaScriptCode)
		if source == "" {
			run.Skipped = true
			run.Reason = fmt.Sprintf("javascript block %d of %d declares no `code:`, so there is nothing to run",
				index+1, len(blocks))
			return run
		}
		if needed := nucleiModulesNeeded(source); len(needed) > 0 {
			run.Skipped = true
			run.Reason = fmt.Sprintf(
				"javascript block %d of %d requires %s, a protocol library nuclei provides inside its own "+
					"runtime. This project performs that protocol in Go and does not ship a JavaScript "+
					"implementation of it, so the script is refused rather than run without the module",
				index+1, len(blocks), strings.Join(needed, ", "))
			return run
		}
		result, reason := evaluateJavaScript(ctx, source, block.JavaScriptArgs, dynamic, target)
		if reason != "" {
			run.Skipped = true
			run.Reason = fmt.Sprintf("javascript block %d of %d: %s", index+1, len(blocks), reason)
			return run
		}
		run.Request += "// javascript block " + fmt.Sprint(index+1) + "\n" + source + "\n"
		run.Response += result
		verdict := scoreJavaScriptBlock(document, block, result)
		run.Extracts = append(run.Extracts, verdict.Extracts...)
		for name, values := range verdict.ExtractLists {
			run.ExtractLists[name] = append(run.ExtractLists[name], values...)
		}
		if verdict.Matched {
			run.Matched = true
			if len(run.MatcherNames) == 0 {
				run.MatcherNames = verdict.MatcherNames
			}
			continue
		}
	}
	if !run.Matched {
		run.Skipped = true
		run.Reason = fmt.Sprintf("all %d javascript block(s) ran and matched nothing", len(blocks))
	}
	return run
}

// nucleiModulesNeeded lists the `require("nuclei/…")` modules a script wants.
func nucleiModulesNeeded(source string) []string {
	seen := map[string]bool{}
	var out []string
	for _, quote := range []string{`"`, `'`} {
		needle := "require(" + quote + "nuclei/"
		for cursor := 0; ; {
			at := strings.Index(source[cursor:], needle)
			if at < 0 {
				break
			}
			cursor += at + len(needle)
			rest := source[cursor:]
			end := strings.IndexAny(rest, quote)
			if end < 0 {
				break
			}
			name := "nuclei/" + rest[:end]
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// evaluateJavaScript runs one script and returns its value as text.
func evaluateJavaScript(ctx context.Context, source string, args map[string]string,
	dynamic map[string]string, target string) (string, string) {
	interpreter, err := exec.LookPath("node")
	if err != nil {
		return "", "this host has no `node`, so a javascript block cannot be executed: " + oneLine(err.Error())
	}
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	directory, err := os.MkdirTemp("", "requestrider-js-")
	if err != nil {
		return "", "cannot stage the script: " + oneLine(err.Error())
	}
	defer os.RemoveAll(directory)

	// The values a script reads are the ones a request is allowed to send: the
	// single-valued extractions and the block's own `args:`. A name extracted
	// several times is not among them, for the same reason it is not on the wire.
	template := map[string]string{}
	for name, value := range dynamic {
		template[name] = value
	}
	if parsed := mustParseTarget(target); parsed != nil {
		template["BaseURL"] = strings.TrimSuffix(target, "/")
		template["Hostname"] = parsed.Hostname()
	}
	injected := map[string]interface{}{
		"template": template,
		"args":     args,
	}
	if injected["args"] == nil {
		injected["args"] = map[string]string{}
	}
	encoded, err := json.Marshal(injected)
	if err != nil {
		return "", "cannot encode what the script reads: " + oneLine(err.Error())
	}
	scriptPath := filepath.Join(directory, "script.js")
	if err := os.WriteFile(scriptPath, []byte(source), 0o700); err != nil {
		return "", "cannot stage the script: " + oneLine(err.Error())
	}
	injectedPath := filepath.Join(directory, "injected.json")
	if err := os.WriteFile(injectedPath, encoded, 0o600); err != nil {
		return "", "cannot stage what the script reads: " + oneLine(err.Error())
	}
	driverPath := filepath.Join(directory, "driver.js")
	if err := os.WriteFile(driverPath, []byte(javascriptDriver), 0o700); err != nil {
		return "", "cannot stage the evaluator: " + oneLine(err.Error())
	}

	command := exec.CommandContext(runCtx, interpreter, driverPath, scriptPath, injectedPath)
	command.WaitDelay = 2 * time.Second
	output, runErr := command.Output()
	if runErr != nil {
		return "", "cannot run the script: " + oneLine(runErr.Error())
	}
	if len(output) > javascriptResultMaxBytes {
		output = output[:javascriptResultMaxBytes]
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(output, &decoded); err != nil {
		return "", "the evaluator printed text that is not JSON: " + oneLine(string(truncateOutput(string(output))))
	}
	if message, failed := decoded["__error"]; failed {
		return "", "the script raised: " + oneLine(asString(message))
	}
	value := decoded["__value"]
	text, isText := value.(string)
	if !isText {
		text = string(truncateOutput(string(mustJSON(value))))
	}
	return text, ""
}

// scoreJavaScriptBlock judges the script's value with the same operators a response
// goes through, so `response`, `body`, `raw` and `dsl` mean here what they mean on
// the wire.
func scoreJavaScriptBlock(document *passiveDocument, block passiveRequest, value string) PassiveMatch {
	exchange := PassiveExchange{
		Method:      "JAVASCRIPT",
		URL:         "javascript://block",
		Host:        "javascript",
		RawRequest:  block.JavaScriptCode,
		RawResponse: value,
		Body:        value,
		StatusCode:  200,
		Parts: map[string]string{
			"response": value,
			"raw":      value,
			"body":     value,
			"data":     value,
		},
	}
	return scoreCompiled(document, block, exchange)
}

func mustJSON(value interface{}) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte{}
	}
	return encoded
}

func asString(value interface{}) string {
	if text, ok := value.(string); ok {
		return text
	}
	return string(mustJSON(value))
}
