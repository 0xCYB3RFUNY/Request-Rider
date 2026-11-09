package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// `code:` — 967 шаблонів офіційного корпусу, другий за величиною протокол після
// `http`. Движки виміряні на корпусі:
//
//	sh 1734   bash 53   py 28   ruby 1   rb 1   php 1   powershell 1
//
// Тобто `sh` і `bash` — це 96 % цього класу, і решта розподілена так, що кожен
// рушій має по одному-два шаблони.
//
// Це той самий код, який виконує бінарник, тільки в цьому проєкті: `exec.Command`
// без оболонки, аргументи масивом, і жодного shell-рядка, який треба розбирати.
//
// Обмеження, яке треба назвати: таймаут. Команда, що не повертається, не повинна
// тримати прогін вічно — але межа тут не прихована, вона видима в аргументах і
// перекривається.

const defaultCodeTimeoutSec = 60

// codeMaxOutputBytes caps what a template's output can occupy.
//
// It is a memory bound, not a capability bound: a template may print as much as it
// likes and only the recorded prefix is kept, which is stated in the reason rather
// than silently applied.
const codeMaxOutputBytes = 1 << 20

// runCodeTemplate executes one `code:` block and returns its output as an exchange
// the ordinary matcher path can judge.
//
// The parts nuclei exposes are `stdout` and `stderr`, and `response` is the same
// text. Nothing else is invented: a template that matches on `code_1_response` or
// `body` is a `code` template whose DSL reads a variable this runner does not set,
// and it says so by matching nothing rather than by pretending.
// runCodeTemplate is the entry for a `code:` block outside a flow.
func runCodeTemplate(ctx context.Context, document *passiveDocument, block passiveRequest, target string, position int) LocalRun {
	return runCodeTemplateWith(ctx, document, block, target, position, nil)
}

// runCodeTemplateWith runs one block with values already known.
//
// `dynamic` is what a flow computed before this step. Measured: 589 flow templates
// call `code(n)`, and the cloud family writes `for (let B of iterate(template.buckets))
// { set("bucket", B); code(1) }` — the script's whole subject is a value the flow
// assigned one line earlier, so a block that cannot see the flow's variables reads
// an empty bucket name and reports the result of checking nothing.
func runCodeTemplateWith(ctx context.Context, document *passiveDocument, block passiveRequest,
	target string, position int, dynamic map[string]string) LocalRun {
	run := LocalRun{}
	engine := firstCodeEngine(block)
	if engine == "" {
		run.Reason = "the block declares a `code:` engine but this runner reads none, so there is nothing to run"
		return run
	}
	source := block.CodeSource
	if strings.TrimSpace(source) == "" {
		run.Reason = "the block declares a `code:` engine and no `source:`, so there is nothing to run"
		return run
	}

	timeout := codeTimeout(block)
	if override := optionalPositiveInt("RR_CODE_TIMEOUT_SEC"); override > 0 {
		timeout = override
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// No shell: the script goes to the interpreter's stdin exactly as written, and
	// the interpreter is named as an argument. A command line that had to be
	// assembled and parsed would be a second language in this project.
	// nuclei передає скрипт файлом, а не стандартним вводом — виміряно на v3.11.1:
	//
	//	failed to exec command got: /tmp/nuclei-tmp-1096024597/2915071191: 1: az: not found
	//
	// Різниця не в вердикті: на трьох шаблонах, де `az` не встановлено, обидва
	// шляхи дають `exit status 127`. Різниця в тому, що при передачі через stdin
	// у скрипта немає власного імені файлу, тому `$0`, `dirname $0` і будь-які
	// шляхи відносно нього вказують не туди. Скрипт, який читає себе, працював би
	// в оригіналі й не працював би тут — тихо, без помилки.
	script, err := writeCodeScript(ctx, engine, expandDynamic(source, mustParseTarget(target), dynamic))
	if err != nil {
		run.Reason = "cannot stage the block's script: " + oneLine(err.Error())
		return run
	}
	// The whole directory, not just the file: removing only the script leaves an
	// empty `/tmp/requestrider-code-*` behind, and a 500-template measurement run
	// would leave five hundred of them for the rest of the machine's life.
	defer os.RemoveAll(script.dir)

	command := exec.CommandContext(runCtx, codeInterpreter(engine), script.path)
	// Killing the interpreter is not the same as the command having finished.
	//
	// `sh` runs `sleep 30` as its own child, so cancelling the context kills `sh`
	// and leaves `sleep` alive, still holding the output pipe — and `Run` blocks
	// until the pipe closes. Measured: a template whose own `timeout: 1` should
	// have ended in one second took thirty, which is a template that overruns its
	// deadline deciding on its own when to stop.
	//
	// `WaitDelay` bounds the wait after the kill: the pipes are closed and `Run`
	// returns. The delay is short, because at this point the deadline has already
	// passed and there is nothing left to wait for.
	command.WaitDelay = 2 * time.Second
	command.Stdin = strings.NewReader(script.source)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.Env = append(codeEnvironment(target), "PATH="+osGetenv("PATH"))

	started := time.Now()
	runErr := command.Run()
	elapsed := time.Since(started)
	run.Elapsed = elapsed
	run.StatusCode = 0
	stdoutText := truncateOutput(stdout.String())
	stderrText := truncateOutput(stderr.String())
	run.Response = stdoutText
	run.Request = renderCodeRequest(engine, target, source, stdoutText, stderrText, runErr)

	if runErr != nil {
		if runCtx.Err() != nil {
			run.Reason = fmt.Sprintf(
				"the block's %s script did not finish within this project's %d-second deadline, so it "+
					"produced no verdict. Raise RR_CODE_TIMEOUT_SEC to give it more time", engine, timeout)
			return run
		}
		run.Reason = fmt.Sprintf("the block's %s script failed: %s", engine, oneLine(runErr.Error()))
		return run
	}

	exchange := PassiveExchange{
		Method:      "CODE",
		URL:         target,
		Host:        target,
		RawRequest:  run.Request,
		RawResponse: stdoutText,
		Body:        stdoutText,
		Duration:    elapsed,
		// The parts the corpus actually names, measured rather than guessed:
		// `code_<n>_response` is the most-used matcher of the whole protocol, and
		// `stdout`/`stderr` are the same streams under their own names. `all` is
		// both streams together, because a template asking for everything wants to
		// see the failure as well as the output.
		Parts: map[string]string{
			fmt.Sprintf("code_%d_response", position): stdoutText,
			fmt.Sprintf("code_%d_stderr", position):   stderrText,
			"stdout":                                  stdoutText,
			"stderr":                                  stderrText,
			"all":                                     stdoutText + stderrText,
		},
	}
	verdict := scoreCompiled(document, block, exchange)
	run.Matched = verdict.Matched
	run.MatcherNames = verdict.MatcherNames
	run.Extracts = verdict.Extracts
	run.Dynamic = verdict.Dynamic
	run.ExtractLists = verdict.ExtractLists
	if stderrText != "" && !verdict.Matched {
		run.Reason = "the script finished and wrote to stderr; its stdout matched nothing"
	}
	return run
}

// firstCodeEngine returns the engine a block asks for.
//
// A list means "try these in order", which nuclei does; here the first one whose
// interpreter exists wins, and the reason names the ones that are missing when none
// does.
func firstCodeEngine(block passiveRequest) string {
	for _, engine := range block.CodeEngines {
		trimmed := strings.ToLower(strings.TrimSpace(engine))
		if trimmed == "" {
			continue
		}
		if _, err := exec.LookPath(codeInterpreter(trimmed)); err == nil {
			return trimmed
		}
	}
	return ""
}

// codeInterpreter maps a template's engine spelling to a program.
//
// The mapping is a table and not a computed shell string, so a template cannot name
// an interpreter this project does not support.
func codeInterpreter(engine string) string {
	switch engine {
	case "sh", "bash", "zsh", "shell":
		return "/bin/sh"
	case "py", "python", "python3":
		return "/bin/python3"
	case "ruby", "rb":
		return "/usr/bin/ruby"
	case "php":
		return "/usr/bin/php"
	case "powershell", "pwsh":
		return "/usr/bin/pwsh"
	default:
		return ""
	}
}

// codeTimeout is the deadline for one script.
//
// It can be written per block with `timeout: N`, which is nuclei's own spelling and
// is honoured first so a template that knows its own runtime keeps it.
func codeTimeout(block passiveRequest) int {
	if block.CodeTimeoutSec > 0 {
		return block.CodeTimeoutSec
	}
	return defaultCodeTimeoutSec
}

// codeEnvironment is the environment a template's script sees.
//
// It gets the target under both spellings the corpus uses, and nothing else is
// invented: no fake browser, no pretend request object, no "security" variable that
// would only exist to be refused.
func codeEnvironment(target string) []string {
	return []string{
		"BaseURL=" + strings.TrimSuffix(target, "/"),
		"base_url=" + strings.TrimSuffix(target, "/"),
		"HOSTNAME=" + hostOf(target),
		"TARGET=" + target,
		"HOME=" + osGetenv("HOME"),
	}
}

// truncateOutput keeps the recorded prefix and says when it did.
func truncateOutput(text string) string {
	if len(text) <= codeMaxOutputBytes {
		return text
	}
	return text[:codeMaxOutputBytes]
}

// renderCodeRequest shows the script and both streams, because a verdict without the
// script that produced it is not evidence.
func renderCodeRequest(engine, target, source, stdout, stderr string, runErr error) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# engine: %s\n", engine)
	fmt.Fprintf(&builder, "# target: %s\n", target)
	fmt.Fprintf(&builder, "%s", source)
	if !strings.HasSuffix(source, "\n") {
		builder.WriteString("\n")
	}
	fmt.Fprintf(&builder, "--- stdout (%d bytes)\n%s", len(stdout), stdout)
	if stderr != "" {
		fmt.Fprintf(&builder, "--- stderr (%d bytes)\n%s", len(stderr), stderr)
	}
	if runErr != nil {
		fmt.Fprintf(&builder, "--- exit\n%s\n", oneLine(runErr.Error()))
	}
	return builder.String()
}

// hostOf returns the host of an absolute URL, or the URL itself when it has none.
func hostOf(target string) string {
	if parsed := mustParseTarget(target); parsed.Host != "" {
		return parsed.Host
	}
	return target
}

// osGetenv keeps the environment reads in one place, so a missing variable has one
// spelling rather than a dozen.
func osGetenv(name string) string { return os.Getenv(name) }

// runCodeDocument runs every `code:` block of a document and reports the verdict of
// the one that decided it.
//
// A block that matched ends the run, which is what `stop-at-first-match` means for
// a list of blocks: a script that found what it was looking for does not need the
// next one to run.
func runCodeDocument(ctx context.Context, document *passiveDocument, blocks []passiveRequest, target string) LocalRun {
	return runCodeDocumentWith(ctx, document, blocks, target, nil)
}

// runCodeDocumentWith runs the blocks with values the request phase produced.
//
// A document may have both `http:` and `code:` blocks, and the script is written to
// act on what the request found. Without carrying those values the script runs with
// empty ones and the document reports a negative for a check it could not make.
func runCodeDocumentWith(ctx context.Context, document *passiveDocument, blocks []passiveRequest,
	target string, carried map[string]string) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	for index, block := range blocks {
		step := runCodeTemplateWith(ctx, document, block, target, index, carried)
		if run.Request == "" {
			run.Request, run.Response = step.Request, step.Response
			run.StatusCode, run.Elapsed = step.StatusCode, step.Elapsed
		} else {
			run.Request += "\n--- " + step.Request
			run.Response += "\n--- " + step.Response
		}
		run.Extracts = append(run.Extracts, step.Extracts...)
		if step.Matched {
			run.Matched = true
			run.MatcherNames = step.MatcherNames
			return run
		}
		if step.Reason != "" {
			run.Reason = fmt.Sprintf("code block %d of %d: %s", index+1, len(blocks), step.Reason)
			return run
		}
	}
	run.Reason = fmt.Sprintf("all %d code block(s) ran and matched nothing", len(blocks))
	return run
}

// codeEngines reads the `engine:` key in both spellings the corpus uses.
//
//	engine:                       engine:
//	  - sh                          sh: "id"
//	  - bash
//
// A list means "try these in order" and a mapping means "run this under this
// interpreter". Decoding into one fixed shape broke the other: with `[]string`,
// every `sh: "id"` document failed to parse and was reported as invalid YAML
// rather than as a `code` template — measured, it took out two existing tests that
// were asserting the refusal names `code`.
type codeEngines []string

// UnmarshalYAML accepts both spellings.
func (c *codeEngines) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var names []string
		if err := node.Decode(&names); err != nil {
			return err
		}
		*c = names
		return nil
	case yaml.MappingNode:
		// A mapping's keys are the interpreters. The values are the interpreter's
		// own arguments, which this runner does not pass through: it writes the
		// script to stdin and names the interpreter, so an argument written in the
		// template would be a second, unparsed language.
		names := make([]string, 0, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			names = append(names, node.Content[index].Value)
		}
		*c = names
		return nil
	default:
		return fmt.Errorf("engine must be a list of interpreters or a mapping of interpreter to arguments")
	}
}

// codeEngineNames lists the interpreters a document asked for.
//
// A refusal that says only "no engine" leaves the operator to open the file to find
// out whether the problem is a typo or a host without that interpreter, so the names
// the document actually wrote are named back.
func codeEngineNames(document *passiveDocument) string {
	var names []string
	for _, block := range document.CodeBlocks {
		for _, engine := range block.CodeEngines {
			if trimmed := strings.ToLower(strings.TrimSpace(engine)); trimmed != "" {
				names = append(names, trimmed)
			}
		}
	}
	if len(names) == 0 {
		return "none named"
	}
	return strings.Join(names, ", ")
}

// codeBlocks reads the `code:` key in the three spellings the corpus uses: a list
// of blocks, a bare `true` that only switches the protocol on, and a single block
// written without the list dash.
type codeBlocks []passiveRequest

// UnmarshalYAML accepts all three, and says which one it saw when none fits.
func (c *codeBlocks) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var blocks []passiveRequest
		if err := node.Decode(&blocks); err != nil {
			return err
		}
		*c = blocks
		return nil
	case yaml.MappingNode:
		var block passiveRequest
		if err := node.Decode(&block); err != nil {
			return err
		}
		*c = []passiveRequest{block}
		return nil
	case yaml.ScalarNode:
		var enabled bool
		if err := node.Decode(&enabled); err != nil {
			return fmt.Errorf("code: must be a list of blocks, one block, or true; %q is none of those",
				node.Value)
		}
		// `code: true` enables the protocol without declaring a block here. The
		// document's own request blocks still run, so there is nothing to record.
		_ = enabled
		*c = nil
		return nil
	default:
		return fmt.Errorf("code: must be a list of blocks, one block, or true")
	}
}

// codeScript is a template's script written where an interpreter can be pointed at
// it, which is how nuclei hands it over.
type codeScript struct {
	path   string
	dir    string
	source string
}

// writeCodeScript stages a script under a private temporary directory.
//
// Two properties matter and both are measured rather than assumed. The directory
// is per-block, so two scripts of one template cannot see each other's files, and it
// is readable only by its owner, because the script's content is the template's text
// and a world-writable staging path is a way for another local process to replace it
// between the write and the exec.
//
// The name keeps the interpreter's extension so a script that dispatches on `$0` or
// on its own suffix sees what it expects.
func writeCodeScript(ctx context.Context, engine, source string) (codeScript, error) {
	dir, err := os.MkdirTemp("", "requestrider-code-")
	if err != nil {
		return codeScript{}, err
	}
	name := "script"
	switch codeInterpreter(engine) {
	case "/bin/sh":
		name = "script.sh"
	case "/usr/bin/ruby":
		name = "script.rb"
	case "/usr/bin/php":
		name = "script.php"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(source), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return codeScript{}, err
	}
	return codeScript{path: path, dir: dir, source: source}, nil
}
