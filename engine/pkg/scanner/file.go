package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// `file:` — 447 шаблонів офіційного корпусу, третій за величиною протокол.
//
// Виміряно на корпусі: **усі 447** оголошують лише `extensions:` і жодного не
// називає шляху. Тобто предметом такого шаблону є «кожен локальний файл цього
// розширення», і nuclei вирішує його через `-target`, який у нього є шляхом.
//
// У цьому проєкті ціль — URL. Тому два випадки, і обидва чесні:
//
//   - оператор вказав локальний шлях — шаблон виконується проти нього;
//   - оператор вказав URL — шаблон **відмовляється на ім'я**, і це не суворість,
//     а відсутність предмета.
//
// Чому не «прочитати локальну систему рушія»: движок живе на машині, де працює
// сам сканер, і його `/usr/lib/python3` не є нічим для цілі оператора. Знахідка
// «є файл із `subprocess`» була б твердженням про нашу машину, надрукованим у
// звіт про його ціль.

// fileScanMaxBytes bounds how much of one file is read.
//
// It is a memory bound and not a capability bound: the reason says when the file
// was longer, so the operator sees that the match was decided on a prefix rather
// than being told the file matched nothing.
const fileScanMaxBytes = 4 << 20

// fileScanMaxFiles bounds how many files one block reads.
//
// Also a memory bound, and it is visible: the run reports the number of files read
// and says the cap was reached. Without a bound a `file:` block listing `py` walks
// an entire filesystem and the job never finishes — which is exactly the hang this
// project's technical limits exist to prevent. The operator raises it with
// `RR_FILE_MAX_FILES`, so the ceiling is a value, not a refusal.
var fileScanMaxFiles = func() int { return 2000 }

// runFileDocument reads the local files a document's `file:` blocks name and
// scores each against that block's operators.
func runFileDocument(ctx context.Context, document *passiveDocument, blocks []passiveRequest, target string) LocalRun {
	run := LocalRun{
		TemplateID: strings.TrimSpace(document.ID),
		Name:       strings.TrimSpace(document.Info.Name),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	root, err := fileRoot(target)
	if err != "" {
		run.Skipped = true
		run.Reason = err
		return run
	}
	limit := fileScanMaxFiles()
	if override := optionalPositiveInt("RR_FILE_MAX_FILES"); override > 0 {
		limit = override
	}
	read := 0
	truncated := false
	for index, block := range blocks {
		extensions := fileExtensions(block)
		if len(extensions) == 0 {
			run.Skipped = true
			run.Reason = fmt.Sprintf(
				"file block %d of %d names no `extensions:`, so there is nothing to look for; this runner "+
					"does not guess which files a template meant", index+1, len(blocks))
			return run
		}
		matchedFiles := 0
		walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if entry.IsDir() {
				if path != root && strings.HasPrefix(entry.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !hasAnyExtension(path, extensions) {
				return nil
			}
			if read >= limit {
				truncated = true
				return filepath.SkipAll
			}
			content, size, readErr := readCapped(path)
			if readErr != nil {
				return nil
			}
			read++
			verdict := scoreFileBlock(document, block, path, content)
			run.Extracts = append(run.Extracts, verdict.Extracts...)
			for name, values := range verdict.ExtractLists {
				run.ExtractLists[name] = append(run.ExtractLists[name], values...)
			}
			if !verdict.Matched {
				return nil
			}
			matchedFiles++
			run.Matched = true
			if len(run.MatcherNames) == 0 {
				run.MatcherNames = verdict.MatcherNames
			}
			run.Response += fmt.Sprintf("--- %s (%d bytes)\n%s", path, size, content)
			return nil
		})
		if walkErr != nil && ctx.Err() != nil {
			run.Skipped = true
			run.Reason = "the file walk was cancelled: " + oneLine(ctx.Err().Error())
			return run
		}
		if truncated {
			// Set before the early return below, because a block that stopped at
			// the limit and matched nothing has both facts to report — and the
			// limit is the one that explains why it read so little.
			run.SkippedNote = fmt.Sprintf(
				"read %d file(s) and stopped at this project's file limit; raise RR_FILE_MAX_FILES to read more",
				limit)
		}
		if matchedFiles == 0 {
			run.Skipped = true
			run.Reason = fmt.Sprintf("file block %d of %d read %d file(s) of type %s and none matched",
				index+1, len(blocks), read, strings.Join(extensions, ", "))
			return run
		}
	}
	run.Reason = fmt.Sprintf("read %d local file(s) under %s", read, root)
	return run
}

// fileRoot returns the directory a `file:` block reads, or the reason there is
// none.
//
// The refusal names both halves: the template checks local files, and the run's
// target is a URL. A reader who does not know that would otherwise see a `file:`
// template simply "not matched", which is a claim about a check that never ran.
func fileRoot(target string) (string, string) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", "the run names no target, and this template checks local files, so there is no subject to read"
	}
	if strings.Contains(trimmed, "://") {
		return "", fmt.Sprintf(
			"this template checks local files with the extensions it lists, and the run's target is the URL %s; "+
				"point the scan at a directory to check files", trimmed)
	}
	info, err := os.Stat(trimmed)
	if err != nil {
		return "", fmt.Sprintf("the run's target %s cannot be read: %s", trimmed, oneLine(err.Error()))
	}
	if !info.IsDir() {
		return filepath.Dir(trimmed), ""
	}
	return trimmed, ""
}

// fileExtensions reads the `extensions:` list of a `file:` block.
func fileExtensions(block passiveRequest) []string {
	var out []string
	for _, extension := range block.FileExtensions {
		normalized := strings.ToLower(strings.TrimSpace(extension))
		if normalized == "" {
			continue
		}
		if !strings.HasPrefix(normalized, ".") {
			normalized = "." + normalized
		}
		out = append(out, normalized)
	}
	return out
}

func hasAnyExtension(path string, extensions []string) bool {
	lowered := strings.ToLower(filepath.Base(path))
	for _, extension := range extensions {
		if strings.HasSuffix(lowered, extension) {
			return true
		}
	}
	return false
}

// readCapped reads a file's prefix and reports its real size, so a truncated read
// is visible rather than looking like the whole file.
func readCapped(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	buffer := make([]byte, fileScanMaxBytes)
	read, err := file.Read(buffer)
	if err != nil && read == 0 {
		return "", info.Size(), err
	}
	return string(buffer[:read]), info.Size(), nil
}

// scoreFileBlock judges one file's content against the block's operators.
//
// The content becomes the exchange's body, which is the same judge a request
// answer goes through — so a `word`, `regex`, `dsl` or `status` matcher means the
// same thing here as it does on the wire, and there is no second evaluator to
// drift from the first.
func scoreFileBlock(document *passiveDocument, block passiveRequest, path, content string) PassiveMatch {
	exchange := PassiveExchange{
		Method:      "FILE",
		URL:         path,
		Host:        path,
		RawRequest:  "FILE " + path,
		RawResponse: content,
		Body:        content,
		StatusCode:  200,
		Duration:    time.Duration(0),
	}
	return scoreCompiled(document, block, exchange)
}
