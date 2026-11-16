package scanner

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `file:` — 447 шаблонів корпусу, і **всі 447** оголошують лише `extensions:`.
// Тому два випадки треба перевірити окремо: оператор дав локальний шлях — шаблон
// виконується; дав URL — відмова на ім'я, бо предмета немає.

// fileTree writes a small directory with one file per extension and returns it.
func fileTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "risky.py"), "import os\nFINDME os.system('id')\n")
	mustWrite(t, filepath.Join(root, "notes.txt"), "nothing of interest here\n")
	mustWrite(t, filepath.Join(root, "nested", "deeper.py"), "x = 1\n")
	return root
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("cannot create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
}

const fileTemplate = `
id: file-python-injection
info:
  name: python file calling os.system
  severity: medium
file:
  - extensions:
      - py
    matchers:
      - type: regex
        part: body
        regex:
          - "FINDME"
`

// Мутація: прибрати читання файлів.
func TestAFileBlockReadsTheLocalFilesItNames(t *testing.T) {
	root := fileTree(t)
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), fileTemplate, root, transport)

	if run.Reason == "" && !run.Matched {
		t.Fatalf("a file whose content matched reported neither a match nor a reason: %q", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("a `file:` block reading a real .py file did not match its regex: %q", run.Reason)
	}
	if transport.count() != 0 {
		t.Fatalf("a `file:` block sent %d HTTP request(s); it reads the local filesystem", transport.count())
	}
	if !strings.Contains(run.Response, "risky.py") {
		t.Fatalf("the match names no file: %q", run.Response)
	}
}

// Мутація: не читати вкладені каталоги.
func TestAFileBlockWalksNestedDirectories(t *testing.T) {
	root := fileTree(t)
	document := strings.Replace(fileTemplate, `"FINDME"`, `"x = 1"`, 1)
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, root, transport)

	if !run.Matched {
		t.Fatalf("the only matching file is in a nested directory and was not reached: %q", run.Reason)
	}
	if !strings.Contains(run.Response, filepath.Join("nested", "deeper.py")) {
		t.Fatalf("the nested file was not read: %q", run.Response)
	}
}

// Розширення фільтрує: `.txt` не читається, коли блок просить `py`.
func TestOnlyTheExtensionsTheBlockNamesAreRead(t *testing.T) {
	root := fileTree(t)
	document := strings.Replace(fileTemplate, `"FINDME"`, `"nothing of interest"`, 1)
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, root, transport)

	if run.Matched {
		t.Fatalf("a block naming `py` matched on a .txt file: %q", run.Response)
	}
	if !strings.Contains(run.Reason, "none matched") {
		t.Fatalf("a block that read files and matched nothing did not say so: %q", run.Reason)
	}
}

// Найважливіше: без локального шляху немає предмета, і це **відмова**, а не
// негативний результат.
//
// Раніше в проекті вже було рішення не читати локальну систему рушія: рушій живе
// на машині сканера, і його власні файли не є нічим для цілі оператора.
func TestAFileTemplateAgainstAURLIsRefusedByName(t *testing.T) {
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), fileTemplate, "https://example.org/", transport)

	if run.Matched {
		t.Fatal("a `file:` template reported a finding against a URL target")
	}
	if !strings.Contains(run.Reason, "local files") || !strings.Contains(run.Reason, "https://example.org/") {
		t.Fatalf("the refusal does not name both halves — the template's subject and the target: %q", run.Reason)
	}
	if !run.Skipped {
		t.Fatalf("a template with no subject was reported as a check that ran: %+v", run)
	}
	if transport.count() != 0 {
		t.Fatalf("a refused `file:` template still sent %d request(s)", transport.count())
	}
}

// Блок без `extensions:` — немає чого шукати, і це не відмова з приводу браку
// доступу, а відмова з приводу браку предмета.
func TestAFileBlockWithoutExtensionsIsNamed(t *testing.T) {
	root := fileTree(t)
	document := `
id: file-no-extensions
info:
  name: a file block that names no type
  severity: info
file:
  - matchers:
      - type: word
        part: body
        words:
          - anything
`
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, root, transport)

	if !strings.Contains(run.Reason, "extensions") {
		t.Fatalf("the missing extension list was not named: %q", run.Reason)
	}
}

// Право оператора: межа числа файлів перекривається змінною, і без неї блок
// повідомляє, що зупинився на ній, а не мовчить.
func TestTheFileLimitIsVisibleAndRaisable(t *testing.T) {
	root := fileTree(t)
	t.Setenv("RR_FILE_MAX_FILES", "1")
	document := strings.Replace(fileTemplate, `"FINDME"`, `"x = 1"`, 1)
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, root, transport)

	if !strings.Contains(run.SkippedNote, "RR_FILE_MAX_FILES") {
		t.Fatalf("the file limit was reached without saying so: note=%q reason=%q", run.SkippedNote, run.Reason)
	}
}
