package scanner

import "testing"

// Один шаблон без дедлайну не має права визначати час усіх інших у батчі.
//
// nuclei виконує всі шаблони виклику в одному процесі, і `code`-шаблон, чий
// скрипт читає з сокета без `settimeout`, чекає на співрозмовника, який не
// відповість. Виміряно на v3.11.1: `code/cves/2016/CVE-2016-8735` має чотири
// виклики `recv(4096)` і жодного `settimeout`, і тримав батч із чотирьох файлів
// 30 хвилин з порожнім звітом — три сусіди втратили свої вердикти через нього.

const blockingTemplate = `id: blocking-read
info:
  name: reads without a deadline
  author: tester
  severity: info
code:
  - engine:
      - py
      - python3
    source: |
      import socket
      s = socket.socket()
      s.connect(("HOST", PORT))
      s.recv(4096)
`

const boundedTemplate = `id: bounded-read
info:
  name: reads with a deadline
  author: tester
  severity: info
code:
  - engine:
      - py
      - python3
    source: |
      import socket
      s = socket.socket()
      s.settimeout(5)
      s.connect(("HOST", PORT))
      s.recv(4096)
`

func blockingStaged(t *testing.T, name, body string) StagedFile {
	t.Helper()
	meta, reason := parseTemplateDocument(body)
	if reason != "" {
		t.Fatalf("parse %s: %s", name, reason)
	}
	return StagedFile{UploadName: name, Meta: meta}
}

// The second shape of the same problem: a local-check template that opens a
// full-screen program. `code/privilege-escalation/linux/binary/privesc-vim.yaml`
// runs `vim -c '!whoami'` and, with no `-e`, vim takes the screen and waits for a
// keypress that never comes. Measured: one such file held a 114-file batch for
// twenty-five minutes with an empty report.
func TestInteractiveTerminalIsRecognisedAsBlocking(t *testing.T) {
	interactive := `id: privesc-vim
info:
  name: Vim
  author: tester
  severity: info
self-contained: true
code:
  - engine:
      - sh
      - bash
    source: |
      whoami
  - engine:
      - sh
      - bash
    source: |
      vim -c '!whoami'
`
	bounded := `id: bounded-vim
info:
  name: Vim without a screen
  author: tester
  severity: info
self-contained: true
code:
  - engine:
      - sh
      - bash
    source: |
      vim -es -c '!whoami'
`
	first, reason := parseTemplateDocument(interactive)
	if reason != "" {
		t.Fatalf("parse interactive: %s", reason)
	}
	if !first.BlocksWithoutDeadline() {
		t.Fatal("vim -c '!whoami' opens the screen and must be read as blocking")
	}

	second, reason := parseTemplateDocument(bounded)
	if reason != "" {
		t.Fatalf("parse bounded: %s", reason)
	}
	if second.BlocksWithoutDeadline() {
		t.Fatal("vim -es is non-interactive and must not be taken away from its batch")
	}
}

// The list of programs is the whole point, and the corpus says why. The first
// version named `vim` alone and the very next batch was held by
// `view -c ':!whoami'` — the same editor under a different name, 25 minutes lost
// to it. All three spellings the corpus actually uses must be recognised.
func TestEveryEditorSpellingTheCorpusUsesIsRecognised(t *testing.T) {
	for _, command := range []string{
		"vim -c '!whoami'",
		"view -c ':!whoami'",
		"vi -c '!whoami'",
	} {
		document := "id: privesc-editor\ninfo:\n  name: Editor\n  author: t\n  severity: info\n" +
			"code:\n  - engine:\n      - sh\n    source: |\n      whoami\n  - engine:\n" +
			"      - sh\n    source: |\n      " + command + "\n"
		meta, reason := parseTemplateDocument(document)
		if reason != "" {
			t.Fatalf("parse %q: %s", command, reason)
		}
		if !meta.BlocksWithoutDeadline() {
			t.Fatalf("%q opens a full-screen editor and must be read as blocking", command)
		}
	}
}

// A name that merely contains a program name is not that program: `viewmodel`
// and `vimium` are ordinary binaries that return.
func TestASubstringOfAProgramNameIsNotTheProgram(t *testing.T) {
	document := `id: not-an-editor
info:
  name: Not an editor
  author: t
  severity: info
code:
  - engine:
      - sh
    source: |
      viewmodel --version
`
	meta, reason := parseTemplateDocument(document)
	if reason != "" {
		t.Fatalf("parse: %s", reason)
	}
	if meta.BlocksWithoutDeadline() {
		t.Fatal("viewmodel is not view")
	}
}

// The document is read, not guessed: the same `recv(` with a `settimeout` beside
// it is not a blocking read, and calling it one would take a working template
// out of its batch for no reason.
func TestBlocksWithoutDeadlineReadsTheDocumentsOwnScript(t *testing.T) {
	blocking, _ := parseTemplateDocument(blockingTemplate)
	if !blocking.BlocksWithoutDeadline() {
		t.Fatal("a recv() with no deadline anywhere must be recognised")
	}

	bounded, _ := parseTemplateDocument(boundedTemplate)
	if bounded.BlocksWithoutDeadline() {
		t.Fatal("a settimeout beside the same recv() must not be read as blocking")
	}

	// Not a `code` document at all: an HTTP template has no script to block on.
	web, reason := parseTemplateDocument(`id: web
info:
  name: web
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
`)
	if reason != "" {
		t.Fatalf("parse web: %s", reason)
	}
	if web.BlocksWithoutDeadline() {
		t.Fatal("an http template has no code block to block on")
	}
}

// The promise is about the batch, not about the document: a blocking file must
// not be a neighbour of anything, because that is the only way its deadline can
// be its own.
func TestBlockingTemplateNeverSharesABatchWithAnother(t *testing.T) {
	bounded := blockingStaged(t, "bounded.yaml", boundedTemplate)
	blocking := blockingStaged(t, "blocking.yaml", blockingTemplate)
	other := blockingStaged(t, "http.yaml", `id: plain-http
info:
  name: plain http
  author: tester
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
`)

	groups := groupByCapability([]StagedFile{bounded, blocking, other})

	for key, files := range groups {
		if len(files) < 2 {
			continue
		}
		for _, file := range files {
			if file.Meta != nil && file.Meta.BlocksWithoutDeadline() {
				t.Fatalf("a blocking document shares the batch %v with %d other file(s)", key, len(files)-1)
			}
		}
	}
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want one per document: the blocking one must stand alone", len(groups))
	}
}

// Two blocking documents may share neither: each holds the process on its own, so
// the second one waits for the first to return before its own deadline starts.
func TestTwoBlockingTemplatesDoNotShareABatch(t *testing.T) {
	first := blockingStaged(t, "blocking-a.yaml", blockingTemplate)
	secondBody := replaceFirstID(blockingTemplate, "blocking-read-2")
	second := blockingStaged(t, "blocking-b.yaml", secondBody)

	groups := groupByCapability([]StagedFile{first, second})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2: each blocking document needs its own process", len(groups))
	}
}

// The deadline that applies is the one for the batch, and it is smaller than the
// run's own. A one-document batch is exactly the case where the run's hour-long
// budget would become a single template's personal one.
func TestBatchTimeoutIsTheTighterOneForAnIsolatedBatch(t *testing.T) {
	run := NucleiBatch{}

	if got, want := batchTimeoutSec(run), nucleiTimeoutSec(); got != want {
		t.Fatalf("a shared batch deadline = %d, want the run's own %d", got, want)
	}
	// The key a blocking document actually gets, not a hand-written one: the
	// deadline follows from the plan, so a plan that produced an unrecognised
	// key would silently hand the document the run's own hour.
	blocking := blockingStaged(t, "blocking.yaml", blockingTemplate)
	var key capabilityKey
	for groupKey, files := range groupByCapability([]StagedFile{blocking}) {
		if len(files) == 1 {
			key = groupKey
		}
	}
	if key == "" {
		t.Fatal("a blocking document did not get a group of its own")
	}
	isolated := NucleiBatch{Key: key}
	if !key.isolated() {
		t.Fatalf("the key %q a blocking document got is not recognised as isolated", key)
	}
	if got := batchTimeoutSec(isolated); got >= nucleiTimeoutSec() {
		t.Fatalf("isolated batch deadline = %d, want less than the run's own %d", got, nucleiTimeoutSec())
	}
}

// A batch of `headless` documents gets the short deadline too, and the reason is
// the opposite of the previous one: there the file itself would not return, here
// the browser is a local resource whose coming up is a fact about the machine.
// Measured on v3.11.1: Chromium opened its DevTools endpoint and the invocation
// then waited for a session that never finished — 27 headless files held their
// batch for 28 minutes with an empty report.
func TestBrowserBatchGetsTheShortDeadline(t *testing.T) {
	browser := NucleiBatch{Capabilities: []Capability{CapabilityHeadless}}
	web := NucleiBatch{Capabilities: []Capability{CapabilityCode}}

	if !browser.drivesBrowser() {
		t.Fatal("a headless batch must be recognised as driving the browser")
	}
	if web.drivesBrowser() {
		t.Fatal("an http batch does not drive a browser")
	}
	if got := batchTimeoutSec(browser); got >= nucleiTimeoutSec() {
		t.Fatalf("browser batch deadline = %d, want less than the run's own %d", got, nucleiTimeoutSec())
	}
	if got, want := batchTimeoutSec(web), nucleiTimeoutSec(); got != want {
		t.Fatalf("http batch deadline = %d, want the run's own %d", got, want)
	}
}

// The bound is a deadline and not a skip: on a machine where the browser comes
// up, these templates are real checks, and the override stays available.
func TestTheBrowserDeadlineIsOverridableWithoutAnUpperCeiling(t *testing.T) {
	browser := NucleiBatch{Capabilities: []Capability{CapabilityHeadless}}
	t.Setenv("RR_NUCLEI_ISOLATED_TIMEOUT_SEC", "9000")
	if got := batchTimeoutSec(browser); got != 9000 {
		t.Fatalf("override ignored: deadline = %d, want 9000", got)
	}
}

func replaceFirstID(body, id string) string {
	out := "id: " + id
	return out + body[len("id: blocking-read"):]
}
