package scanner

import "testing"

// Javascript-шаблон із socket-рушієм і декартовим добутком payload не повертається
// вчасно — і тоді сусіди по батчу втрачають свої вердикти.
//
// Виміряно на v3.11.1: `javascript/misconfiguration/smb/smb-shares.yaml` має
// `attack: clusterbomb` (4 імена × 6 паролів), `threads: 1`, і кожна ітерація —
// це `ListShares` на порт 445. На хості, де 445 закритий, бінарник відповів
//
//	[WRN] js runtime did not terminate after interrupt; abandoning it to avoid
//	      concurrent use: nuclei js runtime: program failed to terminate after
//	      interrupt: context deadline exceeded
//
// і в батчі з дев'яти файлів тримав виклик 21 хвилину з порожнім звітом. Наодинці
// він завершувався за 100 с і не писав нічого — те саме з іншого боку.

const blockingJavascript = `id: smb-shares-blocking
info:
  name: SMB shares
  author: tester
  severity: info
javascript:
  - pre-condition: |
      isPortOpen(Host, Port);
    code: |
      var smb = require("nuclei/smb");
      var client = smb.SMBClient();
      var shares = client.ListShares(Host, Port, User, Pass);
      Export(shares || []);
    args:
      Host: "{{Host}}"
      Port: "445"
      User: "{{username}}"
      Pass: "{{password}}"
    attack: clusterbomb
    threads: 1
    stop-at-first-match: true
    payloads:
      username:
        - ""
        - administrator
        - guest
      password:
        - ""
        - administrator
        - password
    matchers:
      - type: dsl
        dsl:
          - success == true
`

// The document is read, not guessed: a plain javascript check that opens one
// socket and returns is an ordinary template, and taking it away from its batch
// would cost an invocation for nothing.
func TestJavascriptBlockingIsReadFromTheDocument(t *testing.T) {
	blocking, reason := parseTemplateDocument(blockingJavascript)
	if reason != "" {
		t.Fatalf("parse blocking: %s", reason)
	}
	if !blocking.javascriptNeedsItsOwnProcess() {
		t.Fatal("clusterbomb over a socket engine must be recognised")
	}

	// Same engine, one combination: `attack: single` is the default spelled out,
	// and it multiplies nothing.
	single := `id: single-iteration
info:
  name: single iteration
  author: tester
  severity: info
javascript:
  - code: |
      var smb = require("nuclei/smb");
      Export(smb.SMBClient().ListShares(Host, Port, User, Pass) || []);
    attack: single
    args:
      Host: "{{Host}}"
      Port: "445"
`
	plain, reason := parseTemplateDocument(single)
	if reason != "" {
		t.Fatalf("parse single: %s", reason)
	}
	if plain.javascriptNeedsItsOwnProcess() {
		t.Fatal("one iteration over one socket must stay in its batch")
	}

	// The cartesian product without a socket engine is arithmetic, not a socket
	// wait: `nuclei/http` returns on its own.
	httpEngine := `id: cartesian-http
info:
  name: cartesian http
  author: tester
  severity: info
javascript:
  - code: |
      var http = require("nuclei/http");
      Export(http.get(Host));
    attack: clusterbomb
    payloads:
      username:
        - a
        - b
`
	cheap, reason := parseTemplateDocument(httpEngine)
	if reason != "" {
		t.Fatalf("parse cartesian: %s", reason)
	}
	if cheap.javascriptNeedsItsOwnProcess() {
		t.Fatal("nuclei/http is not a socket engine that blocks")
	}
}

// A `code` document must not be recognised as this one: the two classes are read
// from different blocks and a `code` template has no `javascript:` body at all.
func TestTheJavascriptRuleDoesNotReachCodeDocuments(t *testing.T) {
	meta, reason := parseTemplateDocument(`id: plain-code
info:
  name: plain code
  author: tester
  severity: info
code:
  - engine:
      - sh
    source: echo hi
    matchers:
      - type: word
        words:
          - hi
`)
	if reason != "" {
		t.Fatalf("parse: %s", reason)
	}
	if meta.javascriptNeedsItsOwnProcess() {
		t.Fatal("a code document must not be read through the javascript rule")
	}
}

// The promise is about the batch, and this is the class it protects: a blocking
// javascript document must not be a neighbour of anything.
func TestABlockingJavascriptTemplateNeverSharesABatch(t *testing.T) {
	meta, reason := parseTemplateDocument(blockingJavascript)
	if reason != "" {
		t.Fatalf("parse: %s", reason)
	}
	blocking := StagedFile{UploadName: "smb-shares.yaml", Meta: meta}

	groups := groupByCapability([]StagedFile{blocking, httpDocument(t, "web")})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2: the blocking javascript document must stand alone", len(groups))
	}
	for key, files := range groups {
		if len(files) > 1 {
			t.Fatalf("group %q holds %d files", key, len(files))
		}
	}
}
