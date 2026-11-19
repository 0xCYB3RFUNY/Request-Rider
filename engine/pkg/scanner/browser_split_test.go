package scanner

import (
	"slices"
	"testing"
)

// Браузер — це один процес на весь виклик, і nuclei тримає його до останнього
// шаблону.
//
// Виміряно на v3.11.1 на цій машині: Chromium відкриває DevTools, а сеанс не
// завершується. Тому шаблон, якому браузер не потрібен, чекає на браузер
// сусіда:
//
//	nuclei -t . -w . -it . -ms -or -timeout 5   -> жодного запису за 240 с
//	той самий файл без -headless                 -> 1 запис за 17 с
//
// Дев'ять шаблонів обліку корпусу потрапили саме так: п'ять `javascript`,
// чотири `http`, і жоден з них не має блоку `headless:`.

func httpDocument(t *testing.T, id string) StagedFile {
	t.Helper()
	body := "id: " + id + "\ninfo:\n  name: " + id + "\n  author: tester\n  severity: info\n" +
		"http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n" +
		"      - type: status\n        status: [200]\n"
	meta, reason := parseTemplateDocument(body)
	if reason != "" {
		t.Fatalf("parse %s: %s", id, reason)
	}
	return StagedFile{UploadName: id + ".yaml", Meta: meta}
}

func headlessDocument(t *testing.T, id string) StagedFile {
	t.Helper()
	body := "id: " + id + "\ninfo:\n  name: " + id + "\n  author: tester\n  severity: info\n" +
		"headless:\n  - steps:\n      - action: navigate\n        args:\n          url: \"{{BaseURL}}/\"\n"
	meta, reason := parseTemplateDocument(body)
	if reason != "" {
		t.Fatalf("parse %s: %s", id, reason)
	}
	if !slices.Contains(meta.Capabilities, CapabilityHeadless) {
		t.Fatalf("%s does not ask for the browser: %v", id, meta.Capabilities)
	}
	return StagedFile{UploadName: id + ".yaml", Meta: meta}
}

// The promise is about batches, and the batch is identified by its flags: a group
// that reports `drivesBrowser` receives `-headless`, and `-headless` is the thing
// that never finishes here.
func TestAnHttpTemplateNeverSharesABatchWithABrowserTemplate(t *testing.T) {
	web := httpDocument(t, "plain-http")
	browser := headlessDocument(t, "needs-a-browser")

	groups := groupByCapability([]StagedFile{web, browser})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2: the browser must not ride along with an HTTP template", len(groups))
	}
	for key, files := range groups {
		if key.isolated() {
			continue
		}
		batch := NucleiBatch{Key: key, Capabilities: key.parseCapabilities()}
		if batch.drivesBrowser() && len(files) > 1 {
			t.Fatalf("a batch carrying -headless holds %d documents", len(files))
		}
		for _, file := range files {
			if file.Meta != nil && file.Meta.BlocksWithoutDeadline() {
				t.Fatal("a blocking document is in a batch with others")
			}
			if batch.drivesBrowser() && !slices.Contains(file.Meta.Capabilities, CapabilityHeadless) {
				t.Fatalf("%s is made to wait for a browser it never asked for", file.UploadName)
			}
		}
	}
}

// The split must not invent a browser for the plain side: if the key carried
// `-headless` after being cleaned, the whole batch would hang again.
func TestThePlainBatchGetsNoBrowserFlag(t *testing.T) {
	groups := groupByCapability([]StagedFile{httpDocument(t, "only-http")})
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	for key, files := range groups {
		if len(files) != 1 {
			t.Fatalf("a lone HTTP template was split: %d files", len(files))
		}
		if (NucleiBatch{Capabilities: key.parseCapabilities()}).drivesBrowser() {
			t.Fatalf("a plain HTTP batch carries -headless: %q", key)
		}
	}
}

// Two headless templates may still share: they need the same browser anyway, and
// the batch already has its own short deadline.
func TestTwoBrowserTemplatesStillShareOneBatch(t *testing.T) {
	groups := groupByCapability([]StagedFile{
		headlessDocument(t, "browser-one"),
		headlessDocument(t, "browser-two"),
	})
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1: two templates needing the same browser need two batches", len(groups))
	}
	for key := range groups {
		if !(NucleiBatch{Capabilities: key.parseCapabilities()}).drivesBrowser() {
			t.Fatalf("a batch of headless documents does not carry -headless: %q", key)
		}
	}
}

// The other capabilities are untouched by the split. A `code` template still
// gets `-code`, and `-code` is not what hangs.
func TestTheSplitLeavesOtherCapabilitiesAlone(t *testing.T) {
	body := "id: needs-code\ninfo:\n  name: needs code\n  author: tester\n  severity: info\n" +
		"code:\n  - engine:\n      - sh\n    source: echo hi\n    matchers:\n      - type: word\n        words:\n          - hi\n"
	meta, reason := parseTemplateDocument(body)
	if reason != "" {
		t.Fatalf("parse: %s", reason)
	}
	groups := groupByCapability([]StagedFile{
		{UploadName: "code.yaml", Meta: meta},
		httpDocument(t, "web"),
	})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	for key := range groups {
		if (NucleiBatch{Capabilities: key.parseCapabilities()}).drivesBrowser() {
			t.Fatalf("a non-browser batch grew -headless: %q", key)
		}
	}
}
