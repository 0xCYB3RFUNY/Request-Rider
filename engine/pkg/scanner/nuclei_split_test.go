package scanner

// The split is what makes one scan cover the whole corpus: the binary takes the
// files it can execute, the local runner takes the flows it cannot, and the
// operator presses one button. These tests hold the boundary, because a file on
// the wrong side is either a refused run or a flow reported as a plain template.

import "testing"

const plainDoc = `id: plain
info:
  name: Plain
  author: t
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

const flowDoc = `id: flowy
info:
  name: Flowy
  author: t
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
    matchers:
      - type: word
        words:
          - "a"
  - method: GET
    path:
      - "{{BaseURL}}/b"
    matchers:
      - type: word
        words:
          - "b"
`

func TestSplitFlowTemplatesSendsFlowsToTheLocalRunner(t *testing.T) {
	flowMeta, reason := parseTemplateDocument(flowDoc)
	if reason != "" {
		t.Fatalf("flow document refused at parse time: %s", reason)
	}
	plainMeta, reason := parseTemplateDocument(plainDoc)
	if reason != "" {
		t.Fatalf("plain document refused at parse time: %s", reason)
	}
	staged := []StagedFile{
		{UploadName: "plain.yaml", Meta: plainMeta},
		{UploadName: "flowy.yaml", Meta: flowMeta},
	}

	flow, ordinary := SplitFlowTemplates(staged)
	if len(flow) != 1 || flow[0].UploadName != "flowy.yaml" {
		t.Errorf("flow half = %v, want only flowy.yaml", names(flow))
	}
	if len(ordinary) != 1 || ordinary[0].UploadName != "plain.yaml" {
		t.Errorf("ordinary half = %v, want only plain.yaml", names(ordinary))
	}
}

// A file that failed to parse has no meta, so it cannot be known to be a flow.
// It belongs to the binary, which is the path that names the parse failure.
func TestSplitFlowTemplatesKeepsUnparsedFilesOnTheBinaryPath(t *testing.T) {
	staged := []StagedFile{
		{UploadName: "broken.yaml", Meta: nil, Reason: "invalid YAML"},
	}
	flow, ordinary := SplitFlowTemplates(staged)
	if len(flow) != 0 {
		t.Errorf("a file with no meta was sent to the local runner: %v", names(flow))
	}
	if len(ordinary) != 1 {
		t.Errorf("ordinary half = %v, want the unparsed file kept for the binary", names(ordinary))
	}
}

func TestStagedFromUploadsKeepsEveryFileItWasGiven(t *testing.T) {
	staged, contents := StagedFromUploads([]UploadInput{
		{Name: "plain.yaml", Path: "http/plain.yaml", Content: plainDoc},
		{Name: "flowy.yaml", Path: "http/flowy.yaml", Content: flowDoc},
		{Name: "broken.yaml", Path: "http/broken.yaml", Content: "id: [unclosed\n"},
	})
	if len(staged) != 3 || len(contents) != 3 {
		t.Fatalf("got %d files and %d bodies, want 3 and 3", len(staged), len(contents))
	}
	for index := range staged {
		if contents[index] == "" {
			t.Errorf("file %d has no body, so the pair by index is broken", index)
		}
	}
	if staged[0].Meta == nil || !staged[0].Meta.IsFlow() && staged[0].Meta.TemplateID != "plain" {
		t.Errorf("first file was not parsed: %+v", staged[0].Meta)
	}
	if staged[1].Meta == nil || !staged[1].Meta.IsFlow() {
		t.Error("second file lost its flow identity")
	}
	if staged[2].Reason == "" {
		t.Error("the unparseable file lost its reason, so the report would show it as fine")
	}
}

func names(files []StagedFile) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.UploadName)
	}
	return out
}
