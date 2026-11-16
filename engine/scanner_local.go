package main

// The local runner, reachable.
//
// The binary path and this one are not two buttons: the plan hands every
// `flow:` template to the local runner and everything else to the binary, so the
// operator presses one button and the engine decides per file. The report keeps
// both kinds of row because the evidence behind them differs — a binary row
// carries nuclei's own verdict, a runner row carries the exchange this engine
// sent and scored itself — and a report that mixed them silently would be
// indistinguishable from a report where one engine did everything.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"intruder/engine/pkg/scanner"
)

// scannerLocalRequest runs templates through the project's own runner.
//
// The templates are given inline rather than as an upload id so that one scan
// can split its staged set: the binary takes the files it can execute and this
// route takes the `flow:` files it cannot, from the same upload and in one
// report. An upload id per route would mean the second call finds the staging
// directory already consumed, which is two runs dressed as one.
type scannerLocalRequest struct {
	URL       string                `json:"url"`
	UploadID  string                `json:"upload_id,omitempty"`
	Templates []scanner.UploadInput `json:"templates,omitempty"`
	toolRunRoute
}

// scannerLocalRow is one template's outcome on the local path.
type scannerLocalRow struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	TemplateID string   `json:"template_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason,omitempty"`
	Matcher    []string `json:"matchers,omitempty"`
	Extracts   []string `json:"extracted,omitempty"`
	Engine     string   `json:"engine"`
	Evidence   string   `json:"evidence,omitempty"`
}

// scannerLocalResponse is the report the browser renders.
type scannerLocalResponse struct {
	URL       string            `json:"url"`
	Templates []scannerLocalRow `json:"templates"`
	Count     int               `json:"count"`
	Matched   int               `json:"matched"`
	Unscored  int               `json:"unscored"`
	SourceIP  string            `json:"source_ip"`
}

// scannerLocalRun executes every staged template with the local runner.
//
// The upload is consumed exactly as the binary path consumes it, so a run that
// went through both paths cannot silently re-read a staging directory that is
// already gone.
func (s *server) scannerLocalRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input scannerLocalRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	target := strings.TrimSpace(input.URL)
	if target == "" {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url is required"))
		return
	}
	if strings.TrimSpace(input.UploadID) == "" && len(input.Templates) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", fmt.Errorf("upload_id or templates is required"))
		return
	}

	var staged []scanner.StagedFile
	var contents []string
	if len(input.Templates) > 0 {
		staged, contents = scanner.StagedFromUploads(input.Templates)
	} else {
		var err error
		staged, contents, err = scanner.TakeStagedTemplates(input.UploadID)
		if err != nil {
			if strings.Contains(err.Error(), "is unknown or already consumed") {
				writeError(w, http.StatusBadRequest, "INVALID_UPLOAD", err)
				return
			}
			writeError(w, http.StatusBadRequest, "INVALID_TEMPLATE", err)
			return
		}
	}

	_, routeContext, release := s.bindRouteContext(r.Context())
	defer release()
	sourceIP := s.ensureSourceIP(routeContext)
	transport, err := s.toolRouteTransport(input.toolRunRoute)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", err)
		return
	}

	rows := make([]scannerLocalRow, 0, len(staged))
	matched, unscored := 0, 0
	for index, file := range staged {
		row := scannerLocalRow{
			Name:   file.UploadName,
			Path:   file.RelativePath,
			Engine: "requestrider",
			Status: scanner.TemplateNotMatched,
		}
		if file.Meta != nil {
			row.TemplateID = file.Meta.TemplateID
			row.Title = file.Meta.Name
			row.Severity = file.Meta.Severity
		}
		if index >= len(contents) {
			row.Status = scanner.TemplateSkipped
			row.Reason = "the staged copy of this file is missing, so there was nothing to run"
			rows = append(rows, row)
			continue
		}
		run := scanner.RunTemplateLocally(routeContext, contents[index], target, transport)
		switch {
		case run.Reason != "":
			// A file this runner cannot perform is not a template that matched
			// nothing. It is reported under the status the reason names, and the
			// reason travels with it.
			row.Status = statusForLocalReason(run.Reason)
			row.Reason = run.Reason
			unscored++
		case run.Matched:
			row.Status = scanner.TemplateMatched
			row.Matcher = run.MatcherNames
			row.Extracts = run.Extracts
			matched++
		default:
			row.Status = scanner.TemplateNotMatched
		}
		if run.Response != "" {
			row.Evidence = run.Request + "\n" + run.Response
		}
		rows = append(rows, row)
	}

	writeJSON(w, http.StatusOK, scannerLocalResponse{
		URL: target, Templates: rows, Count: len(rows),
		Matched: matched, Unscored: unscored, SourceIP: sourceIP,
	})
}

// statusForLocalReason maps a refusal onto the status the report already uses,
// so a row produced here sorts and filters with every other row. A refusal that
// has no home would be reported as "ran, matched nothing", which is the one
// claim this report never makes.
func statusForLocalReason(reason string) string {
	switch {
	case strings.Contains(reason, "flow definition"):
		return scanner.TemplateFlow
	case strings.Contains(reason, "no request block"),
		strings.Contains(reason, "no path"),
		strings.Contains(reason, "raw HTTP request"),
		strings.Contains(reason, "no runnable template"):
		return scanner.TemplateInvalid
	case strings.Contains(reason, "cannot read the flow expression"),
		strings.Contains(reason, "http("),
		strings.Contains(reason, "performs only http steps"):
		return scanner.TemplateFlow
	case strings.Contains(reason, "cannot compile"):
		return scanner.TemplateInvalid
	default:
		return scanner.TemplateSkipped
	}
}
