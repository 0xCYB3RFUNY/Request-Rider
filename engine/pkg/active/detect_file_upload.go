package active

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
)

// FileUpload audits file upload endpoints and multipart forms for unrestricted
// upload of files with dangerous types (CWE-434). It sends harmless marker
// payloads with dangerous extensions (.php, .jsp, .svg) and checks whether
// the endpoint accepts them without validation.
type FileUpload struct{}

// Name implements Module.
func (FileUpload) Name() string { return "file_upload" }

// Level implements Module.
func (FileUpload) Level() Level { return LevelEndpoint }

var uploadHints = []string{
	"upload", "avatar", "attachment", "import", "media", "file", "document", "photo",
}

func isUploadSurface(p Point, baseline *Response) bool {
	if strings.EqualFold(p.FieldType, "file") {
		return true
	}
	lowerURL := strings.ToLower(p.URL)
	for _, h := range uploadHints {
		if strings.Contains(lowerURL, h) {
			return true
		}
	}
	if baseline != nil && strings.Contains(strings.ToLower(baseline.Body), `type="file"`) {
		return true
	}
	return false
}

// Scan probes an upload surface with harmless dangerous-extension multipart payloads.
func (FileUpload) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || !isUploadSurface(p, baseline) {
		return nil
	}

	fieldName := p.Param
	if fieldName == "" {
		fieldName = "file"
	}
	canary := newCanary("rrup")
	if canary == "" {
		return nil
	}

	type uploadCandidate struct {
		filename    string
		contentType string
		content     string
	}
	candidates := []uploadCandidate{
		{filename: canary + ".php", contentType: "application/x-php", content: "<?php /* " + canary + " */ ?>"},
		{filename: canary + ".svg", contentType: "image/svg+xml", content: "<svg><!-- " + canary + " --></svg>"},
	}

	var findings []Finding
	for _, cand := range candidates {
		if ctx.Err() != nil {
			return findings
		}
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		part, err := mw.CreateFormFile(fieldName, cand.filename)
		if err != nil {
			continue
		}
		if _, err := part.Write([]byte(cand.content)); err != nil {
			continue
		}
		_ = mw.Close()

		resp, err := t.DoBody(ctx, http.MethodPost, p.URL, buf.Bytes(), mw.FormDataContentType(), false, nil)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && FreshFold(baseline, resp, cand.filename) {
			f, _ := NewFinding(Spec{
				Module:   "file_upload",
				Title:    "Unrestricted upload of dangerous file type (" + cand.filename + ") on " + p.URL,
				Claimed:  SeverityHigh,
				Tier:     TierPotential,
				Point:    Point{URL: p.URL, Method: http.MethodPost, Param: fieldName, Source: SourceForm},
				Payload:  cand.filename,
				Evidence: Snippet(resp.Body, cand.filename, 220),
				Description: "The upload endpoint accepted a multipart file with a dangerous extension (" +
					cand.filename + ") and returned HTTP " + resp.Status + " confirming the filename (CWE-434).",
				Remediation: "Validate file types using an explicit allowlist of extensions and magic bytes, " +
					"rename uploaded files to random identifiers, and serve them from an isolated non-executable domain.",
			})
			findings = append(findings, f)
			break
		}
	}
	return findings
}
