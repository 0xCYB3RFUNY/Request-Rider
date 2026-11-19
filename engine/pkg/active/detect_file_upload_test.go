package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFileUploadDetectsAcceptedDangerousExtension(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method="post" enctype="multipart/form-data"><input type="file" name="file"></form>`))
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "bad multipart", http.StatusBadRequest)
			return
		}
		part, err := mr.NextPart()
		if err != nil {
			http.Error(w, "missing part", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"uploaded","path":"/uploads/` + part.FileName() + `"}`))
	}))
	defer srv.Close()

	tr, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	p := Point{URL: srv.URL + "/api/upload", Method: http.MethodGet}
	baseline, err := tr.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	findings := (FileUpload{}).Scan(context.Background(), tr, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 file_upload finding, got %d", len(findings))
	}
	if findings[0].CWE != "CWE-434" || !strings.Contains(findings[0].Payload, ".php") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestFileUploadSkipsNonUploadPage(t *testing.T) {
	p := Point{URL: "http://target.test/about", Method: http.MethodGet}
	baseline := &Response{StatusCode: 200, Body: "<html>About us</html>"}
	findings := (FileUpload{}).Scan(context.Background(), nil, p, baseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on non-upload page, got %d", len(findings))
	}
}
