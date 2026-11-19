package bypass

// The traversal family and the check that keeps it honest.
//
// Both came out of a live measurement, and both are about the same thing: a
// `/../` form really does change what a target answers, and really does not
// necessarily deliver the resource that was asked for.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestATraversalToTheRootIsNotAccessToTheFile is the false positive the original
// tool reported, reproduced here as a test so it cannot come back.
//
// Measured 2026-10-03 on `www.liveinternet.ru/.git/config`: a plain GET answers
// `403`, and `/../` answers `200` — with the site's home page, 34885 bytes,
// titled `LiveInternet @ Статистика и дневники`. The file answers `403` with 437
// bytes. The tool that found this printed `9 bypass(es) confirmed` while its own
// `False Positives Filtered` counter read `0`.
//
// So the fixture below is exactly that target: a root page, and a file that is
// refused. A walk must report that it got an answer *and* that the answer was the
// wrong page.
func TestATraversalToTheRootIsNotAccessToTheFile(t *testing.T) {
	const rootPage = `<html><head><title>LiveInternet @ home</title></head><body>` +
		`<p>the front page, 34885 bytes worth of it</p></body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// nginx resolves a traversal to the root and serves the root.
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(rootPage))
			return
		}
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(rootPage))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
	}))
	t.Cleanup(server.Close)

	req := mustRequest(t, server.URL+"/.git/config")
	resp, attempt, err := New([]string{"path-traversal-lead"}).Attempt(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()

	if attempt.SucceededBy == "" {
		t.Fatalf("the traversal did not reach anything at all: %s", attempt.TriedSummary())
	}
	if !attempt.ServedSiteRoot {
		t.Error("the walk answered with the site's root page and did not say so; " +
			"a report reading 'reached' would name a form that delivered the wrong page")
	}
	if attempt.ReachedTheNamedResource() {
		t.Error("ReachedTheNamedResource is true while the served page is the root: " +
			"that is the exact false positive this package exists to avoid")
	}
	if attempt.Note == "" {
		t.Error("no note explains what actually came back, so the report has nothing " +
			"to tell the operator that the form was not what it claimed")
	}
}

// TestAFormThatServesTheFileIsAccess is the other half, and without it the first
// test could be satisfied by a driver that calls everything a root.
func TestAFormThatServesTheFileIsAccess(t *testing.T) {
	const secret = "[core]\n\trepositoryformatversion = 0"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>home</title></head><body>front page</body></html>"))
			return
		}
		if strings.Contains(r.URL.Path, ";") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(secret))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	req := mustRequest(t, server.URL+"/.git/config")
	resp, attempt, err := New([]string{"path-segment-1"}).Attempt(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()

	if !attempt.ReachedTheNamedResource() {
		t.Errorf("the form served the file and was still not counted as access: "+
			"SucceededBy=%q ServedSiteRoot=%v", attempt.SucceededBy, attempt.ServedSiteRoot)
	}
}

// TestTheRootIsFetchedOncePerHost pins the cost. The comparison is worth a
// request, but only one: a walk that re-fetched the root per successful form
// would double its own cost on the exact resources where a form worked.
func TestTheRootIsFetchedOncePerHost(t *testing.T) {
	roots := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			roots++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>home</html>"))
			return
		}
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>home</html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	driver := New([]string{"path-traversal-lead"})
	for _, path := range []string{"/.git/config", "/.env", "/admin", "/backup.zip"} {
		req := mustRequest(t, server.URL+path)
		resp, _, err := driver.Attempt(context.Background(), server.Client(), req)
		if err != nil {
			t.Fatalf("attempt %s: %v", path, err)
		}
		resp.Body.Close()
	}
	if roots != 1 {
		t.Errorf("the root was fetched %d times for 4 successful walks, want 1: the "+
			"comparison is one request per host, not one per form", roots)
	}
}

// TestTheBodyIsStillReadableAfterTheComparison keeps the comparison from eating
// the evidence. A walk that consumed the body would hand the caller an empty
// page *and* a report claiming a success — the same defect one layer over.
func TestTheBodyIsStillReadableAfterTheComparison(t *testing.T) {
	payload := "<html><head><title>home</title></head><body>" +
		strings.Repeat("content line with room to be compared. ", 400) + "</body></html>"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(payload))
			return
		}
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(payload))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	req := mustRequest(t, server.URL+"/secret")
	resp, _, err := New([]string{"path-traversal-lead"}).Attempt(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	defer resp.Body.Close()

	got := readAllOf(t, resp)
	if !strings.Contains(got, "content line with room") {
		t.Errorf("the caller's body is %d bytes and does not contain the page; the "+
			"root comparison consumed the evidence it was comparing", len(got))
	}
}

// readAllOf reads a response for a test assertion.
func readAllOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	var out strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		out.Write(buf[:n])
		if err != nil || n == 0 {
			return out.String()
		}
	}
}
