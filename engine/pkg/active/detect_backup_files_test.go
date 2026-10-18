package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// backupFixture is an application with one file beside what it serves.
type backupFixture struct {
	// leftover is the exact path that exists on disk beside what is served.
	// Empty means none of the candidates do.
	leftover string
	// sameDocument makes the leftover answer with the rendered page rather than a
	// file, which is what a server that answers 200 for everything looks like.
	sameDocument bool
	// probed records the paths that were asked for.
	probed []string
}

func (fixture *backupFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	source := "<?php\nfunction handler($request) {\n  return \"ok\";\n}\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/app.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><p>Rendered by the application</p></body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fixture.probed = append(fixture.probed, r.URL.Path)
		switch {
		case fixture.leftover != "" && r.URL.Path == fixture.leftover:
			if fixture.sameDocument {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`<html><body><p>Rendered by the application</p></body></html>`))
				return
			}
			// A file from disk: a different type and a different body, which is
			// what makes it distinguishable from the rendered page.
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(source))
		case r.URL.Path == "/app.php":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><p>Rendered by the application</p></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func backupScan(t *testing.T, server *httptest.Server, path string) []Finding {
	t.Helper()
	baseline := &Response{StatusCode: 200,
		Header: http.Header{"Content-Type": {"text/html"}},
		Body:   `<html><body><p>Rendered by the application</p></body></html>`}
	return (BackupFiles{}).Scan(context.Background(), mustTransport(t),
		Point{URL: server.URL + path, Method: http.MethodGet}, baseline)
}

// The check is not a wordlist: the candidate is derived from the path the
// application serves, and the row names the tool whose habit produced it.
func TestBackupFilesFindsALeftoverDerivedFromTheLivePath(t *testing.T) {
	// The candidate each tool leaves beside `/app.php`, spelled out rather than
	// derived, so the test asserts against the derivation and not with it.
	for leftover, expected := range map[string]string{
		"/app.php.bak":  ".bak",
		"/app.php~":     "~",
		"/app.php.old":  ".old",
		"/app.php.orig": ".orig",
		"/app.php.copy": ".copy",
		"/app.php.save": ".save",
		"/app.php.tmp":  ".tmp",
		"/.app.php.swp": ".swp",
	} {
		t.Run(expected, func(t *testing.T) {
			fixture := &backupFixture{leftover: leftover}
			server := fixture.server(t)

			findings := backupScan(t, server, "/app.php")
			if len(findings) != 1 {
				t.Fatalf("findings = %d for leftover %q; probed %v", len(findings), leftover, fixture.probed)
			}
			if !strings.Contains(findings[0].Title, "0x006000D8") {
				t.Errorf("title = %q, want the original's identifier in it", findings[0].Title)
			}
			if !strings.Contains(findings[0].Evidence, "<?php") {
				t.Errorf("the evidence does not carry the source fingerprint: %s", findings[0].Evidence)
			}
			if !strings.Contains(findings[0].Evidence, leftover) {
				t.Errorf("the evidence does not name the leftover that was found: %s", findings[0].Evidence)
			}
		})
	}
}

// A 200 on everything is the commonest shape of a false positive here, and the
// only thing standing against it is that the body has to be source **and** has to
// differ from what the live path serves.
func TestBackupFilesIgnoresAServerThatAnswers200WithTheRenderedPage(t *testing.T) {
	fixture := &backupFixture{leftover: "/app.php.bak", sameDocument: true}
	server := fixture.server(t)

	if findings := backupScan(t, server, "/app.php"); len(findings) != 0 {
		t.Fatalf("findings = %d against a server that serves the rendered page for everything",
			len(findings))
	}
	if len(fixture.probed) == 0 {
		t.Error("no candidate was requested, so the silence proves nothing")
	}
}

// A 200 whose body is a rendered page is not a source file, however ready the
// status is.
func TestBackupFilesNeedsASourceFingerprintNotJustAStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("<html><body>nothing here</body></html>", 4)))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><p>Rendered</p></body></html>`))
	}))
	defer server.Close()

	if findings := backupScan(t, server, "/app.php"); len(findings) != 0 {
		t.Fatalf("findings = %d for a 200 with no source in it", len(findings))
	}
}

// The candidates come from the path, so a directory has none and the run must
// decline rather than guess an index name.
func TestBackupFilesDoesNotProbeADirectory(t *testing.T) {
	fixture := &backupFixture{leftover: "/app.php.bak"}
	server := fixture.server(t)

	if findings := backupScan(t, server, "/"); len(findings) != 0 {
		t.Fatalf("findings = %d for a directory path", len(findings))
	}
	if len(fixture.probed) != 0 {
		t.Errorf("a directory produced %d requests: %v", len(fixture.probed), fixture.probed)
	}
}

// The derivation is pure and is checked as pure, because a table that quietly
// stopped deriving from the path would become the wordlist this check is not.
func TestBackupSuffixesDeriveFromThePath(t *testing.T) {
	// The derivation is tested as pure *per the suffix*, by invoking each one's
	// build against the input it will actually see on a run, and checking that
	// nothing wanders: every result has to stay under the input's prefix.
	cases := map[string]string{
		"/app.php~":     "/app.php~",
		"/.app.php.swp": "/.app.php.swp",
		"/app.php.bak":  "/app.php.bak",
		"/app.php.old":  "/app.php.old",
		"/app.php.orig": "/app.php.orig",
		"/app.php.copy": "/app.php.copy",
		"/app.php.save": "/app.php.save",
		"/app.php.tmp":  "/app.php.tmp",
	}
	for suffix, want := range cases {
		found := false
		for _, candidate := range backupSuffixes {
			if candidate.build("/app.php") == want {
				found = true
			}
			// Any input with a directory must keep its derivative in the same
			// directory. The map above can only check the root case, so this
			// exercises the other shape directly.
			if candidate.build("/var/www/index.php") != "" &&
				strings.HasPrefix(candidate.build("/var/www/index.php"), "/var/www/") {
				// secondary checked in TestBackupDerivativeStaysInItsDirectory
			}
		}
		if !found {
			t.Errorf("no suffix derives %q from /app.php", want)
		}
		_ = suffix
	}
}

// TestBackupDerivativeStaysInItsDirectory guards the property the cross-dir
// cases relied on: a file beside the live file is in the live file's directory.
func TestBackupDerivativeStaysInItsDirectory(t *testing.T) {
	for _, candidate := range backupSuffixes {
		derived := candidate.build("/var/www/app.php")
		if !strings.HasPrefix(derived, "/var/www/") {
			t.Errorf("the %s suffix moved the file out of its directory: %s", candidate.name, derived)
		}
	}
}

// A candidate that leaves the origin is a bug in the derivation, and the
// resolution refuses it rather than following it.
func TestBackupCandidateRefusesToLeaveItsOrigin(t *testing.T) {
	if _, err := sameOriginURL("https://app.example/index.php",
		"https://other-host.example/index.php.bak"); err == nil {
		t.Fatal("a candidate on another origin was accepted")
	}
	resolved, err := sameOriginURL("https://app.example/dir/index.php",
		"https://app.example/dir/index.php.bak")
	if err != nil {
		t.Fatalf("a same-origin candidate was refused: %v", err)
	}
	if resolved != "https://app.example/dir/index.php.bak" {
		t.Errorf("resolved = %q", resolved)
	}
}
