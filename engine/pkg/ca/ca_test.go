package ca

import (
	"os"
	"path/filepath"
	"testing"
)

// The CA private key is the anchor of every interception the tool performs.
// `GenerateCA` writes it 0600 and `NewCAManager` creates the directory 0700, so a
// key created here is safe. What is not safe is a key that already existed with
// wider permissions: unpacked from an archive, copied from a filesystem without
// unix modes, or bind-mounted from the host — `docker-compose.yml` mounts
// `./data/ca`, and the host decides the modes. `LoadCA` used to accept such a key
// silently, and a readable CA key means any local user can sign a certificate for
// any domain.

func TestGeneratedKeyIsAlreadyPrivate(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	if manager.Cert == nil || manager.Key == nil {
		t.Fatal("CA was not generated")
	}

	keyInfo, err := os.Stat(manager.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0600 {
		t.Errorf("generated key mode = %o, want 600", got)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Errorf("generated directory mode = %o, want 700", got)
	}
}

func TestExistingKeyWithWidePermissionsIsTightenedOnLoad(t *testing.T) {
	dir := t.TempDir()
	first, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("first NewCAManager: %v", err)
	}
	certBefore := first.Cert

	// Simulate a key that arrived from elsewhere: same bytes, wider modes.
	if err := os.Chmod(first.KeyPath, 0644); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	second, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("second NewCAManager: %v", err)
	}

	keyInfo, err := os.Stat(second.KeyPath)
	if err != nil {
		t.Fatalf("stat key after load: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0600 {
		t.Errorf("key mode after load = %o, want 600", got)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir after load: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Errorf("directory mode after load = %o, want 700", got)
	}

	// Tightening must not replace the CA: an operator's intercept continuity
	// depends on this key staying the same across restarts.
	if !certBefore.Equal(second.Cert) {
		t.Error("loading replaced the existing certificate")
	}
}

func TestTightenPermissionsIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewCAManager(dir)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	for round := 0; round < 3; round++ {
		if err := manager.tightenPermissions(dir); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	info, err := os.Stat(filepath.Clean(manager.KeyPath))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("mode after repeated calls = %o, want 600", got)
	}
}

func TestTightenPermissionsToleratesAMissingKey(t *testing.T) {
	// `tightenPermissions` runs on the load path, where the key is expected to
	// exist. A missing file must not panic or error: the caller has already
	// decided whether the CA is usable, and this is only a safety net.
	dir := t.TempDir()
	manager := &CAManager{KeyPath: filepath.Join(dir, "ca.key")}
	if err := manager.tightenPermissions(dir); err != nil {
		t.Fatalf("missing key should be tolerated, got %v", err)
	}
}
