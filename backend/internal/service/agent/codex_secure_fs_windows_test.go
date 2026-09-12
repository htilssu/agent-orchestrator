//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexPrivateDirectoryWithWindowsSystemAncestors(t *testing.T) {
	dir := t.TempDir()
	if err := protectCodexPrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := validateCodexDirectory(dir, true); err != nil {
		t.Fatalf("private directory beneath Windows system ancestors rejected: %v", err)
	}
}

func TestCodexDirectoryAncestorsRejectNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCodexDirectoryAncestors(path); err == nil {
		t.Fatal("non-directory ancestor accepted")
	}
}
