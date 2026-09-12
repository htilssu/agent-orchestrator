//go:build windows

package agent

import "testing"

func TestCodexPrivateDirectoryWithWindowsSystemAncestors(t *testing.T) {
	dir := t.TempDir()
	if err := protectCodexPrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := validateCodexDirectory(dir, true); err != nil {
		t.Fatalf("private directory beneath Windows system ancestors rejected: %v", err)
	}
}
