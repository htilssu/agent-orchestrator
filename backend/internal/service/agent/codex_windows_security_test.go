package agent

import "testing"

func TestWindowsNoFollowAndWriteThroughPolicies(t *testing.T) {
	if got := codexWindowsNoFollowOpenFlags(); got&codexWindowsOpenReparsePoint == 0 || got&codexWindowsBackupSemantics == 0 {
		t.Fatalf("no-follow open flags = %#x", got)
	}
	if got := codexWindowsAtomicReplaceFlags(); got != codexWindowsMoveReplaceExisting|codexWindowsMoveWriteThrough {
		t.Fatalf("atomic replace flags = %#x", got)
	}
	if got := codexWindowsDirectoryFlushAccess(); got&codexWindowsGenericWrite == 0 || got&codexWindowsReadControl != 0 {
		t.Fatalf("directory flush access = %#x", got)
	}
}

func TestWindowsPathMetadataPolicyRejectsReparseTypeAndHardLinks(t *testing.T) {
	safeFile := codexWindowsPathMetadata{HardLinks: 1, VolumeSerial: 9, FileIndexHigh: 4, FileIndexLow: 2}
	if !codexWindowsPathMetadataIsSafe(safeFile, false, true) {
		t.Fatal("safe file metadata rejected")
	}
	for name, mutate := range map[string]func(*codexWindowsPathMetadata){
		"reparse":   func(m *codexWindowsPathMetadata) { m.Attributes |= codexWindowsAttributeReparsePoint },
		"directory": func(m *codexWindowsPathMetadata) { m.Attributes |= codexWindowsAttributeDirectory },
		"hardlink":  func(m *codexWindowsPathMetadata) { m.HardLinks = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			metadata := safeFile
			mutate(&metadata)
			if codexWindowsPathMetadataIsSafe(metadata, false, true) {
				t.Fatalf("unsafe %s metadata accepted", name)
			}
		})
	}
	safeDirectory := safeFile
	safeDirectory.Attributes = codexWindowsAttributeDirectory
	if !codexWindowsPathMetadataIsSafe(safeDirectory, true, false) {
		t.Fatal("safe ancestor directory rejected")
	}
	changed := safeFile
	changed.FileIndexLow++
	if codexWindowsSameStableIdentity(safeFile, changed) {
		t.Fatal("changed Windows file identity accepted")
	}
	if !codexWindowsSameStableIdentity(safeFile, safeFile) {
		t.Fatal("stable Windows file identity rejected")
	}
}
