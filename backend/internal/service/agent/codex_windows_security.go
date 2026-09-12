package agent

const (
	codexWindowsAttributeDirectory    uint32 = 0x00000010
	codexWindowsAttributeReparsePoint uint32 = 0x00000400
	codexWindowsOpenReparsePoint      uint32 = 0x00200000
	codexWindowsBackupSemantics       uint32 = 0x02000000
	codexWindowsMoveReplaceExisting   uint32 = 0x00000001
	codexWindowsMoveWriteThrough      uint32 = 0x00000008
	codexWindowsReadControl           uint32 = 0x00020000
	codexWindowsReadData              uint32 = 0x00000001
	codexWindowsWriteData             uint32 = 0x00000002
	codexWindowsAppendData            uint32 = 0x00000004
	codexWindowsWriteEA               uint32 = 0x00000010
	codexWindowsDeleteChild           uint32 = 0x00000040
	codexWindowsWriteAttributes       uint32 = 0x00000100
	codexWindowsDelete                uint32 = 0x00010000
	codexWindowsWriteDAC              uint32 = 0x00040000
	codexWindowsWriteOwner            uint32 = 0x00080000
	codexWindowsGenericAll            uint32 = 0x10000000
	codexWindowsGenericWrite          uint32 = 0x40000000
	codexWindowsGenericRead           uint32 = 0x80000000
)

type codexWindowsPathMetadata struct {
	Attributes    uint32
	HardLinks     uint32
	VolumeSerial  uint32
	FileIndexHigh uint32
	FileIndexLow  uint32
}

func codexWindowsNoFollowOpenFlags() uint32 {
	return codexWindowsOpenReparsePoint | codexWindowsBackupSemantics
}

func codexWindowsAtomicReplaceFlags() uint32 {
	return codexWindowsMoveReplaceExisting | codexWindowsMoveWriteThrough
}

func codexWindowsDirectoryFlushAccess() uint32 {
	return codexWindowsGenericWrite
}

func codexWindowsPathMetadataIsSafe(metadata codexWindowsPathMetadata, directory, requireSingleLink bool) bool {
	if metadata.Attributes&codexWindowsAttributeReparsePoint != 0 || (metadata.Attributes&codexWindowsAttributeDirectory != 0) != directory {
		return false
	}
	return !requireSingleLink || metadata.HardLinks == 1
}

func codexWindowsSameStableIdentity(left, right codexWindowsPathMetadata) bool {
	return left.VolumeSerial == right.VolumeSerial && left.FileIndexHigh == right.FileIndexHigh && left.FileIndexLow == right.FileIndexLow
}
