//go:build windows

package agent

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func codexPrivateFileMode(os.FileInfo) bool { return true }

func openCodexFileNoFollow(path string) (*os.File, error) {
	handle, info, err := openCodexWindowsPath(path, false)
	if err != nil {
		return nil, err
	}
	if !codexWindowsPathMetadataIsSafe(codexWindowsMetadata(info), false, true) {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("codex file handle is unsafe")
	}
	return os.NewFile(uintptr(handle), filepath.Base(path)), nil
}

func validateCodexDirectory(path string, _ bool) error {
	handle, info, err := openCodexWindowsPath(path, true)
	if err != nil {
		return errors.New("codex directory is unsafe")
	}
	_ = windows.CloseHandle(handle)
	if !codexWindowsPathMetadataIsSafe(codexWindowsMetadata(info), true, false) {
		return errors.New("codex directory is unsafe")
	}
	return validateCodexDirectoryAncestors(path)
}

func validateCodexDirectoryAncestors(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return errors.New("codex directory path is invalid")
	}
	for current := abs; ; current = filepath.Dir(current) {
		ptr, ptrErr := windows.UTF16PtrFromString(current)
		if ptrErr != nil {
			return errors.New("codex directory path is invalid")
		}
		attributes, attrErr := windows.GetFileAttributes(ptr)
		if errors.Is(attrErr, windows.ERROR_FILE_NOT_FOUND) || errors.Is(attrErr, windows.ERROR_PATH_NOT_FOUND) {
			if parent := filepath.Dir(current); parent != current {
				continue
			}
			return errors.New("codex directory has no trusted ancestor")
		}
		if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("codex directory has an unsafe ancestor")
		}
		// Retain directory/reparse checks without an owner or ACL policy.
		if parent := filepath.Dir(current); parent == current {
			return nil
		}
	}
}

func openCodexWindowsPath(path string, directory bool) (windows.Handle, windows.ByHandleFileInformation, error) {
	return openCodexWindowsPathWithAccess(path, directory, windows.GENERIC_READ)
}

func openCodexWindowsPathWithAccess(path string, directory bool, access uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, windows.ByHandleFileInformation{}, err
	}
	handle, err := windows.CreateFile(
		ptr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		codexWindowsNoFollowOpenFlags(),
		0,
	)
	if err != nil {
		return windows.InvalidHandle, windows.ByHandleFileInformation{}, err
	}
	fail := func(err error) (windows.Handle, windows.ByHandleFileInformation, error) {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, windows.ByHandleFileInformation{}, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return fail(errors.New("codex path is a reparse point or has the wrong type"))
	}
	return handle, info, nil
}

func codexWindowsMetadata(info windows.ByHandleFileInformation) codexWindowsPathMetadata {
	return codexWindowsPathMetadata{
		Attributes: info.FileAttributes, HardLinks: info.NumberOfLinks,
		VolumeSerial: info.VolumeSerialNumber, FileIndexHigh: info.FileIndexHigh, FileIndexLow: info.FileIndexLow,
	}
}

// Windows uses the existing filesystem ACL without AO rewriting it.
func protectCodexPrivateDirectory(path string) error {
	return validateCodexDirectory(path, false)
}

func protectCodexPrivateFile(path string, file *os.File) error {
	if file == nil {
		return errors.New("codex private file handle is unavailable")
	}
	var original windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &original); err != nil {
		return err
	}
	handle, opened, err := openCodexWindowsPathWithAccess(
		path,
		false,
		windows.GENERIC_READ,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if !codexWindowsSameStableIdentity(
		codexWindowsMetadata(original),
		codexWindowsMetadata(opened),
	) {
		return errors.New("codex private file changed during validation")
	}
	return nil
}

func syncDirectory(path string) error {
	handle, info, err := openCodexWindowsPathWithAccess(path, true, codexWindowsDirectoryFlushAccess())
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if !codexWindowsPathMetadataIsSafe(codexWindowsMetadata(info), true, false) {
		return errors.New("codex directory is unsafe")
	}
	return windows.FlushFileBuffers(handle)
}
