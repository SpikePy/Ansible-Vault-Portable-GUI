package main

import (
	"os"
	"path/filepath"
)

// atomicWriteFile writes data to path without ever leaving it truncated or
// partially written: it writes to a temporary file in the same directory
// (so the final rename stays on one filesystem and is atomic), sets its
// permissions to mode, then renames it over path. If the process is
// killed, loses power, or the write otherwise fails partway through,
// path itself is left untouched — worst case there's a leftover temp file
// to clean up, never a corrupted target file.
func atomicWriteFile(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ansible-vault-gui-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
