package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAtomicWriteFileCreatesAndWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")

	if err := atomicWriteFile(path, []byte("hello"), 0o640); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading result: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
}

func TestAtomicWriteFilePreservesPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")

	if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wantMode := info.Mode().Perm()

	if err := atomicWriteFile(path, []byte("replaced"), wantMode); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != wantMode {
		t.Fatalf("permissions = %v, want %v", got, wantMode)
	}
}

func TestAtomicWriteFileOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")

	if err := os.WriteFile(path, []byte("this is much longer original content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A naive truncate-then-write done slowly could theoretically leave
	// trailing bytes from the longer original if something went wrong;
	// atomicWriteFile's rename-based approach can't do that.
	if string(got) != "short" {
		t.Fatalf("content = %q, want %q (no leftover bytes from the original)", got, "short")
	}
}

func TestAtomicWriteFileLeavesOriginalUntouchedOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")
	original := []byte("must survive a failed write")

	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// Point atomicWriteFile at a path whose directory doesn't exist, so
	// the initial CreateTemp fails before anything touches the real file.
	badPath := filepath.Join(dir, "does-not-exist", "out.yml")
	if err := atomicWriteFile(badPath, []byte("new"), 0o600); err == nil {
		t.Fatal("expected an error writing to a nonexistent directory, got nil")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("original file was modified: got %q, want %q", got, original)
	}
}

func TestAtomicWriteFileCleansUpTempFileOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based read-only simulation doesn't translate to Windows ACLs")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")

	// Make the directory read-only so os.Chmod on the temp file (or the
	// final rename) fails partway through, then confirm no stray
	// .ansible-vault-gui-*.tmp file is left behind.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	_ = atomicWriteFile(path, []byte("data"), 0o600)

	entries, err := os.ReadDir(dir)
	if err != nil {
		// Might not even be able to list a 0500 dir depending on OS/user;
		// not the point of this test either way.
		t.Skipf("could not list temp dir to check for leftovers: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ansible-vault-gui-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}
