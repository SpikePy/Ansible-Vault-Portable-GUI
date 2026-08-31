package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func postJSON(t *testing.T, handler http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeAPIResponse(t *testing.T, rec *httptest.ResponseRecorder) apiResponse {
	t.Helper()
	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.Body.String(), err)
	}
	return resp
}

func TestRequireToken(t *testing.T) {
	called := false
	inner := func(w http.ResponseWriter, r *http.Request) { called = true }
	handler := requireToken("secret-token", inner)

	req := httptest.NewRequest(http.MethodGet, "/api/file", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("no token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("no token: inner handler was called, should not have been")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/file", nil)
	req.Header.Set("X-Vault-Token", "wrong-token")
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("wrong token: inner handler was called, should not have been")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/file", nil)
	req.Header.Set("X-Vault-Token", "secret-token")
	rec = httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("correct token: inner handler was not called")
	}
}

func TestHandleFileEncryptDecryptView(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yml")
	if err := os.WriteFile(path, []byte("plaintext content"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, handleFile, "/api/file", fileRequest{
		Action: "encrypt", Path: path, Password: "s3cret",
	})
	resp := decodeAPIResponse(t, rec)
	if !resp.OK {
		t.Fatalf("encrypt: ok=false, message=%q", resp.Message)
	}
	if !strings.HasPrefix(resp.Result, vaultHeader) {
		t.Errorf("encrypt result missing vault header: %q", resp.Result)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isVaultText(onDisk) {
		t.Error("file on disk was not actually encrypted")
	}

	// Attempting to encrypt an already-encrypted file must be refused.
	rec = postJSON(t, handleFile, "/api/file", fileRequest{
		Action: "encrypt", Path: path, Password: "s3cret",
	})
	resp = decodeAPIResponse(t, rec)
	if resp.OK {
		t.Fatal("re-encrypting an already-encrypted file should have failed")
	}

	// view must not modify the file.
	rec = postJSON(t, handleFile, "/api/file", fileRequest{
		Action: "view", Path: path, Password: "s3cret",
	})
	resp = decodeAPIResponse(t, rec)
	if !resp.OK || resp.Result != "plaintext content" {
		t.Fatalf("view: ok=%v, result=%q, message=%q", resp.OK, resp.Result, resp.Message)
	}
	onDisk, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isVaultText(onDisk) {
		t.Error("view modified the file on disk")
	}

	// decrypt must overwrite it.
	rec = postJSON(t, handleFile, "/api/file", fileRequest{
		Action: "decrypt", Path: path, Password: "s3cret",
	})
	resp = decodeAPIResponse(t, rec)
	if !resp.OK || resp.Result != "plaintext content" {
		t.Fatalf("decrypt: ok=%v, result=%q, message=%q", resp.OK, resp.Result, resp.Message)
	}
	onDisk, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != "plaintext content" {
		t.Errorf("file on disk after decrypt = %q, want %q", onDisk, "plaintext content")
	}
}

func TestHandleFileErrors(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		resp := decodeAPIResponse(t, postJSON(t, handleFile, "/api/file", fileRequest{Action: "view", Password: "s3cret"}))
		if resp.OK {
			t.Fatal("expected failure for missing path")
		}
	})

	t.Run("missing password", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "f.yml")
		os.WriteFile(path, []byte("x"), 0o600)
		resp := decodeAPIResponse(t, postJSON(t, handleFile, "/api/file", fileRequest{Action: "view", Path: path}))
		if resp.OK {
			t.Fatal("expected failure for missing password (and no ANSIBLE_VAULT_PASSWORD)")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		resp := decodeAPIResponse(t, postJSON(t, handleFile, "/api/file", fileRequest{
			Action: "view", Path: "/does/not/exist.yml", Password: "s3cret",
		}))
		if resp.OK {
			t.Fatal("expected failure for a nonexistent file")
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "f.yml")
		os.WriteFile(path, []byte("x"), 0o600)
		resp := decodeAPIResponse(t, postJSON(t, handleFile, "/api/file", fileRequest{
			Action: "bogus", Path: path, Password: "s3cret",
		}))
		if resp.OK {
			t.Fatal("expected failure for an unknown action")
		}
	})
}

func TestHandleInline(t *testing.T) {
	rec := postJSON(t, handleInline, "/api/inline", inlineRequest{
		Action: "encrypt", Name: "db_password", Secret: "hunter2", Password: "s3cret", Multiline: true,
	})
	resp := decodeAPIResponse(t, rec)
	if !resp.OK {
		t.Fatalf("encrypt: ok=false, message=%q", resp.Message)
	}
	if !strings.HasPrefix(resp.Result, "db_password: !vault |\n") {
		t.Errorf("unexpected encrypt result: %q", resp.Result)
	}

	rec = postJSON(t, handleInline, "/api/inline", inlineRequest{
		Action: "decrypt", VaultText: resp.Result, Password: "s3cret",
	})
	resp = decodeAPIResponse(t, rec)
	if !resp.OK || resp.Result != "hunter2" {
		t.Fatalf("decrypt: ok=%v, result=%q, message=%q", resp.OK, resp.Result, resp.Message)
	}

	t.Run("encrypt without secret", func(t *testing.T) {
		resp := decodeAPIResponse(t, postJSON(t, handleInline, "/api/inline", inlineRequest{
			Action: "encrypt", Password: "s3cret",
		}))
		if resp.OK {
			t.Fatal("expected failure for empty secret")
		}
	})

	t.Run("decrypt without vault text", func(t *testing.T) {
		resp := decodeAPIResponse(t, postJSON(t, handleInline, "/api/inline", inlineRequest{
			Action: "decrypt", Password: "s3cret",
		}))
		if resp.OK {
			t.Fatal("expected failure for empty vault text")
		}
	})
}

func TestHandleBrowse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.yml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/browse?path="+dir, nil)
	rec := httptest.NewRecorder()
	handleBrowse(rec, req)

	var resp browseResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("handleBrowse failed: %s", resp.Message)
	}
	if len(resp.Entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(resp.Entries), resp.Entries)
	}
	// Directories should sort before files, and be sorted by name.
	if !resp.Entries[0].IsDir || resp.Entries[0].Name != "subdir" {
		t.Errorf("first entry = %+v, want subdir first", resp.Entries[0])
	}
	if resp.Entries[1].Name != "a.yml" || resp.Entries[2].Name != "b.yml" {
		t.Errorf("files not sorted by name: %+v, %+v", resp.Entries[1], resp.Entries[2])
	}
}

func TestHandleBrowseNonexistent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/browse?path=/does/not/exist", nil)
	rec := httptest.NewRecorder()
	handleBrowse(rec, req)

	var resp browseResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("expected failure browsing a nonexistent path")
	}
}

func TestHandlePreview(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.yml")
	if err := os.WriteFile(path, []byte("hello preview"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/preview?path="+path, nil)
	rec := httptest.NewRecorder()
	handlePreview(rec, req)

	var resp previewResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Content != "hello preview" || resp.Truncated {
		t.Fatalf("got %+v", resp)
	}
}

func TestHandlePreviewTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yml")
	big := bytes.Repeat([]byte("a"), previewMaxBytes+100)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/preview?path="+path, nil)
	rec := httptest.NewRecorder()
	handlePreview(rec, req)

	var resp previewResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || !resp.Truncated || len(resp.Content) != previewMaxBytes {
		t.Fatalf("ok=%v truncated=%v len=%d, want ok=true truncated=true len=%d",
			resp.OK, resp.Truncated, len(resp.Content), previewMaxBytes)
	}
}

func TestHandlePreviewDirectory(t *testing.T) {
	dir := t.TempDir()
	req := httptest.NewRequest(http.MethodGet, "/api/preview?path="+dir, nil)
	rec := httptest.NewRecorder()
	handlePreview(rec, req)

	var resp previewResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("expected failure previewing a directory")
	}
}

func TestResolveGUIPassword(t *testing.T) {
	if _, err := resolveGUIPassword("s3cret", "", ""); err != nil {
		t.Errorf("direct password: unexpected error: %v", err)
	}
	os.Unsetenv(defaultPasswordEnv)
	if _, err := resolveGUIPassword("", "", ""); err == nil {
		t.Error("no password given: expected an error, got nil")
	}
}
