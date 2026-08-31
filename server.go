package main

// The local, token-gated web server behind the GUI.

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed gui.html
var guiHTML string

// defaultAddr is fixed (rather than an OS-assigned random port) so the
// page's origin stays the same across restarts, which is what lets the
// browser's localStorage-based settings persistence survive a restart. Only
// one instance can bind this port at a time; pass a different addr to run
// to use more.
const defaultAddr = "127.0.0.1:47990"

// run starts the local GUI server on addr and blocks until the server
// exits — either because the browser tab was closed (see the /api/shutdown
// handler) or the process is killed.
func run(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generating session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	page := strings.Replace(guiHTML, "__TOKEN__", token, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	})
	mux.HandleFunc("/api/file", requireToken(token, handleFile))
	mux.HandleFunc("/api/inline", requireToken(token, handleInline))
	mux.HandleFunc("/api/browse", requireToken(token, handleBrowse))
	mux.HandleFunc("/api/preview", requireToken(token, handlePreview))
	mux.HandleFunc("/api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		// navigator.sendBeacon (used by the page's pagehide handler, see
		// gui.html) can't set custom headers, so this one endpoint takes
		// the token as a query parameter instead of the X-Vault-Token
		// header the others require.
		if r.URL.Query().Get("token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		go func() {
			time.Sleep(200 * time.Millisecond)
			os.Exit(0)
		}()
	})

	url := fmt.Sprintf("http://%s/?token=%s", listener.Addr().String(), token)
	openBrowser(url)

	return http.Serve(listener, mux)
}

// requireToken protects the API endpoints from other local processes /
// browser tabs guessing at the port: the page embeds the token and sends
// it on every request.
func requireToken(token string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

type apiResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Result  string `json:"result,omitempty"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, apiResponse{OK: false, Message: err.Error()})
}

type fileRequest struct {
	Action       string `json:"action"` // encrypt | decrypt | view
	Path         string `json:"path"`
	Password     string `json:"password"`
	PasswordFile string `json:"passwordFile"`
	PasswordEnv  string `json:"passwordEnv"`
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	var req fileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.New("invalid request"))
		return
	}
	if req.Path == "" {
		writeError(w, errors.New("file path is required"))
		return
	}
	encrypt := req.Action == "encrypt"
	pw, err := resolveGUIPassword(req.Password, req.PasswordFile, req.PasswordEnv)
	if err != nil {
		writeError(w, err)
		return
	}

	info, err := os.Stat(req.Path)
	if err != nil {
		writeError(w, fmt.Errorf("reading input file: %w", err))
		return
	}
	mode := info.Mode().Perm()
	raw, err := os.ReadFile(req.Path)
	if err != nil {
		writeError(w, fmt.Errorf("reading input file: %w", err))
		return
	}
	if encrypt && isVaultText(raw) {
		writeError(w, fmt.Errorf("%s is already encrypted; decrypt it first if you want to re-encrypt it", req.Path))
		return
	}

	switch req.Action {
	case "view":
		plaintext, err := viewFile(raw, pw)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, apiResponse{OK: true, Result: string(plaintext)})
	case "encrypt", "decrypt":
		var result []byte
		if encrypt {
			result, err = encryptVault(raw, pw, true)
		} else {
			result, err = decryptVault(raw, pw)
		}
		if err != nil {
			writeError(w, err)
			return
		}
		if err := os.WriteFile(req.Path, result, mode); err != nil {
			writeError(w, fmt.Errorf("writing file: %w", err))
			return
		}
		verb := "Encrypted"
		if !encrypt {
			verb = "Decrypted"
		}
		writeJSON(w, apiResponse{OK: true, Message: fmt.Sprintf("%s %s.", verb, req.Path), Result: string(result)})
	default:
		writeError(w, fmt.Errorf("unknown action %q", req.Action))
	}
}

type inlineRequest struct {
	Action       string `json:"action"` // encrypt | decrypt
	Name         string `json:"name"`
	Secret       string `json:"secret"`
	Multiline    bool   `json:"multiline"` // encrypt only: wrap the hex body at 80 chars/line vs. one single line
	VaultText    string `json:"vaultText"`
	Password     string `json:"password"`
	PasswordFile string `json:"passwordFile"`
	PasswordEnv  string `json:"passwordEnv"`
}

func handleInline(w http.ResponseWriter, r *http.Request) {
	var req inlineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.New("invalid request"))
		return
	}
	encrypt := req.Action == "encrypt"
	pw, err := resolveGUIPassword(req.Password, req.PasswordFile, req.PasswordEnv)
	if err != nil {
		writeError(w, err)
		return
	}

	if encrypt {
		if req.Secret == "" {
			writeError(w, errors.New("secret is required"))
			return
		}
		vaultText, err := encryptVault([]byte(req.Secret), pw, req.Multiline)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, apiResponse{OK: true, Result: string(formatInlineVault(vaultText, req.Name))})
		return
	}

	if req.VaultText == "" {
		writeError(w, errors.New("vault text is required"))
		return
	}
	plaintext, err := decryptVault([]byte(req.VaultText), pw)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, apiResponse{OK: true, Result: string(plaintext)})
}

type browseEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
}

type browseResponse struct {
	OK      bool          `json:"ok"`
	Message string        `json:"message,omitempty"`
	Path    string        `json:"path,omitempty"`
	Parent  string        `json:"parent,omitempty"`
	Entries []browseEntry `json:"entries,omitempty"`
}

// handleBrowse lists a directory's contents so the GUI can offer a
// server-side file picker. It's server-side because a browser's native
// <input type="file"> never exposes the real filesystem path (by design,
// for security) — but since this server only ever listens on 127.0.0.1 and
// every request is already token-gated, walking the local filesystem here
// exposes nothing the file/password-file operations couldn't already reach.
func handleBrowse(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("path")
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = home
		} else {
			dir = "."
		}
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		writeJSON(w, browseResponse{OK: false, Message: err.Error()})
		return
	}
	info, err := os.Stat(absDir)
	if err != nil {
		writeJSON(w, browseResponse{OK: false, Message: err.Error()})
		return
	}
	if !info.IsDir() {
		absDir = filepath.Dir(absDir)
	}

	dirEntries, err := os.ReadDir(absDir)
	if err != nil {
		writeJSON(w, browseResponse{OK: false, Message: err.Error()})
		return
	}

	entries := make([]browseEntry, 0, len(dirEntries))
	for _, e := range dirEntries {
		isDir := e.IsDir()
		fullPath := filepath.Join(absDir, e.Name())
		if e.Type()&os.ModeSymlink != 0 {
			if fi, err := os.Stat(fullPath); err == nil {
				isDir = fi.IsDir()
			}
		}
		entries = append(entries, browseEntry{Name: e.Name(), Path: fullPath, IsDir: isDir})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})

	parent := filepath.Dir(absDir)
	if parent == absDir {
		parent = ""
	}

	writeJSON(w, browseResponse{OK: true, Path: absDir, Parent: parent, Entries: entries})
}

// previewMaxBytes caps how much of a file handlePreview reads, so a huge
// file doesn't get read into memory and shipped to the browser wholesale.
const previewMaxBytes = 64 * 1024

type previewResponse struct {
	OK        bool   `json:"ok"`
	Message   string `json:"message,omitempty"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// handlePreview returns the raw (not decrypted) current content of a file,
// so the GUI can show what's currently on disk at the given path.
func handlePreview(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSON(w, previewResponse{OK: false, Message: "no path given"})
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		writeJSON(w, previewResponse{OK: false, Message: err.Error()})
		return
	}
	if info.IsDir() {
		writeJSON(w, previewResponse{OK: false, Message: "is a directory"})
		return
	}

	f, err := os.Open(path)
	if err != nil {
		writeJSON(w, previewResponse{OK: false, Message: err.Error()})
		return
	}
	defer f.Close()

	buf := make([]byte, previewMaxBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		writeJSON(w, previewResponse{OK: false, Message: err.Error()})
		return
	}

	truncated := n > previewMaxBytes
	if truncated {
		n = previewMaxBytes
	}
	writeJSON(w, previewResponse{OK: true, Content: string(buf[:n]), Truncated: truncated})
}

// resolveGUIPassword is resolvePassword, turning "not found" into an error
// since the GUI has no terminal to fall back to prompting on.
func resolveGUIPassword(password, passwordFile, passwordEnv string) ([]byte, error) {
	pw, ok, err := resolvePassword(password, passwordFile, passwordEnv)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no password given (and ANSIBLE_VAULT_PASSWORD is not set)")
	}
	return pw, nil
}
