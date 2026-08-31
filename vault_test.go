package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, multiline := range []bool{true, false} {
		t.Run(map[bool]string{true: "multiline", false: "single-line"}[multiline], func(t *testing.T) {
			plaintext := []byte("hello world: secret=42")
			password := []byte("s3cret")

			encrypted, err := encryptVault(plaintext, password, multiline)
			if err != nil {
				t.Fatalf("encryptVault: %v", err)
			}
			if !bytes.HasPrefix(encrypted, []byte(vaultHeader+"\n")) {
				t.Fatalf("encrypted output missing header: %q", encrypted)
			}

			decrypted, err := decryptVault(encrypted, password)
			if err != nil {
				t.Fatalf("decryptVault: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestEncryptMultilineWrapping(t *testing.T) {
	// A long enough secret that the hex body definitely exceeds one
	// lineWidth-character line once wrapped.
	plaintext := bytes.Repeat([]byte("x"), 200)
	password := []byte("s3cret")

	wrapped, err := encryptVault(plaintext, password, true)
	if err != nil {
		t.Fatalf("encryptVault(multiline): %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(wrapped), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected multiple wrapped lines, got %d: %q", len(lines), wrapped)
	}
	for _, l := range lines[1:] {
		if len(l) > lineWidth {
			t.Fatalf("line exceeds lineWidth (%d): %q", lineWidth, l)
		}
	}

	single, err := encryptVault(plaintext, password, false)
	if err != nil {
		t.Fatalf("encryptVault(single-line): %v", err)
	}
	singleLines := strings.Split(strings.TrimRight(string(single), "\n"), "\n")
	if len(singleLines) != 2 {
		t.Fatalf("expected exactly 2 lines (header + one hex line), got %d: %q", len(singleLines), single)
	}

	// Both forms must decrypt to the same plaintext.
	d1, err := decryptVault(wrapped, password)
	if err != nil {
		t.Fatalf("decryptVault(wrapped): %v", err)
	}
	d2, err := decryptVault(single, password)
	if err != nil {
		t.Fatalf("decryptVault(single): %v", err)
	}
	if !bytes.Equal(d1, plaintext) || !bytes.Equal(d2, plaintext) {
		t.Fatalf("decrypted content mismatch")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	encrypted, err := encryptVault([]byte("secret"), []byte("correct"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	if _, err := decryptVault(encrypted, []byte("wrong")); err == nil {
		t.Fatal("expected an error decrypting with the wrong password, got nil")
	}
}

func TestDecryptCorrupted(t *testing.T) {
	encrypted, err := encryptVault([]byte("secret"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	corrupted := bytes.Replace(encrypted, []byte("0"), []byte("1"), 1)
	if bytes.Equal(corrupted, encrypted) {
		t.Skip("corruption did not change the ciphertext; nothing to test")
	}
	if _, err := decryptVault(corrupted, []byte("s3cret")); err == nil {
		t.Fatal("expected an error decrypting corrupted ciphertext, got nil")
	}
}

func TestIsVaultText(t *testing.T) {
	encrypted, err := encryptVault([]byte("secret"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	if !isVaultText(encrypted) {
		t.Error("isVaultText(encrypted) = false, want true")
	}
	if isVaultText([]byte("just: plain\nyaml: content\n")) {
		t.Error("isVaultText(plain yaml) = true, want false")
	}
	if !isVaultText([]byte("app: x\nkey: !vault |\n    $ANSIBLE_VAULT;1.1;AES256\n    deadbeef\n")) {
		t.Error("isVaultText(mixed file with inline vault) = false, want true")
	}
}

func TestFormatInlineVault(t *testing.T) {
	vaultText, err := encryptVault([]byte("hunter2"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	withName := string(formatInlineVault(vaultText, "db_password"))
	if !strings.HasPrefix(withName, "db_password: !vault |\n") {
		t.Errorf("formatInlineVault with name: unexpected prefix: %q", withName)
	}

	withoutName := string(formatInlineVault(vaultText, ""))
	if !strings.HasPrefix(withoutName, "!vault |\n") {
		t.Errorf("formatInlineVault without name: unexpected prefix: %q", withoutName)
	}

	for _, line := range strings.Split(strings.TrimRight(withName, "\n"), "\n")[1:] {
		if !strings.HasPrefix(line, inlineIndent) {
			t.Errorf("line not indented with inlineIndent: %q", line)
		}
	}
}

func TestViewFileFullVault(t *testing.T) {
	plaintext := []byte("just the file content")
	encrypted, err := encryptVault(plaintext, []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	got, err := viewFile(encrypted, []byte("s3cret"))
	if err != nil {
		t.Fatalf("viewFile: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("viewFile = %q, want %q", got, plaintext)
	}
}

func TestViewFileInlineSecrets(t *testing.T) {
	block1, err := encryptVault([]byte("hunter2"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	block2, err := encryptVault([]byte("topsecret123"), []byte("s3cret"), false)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	mixed := "---\n" +
		"app_name: myapp\n" +
		string(formatInlineVault(block1, "db_password")) +
		"port: 8080\n" +
		string(formatInlineVault(block2, "api_key")) +
		"debug: false\n"

	got, err := viewFile([]byte(mixed), []byte("s3cret"))
	if err != nil {
		t.Fatalf("viewFile: %v", err)
	}

	want := "---\n" +
		"app_name: myapp\n" +
		"db_password: hunter2\n" +
		"port: 8080\n" +
		"api_key: topsecret123\n" +
		"debug: false"
	if strings.TrimRight(string(got), "\n") != want {
		t.Fatalf("viewFile mixed content =\n%q\nwant\n%q", got, want)
	}
}

func TestViewFileInlineWrongPasswordAborts(t *testing.T) {
	block, err := encryptVault([]byte("hunter2"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	mixed := "before\n" + string(formatInlineVault(block, "secret")) + "after\n"

	if _, err := viewFile([]byte(mixed), []byte("wrongpassword")); err == nil {
		t.Fatal("expected an error for wrong password, got nil")
	}
}

func TestViewFileNoVaultContent(t *testing.T) {
	if _, err := viewFile([]byte("just: plain\nyaml: content\n"), []byte("s3cret")); err == nil {
		t.Fatal("expected an error when there's no vault content at all, got nil")
	}
}

func TestViewFileBareInlineBlock(t *testing.T) {
	block, err := encryptVault([]byte("just_a_secret"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	raw := "- foo\n" + string(formatInlineVault(block, "")) + "- bar\n"

	got, err := viewFile([]byte(raw), []byte("s3cret"))
	if err != nil {
		t.Fatalf("viewFile: %v", err)
	}
	want := "- foo\njust_a_secret\n- bar"
	if strings.TrimRight(string(got), "\n") != want {
		t.Fatalf("viewFile bare block =\n%q\nwant\n%q", got, want)
	}
}

func TestParseVaultTextMissingHeaderFallback(t *testing.T) {
	encrypted, err := encryptVault([]byte("secret"), []byte("s3cret"), true)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}
	// Strip the header line, keeping just the hex body.
	lines := strings.SplitN(string(encrypted), "\n", 2)
	headerless := []byte(lines[1])

	got, err := decryptVault(headerless, []byte("s3cret"))
	if err != nil {
		t.Fatalf("decryptVault (headerless): %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("decryptVault (headerless) = %q, want %q", got, "secret")
	}
}

func TestResolvePassword(t *testing.T) {
	t.Run("direct value wins", func(t *testing.T) {
		pw, ok, err := resolvePassword("direct", "", "")
		if err != nil || !ok || string(pw) != "direct" {
			t.Fatalf("got (%q, %v, %v), want (\"direct\", true, nil)", pw, ok, err)
		}
	})

	t.Run("password file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "pw.txt")
		if err := os.WriteFile(path, []byte("frompwfile\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pw, ok, err := resolvePassword("", path, "")
		if err != nil || !ok || string(pw) != "frompwfile" {
			t.Fatalf("got (%q, %v, %v), want (\"frompwfile\", true, nil)", pw, ok, err)
		}
	})

	t.Run("environment variable", func(t *testing.T) {
		t.Setenv("TEST_VAULT_PW", "fromenv")
		pw, ok, err := resolvePassword("", "", "TEST_VAULT_PW")
		if err != nil || !ok || string(pw) != "fromenv" {
			t.Fatalf("got (%q, %v, %v), want (\"fromenv\", true, nil)", pw, ok, err)
		}
	})

	t.Run("missing named environment variable errors", func(t *testing.T) {
		os.Unsetenv("TEST_VAULT_PW_MISSING")
		_, ok, err := resolvePassword("", "", "TEST_VAULT_PW_MISSING")
		if err == nil || ok {
			t.Fatalf("got (ok=%v, err=%v), want an error and ok=false", ok, err)
		}
	})

	t.Run("default ANSIBLE_VAULT_PASSWORD fallback", func(t *testing.T) {
		t.Setenv(defaultPasswordEnv, "fromdefaultenv")
		pw, ok, err := resolvePassword("", "", "")
		if err != nil || !ok || string(pw) != "fromdefaultenv" {
			t.Fatalf("got (%q, %v, %v), want (\"fromdefaultenv\", true, nil)", pw, ok, err)
		}
	})

	t.Run("nothing given", func(t *testing.T) {
		os.Unsetenv(defaultPasswordEnv)
		_, ok, err := resolvePassword("", "", "")
		if err != nil || ok {
			t.Fatalf("got (ok=%v, err=%v), want (false, nil)", ok, err)
		}
	})
}
