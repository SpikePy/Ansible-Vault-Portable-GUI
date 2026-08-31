package main

// Implements the Ansible Vault AES256 cipher (format 1.1/1.2):
// PBKDF2-HMAC-SHA256 key derivation, AES-256-CTR encryption, and an
// HMAC-SHA256 integrity check.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	vaultHeader        = "$ANSIBLE_VAULT;1.1;AES256"
	vaultHeaderPrefix  = "$ANSIBLE_VAULT;"
	pbkdf2Iterations   = 10000
	keyLength          = 32
	ivLength           = 16
	saltLength         = 32
	lineWidth          = 80
	inlineIndent       = "    " // 4 spaces of indentation for "name: !vault |" blocks
	defaultPasswordEnv = "ANSIBLE_VAULT_PASSWORD"
)

func decryptVault(raw []byte, password []byte) ([]byte, error) {
	salt, expectedHMAC, ciphertext, err := parseVaultText(raw)
	if err != nil {
		return nil, err
	}
	return decryptVaultParts(salt, expectedHMAC, ciphertext, password)
}

// decryptVaultParts is decryptVault's core, taking the already-parsed salt,
// HMAC and ciphertext directly. Split out so decryptInlineVaults can decrypt
// several separately-parsed blocks within one larger file without having to
// glue each one back into a full vault-text string first.
func decryptVaultParts(salt, expectedHMAC, ciphertext, password []byte) ([]byte, error) {
	derived := pbkdf2.Key(password, salt, pbkdf2Iterations, 2*keyLength+ivLength, sha256.New)
	aesKey := derived[:keyLength]
	hmacKey := derived[keyLength : 2*keyLength]
	iv := derived[2*keyLength : 2*keyLength+ivLength]

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)
	if !hmac.Equal(mac.Sum(nil), expectedHMAC) {
		return nil, errors.New("HMAC verification failed: wrong password or corrupted file")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	padded := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(padded, ciphertext)

	return unpad(padded)
}

// viewFile decrypts raw for a non-destructive preview: if the whole file is
// a standard vault (starts with the $ANSIBLE_VAULT header), it's decrypted
// as usual. Otherwise, raw is scanned for one or more inline "name: !vault
// |" blocks (the format for a single vault-encrypted variable embedded in
// an otherwise plaintext file) and each one found is replaced by its
// decrypted plaintext value, leaving the rest of the file untouched.
func viewFile(raw []byte, password []byte) ([]byte, error) {
	firstNonBlank := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			firstNonBlank = t
			break
		}
	}
	if strings.HasPrefix(firstNonBlank, vaultHeaderPrefix) {
		return decryptVault(raw, password)
	}

	out, count, err := decryptInlineVaults(raw, password)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("no vault content found: not a full vault file, and no inline \"!vault\" blocks were found")
	}
	return out, nil
}

// decryptInlineVaults scans raw for inline "!vault |" YAML blocks (a line
// containing "!vault" followed by an indented $ANSIBLE_VAULT envelope) and
// returns raw with each one replaced by its decrypted plaintext value,
// preserving whatever preceded "!vault" on that line (typically "key: ").
// count is how many blocks were found and decrypted; everything else in
// raw is passed through unchanged. A block that merely looks like one
// (e.g. the tag appears without a valid envelope following it) is left as
// found. A genuine decrypt failure (wrong password, bad HMAC) aborts and
// returns that error rather than silently skipping the block.
func decryptInlineVaults(raw []byte, password []byte) ([]byte, int, error) {
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	var out []string
	count := 0

	for i := 0; i < len(lines); {
		line := lines[i]
		if !strings.Contains(line, "!vault") {
			out = append(out, line)
			i++
			continue
		}

		j := i + 1
		for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		if j >= len(lines) || !strings.HasPrefix(strings.TrimSpace(lines[j]), vaultHeaderPrefix) {
			out = append(out, line)
			i++
			continue
		}

		k := j + 1
		for k < len(lines) && isHexString(strings.TrimSpace(lines[k])) {
			k++
		}
		if k == j+1 {
			out = append(out, line)
			i++
			continue
		}

		blockText := strings.TrimSpace(lines[j]) + "\n" + strings.Join(lines[j+1:k], "\n") + "\n"
		salt, expectedHMAC, ciphertext, perr := parseVaultText([]byte(blockText))
		if perr != nil {
			out = append(out, line)
			i++
			continue
		}
		plaintext, derr := decryptVaultParts(salt, expectedHMAC, ciphertext, password)
		if derr != nil {
			return nil, count, derr
		}

		prefix := strings.TrimRight(line[:strings.Index(line, "!vault")], " \t")
		if prefix != "" {
			prefix += " "
		}
		out = append(out, prefix+string(plaintext))
		count++
		i = k
	}

	return []byte(strings.Join(out, "\n")), count, nil
}

// encryptVault encrypts plaintext into the standard vault text format. When
// multiline is true, the hex body is wrapped at lineWidth characters per
// line (the format ansible-vault itself produces); when false, the entire
// hex body is emitted as a single line. Both are valid, equivalent input to
// decryptVault/parseVaultText — this only affects how the output looks.
func encryptVault(plaintext []byte, password []byte, multiline bool) ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	derived := pbkdf2.Key(password, salt, pbkdf2Iterations, 2*keyLength+ivLength, sha256.New)
	aesKey := derived[:keyLength]
	hmacKey := derived[keyLength : 2*keyLength]
	iv := derived[2*keyLength : 2*keyLength+ivLength]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, padded)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)

	body := hex.EncodeToString(salt) + "\n" + hex.EncodeToString(mac.Sum(nil)) + "\n" + hex.EncodeToString(ciphertext)
	hexBody := hex.EncodeToString([]byte(body))

	var out bytes.Buffer
	out.WriteString(vaultHeader)
	out.WriteByte('\n')
	if multiline {
		out.WriteString(wrapLines(hexBody, lineWidth))
	} else {
		out.WriteString(hexBody)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

func wrapLines(s string, width int) string {
	var sb strings.Builder
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(s[i:end])
	}
	return sb.String()
}

// isVaultText reports whether raw already looks like an encrypted vault
// (any line starts with the $ANSIBLE_VAULT; header prefix). Both this
// tool's own encryptVault output and real ansible-vault files always
// include that header line, so this is enough to catch "encrypt" being
// pointed at an already-encrypted file before it double-encrypts it.
func isVaultText(raw []byte) bool {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), vaultHeaderPrefix) {
			return true
		}
	}
	return false
}

// parseVaultText parses the $ANSIBLE_VAULT envelope. The body, once
// hex-decoded, is itself three newline-separated hex strings:
// salt, hmac, ciphertext (see lib/ansible/parsing/vault in ansible-core).
//
// The header is located by scanning rather than assumed to be on line 0, and
// every body line is trimmed independently, so this also accepts an inline
// "name: !vault |" (or bare "!vault |") YAML block copy-pasted at whatever
// indentation the source file used.
func parseVaultText(raw []byte) (salt, expectedHMAC, ciphertext []byte, err error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	allLines := strings.Split(strings.TrimRight(text, "\n"), "\n")

	headerIdx := -1
	for i, line := range allLines {
		if strings.HasPrefix(strings.TrimSpace(line), vaultHeaderPrefix) {
			headerIdx = i
			break
		}
	}

	// bodyStart is where the hex body lines begin. If there's no
	// $ANSIBLE_VAULT header at all (e.g. someone pasted just the hex body,
	// or copied a block with the header line trimmed off), fall back to
	// skipping past any leading non-hex lines and assume the only format
	// this tool supports: version 1.1, cipher AES256.
	bodyStart := 0
	if headerIdx != -1 {
		header := strings.TrimSpace(allLines[headerIdx])
		parts := strings.Split(header, ";")
		if len(parts) < 3 {
			return nil, nil, nil, fmt.Errorf("malformed vault header: %q", header)
		}
		version, cipherName := parts[1], parts[2]
		if version != "1.1" && version != "1.2" {
			return nil, nil, nil, fmt.Errorf("unsupported vault format version %q", version)
		}
		if cipherName != "AES256" {
			return nil, nil, nil, fmt.Errorf("unsupported cipher %q (only AES256 is supported)", cipherName)
		}
		bodyStart = headerIdx + 1
	} else {
		for i, line := range allLines {
			if isHexString(strings.TrimSpace(line)) {
				bodyStart = i
				break
			}
		}
	}

	var hexLines []string
	for _, line := range allLines[bodyStart:] {
		trimmed := strings.TrimSpace(line)
		if !isHexString(trimmed) {
			break
		}
		hexLines = append(hexLines, trimmed)
	}
	if len(hexLines) == 0 {
		return nil, nil, nil, errors.New("no vault body found: expected either an $ANSIBLE_VAULT header or a hex-encoded vault body")
	}

	body, err := hex.DecodeString(strings.Join(hexLines, ""))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding vault body: %w", err)
	}

	bodyParts := strings.SplitN(string(body), "\n", 3)
	if len(bodyParts) != 3 {
		return nil, nil, nil, errors.New("malformed vault body")
	}

	salt, err = hex.DecodeString(bodyParts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding salt: %w", err)
	}
	expectedHMAC, err = hex.DecodeString(bodyParts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding hmac: %w", err)
	}
	ciphertext, err = hex.DecodeString(bodyParts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	return salt, expectedHMAC, ciphertext, nil
}

// isHexString reports whether s is non-empty and consists entirely of hex
// digits. Used to find where a vault body's hex lines end when they're
// embedded in a larger pasted block (e.g. more YAML keys following an
// inline "name: !vault |" value, with no blank line in between).
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty plaintext")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// formatInlineVault renders vaultText (the output of encryptVault) as the
// "name: !vault |" block style ansible-vault itself produces.
func formatInlineVault(vaultText []byte, name string) []byte {
	lines := strings.Split(strings.TrimRight(string(vaultText), "\n"), "\n")
	var out strings.Builder
	if name != "" {
		out.WriteString(name)
		out.WriteString(": ")
	}
	out.WriteString("!vault |\n")
	for _, line := range lines {
		out.WriteString(inlineIndent)
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

// resolvePassword resolves the vault password from a direct value, a file,
// an environment variable, or the default ANSIBLE_VAULT_PASSWORD
// environment variable (checked in that order, first match wins). ok is
// false only when none of password/passwordFile/passwordEnv/
// ANSIBLE_VAULT_PASSWORD provided a password.
func resolvePassword(password, passwordFile, passwordEnv string) (pw []byte, ok bool, err error) {
	switch {
	case password != "":
		return []byte(password), true, nil
	case passwordFile != "":
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return nil, false, fmt.Errorf("reading password file: %w", err)
		}
		return bytes.TrimRight(data, "\r\n"), true, nil
	case passwordEnv != "":
		val, ok := os.LookupEnv(passwordEnv)
		if !ok {
			return nil, false, fmt.Errorf("environment variable %s is not set", passwordEnv)
		}
		return []byte(val), true, nil
	default:
		if val, ok := os.LookupEnv(defaultPasswordEnv); ok {
			return []byte(val), true, nil
		}
		return nil, false, nil
	}
}
