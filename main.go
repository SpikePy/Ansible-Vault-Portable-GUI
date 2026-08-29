package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	vaultHeader        = "$ANSIBLE_VAULT;1.1;AES256"
	vaultHeaderPrefix  = "$ANSIBLE_VAULT;"
	pbkdf2Iterations   = 10000
	keyLength          = 32
	ivLength           = 16
	saltLength         = 32
	lineWidth          = 80
	inlineIndent       = "          " // matches the indentation ansible-vault itself uses for "name: !vault |" blocks
	defaultPasswordEnv = "ANSIBLE_VAULT_PASSWORD"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	encrypt := flag.Bool("encrypt", false, "encrypt the input file")
	decrypt := flag.Bool("decrypt", false, "decrypt the input file")
	view := flag.Bool("view", false, "decrypt the input file and print it to stdout, without modifying it")
	encryptInline := flag.String("encrypt-inline", "", "encrypt a secret into an inline YAML \"!vault |\" block; value is \"name=secret\" or just \"secret\"")
	decryptInline := flag.String("decrypt-inline", "", "decrypt an inline \"name: !vault |\" YAML block (or bare vault text) and print the plaintext")
	password := flag.String("password", "", "vault password given directly (insecure: visible in shell history / process list); "+
		"defaults to the ANSIBLE_VAULT_PASSWORD environment variable if not set")
	passwordFile := flag.String("password-file", "", "read the vault password from this file")
	passwordEnv := flag.String("password-env", "", "read the vault password from this environment variable")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s (-encrypt|-decrypt) [options] <file>\n"+
			"       %s -view [options] <file>\n"+
			"       %s -encrypt-inline [options] [name=]<secret>\n"+
			"       %s -decrypt-inline [options] <vault-text>\n\n"+
			"-encrypt/-decrypt always overwrite <file> in place (keeping its name\n"+
			"and permissions). -view always leaves <file> untouched and prints the\n"+
			"decrypted content to stdout.\n"+
			"-encrypt-inline/-decrypt-inline take the secret directly as an argument\n"+
			"and always print the result to stdout.\n\n"+
			"The vault password comes from -password, -password-file or -password-env\n"+
			"(checked in that order); if none of those are given, the ANSIBLE_VAULT_PASSWORD\n"+
			"environment variable is used if set, otherwise an interactive prompt is shown.\n\noptions:\n",
			os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	switch {
	case *encryptInline != "" && *decryptInline != "":
		fmt.Fprintln(os.Stderr, "error: specify only one of -encrypt-inline or -decrypt-inline")
		flag.Usage()
		os.Exit(2)
	case *encryptInline != "":
		return runEncryptInline(*encryptInline, *password, *passwordFile, *passwordEnv)
	case *decryptInline != "":
		return runDecryptInline(*decryptInline, *password, *passwordFile, *passwordEnv)
	}

	modeCount := 0
	for _, set := range []bool{*encrypt, *decrypt, *view} {
		if set {
			modeCount++
		}
	}
	if modeCount != 1 {
		fmt.Fprintln(os.Stderr, "error: specify exactly one of -encrypt, -decrypt or -view")
		flag.Usage()
		os.Exit(2)
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	inputPath := flag.Arg(0)
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}
	inputMode := info.Mode().Perm()
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	pw, err := getPassword(*password, *passwordFile, *passwordEnv, *encrypt)
	if err != nil {
		return err
	}

	if *view {
		plaintext, err := decryptVault(raw, pw)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(plaintext)
		if err == nil {
			_, err = os.Stdout.Write([]byte("\n"))
		}
		return err
	}

	var result []byte
	if *encrypt {
		result, err = encryptVault(raw, pw)
	} else {
		result, err = decryptVault(raw, pw)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(inputPath, result, inputMode)
}

// runEncryptInline encrypts a secret and prints it as an inline YAML
// "name: !vault |" block, the format ansible expects for a single
// vault-encrypted variable embedded in an otherwise plaintext file. arg is
// "name=secret", or just "secret" to omit the "name:" prefix (matching
// `ansible-vault encrypt_string` with/without --name).
func runEncryptInline(arg, password, passwordFile, passwordEnv string) error {
	name, secret := "", arg
	if idx := strings.IndexByte(arg, '='); idx >= 0 {
		name, secret = arg[:idx], arg[idx+1:]
	}

	pw, err := getPassword(password, passwordFile, passwordEnv, true)
	if err != nil {
		return err
	}
	vaultText, err := encryptVault([]byte(secret), pw)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(formatInlineVault(vaultText, name))
	return err
}

// runDecryptInline decrypts an inline "name: !vault |" YAML block (or a
// bare $ANSIBLE_VAULT block, at any indentation) and prints the plaintext.
func runDecryptInline(arg, password, passwordFile, passwordEnv string) error {
	pw, err := getPassword(password, passwordFile, passwordEnv, false)
	if err != nil {
		return err
	}
	plaintext, err := decryptVault([]byte(arg), pw)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(plaintext)
	if err == nil {
		_, err = os.Stdout.Write([]byte("\n"))
	}
	return err
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

// getPassword resolves the vault password from a CLI flag, a file, an
// environment variable, the default ANSIBLE_VAULT_PASSWORD environment
// variable, or an interactive prompt (checked in that order). When
// encrypting via an interactive prompt, it asks twice and requires both
// entries to match.
func getPassword(password, passwordFile, passwordEnv string, encrypt bool) ([]byte, error) {
	switch {
	case password != "":
		return []byte(password), nil
	case passwordFile != "":
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("reading password file: %w", err)
		}
		return bytes.TrimRight(data, "\r\n"), nil
	case passwordEnv != "":
		val, ok := os.LookupEnv(passwordEnv)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", passwordEnv)
		}
		return []byte(val), nil
	default:
		if val, ok := os.LookupEnv(defaultPasswordEnv); ok {
			return []byte(val), nil
		}
		pw, err := promptPassword("Vault password: ")
		if err != nil {
			return nil, err
		}
		if encrypt {
			confirm, err := promptPassword("Confirm vault password: ")
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(pw, confirm) {
				return nil, errors.New("passwords do not match")
			}
		}
		return pw, nil
	}
}

func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return pw, nil
}

func decryptVault(raw []byte, password []byte) ([]byte, error) {
	salt, expectedHMAC, ciphertext, err := parseVaultText(raw)
	if err != nil {
		return nil, err
	}

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

func encryptVault(plaintext []byte, password []byte) ([]byte, error) {
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
	out.WriteString(wrapLines(hexBody, lineWidth))
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
