package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// commandUsage is printed above a subcommand's flag defaults, keyed by
// subcommand name.
var commandUsage = map[string]string{
	"encrypt": "usage: %[1]s encrypt -file <file> [options]\n" +
		"       %[1]s encrypt -inline [name=]<secret> [options]\n\n" +
		"-file overwrites <file> in place (keeping its name and permissions).\n" +
		"-inline encrypts the secret directly and prints an inline YAML\n" +
		"\"!vault |\" block to stdout (name= is optional; omit it for a bare block).\n\n",
	"decrypt": "usage: %[1]s decrypt -file <file> [options]\n" +
		"       %[1]s decrypt -inline <vault-text> [options]\n\n" +
		"-file overwrites <file> in place (keeping its name and permissions).\n" +
		"-inline decrypts a bare vault block or an inline \"name: !vault |\" block\n" +
		"given directly as an argument, and prints the plaintext to stdout.\n\n",
	"view": "usage: %[1]s view -file <file> [options]\n\n" +
		"view always leaves <file> untouched and prints the decrypted content\n" +
		"to stdout.\n\n",
}

const passwordSourceHelp = "The vault password comes from -password, -password-file or -password-env\n" +
	"(checked in that order); if none of those are given, the ANSIBLE_VAULT_PASSWORD\n" +
	"environment variable is used if set, otherwise an interactive prompt is shown.\n\noptions:\n"

func run() error {
	if len(os.Args) < 2 {
		printTopUsage()
		os.Exit(2)
	}
	command := os.Args[1]
	if command == "-h" || command == "-help" || command == "--help" {
		printTopUsage()
		os.Exit(0)
	}

	if command == "gui" {
		fs := flag.NewFlagSet("gui", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:0", "address to run the local GUI server on")
		fs.Usage = func() {
			fmt.Fprintf(os.Stderr, "usage: %s gui [-addr host:port]\n\n"+
				"Starts a local web server (bound to 127.0.0.1 by default) serving a\n"+
				"GUI for all encrypt/decrypt/view operations, and opens it in your\n"+
				"default browser. The password is entered in the GUI itself, so none\n"+
				"of -password/-password-file/-password-env apply here.\n\noptions:\n", os.Args[0])
			fs.PrintDefaults()
		}
		fs.Parse(os.Args[2:])
		return runGUI(*addr)
	}

	if _, ok := commandUsage[command]; !ok {
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", command)
		printTopUsage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet(command, flag.ExitOnError)
	file := fs.String("file", "", "file to "+command)
	inline := fs.String("inline", "", "secret / vault text to "+command+" directly, instead of a file")
	password := fs.String("password", "", "vault password given directly (insecure: visible in shell history / process list); "+
		"defaults to the ANSIBLE_VAULT_PASSWORD environment variable if not set")
	passwordFile := fs.String("password-file", "", "read the vault password from this file")
	passwordEnv := fs.String("password-env", "", "read the vault password from this environment variable")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, commandUsage[command], os.Args[0])
		fmt.Fprint(os.Stderr, passwordSourceHelp)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[2:])

	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	if command == "view" {
		if *file == "" || *inline != "" {
			fmt.Fprintln(os.Stderr, "error: view requires -file and does not accept -inline")
			fs.Usage()
			os.Exit(2)
		}
		return runView(*file, *password, *passwordFile, *passwordEnv)
	}

	if (*file == "") == (*inline == "") {
		fmt.Fprintln(os.Stderr, "error: specify exactly one of -file or -inline")
		fs.Usage()
		os.Exit(2)
	}

	encrypt := command == "encrypt"
	if *file != "" {
		return runFile(*file, encrypt, *password, *passwordFile, *passwordEnv)
	}
	return runInline(*inline, encrypt, *password, *passwordFile, *passwordEnv)
}

func printTopUsage() {
	fmt.Fprintf(os.Stderr, "usage: %s (encrypt|decrypt|view) -file <file> [options]\n"+
		"       %s (encrypt|decrypt) -inline <secret> [options]\n"+
		"       %s gui [-addr host:port]\n\n"+
		"run '%s <command> -h' for command-specific help\n", os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

// runFile encrypts or decrypts path in place, keeping its name and
// permissions.
func runFile(path string, encrypt bool, password, passwordFile, passwordEnv string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}
	mode := info.Mode().Perm()
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	pw, err := getPassword(password, passwordFile, passwordEnv, encrypt)
	if err != nil {
		return err
	}

	var result []byte
	if encrypt {
		result, err = encryptVault(raw, pw)
	} else {
		result, err = decryptVault(raw, pw)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(path, result, mode)
}

// runView decrypts path and prints it to stdout without modifying it.
func runView(path, password, passwordFile, passwordEnv string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	pw, err := getPassword(password, passwordFile, passwordEnv, false)
	if err != nil {
		return err
	}

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

// runInline encrypts or decrypts arg directly and prints the result to
// stdout. When encrypting, arg is "name=secret" (or just "secret" to omit
// the "name:" prefix) and the result is rendered as the inline YAML
// "name: !vault |" block ansible-vault itself produces. When decrypting,
// arg is that block (or a bare vault block), and the result is the
// plaintext secret.
func runInline(arg string, encrypt bool, password, passwordFile, passwordEnv string) error {
	pw, err := getPassword(password, passwordFile, passwordEnv, encrypt)
	if err != nil {
		return err
	}

	if encrypt {
		name, secret := "", arg
		if idx := strings.IndexByte(arg, '='); idx >= 0 {
			name, secret = arg[:idx], arg[idx+1:]
		}
		vaultText, err := encryptVault([]byte(secret), pw)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(formatInlineVault(vaultText, name))
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

// resolvePassword resolves the vault password from a CLI flag, a file, an
// environment variable, or the default ANSIBLE_VAULT_PASSWORD environment
// variable (checked in that order, first match wins). ok is false only when
// none of password/passwordFile/passwordEnv/ANSIBLE_VAULT_PASSWORD provided
// a password — the caller decides what to do next (prompt, or report an
// error, depending on whether an interactive terminal is available).
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

// getPassword is resolvePassword plus an interactive, hidden-input prompt
// fallback for the CLI (asked twice and required to match when encrypting).
func getPassword(password, passwordFile, passwordEnv string, encrypt bool) ([]byte, error) {
	pw, ok, err := resolvePassword(password, passwordFile, passwordEnv)
	if err != nil {
		return nil, err
	}
	if ok {
		return pw, nil
	}

	pw, err = promptPassword("Vault password: ")
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

func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return pw, nil
}
