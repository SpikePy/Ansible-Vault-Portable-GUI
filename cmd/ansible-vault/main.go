package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"ansible-vault/internal/vault"
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
	"encrypt": "usage: %[1]s encrypt --file/-f <file> [options]\n" +
		"       %[1]s encrypt --inline/-i [name=]<secret> [options]\n\n" +
		"--file/-f overwrites <file> in place (keeping its name and permissions).\n" +
		"--inline/-i encrypts the secret directly and prints an inline YAML\n" +
		"\"!vault |\" block to stdout (name= is optional; omit it for a bare block).\n\n",
	"decrypt": "usage: %[1]s decrypt --file/-f <file> [options]\n" +
		"       %[1]s decrypt --inline/-i <vault-text> [options]\n\n" +
		"--file/-f overwrites <file> in place (keeping its name and permissions).\n" +
		"--inline/-i decrypts a bare vault block or an inline \"name: !vault |\" block\n" +
		"given directly as an argument, and prints the plaintext to stdout.\n\n",
	"view": "usage: %[1]s view --file/-f <file> [options]\n\n" +
		"view always leaves <file> untouched and prints the decrypted content\n" +
		"to stdout.\n\n",
}

const passwordSourceHelp = "The vault password comes from --password/-p, --password-file/-F or\n" +
	"--password-env/-e (checked in that order); if none of those are given,\n" +
	"the ANSIBLE_VAULT_PASSWORD environment variable is used if set, otherwise\n" +
	"an interactive prompt is shown.\n\n" +
	"A long option may be given as \"--flag value\" or \"--flag=value\"; a short\n" +
	"option the same way as \"-f value\" or \"-f=value\". A single dash also\n" +
	"works on a long name (\"-file\"), for backward compatibility.\n\noptions:\n"

// commandFlagOpts describes the --long/-short flag pairs shared by the
// encrypt/decrypt/view subcommands, used both to register them on a
// flag.FlagSet and to render their help text (see printCommandOptions).
func commandFlagOpts(command string) []struct{ short, long, usage string } {
	return []struct{ short, long, usage string }{
		{"f", "file", "file to " + command},
		{"i", "inline", "secret / vault text to " + command + " directly, instead of a file"},
		{"p", "password", "vault password given directly (insecure: visible in shell history / process list); " +
			"defaults to the ANSIBLE_VAULT_PASSWORD environment variable if not set"},
		{"F", "password-file", "read the vault password from this file"},
		{"e", "password-env", "read the vault password from this environment variable"},
	}
}

func printCommandOptions(command string) {
	for _, o := range commandFlagOpts(command) {
		fmt.Fprintf(os.Stderr, "  -%s, --%s string\n    \t%s\n", o.short, o.long, o.usage)
	}
}

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

	if _, ok := commandUsage[command]; !ok {
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", command)
		printTopUsage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet(command, flag.ExitOnError)
	var file, inline, password, passwordFile, passwordEnv string
	fs.StringVar(&file, "file", "", "")
	fs.StringVar(&file, "f", "", "")
	fs.StringVar(&inline, "inline", "", "")
	fs.StringVar(&inline, "i", "", "")
	fs.StringVar(&password, "password", "", "")
	fs.StringVar(&password, "p", "", "")
	fs.StringVar(&passwordFile, "password-file", "", "")
	fs.StringVar(&passwordFile, "F", "", "")
	fs.StringVar(&passwordEnv, "password-env", "", "")
	fs.StringVar(&passwordEnv, "e", "", "")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, commandUsage[command], os.Args[0])
		fmt.Fprint(os.Stderr, passwordSourceHelp)
		printCommandOptions(command)
	}
	fs.Parse(os.Args[2:])

	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	if command == "view" {
		if file == "" || inline != "" {
			fmt.Fprintln(os.Stderr, "error: view requires --file/-f and does not accept --inline/-i")
			fs.Usage()
			os.Exit(2)
		}
		return runView(file, password, passwordFile, passwordEnv)
	}

	if (file == "") == (inline == "") {
		fmt.Fprintln(os.Stderr, "error: specify exactly one of --file/-f or --inline/-i")
		fs.Usage()
		os.Exit(2)
	}

	encrypt := command == "encrypt"
	if file != "" {
		return runFile(file, encrypt, password, passwordFile, passwordEnv)
	}
	return runInline(inline, encrypt, password, passwordFile, passwordEnv)
}

func printTopUsage() {
	fmt.Fprintf(os.Stderr, "usage: %s (encrypt|decrypt|view) --file/-f <file> [options]\n"+
		"       %s (encrypt|decrypt) --inline/-i <secret> [options]\n\n"+
		"run '%s <command> -h' for command-specific help\n", os.Args[0], os.Args[0], os.Args[0])
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
	if encrypt && vault.IsVaultText(raw) {
		return fmt.Errorf("%s is already encrypted; decrypt it first if you want to re-encrypt it", path)
	}

	pw, err := getPassword(password, passwordFile, passwordEnv, encrypt)
	if err != nil {
		return err
	}

	var result []byte
	if encrypt {
		result, err = vault.EncryptVault(raw, pw, true)
	} else {
		result, err = vault.DecryptVault(raw, pw)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(path, result, mode)
}

// runView decrypts path and prints it to stdout without modifying it. path
// can be a full vault file, or a plain file containing one or more inline
// "!vault" blocks (see vault.ViewFile).
func runView(path, password, passwordFile, passwordEnv string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	pw, err := getPassword(password, passwordFile, passwordEnv, false)
	if err != nil {
		return err
	}

	plaintext, err := vault.ViewFile(raw, pw)
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
		vaultText, err := vault.EncryptVault([]byte(secret), pw, true)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(vault.FormatInlineVault(vaultText, name))
		return err
	}

	plaintext, err := vault.DecryptVault([]byte(arg), pw)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plaintext)
	if err == nil {
		_, err = os.Stdout.Write([]byte("\n"))
	}
	return err
}

// getPassword is vault.ResolvePassword plus an interactive, hidden-input
// prompt fallback for the CLI (asked twice and required to match when
// encrypting).
func getPassword(password, passwordFile, passwordEnv string, encrypt bool) ([]byte, error) {
	pw, ok, err := vault.ResolvePassword(password, passwordFile, passwordEnv)
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
