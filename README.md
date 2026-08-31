# ansible-vault

A minimal, dependency-light command-line tool for encrypting and decrypting
[Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html)
files and inline `!vault` secrets — written in Go, with no dependency on
Python or `ansible-core`. Ships as a single static binary for Linux and
Windows.

Implements the standard **AES256** vault cipher (format `1.1`/`1.2`):
PBKDF2-HMAC-SHA256 key derivation, AES-256-CTR encryption, and an
HMAC-SHA256 integrity check — the same scheme `ansible-vault` itself uses.

## Features

- Encrypt / decrypt whole files in place, or view a decrypted file without
  touching it
- Encrypt / decrypt a single secret inline, as the
  `name: !vault |` block format Ansible uses for individual vaulted
  variables embedded in an otherwise plaintext YAML file
- A simple local GUI (`ansible-vault gui`) covering the same operations,
  for when you'd rather not use the CLI
- Password via CLI flag, file, environment variable, the standard
  `ANSIBLE_VAULT_PASSWORD` environment variable, or an interactive
  (hidden-input) prompt
- No runtime dependencies — a single static binary
- Cross-compiles cleanly for Linux and Windows

## Installation

### Build from source

Requires Go 1.21+.

```sh
git clone <this-repo>
cd ansible-vault
go build -o ansible-vault .
```

### Cross-compile

```sh
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/ansible-vault .
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/ansible-vault.exe .
```

### CI

`.gitlab-ci.yml` cross-compiles both binaries on every push and publishes
them as pipeline job artifacts (30-day expiry) — download them from the
pipeline's **Job artifacts** panel. Compiled binaries aren't committed to
the repo (`dist/` is gitignored); build from source or grab them from CI.

## Usage

```
usage: ansible-vault (encrypt|decrypt|view) -file <file> [options]
       ansible-vault (encrypt|decrypt) -inline <secret> [options]
       ansible-vault gui [-addr host:port]
```

Every invocation starts with a command — `encrypt`, `decrypt`, `view`, or
`gui` — followed by either `-file <path>` or (for `encrypt`/`decrypt`)
`-inline <secret>`, plus any password options.

- `encrypt -file` / `decrypt -file` always overwrite `<file>` in place,
  keeping its name and file permissions.
- `view -file` always leaves `<file>` untouched and prints the decrypted
  content to stdout. `view` does not accept `-inline`.
- `encrypt -inline` / `decrypt -inline` take the secret directly as an
  argument and always print the result to stdout.
- Running `ansible-vault` with **no arguments** starts the GUI (same as
  `gui` with no `-addr`) — handy for a desktop shortcut/launcher.

Run `ansible-vault -h` for this summary, or `ansible-vault <command> -h`
for command-specific help.

### Encrypting and decrypting a file

```sh
# Encrypt a file in place
ansible-vault encrypt -file secrets.yml

# Decrypt a file in place
ansible-vault decrypt -file secrets.yml

# View decrypted content without modifying the file
ansible-vault view -file secrets.yml
```

### Inline secrets

Ansible supports vault-encrypting a single variable inside an otherwise
plaintext file, using an inline `!vault` block:

```yaml
db_password: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    663834396532363364626265666530...
```

`encrypt -inline` generates that block; `decrypt -inline` reads it back:

```sh
# name=secret produces "name: !vault |"
ansible-vault encrypt -inline "db_password=hunter2"

# just "secret" (no name=) produces a bare "!vault |" block
ansible-vault encrypt -inline "hunter2"

# decrypt -inline finds the $ANSIBLE_VAULT header wherever it appears,
# so you can paste the block as-is — with its "name:" prefix, at whatever
# indentation the source file used, or even with the header line itself
# stripped off
ansible-vault decrypt -inline "db_password: !vault |
    \$ANSIBLE_VAULT;1.1;AES256
    663834396532363364626265666530..."
```

### GUI

```sh
ansible-vault gui
```

Starts a small local web server (bound to `127.0.0.1` on a fixed port,
`47990`, by default) serving a page with all the same operations —
encrypt / decrypt a file, encrypt / decrypt an inline secret — and opens
it in your default browser. Everything runs locally: the server only
listens on loopback, every request must carry a random per-session token
embedded in the page, and no file path or secret is ever sent anywhere
but to your own machine's `localhost`. Each form has a single password
field plus a "Password" / "Password file" / "Environment variable" radio
choice next to it, mirroring the CLI's `-password` / `-password-file` /
`-password-env`; leaving it blank falls back to `ANSIBLE_VAULT_PASSWORD`,
same as the CLI.

The File tab has an Encrypt/Decrypt radio and a "just show the decrypted
content, don't overwrite the file" checkbox — check it before running
Decrypt to preview a file's content without touching it (equivalent to
the CLI's `view`); leave it unchecked and Decrypt overwrites the file in
place, same as `decrypt -file`. Encrypt always overwrites.

The Inline tab's Encrypt mode has a "wrap encrypted output at 80
characters per line" checkbox (checked by default) — uncheck it to get
the whole hex body as a single line instead of the usual 80-char-wrapped
block. Both forms decrypt identically either way.

The file-path field and the password field, when set to "Password file"
mode, both have a **Browse…** button that opens a server-side directory
browser — a browser's native file picker can't expose real filesystem
paths for security reasons, so the GUI's own Go process lists directories
for you instead and fills in the full path when you click a file. You can
still just type or paste a path directly if you prefer. The password
field also has a show/hide toggle when in "Password" mode.

Password fields use `autocomplete="new-password"`, which stops browsers'
own password managers from offering to save or autofill them. Third-party
password-manager extensions (Bitwarden, 1Password, etc.) generally ignore
that hint by design and may still prompt to save — that's a limitation of
the page having no reliable way to override another program's UI, not
something worth fighting; just dismiss the prompt if it appears.

As you type or pick a file path, the File tab shows that file's current
raw content (up to 64 KiB) in a read-only box below the path field, so
you can see what's actually on disk — plaintext or an existing vault
block — before deciding what to run. It refreshes automatically after
encrypt/decrypt.

**Settings are remembered.** Every field — including passwords — is saved
to the browser's local storage as you type and restored the next time you
open the page, so you don't have to re-enter everything each run. This is
why the port defaults to a fixed value rather than a random one: browser
storage is tied to the page's origin (host+port), so it would be
forgotten on the next run if the port changed every time. This does mean
passwords sit in plaintext in that browser profile's local storage
indefinitely — fine for a personal machine, worth keeping in mind on a
shared one. Only one GUI instance can use a given port at a time; run a
second one with `-addr 127.0.0.1:<other-port>` (its browser storage, and
therefore its remembered settings, will be separate from the default
instance's).

Stop the GUI with Ctrl+C in the terminal it's running in.

### Supplying the password

Checked in this order:

1. `-password <value>` — given directly (insecure: visible in shell
   history and process list)
2. `-password-file <path>` — read from a file
3. `-password-env <VAR>` — read from the named environment variable
4. the `ANSIBLE_VAULT_PASSWORD` environment variable, if set
5. an interactive, hidden-input prompt (asked twice and confirmed when
   encrypting)

```sh
ansible-vault decrypt -file secrets.yml -password-file ~/.vault_pass
ANSIBLE_VAULT_PASSWORD=hunter2 ansible-vault view -file secrets.yml
```

## Notes

- Only the AES256 cipher (vault format `1.1`/`1.2`) is supported — this is
  the default and by far the most common Ansible Vault format.
- Wrong-password and corrupted-file cases are both caught by the HMAC
  check before any plaintext is produced.
- `encrypt -file` (CLI and GUI) refuses to run if the file already looks
  encrypted (starts with an `$ANSIBLE_VAULT;` header), so it never
  double-encrypts a file by mistake — decrypt it first if you actually
  want to re-encrypt it (e.g. with a new password).
