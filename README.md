# Ansible-Vault Portable GUI

![Ansible-Vault Portable GUI screenshot](docs/gui-screenshot.png)

A minimal, dependency-light local GUI for encrypting and decrypting
[Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html)
files and inline `!vault` secrets — written in Go, with no dependency on
Python or `ansible-core`. Ships as a single static binary for Linux,
Windows, and macOS: `ansible-vault-portable-gui`.

Implements the standard **AES256** vault cipher (format `1.1`/`1.2`):
PBKDF2-HMAC-SHA256 key derivation, AES-256-CTR encryption, and an
HMAC-SHA256 integrity check — the same scheme `ansible-vault` itself uses.

## Features

- Encrypt / decrypt whole files in place, or view a decrypted file without
  touching it
- Encrypt / decrypt a single secret inline, as the
  `name: !vault |` block format Ansible uses for individual vaulted
  variables embedded in an otherwise plaintext YAML file
- Runs entirely locally: a small web server bound to `127.0.0.1`, opened
  in your default browser — no data ever leaves the machine
- No console/terminal window on Windows, and no window left running
  after you're done — it starts silently and stops itself when its
  browser tab is closed
- Password via the form, a file, an environment variable, or the standard
  `ANSIBLE_VAULT_PASSWORD` environment variable
- No runtime dependencies — a single static binary
- Cross-compiles cleanly for Linux, Windows, and macOS

## Installation

### Build from source

Requires Go 1.21+.

```sh
git clone <this-repo>
cd ansible-vault-portable-gui
go build -o ansible-vault-portable-gui .
```

### Cross-compile

The Windows build additionally needs `-H=windowsgui` (a linker flag that
marks the binary as a GUI-subsystem app, so Windows never allocates a
console for it, not even briefly).

```sh
GOOS=linux   GOARCH=amd64   go build -ldflags="-s -w" -o dist/ansible-vault-portable-gui .
GOOS=windows GOARCH=amd64   go build -ldflags="-s -w -H=windowsgui" -o dist/ansible-vault-portable-gui.exe .
GOOS=darwin  GOARCH=amd64   go build -ldflags="-s -w" -o dist/ansible-vault-portable-gui-macos-amd64 .
GOOS=darwin  GOARCH=arm64   go build -ldflags="-s -w" -o dist/ansible-vault-portable-gui-macos-arm64 .
```

### CI

`.gitlab-ci.yml` runs `go vet`/`go test`, then cross-compiles all four
binaries (Linux, Windows, macOS Intel, macOS Apple Silicon) on every push
and publishes them as pipeline job artifacts (30-day expiry) — download
them from the pipeline's **Job artifacts** panel. Compiled binaries
aren't committed to the repo (`dist/` is gitignored); build from source
or grab them from CI.

`.github/workflows/release.yml` automates actual releases: pushing a tag
matching `v*` (e.g. `v4.1.0`) runs the same vet/test/cross-compile steps,
then creates a GitHub Release for that tag with all four binaries
attached and auto-generated release notes — no manual `gh release
create` needed anymore.

### Tests

```sh
go test ./...
```

Covers the vault crypto/parsing logic (`vault_test.go`), the atomic
file-write helper (`atomicwrite_test.go`), and the HTTP API handlers
(`server_test.go`).

## Usage

```sh
ansible-vault-portable-gui
```

Or, on Windows, just double-click `ansible-vault-portable-gui.exe`. Either way, a
local server starts (bound to `127.0.0.1` on a fixed port, `47990`, by
default) and opens in your default browser — no arguments needed for
everyday use.

Everything runs locally: the server only listens on loopback, every
request must carry a random per-session token embedded in the page, and
no file path or secret is ever sent anywhere but to your own machine's
`localhost`. Each form has a single password field plus a "Password" /
"Password file" / "Environment variable" radio choice next to it; leaving
it blank falls back to the `ANSIBLE_VAULT_PASSWORD` environment variable.

**The server stops itself when its browser tab is actually closed** (or
navigated away from), so there's nothing to clean up manually — no
window, no console, no background process left running. A reload
(F5/Ctrl+R) does *not* stop it — the page briefly asks the server to shut
down on the way out, same as a real close, but then cancels that request
as soon as it comes back up in the same tab, so refreshing the page is
safe. Ctrl+C also works if you're watching the terminal it was launched
from.

Only one instance can use a given port at a time; run a second one with
`ansible-vault-portable-gui -addr 127.0.0.1:<other-port>` (its browser storage,
and therefore its remembered settings, will be separate from the default
instance's).

### File tab

Has an Encrypt/Decrypt radio and an "Enable file overwrite" checkbox,
**unchecked by default** — Decrypt previews the file's content without
touching it unless you check the box, which then makes Decrypt overwrite
the file in place instead. Encrypt always overwrites, and refuses to run
if the file already looks encrypted (starts with an `$ANSIBLE_VAULT;`
header), so it never double-encrypts a file by mistake — decrypt it first
if you actually want to re-encrypt it (e.g. with a new password).

Also works on a file that *isn't* fully vault-encrypted but contains one
or more inline `name: !vault |` secrets (see "Inline secrets" below) —
each one found gets decrypted for display (as `name: <value>`), everything
else in the file is shown unchanged, and the file itself is never
modified. If a decrypt fails (wrong password), the whole preview fails
rather than showing a partially-decrypted result. The checkbox is
automatically forced off and locked whenever the loaded file looks like
this — such a file can only ever be previewed, never
decrypted-and-overwritten in place.

When Encrypt is selected and the password source is set to "Password", a
**🎲 Generate** button appears next to the password field — click it for a
random 24-character password (drawn from `crypto.getRandomValues`,
excluding visually-ambiguous characters like `0`/`O` and `1`/`l`/`I`). It
fills the field and reveals it so you can see and copy what was generated.
The same button is available on the Inline tab's password field.

As you type or pick a file path, the tab shows that file's current raw
content (up to 64 KiB) in a read-only box below the path field, so you
can see what's actually on disk — plaintext or an existing vault block —
before deciding what to run. It refreshes automatically after
encrypt/decrypt.

The file-path field and the password field, when set to "Password file"
mode, both have a **Browse…** button that opens a server-side directory
browser — a browser's native file picker can't expose real filesystem
paths for security reasons, so the app's own Go process lists directories
for you instead and fills in the full path when you click a file. You can
still just type or paste a path directly if you prefer.

### Inline secrets

Ansible supports vault-encrypting a single variable inside an otherwise
plaintext file, using an inline `!vault` block:

```yaml
db_password: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    663834396532363364626265666530...
```

The Inline tab's Encrypt mode produces exactly that block: give it a
variable name (optional — leave it empty for a bare `!vault |` block
without a `name:` prefix) and a secret, and it's encrypted directly with
no file involved. Decrypt mode reads it back — paste the block as-is,
with or without its `name:` prefix, at whatever indentation the source
file used, or even with the header line itself stripped off; it finds the
`$ANSIBLE_VAULT` header wherever it appears.

Encrypt mode also has a "wrap encrypted output at 80 characters per line"
checkbox (checked by default) — uncheck it to get the whole hex body as a
single line instead of the usual 80-char-wrapped block. Both forms
decrypt identically either way.

## Supplying the password

Checked in this order:

1. The password field, typed directly (has a show/hide toggle)
2. A password file (has a **Browse…** button, same as the file path field)
3. An environment variable name
4. The `ANSIBLE_VAULT_PASSWORD` environment variable, if none of the
   above are set

Password fields use `autocomplete="new-password"`, which stops browsers'
own password managers from offering to save or autofill them. Third-party
password-manager extensions (Bitwarden, 1Password, etc.) generally ignore
that hint by design and may still prompt to save — that's a limitation of
the page having no reliable way to override another program's UI, not
something worth fighting; just dismiss the prompt if it appears.

The Password / Password file / Environment variable radio choice shares a
single input field, but each of the three remembers its own separate
value — switching from "Password" to "Password file" and back doesn't
lose or mix up what you'd typed in either one.

The file path field and the password-file field both offer a dropdown of
the last 5 distinct paths used (shown when you click into the field) —
browser-native autocomplete suggestions, not a custom widget.

**Settings are remembered.** Every field — including passwords — is saved
to the browser's local storage as you type and restored the next time you
open the page, so you don't have to re-enter everything each run. This is
why the port defaults to a fixed value rather than a random one: browser
storage is tied to the page's origin (host+port), so it would be
forgotten on the next run if the port changed every time. This does mean
passwords sit in plaintext in that browser profile's local storage
indefinitely — fine for a personal machine, worth keeping in mind on a
shared one.

## Notes

- Only the AES256 cipher (vault format `1.1`/`1.2`) is supported — this is
  the default and by far the most common Ansible Vault format.
- Wrong-password and corrupted-file cases are both caught by the HMAC
  check before any plaintext is produced.
- File writes are atomic: the new content is written to a temp file in the
  same directory and renamed into place, so a crash or a full disk mid-write
  can't leave a truncated or corrupted file behind — the original either
  stays fully intact or is fully replaced, never partially.
