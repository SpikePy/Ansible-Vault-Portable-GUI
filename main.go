// Command ansible-vault-gui is a windowless local GUI for encrypting and
// decrypting Ansible Vault files and inline "!vault" secrets. It starts a
// local web server silently (no terminal/console output), opens the
// default browser, and exits on its own once that browser tab is closed
// (see server.go's /api/shutdown). On Windows this binary is built with
// -H=windowsgui so double-clicking it never flashes a console window.
package main

import (
	"flag"
	"os"
)

func main() {
	addr := flag.String("addr", defaultAddr, "address to run the local server on")
	flag.Parse()

	if err := run(*addr); err != nil {
		os.Exit(1)
	}
}
