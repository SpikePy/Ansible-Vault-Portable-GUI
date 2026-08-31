// Command ansible-vault-gui is a windowless launcher for the ansible-vault
// GUI: it starts the local server silently (no terminal/console output),
// opens the default browser, and exits on its own once that browser tab is
// closed (see internal/guiserver's /api/shutdown). On Windows this binary
// is built with -H=windowsgui so double-clicking it never flashes a
// console window, unlike the main ansible-vault(.exe) binary which needs a
// real console for its CLI commands.
package main

import (
	"flag"
	"os"

	"ansible-vault/internal/guiserver"
)

func main() {
	addr := flag.String("addr", guiserver.DefaultAddr, "address to run the local GUI server on")
	flag.Parse()

	if err := guiserver.Run(*addr, nil); err != nil {
		os.Exit(1)
	}
}
