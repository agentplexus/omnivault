// Package main provides the omnivault CLI.
package main

import (
	"fmt"
	"os"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "unlock":
		err = cmdUnlock(args)
	case "lock":
		err = cmdLock(args)
	case "status":
		err = cmdStatus(args)
	case "get":
		err = cmdGet(args)
	case "set":
		err = cmdSet(args)
	case "list", "ls":
		err = cmdList(args)
	case "delete", "rm":
		err = cmdDelete(args)
	case "search":
		err = cmdSearch(args)
	case "export":
		err = cmdExport(args)
	case "import":
		err = cmdImport(args)
	case "passwd":
		err = cmdPasswd(args)
	case "daemon":
		err = cmdDaemon(args)
	case "version":
		fmt.Printf("omnivault version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd) //nolint:gosec // G705: stderr output, not HTML
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`omnivault - Secure local secret management

Usage:
  omnivault <command> [arguments]

Vault Commands:
  init              Initialize a new vault with a master password
  unlock            Unlock the vault
  lock              Lock the vault
  status            Show vault and daemon status
  passwd            Change the master password

Secret Commands:
  get <path>        Get a secret value
    --format        Output format: text, json, yaml, shell (default: text)
    --field         Extract a specific field from the secret
  set <path> [val]  Set a secret (prompts for value if not provided)
  list [prefix]     List secrets
    --format        Output format: text, json, yaml (default: text)
    --metadata      Show detailed metadata (timestamps, full tags)
  delete <path>     Delete a secret
  search <pattern>  Search for secrets by path
    --regex         Use regex pattern instead of glob

Import/Export Commands:
  export [prefix]   Export secrets as JSON
    --output        Output file (default: stdout)
  import [file]     Import secrets from JSON (default: stdin)
    --merge         Skip existing secrets instead of overwriting

Daemon Commands:
  daemon start      Start the daemon in background
  daemon stop       Stop the daemon
  daemon status     Show daemon status
  daemon run        Run daemon in foreground (for debugging)

Other Commands:
  version           Show version
  help              Show this help

Configuration:
  Config file: ~/.omnivault/config.json
  Supported settings:
    auto_lock_timeout    Duration before auto-lock (e.g., "15m", "1h")
    default_format       Default output format (text, json, yaml)
    expiry_warning_days  Days before expiry to show warnings (default: 30)

Examples:
  omnivault init
  omnivault set database/password
  omnivault get database/password
  omnivault get database/password --format json
  omnivault get database/password --field password
  omnivault list database/ --metadata
  omnivault search "database/*"
  omnivault search ".*prod.*" --regex
  omnivault export > backup.json
  omnivault import backup.json --merge
  omnivault passwd`)
}
