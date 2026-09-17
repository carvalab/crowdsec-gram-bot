// Command crowdsec-gram-bot is a Telegram bot daemon and CLI to manage
// CrowdSec bans via LAPI (machine credentials) with cscli fallback.
package main

import (
	"fmt"
	"os"
	"strings"
)

var version = "dev"
var commit = "none"
var date = "unknown"

var subcommands = []string{"bot", "bans", "unban", "unbanwl", "version", "update"}

func runVersion() string {
	return fmt.Sprintf("version=%s commit=%s date=%s", version, commit, date)
}

func knownSubcommand(s string) bool {
	for _, c := range subcommands {
		if c == s {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: crowdsec-gram-bot <%s> [flags]\n", strings.Join(subcommands, "|"))
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if !knownSubcommand(os.Args[1]) {
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if os.Args[1] == "version" {
		fmt.Println(runVersion())
		return
	}
	fmt.Fprintln(os.Stderr, "not implemented yet: "+os.Args[1])
	os.Exit(1)
}
