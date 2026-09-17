// Command crowdsec-gram-bot is a Telegram bot daemon and CLI to manage
// CrowdSec bans via LAPI (machine credentials) with cscli fallback.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// sigContext cancels on Ctrl-C or SIGTERM (systemd/docker stop).
// Callers must defer the returned cancel.
func sigContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// mustCtx is sigContext for short-lived CLI runs (cancel at process exit).
func mustCtx() context.Context {
	ctx, cancel := sigContext()
	_ = cancel
	return ctx
}

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
	switch os.Args[1] {
	case "version":
		fmt.Println(runVersion())
		return
	case "bans":
		runBansCmd(mustCtx(), os.Args[2:])
		return
	case "unban":
		runUnbanCmd(mustCtx(), os.Args[2:], false)
		return
	case "unbanwl":
		runUnbanCmd(mustCtx(), os.Args[2:], true)
		return
	case "update":
		runUpdateCmd(mustCtx(), os.Args[2:])
		return
	case "bot":
		ctx, cancel := sigContext()
		defer cancel()
		if err := runBot(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "not implemented yet: "+os.Args[1])
	os.Exit(1)
}
