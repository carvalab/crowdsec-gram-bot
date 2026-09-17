package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/carvalab/crowdsec-gram-bot/internal/cscli"
	"github.com/carvalab/crowdsec-gram-bot/internal/lapi"
)

// exit codes: 0 ok, 1 runtime error, 2 usage error.
func fatalUsage(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "usage: "+format+"\n", args...)
	os.Exit(2)
}

func fatalErr(err error) {
	fmt.Fprintln(os.Stderr, "error: "+err.Error())
	os.Exit(1)
}

// parseMixed parses flags regardless of position (stdlib flag stops at the
// first positional, so `unban 1.2.3.4 --dry-run` would otherwise fail).
// Returns the positional args.
// boolFlags are flags that take no value; all others consume the next arg.
var boolFlags = map[string]bool{"dry-run": true, "json": true, "h": true, "help": true}

func parseMixed(fs *flag.FlagSet, usage string, args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := strings.TrimLeft(a, "-")
		if len(a) > 1 && a[0] == '-' && !strings.Contains(name, "=") && !boolFlags[strings.SplitN(name, "=", 2)[0]] {
			flags = append(flags, a)
			if i+1 < len(args) {
				next := args[i+1]
				nextName := strings.SplitN(strings.TrimLeft(next, "-"), "=", 2)[0]
				// Don't swallow a token that is itself a defined flag:
				// leave it so flag.Parse reports the missing value (exit 2).
				if !strings.HasPrefix(next, "-") || fs.Lookup(nextName) == nil {
					i++
					flags = append(flags, next)
				}
			}
			continue
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			continue
		}
		pos = append(pos, a)
	}
	if err := fs.Parse(append(flags, pos...)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "usage: "+usage)
			os.Exit(0)
		}
		os.Exit(2)
	}
	return fs.Args()
}

// applyFlags maps CLI flags onto env overrides for one run.
func applyFlags(via, ttl, limit string, dryRun bool) {
	// A value starting with "-" means the flag got no value (e.g.
	// `--via --dry-run`): stdlib flag would silently swallow the next
	// flag as the value, so reject loudly instead (exit 2).
	for _, v := range []string{via, ttl, limit} {
		if strings.HasPrefix(v, "-") {
			fatalUsage("flag got another flag as its value: %q (missing value?)", v)
		}
	}
	if via != "" {
		switch strings.ToLower(strings.TrimSpace(via)) {
		case "cscli", "lapi", "auto", "1", "0":
			os.Setenv("USE_CSCLI", via)
		default:
			fatalUsage("--via must be cscli|lapi|auto, got %q", via)
		}
	}
	if ttl != "" {
		os.Setenv("WHITELIST_TTL", ttl)
	}
	if limit != "" {
		os.Setenv("LIST_LIMIT", limit)
	}
	if dryRun {
		os.Setenv("DRY_RUN", "1")
	}
}

func runBansCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("bans", flag.ContinueOnError)
	limit := fs.String("limit", "", "override LIST_LIMIT")
	asJSON := fs.Bool("json", false, "raw JSON output")
	via := fs.String("via", "", "cscli|lapi|auto")
	dryRun := fs.Bool("dry-run", false, "print what would run")
	rest := parseMixed(fs, "bans [--limit N] [--json] [--via cscli|lapi|auto] [--dry-run]", args)
	if len(rest) != 0 {
		fatalUsage("bans [--limit N] [--json] [--via cscli|lapi|auto] [--dry-run]")
	}
	applyFlags(*via, "", *limit, *dryRun)
	if *asJSON {
		if *dryRun {
			fmt.Fprintln(os.Stderr, "dry-run: list decisions as JSON")
			fmt.Println("[]")
			return
		}
		c := loadConfig()
		if err := c.validate(); err != nil {
			fatalErr(err)
		}
		var ds []lapi.Decision
		var err error
		if c.via == modeCSCLI {
			ds, err = cscli.List(ctx)
		} else {
			ds, err = c.lapiClient().ListDecisions(ctx)
			if err != nil && c.via == modeAuto && c.useCSCLI() && lapiErrFallback(err) {
				ds, err = cscli.List(ctx)
			}
		}
		if err != nil {
			fatalErr(err)
		}
		b, _ := json.MarshalIndent(ds, "", "  ")
		fmt.Println(string(b))
		return
	}
	out, err := runList(ctx)
	if err != nil {
		fatalErr(err)
	}
	fmt.Println(out)
}

func runUnbanCmd(ctx context.Context, args []string, whitelist bool) {
	name := "unban"
	if whitelist {
		name = "unbanwl"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	via := fs.String("via", "", "cscli|lapi|auto")
	dryRun := fs.Bool("dry-run", false, "print what would run")
	var ttl *string
	usage := name + " [--via cscli|lapi|auto] [--dry-run] <ip>"
	if whitelist {
		ttl = fs.String("ttl", "", "override WHITELIST_TTL")
		usage = name + " [--via cscli|lapi|auto] [--ttl DURATION] [--dry-run] <ip>"
	} else {
		ttl = new(string)
	}
	rest := parseMixed(fs, usage, args)
	if len(rest) != 1 {
		fatalUsage("%s", usage)
	}
	applyFlags(*via, *ttl, "", *dryRun)
	var out string
	var err error
	if whitelist {
		out, err = runUnbanWL(ctx, rest[0])
	} else {
		out, err = runUnban(ctx, rest[0])
	}
	if err != nil {
		fatalErr(err)
	}
	fmt.Println(out)
}
