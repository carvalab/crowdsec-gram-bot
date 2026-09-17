package main

import (
	"context"
	"errors"
	"flag"
	"github.com/carvalab/crowdsec-gram-bot/internal/lapi"
	"net/url"
	"strings"
	"testing"
)

func TestRunVersionContainsDev(t *testing.T) {
	if !strings.Contains(runVersion(), "version=") {
		t.Fatalf("runVersion() = %q, want version= prefix", runVersion())
	}
}

func TestKnownSubcommand(t *testing.T) {
	for _, s := range []string{"bot", "bans", "unban", "unbanwl", "version", "update"} {
		if !knownSubcommand(s) {
			t.Fatalf("knownSubcommand(%q) = false", s)
		}
	}
	if knownSubcommand("bogus") {
		t.Fatal("knownSubcommand(bogus) = true")
	}
}

func TestRunListDryRun(t *testing.T) {
	t.Setenv("DRY_RUN", "1")
	out, err := runList(context.Background())
	if err != nil {
		t.Fatalf("runList dry-run err = %v", err)
	}
	if !strings.Contains(out, "dry-run") {
		t.Fatalf("runList = %q, want dry-run marker", out)
	}
}

func TestResolveMode(t *testing.T) {
	if resolveMode("cscli") != modeCSCLI || resolveMode("lapi") != modeLAPI || resolveMode("bogus") != modeAuto {
		t.Fatal("resolveMode mapping wrong")
	}
}

func TestLapiErrFallback(t *testing.T) {
	fallback := []error{
		&lapi.StatusError{Code: 404, Op: "list"},
		errText("dial tcp: connection refused"),
		errText("no such host"),
		errText("allowlist endpoint not found; create list first"),
		&url.Error{Op: "Get", URL: "http://x", Err: errText("connection refused")},
	}
	for _, err := range fallback {
		if !lapiErrFallback(err) {
			t.Fatalf("%v should fall back", err)
		}
	}
	noFallback := []error{
		&lapi.StatusError{Code: 401, Op: "delete"},
		&lapi.StatusError{Code: 403, Op: "delete"},
		&lapi.StatusError{Code: 500, Op: "list"},
		errText("re-login failed (need MACHINE creds, not bouncer key): x"),
		nil,
	}
	for _, err := range noFallback {
		if lapiErrFallback(err) {
			t.Fatalf("%v must not fall back", err)
		}
	}
}

func TestResolveModeSpecValues(t *testing.T) {
	if resolveMode("1") != modeCSCLI || resolveMode("0") != modeLAPI || resolveMode("auto") != modeAuto {
		t.Fatal("spec 0|1|auto mapping wrong")
	}
}

func TestRunUnbanRejectsBadIP(t *testing.T) {
	for _, ip := range []string{"", "not-an-ip", "1.2.3.9999"} {
		if _, err := runUnban(context.Background(), ip); err == nil {
			t.Fatalf("ip %q accepted", ip)
		}
	}
}

func TestDryRunFalseIsLive(t *testing.T) {
	t.Setenv("DRY_RUN", "false")
	if parseBool("false") || parseBool("0") || !parseBool("1") || !parseBool("true") {
		t.Fatal("parseBool wrong")
	}
}

func TestConfigValidate(t *testing.T) {
	bad := config{ttl: "90d", listLimit: "50"}
	if err := bad.validate(); err == nil {
		t.Fatal("TTL 90d accepted")
	}
	bad = config{ttl: "2160h", listLimit: "abc"}
	if err := bad.validate(); err == nil {
		t.Fatal("limit abc accepted")
	}
}

func errText(s string) error { return errors.New(s) }

func TestArgIP(t *testing.T) {
	ip, ok := argIP("/unban 1.2.3.4")
	if !ok || ip != "1.2.3.4" {
		t.Fatalf("argIP = %q,%v", ip, ok)
	}
	if _, ok := argIP("/unban not-an-ip"); ok {
		t.Fatal("argIP accepted garbage")
	}
	if _, ok := argIP("/unban"); ok {
		t.Fatal("argIP accepted missing arg")
	}
}

func TestIsAdmin(t *testing.T) {
	if !isAdmin(42, 42) || isAdmin(43, 42) {
		t.Fatal("isAdmin wrong")
	}
}

func TestIsCommand(t *testing.T) {
	if !isCommand("/unban 1.2.3.4", "/unban") || !isCommand("/unban@mybot 1.2.3.4", "/unban") {
		t.Fatal("valid /unban rejected")
	}
	for _, m := range []string{"/unbanwl 1.2.3.4", "/unbanned 1.2.3.4", "/unban2 1.2.3.4", ""} {
		if isCommand(m, "/unban") {
			t.Fatalf("%q accepted as /unban", m)
		}
	}
}

func TestCLIDryRunUnban(t *testing.T) {
	t.Setenv("DRY_RUN", "1")
	out, err := runUnban(context.Background(), "9.9.9.9")
	if err != nil || !strings.Contains(out, "9.9.9.9") {
		t.Fatalf("runUnban dry-run = %q, err = %v", out, err)
	}
}

func TestParseMixedFlagAfterPositional(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "")
	ttl := fs.String("ttl", "", "")
	rest := parseMixed(fs, "t <ip>", []string{"9.9.9.9", "--dry-run", "--ttl", "720h"})
	if !*dry || *ttl != "720h" || len(rest) != 1 || rest[0] != "9.9.9.9" {
		t.Fatalf("dry=%v ttl=%q rest=%q", *dry, *ttl, rest)
	}
}
