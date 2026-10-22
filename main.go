// Command crowdsec-gram-bot lets one Telegram user remove CrowdSec bans.
//
//	bot      Telegram daemon, runs as the unprivileged crowdsec-gram-bot user
//	helper   one privileged request on the socket systemd passes as stdin
//	install    set this host up, run as root
//	uninstall  remove the bot, keep its settings
//	update     install the newest signed release, run as root by a timer
//	units      install the systemd units built into this binary, as root
//	version    print the build version
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/carvalab/crowdsec-gram-bot/internal/helper"
	"github.com/carvalab/crowdsec-gram-bot/internal/update"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const botUnit = "crowdsec-gram-bot.service"

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: crowdsec-gram-bot bot|helper|install|uninstall|update|units|version")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("version=%s commit=%s date=%s\n", strings.TrimPrefix(version, "v"), commit, date)
	case "bot":
		err = runBot(ctx)
	case "helper":
		err = runHelper(ctx)
	case "install":
		err = runInstall(ctx)
	case "uninstall":
		err = runUninstall(ctx)
	case "update":
		err = runUpdate(ctx)
	case "units":
		err = runUnits(ctx)
	default:
		fmt.Fprintln(os.Stderr, "usage: crowdsec-gram-bot bot|helper|install|uninstall|update|units|version")
		os.Exit(2)
	}
	if err != nil {
		log.Printf("error: %v", err)
		cancel()
		os.Exit(1)
	}
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func runHelper(ctx context.Context) error {
	conn, err := net.FileConn(os.NewFile(0, "socket"))
	if err != nil {
		return fmt.Errorf("stdin is not the helper socket: %w", err)
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("stdin is not a unix socket")
	}
	if _, err := helper.CheckPeer(uc); err != nil {
		return err
	}
	ttl, err := helper.ParseTTL(getenv("ALLOWLIST_TTL", "90d"))
	if err != nil {
		return err
	}
	name := getenv("ALLOWLIST_NAME", "telegram-bot")
	if !helper.ValidAllowlist(name) {
		return fmt.Errorf("bad ALLOWLIST_NAME %q", name)
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	if err := uc.SetDeadline(time.Now().Add(40 * time.Second)); err != nil {
		return err
	}
	cs := helper.CSCLI{Path: getenv("CSCLI_PATH", "/usr/bin/cscli"), Allowlist: name, TTL: ttl, Now: time.Now}
	return helper.Serve(ctx, uc, cs)
}

func runUpdate(ctx context.Context) error {
	key, err := update.ParseKey(update.PublicKey)
	if err != nil {
		return err
	}
	u := &update.Updater{
		Repo:    getenv("GITHUB_REPO", "carvalab/crowdsec-gram-bot"),
		Token:   strings.TrimSpace(os.Getenv("GITHUB_TOKEN")),
		APIURL:  getenv("GITHUB_API_URL", "https://api.github.com"),
		Current: version,
		Key:     key,
		HTTP:    &http.Client{Timeout: 5 * time.Minute},
	}
	rel, err := u.Latest(ctx)
	if err != nil {
		return err
	}
	if !update.Newer(version, rel.Tag) {
		log.Printf("up to date: running %s, latest release %s", version, rel.Tag)
		return nil
	}
	failed := filepath.Join(getenv("STATE_DIRECTORY", "/var/lib/crowdsec-gram-bot"), "failed-release")
	if b, err := os.ReadFile(failed); err == nil && strings.TrimSpace(string(b)) == rel.Tag {
		log.Printf("skipping %s: it failed its health check and was rolled back; waiting for a newer release", rel.Tag)
		return nil
	}
	log.Printf("updating %s -> %s", version, rel.Tag)
	bin, err := u.Download(ctx, rel)
	if err != nil {
		return err
	}
	if err := update.SmokeTest(ctx, bin, rel.Tag, version); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	running, err := update.Running(ctx, botUnit)
	if err != nil {
		return err
	}
	if err := update.Install(bin, exe); err != nil {
		return err
	}
	if err := healthy(ctx, exe, running); err != nil {
		if rbErr := update.Rollback(exe); rbErr != nil {
			return fmt.Errorf("%s is unhealthy (%v) and rollback failed: %w", rel.Tag, err, rbErr)
		}
		if again := healthy(ctx, exe, running); again != nil {
			return fmt.Errorf("%s is unhealthy (%v), rolled back to %s, which also fails (%v): this looks like a problem on the host, not in the release", rel.Tag, err, version, again)
		}
		if wErr := os.WriteFile(failed, []byte(rel.Tag+"\n"), 0o644); wErr != nil {
			log.Printf("could not record the failed release: %v", wErr)
		}
		return fmt.Errorf("%s is unhealthy, rolled back to %s: %w", rel.Tag, version, err)
	}
	log.Printf("updated to %s; the bot and the helper are healthy", rel.Tag)
	return nil
}

// healthy installs the units of the binary at exe, restarts the bot if it
// was running, and checks both the bot and a real helper request.
func healthy(ctx context.Context, exe string, running bool) error {
	if out, err := exec.CommandContext(ctx, exe, "units").CombinedOutput(); err != nil {
		return fmt.Errorf("install units: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if running {
		if err := update.RestartHealthy(ctx, botUnit, 30*time.Second); err != nil {
			return err
		}
	}
	hctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, err := helper.Call(hctx, helper.SocketPath, helper.Request{Op: helper.OpList}); err != nil {
		return fmt.Errorf("helper check: %w", err)
	}
	return nil
}
