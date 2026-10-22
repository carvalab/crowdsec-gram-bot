package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/carvalab/crowdsec-gram-bot/internal/update"
	"golang.org/x/mod/semver"
	"golang.org/x/term"
)

const (
	binPath  = "/usr/local/bin/crowdsec-gram-bot"
	confDir  = "/etc/crowdsec-gram-bot"
	botUser  = "crowdsec-gram-bot"
	minCrowd = "1.6.8"
)

var unitNames = []string{
	"crowdsec-gram-bot.service", "crowdsec-gram-bot-helper.socket", "crowdsec-gram-bot-helper@.service",
	"crowdsec-gram-bot-update.service", "crowdsec-gram-bot-update.timer",
}

// runInstall checks this binary against its signed release, then sets the
// host up. Run it as root, from the binary you downloaded.
func runInstall(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo crowdsec-gram-bot install")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd is required")
	}
	if _, err := exec.LookPath("cscli"); err != nil {
		return errors.New("cscli not found: install CrowdSec from apt first")
	}
	if err := needCrowdSec(ctx, minCrowd); err != nil {
		return err
	}
	switch err := verifySelf(ctx); {
	case err == nil:
	case errors.Is(err, errNoRelease):
		fmt.Printf("warning: %s\n", err)
		fmt.Println("  check the download yourself: openssl pkeyutl -verify and sha256sum -c against checksums.txt")
	default:
		return err
	}
	if err := ensureUser(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return err
	}
	if err := migrateOldConfig(); err != nil {
		return err
	}
	if err := migrateOldMachine(ctx); err != nil {
		return err
	}
	if err := configure(ctx); err != nil {
		return err
	}
	warnRemote(ctx)
	if err := ensureAllowlist(ctx); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := copyFile(exe, binPath, 0o755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	if err := runUnits(ctx); err != nil {
		return err
	}
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := systemctl(ctx, "enable", "crowdsec-gram-bot-helper.socket", botUnit); err != nil {
		return err
	}
	if err := systemctl(ctx, "restart", "crowdsec-gram-bot-helper.socket"); err != nil {
		return err
	}
	if err := systemctl(ctx, "restart", botUnit); err != nil {
		return err
	}
	updates := "off (no GITHUB_TOKEN in " + confDir + "/update.env)"
	if hasKey(confDir+"/update.env", "GITHUB_TOKEN", ".") {
		if err := systemctl(ctx, "enable", "--now", "crowdsec-gram-bot-update.timer"); err != nil {
			return err
		}
		updates = "on, every 6 hours"
	} else {
		_ = systemctl(ctx, "disable", "--now", "crowdsec-gram-bot-update.timer")
	}
	out, _ := exec.Command(binPath, "version").Output()
	fmt.Printf("installed %s", out)
	fmt.Printf("  bot:      systemctl status %s   (logs: journalctl -u %s)\n", botUnit, botUnit)
	fmt.Printf("  helper:   journalctl -u '%s-helper@*'\n", botUnit)
	fmt.Printf("  updates:  %s\n", updates)
	fmt.Printf("  settings: %s/\n", confDir)
	return nil
}

// runUninstall stops the bot and removes it. Settings and the allowlist stay.
func runUninstall(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo crowdsec-gram-bot uninstall")
	}
	_ = systemctl(ctx, "disable", "--now", botUnit, "crowdsec-gram-bot-update.timer", "crowdsec-gram-bot-helper.socket")
	for _, n := range unitNames {
		os.Remove(unitDir + "/" + n)
	}
	_ = systemctl(ctx, "daemon-reload")
	os.Remove(binPath)
	os.Remove(binPath + ".old")
	os.RemoveAll("/var/lib/crowdsec-gram-bot")
	if err := exec.CommandContext(ctx, "userdel", botUser).Run(); err != nil {
		return fmt.Errorf("userdel %s: %w", botUser, err)
	}
	fmt.Printf("removed. Settings are kept in %s; delete them with: rm -r %s\n", confDir, confDir)
	fmt.Println("The CrowdSec allowlist is kept; delete it with: cscli allowlists delete <name>")
	return nil
}

// errNoRelease means the signature could not be checked, not that it failed.
var errNoRelease = errors.New("no release")

// verifySelf checks this binary against the signed checksum of the release
// it says it is. A file that was changed after the download refuses to
// install. It returns errNoRelease when no release can be fetched, and the
// caller warns instead of stopping: the updater checks every later update.
func verifySelf(ctx context.Context) error {
	if !semver.IsValid("v" + strings.TrimPrefix(version, "v")) {
		return fmt.Errorf("%w: this build (%s) is not a release", errNoRelease, version)
	}
	key, err := update.ParseKey(update.PublicKey)
	if err != nil {
		return err
	}
	u := &update.Updater{
		Repo: getenv("GITHUB_REPO", "carvalab/crowdsec-gram-bot"), Token: strings.TrimSpace(os.Getenv("GITHUB_TOKEN")),
		APIURL: getenv("GITHUB_API_URL", "https://api.github.com"), Key: key,
		HTTP: &http.Client{Timeout: 2 * time.Minute},
	}
	rel, err := u.Latest(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", errNoRelease, err)
	}
	if strings.TrimPrefix(rel.Tag, "v") != strings.TrimPrefix(version, "v") {
		return fmt.Errorf("this binary is %s but the latest release is %s: download the latest one", version, rel.Tag)
	}
	want, err := u.Download(ctx, rel)
	if err != nil {
		return fmt.Errorf("%w: %v", errNoRelease, err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	have, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if string(have) != string(want) {
		return errors.New("this binary does not match its signed release: refusing to install it")
	}
	fmt.Printf("signature and checksum match release %s\n", rel.Tag)
	return nil
}

var versionLine = regexp.MustCompile(`version:\s*v?([0-9][0-9.]*)`)

func needCrowdSec(ctx context.Context, min string) error {
	out, err := exec.CommandContext(ctx, "cscli", "version").CombinedOutput()
	m := versionLine.FindSubmatch(out)
	if err != nil || m == nil {
		return fmt.Errorf("cannot read the CrowdSec version: %w", err)
	}
	got := "v" + string(m[1])
	if semver.Compare(semver.Canonical(got), semver.Canonical("v"+min)) < 0 {
		return fmt.Errorf("CrowdSec %s is too old: allowlists need %s or newer.\nUbuntu's own package is older. Use CrowdSec's repository:\n  curl -s https://install.crowdsec.net | sudo sh && sudo apt install crowdsec", got, min)
	}
	return nil
}

func ensureUser(ctx context.Context) error {
	if exec.CommandContext(ctx, "id", "-u", botUser).Run() == nil {
		return nil
	}
	return exec.CommandContext(ctx, "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", botUser).Run()
}

// migrateOldConfig moves Telegram settings from the first version's single
// env file and deletes it.
func migrateOldConfig() error {
	old := "/etc/crowdsec-gram-bot.env"
	b, err := os.ReadFile(old)
	if err != nil {
		return nil
	}
	fmt.Println("found settings from the old version in /etc/crowdsec-gram-bot.env, moving them")
	dst := confDir + "/bot.env"
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		var kept []string
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "TELEGRAM_TOKEN=") || strings.HasPrefix(line, "TELEGRAM_ADMIN_ID=") {
				kept = append(kept, line)
			}
		}
		if err := os.WriteFile(dst, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	}
	return os.Remove(old)
}

func migrateOldMachine(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "cscli", "machines", "list", "-o", "raw").Output()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Split(line, ",")[0] == "telegram-bot" {
			if err := exec.CommandContext(ctx, "cscli", "machines", "delete", "telegram-bot").Run(); err != nil {
				return fmt.Errorf("delete old telegram-bot machine account: %w", err)
			}
			fmt.Println("deleted the old 'telegram-bot' CrowdSec machine account; it is not needed any more")
		}
	}
	return nil
}

func configure(ctx context.Context) error {
	token, err := setting(confDir+"/bot.env", "TELEGRAM_TOKEN", ".", "Telegram bot token from @BotFather: ", true)
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("TELEGRAM_TOKEN is required")
	}
	id, err := setting(confDir+"/bot.env", "TELEGRAM_ADMIN_ID", "[0-9]", "Your numeric Telegram user id (ask @userinfobot): ", false)
	if err != nil {
		return err
	}
	if _, err := fmt.Sscanf(id, "%d", new(int64)); err != nil || id == "" || id == "0" {
		return errors.New("TELEGRAM_ADMIN_ID must be a number")
	}
	fmt.Println("Auto-updates need a GitHub token, because this repo is private.")
	fmt.Println("Make a fine-grained token: only this repository, permission Contents: read-only.")
	fmt.Println("Leave it empty to update by hand later: sudo crowdsec-gram-bot install")
	if _, err := setting(confDir+"/update.env", "GITHUB_TOKEN", ".", "GitHub token (or empty): ", true); err != nil {
		return err
	}
	helper := confDir + "/helper.env"
	if _, err := os.Stat(helper); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(helper, []byte("ALLOWLIST_NAME=telegram-bot\nALLOWLIST_TTL=90d\n"), 0o600)
	}
	return nil
}

// setting returns the value of key in file, or asks for it and saves it.
// present matches the part after the = of a value that counts as set.
func setting(file, key, present, prompt string, secret bool) (string, error) {
	if v := savedValue(file, key, present); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v, setValue(file, key, v)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", nil
	}
	fmt.Print(prompt)
	var v string
	var err error
	if secret {
		b, rerr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		v, err = string(b), rerr
	} else {
		v, err = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	return v, setValue(file, key, v)
}

func savedValue(file, key, present string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile("(?m)^" + regexp.QuoteMeta(key) + "=(" + present + ".*)$")
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

func hasKey(file, key, present string) bool { return savedValue(file, key, present) != "" }

func setValue(file, key, value string) error {
	b, _ := os.ReadFile(file)
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		if line != "" && !strings.HasPrefix(line, key+"=") {
			kept = append(kept, line)
		}
	}
	kept = append(kept, key+"="+value)
	return os.WriteFile(file, []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

func warnRemote(ctx context.Context) {
	if b, err := os.ReadFile("/etc/crowdsec/local_api_credentials.yaml"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			url := strings.TrimSpace(strings.TrimPrefix(line, "url:"))
			if strings.HasPrefix(line, "url:") && !localURL(url) {
				fmt.Printf("warning: cscli reaches LAPI at %s, but the helper may only connect to localhost.\n", url)
				fmt.Println("  allow it with: systemctl edit crowdsec-gram-bot-helper@.service  ([Service] IPAddressAllow=<that IP>)")
			}
		}
	}
	dbType, dbHost := "sqlite", ""
	if out, err := exec.CommandContext(ctx, "cscli", "config", "show").Output(); err == nil {
		inDB := false
		for _, line := range strings.Split(string(out), "\n") {
			switch {
			case strings.HasPrefix(line, "db_config:"):
				inDB = true
			case len(line) > 0 && line[0] != ' ' && line[0] != '#':
				inDB = false
			case inDB && strings.HasPrefix(strings.TrimSpace(line), "type:"):
				dbType = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "type:")), `"'`)
			case inDB && strings.HasPrefix(strings.TrimSpace(line), "host:"):
				dbHost = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "host:")), `"'`)
			}
		}
	}
	if dbType != "sqlite" && !localURL(dbHost) && !strings.HasPrefix(dbHost, "/") {
		fmt.Printf("warning: CrowdSec's %s database is at %s; /allow talks to it directly, but the helper may only connect to localhost.\n", dbType, dbHost)
		fmt.Println("  allow it with: systemctl edit crowdsec-gram-bot-helper@.service  ([Service] IPAddressAllow=<that IP>)")
	}
}

func localURL(s string) bool {
	return s == "" || strings.HasPrefix(s, "http://127.0.0.1:") || strings.HasPrefix(s, "http://localhost:") ||
		strings.HasPrefix(s, "http://[::1]:") || s == "127.0.0.1" || s == "localhost" || s == "::1"
}

func ensureAllowlist(ctx context.Context) error {
	name := savedValue(confDir+"/helper.env", "ALLOWLIST_NAME", ".")
	if name == "" {
		name = "telegram-bot"
	}
	if exec.CommandContext(ctx, "cscli", "allowlists", "inspect", name).Run() == nil {
		return nil
	}
	if out, err := exec.CommandContext(ctx, "cscli", "allowlists", "create", name, "-d", "IPs allowed from Telegram by crowdsec-gram-bot").CombinedOutput(); err != nil {
		return fmt.Errorf("create allowlist %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(dst+".new", dst)
}
