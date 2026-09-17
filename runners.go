package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/carvalab/crowdsec-gram-bot/internal/cscli"
	"github.com/carvalab/crowdsec-gram-bot/internal/lapi"
)

// runMode selects the backend: auto tries LAPI first, cscli on failure.
type runMode string

const (
	modeAuto  runMode = "auto"
	modeLAPI  runMode = "lapi"
	modeCSCLI runMode = "cscli"
)

func resolveMode(via string) runMode {
	switch strings.ToLower(strings.TrimSpace(via)) {
	case "cscli", "1":
		return modeCSCLI
	case "lapi", "0":
		return modeLAPI
	default:
		return modeAuto
	}
}

// config mirrors the spec env keys.
type config struct {
	lapiURL   string
	login     string
	password  string
	allowID   string
	ttl       string
	listLimit string
	via       runMode
	dryRun    bool
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	return config{
		lapiURL:   getenv("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080"),
		login:     strings.TrimSpace(os.Getenv("CROWDSEC_MACHINE_LOGIN")),
		password:  strings.TrimSpace(os.Getenv("CROWDSEC_MACHINE_PASSWORD")),
		allowID:   getenv("ALLOWLIST_ID", "telegram-temp"),
		ttl:       getenv("WHITELIST_TTL", "2160h"),
		listLimit: getenv("LIST_LIMIT", "50"),
		via:       resolveMode(getenv("USE_CSCLI", "auto")),
		dryRun:    parseBool(os.Getenv("DRY_RUN")),
	}
}

// parseBool accepts 1/t/true (case-insensitive); anything else is false,
// so DRY_RUN=false never enables dry-run.
func parseBool(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}

// validate fails fast on bad operator config (spec: fail fast at startup).
func (c config) validate() error {
	if _, err := time.ParseDuration(c.ttl); err != nil {
		return fmt.Errorf("bad WHITELIST_TTL %q: %w", c.ttl, err)
	}
	if n, err := strconv.Atoi(c.listLimit); err != nil || n < 0 {
		return fmt.Errorf("bad LIST_LIMIT %q: want non-negative integer", c.listLimit)
	}
	return nil
}

func (c config) lapiClient() *lapi.Client {
	return lapi.New(lapi.Config{
		URL: c.lapiURL, Login: c.login, Password: c.password,
		AllowID: c.allowID, TTL: c.ttl, ListLimit: c.listLimit,
	})
}

func shortTime(s string) string {
	if s == "" {
		return "?"
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2006-01-02 15:04")
	}
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func formatDecisions(ds []lapi.Decision) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d bans:\n", len(ds))
	for _, d := range ds {
		ip := d.Value
		if ip == "" {
			ip = d.IP
		}
		fmt.Fprintf(&sb, "• %s (%s/%s until %s)\n", ip, d.Scenario, d.Type, shortTime(d.Until))
	}
	return sb.String()
}

// useCSCLI reports whether the cscli fallback may be attempted.
func (c config) useCSCLI() bool {
	return (c.via == modeAuto || c.via == modeCSCLI) && cscli.Available()
}

// lapiErrFallback decides fallback in auto mode: transport failures and
// LAPI 404s fall back; auth errors (401/403) and other statuses do not.
func lapiErrFallback(err error) bool {
	if err == nil {
		return false
	}
	var se *lapi.StatusError
	if errors.As(err, &se) {
		return se.Code == 404
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "endpoint not found")
}

// validIP rejects empty/malformed input before destructive operations:
// an empty ip filter could match every active decision server-side.
func validIP(ip string) error {
	if net.ParseIP(strings.TrimSpace(ip)) == nil {
		return fmt.Errorf("invalid ip %q", ip)
	}
	return nil
}

// runList lists bans, LAPI-first with cscli fallback.
func runList(ctx context.Context) (string, error) {
	c := loadConfig()
	if err := c.validate(); err != nil {
		return "", err
	}
	if c.dryRun {
		return fmt.Sprintf("dry-run: list decisions via %s (limit %s)", c.via, c.listLimit), nil
	}
	if c.via == modeCSCLI {
		ds, err := cscli.List(ctx)
		if err != nil {
			return "", err
		}
		if len(ds) == 0 {
			return "no bans 🎉", nil
		}
		return formatDecisions(ds), nil
	}
	ds, err := c.lapiClient().ListDecisions(ctx)
	if err == nil {
		if len(ds) == 0 {
			return "no bans 🎉", nil
		}
		return formatDecisions(ds), nil
	}
	if c.via == modeAuto && c.useCSCLI() && lapiErrFallback(err) {
		ds, ferr := cscli.List(ctx)
		if ferr != nil {
			return "", fmt.Errorf("%w (cscli fallback: %w)", err, ferr)
		}
		if len(ds) == 0 {
			return "no bans 🎉", nil
		}
		return formatDecisions(ds), nil
	}
	return "", err
}

// runUnban deletes the ban for ip.
func runUnban(ctx context.Context, ip string) (string, error) {
	if err := validIP(ip); err != nil {
		return "", err
	}
	c := loadConfig()
	if err := c.validate(); err != nil {
		return "", err
	}
	if c.dryRun {
		return fmt.Sprintf("dry-run: unban %s via %s (cscli equiv: cscli decisions delete --ip %s)", ip, c.via, ip), nil
	}
	if c.via == modeCSCLI {
		if err := cscli.Delete(ctx, ip); err != nil {
			return "", err
		}
		return "unbanned " + ip, nil
	}
	if err := c.lapiClient().DeleteDecision(ctx, ip); err == nil {
		return "unbanned " + ip, nil
	} else if c.via == modeAuto && c.useCSCLI() && lapiErrFallback(err) {
		if ferr := cscli.Delete(ctx, ip); ferr != nil {
			return "", fmt.Errorf("%w (cscli fallback: %w)", err, ferr)
		}
		return "unbanned " + ip, nil
	} else {
		return "", err
	}
}

// runUnbanWL deletes the ban and whitelists the ip for the TTL.
func runUnbanWL(ctx context.Context, ip string) (string, error) {
	if err := validIP(ip); err != nil {
		return "", err
	}
	c := loadConfig()
	if err := c.validate(); err != nil {
		return "", err
	}
	if c.dryRun {
		return fmt.Sprintf("dry-run: unban+whitelist %s via %s ttl %s (cscli equiv: cscli decisions delete --ip %s && cscli allowlists add %s %s -e %s)",
			ip, c.via, c.ttl, ip, c.allowID, ip, c.ttl), nil
	}
	if c.via == modeCSCLI {
		if err := cscli.Delete(ctx, ip); err != nil {
			return "", fmt.Errorf("unban failed: %w", err)
		}
		if err := cscli.AllowlistAdd(ctx, c.allowID, ip, c.ttl); err != nil {
			return "", fmt.Errorf("unbanned %s but whitelist failed: %w", ip, err)
		}
		return "unbanned + whitelisted " + ip + " for " + c.ttl, nil
	}
	cl := c.lapiClient()
	if err := cl.DeleteDecision(ctx, ip); err != nil {
		if c.via == modeAuto && c.useCSCLI() && lapiErrFallback(err) {
			if ferr := cscli.Delete(ctx, ip); ferr != nil {
				return "", fmt.Errorf("unban failed: %v (cscli fallback: %v)", err, ferr)
			}
		} else {
			return "", fmt.Errorf("unban failed: %w", err)
		}
	}
	if err := cl.AllowlistAdd(ctx, ip); err != nil {
		if c.via == modeAuto && c.useCSCLI() && lapiErrFallback(err) {
			if ferr := cscli.AllowlistAdd(ctx, c.allowID, ip, c.ttl); ferr != nil {
				return "", fmt.Errorf("unbanned %s but whitelist failed: %w (cscli fallback: %w)", ip, err, ferr)
			}
		} else {
			return "", fmt.Errorf("unbanned %s but whitelist failed: %w", ip, err)
		}
	}
	return "unbanned + whitelisted " + ip + " for " + c.ttl, nil
}

// adminID parses TELEGRAM_ADMIN_ID, used by the bot gate.
func adminID() (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(os.Getenv("TELEGRAM_ADMIN_ID")), 10, 64)
}
