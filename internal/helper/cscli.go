package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CSCLI runs the host's cscli. Every call passes a fixed argument list built
// from validated values; nothing goes through a shell.
type CSCLI struct {
	Path      string
	Allowlist string
	TTL       time.Duration
	Now       func() time.Time
}

var (
	deletedRe     = regexp.MustCompile(`(\d+) decision\(s\) deleted`)
	allowDeleteRe = regexp.MustCompile(`(\d+) decisions deleted by allowlists`)
	allowlistName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// ParseTTL reads a Go duration or a whole number of days such as "90d".
func ParseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("bad ttl %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad ttl %q", s)
	}
	return d, nil
}

// ValidAllowlist reports whether name is safe to pass to cscli as a value.
func ValidAllowlist(name string) bool { return allowlistName.MatchString(name) }

func (c CSCLI) run(ctx context.Context, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, c.Path, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		tail := strings.TrimSpace(stderr.String())
		if tail == "" {
			tail = strings.TrimSpace(stdout.String())
		}
		if r := []rune(tail); len(r) > 300 {
			tail = string(r[len(r)-300:])
		}
		return "", "", fmt.Errorf("cscli %s: %w: %s", args[0]+" "+args[1], err, tail)
	}
	return stdout.String(), stderr.String(), nil
}

type alert struct {
	CreatedAt time.Time `json:"created_at"`
	Decisions []struct {
		Value    string `json:"value"`
		Scenario string `json:"scenario"`
		Origin   string `json:"origin"`
		Type     string `json:"type"`
		Duration string `json:"duration"`
	} `json:"decisions"`
}

// List returns every active local decision, one entry per decision.
func (c CSCLI) List(ctx context.Context) ([]Ban, error) {
	out, _, err := c.run(ctx, "decisions", "list", "-o", "json", "--limit", "0")
	if err != nil {
		return nil, err
	}
	var alerts []alert
	if err := json.Unmarshal([]byte(out), &alerts); err != nil {
		return nil, fmt.Errorf("read cscli decisions: %w", err)
	}
	var bans []Ban
	for _, a := range alerts {
		for _, d := range a.Decisions {
			left, _ := time.ParseDuration(d.Duration)
			bans = append(bans, Ban{IP: d.Value, Scenario: d.Scenario, Origin: d.Origin, Type: d.Type, Left: left, Created: a.CreatedAt})
		}
	}
	return bans, nil
}

// Delete removes every decision that covers ip, including range bans, and
// returns how many were removed.
func (c CSCLI) Delete(ctx context.Context, ip string) (int, error) {
	stdout, stderr, err := c.run(ctx, "decisions", "delete", "--ip", ip)
	if err != nil {
		return 0, err
	}
	m := deletedRe.FindStringSubmatch(stderr + stdout)
	if m == nil {
		return 0, fmt.Errorf("cscli decisions delete: no deleted count in output")
	}
	return strconv.Atoi(m[1])
}

type allowlist struct {
	Items []struct {
		Value      string    `json:"value"`
		Expiration time.Time `json:"expiration"`
	} `json:"items"`
}

// Allow puts ip on the allowlist for the TTL and returns how many bans
// cscli lifted while adding it. cscli keeps the old expiry when the value is
// already there, so the entry is removed and added again; if adding fails,
// the old entry is put back.
func (c CSCLI) Allow(ctx context.Context, ip string) (time.Time, int, error) {
	now := c.Now()
	comment := "crowdsec-gram-bot " + now.UTC().Format("2006-01-02")
	out, _, err := c.run(ctx, "allowlists", "inspect", c.Allowlist, "-o", "json")
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return time.Time{}, 0, err
		}
		if _, _, err := c.run(ctx, "allowlists", "create", c.Allowlist, "-d", "IPs allowed from Telegram by crowdsec-gram-bot"); err != nil {
			return time.Time{}, 0, err
		}
		out = "{}"
	}
	var list allowlist
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return time.Time{}, 0, fmt.Errorf("read cscli allowlist: %w", err)
	}
	var old []string
	for _, it := range list.Items {
		if it.Value != ip {
			continue
		}
		switch {
		case it.Expiration.IsZero() || it.Expiration.Year() <= 1:
			old = []string{"-d", comment}
		case it.Expiration.After(now):
			old = []string{"-e", seconds(it.Expiration.Sub(now)), "-d", comment}
		}
	}
	if _, _, err := c.run(ctx, "allowlists", "remove", c.Allowlist, ip); err != nil {
		return time.Time{}, 0, err
	}
	stdout, stderr, err := c.run(ctx, "allowlists", "add", c.Allowlist, ip, "-e", seconds(c.TTL), "-d", comment)
	if err != nil {
		if old != nil {
			if _, _, rErr := c.run(ctx, append([]string{"allowlists", "add", c.Allowlist, ip}, old...)...); rErr != nil {
				return time.Time{}, 0, fmt.Errorf("%w; restoring the previous entry also failed: %v", err, rErr)
			}
		}
		return time.Time{}, 0, err
	}
	lifted := 0
	if m := allowDeleteRe.FindStringSubmatch(stdout + stderr); m != nil {
		lifted, _ = strconv.Atoi(m[1])
	}
	return now.Add(c.TTL), lifted, nil
}

func seconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) + "s" }
