// Package cscli shells out to the local cscli binary. Used only as a
// fallback when LAPI is unreachable or returns 404, and when USE_CSCLI=1.
package cscli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf8"

	"github.com/carvalab/crowdsec-gram-bot/internal/lapi"
)

// Available reports whether cscli is on PATH.
func Available() bool {
	_, err := exec.LookPath("cscli")
	return err == nil
}

// run executes cscli keeping stdout and stderr apart: List parses stdout
// as JSON, so stderr warnings (exit 0) must not pollute the payload.
func run(ctx context.Context, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "cscli", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(stderr.String())
		if tail == "" {
			tail = strings.TrimSpace(stdout.String())
		}
		if len(tail) > 300 {
			cut := tail[:300]
			for len(cut) > 0 && !utf8.ValidString(cut) {
				cut = cut[:len(cut)-1]
			}
			tail = cut + "…"
		}
		return nil, fmt.Errorf("cscli %s: %w: %s", strings.Join(args, " "), err, tail)
	}
	return stdout.Bytes(), nil
}

// List parses `cscli decisions list -o json` into lapi decisions.
func List(ctx context.Context) ([]lapi.Decision, error) {
	if !Available() {
		return nil, fmt.Errorf("cscli not found in PATH")
	}
	out, err := run(ctx, "decisions", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var ds []lapi.Decision
	if err := json.Unmarshal(out, &ds); err != nil {
		return nil, fmt.Errorf("decode cscli list: %w", err)
	}
	return ds, nil
}

// Delete runs `cscli decisions delete --ip`.
func Delete(ctx context.Context, ip string) error {
	if !Available() {
		return fmt.Errorf("cscli not found in PATH")
	}
	_, err := run(ctx, "decisions", "delete", "--ip", ip)
	return err
}

// AllowlistAdd runs `cscli allowlists add <list> <ip> -e <ttl>`.
func AllowlistAdd(ctx context.Context, list, ip, ttl string) error {
	if !Available() {
		return fmt.Errorf("cscli not found in PATH")
	}
	args := []string{"allowlists", "add", list, ip}
	if ttl != "" {
		args = append(args, "-e", ttl)
	}
	_, err := run(ctx, args...)
	return err
}
