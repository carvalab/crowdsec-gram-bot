package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/carvalab/crowdsec-gram-bot/internal/update"
)

// failedReleaseFile is written by the root updater when a release fails its
// health check and is rolled back. The bot can read it but not change it.
const failedReleaseFile = "/var/lib/crowdsec-gram-bot/failed-release"

// notices returns the messages to send at start: a first start, an update,
// a downgrade, or a release that failed and was rolled back.
func notices(last, current, failed, lastFailed string) []string {
	var out []string
	if failed != "" && failed != lastFailed {
		out = append(out, fmt.Sprintf("⚠️ Release %s failed its health check after installing, so the server went back to %s. It will not be tried again; the next release will be.", failed, current))
	}
	switch {
	case last == "":
		out = append(out, "✅ crowdsec-gram-bot "+current+" is running. Send /help to start.")
	case update.Newer(last, current):
		out = append(out, fmt.Sprintf("⬆️ Updated to %s (was %s).\nWhat changed: https://github.com/carvalab/crowdsec-gram-bot/releases/tag/v%s", current, last, strings.TrimPrefix(current, "v")))
	case last != current:
		out = append(out, fmt.Sprintf("↩️ Now running %s (was %s).", current, last))
	}
	return out
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// announce sends the start notices once. It remembers what it announced in
// the bot's own state directory, so a plain restart sends nothing.
func announce(ctx context.Context, dir string, send func(context.Context, string) error) {
	if dir == "" {
		return
	}
	lastFile, failedFile := filepath.Join(dir, "last-version"), filepath.Join(dir, "last-failed-release")
	failed := readTrim(failedReleaseFile)
	for _, msg := range notices(readTrim(lastFile), version, failed, readTrim(failedFile)) {
		if err := send(ctx, msg); err != nil {
			log.Printf("announce: %v", err)
			return
		}
	}
	if err := os.WriteFile(lastFile, []byte(version+"\n"), 0o600); err != nil {
		log.Printf("announce: %v", err)
	}
	if failed != "" {
		if err := os.WriteFile(failedFile, []byte(failed+"\n"), 0o600); err != nil {
			log.Printf("announce: %v", err)
		}
	}
}
