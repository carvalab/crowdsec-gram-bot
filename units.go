package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

//go:embed systemd/*
var unitFiles embed.FS

const unitDir = "/etc/systemd/system"

// writeUnits makes dir hold the unit files built into this binary and
// returns the names it changed.
func writeUnits(dir string) ([]string, error) {
	entries, err := unitFiles.ReadDir("systemd")
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, e := range entries {
		want, err := unitFiles.ReadFile(path.Join("systemd", e.Name()))
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(dir, e.Name())
		if have, err := os.ReadFile(dst); err == nil && bytes.Equal(have, want) {
			continue
		}
		tmp := dst + ".new"
		if err := os.WriteFile(tmp, want, 0o644); err != nil {
			return nil, err
		}
		if err := os.Chmod(tmp, 0o644); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return nil, err
		}
		changed = append(changed, e.Name())
	}
	return changed, nil
}

func systemctl(ctx context.Context, args ...string) error {
	if out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runUnits installs the units that match this binary, so an update or a
// rollback always brings its own sandbox settings.
func runUnits(ctx context.Context) error {
	changed, err := writeUnits(unitDir)
	if err != nil {
		return err
	}
	if len(changed) == 0 {
		log.Printf("systemd units are up to date")
		return nil
	}
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	for _, name := range changed {
		if strings.HasSuffix(name, ".socket") {
			if err := systemctl(ctx, "try-restart", name); err != nil {
				return err
			}
		}
	}
	log.Printf("updated systemd units: %s", strings.Join(changed, ", "))
	return nil
}
