package main

import (
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
