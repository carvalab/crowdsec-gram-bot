package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWriteUnitsRestoresDriftAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	first, err := writeUnits(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"crowdsec-gram-bot-helper.socket", "crowdsec-gram-bot-helper@.service", "crowdsec-gram-bot-update.service", "crowdsec-gram-bot-update.timer", "crowdsec-gram-bot.service"}
	slices.Sort(first)
	if !slices.Equal(first, want) {
		t.Fatalf("first install wrote %v", first)
	}
	if again, err := writeUnits(dir); err != nil || len(again) != 0 {
		t.Fatalf("second install changed %v, %v", again, err)
	}
	bot := filepath.Join(dir, "crowdsec-gram-bot.service")
	os.WriteFile(bot, []byte("[Service]\nUser=root\n"), 0o666)
	if fixed, err := writeUnits(dir); err != nil || !slices.Equal(fixed, []string{"crowdsec-gram-bot.service"}) {
		t.Fatalf("drift fix changed %v, %v", fixed, err)
	}
	st, _ := os.Stat(bot)
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
}
