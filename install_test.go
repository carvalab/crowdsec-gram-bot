package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bot.env")
	if err := setValue(file, "TELEGRAM_TOKEN", "abc=123"); err != nil {
		t.Fatal(err)
	}
	if err := setValue(file, "TELEGRAM_ADMIN_ID", "42"); err != nil {
		t.Fatal(err)
	}
	if err := setValue(file, "TELEGRAM_TOKEN", "new"); err != nil {
		t.Fatal(err)
	}
	if got := savedValue(file, "TELEGRAM_TOKEN", "."); got != "new" {
		t.Fatalf("token = %q", got)
	}
	if got := savedValue(file, "TELEGRAM_ADMIN_ID", "[0-9]"); got != "42" {
		t.Fatalf("id = %q", got)
	}
	if savedValue(file, "TELEGRAM_ADMIN_ID", "[0-9][0-9][0-9]") != "" {
		t.Fatal("a short id matched a long pattern")
	}
	b, _ := os.ReadFile(file)
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, content %q", st.Mode(), b)
	}
}

func TestLocalURL(t *testing.T) {
	for _, s := range []string{"", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080", "127.0.0.1", "::1"} {
		if !localURL(s) {
			t.Errorf("%q should be local", s)
		}
	}
	for _, s := range []string{"http://10.0.0.5:8080", "db.internal", "http://127.0.0.1.evil:8080"} {
		if localURL(s) {
			t.Errorf("%q should not be local", s)
		}
	}
}
