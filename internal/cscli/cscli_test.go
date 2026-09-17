package cscli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAvailableFalseWithoutBinary(t *testing.T) {
	old := os.Getenv("PATH")
	os.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", old)
	if Available() {
		t.Fatal("Available() = true with empty PATH")
	}
}

func TestDeleteMissingBinaryErrors(t *testing.T) {
	old := os.Getenv("PATH")
	os.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", old)
	if err := Delete(context.Background(), "1.2.3.4"); err == nil {
		t.Fatal("Delete with no cscli = nil error")
	}
}

func TestListParsesJSON(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho '[{\"value\":\"1.2.3.4\",\"scenario\":\"x\",\"type\":\"ban\"}]'\n"
	if err := os.WriteFile(filepath.Join(dir, "cscli"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("PATH")
	os.Setenv("PATH", dir+":"+old)
	defer os.Setenv("PATH", old)
	ds, err := List(context.Background())
	if err != nil || len(ds) != 1 || ds[0].Value != "1.2.3.4" {
		t.Fatalf("list = %+v, err = %v", ds, err)
	}
}

func TestListIgnoresStderrWarnings(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'level=warning msg=\"hub hiccup\"' >&2\necho '[{\"value\":\"2.3.4.5\",\"type\":\"ban\"}]'\n"
	if err := os.WriteFile(filepath.Join(dir, "cscli"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("PATH")
	os.Setenv("PATH", dir+":"+old)
	defer os.Setenv("PATH", old)
	ds, err := List(context.Background())
	if err != nil || len(ds) != 1 || ds[0].Value != "2.3.4.5" {
		t.Fatalf("list = %+v, err = %v", ds, err)
	}
}
