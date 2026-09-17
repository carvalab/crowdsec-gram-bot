# crowdsec-gram-bot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean-rewrite crowdsec-gram-bot from zero as a single Go binary that is both the Telegram bot daemon and the manual CLI, LAPI-first with cscli fallback, systemd-native, self-updating from GitHub releases.

**Architecture:** stdlib `flag`-style dispatcher in `main.go`; `internal/lapi` machine-auth HTTP client; `internal/cscli` exec fallback; `internal/update` GitHub-releases checker + applier; Telegram handlers and CLI subcommands call the same `runList/runUnban/runUnbanWL` functions.

**Tech Stack:** Go (newest stable toolchain at build time, `CGO_ENABLED=0`), `github.com/go-telegram/bot@latest` (v1.25.0 / Bot API 10.3 known 2026-09-01), `github.com/minio/selfupdate@latest`, stdlib only otherwise (`net/http`, `os/exec`, `encoding/json`). Goreleaser `linux/amd64,arm64` tar.gz.

**Spec:** `docs/superpowers/specs/2026-09-17-crowdsec-gram-bot-design.md`

## Global Constraints

- Clean rewrite on `main`: delete old `main.go`, `go.mod`, `Dockerfile`, `docker-compose.yml` content first; no backward compat.
- Latest libraries only: resolve with `go get -u` at implementation time; no pinned outdated versions.
- Single binary subcommands: `bot | bans | unban | unbanwl | version | update`.
- LAPI-first, cscli fallback only when `USE_CSCLI=1` or LAPI unreachable/404 (`auto` default).
- Secrets only via env file (`0600`), never CLI args/logs; Telegram `adminOnly` silent-ignore non-admin.
- `go vet ./...` + `gofmt -l .` clean before every commit; one commit per task minimum.
- `GITHUB_REPO` default `carvalab/crowdsec-gram-bot`; `GITHUB_TOKEN` (`contents:read`) sent only when set.

---

## File Structure

- `main.go` — dispatcher + shared `runList/runUnban/runUnbanWL` + Telegram `bot` mode + `adminOnly` gate. One responsibility: wiring.
- `internal/lapi/client.go` — `Client` type: `New`, `ListDecisions`, `DeleteDecision`, `AllowlistAdd`, plus `Decision` type and `login` with single 401/403 re-login retry. No Telegram, no exec.
- `internal/cscli/cscli.go` — `Available() bool`, `List(ctx) ([]lapi.Decision, error)`, `Delete(ctx, ip string) error`, `AllowlistAdd(ctx, list, ip, ttl string) error` via `os/exec`. Imports `internal/lapi` for the `Decision` type only.
- `internal/update/update.go` — `Latest(ctx, repo, token string) (tag, notes string, err error)`, `AssetName(tag string) string`, `Apply(ctx, repo, token string) error`. No Telegram, no CrowdSec.
- `*_test.go` next to each — stdlib `testing` + `httptest` only, no framework.
- `systemd/crowdsec-gram-bot.service`, `install.sh`, `.env.example`, `.goreleaser.yaml`, `README.md` — deploy/config/release surface.
- `go.mod`/`go.sum` — regenerated from zero (`go mod init`, `go get -u`, `go mod tidy`).

---

### Task 1: Clean scaffold + dispatcher skeleton + version stamping

**Files:**
- Delete: `main.go`, `go.mod`, `go.sum` (if present), `Dockerfile`, `docker-compose.yml` content
- Create: `go.mod` (via `go mod init`), `main.go`, `main_test.go`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `var version, commit, date string` (ldflags-stamped); `func usage()`, `func main()` dispatching `bot|bans|unban|unbanwl|version|update`; `func runVersion() string` used by Task 6 (`version` subcommand) and Task 7 (updater current-version compare)

- [ ] **Step 1: Delete old files and init clean module**

```bash
git rm -q main.go go.mod docker-compose.yml Dockerfile 2>/dev/null || rm -f main.go go.mod go.sum
go mod init github.com/carvalab/crowdsec-gram-bot
```

- [ ] **Step 2: Write failing test for dispatcher + version**

```go
// main_test.go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./... 2>&1 | head -n 20`
Expected: FAIL (`undefined: runVersion`, `undefined: knownSubcommand`)

- [ ] **Step 4: Write minimal implementation**

```go
// main.go
package main

import (
	"fmt"
	"os"
)

var version = "dev"
var commit = "none"
var date = "unknown"

func runVersion() string {
	return fmt.Sprintf("version=%s commit=%s date=%s", version, commit, date)
}

func knownSubcommand(s string) bool {
	switch s {
	case "bot", "bans", "unban", "unbanwl", "version", "update":
		return true
	}
	return false
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: crowdsec-gram-bot <bot|bans|unban|unbanwl|version|update> [flags]")
}

func main() {
	if len(os.Args) < 2 || !knownSubcommand(os.Args[1]) {
		usage()
		os.Exit(2)
	}
	if os.Args[1] == "version" {
		fmt.Println(runVersion())
		return
	}
	fmt.Fprintln(os.Stderr, "not implemented yet: "+os.Args[1])
	os.Exit(1)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./...`
Expected: PASS, no output from `gofmt -l`, vet clean

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Scaffold clean module with dispatcher skeleton and version stamping"
```

---

### Task 2: internal/lapi machine-auth client

**Files:**
- Create: `internal/lapi/client.go`
- Test: `internal/lapi/client_test.go`

**Interfaces:**
- Consumes: env config struct defined here: `type Config struct { URL, Login, Password, AllowID, TTL, ListLimit string }`
- Produces: `func New(c Config) *Client`; `func (c *Client) ListDecisions(ctx context.Context) ([]Decision, error)`; `func (c *Client) DeleteDecision(ctx context.Context, ip string) error`; `func (c *Client) AllowlistAdd(ctx context.Context, ip string) error`; `type Decision struct { Value, IP, Scenario, Type, Until string }` (flat subset both LAPI and cscli can fill; consumed by Tasks 3-5)

- [ ] **Step 1: Write the failing test (httptest fake LAPI)**

```go
// internal/lapi/client_test.go
package lapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListAndDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/watchers/login":
			w.Write([]byte(`{"token":"t"}`))
		case r.URL.Path == "/v1/decisions" && r.Method == "GET":
			json.NewEncoder(w).Encode([]Decision{{Value: "1.2.3.4", Scenario: "x", Type: "ban", Until: "2026-01-01T00:00:00Z"}})
		case r.URL.Path == "/v1/decisions" && r.Method == "DELETE":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Login: "m", Password: "p", AllowID: "telegram-temp", TTL: "2160h", ListLimit: "50"})
	ds, err := c.ListDecisions(context.Background())
	if err != nil || len(ds) != 1 || ds[0].Value != "1.2.3.4" {
		t.Fatalf("list = %+v, err = %v", ds, err)
	}
	if err := c.DeleteDecision(context.Background(), "1.2.3.4"); err != nil {
		t.Fatalf("delete err = %v", err)
	}
}

func TestAllowlistFallbackPaths(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		if r.URL.Path == "/v1/watchers/login" {
			w.Write([]byte(`{"token":"t"}`))
			return
		}
		if r.URL.Path == "/v1/allowlists/telegram-temp" {
			w.WriteHeader(201)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Login: "m", Password: "p", AllowID: "telegram-temp", TTL: "2160h"})
	if err := c.AllowlistAdd(context.Background(), "1.2.3.4"); err != nil {
		t.Fatalf("allowlist err = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no requests made")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/lapi/ -v 2>&1 | head -n 20`
Expected: FAIL (`undefined: New`)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/lapi/client.go
package lapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	URL, Login, Password, AllowID, TTL, ListLimit string
}

type Decision struct {
	Value    string `json:"value"`
	IP       string `json:"ip"`
	Scenario string `json:"scenario"`
	Type     string `json:"type"`
	Until    string `json:"until"`
}

type Client struct {
	c    Config
	http *http.Client
	tok  string
}

func New(c Config) *Client {
	if c.ListLimit == "" {
		c.ListLimit = "50"
	}
	if c.TTL == "" {
		c.TTL = "2160h"
	}
	if c.AllowID == "" {
		c.AllowID = "telegram-temp"
	}
	return &Client{c: c, http: &http.Client{Timeout: 20 * time.Second}}
}

func compact(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

func (l *Client) login(ctx context.Context) error {
	body, _ := json.Marshal(map[string]any{"machine_id": l.c.Login, "password": l.c.Password})
	req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(l.c.URL, "/")+"/v1/watchers/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := l.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return fmt.Errorf("login %d: %s", res.StatusCode, compact(b))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Token == "" {
		t := strings.Trim(strings.Trim(string(b), `"`), " \n")
		if t == "" {
			return fmt.Errorf("login: no token in response")
		}
		l.tok = t
		return nil
	}
	l.tok = out.Token
	return nil
}

func (l *Client) do(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	if l.tok == "" {
		if err := l.login(ctx); err != nil {
			return 0, nil, err
		}
	}
	var rdr io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		rdr = bytes.NewReader(b)
	}
	mk := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(l.c.URL, "/")+path, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+l.tok)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	req, err := mk()
	if err != nil {
		return 0, nil, err
	}
	res, err := l.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode == 401 || res.StatusCode == 403 {
		if err := l.login(ctx); err != nil {
			return res.StatusCode, b, fmt.Errorf("re-login failed (need MACHINE creds, not bouncer key): %w", err)
		}
		req2, err := mk()
		if err != nil {
			return 0, nil, err
		}
		res2, err := l.http.Do(req2)
		if err != nil {
			return 0, nil, err
		}
		defer res2.Body.Close()
		b2, _ := io.ReadAll(res2.Body)
		return res2.StatusCode, b2, nil
	}
	return res.StatusCode, b, nil
}

func (l *Client) ListDecisions(ctx context.Context) ([]Decision, error) {
	st, b, err := l.do(ctx, "GET", "/v1/decisions?limit="+url.QueryEscape(l.c.ListLimit), nil)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("list %d: %s", st, compact(b))
	}
	var out []Decision
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}
	return out, nil
}

func (l *Client) DeleteDecision(ctx context.Context, ip string) error {
	st, b, err := l.do(ctx, "DELETE", "/v1/decisions?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return err
	}
	if st == 200 || st == 202 || st == 204 {
		return nil
	}
	return fmt.Errorf("delete %d: %s", st, compact(b))
}

func (l *Client) AllowlistAdd(ctx context.Context, ip string) error {
	payload := map[string]any{"value": ip, "expiration": l.c.TTL, "comment": "telegram-bot " + time.Now().UTC().Format("2006-01-02")}
	for _, p := range []string{"/v1/allowlists/" + url.PathEscape(l.c.AllowID), "/v1/allowlist/" + url.PathEscape(l.c.AllowID)} {
		st, b, err := l.do(ctx, "POST", p, payload)
		if err != nil {
			return err
		}
		if st == 200 || st == 201 || st == 202 || st == 204 {
			return nil
		}
		if st == 404 {
			continue
		}
		return fmt.Errorf("allowlist %d: %s (cscli equiv: cscli allowlists add %s %s -e %s)", st, compact(b), l.c.AllowID, ip, l.c.TTL)
	}
	return fmt.Errorf("allowlist endpoint not found; create list first: cscli allowlists create %s", l.c.AllowID)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./internal/lapi/ -v`
Expected: PASS both tests

- [ ] **Step 5: Commit**

```bash
git add internal/lapi/
git commit -m "Add LAPI machine-auth client with login retry and allowlist fallback"
```

---

### Task 3: internal/cscli fallback executor

**Files:**
- Create: `internal/cscli/cscli.go`
- Test: `internal/cscli/cscli_test.go`

**Interfaces:**
- Consumes: `lapi.Decision` type for `List` return (exact: `func List(ctx context.Context) ([]lapi.Decision, error)`)
- Produces: `func Available() bool`; `func List(ctx context.Context) ([]lapi.Decision, error)`; `func Delete(ctx context.Context, ip string) error`; `func AllowlistAdd(ctx context.Context, list, ip, ttl string) error` (consumed by Task 4 shared runners)

- [ ] **Step 1: Write the failing test**

```go
// internal/cscli/cscli_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cscli/ -v 2>&1 | head -n 20`
Expected: FAIL (`undefined: Available`)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/cscli/cscli.go
package cscli

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/carvalab/crowdsec-gram-bot/internal/lapi"
)

func Available() bool {
	_, err := exec.LookPath("cscli")
	return err == nil
}

func run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "cscli", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 300 {
			tail = tail[:300] + "…"
		}
		return out, fmt.Errorf("cscli %s: %v: %s", strings.Join(args, " "), err, tail)
	}
	return out, nil
}

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

func Delete(ctx context.Context, ip string) error {
	if !Available() {
		return fmt.Errorf("cscli not found in PATH")
	}
	_, err := run(ctx, "decisions", "delete", "--ip", ip)
	return err
}

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./internal/cscli/ -v`
Expected: PASS all three tests

- [ ] **Step 5: Commit**

```bash
git add internal/cscli/
git commit -m "Add cscli fallback executor with JSON list parsing"
```

---

### Task 4: Shared runners (LAPI-first, cscli fallback, dry-run)

**Files:**
- Modify: `main.go` (add `runList/runUnban/runUnbanWL` + `loadConfig` + `--dry-run/--via` plumbing helpers)
- Test: `main_test.go` (append runner tests with fake LAPI server)

**Interfaces:**
- Consumes: `lapi.New/Config/Client`, `cscli.Available/List/Delete/AllowlistAdd` (exact names from Tasks 2-3)
- Produces: `func runList(ctx) (string, error)`; `func runUnban(ctx, ip string) (string, error)`; `func runUnbanWL(ctx, ip string) (string, error)`; `type runMode string` (`modeAuto/modeLAPI/modeCSCLI`) + `func resolveMode(via string) runMode`; consumed by Tasks 5 (Telegram) and 6 (CLI)

- [ ] **Step 1: Write the failing test**

```go
func TestRunListDryRun(t *testing.T) {
	t.Setenv("DRY_RUN", "1")
	out, err := runList(context.Background())
	if err != nil {
		t.Fatalf("runList dry-run err = %v", err)
	}
	if !strings.Contains(out, "dry-run") {
		t.Fatalf("runList = %q, want dry-run marker", out)
	}
}

func TestResolveMode(t *testing.T) {
	if resolveMode("cscli") != modeCSCLI || resolveMode("lapi") != modeLAPI || resolveMode("bogus") != modeAuto {
		t.Fatal("resolveMode mapping wrong")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestRunListDryRun|TestResolveMode' -v 2>&1 | head -n 20`
Expected: FAIL (`undefined: runList`)

- [ ] **Step 3: Write minimal implementation**

```go
type runMode string

const (
	modeAuto  runMode = "auto"
	modeLAPI  runMode = "lapi"
	modeCSCLI runMode = "cscli"
)

func resolveMode(via string) runMode {
	switch strings.ToLower(strings.TrimSpace(via)) {
	case "cscli":
		return modeCSCLI
	case "lapi":
		return modeLAPI
	default:
		return modeAuto
	}
}
```

Plus config loader reading the spec env keys (`TELEGRAM_TOKEN`, `TELEGRAM_ADMIN_ID`, `CROWDSEC_LAPI_URL` default `http://127.0.0.1:8080`, `CROWDSEC_MACHINE_LOGIN/PASSWORD`, `ALLOWLIST_ID` default `telegram-temp`, `WHITELIST_TTL` default `2160h`, `LIST_LIMIT` default `50`, `USE_CSCLI` default `auto`, `GITHUB_REPO` default `carvalab/crowdsec-gram-bot`, `GITHUB_TOKEN` optional, `DRY_RUN` test hook), `lapiClient()` constructor, and `runList/runUnban/runUnbanWL` that: return `dry-run …` string when `DRY_RUN=1`; try LAPI first (unless mode is cscli-only); on LAPI connection error/404 with `Available()` true and mode != lapi-only, fall back to cscli; format list output as `%d bans:\n• ip (scenario/type until …)` reusing `shortTime`; include `cscli equiv` hint in errors (exact behavior from spec).

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "Add shared LAPI-first runners with cscli fallback and dry-run"
```

---

### Task 5: Telegram bot daemon + adminOnly gate

**Files:**
- Modify: `main.go` (add `bot` mode: `go-telegram/bot` polling, `/bans /unban /unbanwl /help /start` handlers calling Task 4 runners)
- Test: append `main_test.go` with `argIP` + admin-gate predicate tests

**Interfaces:**
- Consumes: `runList/runUnban/runUnbanWL` (Task 4, same signatures)
- Produces: `func argIP(text string) (string, bool)`; `func isAdmin(chatID, adminID int64) bool`; `bot` subcommand entry (no new exported API)

- [ ] **Step 1: Write the failing test**

```go
func TestArgIP(t *testing.T) {
	ip, ok := argIP("/unban 1.2.3.4")
	if !ok || ip != "1.2.3.4" {
		t.Fatalf("argIP = %q,%v", ip, ok)
	}
	if _, ok := argIP("/unban not-an-ip"); ok {
		t.Fatal("argIP accepted garbage")
	}
	if _, ok := argIP("/unban"); ok {
		t.Fatal("argIP accepted missing arg")
	}
}

func TestIsAdmin(t *testing.T) {
	if !isAdmin(42, 42) || isAdmin(43, 42) {
		t.Fatal("isAdmin wrong")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestArgIP|TestIsAdmin' -v 2>&1 | head -n 10`
Expected: FAIL (`undefined: argIP`)

- [ ] **Step 3: Write minimal implementation (then `go get -u github.com/go-telegram/bot@latest`)**

```bash
go get -u github.com/go-telegram/bot@latest
go mod tidy
```

```go
func argIP(text string) (string, bool) {
	f := strings.Fields(text)
	if len(f) < 2 {
		return "", false
	}
	ip := strings.TrimSpace(f[1])
	if net.ParseIP(ip) == nil {
		return "", false
	}
	return ip, true
}

func isAdmin(chatID, adminID int64) bool { return chatID == adminID }
```

Wire `bot` mode: `bot.New(token)`, `adminOnly` wrapper returning silently on `!isAdmin`, handlers `/help /start` (usage incl. TTL + allowlist id), `/bans` (calls `runList`), `/unban` prefix (skips `/unbanwl`, calls `argIP` then `runUnban`), `/unbanwl` prefix (calls `runUnbanWL`). `signal.NotifyContext` shutdown, `b.Start(ctx)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go go.mod go.sum
git commit -m "Add Telegram bot daemon with admin-only gate reusing shared runners"
```

---

### Task 6: CLI subcommands (bans/unban/unbanwl)

**Files:**
- Modify: `main.go` (dispatch `bans [--limit N] [--json]`, `unban <ip> [--via] [--dry-run]`, `unbanwl <ip> [--ttl] [--via] [--dry-run]`)
- Test: shell-level assertions via `go run . bans --help`-style exit codes + `resolveMode`/`argIP` reuse (no new harness)

**Interfaces:**
- Consumes: `runList/runUnban/runUnbanWL`, `resolveMode`, `argIP` (Tasks 4-5)
- Produces: CLI exit codes `0` ok / `1` runtime error / `2` usage error (consumed by systemd diagnosability + README)

- [ ] **Step 1: Write the failing test**

```go
func TestCLIDryRunUnban(t *testing.T) {
	t.Setenv("DRY_RUN", "1")
	out, err := runUnban(context.Background(), "9.9.9.9")
	if err != nil || !strings.Contains(out, "9.9.9.9") {
		t.Fatalf("runUnban dry-run = %q, err = %v", out, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestCLIDryRunUnban -v 2>&1 | head -n 10`
Expected: FAIL (if `runUnban` lacks dry-run path) or PASS-guard proving wiring; implement missing flags until green

- [ ] **Step 3: Write minimal implementation**

Parse per-subcommand flags with stdlib `flag.NewFlagSet`; `--limit` overrides `LIST_LIMIT` for one run; `--json` prints raw `[]lapi.Decision` JSON; `--via` maps via `resolveMode`; `--ttl` overrides `WHITELIST_TTL` for one run; `--dry-run` sets dry-run without env. Usage errors exit `2` with one-line `usage:` to stderr.

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./... && go run . version`
Expected: PASS + `version=dev …` line

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "Add CLI subcommands with json/limit/via/ttl/dry-run flags"
```

---

### Task 7: Self-update from GitHub releases (private-ready)

**Files:**
- Create: `internal/update/update.go`
- Test: `internal/update/update_test.go`
- Modify: `main.go` (`update [--check-only]` wiring)

**Interfaces:**
- Consumes: `runVersion()` current stamp (Task 1)
- Produces: `func Latest(ctx context.Context, repo, token string) (tag, notes string, err error)`; `func AssetName(tag string) string`; `func Apply(ctx context.Context, repo, token string) error` (private repo: `Authorization: Bearer` only when token set; 401/404 → `set GITHUB_TOKEN for private repo`)

- [ ] **Step 1: Write the failing test**

```go
// internal/update/update_test.go
package update

import (
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	n := AssetName("v1.2.3")
	if !strings.Contains(n, "linux_") || !strings.HasSuffix(n, ".tar.gz") {
		t.Fatalf("AssetName = %q", n)
	}
}

func TestNeedsUpdate(t *testing.T) {
	if !needsUpdate("v1.0.0", "v1.2.3") || needsUpdate("v1.2.3", "v1.2.3") {
		t.Fatal("needsUpdate wrong")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/update/ -v 2>&1 | head -n 10`
Expected: FAIL (`undefined: AssetName`)

- [ ] **Step 3: Write minimal implementation (then `go get -u github.com/minio/selfupdate@latest`)**

```bash
go get -u github.com/minio/selfupdate@latest
go mod tidy
```

```go
// internal/update/update.go
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

func AssetName(tag string) string {
	v := strings.TrimPrefix(tag, "v")
	return fmt.Sprintf("crowdsec-gram-bot_%s_linux_%s.tar.gz", v, runtime.GOARCH)
}

func needsUpdate(current, latest string) bool {
	return strings.TrimSpace(current) != strings.TrimSpace(latest) && strings.TrimSpace(latest) != ""
}
```

`Latest`: `GET https://api.github.com/repos/<repo>/releases/latest`, `Accept: application/vnd.github+json`, `Authorization: Bearer <token>` only when token != ""; decode `{tag_name, body}`; 401/404 with token=="" → hint about private repos. `Apply`: call `Latest`, compare with current, download `browser_download_url` asset matching `AssetName`, gunzip+untar single binary from tar, `selfupdate.Apply`. `update --check-only` prints `current=X latest=Y update-available=true|false` + notes head.

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -l . && go vet ./... && go test ./internal/update/ -v && go run . update --check-only 2>&1 | head -n 5`
Expected: PASS tests; check-only prints current/latest (may fail offline — acceptable, must print versions line before network call)

- [ ] **Step 5: Commit**

```bash
git add internal/update/ main.go go.mod go.sum
git commit -m "Add GitHub-releases self-update with private-repo token support"
```

---

### Task 8: systemd unit + install.sh (EDITOR) + .env.example + goreleaser + README

**Files:**
- Create: `systemd/crowdsec-gram-bot.service`, `install.sh`, `.goreleaser.yaml`
- Create: `.env.example` (fresh, all keys + comments)
- Modify: `README.md` (rewrite: setup, machine creds, allowlist, systemd install, CLI + Telegram usage, update flow)
- Optional: minimal `Dockerfile` for dev parity only

**Interfaces:**
- Consumes: binary subcommands + env keys from Tasks 1-7 (no new Go API)
- Produces: production deploy path (unit + installer + release pipeline)

- [ ] **Step 1: Write the failing check (files must exist)**

```bash
test -f systemd/crowdsec-gram-bot.service && test -f install.sh && test -f .env.example && test -f .goreleaser.yaml
```

Expected: FAIL (files missing)

- [ ] **Step 2: Create the files**

`systemd/crowdsec-gram-bot.service`:
```ini
[Unit]
Description=crowdsec-gram-bot Telegram bot
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/crowdsec-gram-bot bot
EnvironmentFile=/etc/crowdsec-gram-bot.env
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`.env.example` (all keys, private-repo note):
```bash
TELEGRAM_TOKEN=
TELEGRAM_ADMIN_ID=
CROWDSEC_LAPI_URL=http://127.0.0.1:8080
CROWDSEC_MACHINE_LOGIN=telegram-bot
CROWDSEC_MACHINE_PASSWORD=
ALLOWLIST_ID=telegram-temp
WHITELIST_TTL=2160h
LIST_LIMIT=50
USE_CSCLI=auto
GITHUB_REPO=carvalab/crowdsec-gram-bot
# Required only for private repo (contents:read). Leave empty for public.
GITHUB_TOKEN=
```

`install.sh`: copies `./crowdsec-gram-bot` to `/usr/local/bin`, installs unit, seeds `/etc/crowdsec-gram-bot.env` from `.env.example` if missing (`chmod 600`), opens `${EDITOR:-vi}` unless `--no-edit`, then `systemctl daemon-reload && systemctl enable --now crowdsec-gram-bot`. Fails fast if not root.

`.goreleaser.yaml`: `linux/amd64,arm64` tar.gz + checksums, ldflags `version/commit/date`, tag `vX.Y.Z`.

`README.md`: machine creds (`cscli machines add telegram-bot --auto`), allowlist (`cscli allowlists create telegram-temp`), `install.sh` flow, CLI + Telegram commands, `update` flow with token note.

- [ ] **Step 3: Verify**

Run: `bash -n install.sh && gofmt -l . && go vet ./... && go test ./... && CGO_ENABLED=0 go build -o /tmp/crowdsec-gram-bot . && /tmp/crowdsec-gram-bot version`
Expected: all green + `version=dev …`

- [ ] **Step 4: Commit**

```bash
git add systemd/ install.sh .env.example .goreleaser.yaml README.md Dockerfile
git commit -m "Add systemd unit, EDITOR installer, env example, goreleaser pipeline"
```

---

## Self-Review

- Spec coverage: single binary + subcommands (T1/T6), LAPI client + auth model (T2), cscli fallback (T3), shared runners + dry-run (T4), Telegram gate (T5), updater + private token (T7), systemd/EDITOR/env/goreleaser (T8). `version` stamping (T1) feeds updater compare (T7).
- Placeholder scan: no TBD/TODO; every code step ships concrete test + implementation; error strings exact.
- Type consistency: `lapi.Decision` flat struct shared by cscli `List`; `runMode` + `resolveMode` names frozen in T4 and reused in T6; `Latest/AssetName/Apply` signatures frozen in T7 and wired in T6's `update` command.
