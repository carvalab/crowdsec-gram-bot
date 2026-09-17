# crowdsec-gram-bot — clean rewrite design (2026-09-17)

## Goal
Single Go binary that is both the Telegram bot daemon (systemd) and the manual CLI for CrowdSec bans. From Telegram: `/bans`, `/unban <ip>`, `/unbanwl <ip>`, `/help`. From shell: same actions as subcommands. Self-updates from GitHub releases. Clean rewrite from zero — no compat with current `main.go`, latest libs only.

## Non-goals
- No Bun/Node runtime on the server. No Docker requirement (systemd native; Dockerfile kept only as optional).
- No `go-cs-bouncer` (bouncer API key is read-only, cannot delete). No `crowdsec/pkg/apiclient` (heavy generated client).
- No multi-admin, no interactive TUI, no CAPI/console integration.

## Architecture
One module `github.com/carvalab/crowdsec-gram-bot`, stdlib `flag`-style dispatch in `main.go`, no CLI framework:
- `main.go` — dispatch: `bot | bans | unban | unbanwl | version | update`
- `internal/lapi/` — machine-auth client: `POST /v1/watchers/login`, `GET /v1/decisions?limit=`, `DELETE /v1/decisions?ip=`, `POST /v1/allowlists/{id}` (+ `/v1/allowlist/{id}` fallback for old servers)
- `internal/cscli/` — fallback executor: `cscli decisions list -o json`, `decisions delete --ip`, `allowlists add <list> <ip> -e <ttl>`; used only when `USE_CSCLI=1` or LAPI unreachable/404
- Telegram handlers and CLI subcommands call the same `unban(ip)`, `list()`, `unbanwl(ip)` functions.

## CLI UX
- `crowdsec-gram-bot bot` — polling daemon (systemd `ExecStart`)
- `crowdsec-gram-bot bans [--limit N] [--json]` — list
- `crowdsec-gram-bot unban 1.2.3.4 [--via cscli|lapi|auto]` — delete decision
- `crowdsec-gram-bot unbanwl 1.2.3.4 [--ttl 2160h]` — delete + allowlist add
- `crowdsec-gram-bot version` — prints `version/commit/date` from ldflags
- `crowdsec-gram-bot update [--check-only]` — compare with GitHub latest release, download `*_linux_<arch>.tar.gz`, apply, print release notes
- Global: `--dry-run` for unban/unbanwl (prints cscli equiv + LAPI request, changes nothing).

## systemd
- Unit `systemd/crowdsec-gram-bot.service`: `ExecStart=/usr/local/bin/crowdsec-gram-bot bot`, `EnvironmentFile=/etc/crowdsec-gram-bot.env`, `Restart=always`, `NoNewPrivileges=true`, `ProtectSystem=strict` (writable `/tmp` only unless cscli fallback needs `cscli` in `PATH`).
- `install.sh`: copies binary, writes unit, ensures `/etc/crowdsec-gram-bot.env` exists (seeded from `.env.example` if missing, `0600 root:root`), then opens `$EDITOR` (fallback `vi`) so the installer configures secrets on first run; `--no-edit` skips. Then `daemon-reload + enable --now`. Env file never committed.
- Docker kept only for dev parity; production path is systemd.

## Autoupdate / releases
- goreleaser: `linux/amd64,arm64` tar.gz + checksums, tag `vX.Y.Z` triggers release.
- Updater lib: `github.com/minio/selfupdate` (apply) + plain GitHub REST `GET /repos/{owner}/{repo}/releases/latest` (no heavy github client needed). Asset match `runtime.GOOS/runtime.GOARCH`. `Authorization: Bearer $GITHUB_TOKEN` sent only when set (private repo); updater fails fast with `set GITHUB_TOKEN for private repo` on 401/404.
- Bot logs `new version available, run update` on start; `update` does replace + `systemctl --no-block restart` hint. Optional timer unit later, not in v1.

## Config / env
Keys (same for `.env` dev and `/etc/crowdsec-gram-bot.env` prod):
`TELEGRAM_TOKEN` (required), `TELEGRAM_ADMIN_ID` (required, numeric chat id), `CROWDSEC_LAPI_URL` (default `http://127.0.0.1:8080`), `CROWDSEC_MACHINE_LOGIN/PASSWORD` (required — machine creds from `cscli machines add telegram-bot --auto`), `ALLOWLIST_ID` (default `telegram-temp`), `WHITELIST_TTL` (default `2160h`), `LIST_LIMIT` (default `50`), `USE_CSCLI` (`0|1|auto`, default `auto`), `GITHUB_REPO` (default `carvalab/crowdsec-gram-bot` — this origin), `GITHUB_TOKEN` (required for private repo, `contents:read`; empty = public anonymous mode, 60 req/h).
Fresh `.env.example` ships all keys with comments; `install.sh` seeds `/etc/crowdsec-gram-bot.env` from it.
Fail fast with `missing required env X` on start.

## Security
- Telegram: `adminOnly` gate — `update.Message.Chat.ID == TELEGRAM_ADMIN_ID`, silent ignore otherwise. Document ID lookup via `@userinfobot`.
- Secrets only in env file, never in CLI args/logs. `compact()` truncates LAPI bodies to 300 chars in errors.
- Machine creds required; detect bouncer-token 403 and print `need MACHINE creds, not bouncer key`.

## Error handling
- LAPI 401/403 → single re-login retry, then explicit error.
- Allowlist 404 → `create list first: cscli allowlists create <id>`; other non-2xx → error includes `cscli equiv` string.
- cscli fallback errors include stderr tail; missing `cscli` binary → clear `cscli not found in PATH` (not silent).

## Testing
- `go vet ./...` + `gofmt -l .` clean. No framework; one `test_*.go` with stdlib asserts for `argIP`, version compare, asset-name match.
- Manual: `bans` output diffed vs `cscli decisions list`; `unban --dry-run` before real; `update --check-only` in CI.

## Rollout (clean rewrite)
Delete `main.go`, `go.mod`, `Dockerfile`, `docker-compose.yml` content and rewrite from zero on `main` (first and only version). Resolve latest at rewrite time: newest `golang:*-alpine` toolchain, `go get -u github.com/go-telegram/bot@latest` (v1.25.0, Bot API 10.3 as of 2026-09-01), `github.com/minio/selfupdate@latest`. Verify with `go mod tidy && CGO_ENABLED=0 go build`.

## References
- LAPI swagger: https://crowdsecurity.github.io/api_doc/lapi/
- Auth model: https://docs.crowdsec.net/docs/next/local_api/authentication/ (machines login/password = write; bouncers API key = read-only)
- Self-update pattern: https://one2n.io/blog/making-your-go-cli-binaries-self-updatable (latest-release lookup + minio/selfupdate.Apply)
- Bun executables (rejected): https://bun.com/docs/bundler/executables (50-80MB, weak updater story)
