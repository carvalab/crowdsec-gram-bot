# crowdsec-gram-bot

Single Go binary: Telegram bot daemon **and** CLI to manage CrowdSec bans.
LAPI-first (machine credentials) with `cscli` fallback, systemd-native,
self-updating from GitHub releases.

Telegram (admin only): `/bans` `/unban <ip>` `/unbanwl <ip>` `/help`
CLI: `bot | bans | unban | unbanwl | version | update`

## Setup (CrowdSec host)

1. Machine creds (bouncer tokens **can't** delete decisions):
   `cscli machines add telegram-bot --auto` → login + password
2. Allowlist: `cscli allowlists create telegram-temp`
3. Build: `go build -o crowdsec-gram-bot .`
   (or with version: `go build -ldflags "-X main.version=v0.1.0" -o crowdsec-gram-bot .`)
4. Install: `sudo ./install.sh` (opens `$EDITOR` for `/etc/crowdsec-gram-bot.env`;
   `--no-edit` skips). Get your chat id from `@userinfobot`.

## CLI

```
crowdsec-gram-bot bans [--limit N] [--json] [--via cscli|lapi|auto] [--dry-run]
crowdsec-gram-bot unban [--via …] [--dry-run] <ip>
crowdsec-gram-bot unbanwl [--via …] [--ttl 720h] [--dry-run] <ip>
crowdsec-gram-bot version
crowdsec-gram-bot update [--check-only]
```

Env: `TELEGRAM_TOKEN`, `TELEGRAM_ADMIN_ID`, `CROWDSEC_LAPI_URL`
(default `http://127.0.0.1:8080`), `CROWDSEC_MACHINE_LOGIN/PASSWORD`,
`ALLOWLIST_ID` (default `telegram-temp`), `WHITELIST_TTL` (default `2160h`),
`LIST_LIMIT` (default `50`), `USE_CSCLI=0|1|auto` (default `auto`),
`GITHUB_REPO` (default `carvalab/crowdsec-gram-bot`),
`GITHUB_TOKEN` (private repos only, `contents:read`).

## Self-update

Releases (`vX.Y.Z` tags via goreleaser) ship
`crowdsec-gram-bot_<ver>_linux_<arch>.tar.gz` + `checksums.txt`.
`update` verifies sha256 fail-closed, replaces the binary, then:
`systemctl --no-block restart crowdsec-gram-bot`.

cscli equivalents: `cscli decisions list`, `cscli decisions delete --ip x.x.x.x`,
`cscli allowlists add telegram-temp x.x.x.x -e 2160h`.
