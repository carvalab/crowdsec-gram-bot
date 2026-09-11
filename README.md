# crowdsec-gram-bot

Telegram polling bot (Go + [go-telegram/bot](https://github.com/go-telegram/bot), zero-deps) to manage CrowdSec bans via LAPI.

Commands: `/bans` `/unban <ip>` `/unbanwl <ip>` (delete + whitelist 90d) `/help`. Only `TELEGRAM_ADMIN_ID` is answered.

## Setup

1. Machine creds (bouncer tokens **can't** delete decisions):
   `cscli machines add telegram-bot --auto` → login + password
2. Allowlist: `cscli allowlists create telegram-temp` (or `allowlist` on older versions)
3. `cp .env.example .env` and fill values
4. `docker compose up -d --build`

cscli equivalents: `cscli decisions list`, `cscli decisions delete --ip x.x.x.x`, `cscli allowlists add telegram-temp x.x.x.x -e 2160h`.
