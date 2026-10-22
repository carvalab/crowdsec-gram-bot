#!/bin/sh
# Install, upgrade or remove crowdsec-gram-bot on a host where CrowdSec is
# installed from apt. Run it from the unpacked release folder; the systemd
# units come from the binary itself.
#
#   sudo ./install.sh              install or upgrade; asks for missing settings
#   sudo ./install.sh --uninstall  stop and remove the bot, keep its settings
#
# Without a terminal, settings come from the environment (TELEGRAM_TOKEN,
# TELEGRAM_ADMIN_ID, GITHUB_TOKEN). Prefer the prompts: values on a command
# line show up in ps and in the shell history.
set -eu

NAME=crowdsec-gram-bot
BIN=/usr/local/bin/$NAME
CONF=/etc/$NAME
UNITS="$NAME.service $NAME-helper.socket $NAME-helper@.service $NAME-update.service $NAME-update.timer"

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root: sudo ./install.sh"
command -v systemctl >/dev/null || die "systemd is required"
cd "$(dirname "$0")"

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now $NAME.service $NAME-update.timer $NAME-helper.socket 2>/dev/null || true
  for u in $UNITS; do rm -f "/etc/systemd/system/$u"; done
  systemctl daemon-reload
  rm -f "$BIN" "$BIN.old"
  rm -rf /var/lib/$NAME
  id -u $NAME >/dev/null 2>&1 && userdel $NAME
  echo "removed. Settings are kept in $CONF; delete them with: rm -r $CONF"
  echo "The CrowdSec allowlist is kept; delete it with: cscli allowlists delete <name>"
  exit 0
fi

command -v cscli >/dev/null || die "cscli not found: install CrowdSec from apt first"
[ -f ./$NAME ] || die "./$NAME binary not found next to install.sh"
csv=$(cscli version 2>&1 | sed -n 's/^version: v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -n 1)
if [ -z "$csv" ] || [ "$(printf '%s\n1.6.8\n' "$csv" | sort -V | head -n 1)" != 1.6.8 ]; then
  die "CrowdSec ${csv:-of unknown version} is too old: allowlists need 1.6.8 or newer.
Ubuntu's own package is older. Use CrowdSec's repository:
  curl -s https://install.crowdsec.net | sudo sh && sudo apt install crowdsec"
fi

ask() { # ask VAR "prompt" [secret]
  eval "val=\${$1:-}"
  if [ -z "$val" ] && [ -t 0 ]; then
    printf '%s' "$2"
    [ "${3:-}" = secret ] && stty -echo
    read -r val
    [ "${3:-}" = secret ] && { stty echo; echo; }
  fi
  eval "$1=\$val"
}

set_kv() { # set_kv FILE KEY VALUE, values are written as-is
  tmp=$(mktemp "$CONF/.env.XXXXXX")
  grep -v "^$2=" "$1" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$2" "$3" >> "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$1"
}

id -u $NAME >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin $NAME
install -d -m 0700 -o root -g root "$CONF"

if [ -f /etc/$NAME.env ]; then
  echo "found settings from the old version in /etc/$NAME.env, moving them"
  if [ ! -f "$CONF/bot.env" ]; then
    grep -E '^TELEGRAM_(TOKEN|ADMIN_ID)=' /etc/$NAME.env > "$CONF/bot.env" || true
    chmod 0600 "$CONF/bot.env"
  fi
  rm -f /etc/$NAME.env
fi
if cscli machines list -o raw 2>/dev/null | cut -d, -f1 | grep -qx telegram-bot; then
  cscli machines delete telegram-bot >/dev/null && echo "deleted the old 'telegram-bot' CrowdSec machine account; it is not needed any more"
fi

touch "$CONF/bot.env" "$CONF/update.env"
chmod 0600 "$CONF/bot.env" "$CONF/update.env"
if ! grep -q '^TELEGRAM_TOKEN=.' "$CONF/bot.env"; then
  ask TELEGRAM_TOKEN "Telegram bot token from @BotFather: " secret
  [ -n "$TELEGRAM_TOKEN" ] || die "TELEGRAM_TOKEN is required"
  set_kv "$CONF/bot.env" TELEGRAM_TOKEN "$TELEGRAM_TOKEN"
fi
if ! grep -q '^TELEGRAM_ADMIN_ID=[0-9]' "$CONF/bot.env"; then
  ask TELEGRAM_ADMIN_ID "Your numeric Telegram user id (ask @userinfobot): "
  case "$TELEGRAM_ADMIN_ID" in ''|*[!0-9]*) die "TELEGRAM_ADMIN_ID must be a number" ;; esac
  set_kv "$CONF/bot.env" TELEGRAM_ADMIN_ID "$TELEGRAM_ADMIN_ID"
fi
if ! grep -q '^GITHUB_TOKEN=.' "$CONF/update.env"; then
  ask GITHUB_TOKEN "GitHub token for auto-updates (fine-grained, this repo only, Contents: read-only; empty skips auto-updates): " secret
  if [ -n "$GITHUB_TOKEN" ]; then set_kv "$CONF/update.env" GITHUB_TOKEN "$GITHUB_TOKEN"; fi
fi
if [ ! -f "$CONF/helper.env" ]; then
  printf 'ALLOWLIST_NAME=telegram-bot\nALLOWLIST_TTL=90d\n' > "$CONF/helper.env"
  chmod 0600 "$CONF/helper.env"
fi

lapi=$(sed -n 's/^url: *//p' /etc/crowdsec/local_api_credentials.yaml 2>/dev/null)
case "$lapi" in
  http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*|"") ;;
  *) echo "warning: cscli reaches LAPI at $lapi, but the helper may only connect to localhost."
     echo "  allow it with: systemctl edit crowdsec-gram-bot-helper@.service  ([Service] IPAddressAllow=<that IP>)" ;;
esac
dbtype=$(awk '/^db_config:/{f=1;next} /^[^ #]/{f=0} f&&$1=="type:"{print $2}' /etc/crowdsec/config.yaml 2>/dev/null | tr -d "\"'")
dbhost=$(awk '/^db_config:/{f=1;next} /^[^ #]/{f=0} f&&$1=="host:"{print $2}' /etc/crowdsec/config.yaml 2>/dev/null | tr -d "\"'")
case "${dbtype:-sqlite}:$dbhost" in
  sqlite:*|*:127.0.0.1|*:localhost|*:::1|*:/*) ;;
  *) echo "warning: CrowdSec's $dbtype database is at $dbhost; /allow talks to it directly, but the helper may only connect to localhost."
     echo "  allow it with: systemctl edit crowdsec-gram-bot-helper@.service  ([Service] IPAddressAllow=<that IP>)" ;;
esac

list=$(sed -n 's/^ALLOWLIST_NAME=//p' "$CONF/helper.env")
list=${list:-telegram-bot}
cscli allowlists inspect "$list" >/dev/null 2>&1 || cscli allowlists create "$list" -d "IPs allowed from Telegram by $NAME" >/dev/null

install -m 0755 ./$NAME "$BIN.new"
mv -f "$BIN.new" "$BIN"
"$BIN" units
systemctl daemon-reload
systemctl enable $NAME-helper.socket $NAME.service
systemctl restart $NAME-helper.socket
systemctl restart $NAME.service
if grep -q '^GITHUB_TOKEN=.' "$CONF/update.env"; then
  systemctl enable --now $NAME-update.timer
  updates="on, every 6 hours"
else
  systemctl disable --now $NAME-update.timer 2>/dev/null || true
  updates="off (no GITHUB_TOKEN in $CONF/update.env)"
fi

echo "installed $($BIN version)"
echo "  bot:      systemctl status $NAME   (logs: journalctl -u $NAME)"
echo "  helper:   journalctl -u '$NAME-helper@*'"
echo "  updates:  $updates"
echo "  settings: $CONF/"
