#!/bin/sh
# Install crowdsec-gram-bot as a systemd service.
# Usage: sudo ./install.sh [--no-edit] [path/to/binary]
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo ./install.sh" >&2
  exit 1
fi
SRC=""
EDIT=1
for a in "$@"; do
  case "$a" in
    --no-edit) EDIT=0 ;;
    *) SRC="$a" ;;
  esac
done
[ -n "$SRC" ] || SRC="./crowdsec-gram-bot"
for f in "$SRC" systemd/crowdsec-gram-bot.service .env.example; do
  [ -f "$f" ] || { echo "required file not found: $f (run from repo root)" >&2; exit 1; }
done
# mv (rename) over a running binary works; in-place rewrite hits ETXTBSY.
install -m 0755 "$SRC" /usr/local/bin/crowdsec-gram-bot.new
mv -f /usr/local/bin/crowdsec-gram-bot.new /usr/local/bin/crowdsec-gram-bot
install -m 0644 systemd/crowdsec-gram-bot.service /etc/systemd/system/crowdsec-gram-bot.service
if [ ! -f /etc/crowdsec-gram-bot.env ]; then
  install -m 0600 .env.example /etc/crowdsec-gram-bot.env
  echo "created /etc/crowdsec-gram-bot.env from .env.example"
else
  chmod 0600 /etc/crowdsec-gram-bot.env
fi
if [ "$EDIT" -eq 1 ] && [ -t 0 ]; then
  "${EDITOR:-vi}" /etc/crowdsec-gram-bot.env
fi
systemctl daemon-reload
systemctl enable crowdsec-gram-bot
systemctl restart crowdsec-gram-bot
echo "installed. check: systemctl status crowdsec-gram-bot"
