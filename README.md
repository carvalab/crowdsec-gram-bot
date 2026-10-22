# crowdsec-gram-bot

Remove your own CrowdSec ban from Telegram. When the WAF bans the IP you are
working from, send the bot `/bans` or your IP from your phone, tap a button,
and you are back in. No other network, no SSH, no console login.

```
/bans           newest bans, each with 🔓 unban and ✅ allowlist buttons
/bans 181.45    shorten the list: only IPs that start with 181.45 (any digits work)
/unban 1.2.3.4  remove every ban on that IP, from any country, including a range ban around it
/allow 1.2.3.4  remove the bans and allowlist the IP for 90 days
1.2.3.4         just the IP: the bot asks which of the two
```

Any IP works, wherever you are. The bot checks your Telegram account, not your
location. The `181.45` above is only an example of narrowing a long list.

The allowlist is CrowdSec's own (`cscli allowlists`, CrowdSec 1.6.8 or newer).
It stops new bans on the IP and lets its requests skip the AppSec WAF.

## How it stays safe

The bot answers one Telegram user, in a private chat, and ignores everyone
else. It never runs as root:

```
Telegram ──► crowdsec-gram-bot.service        user crowdsec-gram-bot, no capabilities,
             (polls Telegram)                 holds only the Telegram token
                 │
                 │  /run/crowdsec-gram-bot-helper.sock   (root:crowdsec-gram-bot 0660)
                 ▼
             crowdsec-gram-bot-helper@.service  root, one process per request,
             (started by systemd)               no internet, runs /usr/bin/cscli
```

The helper is the only part with root. It reads one JSON line and accepts
exactly three requests: `list`, `unban <ip>` and `allow <ip>`. The IP must be a
single unicast address, and `cscli` gets a fixed argument list with no shell.
Even someone who took over the bot process can only unban or allowlist single
IPs. They cannot run commands or reach other files. The helper also checks the
caller's user id on the socket and logs every request to the journal. It sees
an empty `/run`, so even a helper running someone else's code could not reach
root sockets such as `/run/docker.sock` or systemd's bus.

All three units are sandboxed with systemd. `systemd-analyze security` rates
the bot 1.2, the helper 1.8 and the updater 3.6 (0 is safest, 10 is unsandboxed).
The updater keeps its root capabilities on purpose: a root process with fewer
capabilities, like the helper, could otherwise reach into it through `/proc`.

## Install

You need an Ubuntu host with systemd and CrowdSec 1.6.8 or newer from
CrowdSec's apt repository (`curl -s https://install.crowdsec.net | sudo sh`).
Ubuntu's own `crowdsec` package is too old for allowlists.

1. Create the bot with [@BotFather](https://t.me/BotFather) and copy its token.
   Get your numeric user id from [@userinfobot](https://t.me/userinfobot).
2. On the server, paste this block as is. It downloads the release, checks its
   signature and checksum, and only then installs. Each step stops the rest if
   it fails. On an ARM server, change `amd64` to `arm64` in `arch=`.

```sh
arch=amd64 && mkdir -p ~/csgb && cd ~/csgb && \
base=https://github.com/carvalab/crowdsec-gram-bot/releases/latest/download && \
curl -fsSLO "$base/crowdsec-gram-bot_linux_$arch" && \
curl -fsSLO "$base/checksums.txt" && \
curl -fsSLO "$base/checksums.txt.sig" && \
printf '%s\n' '-----BEGIN PUBLIC KEY-----' \
  'MCowBQYDK2VwAyEAOCmvuqGInMtB99Rd/1cm261kAtVWFeNaBuafHIIU6Dw=' \
  '-----END PUBLIC KEY-----' > release-signing-key.pub.pem && \
openssl pkeyutl -verify -rawin -pubin -inkey release-signing-key.pub.pem \
  -in checksums.txt -sigfile checksums.txt.sig && \
sha256sum --ignore-missing -c checksums.txt && \
chmod +x "crowdsec-gram-bot_linux_$arch" && \
sudo "./crowdsec-gram-bot_linux_$arch" install
```

   You must see `Signature Verified Successfully` and
   `crowdsec-gram-bot_linux_amd64: OK` before the install starts. This check is
   the one that protects you. `install` checks itself too, but a tampered
   binary could skip its own check, so that one only catches a damaged
   download. The key in the block is `PublicKey` from
   `internal/update/update.go`. Every later update is checked by the installed
   binary, which you have just verified.

   `install` creates the `crowdsec-gram-bot` user and the allowlist, and starts
   everything. It asks for the Telegram token and your user id. Type them at
   the prompts: values on the command line show up in `ps` and the shell
   history.
3. Send `/help` to your bot. From then on the server installs new releases by
   itself.

`sudo crowdsec-gram-bot install` from a newer binary upgrades the bot and its
units and keeps your settings. `sudo crowdsec-gram-bot uninstall` removes the
bot and keeps its settings and the allowlist.

## Settings

All in `/etc/crowdsec-gram-bot/` (root only, mode 0600). Each unit reads only
its own file.

| File | Keys |
| --- | --- |
| `bot.env` | `TELEGRAM_TOKEN`, `TELEGRAM_ADMIN_ID` |
| `helper.env` | `ALLOWLIST_NAME` (default `telegram-bot`), `ALLOWLIST_TTL` (default `90d`, or a duration like `36h`) |
| `update.env` | optional: `GITHUB_REPO` (default `carvalab/crowdsec-gram-bot`), and `GITHUB_TOKEN` only if you point it at a private fork |

After changing a file: `sudo systemctl restart crowdsec-gram-bot`.

## Auto-updates

`crowdsec-gram-bot-update.timer` checks the latest GitHub release every 6
hours. A release is installed only when all of these hold:

- `checksums.txt` has a valid Ed25519 signature from the key built into the
  binary, so whoever controls a GitHub release still cannot push code to the
  server without that key;
- the tarball matches its checksum;
- the new binary runs and reports the expected version;
- after installing its units and restarting, the bot is still up 30 seconds
  later and the helper answers a real `list` request.

If a check after the restart fails, the previous binary and its units are put
back. When the old version passes the same checks, the bad release is recorded
in `/var/lib/crowdsec-gram-bot/failed-release` and skipped until a newer one
appears. When the old version fails too, the problem is on the host, so
nothing is recorded.

Run it by hand with `sudo systemctl start crowdsec-gram-bot-update` and read
the result with `journalctl -u crowdsec-gram-bot-update`.

## Releasing

```sh
git tag v1.2.3 && git push origin v1.2.3
```

The release workflow tests, then waits for your approval in the `release`
environment (Actions tab, or the GitHub app). Only after you approve does it
get the signing key, build `linux/amd64` and `linux/arm64`, sign
`checksums.txt` and publish. It refuses to run when the key does not match
`PublicKey` in `internal/update/update.go`.

What protects the key:

- it lives only in the `release` environment, which runs only for `v*` tags and
  only after you approve, so other branches and workflows never see it;
- only you can create `v*` tags;
- the key is encrypted, and its passphrase is a second secret;
- the signing step is the only one that receives them.

To rotate the key, put the new public key in `internal/update/update.go` and
`release-signing-key.pub.pem`, release once with the old key, then replace both
environment secrets.

## Logs

```sh
journalctl -u crowdsec-gram-bot             # Telegram side, ignored strangers
journalctl -u 'crowdsec-gram-bot-helper@*'  # every privileged request
journalctl -u crowdsec-gram-bot-update      # updates
```

## Development

```sh
go test -race ./...
docker build -t csgb-e2e:ubuntu-24.04 test/e2e
go test -tags e2e -v -timeout 20m ./test/e2e
```

The end-to-end test boots Ubuntu 24.04 with systemd in Docker, installs
CrowdSec from apt and runs the real `install` command. Only Telegram and GitHub are
faked (`test/e2e/fakeapi`). It covers strangers being ignored, the socket
refusing other users and bad requests, unban and allowlist through the real
`cscli`, the token staying out of the journal, signed updates, rejected
signatures and rollback of a broken release, and uninstall.
