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
2. Auto-updates need a GitHub token, because this repository is private. Make
   a fine-grained token: resource owner `carvalab`, only this repository,
   permission **Contents: read-only**. You can skip it and update by hand.
3. On the server (use `arm64` instead of `amd64` on an ARM server):
   ```sh
   curl -fsSL -o crowdsec-gram-bot \
     https://github.com/carvalab/crowdsec-gram-bot/releases/latest/download/crowdsec-gram-bot_linux_amd64
   chmod +x crowdsec-gram-bot
   sudo ./crowdsec-gram-bot install
   ```
   `install` checks the binary against its signed release before it copies
   anything, creates the `crowdsec-gram-bot` user and the allowlist, and starts
   everything. It asks for the Telegram token, your user id and the GitHub
   token. Type them at the prompts: values on the command line show up in `ps`
   and the shell history.
4. Send `/help` to your bot.

To check the download yourself before the first install, also fetch
`checksums.txt` and `checksums.txt.sig` and run:

```sh
openssl pkeyutl -verify -rawin -pubin -inkey release-signing-key.pub.pem \
  -in checksums.txt -sigfile checksums.txt.sig
grep linux_amd64 checksums.txt | sha256sum -c
```

`release-signing-key.pub.pem` is in this repository. Later updates are checked
automatically.

`sudo crowdsec-gram-bot install` from a newer binary upgrades the bot and its
units and keeps your settings. `sudo crowdsec-gram-bot uninstall` removes the
bot and keeps its settings and the allowlist.

## Settings

All in `/etc/crowdsec-gram-bot/` (root only, mode 0600). Each unit reads only
its own file, so the internet-facing bot never sees the GitHub token.

| File | Keys |
| --- | --- |
| `bot.env` | `TELEGRAM_TOKEN`, `TELEGRAM_ADMIN_ID` |
| `helper.env` | `ALLOWLIST_NAME` (default `telegram-bot`), `ALLOWLIST_TTL` (default `90d`, or a duration like `36h`) |
| `update.env` | `GITHUB_TOKEN`, and optionally `GITHUB_REPO` (default `carvalab/crowdsec-gram-bot`) |

After changing a file: `sudo systemctl restart crowdsec-gram-bot`.

## Auto-updates

`crowdsec-gram-bot-update.timer` checks the latest GitHub release every 6
hours. A release is installed only when all of these hold:

- `checksums.txt` has a valid Ed25519 signature from the key built into the
  binary, so a stolen GitHub token alone cannot push code to the server;
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

The release workflow tests, builds `linux/amd64` and `linux/arm64`, signs
`checksums.txt` and publishes the release. It refuses to run when the
`RELEASE_SIGNING_KEY` secret does not match `PublicKey` in
`internal/update/update.go`.

The signing key is a repository secret. On the Free plan, GitHub gives a
repository secret to every workflow that runs on a push, on any branch. So a
stolen token that can push to this repository can read the key and publish an
update that every server installs. Two things limit that:

- the key is encrypted, and its passphrase is a second secret, so both must
  leak;
- the workflow checks that the secret matches the public key in the code.

Close it properly by upgrading to GitHub Pro and moving both secrets into an
Environment that needs your approval, with a ruleset so only you can push
`v*` tags. Until then, protect the account: two-factor authentication, no
extra collaborators, and no GitHub App set to "all repositories".

To rotate the key, put the new public key in `internal/update/update.go` and
`release-signing-key.pub.pem`, release once with the old secret, then switch
both secrets.

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
