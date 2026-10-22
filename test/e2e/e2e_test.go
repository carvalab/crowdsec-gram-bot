//go:build e2e

// End-to-end test on a real Ubuntu host: systemd as PID 1, CrowdSec from
// apt and the real install command. Only Telegram and GitHub are faked.
//
//	docker build -t csgb-e2e:ubuntu-24.04 test/e2e   (needs internet for apt)
//	go test -tags e2e -v -timeout 20m ./test/e2e
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	tgToken = "123456:FAKE-telegram-token"
	ghToken = "ghtest-token"
	admin   = 4242
	modPath = "github.com/carvalab/crowdsec-gram-bot"
)

type env struct {
	t    *testing.T
	ctr  string
	dir  string
	seen int
	chat []map[string]string
}

func run(t *testing.T, stdin []byte, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func must(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := run(t, nil, name, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func (e *env) sh(script string) (string, error) {
	e.t.Helper()
	return run(e.t, nil, "docker", "exec", e.ctr, "bash", "-c", script)
}

func (e *env) mustSh(script string) string {
	e.t.Helper()
	out, err := e.sh(script)
	if err != nil {
		e.t.Fatalf("%s: %v\n%s", script, err, out)
	}
	return out
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type call struct {
	Method string            `json:"method"`
	Fields map[string]string `json:"fields"`
}

func (e *env) sent() []call {
	e.t.Helper()
	out, err := e.sh("curl -sf http://127.0.0.1:8081/control/sent")
	if err != nil {
		return nil
	}
	var calls []call
	json.Unmarshal([]byte(out), &calls)
	return calls
}

func (e *env) push(update map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(update)
	if m, ok := update["message"].(map[string]any); ok {
		e.chat = append(e.chat, map[string]string{"from": fmt.Sprint(m["from"].(map[string]any)["id"]), "chat": fmt.Sprint(m["chat"].(map[string]any)["type"]), "text": m["text"].(string)})
	} else if q, ok := update["callback_query"].(map[string]any); ok {
		e.chat = append(e.chat, map[string]string{"from": fmt.Sprint(q["from"].(map[string]any)["id"]), "button": q["data"].(string)})
	}
	if out, err := run(e.t, b, "docker", "exec", "-i", e.ctr, "curl", "-sf", "-X", "POST", "--data-binary", "@-", "http://127.0.0.1:8081/control/push"); err != nil {
		e.t.Fatalf("push: %v %s", err, out)
	}
}

func message(from, chat int64, chatType, text string) map[string]any {
	return map[string]any{"message": map[string]any{
		"message_id": 1, "date": time.Now().Unix(), "text": text,
		"from": map[string]any{"id": from, "is_bot": false, "first_name": "u"},
		"chat": map[string]any{"id": chat, "type": chatType},
	}}
}

func button(from int64, data string) map[string]any {
	return map[string]any{"callback_query": map[string]any{
		"id": "cb", "chat_instance": "x", "data": data,
		"from":    map[string]any{"id": from, "is_bot": false, "first_name": "u"},
		"message": map[string]any{"message_id": 7, "date": time.Now().Unix(), "chat": map[string]any{"id": admin, "type": "private"}},
	}}
}

// reply waits for the next sendMessage and checks it contains every want.
func (e *env) reply(want ...string) call {
	e.t.Helper()
	var got call
	waitFor(e.t, fmt.Sprintf("a reply containing %q", want), 30*time.Second, func() bool {
		for _, c := range e.sent()[e.seen:] {
			e.seen++
			if c.Method == "sendMessage" {
				got = c
				return true
			}
		}
		return false
	})
	e.chat = append(e.chat, map[string]string{"bot": got.Fields["text"], "buttons": got.Fields["reply_markup"]})
	for _, w := range want {
		if !strings.Contains(got.Fields["text"]+got.Fields["reply_markup"], w) {
			e.t.Fatalf("reply %q (buttons %s) lacks %q", got.Fields["text"], got.Fields["reply_markup"], w)
		}
	}
	return got
}

func (e *env) noReply() {
	e.t.Helper()
	time.Sleep(4 * time.Second)
	for _, c := range e.sent()[e.seen:] {
		e.seen++
		if c.Method == "sendMessage" {
			e.t.Fatalf("unexpected reply %q", c.Fields["text"])
		}
	}
}

func (e *env) build(out, version, key string) {
	e.t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "-ldflags",
		"-s -w -X main.version="+version+" -X "+modPath+"/internal/update.PublicKey="+key, ".")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("build %s: %v\n%s", version, err, out)
	}
}

func pubKey(t *testing.T, pem string) string {
	der := must(t, "openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER")
	return base64.StdEncoding.EncodeToString([]byte(der)[len(der)-32:])
}

// release writes a GitHub release for version into the container, signed
// the way the release workflow signs it: openssl pkeyutl over checksums.txt.
func (e *env) release(version string, bin []byte, signKey string) {
	e.t.Helper()
	asset := "crowdsec-gram-bot_linux_" + runtime.GOARCH
	rel := filepath.Join(e.dir, "release-"+version)
	os.MkdirAll(rel, 0o755)
	sum := sha256.Sum256(bin)
	os.WriteFile(filepath.Join(rel, asset), bin, 0o644)
	os.WriteFile(filepath.Join(rel, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+asset+"\n"), 0o644)
	must(e.t, "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", signKey, "-in", filepath.Join(rel, "checksums.txt"), "-out", filepath.Join(rel, "checksums.txt.sig"))
	var assets []string
	for _, n := range []string{asset, "checksums.txt", "checksums.txt.sig"} {
		assets = append(assets, fmt.Sprintf(`{"name":%q,"url":"http://127.0.0.1:8081/assets/%s"}`, n, n))
	}
	os.WriteFile(filepath.Join(rel, "latest.json"), []byte(fmt.Sprintf(`{"tag_name":"v%s","assets":[%s]}`, version, strings.Join(assets, ","))), 0o644)
	e.mustSh("rm -rf /srv/release")
	must(e.t, "docker", "cp", rel, e.ctr+":/srv/release")
}

func (e *env) version() string {
	return strings.TrimSpace(e.mustSh("/usr/local/bin/crowdsec-gram-bot version"))
}

func TestEndToEnd(t *testing.T) {
	image := os.Getenv("E2E_IMAGE")
	if image == "" {
		image = "csgb-e2e:ubuntu-24.04"
	}
	e := &env{t: t, dir: t.TempDir()}

	key := filepath.Join(e.dir, "release.pem")
	otherKey := filepath.Join(e.dir, "other.pem")
	must(t, "openssl", "genpkey", "-algorithm", "ed25519", "-out", key)
	must(t, "openssl", "genpkey", "-algorithm", "ed25519", "-out", otherKey)
	pub := pubKey(t, key)

	stage := filepath.Join(e.dir, "stage")
	os.MkdirAll(stage, 0o755)
	e.build(filepath.Join(stage, "crowdsec-gram-bot"), "1.0.0", pub)
	e.build(filepath.Join(e.dir, "v1.1.0"), "1.1.0", pub)
	fake := exec.Command("go", "build", "-o", filepath.Join(e.dir, "fakeapi"), "./fakeapi")
	fake.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if out, err := fake.CombinedOutput(); err != nil {
		t.Fatalf("build fakeapi: %v\n%s", err, out)
	}

	e.ctr = strings.TrimSpace(must(t, "docker", "run", "-d", "--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock", image))
	t.Cleanup(func() {
		if path := os.Getenv("E2E_TRANSCRIPT"); path != "" {
			b, _ := json.MarshalIndent(e.chat, "", "  ")
			os.WriteFile(path, b, 0o644)
		}
		if t.Failed() {
			out, _ := e.sh("journalctl --no-pager -n 80 -u 'crowdsec-gram-bot*'")
			t.Log(out)
		}
		exec.Command("docker", "rm", "-f", e.ctr).Run()
	})
	waitFor(t, "systemd to boot", 60*time.Second, func() bool {
		out, _ := e.sh("systemctl is-system-running")
		return strings.Contains(out, "running") || strings.Contains(out, "degraded")
	})
	e.mustSh("curl -fsSL https://install.crowdsec.net | sh >/dev/null && apt-get install -y -qq crowdsec >/dev/null 2>&1")
	waitFor(t, "crowdsec to start", 90*time.Second, func() bool {
		out, _ := e.sh("cscli lapi status")
		return strings.Contains(out, "successfully interact")
	})
	must(t, "docker", "cp", stage, e.ctr+":/opt/csgb")
	must(t, "docker", "cp", filepath.Join(e.dir, "fakeapi"), e.ctr+":/usr/local/bin/fakeapi")
	e.mustSh(fmt.Sprintf("systemd-run --unit fakeapi -E FAKE_TELEGRAM_TOKEN=%s -E FAKE_GITHUB_TOKEN=%s /usr/local/bin/fakeapi", tgToken, ghToken))

	t.Run("install", func(t *testing.T) {
		e.t = t
		e.mustSh("cscli machines add telegram-bot --auto -f /dev/null")
		e.mustSh(fmt.Sprintf("printf 'TELEGRAM_TOKEN=%s\\nTELEGRAM_ADMIN_ID=%d\\nCROWDSEC_MACHINE_PASSWORD=x\\n' > /etc/crowdsec-gram-bot.env", tgToken, admin))
		staged, _ := os.ReadFile(filepath.Join(stage, "crowdsec-gram-bot"))
		e.release("1.0.0", staged, key)
		gh := "GITHUB_API_URL=http://127.0.0.1:8081 GITHUB_REPO=o/r GITHUB_TOKEN=" + ghToken + " "
		e.mustSh("cp /opt/csgb/crowdsec-gram-bot /tmp/tampered && printf x >> /tmp/tampered")
		if out, err := e.sh(gh + "/tmp/tampered install </dev/null"); err == nil || !strings.Contains(out, "does not match its signed release") {
			t.Fatalf("a changed binary was installed: err=%v\n%s", err, out)
		}
		if out, _ := e.sh("ls /usr/local/bin/crowdsec-gram-bot"); !strings.Contains(out, "No such file") {
			t.Fatalf("the refused binary was copied: %s", out)
		}
		out := e.mustSh(gh + "/opt/csgb/crowdsec-gram-bot install </dev/null")
		for _, want := range []string{"signature and checksum match release v1.0.0", "moving them", "deleted the old 'telegram-bot'", "installed version=1.0.0", "updates:  automatic"} {
			if !strings.Contains(out, want) {
				t.Fatalf("install output lacks %q:\n%s", want, out)
			}
		}
		if out, _ := e.sh("ls /etc/crowdsec-gram-bot.env; cscli machines list -o raw"); strings.Contains(out, "telegram-bot") || !strings.Contains(out, "No such file") {
			t.Fatalf("legacy leftovers: %s", out)
		}
		if strings.Contains(e.mustSh("cat /etc/crowdsec-gram-bot/bot.env"), "CROWDSEC_MACHINE") {
			t.Fatal("old CrowdSec machine password was carried over")
		}
		e.mustSh("printf 'TELEGRAM_API_URL=http://127.0.0.1:8081\\n' >> /etc/crowdsec-gram-bot/bot.env")
		e.mustSh("printf 'GITHUB_API_URL=http://127.0.0.1:8081\\nGITHUB_REPO=o/r\\nGITHUB_TOKEN=" + ghToken + "\\n' >> /etc/crowdsec-gram-bot/update.env")
		e.mustSh("systemctl restart crowdsec-gram-bot")
		waitFor(t, "the bot to register its commands", 30*time.Second, func() bool {
			for _, c := range e.sent() {
				if c.Method == "setMyCommands" && strings.Contains(c.Fields["scope"], "4242") {
					return true
				}
			}
			return false
		})
		e.seen = len(e.sent())
		if out := e.mustSh("ps -o user= -p $(systemctl show -p MainPID --value crowdsec-gram-bot)"); strings.TrimSpace(out) != "crowdsec-gram-bot" {
			t.Fatalf("bot runs as %q", out)
		}
		if out := e.mustSh("stat -c '%A %U %G' /run/crowdsec-gram-bot-helper.sock"); strings.TrimSpace(out) != "srw-rw---- root crowdsec-gram-bot" {
			t.Fatalf("socket perms %q", out)
		}
		if out := e.mustSh("stat -c '%a %U' /etc/crowdsec-gram-bot /etc/crowdsec-gram-bot/bot.env /etc/crowdsec-gram-bot/helper.env"); out != "700 root\n600 root\n600 root\n" {
			t.Fatalf("settings perms %q", out)
		}
		e.mustSh("systemctl is-active crowdsec-gram-bot-update.timer crowdsec-gram-bot-helper.socket crowdsec-gram-bot")
		helperCaps := e.mustSh("systemctl show -p CapabilityBoundingSet --value crowdsec-gram-bot-helper@x.service")
		updateCaps := e.mustSh("systemctl show -p CapabilityBoundingSet --value crowdsec-gram-bot-update.service")
		if strings.TrimSpace(helperCaps) != "" || !strings.Contains(updateCaps, "cap_sys_admin") {
			t.Fatalf("the helper must have no capabilities and the root updater must keep more than it, or the helper could open /proc/<updater>/root: helper=%q update=%q", helperCaps, updateCaps)
		}
		t.Log(e.mustSh("for u in crowdsec-gram-bot crowdsec-gram-bot-helper@x crowdsec-gram-bot-update; do printf '%s: ' $u; systemd-analyze security $u.service --no-pager | tail -1; done"))
	})

	t.Run("helper socket boundary", func(t *testing.T) {
		e.t = t
		e.mustSh("useradd -M mallory")
		if out, _ := e.sh(`runuser -u mallory -- fakeapi call '{"op":"list"}'`); !strings.Contains(out, "permission denied") {
			t.Fatalf("another user reached the helper: %s", out)
		}
		for _, bad := range []string{
			`{"op":"unban","ip":"1.2.3.4 --all"}`,
			`{"op":"unban","ip":"0.0.0.0"}`,
			`{"op":"exec","ip":"1.2.3.4"}`,
			`{"op":"list","filter":"1;id"}`,
			`{"op":"allow","ip":"10.0.0.0/8"}`,
			`{"op":"unban","ip":"1.2.3.4","args":["--all"]}`,
			`{"op":"unban","ip":"9.9.9.9\nop=allow ip=6.6.6.6 result=ok"}`,
		} {
			out := e.mustSh(`runuser -u crowdsec-gram-bot -- fakeapi call '` + bad + `'`)
			if !strings.Contains(out, `"ok":false`) {
				t.Fatalf("helper accepted %s: %s", bad, out)
			}
		}
		if out := e.mustSh(`runuser -u crowdsec-gram-bot -- fakeapi call '{"op":"list"}'`); !strings.Contains(out, `"ok":true`) {
			t.Fatalf("bot user cannot list: %s", out)
		}
		if out := e.mustSh("journalctl --no-pager -u 'crowdsec-gram-bot-helper@*'"); !strings.Contains(out, `op="exec"`) || !strings.Contains(out, "result=error") || strings.Contains(out, "]: op=allow ip=6.6.6.6") {
			t.Fatalf("refusals are not logged:\n%s", out)
		}
	})

	t.Run("telegram", func(t *testing.T) {
		e.t = t
		e.mustSh("cscli decisions add --ip 203.0.113.7 -d 4h -R test; sleep 1; cscli decisions add --ip 198.51.100.9 -d 4h -R test; sleep 1; cscli decisions add --range 192.0.2.0/24 -d 4h -R test")

		e.push(message(admin, admin, "private", "/bans"))
		e.reply("3 active ban(s)", "192.0.2.0/24", "u:203.0.113.7", "a:198.51.100.9")
		e.push(message(admin, admin, "private", "/bans 203.0"))
		e.reply("1 active ban(s)", "203.0.113.7")

		e.push(message(999, 999, "private", "/unban 203.0.113.7"))
		e.push(message(admin, -100777, "supergroup", "/unban 203.0.113.7"))
		e.push(button(999, "u:203.0.113.7"))
		e.noReply()
		if !strings.Contains(e.mustSh("cscli decisions list -o raw"), "203.0.113.7") {
			t.Fatal("a stranger removed a ban")
		}

		e.push(message(admin, admin, "private", "/unban 203.0.113.7"))
		e.reply("Unbanned 203.0.113.7", "Removed 1 ban(s)")
		if strings.Contains(e.mustSh("cscli decisions list -o raw"), "203.0.113.7") {
			t.Fatal("ban is still there")
		}
		e.push(message(admin, admin, "private", "/unban 203.0.113.7"))
		e.reply("had no active ban")
		e.push(message(admin, admin, "private", "/unban 1.2.3.0/24"))
		e.reply("Usage: /unban")

		e.push(message(admin, admin, "private", "192.0.2.50"))
		e.reply("What should I do with 192.0.2.50?", "a:192.0.2.50")
		e.push(button(admin, "a:192.0.2.50"))
		until := time.Now().Add(90 * 24 * time.Hour).UTC().Format("2006-01-02")
		e.reply("192.0.2.50 is allowlisted until "+until, "Removed 1 ban(s)")
		if out := e.mustSh("cscli allowlists inspect telegram-bot -o json"); !strings.Contains(out, `"value": "192.0.2.50"`) || !strings.Contains(out, until) {
			t.Fatalf("allowlist: %s", out)
		}
		if out, _ := e.sh("cscli decisions add --ip 192.0.2.50 -d 4h"); !strings.Contains(out, "allowlisted") {
			t.Fatalf("allowlisted IP could be banned again: %s", out)
		}
		e.push(message(admin, admin, "private", "/allow 192.0.2.50"))
		e.reply("allowlisted until "+until, "It had no active ban.")
		if n := strings.Count(e.mustSh("cscli allowlists inspect telegram-bot -o json"), "192.0.2.50"); n != 1 {
			t.Fatalf("allowlist has %d entries for the IP", n)
		}
	})

	t.Run("token stays out of the journal", func(t *testing.T) {
		e.t = t
		e.mustSh("systemctl stop fakeapi; sleep 6")
		e.mustSh(fmt.Sprintf("systemd-run --unit fakeapi2 -E FAKE_TELEGRAM_TOKEN=%s -E FAKE_GITHUB_TOKEN=%s /usr/local/bin/fakeapi", tgToken, ghToken))
		out := e.mustSh("journalctl --no-pager -u crowdsec-gram-bot")
		if !strings.Contains(out, "bot***/getUpdates") {
			t.Fatalf("no network error was logged:\n%s", out)
		}
		if strings.Contains(out, tgToken) || strings.Contains(e.mustSh("journalctl --no-pager"), tgToken) {
			t.Fatal("the Telegram token is in the journal")
		}
		e.seen = 0
		waitFor(t, "the bot to reconnect", 40*time.Second, func() bool {
			e.push(message(admin, admin, "private", "/help"))
			time.Sleep(3 * time.Second)
			return len(e.sent()) > 0
		})
		e.seen = len(e.sent())
	})

	t.Run("auto update", func(t *testing.T) {
		e.t = t
		update := func() (string, error) {
			return e.sh("systemctl start crowdsec-gram-bot-update.service; rc=$?; journalctl --no-pager -o cat -u crowdsec-gram-bot-update -n 5; exit $rc")
		}
		good, _ := os.ReadFile(filepath.Join(e.dir, "v1.1.0"))

		e.release("1.1.0", good, otherKey)
		if out, err := update(); err == nil || !strings.Contains(out, "bad signature") || e.version() != "version=1.0.0 commit=none date=unknown" {
			t.Fatalf("release signed by another key: err=%v\n%s", err, out)
		}
		e.mustSh("sed -i 's/^GITHUB_TOKEN=.*/GITHUB_TOKEN=wrong/' /etc/crowdsec-gram-bot/update.env")
		e.release("1.1.0", good, key)
		if out, err := update(); err == nil || !strings.Contains(out, "GITHUB_TOKEN") {
			t.Fatalf("wrong token: err=%v\n%s", err, out)
		}
		e.mustSh("sed -i 's/^GITHUB_TOKEN=.*/GITHUB_TOKEN=" + ghToken + "/' /etc/crowdsec-gram-bot/update.env")
		e.mustSh("sed -i 's/^User=crowdsec-gram-bot$/User=root/' /etc/systemd/system/crowdsec-gram-bot.service && systemctl daemon-reload")

		if out, err := update(); err != nil || !strings.Contains(out, "healthy") {
			t.Fatalf("good update: %v\n%s", err, out)
		}
		if v := e.version(); !strings.HasPrefix(v, "version=1.1.0") {
			t.Fatalf("after update: %s", v)
		}
		if !strings.Contains(e.mustSh("journalctl --no-pager -u crowdsec-gram-bot"), "crowdsec-gram-bot 1.1.0 started") {
			t.Fatal("the bot did not restart on the new version")
		}
		if out := e.mustSh("grep -c '^User=crowdsec-gram-bot$' /etc/systemd/system/crowdsec-gram-bot.service; ps -o user= -p $(systemctl show -p MainPID --value crowdsec-gram-bot)"); out != "1\ncrowdsec-gram-bot\n" {
			t.Fatalf("the update did not restore the unit from the binary: %q", out)
		}
		if out, _ := update(); !strings.Contains(out, "up to date") {
			t.Fatalf("second run: %s", out)
		}

		broken := []byte("#!/bin/sh\ncase \"$1\" in version) echo version=1.2.0 ;; units) exec /usr/local/bin/crowdsec-gram-bot.old units ;; *) exit 1 ;; esac\n")
		e.release("1.2.0", broken, key)
		if out, err := update(); err == nil || !strings.Contains(out, "rolled back") {
			t.Fatalf("broken release: err=%v\n%s", err, out)
		}
		if v := e.version(); !strings.HasPrefix(v, "version=1.1.0") {
			t.Fatalf("after rollback: %s", v)
		}
		if out, err := update(); err != nil || !strings.Contains(out, "skipping v1.2.0") {
			t.Fatalf("the failed release was tried again: %v\n%s", err, out)
		}
		e.mustSh("sleep 3; systemctl is-active crowdsec-gram-bot")
		e.seen = len(e.sent())
		e.push(message(admin, admin, "private", "/help"))
		e.reply("CrowdSec unban bot 1.1.0")
	})

	t.Run("uninstall", func(t *testing.T) {
		e.t = t
		e.mustSh("/opt/csgb/crowdsec-gram-bot uninstall")
		out, _ := e.sh("systemctl is-active crowdsec-gram-bot; ls /usr/local/bin/crowdsec-gram-bot /etc/systemd/system/crowdsec-gram-bot* /var/lib/crowdsec-gram-bot; id crowdsec-gram-bot")
		if strings.HasPrefix(out, "active") || !strings.Contains(out, "no such user") || strings.Count(out, "No such file") != 3 {
			t.Fatalf("leftovers after uninstall:\n%s", out)
		}
		e.mustSh("test -f /etc/crowdsec-gram-bot/bot.env")
	})
}
