// Command crowdsec-gram-bot is a minimal Telegram polling bot to manage
// CrowdSec bans via the Local API (LAPI) using machine credentials.
//
// Commands (admin only):
//   /bans            list current decisions
//   /unban <ip>      delete decision for IP
//   /unbanwl <ip>    delete decision + add to allowlist with expiry (default 90d)
//   /help            usage
//
// Auth: only TELEGRAM_ADMIN_ID chat is answered. LAPI needs a *machine*
// login (bouncer tokens can't DELETE decisions):
//   cscli machines add telegram-bot --auto
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

type cfg struct {
	tgToken   string
	adminID   int64
	lapi      string
	login     string
	password  string
	allowID   string
	ttl       string
	listLimit string
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("missing required env %s", k)
	}
	return v
}

func loadCfg() cfg {
	admin, err := strconv.ParseInt(mustEnv("TELEGRAM_ADMIN_ID"), 10, 64)
	if err != nil {
		log.Fatalf("bad TELEGRAM_ADMIN_ID: %v", err)
	}
	c := cfg{
		tgToken:   mustEnv("TELEGRAM_TOKEN"),
		adminID:   admin,
		lapi:      strings.TrimRight(mustEnv("CROWDSEC_LAPI_URL"), "/"),
		login:     mustEnv("CROWDSEC_MACHINE_LOGIN"),
		password:  mustEnv("CROWDSEC_MACHINE_PASSWORD"),
		allowID:   os.Getenv("ALLOWLIST_ID"),
		ttl:       os.Getenv("WHITELIST_TTL"),
		listLimit: os.Getenv("LIST_LIMIT"),
	}
	if c.allowID == "" {
		c.allowID = "telegram-temp"
	}
	if c.ttl == "" {
		c.ttl = "2160h" // 90d ≈ 3 months
	}
	if c.listLimit == "" {
		c.listLimit = "50"
	}
	return c
}

// --- LAPI client (machine auth) ---

type lapi struct {
	c     cfg
	http  *http.Client
	token string
}

func (l *lapi) login(ctx context.Context) error {
	body, _ := json.Marshal(map[string]any{
		"machine_id": l.c.login,
		"password":   l.c.password,
		// scenarios omitted: not mandatory for login
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", l.c.lapi+"/v1/watchers/login", bytes.NewReader(body))
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
		// some versions nest differently; try raw token string
		t := strings.Trim(strings.Trim(string(b), `"`), " \n")
		if t == "" {
			return fmt.Errorf("login: no token in response")
		}
		l.token = t
		return nil
	}
	l.token = out.Token
	return nil
}

func (l *lapi) do(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	if l.token == "" {
		if err := l.login(ctx); err != nil {
			return 0, nil, err
		}
	}
	var rdr io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, l.c.lapi+path, rdr)
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := l.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode == 401 || res.StatusCode == 403 {
		// token expired or wrong role (bouncer tokens can't write) → re-login once
		if err := l.login(ctx); err != nil {
			return res.StatusCode, b, fmt.Errorf("re-login failed (need MACHINE creds, not bouncer key): %w", err)
		}
		req2, _ := http.NewRequestWithContext(ctx, method, l.c.lapi+path, rdr)
		req2.Header.Set("Authorization", "Bearer "+l.token)
		req2.Header.Set("Content-Type", "application/json")
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

type decision struct {
	ID       int64  `json:"id"`
	IP       string `json:"ip"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
	Until    string `json:"until"`
}

func (l *lapi) listDecisions(ctx context.Context) ([]decision, error) {
	st, b, err := l.do(ctx, "GET", "/v1/decisions?limit="+url.QueryEscape(l.c.listLimit), nil)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("list %d: %s", st, compact(b))
	}
	var out []decision
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}
	return out, nil
}

func (l *lapi) deleteDecision(ctx context.Context, ip string) error {
	// LAPI filters by ip query param; scope/value variant differs per version.
	st, b, err := l.do(ctx, "DELETE", "/v1/decisions?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return err
	}
	if st == 200 || st == 202 || st == 204 {
		return nil
	}
	return fmt.Errorf("delete %d: %s", st, compact(b))
}

func (l *lapi) allowlistAdd(ctx context.Context, ip string) error {
	payload := map[string]any{"value": ip, "expiration": l.c.ttl, "comment": "telegram-bot " + time.Now().UTC().Format("2006-01-02")}
	// Endpoint naming differs per version (allowlist vs allowlists); try both.
	for _, p := range []string{
		"/v1/allowlists/" + url.PathEscape(l.c.allowID),
		"/v1/allowlist/" + url.PathEscape(l.c.allowID),
	} {
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
		return fmt.Errorf("allowlist %d: %s (cscli equiv: cscli allowlists add %s %s -e %s)",
			st, compact(b), l.c.allowID, ip, l.c.ttl)
	}
	return fmt.Errorf("allowlist endpoint not found; create list first: cscli allowlists create %s", l.c.allowID)
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

// --- Telegram handlers ---

func adminOnly(adminID int64, next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, u *models.Update) {
		if u.Message == nil || u.Message.Chat.ID != adminID {
			return // silent ignore
		}
		next(ctx, b, u)
	}
}

func send(b *bot.Bot, ctx context.Context, chatID int64, text string) {
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: text})
}

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

func main() {
	c := loadCfg()
	cl := &lapi{c: c, http: &http.Client{Timeout: 20 * time.Second}}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	b, err := bot.New(c.tgToken)
	if err != nil {
		log.Fatal(err)
	}

	help := "/bans — list bans\n/unban <ip> — delete ban\n/unbanwl <ip> — delete + whitelist " + c.ttl + " (list " + c.allowID + ")\n/help — this"

	b.RegisterHandler(bot.HandlerTypeMessageText, "/help", bot.MatchTypeExact, adminOnly(c.adminID, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		send(b, ctx, u.Message.Chat.ID, help)
	}))
	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, adminOnly(c.adminID, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		send(b, ctx, u.Message.Chat.ID, help)
	}))

	b.RegisterHandler(bot.HandlerTypeMessageText, "/bans", bot.MatchTypeExact, adminOnly(c.adminID, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		ds, err := cl.listDecisions(ctx)
		if err != nil {
			send(b, ctx, u.Message.Chat.ID, "list failed: "+err.Error())
			return
		}
		if len(ds) == 0 {
			send(b, ctx, u.Message.Chat.ID, "no bans 🎉")
			return
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d bans:\n", len(ds))
		for _, d := range ds {
			ip := d.Value
			if ip == "" {
				ip = d.IP
			}
			fmt.Fprintf(&sb, "• %s (%s/%s until %s)\n", ip, d.Scenario, d.Type, shortTime(d.Until))
		}
		send(b, ctx, u.Message.Chat.ID, sb.String())
	}))

	b.RegisterHandler(bot.HandlerTypeMessageText, "/unban", bot.MatchTypePrefix, adminOnly(c.adminID, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		if strings.HasPrefix(u.Message.Text, "/unbanwl") {
			return // handled by /unbanwl
		}
		ip, ok := argIP(u.Message.Text)
		if !ok {
			send(b, ctx, u.Message.Chat.ID, "usage: /unban 1.2.3.4")
			return
		}
		if err := cl.deleteDecision(ctx, ip); err != nil {
			send(b, ctx, u.Message.Chat.ID, "unban failed: "+err.Error())
			return
		}
		send(b, ctx, u.Message.Chat.ID, "unbanned "+ip)
	}))

	b.RegisterHandler(bot.HandlerTypeMessageText, "/unbanwl", bot.MatchTypePrefix, adminOnly(c.adminID, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		ip, ok := argIP(u.Message.Text)
		if !ok {
			send(b, ctx, u.Message.Chat.ID, "usage: /unbanwl 1.2.3.4")
			return
		}
		if err := cl.deleteDecision(ctx, ip); err != nil {
			send(b, ctx, u.Message.Chat.ID, "unban failed: "+err.Error())
			return
		}
		if err := cl.allowlistAdd(ctx, ip); err != nil {
			send(b, ctx, u.Message.Chat.ID, "unbanned "+ip+" but whitelist failed: "+err.Error())
			return
		}
		send(b, ctx, u.Message.Chat.ID, "unbanned + whitelisted "+ip+" for "+c.ttl)
	}))

	log.Println("bot polling…")
	b.Start(ctx)
}

func shortTime(s string) string {
	if s == "" {
		return "?"
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2006-01-02 15:04")
	}
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
