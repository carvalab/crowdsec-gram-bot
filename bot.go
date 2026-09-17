package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// argIP extracts a validated IP from "/cmd 1.2.3.4" text.
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

// isAdmin gates every update to the single allowed chat.
func isAdmin(chatID, adminID int64) bool { return chatID == adminID }

// isCommand checks the first token equals cmd, tolerating @botname suffix.
func isCommand(text, cmd string) bool {
	f := strings.Fields(text)
	if len(f) == 0 {
		return false
	}
	base, _, _ := strings.Cut(f[0], "@")
	return base == cmd
}

func adminOnly(adminID int64, next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, u *models.Update) {
		if u.Message == nil || !isAdmin(u.Message.Chat.ID, adminID) {
			return // silent ignore
		}
		next(ctx, b, u)
	}
}

func send(b *bot.Bot, ctx context.Context, chatID int64, text string) {
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: text})
}

// runBot starts Telegram polling. Only TELEGRAM_ADMIN_ID is answered.
func runBot(ctx context.Context) error {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN"))
	if token == "" {
		return fmt.Errorf("missing required env TELEGRAM_TOKEN")
	}
	admin, err := adminID()
	if err != nil {
		return fmt.Errorf("bad TELEGRAM_ADMIN_ID: %w", err)
	}
	c := loadConfig()
	if err := c.validate(); err != nil {
		return err
	}
	if c.login == "" || c.password == "" {
		return fmt.Errorf("missing required env CROWDSEC_MACHINE_LOGIN/CROWDSEC_MACHINE_PASSWORD")
	}

	b, err := bot.New(token)
	if err != nil {
		return err
	}

	help := "/bans — list bans\n/unban <ip> — delete ban\n/unbanwl <ip> — delete + whitelist " + c.ttl + " (list " + c.allowID + ")\n/help — this"

	b.RegisterHandler(bot.HandlerTypeMessageText, "/help", bot.MatchTypeExact, adminOnly(admin, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		send(b, ctx, u.Message.Chat.ID, help)
	}))
	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, adminOnly(admin, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		send(b, ctx, u.Message.Chat.ID, help)
	}))

	b.RegisterHandler(bot.HandlerTypeMessageText, "/bans", bot.MatchTypeExact, adminOnly(admin, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		out, err := runList(ctx)
		if err != nil {
			send(b, ctx, u.Message.Chat.ID, "list failed: "+err.Error())
			return
		}
		send(b, ctx, u.Message.Chat.ID, out)
	}))

	b.RegisterHandler(bot.HandlerTypeMessageText, "/unban", bot.MatchTypePrefix, adminOnly(admin, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		if !isCommand(u.Message.Text, "/unban") {
			return // /unbanwl, typos like /unbanned
		}
		ip, ok := argIP(u.Message.Text)
		if !ok {
			send(b, ctx, u.Message.Chat.ID, "usage: /unban 1.2.3.4")
			return
		}
		out, err := runUnban(ctx, ip)
		if err != nil {
			send(b, ctx, u.Message.Chat.ID, "unban failed: "+err.Error())
			return
		}
		send(b, ctx, u.Message.Chat.ID, out)
	}))

	b.RegisterHandler(bot.HandlerTypeMessageText, "/unbanwl", bot.MatchTypePrefix, adminOnly(admin, func(ctx context.Context, b *bot.Bot, u *models.Update) {
		ip, ok := argIP(u.Message.Text)
		if !ok {
			send(b, ctx, u.Message.Chat.ID, "usage: /unbanwl 1.2.3.4")
			return
		}
		out, err := runUnbanWL(ctx, ip)
		if err != nil {
			send(b, ctx, u.Message.Chat.ID, err.Error())
			return
		}
		send(b, ctx, u.Message.Chat.ID, out)
	}))

	b.Start(ctx)
	return nil
}
