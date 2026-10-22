package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/carvalab/crowdsec-gram-bot/internal/helper"
)

type caller func(ctx context.Context, req helper.Request) (helper.Response, error)

// app answers one Telegram user, in a private chat, and nobody else.
type app struct {
	admin int64
	call  caller
}

type reply struct {
	text    string
	buttons [][]models.InlineKeyboardButton
}

func runBot(ctx context.Context) error {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN"))
	if token == "" {
		return errors.New("missing TELEGRAM_TOKEN")
	}
	admin, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("TELEGRAM_ADMIN_ID")), 10, 64)
	if err != nil || admin <= 0 {
		return errors.New("TELEGRAM_ADMIN_ID must be your numeric Telegram user id")
	}
	a := &app{admin: admin, call: func(ctx context.Context, req helper.Request) (helper.Response, error) {
		ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		return helper.Call(ctx, helper.SocketPath, req)
	}}
	opts := []bot.Option{
		bot.WithDefaultHandler(a.handle),
		bot.WithAllowedUpdates(bot.AllowedUpdates{"message", "callback_query"}),
		bot.WithNotAsyncHandlers(),
	}
	if u := strings.TrimSpace(os.Getenv("TELEGRAM_API_URL")); u != "" {
		opts = append(opts, bot.WithServerURL(u))
	}
	b, err := bot.New(token, opts...)
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	if _, err := b.SetMyCommands(ctx, &bot.SetMyCommandsParams{
		Scope: &models.BotCommandScopeChat{ChatID: admin},
		Commands: []models.BotCommand{
			{Command: "bans", Description: "Newest bans, with unban buttons"},
			{Command: "unban", Description: "Remove the ban on an IP"},
			{Command: "allow", Description: "Unban and allowlist an IP"},
			{Command: "help", Description: "How to use this bot"},
		},
	}); err != nil {
		log.Printf("telegram: set command menu: %v", err)
	}
	log.Printf("crowdsec-gram-bot %s started, answering Telegram user %d only", version, admin)
	b.Start(ctx)
	return nil
}

func (a *app) handle(ctx context.Context, b *bot.Bot, u *models.Update) {
	switch {
	case u.Message != nil:
		m := u.Message
		if m.From == nil || m.From.ID != a.admin || m.Chat.ID != a.admin || m.Chat.Type != models.ChatTypePrivate {
			log.Printf("ignored message from user %d in chat %d", fromID(m.From), m.Chat.ID)
			return
		}
		a.send(ctx, b, a.onText(ctx, m.Text))
	case u.CallbackQuery != nil:
		q := u.CallbackQuery
		msg := q.Message.Message
		if q.From.ID != a.admin || msg == nil || msg.Chat.ID != a.admin {
			log.Printf("ignored button from user %d", q.From.ID)
			return
		}
		_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: q.ID})
		a.send(ctx, b, a.onButton(ctx, q.Data))
	}
}

func fromID(u *models.User) int64 {
	if u == nil {
		return 0
	}
	return u.ID
}

func (a *app) send(ctx context.Context, b *bot.Bot, r reply) {
	p := &bot.SendMessageParams{ChatID: a.admin, Text: r.text}
	if len(r.buttons) > 0 {
		p.ReplyMarkup = &models.InlineKeyboardMarkup{InlineKeyboard: r.buttons}
	}
	if _, err := b.SendMessage(ctx, p); err != nil {
		log.Printf("send reply: %v", err)
	}
}

func help() reply {
	return reply{text: "CrowdSec unban bot " + version + "\n\n" +
		"/bans: newest bans, with buttons\n" +
		"/bans 181.45: only IPs that start with 181.45\n" +
		"/unban 1.2.3.4: remove the ban\n" +
		"/allow 1.2.3.4: remove the ban and allowlist the IP, so it is not banned again\n\n" +
		"You can also just send an IP.\n" +
		"Locked out? Open https://ifconfig.me on the blocked network to see your IP."}
}

// command splits "/bans@MyBot 181.45" into "/bans" and "181.45".
func command(text string) (string, string) {
	f := strings.Fields(text)
	if len(f) == 0 {
		return "", ""
	}
	cmd, _, _ := strings.Cut(strings.ToLower(f[0]), "@")
	return cmd, strings.Join(f[1:], " ")
}

func (a *app) onText(ctx context.Context, text string) reply {
	cmd, arg := command(text)
	switch cmd {
	case "/start", "/help":
		return help()
	case "/bans":
		return a.list(ctx, arg)
	case "/unban":
		return a.act(ctx, helper.OpUnban, arg)
	case "/allow":
		return a.act(ctx, helper.OpAllow, arg)
	}
	if ip, err := helper.ParseIP(text); err == nil {
		s := ip.String()
		return reply{text: "What should I do with " + s + "?", buttons: [][]models.InlineKeyboardButton{{
			{Text: "🔓 Unban", CallbackData: "u:" + s},
			{Text: "✅ Unban + allowlist", CallbackData: "a:" + s},
		}}}
	}
	return reply{text: "I did not get that. Send an IP, or /help."}
}

func (a *app) onButton(ctx context.Context, data string) reply {
	kind, ip, _ := strings.Cut(data, ":")
	switch kind {
	case "u":
		return a.act(ctx, helper.OpUnban, ip)
	case "a":
		return a.act(ctx, helper.OpAllow, ip)
	}
	return reply{text: "That button is not valid any more. Try /bans."}
}

func (a *app) act(ctx context.Context, op helper.Op, arg string) reply {
	ip, err := helper.ParseIP(arg)
	if err != nil {
		return reply{text: "Usage: /" + string(op) + " 1.2.3.4"}
	}
	s := ip.String()
	resp, err := a.call(ctx, helper.Request{Op: op, IP: s})
	if err != nil {
		log.Printf("%s %s failed: %v", op, s, err)
		return reply{text: "⚠️ " + string(op) + " " + s + " failed: " + err.Error()}
	}
	log.Printf("%s %s ok: %d ban(s) removed", op, s, resp.Deleted)
	removed := "It had no active ban."
	if resp.Deleted > 0 {
		removed = fmt.Sprintf("Removed %d ban(s). The firewall picks this up within a few seconds.", resp.Deleted)
	}
	if op == helper.OpAllow {
		return reply{text: "✅ " + s + " is allowlisted until " + resp.Until.UTC().Format("2006-01-02") + ". " + removed}
	}
	if resp.Deleted == 0 {
		return reply{text: "ℹ️ " + s + " had no active ban. Nothing changed."}
	}
	return reply{text: "🔓 Unbanned " + s + ". " + removed}
}

func (a *app) list(ctx context.Context, filter string) reply {
	resp, err := a.call(ctx, helper.Request{Op: helper.OpList, Filter: filter})
	if err != nil {
		return reply{text: "⚠️ listing bans failed: " + err.Error()}
	}
	if resp.Total == 0 {
		if filter != "" {
			return reply{text: "No active bans for IPs that start with " + filter + "."}
		}
		return reply{text: "No active bans. 🎉"}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "🚫 %d active ban(s), newest first:\n\n", resp.Total)
	var rows [][]models.InlineKeyboardButton
	for i, ban := range resp.Bans {
		fmt.Fprintf(&sb, "%d. %s · %s · %s left\n", i+1, ban.IP, shortScenario(ban.Scenario), shortDuration(ban.Left))
		if _, err := helper.ParseIP(ban.IP); err != nil {
			continue
		}
		rows = append(rows, []models.InlineKeyboardButton{
			{Text: "🔓 " + ban.IP, CallbackData: "u:" + ban.IP},
			{Text: "✅ allowlist", CallbackData: "a:" + ban.IP},
		})
	}
	if resp.Total > len(resp.Bans) {
		fmt.Fprintf(&sb, "\nShowing %d of %d. Narrow it down: /bans 181.45", len(resp.Bans), resp.Total)
	}
	if strings.Contains(sb.String(), "/") {
		sb.WriteString("\nA range ban (with /) is lifted when you /unban an IP inside it.")
	}
	return reply{text: sb.String(), buttons: rows}
}

func shortScenario(s string) string {
	if _, name, ok := strings.Cut(s, "/"); ok && !strings.Contains(s, " ") {
		return name
	}
	return s
}

func shortDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "?"
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dm", max(1, int(d.Minutes())))
	}
}
