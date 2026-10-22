package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/carvalab/crowdsec-gram-bot/internal/helper"
)

const adminID = 4242

type recorder struct {
	mu    sync.Mutex
	sent  []string
	calls []helper.Request
}

func newTestApp(t *testing.T) (*app, *bot.Bot, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(1 << 20)
		rec.mu.Lock()
		if strings.HasSuffix(r.URL.Path, "/sendMessage") {
			rec.sent = append(rec.sent, r.FormValue("text"))
		}
		rec.mu.Unlock()
		w.Write([]byte(`{"ok":true,"result":{"message_id":1,"date":0,"chat":{"id":4242,"type":"private"}}}`))
	}))
	t.Cleanup(srv.Close)
	b, err := bot.New("TOKEN", bot.WithServerURL(srv.URL), bot.WithSkipGetMe())
	if err != nil {
		t.Fatal(err)
	}
	a := &app{admin: adminID, call: func(_ context.Context, req helper.Request) (helper.Response, error) {
		rec.calls = append(rec.calls, req)
		return helper.Response{OK: true, Deleted: 1, Until: time.Date(2027, 1, 20, 0, 0, 0, 0, time.UTC)}, nil
	}}
	return a, b, rec
}

func msg(from, chat int64, typ models.ChatType, text string) *models.Update {
	return &models.Update{Message: &models.Message{From: &models.User{ID: from}, Chat: models.Chat{ID: chat, Type: typ}, Text: text}}
}

func TestOnlyAdminInPrivateChatIsServed(t *testing.T) {
	a, b, rec := newTestApp(t)
	ctx := context.Background()
	a.handle(ctx, b, msg(999, 999, models.ChatTypePrivate, "/unban 1.2.3.4"))
	a.handle(ctx, b, msg(adminID, -100123, models.ChatTypeSupergroup, "/unban 1.2.3.4"))
	a.handle(ctx, b, msg(999, adminID, models.ChatTypePrivate, "/unban 1.2.3.4"))
	a.handle(ctx, b, &models.Update{Message: &models.Message{Chat: models.Chat{ID: adminID, Type: models.ChatTypePrivate}, Text: "/unban 1.2.3.4"}})
	a.handle(ctx, b, &models.Update{CallbackQuery: &models.CallbackQuery{From: models.User{ID: 999}, Data: "u:1.2.3.4",
		Message: models.MaybeInaccessibleMessage{Message: &models.Message{Chat: models.Chat{ID: adminID}}}}})
	if len(rec.calls) != 0 || len(rec.sent) != 0 {
		t.Fatalf("strangers got through: calls=%v sent=%v", rec.calls, rec.sent)
	}
	a.handle(ctx, b, msg(adminID, adminID, models.ChatTypePrivate, "/unban 1.2.3.4"))
	a.handle(ctx, b, &models.Update{CallbackQuery: &models.CallbackQuery{ID: "q", From: models.User{ID: adminID}, Data: "a:5.6.7.8",
		Message: models.MaybeInaccessibleMessage{Message: &models.Message{Chat: models.Chat{ID: adminID}}}}})
	if len(rec.calls) != 2 || rec.calls[0].Op != helper.OpUnban || rec.calls[1] != (helper.Request{Op: helper.OpAllow, IP: "5.6.7.8"}) {
		t.Fatalf("admin calls = %+v", rec.calls)
	}
	if len(rec.sent) != 2 || !strings.Contains(rec.sent[1], "allowlisted until 2027-01-20") {
		t.Fatalf("sent = %q", rec.sent)
	}
}

func TestBadArgumentsNeverReachHelper(t *testing.T) {
	a, _, rec := newTestApp(t)
	for _, text := range []string{"/unban", "/unban 1.2.3.0/24", "/unban 1.2.3.4 --all", "/allow $(id)", "/allow example.com", "u:1.2.3.4"} {
		r := a.onText(context.Background(), text)
		if !strings.Contains(r.text, "Usage") && !strings.Contains(r.text, "did not get") {
			t.Errorf("%q -> %q", text, r.text)
		}
	}
	if r := a.onButton(context.Background(), "x:1.2.3.4"); !strings.Contains(r.text, "not valid") {
		t.Errorf("unknown button -> %q", r.text)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("helper called with %+v", rec.calls)
	}
}

func TestBareIPOffersButtons(t *testing.T) {
	a, _, _ := newTestApp(t)
	r := a.onText(context.Background(), "::ffff:181.45.3.2")
	b, _ := json.Marshal(r.buttons)
	if !strings.Contains(r.text, "181.45.3.2") || !strings.Contains(string(b), `"u:181.45.3.2"`) || !strings.Contains(string(b), `"a:181.45.3.2"`) {
		t.Fatalf("reply = %q buttons = %s", r.text, b)
	}
}

func TestCommandSplit(t *testing.T) {
	if c, a := command("/Bans@MyBot  181.45 "); c != "/bans" || a != "181.45" {
		t.Fatalf("got %q %q", c, a)
	}
}
