// Package lapi is a minimal CrowdSec Local API client using machine
// credentials (login/password). Bouncer API keys are read-only and cannot
// delete decisions or manage allowlists, so they are not supported here.
package lapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Config holds LAPI connection settings. Empty AllowID/TTL/ListLimit fall
// back to telegram-temp/2160h/50.
type Config struct {
	URL, Login, Password, AllowID, TTL, ListLimit string
}

// Decision is the flat subset of LAPI/cscli decision fields we display.
type Decision struct {
	Value    string `json:"value"`
	IP       string `json:"ip"`
	Scenario string `json:"scenario"`
	Type     string `json:"type"`
	Until    string `json:"until"`
}

// Client talks to LAPI with a cached JWT from watchers/login.
// Safe for concurrent use by multiple goroutines.
type Client struct {
	c    Config
	http *http.Client

	mu  sync.Mutex
	tok string

	// loginMu single-flights the initial login so concurrent first
	// calls issue one login instead of one per goroutine.
	loginMu sync.Mutex
}

// New builds a Client with sane defaults.
func New(c Config) *Client {
	if c.ListLimit == "" {
		c.ListLimit = "50"
	}
	if c.TTL == "" {
		c.TTL = "2160h"
	}
	if c.AllowID == "" {
		c.AllowID = "telegram-temp"
	}
	return &Client{c: c, http: &http.Client{Timeout: 20 * time.Second}}
}

func compact(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		cut := s[:300]
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
		return cut + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

func (l *Client) getToken() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tok
}

func (l *Client) setToken(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tok = t
}

func (l *Client) login(ctx context.Context) error {
	body, err := json.Marshal(map[string]any{"machine_id": l.c.Login, "password": l.c.Password})
	if err != nil {
		return fmt.Errorf("build login body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(l.c.URL, "/")+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := l.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("login %d: %s", res.StatusCode, compact(b))
	}
	var out struct {
		Token string `json:"token"`
	}
	if decErr := json.Unmarshal(b, &out); decErr == nil {
		if out.Token == "" {
			return fmt.Errorf("login: no token in response")
		}
		l.setToken(out.Token)
		return nil
	} else {
		// Fallback: some versions return the token as a bare JSON string.
		var bare string
		if json.Unmarshal(b, &bare) == nil && strings.TrimSpace(bare) != "" {
			l.setToken(strings.TrimSpace(bare))
			return nil
		}
		return fmt.Errorf("decode login response: %w", decErr)
	}
}

func (l *Client) do(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	var payloadBytes []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, fmt.Errorf("encode request: %w", err)
		}
		payloadBytes = b
	}
	mk := func() (*http.Request, error) {
		var rdr io.Reader
		if payloadBytes != nil {
			rdr = bytes.NewReader(payloadBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(l.c.URL, "/")+path, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+l.getToken())
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	if l.getToken() == "" {
		l.loginMu.Lock()
		if l.getToken() == "" {
			err := l.login(ctx)
			l.loginMu.Unlock()
			if err != nil {
				return 0, nil, err
			}
		} else {
			l.loginMu.Unlock()
		}
	}
	req, err := mk()
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	res, err := l.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("read response: %w", err)
	}
	if res.StatusCode == 401 || res.StatusCode == 403 {
		// Token expired or wrong role (bouncer keys can't write) → re-login once.
		if err := l.login(ctx); err != nil {
			return res.StatusCode, b, fmt.Errorf("re-login failed (need MACHINE creds, not bouncer key): %w", err)
		}
		req2, err := mk()
		if err != nil {
			return 0, nil, fmt.Errorf("build retry request: %w", err)
		}
		res2, err := l.http.Do(req2)
		if err != nil {
			return 0, nil, err
		}
		defer res2.Body.Close()
		b2, err := io.ReadAll(io.LimitReader(res2.Body, 1<<20))
		if err != nil {
			return 0, nil, fmt.Errorf("read retry response: %w", err)
		}
		return res2.StatusCode, b2, nil
	}
	return res.StatusCode, b, nil
}

// ListDecisions returns current decisions (up to ListLimit).
func (l *Client) ListDecisions(ctx context.Context) ([]Decision, error) {
	st, b, err := l.do(ctx, "GET", "/v1/decisions?limit="+url.QueryEscape(l.c.ListLimit), nil)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("list %d: %s", st, compact(b))
	}
	var out []Decision
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}
	return out, nil
}

// DeleteDecision removes the decision for ip.
func (l *Client) DeleteDecision(ctx context.Context, ip string) error {
	st, b, err := l.do(ctx, "DELETE", "/v1/decisions?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return err
	}
	if st == 200 || st == 202 || st == 204 {
		return nil
	}
	return fmt.Errorf("delete %d: %s", st, compact(b))
}

// AllowlistAdd adds ip to the allowlist with TTL expiry. Endpoint naming
// differs per CrowdSec version (allowlist vs allowlists); both are tried.
func (l *Client) AllowlistAdd(ctx context.Context, ip string) error {
	payload := map[string]any{"value": ip, "expiration": l.c.TTL, "comment": "telegram-bot " + time.Now().UTC().Format("2006-01-02")}
	for _, p := range []string{"/v1/allowlists/" + url.PathEscape(l.c.AllowID), "/v1/allowlist/" + url.PathEscape(l.c.AllowID)} {
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
		return fmt.Errorf("allowlist %d: %s (cscli equiv: cscli allowlists add %s %s -e %s)", st, compact(b), l.c.AllowID, ip, l.c.TTL)
	}
	return fmt.Errorf("allowlist endpoint not found; create list first: cscli allowlists create %s", l.c.AllowID)
}
