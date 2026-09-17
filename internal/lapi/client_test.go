package lapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListAndDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/watchers/login":
			w.Write([]byte(`{"token":"t"}`))
		case r.URL.Path == "/v1/decisions" && r.Method == "GET":
			json.NewEncoder(w).Encode([]Decision{{Value: "1.2.3.4", Scenario: "x", Type: "ban", Until: "2026-01-01T00:00:00Z"}})
		case r.URL.Path == "/v1/decisions" && r.Method == "DELETE":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Login: "m", Password: "p", AllowID: "telegram-temp", TTL: "2160h", ListLimit: "50"})
	ds, err := c.ListDecisions(context.Background())
	if err != nil || len(ds) != 1 || ds[0].Value != "1.2.3.4" {
		t.Fatalf("list = %+v, err = %v", ds, err)
	}
	if err := c.DeleteDecision(context.Background(), "1.2.3.4"); err != nil {
		t.Fatalf("delete err = %v", err)
	}
}

func TestAllowlistFallbackPaths(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		if r.URL.Path == "/v1/watchers/login" {
			w.Write([]byte(`{"token":"t"}`))
			return
		}
		if r.URL.Path == "/v1/allowlists/telegram-temp" {
			w.WriteHeader(201)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Login: "m", Password: "p", AllowID: "telegram-temp", TTL: "2160h"})
	if err := c.AllowlistAdd(context.Background(), "1.2.3.4"); err != nil {
		t.Fatalf("allowlist err = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no requests made")
	}
}

func TestAllowlistRetryResendsBody(t *testing.T) {
	var bodies []string
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/watchers/login" {
			w.Write([]byte(`{"token":"t"}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if first {
			first = false
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Login: "m", Password: "p", AllowID: "telegram-temp", TTL: "2160h"})
	if err := c.AllowlistAdd(context.Background(), "5.6.7.8"); err != nil {
		t.Fatalf("allowlist err = %v", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("want 2 POST attempts, got %d", len(bodies))
	}
	for i, b := range bodies {
		var p map[string]any
		if err := json.Unmarshal([]byte(b), &p); err != nil || p["value"] != "5.6.7.8" {
			t.Fatalf("attempt %d body = %q, want value=5.6.7.8", i, b)
		}
	}
}

func TestLoginBadURLReturnsError(t *testing.T) {
	c := New(Config{URL: "http://[::1", Login: "m", Password: "p"})
	if _, err := c.ListDecisions(context.Background()); err == nil {
		t.Fatal("want error for malformed URL, got nil")
	}
}

func TestLoginGarbageBodyIsError(t *testing.T) {
	for _, body := range []string{`<html>proxy error</html>`, `null`, `{"token":""}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		c := New(Config{URL: srv.URL, Login: "m", Password: "p"})
		if _, err := c.ListDecisions(context.Background()); err == nil {
			srv.Close()
			t.Fatalf("body %q: want error, got nil", body)
		}
		srv.Close()
		if c.getToken() != "" {
			t.Fatalf("body %q: garbage token cached", body)
		}
	}
}

func TestLoginBareStringToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/watchers/login" {
			w.Write([]byte(`"bare-token-123"`))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := New(Config{URL: srv.URL, Login: "m", Password: "p"})
	if _, err := c.ListDecisions(context.Background()); err != nil {
		t.Fatalf("bare token err = %v", err)
	}
	if c.getToken() != "bare-token-123" {
		t.Fatalf("token = %q", c.getToken())
	}
}
