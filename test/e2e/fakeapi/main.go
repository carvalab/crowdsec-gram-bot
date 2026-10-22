// Command fakeapi stands in for api.telegram.org and api.github.com inside
// the end-to-end container. The test pushes Telegram updates through
// /control/push, reads what the bot sent from /control/sent, and serves a
// release from /srv/release for the updater. "fakeapi call JSON" probes the
// helper socket.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type call struct {
	Method string            `json:"method"`
	Fields map[string]string `json:"fields"`
}

type server struct {
	token   string
	ghToken string
	mu      sync.Mutex
	nextID  int
	queue   []json.RawMessage
	sent    []call
	wake    chan struct{}
}

func (s *server) telegram(w http.ResponseWriter, r *http.Request) {
	token, method, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/bot"), "/")
	if token != s.token {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
		return
	}
	fields := map[string]string{}
	if err := r.ParseMultipartForm(1 << 20); err == nil {
		for k, v := range r.MultipartForm.Value {
			fields[k] = v[0]
		}
	}
	switch method {
	case "getMe":
		w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"fake","username":"fake_bot"}}`))
		return
	case "getUpdates":
		deadline := time.After(2 * time.Second)
		for {
			s.mu.Lock()
			if len(s.queue) > 0 {
				out, _ := json.Marshal(s.queue)
				s.queue = nil
				s.mu.Unlock()
				w.Write([]byte(`{"ok":true,"result":` + string(out) + `}`))
				return
			}
			s.mu.Unlock()
			select {
			case <-s.wake:
			case <-deadline:
				w.Write([]byte(`{"ok":true,"result":[]}`))
				return
			case <-r.Context().Done():
				return
			}
		}
	}
	s.mu.Lock()
	s.sent = append(s.sent, call{Method: method, Fields: fields})
	s.mu.Unlock()
	if method == "sendMessage" {
		w.Write([]byte(`{"ok":true,"result":{"message_id":7,"date":0,"chat":{"id":1,"type":"private"}}}`))
		return
	}
	w.Write([]byte(`{"ok":true,"result":true}`))
}

func (s *server) push(w http.ResponseWriter, r *http.Request) {
	var u map[string]any
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.nextID++
	u["update_id"] = s.nextID
	b, _ := json.Marshal(u)
	s.queue = append(s.queue, b)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *server) sentCalls(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	json.NewEncoder(w).Encode(s.sent)
}

func (s *server) github(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.ghToken {
		http.NotFound(w, r)
		return
	}
	name := "latest.json"
	if a, ok := strings.CutPrefix(r.URL.Path, "/assets/"); ok {
		name = filepath.Base(a)
	}
	f, err := os.Open(filepath.Join("/srv/release", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

// probe sends one raw request line to the helper socket and prints the answer,
// so the test can probe the socket as different users.
func probe(line string) {
	c, err := net.Dial("unix", "/run/crowdsec-gram-bot-helper.sock")
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(3)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	io.WriteString(c, line+"\n")
	out, _ := io.ReadAll(c)
	fmt.Print(string(out))
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "call" {
		probe(os.Args[2])
		return
	}
	s := &server{token: os.Getenv("FAKE_TELEGRAM_TOKEN"), ghToken: os.Getenv("FAKE_GITHUB_TOKEN"), wake: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /control/push", s.push)
	mux.HandleFunc("GET /control/sent", s.sentCalls)
	mux.HandleFunc("/repos/", s.github)
	mux.HandleFunc("/assets/", s.github)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/bot") {
			s.telegram(w, r)
			return
		}
		http.NotFound(w, r)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:8081", mux))
}
