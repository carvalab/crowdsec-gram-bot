// Package helper is the privileged half of the bot. A systemd socket starts
// one root process per connection; it reads a single request, which can only
// list bans, unban one IP or allowlist one IP, and runs cscli with fixed
// arguments for it. The Telegram side never runs as root.
package helper

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

const (
	SocketPath = "/run/crowdsec-gram-bot-helper.sock"
	BotUser    = "crowdsec-gram-bot"

	maxRequestBytes  = 512
	maxResponseBytes = 1 << 20
	maxListed        = 20
)

type Op string

const (
	OpList  Op = "list"
	OpUnban Op = "unban"
	OpAllow Op = "allow"
)

type Request struct {
	Op     Op     `json:"op"`
	IP     string `json:"ip,omitempty"`
	Filter string `json:"filter,omitempty"`
}

type Ban struct {
	IP       string        `json:"ip"`
	Scenario string        `json:"scenario"`
	Origin   string        `json:"origin"`
	Type     string        `json:"type"`
	Left     time.Duration `json:"left"`
	Created  time.Time     `json:"created"`
}

type Response struct {
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	Bans    []Ban     `json:"bans,omitempty"`
	Total   int       `json:"total"`
	Deleted int       `json:"deleted"`
	Until   time.Time `json:"until,omitzero"`
}

var filterRe = regexp.MustCompile(`^[0-9a-fA-F.:]{1,39}$`)

// ParseIP accepts exactly one unicast IPv4 or IPv6 address and returns it in
// canonical form. Ranges, zones, hostnames and flags are rejected.
func ParseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("not a single IP address: %q", s)
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("not a host IP address: %q", s)
	}
	return a, nil
}

// Validate checks a request and canonicalises its IP. The helper calls it
// on every request, so it is the security boundary, not the bot.
func (r *Request) Validate() error {
	switch r.Op {
	case OpList:
		if r.IP != "" {
			return fmt.Errorf("list takes no ip")
		}
		if r.Filter != "" && !filterRe.MatchString(r.Filter) {
			return fmt.Errorf("bad filter %q: use the start of an IP, like 181.45", r.Filter)
		}
	case OpUnban, OpAllow:
		if r.Filter != "" {
			return fmt.Errorf("%s takes no filter", r.Op)
		}
		a, err := ParseIP(r.IP)
		if err != nil {
			return err
		}
		r.IP = a.String()
	default:
		return fmt.Errorf("unknown op %q", r.Op)
	}
	return nil
}
