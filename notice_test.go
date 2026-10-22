package main

import (
	"strings"
	"testing"
)

func TestNotices(t *testing.T) {
	cases := []struct {
		last, current, failed, lastFailed string
		want                              []string
	}{
		{"", "1.0.2", "", "", []string{"is running"}},
		{"1.0.2", "1.0.2", "", "", nil},
		{"1.0.2", "1.0.3", "", "", []string{"Updated to 1.0.3 (was 1.0.2)", "releases/tag/v1.0.3"}},
		{"1.0.3", "1.0.2", "", "", []string{"Now running 1.0.2 (was 1.0.3)"}},
		{"1.0.3", "1.0.3", "v1.0.4", "", []string{"v1.0.4 failed its health check", "went back to 1.0.3"}},
		{"1.0.3", "1.0.3", "v1.0.4", "v1.0.4", nil},
	}
	for _, c := range cases {
		got := strings.Join(notices(c.last, c.current, c.failed, c.lastFailed), "\n")
		if len(c.want) == 0 && got != "" {
			t.Errorf("%+v: want nothing, got %q", c, got)
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%+v: %q lacks %q", c, got, w)
			}
		}
	}
}
