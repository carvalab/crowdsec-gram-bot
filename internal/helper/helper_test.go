package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestParseIP(t *testing.T) {
	ok := map[string]string{
		"1.2.3.4":          "1.2.3.4",
		" 1.2.3.4 ":        "1.2.3.4",
		"2001:DB8::1":      "2001:db8::1",
		"::ffff:192.0.2.1": "192.0.2.1",
		"127.0.0.1":        "127.0.0.1",
	}
	for in, want := range ok {
		got, err := ParseIP(in)
		if err != nil || got.String() != want {
			t.Errorf("ParseIP(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1.2.3.0/24", "example.com", "-e", "--all", "1.2.3.4 --all", "1.2.3.4;id", "01.2.3.4", "fe80::1%eth0", "0.0.0.0", "::", "224.0.0.1", "1.2.3"} {
		if _, err := ParseIP(in); err == nil {
			t.Errorf("ParseIP(%q) accepted", in)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []Request{
		{Op: "exec", IP: "1.2.3.4"},
		{Op: ""},
		{Op: OpList, IP: "1.2.3.4"},
		{Op: OpList, Filter: "1.2;id"},
		{Op: OpList, Filter: "-a"},
		{Op: OpList, Filter: strings.Repeat("1", 40)},
		{Op: OpUnban},
		{Op: OpUnban, IP: "1.2.3.4", Filter: "1"},
		{Op: OpAllow, IP: "10.0.0.0/8"},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted", r)
		}
	}
	r := Request{Op: OpAllow, IP: "::ffff:1.2.3.4"}
	if err := r.Validate(); err != nil || r.IP != "1.2.3.4" {
		t.Fatalf("Validate canonical = %q, %v", r.IP, err)
	}
}

type fakeBackend struct {
	calls    []string
	bans     []Ban
	allowErr error
}

func (f *fakeBackend) List(context.Context) ([]Ban, error) {
	f.calls = append(f.calls, "list")
	return f.bans, nil
}

func (f *fakeBackend) Delete(_ context.Context, ip string) (int, error) {
	f.calls = append(f.calls, "delete "+ip)
	return 2, nil
}

func (f *fakeBackend) Allow(_ context.Context, ip string) (time.Time, int, error) {
	f.calls = append(f.calls, "allow "+ip)
	return time.Date(2027, 1, 20, 0, 0, 0, 0, time.UTC), 1, f.allowErr
}

func serve(t *testing.T, be Backend, in string) Response {
	t.Helper()
	out := &bytes.Buffer{}
	rw := struct {
		io.Reader
		io.Writer
	}{strings.NewReader(in), out}
	if err := Serve(context.Background(), rw, be); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("bad response %q: %v", out.String(), err)
	}
	return resp
}

func TestServeRejectsBadInputWithoutCallingCrowdSec(t *testing.T) {
	for _, in := range []string{
		`{"op":"unban","ip":"1.2.3.4"}`,
		strings.Repeat(" ", maxRequestBytes) + `{"op":"list"}` + "\n",
		`{"op":"unban","ip":"1.2.3.4","cmd":"id"}` + "\n",
		`{"op":"unban","ip":"1.2.3.4"}{"op":"allow","ip":"5.6.7.8"}` + "\n",
		`{"op":"unban","ip":"1.2.3.4 --all"}` + "\n",
		"not json\n",
	} {
		be := &fakeBackend{}
		resp := serve(t, be, in)
		if resp.OK || resp.Error == "" || len(be.calls) != 0 {
			t.Errorf("input %.60q: resp=%+v calls=%v", in, resp, be.calls)
		}
	}
}

func TestServeAllowAllowlistsBeforeUnban(t *testing.T) {
	be := &fakeBackend{}
	resp := serve(t, be, `{"op":"allow","ip":"::ffff:1.2.3.4"}`+"\n")
	if !resp.OK || resp.Deleted != 3 || resp.Until.IsZero() {
		t.Fatalf("resp = %+v", resp)
	}
	if strings.Join(be.calls, ",") != "allow 1.2.3.4,delete 1.2.3.4" {
		t.Fatalf("calls = %v", be.calls)
	}
}

func TestServeAllowFailureKeepsBan(t *testing.T) {
	be := &fakeBackend{allowErr: errors.New("db locked")}
	resp := serve(t, be, `{"op":"allow","ip":"1.2.3.4"}`+"\n")
	if resp.OK || len(be.calls) != 1 {
		t.Fatalf("resp = %+v calls = %v", resp, be.calls)
	}
}

func TestServeListFiltersSortsAndCaps(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	be := &fakeBackend{}
	for i := range 30 {
		be.bans = append(be.bans, Ban{IP: "10.0.0." + string(rune('0'+i%10)), Created: base.Add(time.Duration(i) * time.Minute)})
	}
	be.bans = append(be.bans, Ban{IP: "192.0.2.1", Created: base})
	resp := serve(t, be, `{"op":"list","filter":"10.0."}`+"\n")
	if resp.Total != 30 || len(resp.Bans) != maxListed {
		t.Fatalf("total=%d listed=%d", resp.Total, len(resp.Bans))
	}
	if !resp.Bans[0].Created.Equal(base.Add(29 * time.Minute)) {
		t.Fatalf("not newest first: %v", resp.Bans[0].Created)
	}
}

func TestParseTTL(t *testing.T) {
	if d, err := ParseTTL("90d"); err != nil || d != 2160*time.Hour {
		t.Fatalf("90d = %v, %v", d, err)
	}
	if d, err := ParseTTL("36h"); err != nil || d != 36*time.Hour {
		t.Fatalf("36h = %v, %v", d, err)
	}
	for _, s := range []string{"", "0d", "-1h", "forever", "1.5d"} {
		if _, err := ParseTTL(s); err == nil {
			t.Errorf("ParseTTL(%q) accepted", s)
		}
	}
}
