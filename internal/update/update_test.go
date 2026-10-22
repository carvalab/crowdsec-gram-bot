package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"1.2.9", "v1.2.10", true},
		{"v1.2.10", "v1.2.9", false},
		{"1.0.0", "v1.0.0", false},
		{"dev", "v9.9.9", false},
		{"1.0.0", "garbage", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.cur, c.latest, got)
		}
	}
}

func TestShippedKeyParses(t *testing.T) {
	if _, err := ParseKey(PublicKey); err != nil {
		t.Fatal(err)
	}
}

func payload() []byte { return []byte("NEWBINARY") }

type fakeGitHub struct {
	srv      *httptest.Server
	files    map[string][]byte
	gotToken []string
}

func newFakeGitHub(t *testing.T, signer ed25519.PrivateKey, tamper func(map[string][]byte)) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{files: map[string][]byte{}}
	tag := "v1.2.3"
	sum := sha256.Sum256(payload())
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + BinaryName(tag) + "\n")
	f.files[BinaryName(tag)] = payload()
	f.files[sumsName] = sums
	f.files[sigName] = ed25519.Sign(signer, sums)
	if tamper != nil {
		tamper(f.files)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gotToken = append(f.gotToken, r.Header.Get("Authorization"))
		if r.URL.Path == "/repos/o/r/releases/latest" {
			var assets []string
			for name := range f.files {
				assets = append(assets, fmt.Sprintf(`{"name":%q,"url":"%s/assets/%s"}`, name, f.srv.URL, name))
			}
			fmt.Fprintf(w, `{"tag_name":%q,"assets":[%s]}`, tag, strings.Join(assets, ","))
			return
		}
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/assets/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func download(t *testing.T, f *fakeGitHub, key ed25519.PublicKey) ([]byte, error) {
	t.Helper()
	u := &Updater{Repo: "o/r", Token: "secret", APIURL: f.srv.URL, Key: key, HTTP: f.srv.Client()}
	rel, err := u.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return u.Download(context.Background(), rel)
}

func TestDownloadVerifiesSignatureAndChecksum(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)

	f := newFakeGitHub(t, priv, nil)
	bin, err := download(t, f, pub)
	if err != nil || string(bin) != "NEWBINARY" {
		t.Fatalf("good release: %q, %v", bin, err)
	}
	for _, tok := range f.gotToken {
		if tok != "Bearer secret" {
			t.Fatalf("token header = %q", tok)
		}
	}

	if _, err := download(t, newFakeGitHub(t, priv, nil), otherPub); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("wrong trusted key: %v", err)
	}
	if _, err := download(t, newFakeGitHub(t, otherPriv, nil), pub); err == nil {
		t.Fatal("release signed by another key was accepted")
	}
	swapped := newFakeGitHub(t, priv, func(m map[string][]byte) {
		m[BinaryName("v1.2.3")] = []byte("EVIL")
	})
	if _, err := download(t, swapped, pub); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("swapped tarball: %v", err)
	}
	unsigned := newFakeGitHub(t, priv, func(m map[string][]byte) { delete(m, sigName) })
	if _, err := download(t, unsigned, pub); err == nil {
		t.Fatal("unsigned release was accepted")
	}
}

func TestTokenNeverLeavesAPIHost(t *testing.T) {
	u := &Updater{APIURL: "https://api.github.com", Token: "secret", HTTP: http.DefaultClient}
	_, err := u.get(context.Background(), "https://evil.example/asset", "x", 10)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v", err)
	}
}
