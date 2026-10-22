// Package update replaces the binary with the newest GitHub release. A
// release is trusted only when its checksums.txt carries a valid Ed25519
// signature from the key baked into this binary.
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/selfupdate"
	"golang.org/x/mod/semver"
)

// PublicKey verifies release signatures. It is a variable only so the
// end-to-end test can build a binary that trusts its own test key.
var PublicKey = "OCmvuqGInMtB99Rd/1cm261kAtVWFeNaBuafHIIU6Dw="

const (
	sumsName      = "checksums.txt"
	sigName       = "checksums.txt.sig"
	maxAssetBytes = 64 << 20
)

type Updater struct {
	Repo    string
	Token   string
	APIURL  string
	Current string
	Key     ed25519.PublicKey
	HTTP    *http.Client
}

type Release struct {
	Tag    string
	Assets map[string]string
}

// ParseKey decodes a base64 Ed25519 public key.
func ParseKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad release public key")
	}
	return ed25519.PublicKey(b), nil
}

// AssetName is the release tarball for this platform.
func AssetName(tag string) string {
	return fmt.Sprintf("crowdsec-gram-bot_%s_linux_%s.tar.gz", strings.TrimPrefix(tag, "v"), runtime.GOARCH)
}

// Newer reports whether latest is a higher semver than current. Builds that
// are not semver, such as "dev", never auto-update.
func Newer(current, latest string) bool {
	norm := func(v string) string { return "v" + strings.TrimPrefix(strings.TrimSpace(v), "v") }
	c, l := norm(current), norm(latest)
	return semver.IsValid(c) && semver.IsValid(l) && semver.Compare(l, c) > 0
}

func (u *Updater) get(ctx context.Context, url, accept string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, strings.TrimRight(u.APIURL, "/")+"/") {
		return nil, fmt.Errorf("refusing to send the GitHub token to %s", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if u.Token != "" {
		req.Header.Set("Authorization", "Bearer "+u.Token)
	}
	res, err := u.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", url, limit)
	}
	switch {
	case res.StatusCode == http.StatusOK:
		return b, nil
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("github %d for %s: the repo is private, so GITHUB_TOKEN needs contents:read on it", res.StatusCode, url)
	default:
		return nil, fmt.Errorf("github %d for %s", res.StatusCode, url)
	}
}

// Latest returns the newest published release.
func (u *Updater) Latest(ctx context.Context) (Release, error) {
	b, err := u.get(ctx, strings.TrimRight(u.APIURL, "/")+"/repos/"+u.Repo+"/releases/latest", "application/vnd.github+json", 4<<20)
	if err != nil {
		return Release{}, err
	}
	var r struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return Release{}, fmt.Errorf("decode release: %w", err)
	}
	if r.Tag == "" {
		return Release{}, errors.New("latest release has no tag")
	}
	rel := Release{Tag: r.Tag, Assets: map[string]string{}}
	for _, a := range r.Assets {
		rel.Assets[a.Name] = a.URL
	}
	return rel, nil
}

func (u *Updater) asset(ctx context.Context, rel Release, name string, limit int64) ([]byte, error) {
	url := rel.Assets[name]
	if url == "" {
		return nil, fmt.Errorf("release %s has no %s", rel.Tag, name)
	}
	return u.get(ctx, url, "application/octet-stream", limit)
}

// Download fetches the binary for this platform and returns it only when
// the signature and the checksum both match.
func (u *Updater) Download(ctx context.Context, rel Release) ([]byte, error) {
	sums, err := u.asset(ctx, rel, sumsName, 1<<20)
	if err != nil {
		return nil, err
	}
	sig, err := u.asset(ctx, rel, sigName, 1<<10)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(u.Key, sums, sig) {
		return nil, fmt.Errorf("release %s: bad signature on %s, refusing update", rel.Tag, sumsName)
	}
	name := AssetName(rel.Tag)
	want, err := findSum(sums, name)
	if err != nil {
		return nil, err
	}
	tarball, err := u.asset(ctx, rel, name, maxAssetBytes)
	if err != nil {
		return nil, err
	}
	if got := sha256.Sum256(tarball); !bytes.Equal(got[:], want) {
		return nil, fmt.Errorf("checksum mismatch for %s, refusing update", name)
	}
	return extractBinary(bytes.NewReader(tarball))
}

func findSum(sums []byte, name string) ([]byte, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			sum, err := hex.DecodeString(f[0])
			if err != nil || len(sum) != sha256.Size {
				return nil, fmt.Errorf("bad checksum entry for %s", name)
			}
			return sum, nil
		}
	}
	return nil, fmt.Errorf("no checksum for %s", name)
}

func extractBinary(r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("no crowdsec-gram-bot binary in archive")
		}
		if err != nil {
			return nil, fmt.Errorf("untar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != "crowdsec-gram-bot" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxAssetBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read binary: %w", err)
		}
		if len(b) > maxAssetBytes {
			return nil, fmt.Errorf("binary is larger than %d MiB", maxAssetBytes>>20)
		}
		return b, nil
	}
}

// SmokeTest runs `bin version` from a temp file and checks it reports tag.
func SmokeTest(ctx context.Context, bin []byte, tag string) error {
	f, err := os.CreateTemp("", "crowdsec-gram-bot-new-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(bin); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o700); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, f.Name(), "version").Output()
	if err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}
	if !strings.Contains(string(out), "version="+strings.TrimPrefix(tag, "v")) {
		return fmt.Errorf("new binary reports %q, want %s", strings.TrimSpace(string(out)), tag)
	}
	return nil
}

// Install swaps exe for bin and keeps the previous binary at exe+".old".
func Install(bin []byte, exe string) error {
	sum := sha256.Sum256(bin)
	if err := selfupdate.Apply(bytes.NewReader(bin), selfupdate.Options{TargetPath: exe, Checksum: sum[:], OldSavePath: exe + ".old"}); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}

// Rollback puts the binary saved by Install back in place.
func Rollback(exe string) error { return os.Rename(exe+".old", exe) }

type unitState struct {
	Active   string
	Restarts int
}

func state(ctx context.Context, unit string) (unitState, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "ActiveState", "-p", "NRestarts", unit).Output()
	if err != nil {
		return unitState{}, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	var s unitState
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "ActiveState":
			s.Active = v
		case "NRestarts":
			s.Restarts, _ = strconv.Atoi(v)
		}
	}
	return s, nil
}

// Running reports whether unit is active right now.
func Running(ctx context.Context, unit string) (bool, error) {
	s, err := state(ctx, unit)
	return s.Active == "active", err
}

// RestartHealthy restarts unit and fails if it is not still up, without
// crash restarts, after settle.
func RestartHealthy(ctx context.Context, unit string, settle time.Duration) error {
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	before, err := state(ctx, unit)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(settle):
	}
	after, err := state(ctx, unit)
	if err != nil {
		return err
	}
	if after.Active != "active" || after.Restarts > before.Restarts {
		return fmt.Errorf("%s is %s after %d restart(s)", unit, after.Active, after.Restarts-before.Restarts)
	}
	return nil
}
