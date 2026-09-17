// Package update self-updates the binary from GitHub releases.
// Works with public repos anonymously and private repos via GITHUB_TOKEN
// (contents:read). Asset convention: crowdsec-gram-bot_<ver>_linux_<arch>.tar.gz
// containing a single executable.
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

var (
	// apiClient serves small JSON calls; downloadClient serves the asset
	// tarball (Timeout covers the whole body read, so it gets a large cap).
	apiClient      = &http.Client{Timeout: 20 * time.Second}
	downloadClient = &http.Client{Timeout: 10 * time.Minute}
)

var httpClient = apiClient

// AssetName maps a release tag to this platform's asset file.
func AssetName(tag string) string {
	v := strings.TrimPrefix(strings.TrimSpace(tag), "v")
	return fmt.Sprintf("crowdsec-gram-bot_%s_linux_%s.tar.gz", v, runtime.GOARCH)
}

func NeedsUpdate(current, latest string) bool {
	norm := func(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }
	current, latest = norm(current), norm(latest)
	return latest != "" && current != latest
}

type release struct {
	Tag    string `json:"tag_name"`
	Body   string `json:"body"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"assets"`
}

func ghGet(ctx context.Context, url, token string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("read github response: %w", err)
	}
	if res.StatusCode == 401 || res.StatusCode == 404 {
		return fmt.Errorf("github %d: %s (private repo? set GITHUB_TOKEN with contents:read)", res.StatusCode, compact(b))
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("github %d: %s", res.StatusCode, compact(b))
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode github response: %w", err)
	}
	return nil
}

func compact(b []byte) string {
	s := strings.TrimSpace(string(b))
	if r := []rune(s); len(r) > 300 {
		return string(r[:300]) + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

func fetchRelease(ctx context.Context, repo, token string) (release, error) {
	var r release
	if err := ghGet(ctx, "https://api.github.com/repos/"+repo+"/releases/latest", token, &r); err != nil {
		return r, err
	}
	if r.Tag == "" {
		return r, fmt.Errorf("latest release has no tag")
	}
	return r, nil
}

// Latest returns the newest release tag and notes for repo ("owner/name").
func Latest(ctx context.Context, repo, token string) (tag, notes string, err error) {
	r, err := fetchRelease(ctx, repo, token)
	if err != nil {
		return "", "", err
	}
	return r.Tag, r.Body, nil
}

// Apply downloads the asset for this platform, verifies its sha256 against
// the release checksums.txt, and replaces the binary. Returns the tag.
// Fail-closed: a missing/unparsable checksum aborts the update.
func Apply(ctx context.Context, repo, token string) (string, error) {
	r, err := fetchRelease(ctx, repo, token)
	if err != nil {
		return "", err
	}
	tag := r.Tag
	want := AssetName(tag)
	byName := map[string]string{}
	for _, a := range r.Assets {
		byName[a.Name] = a.URL
	}
	dl := byName[want]
	if dl == "" {
		return "", fmt.Errorf("no asset %q in release %s", want, tag)
	}
	tarball, err := download(ctx, dl, token)
	if err != nil {
		return "", err
	}
	sumURL := byName["checksums.txt"]
	if sumURL == "" {
		return "", fmt.Errorf("no checksums.txt in release %s: refusing unverified update", tag)
	}
	wantSum, err := findChecksum(ctx, sumURL, token, want)
	if err != nil {
		return "", err
	}
	if got := sha256.Sum256(tarball); !bytes.Equal(got[:], wantSum) {
		return "", fmt.Errorf("checksum mismatch for %s: refusing update", want)
	}
	bin, err := extractBinary(bytes.NewReader(tarball))
	if err != nil {
		return "", err
	}
	binSum := sha256.Sum256(bin)
	if err := selfupdate.Apply(bytes.NewReader(bin), selfupdate.Options{Checksum: binSum[:]}); err != nil {
		return "", fmt.Errorf("apply update: %w (rollback on failure is automatic)", err)
	}
	return tag, nil
}

// download fetches a URL fully (bounded by maxAssetBytes+tar overhead).
func download(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := downloadClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return nil, fmt.Errorf("download %d: %s", res.StatusCode, compact(b))
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxAssetBytes+1<<20))
	if err != nil {
		return nil, fmt.Errorf("read download: %w", err)
	}
	return b, nil
}

// findChecksum parses a `sha256  filename` checksums.txt for want.
func findChecksum(ctx context.Context, url, token, want string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums %d: %s", res.StatusCode, compact(b))
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == want {
			sum, err := hex.DecodeString(f[0])
			if err != nil || len(sum) != 32 {
				return nil, fmt.Errorf("bad checksum entry for %s", want)
			}
			return sum, nil
		}
	}
	return nil, fmt.Errorf("no checksum for %s in checksums.txt", want)
}

// maxAssetBytes caps a single asset member; +1 byte detects overflow
// (LimitReader alone would truncate silently and brick the binary).
var maxAssetBytes = int64(64 << 20)

// extractBinary gunzips+untars a single-file archive, returning its bytes.
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
			break
		}
		if err != nil {
			return nil, fmt.Errorf("untar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxAssetBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read asset file: %w", err)
		}
		if int64(len(b)) > maxAssetBytes {
			return nil, fmt.Errorf("asset exceeds %d MiB limit", maxAssetBytes>>20)
		}
		if len(b) == 0 {
			continue
		}
		return b, nil
	}
	return nil, fmt.Errorf("no executable found in archive")
}
