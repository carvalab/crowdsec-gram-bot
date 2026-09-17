package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	n := AssetName("v1.2.3")
	if !strings.Contains(n, "linux_") || !strings.HasSuffix(n, ".tar.gz") {
		t.Fatalf("AssetName = %q", n)
	}
}

func TestNeedsUpdate(t *testing.T) {
	if !NeedsUpdate("v1.0.0", "v1.2.3") || NeedsUpdate("v1.2.3", "v1.2.3") {
		t.Fatal("needsUpdate wrong")
	}
}

func TestNeedsUpdateNormalizesVPrefix(t *testing.T) {
	if NeedsUpdate("v1.2.3", "v1.2.3") || NeedsUpdate("1.2.3", "v1.2.3") || NeedsUpdate("v1.2.3", "1.2.3") {
		t.Fatal("same version with different v-prefix should not update")
	}
	if !NeedsUpdate("dev", "v1.2.3") || !NeedsUpdate("v1.2.2", "v1.2.3") {
		t.Fatal("different versions should update")
	}
}

func TestExtractBinaryRejectsOverflow(t *testing.T) {
	old := maxAssetBytes
	maxAssetBytes = 16
	defer func() { maxAssetBytes = old }()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	big := make([]byte, 32)
	if err := tw.WriteHeader(&tar.Header{Name: "bot", Mode: 0o755, Size: int64(len(big))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(big); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	if _, err := extractBinary(&buf); err == nil {
		t.Fatal("oversized asset accepted")
	}
}

func TestExtractBinaryRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	want := []byte("fake-binary")
	if err := tw.WriteHeader(&tar.Header{Name: "bot", Mode: 0o755, Size: int64(len(want))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(want); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	got, err := extractBinary(&buf)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %q, err %v", got, err)
	}
}
