package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
)

func TestResolveSecret_File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.txt")
	want := []byte("s3cr3t-bytes")
	if err := os.WriteFile(p, want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := core.ResolveSecret(context.Background(), "file://"+p)
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveSecret_FileMissing(t *testing.T) {
	if _, err := core.ResolveSecret(context.Background(), "file:///nonexistent/abs/path"); err == nil {
		t.Error("missing file: want error")
	}
}

func TestResolveSecret_FileRejectsRelativeAndHost(t *testing.T) {
	for _, uri := range []string{"file://relative/path", "file://host/abs/path"} {
		if _, err := core.ResolveSecret(context.Background(), uri); err == nil {
			t.Errorf("ResolveSecret(%q): want error (must be file:///abs/path)", uri)
		}
	}
}

func TestResolveSecret_SeamsUnsupported(t *testing.T) {
	for _, uri := range []string{"vault://kv/data/x", "awssm://prod/key"} {
		if _, err := core.ResolveSecret(context.Background(), uri); !errors.Is(err, core.ErrUnsupportedScheme) {
			t.Errorf("ResolveSecret(%q): want ErrUnsupportedScheme, got %v", uri, err)
		}
	}
}

func TestResolveSecret_BareStringRejected(t *testing.T) {
	// D4: an unschemed value is ambiguous; reject (fail-closed).
	if _, err := core.ResolveSecret(context.Background(), "just-a-literal"); !errors.Is(err, core.ErrUnsupportedScheme) {
		t.Errorf("bare string: want ErrUnsupportedScheme, got %v", err)
	}
}
