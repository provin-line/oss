package core

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// ErrUnsupportedScheme is returned for a secret URI whose scheme this build does
// not resolve (the vault:// / awssm:// seams, and any unschemed/bare value).
var ErrUnsupportedScheme = errors.New("core: unsupported secret scheme")

// ResolveSecret loads the secret named by uri. file:///abs/path reads the file;
// vault:// and awssm:// are recognized seams that return ErrUnsupportedScheme
// until implemented; anything else (including a bare unschemed string) is
// rejected with ErrUnsupportedScheme — fail-closed, never guessed. ctx is
// carried now (file:// ignores it) so the network-bound seams need no signature
// change later.
func ResolveSecret(ctx context.Context, uri string) ([]byte, error) {
	_ = ctx // unused until the network-bound seams land
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("core: parse secret uri %q: %w", uri, err)
	}
	switch u.Scheme {
	case "file":
		// Require the file:///abs/path form: no host, absolute path.
		if u.Host != "" {
			return nil, fmt.Errorf("core: file secret uri must be file:///abs/path (no host): %q", uri)
		}
		if u.Path == "" || !filepath.IsAbs(u.Path) {
			return nil, fmt.Errorf("core: file secret path must be absolute: %q", uri)
		}
		b, err := os.ReadFile(u.Path)
		if err != nil {
			return nil, fmt.Errorf("core: read secret: %w", err)
		}
		return b, nil
	case "vault", "awssm":
		return nil, fmt.Errorf("%w: %q (seam not implemented)", ErrUnsupportedScheme, u.Scheme)
	default:
		return nil, fmt.Errorf("%w: %q (a scheme is required, e.g. file://)", ErrUnsupportedScheme, u.Scheme)
	}
}
