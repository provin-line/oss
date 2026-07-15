package core

import (
	"crypto/tls"
	"fmt"
)

// LoadServerTLS is the TLS boot preflight (P0-6). For a TLS posture it loads
// and validates the certificate pair and returns the server configuration; for
// a cleartext posture it returns nil.
//
// Call it BEFORE any side-effectful boot work. Serving used to load the pair
// lazily inside ListenAndServeTLS, which meant a node with an unreadable or
// mismatched pair would first create stores, connect transports, and bind its
// listener — and only then die, leaving half-initialized state behind. The
// preflight makes cert failure a clean pre-side-effect boot failure.
//
// The returned config carries the loaded pair, and the caller serves from it
// (ListenAndServeTLS("", "") uses Certificates) — the files are not re-read at
// serve time, so what serves is byte-for-byte what was validated. A re-read
// would reopen the window between validation and use that the preflight closes.
//
// MinVersion is pinned to TLS 1.2 explicitly. Go's server default is the same
// value today, but the floor is this repository's contract
// (SECURITY.md; the P0-6 closure conditions), and a contract held by a
// library default is one dependency upgrade away from silently changing.
// Cipher suites stay on Go's secure defaults deliberately: TLS 1.3 suites are
// not configurable through the API, and a frozen allowlist would block future
// stdlib security improvements (SECURITY.md records this posture).
func (c TLSConfig) LoadServerTLS() (*tls.Config, error) {
	if !c.ServesTLS() {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("core: TLS preflight: certificate pair (%s, %s): %w", c.CertFile, c.KeyFile, err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}, nil
}
