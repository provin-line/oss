// Package commands implements the provin CLI's command groups (one file per
// group). Commands hold no protocol logic beyond request shaping: the wire is
// internal/client, key custody is internal/keyfile.
package commands

import (
	"io"
	"net/http"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/client"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
)

// Env is the per-invocation environment every command runs against: the
// registry base URL and L1 token (flags / PROVIN_REGISTRY / PROVIN_TOKEN),
// the HTTP transport (nil = http.DefaultClient; tests inject httptest's), and
// the stream user-facing output goes to.
type Env struct {
	Registry   string
	Token      string
	HTTPClient connect.HTTPClient
	Stdout     io.Writer
}

func (e Env) httpClient() connect.HTTPClient {
	if e.HTTPClient == nil {
		return http.DefaultClient
	}
	return e.HTTPClient
}

func (e Env) out() io.Writer {
	if e.Stdout == nil {
		return io.Discard
	}
	return e.Stdout
}

func (e Env) didClient() (didpbconnect.DIDServiceClient, error) {
	return client.DID(e.httpClient(), e.Registry, e.Token)
}
