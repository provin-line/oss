// Package commands implements the provin CLI's command groups (one file per
// group). Commands hold no protocol logic beyond request shaping: the wire is
// internal/client, key custody is internal/keyfile.
package commands

import (
	"fmt"
	"io"
	"net/http"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/client"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	"github.com/provin-line/oss/internal/origin"
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

// httpClient is the client for calls to the registry that carry the token. The
// default client, or an *http.Client given, is confined: it follows no
// redirect, so the token goes to the registry's origin only. Another
// connect.HTTPClient (a test's) is used as given.
func (e Env) httpClient() connect.HTTPClient {
	switch c := e.HTTPClient.(type) {
	case nil:
		return origin.Confine(http.DefaultClient)
	case *http.Client:
		return origin.Confine(c)
	default:
		return c
	}
}

// publicHTTPClient is the client for the registry's public routes, which carry
// no token: it follows redirects as the default client does.
func (e Env) publicHTTPClient() connect.HTTPClient {
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

func (e Env) schemaClient() (schemapbconnect.SchemaServiceClient, error) {
	return client.Schema(e.httpClient(), e.Registry, e.Token)
}

func (e Env) chainClient() (chainpbconnect.ChainServiceClient, error) {
	return client.Chain(e.httpClient(), e.Registry, e.Token)
}

// ExitStatus is a typed error a command can return to request a specific
// process exit code, beyond the generic 1 every other error maps to (spec
// cli-stage3-orgverify-port §7.3). main() unwraps it via errors.As and exits
// with Code — commands themselves never call os.Exit, so every command path
// stays testable in-process (run() / commands.XXX return an error either
// way).
//
// Message, when non-empty, is also printed to stderr; when empty, main()
// prints nothing beyond exiting with Code — the verdict-driven codes from
// `org verify` leave it empty because the verdict was already reported on
// stdout (see OrgVerify), and repeating it on stderr would be noise, not new
// information.
type ExitStatus struct {
	Code    int
	Message string
}

// Error implements error. It never returns an empty string even when Message
// is empty, so ExitStatus remains a well-behaved error on any path that logs
// err.Error() directly instead of going through main()'s Message-aware
// unwrap.
func (e ExitStatus) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("exit status %d", e.Code)
}
