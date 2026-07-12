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
