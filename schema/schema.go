// Package schema defines payload validation against registered schemas
// — the client-side contract of the schema registry. Implementations
// live in subpackages, mirroring the resolver package's pattern: local
// (PoC fixtures and in-org deployments) now; a registry-backed client
// lands with the network layer.
package schema

import (
	"context"

	"github.com/provin-line/oss/vc"
)

// Validator validates a payload against the schema named by ref.
// Resolution of ref — the content-addressed fetch from a registry or a
// local store — is the implementation's concern; a validation failure
// is an error naming the violated constraint. A process's input and
// output checks are both expressed with this one interface; the checks
// are optional per the processing lifecycle, expressed by injecting no
// validator.
type Validator interface {
	Validate(ctx context.Context, payload []byte, ref vc.SchemaRef) error
}
