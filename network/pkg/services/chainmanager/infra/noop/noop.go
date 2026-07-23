// Package noop is a debug/test-only infra.Operator: it records nothing and wires
// no real transport. It exists so the chainmanager peer server can be exercised
// end-to-end without a live pub-sub backend.
//
// It MUST NOT be wired into a production build — neither production binary
// (cmd/network, cmd/pipeline) imports this package (the ChainPeerService prod
// mount uses the nats operator, a later slice). All operations are
// idempotent, which the domain's ref-counted export lifecycle relies on
// (slice-11 D-p8).
package noop

import "github.com/provin-line/oss/network/pkg/services/chainmanager/infra"

// Operator is the no-op transport operator.
type Operator struct{}

var _ infra.Operator = (*Operator)(nil)

// New returns a no-op Operator.
func New() *Operator { return &Operator{} }

// PublishType names this operator's (absent) transport.
func (*Operator) PublishType() string { return "noop" }

// AddExport returns deterministic, transport-free connection parameters. It is
// idempotent: repeated calls for the same subject return the same info, nil.
func (*Operator) AddExport(outputSubject string) (map[string]string, error) {
	return map[string]string{"subject": outputSubject, "publishType": "noop"}, nil
}

// RemoveExport is a no-op.
func (*Operator) RemoveExport(string) error { return nil }

// AddImport is a no-op.
func (*Operator) AddImport(remoteSubject, remoteAccountKey, localSubject string) error { return nil }

// RemoveImport is a no-op.
func (*Operator) RemoveImport(remoteSubject, remoteAccountKey string) error { return nil }
