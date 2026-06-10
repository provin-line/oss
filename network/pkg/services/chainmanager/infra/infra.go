// Package infra defines the transport-level operator abstraction for chain
// connections — the Hub swap point for the network-side pub-sub backend.
// Implementations: nats/ (account-claims JWT management), noop/ (debug only;
// must be impossible to wire in non-debug builds).
package infra

// Operator wires and unwires cross-account transport for chain
// subscriptions. The publisher side exports its output subject; the
// subscriber side imports it under a local subject.
type Operator interface {
	// AddExport exposes outputSubject to subscribers and returns
	// transport-specific connection parameters for the subscriber side.
	AddExport(outputSubject string) (connectionInfo map[string]string, err error)
	RemoveExport(outputSubject string) error

	// AddImport maps a remote subject (identified by the remote account key)
	// onto localSubject.
	AddImport(remoteSubject, remoteAccountKey, localSubject string) error
	RemoveImport(remoteSubject, remoteAccountKey string) error

	// PublishType names the transport this operator manages (e.g. "nats").
	PublishType() string
}
