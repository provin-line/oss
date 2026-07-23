package core

import (
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/provin-line/oss/hoconconfig"
)

//go:embed reference.conf
var referenceConf string

func init() {
	hoconconfig.RegisterPackageReference("network/core", referenceConf)
}

// Config keys under the provin.network.core block.
const (
	keyListenAddr           = "provin.network.core.listen-addr"
	keyDataDir              = "provin.network.core.data-dir"
	keyAllowLoopback        = "provin.network.core.dev.allow-loopback"
	keyAllowPrivateNetworks = "provin.network.core.allow-private-networks"
	keyMetricsEnabled       = "provin.network.core.metrics.enabled"
	keyTLSCertFile          = "provin.network.core.tls.cert-file"
	keyTLSKeyFile           = "provin.network.core.tls.key-file"
	keyTLSAllowCleartext    = "provin.network.core.tls.allow-cleartext"
)

// CoreConfig is the server foundation's typed configuration. Every value comes
// from reference.conf (no Go-side defaults); an invalid value is a boot error.
type CoreConfig struct {
	// ListenAddr is the host:port the node binary (cmd/network or
	// cmd/pipeline) serves on.
	ListenAddr string
	// DataDir roots durable YAML state (stores live under it).
	DataDir string
	// AllowLoopback feeds core.WithAllowLoopback — local-dev only.
	AllowLoopback bool
	// AllowPrivateNetworks feeds core.WithAllowPrivateNetworks — the opt-in for
	// deployments whose peers live on RFC 1918 addresses (LAN, VPC, container
	// networks).
	AllowPrivateNetworks bool
	// MetricsEnabled mounts the unauthenticated /metrics endpoint (OpenTelemetry
	// counters, Prometheus exposition) on the serving listener. Default false:
	// the listener is not loopback-bound, and metrics expose loop names and
	// traffic/failure/verdict rates — materially more than /healthz. Enable it
	// where the listener's network is trusted (e.g. the quickstart compose).
	MetricsEnabled bool
	// TLS is the transport-security posture (see TLSConfig and the boot guard
	// in LoadCoreConfig).
	TLS TLSConfig
}

// TLSConfig is the node's transport-security posture. A non-loopback listener
// must choose one of: node-native TLS (CertFile+KeyFile), or an explicit
// AllowCleartext acknowledgement (behind a real terminator, or a trusted dev
// network). LoadCoreConfig fails closed otherwise.
type TLSConfig struct {
	// CertFile / KeyFile enable node-native TLS (h2 over TLS via ALPN). Both or
	// neither — one alone is a boot error. The certificate is loaded ONCE at
	// boot; rotation requires a restart (no hot reload). When set, TLS wins and
	// AllowCleartext is ignored.
	CertFile string
	KeyFile  string
	// AllowCleartext acknowledges serving cleartext h2c on a NON-loopback
	// listener. It is an acknowledgement, not a claim that a terminator exists:
	// production must place a real TLS terminator in front AND make this
	// cleartext backend reachable only from it (loopback / netns / firewall);
	// the guard does not and cannot enforce that isolation.
	AllowCleartext bool
}

// ServesTLS reports whether the node terminates TLS itself.
func (c TLSConfig) ServesTLS() bool { return c.CertFile != "" && c.KeyFile != "" }

// LoadCoreConfig reads and validates the core block from a loaded hocon config.
// It fails closed: an invalid or missing value returns an error naming the key,
// so a misconfigured binary dies at startup rather than on first request.
func LoadCoreConfig(cfg *hoconconfig.Config) (*CoreConfig, error) {
	listenAddr, err := cfg.String(keyListenAddr)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyListenAddr, err)
	}
	if err := validateListenAddr(listenAddr); err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyListenAddr, err)
	}
	dataDir, err := cfg.String(keyDataDir)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyDataDir, err)
	}
	if dataDir == "" {
		return nil, fmt.Errorf("core: config %s: must not be empty", keyDataDir)
	}
	allowLoopback, err := cfg.Bool(keyAllowLoopback)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyAllowLoopback, err)
	}
	allowPrivate, err := cfg.Bool(keyAllowPrivateNetworks)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyAllowPrivateNetworks, err)
	}
	metricsEnabled, err := cfg.Bool(keyMetricsEnabled)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyMetricsEnabled, err)
	}
	certFile, err := cfg.String(keyTLSCertFile)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyTLSCertFile, err)
	}
	keyFile, err := cfg.String(keyTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyTLSKeyFile, err)
	}
	allowCleartext, err := cfg.Bool(keyTLSAllowCleartext)
	if err != nil {
		return nil, fmt.Errorf("core: config %s: %w", keyTLSAllowCleartext, err)
	}
	tls := TLSConfig{CertFile: certFile, KeyFile: keyFile, AllowCleartext: allowCleartext}
	if err := validateTLSPosture(listenAddr, tls); err != nil {
		return nil, err
	}
	return &CoreConfig{
		ListenAddr:           listenAddr,
		DataDir:              dataDir,
		AllowLoopback:        allowLoopback,
		AllowPrivateNetworks: allowPrivate,
		MetricsEnabled:       metricsEnabled,
		TLS:                  tls,
	}, nil
}

// validateTLSPosture is the fail-closed transport-security guard: a non-loopback
// listener may serve cleartext ONLY when the operator has explicitly chosen a
// posture (node-native TLS, or an AllowCleartext acknowledgement). It is
// independent of the outbound SSRF knobs (allow-loopback / allow-private).
func validateTLSPosture(listenAddr string, tls TLSConfig) error {
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		return fmt.Errorf("core: config %s / %s: set both or neither (one alone cannot serve TLS)", keyTLSCertFile, keyTLSKeyFile)
	}
	if tls.ServesTLS() || ListenerIsLoopback(listenAddr) {
		return nil // TLS terminates here, or cleartext stays local
	}
	if !tls.AllowCleartext {
		return fmt.Errorf("core: config %s: a non-loopback listener would serve cleartext h2c (bearer tokens in the clear). Set %s + %s to terminate TLS here, or place a TLS terminator in front, isolate this backend, and set %s = true",
			keyListenAddr, keyTLSCertFile, keyTLSKeyFile, keyTLSAllowCleartext)
	}
	return nil
}

// ListenerIsLoopback reports whether a host:port listen address is GUARANTEED to
// bind only the loopback interface. Only loopback IP LITERALS qualify: 127/8,
// every spelling of ::1, and IPv4-mapped loopback. A hostname — including
// "localhost" — does NOT qualify, even though it usually resolves to loopback:
// http.Server resolves it at bind time, and if /etc/hosts / NSS / DNS maps it to
// a non-loopback address the node would bind a public interface while the guard
// believed it was local (the decision must match the actual bind, not a name
// that could resolve elsewhere). An empty host (":8443") binds all interfaces
// and is NOT loopback. No DNS resolution is performed — the guard fails
// conservatively toward non-loopback, so a hostname listener must choose an
// explicit transport posture.
func ListenerIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	a, perr := netip.ParseAddr(host)
	return perr == nil && a.Unmap().IsLoopback()
}

// validateListenAddr requires a host:port whose port is a decimal in 1..65535,
// so a service-name or out-of-range port fails boot here rather than at Listen.
func validateListenAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("must not be empty")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("not host:port: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port %q is not numeric", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port %d out of range 1..65535", n)
	}
	return nil
}
