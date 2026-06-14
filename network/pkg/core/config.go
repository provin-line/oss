package core

import (
	_ "embed"
	"fmt"
	"net"
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
	keyListenAddr    = "provin.network.core.listen-addr"
	keyDataDir       = "provin.network.core.data-dir"
	keyAllowLoopback = "provin.network.core.dev.allow-loopback"
)

// CoreConfig is the server foundation's typed configuration. Every value comes
// from reference.conf (no Go-side defaults); an invalid value is a boot error.
type CoreConfig struct {
	// ListenAddr is the host:port the standalone binary serves on.
	ListenAddr string
	// DataDir roots durable YAML state (stores live under it).
	DataDir string
	// AllowLoopback feeds core.WithAllowLoopback — local-dev only.
	AllowLoopback bool
}

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
	return &CoreConfig{
		ListenAddr:    listenAddr,
		DataDir:       dataDir,
		AllowLoopback: allowLoopback,
	}, nil
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
