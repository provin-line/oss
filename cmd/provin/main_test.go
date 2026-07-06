package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_UnknownOrMissingCommand(t *testing.T) {
	for name, args := range map[string][]string{
		"no args":       {},
		"group only":    {"owner"},
		"unknown group": {"frobnicate", "now"},
		"unknown op":    {"owner", "destroy"},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background(), args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("want usage error, got %v", err)
			}
		})
	}
}

func TestRun_RequiredFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"owner init no did":       {"owner", "init", "--key", "k.jwk"},
		"owner init no key":       {"owner", "init", "--did", "did:x"},
		"pipeline create no did":  {"pipeline", "create", "--owner-key", "k.jwk"},
		"process create no owner": {"process", "create", "--did", "did:x"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(context.Background(), args, io.Discard); err == nil || !strings.Contains(err.Error(), "required") {
				t.Fatalf("want required-flag error, got %v", err)
			}
		})
	}
}

// A malformed registry URL fails closed before any network I/O (the client
// validates the base URL); PROVIN_REGISTRY feeds the flag default.
func TestRun_RegistryURLValidatedFromEnv(t *testing.T) {
	t.Setenv("PROVIN_REGISTRY", "not-a-url")
	t.Setenv("PROVIN_TOKEN", "tok")
	key := filepath.Join(t.TempDir(), "owner.jwk")
	err := run(context.Background(), []string{"owner", "init", "--did", "did:dplaax:poc.dplaax.dev:org:acme", "--key", key}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "registry URL") {
		t.Fatalf("want registry-URL validation error, got %v", err)
	}
}
