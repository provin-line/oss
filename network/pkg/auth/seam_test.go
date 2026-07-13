package auth_test

import (
	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/network/pkg/auth"
)

// The exported auth seam is expressed in the package-owned Verifier interface:
// the frozen public surface carries no upstream (o3co) type identity, so the
// enforcement library can be swapped without breaking auth's signatures
// (P0-4 follow-up, F1). Function-value assignment requires identical types,
// so these pin the exact exported signatures at compile time — repointing
// either signature back at an upstream-owned type breaks this file.
var (
	_ func(*auth.AuthConfig) (auth.Verifier, error) = auth.NewVerifier
	_ func(auth.Verifier) []connect.Interceptor     = auth.Interceptors
)

// The o3co enforcement endpoints satisfy the package-owned seam structurally —
// swapping the exported type identity costs implementations nothing.
// (Behavioral coverage of the backends lives in auth_test.go.)
var _ auth.Verifier = endpoint.NewStaticEndpoint(nil)
