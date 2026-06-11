# network/pkg/services — Service Packages

One package per network service. Every service follows the same three-layer shape:

```
<service>/
├── handler/            proto ↔ domain conversion + Connect error mapping. No logic.
├── <service>.go        domain service. No proto types. Constructor: New(required..., opts ...Option)
└── store/              persistence interfaces + yamlstore/ implementation. No validation.
```

## Cross-cutting rules

- **Typed errors end-to-end.** Domain errors are sentinel/typed errors mapped to
  Connect codes with `errors.Is` in handlers. String-matching on error messages
  (a predecessor PoC shortcut) is not acceptable here.
- Compile-time conformance assertions (`var _ Iface = (*Impl)(nil)`) in every handler
  and store implementation.
- Fail-fast constructors on security-critical paths: a misconfigured binary must die
  at startup, not on first request.
- Store implementations build filesystem paths only from safety-checked DID/name
  segments (path-traversal guard lives at the boundary, not in callers).

## Services

| Package | Notes |
|---|---|
| `didregistry/` | DID lifecycle; owns the YAML DID/key stores |
| `signer/` | Signing over `keystore`; no store of its own |
| `schemaregistry/` | Immutable schemas; content-addressed version naming |
| `chainmanager/` | Subscriptions, allow-lists, infra operators, L2 wireauth |
| `vcresolver/` | VC store + async batch chain resolution |
