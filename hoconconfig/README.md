# packages/hoconconfig — Three-Layer HOCON Configuration

Layered configuration loader used by every binary in this repository.

## Layers (lowest to highest precedence)

1. **Reference** — package defaults, registered at `init()` via embedded
   `reference.conf` files (`go:embed` + `RegisterPackageReference`).
2. **Application** — operator-shipped `config/application.conf` (optional).
3. **Overlay** — file pointed to by an environment variable (optional;
   `CONFIG_OVERLAY` for network, `CONFIG_FILE` for component binaries).

Substitutions (`${...}`) resolve once after all layers merge, so any layer may
reference keys defined in a lower one.

## Hard rule: no Go-side defaults

Every default lives in a `reference.conf`. Go code never silently substitutes a
fallback value for a missing key; binaries validate operator overrides at startup
and fail loudly on invalid values (e.g. non-positive intervals).
