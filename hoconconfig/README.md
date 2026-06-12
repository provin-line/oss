# hoconconfig — Three-Layer HOCON Configuration

Layered configuration loader used by every binary in this repository.

## Layers (lowest to highest precedence)

1. **Reference** — package defaults, registered at `init()` via embedded
   `reference.conf` files (`go:embed` + `RegisterPackageReference`).
2. **Application** — operator-shipped `config/application.conf` (optional).
3. **Overlay** — file pointed to by an environment variable (optional;
   `CONFIG_OVERLAY` for network, `CONFIG_FILE` for process binaries).

Substitutions (`${...}`) resolve once after all layers merge, so any layer may
reference keys defined in a lower one.

## Hard rule: no Go-side defaults

Every default lives in a `reference.conf`. Go code never silently substitutes a
fallback value for a missing key; binaries validate operator overrides at startup
and fail loudly on invalid values (e.g. non-positive intervals).

## API

```go
// RegisterPackageReference registers a package's embedded reference.conf
// at init() time. Panics (wrapping ErrDuplicateReference) on duplicate names.
func RegisterPackageReference(name, content string)

// Load concatenates all registered references + optional config/application.conf
// (under appDir) + optional overlay file (path from overlayEnv env var), then
// parses once. A set-but-unreadable overlay is an error; an absent env var is OK.
func Load(appDir, overlayEnv string) (*Config, error)

func (c *Config) String(path string) (string, error)
func (c *Config) Int(path string) (int, error)
func (c *Config) Bool(path string) (bool, error)
func (c *Config) Duration(path string) (time.Duration, error)  // "250 ms", "5 s", …
func (c *Config) StringList(path string) ([]string, error)
func (c *Config) Has(path string) bool  // for optional blocks

// Sentinel errors (all returned wrapped with the offending path):
var ErrMissingKey, ErrTypeMismatch, ErrDuplicateReference error
```

Merge strategy: all layers are concatenated as plain text and parsed **once**.
HOCON gives later keys precedence and resolves substitutions over the whole
document — substitutions in any layer may reference keys defined in a lower one.

## Known limitations

**`null` values**: `key = null` is present in the document — `Has` returns `true`.
Typed accessors (`String`, `Int`, …) return `ErrTypeMismatch` because `null` is
not a string, integer, etc.

**Substitution self-reference**: real HOCON supports self-referencing substitutions
(`x = ${x}"-suffix"`) to extend a lower-layer value in a higher layer. This
library raises a substitution-cycle error for that pattern. Use a distinct key
name instead of self-referencing when layering values.
