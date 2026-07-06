// Package hoconconfig implements a three-layer HOCON configuration loader.
//
// # Layer merging strategy
//
// All registered reference texts are concatenated in registration order,
// followed by the application file (if present), followed by the overlay file
// (if present). The concatenated text is parsed ONCE as a single HOCON
// document. HOCON's own rules — later keys override earlier ones and
// substitutions (${...}) resolve over the whole document — provide exactly
// the "substitutions resolve once after all layers merge" semantics required
// by the contract.
//
// # Hard rule: no Go-side defaults
//
// Every default lives in a reference.conf. Every accessor returns an error for
// a missing key or a type mismatch; no accessor silently returns a zero value.
package hoconconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gurkankaymak/hocon"
)

// ─────────────────────────────────────────────────────────────────────────────
// Sentinel errors
// ─────────────────────────────────────────────────────────────────────────────

// ErrMissingKey is returned (wrapped with the offending path) when a requested
// configuration key is absent from the merged document.
var ErrMissingKey = errors.New("missing configuration key")

// ErrTypeMismatch is returned (wrapped with the offending path) when the value
// at a key exists but cannot be interpreted as the requested Go type.
var ErrTypeMismatch = errors.New("configuration type mismatch")

// ErrDuplicateReference is the panic value (wrapped with the package name) when
// RegisterPackageReference is called twice with the same name. Duplicate names
// are a wiring bug caught at init time.
var ErrDuplicateReference = errors.New("duplicate reference registration")

// ─────────────────────────────────────────────────────────────────────────────
// Package-level reference registry
// ─────────────────────────────────────────────────────────────────────────────

type referenceEntry struct {
	name    string
	content string
}

var (
	registryMu    sync.Mutex
	registry      []referenceEntry
	registryNames = make(map[string]struct{})
)

// RegisterPackageReference registers a package's embedded reference.conf.
// Called from init(); name identifies the package for diagnostics and
// duplicate detection (registering the same name twice panics — a wiring
// bug caught at init time).
func RegisterPackageReference(name, content string) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registryNames[name]; exists {
		panic(fmt.Errorf("%w: %q", ErrDuplicateReference, name))
	}
	registryNames[name] = struct{}{}
	registry = append(registry, referenceEntry{name: name, content: content})
}

// ─────────────────────────────────────────────────────────────────────────────
// Load
// ─────────────────────────────────────────────────────────────────────────────

// Load merges reference + optional config/application.conf (relative to
// appDir) + optional overlay file named by the overlayEnv environment
// variable, parses once, and returns the resolved configuration.
// A named-but-unreadable overlay file is an error (fail loud, never
// silently run without the operator's overlay).
func Load(appDir, overlayEnv string) (*Config, error) {
	var parts []string

	// Layer 1: all registered references, in registration order.
	registryMu.Lock()
	refs := make([]referenceEntry, len(registry))
	copy(refs, registry)
	registryMu.Unlock()

	for _, r := range refs {
		parts = append(parts, r.content)
	}

	// Layer 2: optional config/application.conf.
	appConf := filepath.Join(appDir, "config", "application.conf")
	appBytes, err := os.ReadFile(appConf)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("hoconconfig: reading application.conf: %w", err)
	}
	if err == nil {
		parts = append(parts, string(appBytes))
	}

	// Layer 3: optional overlay file named by overlayEnv.
	if overlayEnv != "" {
		overlayPath := os.Getenv(overlayEnv)
		if overlayPath != "" {
			overlayBytes, err := os.ReadFile(overlayPath)
			if err != nil {
				return nil, fmt.Errorf("hoconconfig: reading overlay %q (env %s): %w", overlayPath, overlayEnv, err)
			}
			parts = append(parts, string(overlayBytes))
		}
	}

	// Concatenate all layers and parse once.
	merged := strings.Join(parts, "\n")
	hc, err := hocon.ParseString(merged)
	if err != nil {
		return nil, fmt.Errorf("hoconconfig: parse error: %w", err)
	}

	return &Config{h: hc}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

// Config holds a parsed, fully-resolved HOCON configuration document.
type Config struct {
	h *hocon.Config
}

// Has reports whether path exists in the configuration. Use this for optional
// blocks such as schema references.
//
// Discovery: the HOCON library panics when Get traverses a scalar (String,
// Int, …) as if it were an Object (e.g. path "a.b" where "a" is a string).
// We recover from that panic and treat it as "key absent" — the same contract
// a caller expects from Has on a non-existent nested path.
func (c *Config) Has(path string) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	return c.h.Get(path) != nil
}

// String returns the value at path as a string. Returns ErrMissingKey (wrapped)
// if the key is absent and ErrTypeMismatch (wrapped) if the value is not a
// string type.
//
// Implementation note: the parser strips surrounding double-quote characters
// from quoted HOCON strings at parse time, so hocon.String holds the bare
// value. We extract it via a direct type assertion. We do NOT call
// hocon.Config.GetString — that calls Value.String(), which re-wraps values
// containing special characters (space, colon, slash, …) in literal quotes,
// corrupting round-trip fidelity.
//
// Library defect: Get panics when traversing a scalar value as an Object
// (e.g. path "a.b.c" where "a.b" resolves to a string). We recover from
// that panic and return ErrTypeMismatch — the caller's expectation on any
// shape error.
func (c *Config) String(path string) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = ""
			err = fmt.Errorf("%w: scalar parent at %q (library panic: %v)", ErrTypeMismatch, path, r)
		}
	}()
	v := c.h.Get(path)
	if v == nil {
		return "", fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	s, ok := v.(hocon.String)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string (got %T)", ErrTypeMismatch, path, v)
	}
	return string(s), nil
}

// Int returns the value at path as an int. Returns ErrMissingKey (wrapped) if
// the key is absent and ErrTypeMismatch (wrapped) if the value is not a HOCON
// integer (strings that are not pure numeric literals are rejected — the
// library would otherwise panic).
func (c *Config) Int(path string) (int, error) {
	v := c.h.Get(path)
	if v == nil {
		return 0, fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	if v.Type() != hocon.NumberType {
		return 0, fmt.Errorf("%w: %q is not a number (got %T)", ErrTypeMismatch, path, v)
	}
	// Only hocon.Int is acceptable for Int(); Float32/Float64 are also NumberType
	// but semantically different. Use a type switch for precision.
	switch v.(type) {
	case hocon.Int:
		return c.h.GetInt(path), nil
	default:
		return 0, fmt.Errorf("%w: %q is a float, not an integer", ErrTypeMismatch, path)
	}
}

// Bool returns the value at path as a bool. Returns ErrMissingKey (wrapped) if
// the key is absent and ErrTypeMismatch (wrapped) if the value is not a HOCON
// boolean.
func (c *Config) Bool(path string) (bool, error) {
	v := c.h.Get(path)
	if v == nil {
		return false, fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	switch v.(type) {
	case hocon.Boolean:
		return c.h.GetBoolean(path), nil
	default:
		return false, fmt.Errorf("%w: %q is not a boolean (got %T)", ErrTypeMismatch, path, v)
	}
}

// Duration returns the value at path as a time.Duration. The HOCON library
// parses duration literals (e.g. "250 ms", "5 s") as a dedicated Duration
// type. Returns ErrMissingKey (wrapped) if the key is absent and
// ErrTypeMismatch (wrapped) if the value is not a HOCON duration.
//
// Discovery: hocon.Duration has Type() == StringType (same as hocon.String),
// so type-checking requires a concrete type assertion, not a Type() comparison.
func (c *Config) Duration(path string) (time.Duration, error) {
	v := c.h.Get(path)
	if v == nil {
		return 0, fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	switch v.(type) {
	case hocon.Duration:
		return c.h.GetDuration(path), nil
	default:
		return 0, fmt.Errorf("%w: %q is not a duration (got %T)", ErrTypeMismatch, path, v)
	}
}

// StringList returns the value at path as []string. Returns ErrMissingKey
// (wrapped) if the key is absent and ErrTypeMismatch (wrapped) if the value
// is not a HOCON array or if any element is not a HOCON string.
//
// Implementation note: we iterate the underlying hocon.Array and type-assert
// each element as hocon.String. This rejects non-string elements (int, bool,
// …) with ErrTypeMismatch — GetStringSlice silently coerces them. The parser
// stores hocon.String with quotes already stripped (same as String()), so no
// additional trimming is needed. We do NOT call Value.String() on elements —
// that re-wraps values containing special characters, corrupting round-trip
// fidelity.
func (c *Config) StringList(path string) ([]string, error) {
	v := c.h.Get(path)
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	arr, ok := v.(hocon.Array)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an array (got %T)", ErrTypeMismatch, path, v)
	}
	out := make([]string, len(arr))
	for i, elem := range arr {
		s, ok := elem.(hocon.String)
		if !ok {
			return nil, fmt.Errorf("%w: %q element %d is not a string (got %T)", ErrTypeMismatch, path, i, elem)
		}
		out[i] = string(s)
	}
	return out, nil
}

// StringMap returns the object at path as a key -> string-value map. It reads
// the object's entries directly (no per-key path round-trip), so keys
// containing dots — quoted HOCON keys like "mfg.dplaax.dev" — are returned
// verbatim; the path parser would otherwise split them. Returns ErrMissingKey
// if path is absent, and ErrTypeMismatch if path is not an object or any value
// is not a string.
//
// Like String, a scalar parent (a non-object at path) surfaces as
// ErrTypeMismatch rather than a library panic.
func (c *Config) StringMap(path string) (m map[string]string, err error) {
	defer func() {
		if r := recover(); r != nil {
			m = nil
			err = fmt.Errorf("%w: scalar parent at %q (library panic: %v)", ErrTypeMismatch, path, r)
		}
	}()
	v := c.h.Get(path)
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	obj, ok := v.(hocon.Object)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an object (got %T)", ErrTypeMismatch, path, v)
	}
	m = make(map[string]string, len(obj))
	for k, val := range obj {
		sv, ok := val.(hocon.String)
		if !ok {
			return nil, fmt.Errorf("%w: %q key %q is not a string (got %T)", ErrTypeMismatch, path, k, val)
		}
		m[k] = string(sv)
	}
	return m, nil
}

// Keys returns the field names of the HOCON object at path, sorted for
// deterministic iteration. Returns ErrMissingKey (wrapped) if the key is absent
// and ErrTypeMismatch (wrapped) if the value is not an object. This is the
// accessor for object-keyed config blocks (e.g. a set of named service
// endpoints): enumerate the keys here, then read each entry's fields with the
// scalar accessors at "path.<key>.<field>".
//
// Like String, a scalar parent (a non-object at path) surfaces as
// ErrTypeMismatch rather than a library panic.
func (c *Config) Keys(path string) (keys []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			keys = nil
			err = fmt.Errorf("%w: scalar parent at %q (library panic: %v)", ErrTypeMismatch, path, r)
		}
	}()
	v := c.h.Get(path)
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrMissingKey, path)
	}
	obj, ok := v.(hocon.Object)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an object (got %T)", ErrTypeMismatch, path, v)
	}
	keys = make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
