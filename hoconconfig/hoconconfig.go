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
// # Parser choice
//
// The parser is o3co/go.hocon, a full Lightbend-spec implementation. The
// previous dependency (gurkankaymak/hocon) violated the spec in ways that hit
// this repository twice over: a '#' comment containing '//' silently swallowed
// the FOLLOWING line — so comment text changed the parsed document, and three
// reference defaults vanished without a parse error — and Get panicked when a
// path traversed a scalar as an object, which the accessors below had to
// recover from. Both are gone: the accessors read raw values through
// UnmarshalPath, which reports a scalar traversal as a missing key rather than
// panicking, and comments are comments again.
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

	hocon "github.com/o3co/go.hocon"
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

// referenceText returns all registered references, concatenated in
// registration order, as a single HOCON source blob. Shared by Load (which
// folds it into a larger concatenate-and-parse-once string) and LoadFile
// (which parses it as its own layer and merges via WithFallback).
func referenceText() string {
	registryMu.Lock()
	refs := make([]referenceEntry, len(registry))
	copy(refs, registry)
	registryMu.Unlock()

	parts := make([]string, len(refs))
	for i, r := range refs {
		parts[i] = r.content
	}
	return strings.Join(parts, "\n")
}

// Load merges reference + optional config/application.conf (relative to
// appDir) + optional overlay file named by the overlayEnv environment
// variable, parses once, and returns the resolved configuration.
// A named-but-unreadable overlay file is an error (fail loud, never
// silently run without the operator's overlay).
func Load(appDir, overlayEnv string) (*Config, error) {
	var parts []string

	// Layer 1: all registered references, in registration order.
	parts = append(parts, referenceText())

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
// LoadFile
// ─────────────────────────────────────────────────────────────────────────────

// LoadFile loads configuration for a short-lived, per-execution binary from a
// single REQUIRED file named by the fileEnv environment variable (the
// CONFIG_FILE convention). Unlike Load, there is no default location to fall
// back to: an unset or empty-string fileEnv is an error naming the variable,
// because an STL binary has nowhere else to look.
//
// Registered references still layer first, exactly as in Load's layer 1, and
// the file's values take precedence over them. Critically, a relative
// `include "..."` directive inside the file resolves against the FILE's own
// directory rather than the process's current working directory: the file is
// parsed with go.hocon's ParseFileWithOptions, which threads the file's
// directory through to the resolver as the include base dir during the parse
// phase (before any include is expanded) — the same mechanism ParseFile uses,
// so optional includes, `include required(...)`, and nested includes all get
// the library's real semantics rather than a hand-rolled path rewrite.
//
// The reference layer and the file are each parsed with substitution
// resolution deferred (go.hocon's E12 lifecycle), merged with
// fileConfig.WithFallback(refConfig) — the file (receiver) wins, references
// (fallback) fill in what the file doesn't set — and resolved once over the
// merged tree, matching Load's "layer then resolve once" contract.
func LoadFile(fileEnv string) (*Config, error) {
	path := os.Getenv(fileEnv)
	if path == "" {
		return nil, fmt.Errorf("hoconconfig: %s must be set to a config file path", fileEnv)
	}

	deferred := hocon.DefaultParseOptions().WithResolveSubstitutions(false)

	// The file layer: parsed from disk so its directory becomes the include
	// base dir. Read before the reference layer so an unreadable file fails
	// with an unambiguous error regardless of registry state.
	fileConfig, err := hocon.ParseFileWithOptions(path, deferred)
	if err != nil {
		// One message for both failure classes the library folds into ParseError
		// (unreadable file AND HOCON syntax error) — "load", not "reading", so a
		// parse failure is not misreported as I/O; %w carries the specifics.
		return nil, fmt.Errorf("hoconconfig: load config file %q (env %s): %w", path, fileEnv, err)
	}

	// The reference layer, same content Load's layer 1 uses.
	refConfig, err := hocon.ParseStringWithOptions(referenceText(), deferred)
	if err != nil {
		return nil, fmt.Errorf("hoconconfig: parsing references: %w", err)
	}

	merged, err := fileConfig.WithFallback(refConfig).Resolve(hocon.DefaultResolveOptions())
	if err != nil {
		return nil, fmt.Errorf("hoconconfig: resolve error: %w", err)
	}

	return &Config{h: merged}, nil
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
// A path that traverses a scalar (e.g. "a.b" where "a" is a string) is absent,
// not an error: nothing lives there.
func (c *Config) Has(path string) bool { return c.h.Has(path) }

// value reads the raw, resolved value at path as a plain Go value — string,
// int64, float64, bool, []any, or map[string]any. Every accessor below goes
// through it, so type strictness is decided HERE rather than delegated to the
// library's typed getters, which coerce (GetString on an int yields "3"). The
// facade's contract is that a type mismatch is an error, not a conversion:
// config that says one thing and means another is how a deployment surprises
// someone at 3am.
func (c *Config) value(path string) (any, error) {
	var v any
	if err := c.h.UnmarshalPath(path, &v); err == nil {
		return v, nil
	}
	// The library reports "key not found" both for a path nobody set and for a
	// path that runs THROUGH a scalar ("a.b.c" where "a.b" is a string). Those
	// are different problems and callers act on them differently: absent means
	// "use the default", while a scalar in the way means the config says
	// something the reader cannot mean — `tls = "yes"` instead of
	// `tls { cert-file = ... }`. Collapsing the second into ErrMissingKey would
	// let a caller's "absent, use default" branch swallow a misconfiguration.
	if ancestor, ok := c.scalarAncestor(path); ok {
		return nil, fmt.Errorf("%w: %q traverses %q, which is not an object", ErrTypeMismatch, path, ancestor)
	}
	return nil, fmt.Errorf("%w: %q", ErrMissingKey, path)
}

// scalarAncestor reports the longest strict prefix of path that exists but is
// not an object — the thing standing between the caller and their key.
func (c *Config) scalarAncestor(path string) (string, bool) {
	segments := strings.Split(path, ".")
	for i := len(segments) - 1; i > 0; i-- {
		prefix := strings.Join(segments[:i], ".")
		if !c.h.Has(prefix) {
			continue
		}
		if _, err := c.h.GetConfigE(prefix); err != nil {
			return prefix, true
		}
		// The nearest existing ancestor is an object, so the key is simply absent.
		return "", false
	}
	return "", false
}

// String returns the value at path as a string. Returns ErrMissingKey
// (wrapped) if the key is absent and ErrTypeMismatch (wrapped) if the value is
// not a HOCON string. A number is NOT coerced: "3" and 3 are different config,
// and a caller asking for a string wants the one that was written as one.
func (c *Config) String(path string) (string, error) {
	v, err := c.value(path)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string (got %T)", ErrTypeMismatch, path, v)
	}
	return s, nil
}

// Int returns the value at path as an int. Returns ErrMissingKey (wrapped) if
// the key is absent and ErrTypeMismatch (wrapped) if the value is not a HOCON
// integer — a float is a mismatch, not a truncation.
func (c *Config) Int(path string) (int, error) {
	v, err := c.value(path)
	if err != nil {
		return 0, err
	}
	switch n := v.(type) {
	case int64:
		return int(n), nil
	case float64:
		return 0, fmt.Errorf("%w: %q is a float, not an integer", ErrTypeMismatch, path)
	default:
		return 0, fmt.Errorf("%w: %q is not a number (got %T)", ErrTypeMismatch, path, v)
	}
}

// Bool returns the value at path as a bool. Returns ErrMissingKey (wrapped) if
// the key is absent and ErrTypeMismatch (wrapped) if the value is not a HOCON
// boolean.
func (c *Config) Bool(path string) (bool, error) {
	v, err := c.value(path)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%w: %q is not a boolean (got %T)", ErrTypeMismatch, path, v)
	}
	return b, nil
}

// Duration returns the value at path as a time.Duration. HOCON duration
// literals ("250 ms", "5 s") are strings on the wire, so this asks the library
// to interpret one: the raw value must be a string, and it must parse as a
// duration. Returns ErrMissingKey (wrapped) if the key is absent and
// ErrTypeMismatch (wrapped) otherwise.
func (c *Config) Duration(path string) (time.Duration, error) {
	v, err := c.value(path)
	if err != nil {
		return 0, err
	}
	if _, ok := v.(string); !ok {
		return 0, fmt.Errorf("%w: %q is not a duration (got %T)", ErrTypeMismatch, path, v)
	}
	d, derr := c.h.GetDurationE(path)
	if derr != nil {
		return 0, fmt.Errorf("%w: %q is not a duration (%v)", ErrTypeMismatch, path, derr)
	}
	return d, nil
}

// StringList returns the value at path as []string. Returns ErrMissingKey
// (wrapped) if the key is absent and ErrTypeMismatch (wrapped) if the value is
// not a HOCON array or if any element is not a HOCON string. Elements are NOT
// coerced: a list of numbers is a mismatch, not a list of numerals.
func (c *Config) StringList(path string) ([]string, error) {
	v, err := c.value(path)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an array (got %T)", ErrTypeMismatch, path, v)
	}
	out := make([]string, len(arr))
	for i, elem := range arr {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %q element %d is not a string (got %T)", ErrTypeMismatch, path, i, elem)
		}
		out[i] = s
	}
	return out, nil
}

// StringMap returns the object at path as a key -> string-value map. It reads
// the object's entries directly (no per-key path round-trip), so keys
// containing dots — quoted HOCON keys like "mfg.poc.dplaax.dev" — are returned
// verbatim; the path parser would otherwise split them. Returns ErrMissingKey
// if path is absent, and ErrTypeMismatch if path is not an object or any value
// is not a string.
func (c *Config) StringMap(path string) (map[string]string, error) {
	v, err := c.value(path)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an object (got %T)", ErrTypeMismatch, path, v)
	}
	m := make(map[string]string, len(obj))
	for k, val := range obj {
		sv, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %q key %q is not a string (got %T)", ErrTypeMismatch, path, k, val)
		}
		m[k] = sv
	}
	return m, nil
}

// Keys returns the field names of the HOCON object at path, sorted for
// deterministic iteration. Returns ErrMissingKey (wrapped) if the key is absent
// and ErrTypeMismatch (wrapped) if the value is not an object. This is the
// accessor for object-keyed config blocks (e.g. a set of named service
// endpoints): enumerate the keys here, then read each entry's fields with the
// scalar accessors at "path.<key>.<field>".
func (c *Config) Keys(path string) ([]string, error) {
	v, err := c.value(path)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an object (got %T)", ErrTypeMismatch, path, v)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
