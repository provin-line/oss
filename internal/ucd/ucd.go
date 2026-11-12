// Package ucd holds the tables of the Unicode Character Database the module
// reads characters by, of one Unicode version (Version), whatever version the
// Go toolchain's unicode package carries. So what the module decides by a
// character's general category or property is the same on every toolchain.
//
// The tables are generated from the UCD files of that version themselves,
// refused unless their SHA-256 is the pinned one (internal/ucdgen):
//
//	go generate ./internal/ucd
package ucd

//go:generate go run ./internal/ucdgen -o tables.go

import "unicode"

// Category is the table of the general category whose short name is name, as
// unicode.Categories names them (Lu, L, LC, Cn ...), or nil for any other
// name. Its ranges are in order and have stride 1; no two overlap or touch,
// but where one is split at U+FFFF between R16 and R32. The tables are
// shared: a caller does not change them.
func Category(name string) *unicode.RangeTable { return categories[name] }

// Property is the table of the binary property name, or nil: the property
// here is White_Space. Its ranges are as a Category's, and it is shared as
// they are.
func Property(name string) *unicode.RangeTable { return properties[name] }
