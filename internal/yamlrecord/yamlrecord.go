// Package yamlrecord encodes the records the node's YAML stores keep, so that
// a record reads back as it was written. YAML reads some strings back as
// others (a tab dropped, a CR read as LF, invalid UTF-8 as U+FFFD, ".nan" as
// "NaN", a key "? a" as "a"), some not at all (a key "<<" or one holding a
// newline), and goccy/go-yaml's writer itself drops trailing spaces before a
// newline in a block. A record stored that way would change when read, or
// fail every read of the store that meets it.
package yamlrecord

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/goccy/go-yaml"
)

// ErrUnfaithful refuses a record whose YAML would not read back as written.
var ErrUnfaithful = errors.New("yamlrecord: the record would not read back as written")

// Encode writes r as YAML, refusing it with ErrUnfaithful unless the YAML reads
// back as r. The two are compared in goccy/go-yaml's JSON form, which quotes
// every string and so loses none. A time is compared as RFC 3339 writes it, so
// a record's times should be in UTC (an offset with seconds is written in
// minutes).
func Encode[T any](r *T) ([]byte, error) {
	data, err := yaml.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("yamlrecord: marshal: %w", err)
	}
	back := new(T)
	if err := yaml.Unmarshal(data, back); err != nil {
		// The parser's error quotes the record's text; it is not repeated.
		return nil, refuse(r)
	}
	want, err := yaml.MarshalWithOptions(r, yaml.JSON())
	if err != nil {
		return nil, fmt.Errorf("yamlrecord: marshal: %w", err)
	}
	got, err := yaml.MarshalWithOptions(back, yaml.JSON())
	if err != nil || !bytes.Equal(got, want) {
		return nil, refuse(r)
	}
	return data, nil
}

// refuse logs a refusal and returns ErrUnfaithful. The stores' callers hold
// what they store to forms that read back as written, so a refusal means a
// check before the store let a value through: the log names the record's type,
// not its content.
func refuse(r any) error {
	log.Printf("yamlrecord: refused a %T that would not read back as written (a value passed the checks before the store)", r)
	return ErrUnfaithful
}

// Bytes is a byte string written as one base64 string. YAML's default for
// []byte, a sequence of one integer per byte, costs about 1.3 KB of memory to
// read per byte. A record an earlier version wrote that way still reads, at
// that cost: the YAML parser reads the sequence before Bytes sees it.
type Bytes []byte

// MarshalYAML implements yaml.InterfaceMarshaler.
func (b Bytes) MarshalYAML() (any, error) {
	return base64.StdEncoding.EncodeToString(b), nil
}

// UnmarshalYAML implements yaml.InterfaceUnmarshaler.
func (b *Bytes) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		v, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			return fmt.Errorf("yamlrecord: bytes: %w", err)
		}
		*b = v
		return nil
	}
	var sequence []byte
	if err := unmarshal(&sequence); err != nil {
		return err
	}
	*b = sequence
	return nil
}
