package canon

import (
	"bytes"
	"encoding/json" // decoder-hygiene-exempt: this file IS the strict decode path
	"errors"
	"fmt"
	"io"
	"strconv"
)

// DuplicateKeyError reports a duplicate object key encountered during strict
// decoding, with the path to the offending object for diagnostics.
type DuplicateKeyError struct {
	Key  string
	Path []string
}

func (e *DuplicateKeyError) Error() string {
	return fmt.Sprintf("duplicate JSON key %q at %v", e.Key, e.Path)
}

// StrictDecoder is the only JSON decode path permitted on protocol
// boundaries. It enforces, in order:
//
//  1. duplicate-key rejection (RFC 8785 §3.2.5) — returns *DuplicateKeyError
//  2. trailing-data rejection — a document must be exactly one JSON value
//  3. numeric precision preservation — numbers decode as json.Number so
//     integers above 2^53 survive round-trips
//
// Direct encoding/json decoding on a protocol path requires a
// `decoder-hygiene-exempt` comment and is checked by CI.
type StrictDecoder struct {
	data []byte
	used bool
}

// NewStrictDecoder returns a single-shot decoder over data.
func NewStrictDecoder(data []byte) *StrictDecoder { return &StrictDecoder{data: data} }

// Decode decodes the document into v under the strict rules. A second call
// returns io.EOF.
func (d *StrictDecoder) Decode(v any) error {
	if d.used {
		return io.EOF
	}
	d.used = true

	// Pass 1: structural walk — duplicate keys and trailing data.
	dec := json.NewDecoder(bytes.NewReader(d.data))
	dec.UseNumber()
	if err := walkValue(dec, nil); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("canon: trailing data after JSON document (next token %v, err %v)", tok, err)
	}

	// Pass 2: decode into v with precision preserved.
	dec2 := json.NewDecoder(bytes.NewReader(d.data))
	dec2.UseNumber()
	return dec2.Decode(v)
}

func walkValue(dec *json.Decoder, path []string) error {
	tok, err := dec.Token()
	if err == io.EOF {
		return errors.New("canon: empty JSON document")
	}
	if err != nil {
		return err
	}
	return walkFrom(dec, tok, path)
}

func walkFrom(dec *json.Decoder, tok json.Token, path []string) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("canon: non-string object key %v", keyTok)
			}
			if seen[key] {
				return &DuplicateKeyError{Key: key, Path: append([]string(nil), path...)}
			}
			seen[key] = true
			if err := walkValue(dec, append(path, key)); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return err
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, append(path, strconv.Itoa(i))); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return err
		}
	}
	return nil
}
