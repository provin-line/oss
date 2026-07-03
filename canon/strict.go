package canon

import (
	"bytes"
	"encoding/json" // decoder-hygiene-exempt: this file IS the strict decode path
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
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
//  4. invalid-Unicode rejection — non-UTF-8 document bytes and unpaired
//     surrogate escapes (\uD800–\uDFFF) are errors. encoding/json would
//     silently replace both with U+FFFD, so the decoded value — and every
//     canonical hash derived from it — would diverge from the received
//     bytes (RFC 8785 presumes valid Unicode; fail closed instead).
//
// Direct encoding/json decoding on a protocol path requires a
// `decoder-hygiene-exempt` comment, enforced by `make lint`
// (scripts/check-decoder-hygiene.sh).
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

	if !utf8.Valid(d.data) {
		return errors.New("canon: document is not valid UTF-8")
	}
	if err := checkSurrogateEscapes(d.data); err != nil {
		return err
	}

	// Pass 1: structural walk — duplicate keys and trailing data.
	dec := json.NewDecoder(bytes.NewReader(d.data))
	dec.UseNumber()
	if err := walkValue(dec, nil); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("canon: trailing data after JSON document: %w", err)
		}
		return fmt.Errorf("canon: trailing data after JSON document (next token %v)", tok)
	}

	// Pass 2: decode into v with precision preserved.
	dec2 := json.NewDecoder(bytes.NewReader(d.data))
	dec2.UseNumber()
	return dec2.Decode(v)
}

// checkSurrogateEscapes scans the raw document for \uXXXX escapes inside
// string literals and rejects unpaired surrogates: a high surrogate
// (D800–DBFF) must be immediately followed by an escaped low surrogate
// (DC00–DFFF), and a low surrogate must not appear alone.
func checkSurrogateEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return errors.New("canon: truncated escape sequence")
			}
			if data[i+1] != 'u' {
				i++ // simple escape: skip the escaped character
				continue
			}
			cp, width, err := readUnicodeEscape(data, i)
			if err != nil {
				return err
			}
			switch {
			case cp >= 0xDC00 && cp <= 0xDFFF:
				return fmt.Errorf("canon: unpaired low surrogate escape \\u%04X", cp)
			case cp >= 0xD800 && cp <= 0xDBFF:
				lo, loWidth, err := readUnicodeEscape(data, i+width)
				if err != nil || lo < 0xDC00 || lo > 0xDFFF {
					return fmt.Errorf("canon: unpaired high surrogate escape \\u%04X", cp)
				}
				i += width + loWidth - 1
			default:
				i += width - 1
			}
		}
	}
	return nil
}

// readUnicodeEscape parses a \uXXXX sequence starting at data[i] (which must
// be the backslash) and returns the code unit and the sequence width (6).
func readUnicodeEscape(data []byte, i int) (int, int, error) {
	if i+5 >= len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, 0, errors.New("canon: truncated \\u escape")
	}
	cp, err := strconv.ParseInt(string(data[i+2:i+6]), 16, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("canon: malformed \\u escape: %w", err)
	}
	return int(cp), 6, nil
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
