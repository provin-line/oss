package canon

import (
	"bytes"
	"encoding"
	"encoding/json" // decoder-hygiene-exempt: this file IS the strict decode path
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/excerpt"
)

// DuplicateKeyError reports a duplicate object key encountered during strict
// decoding, with the path to the offending object for diagnostics. Key is the
// later key. Other, when not empty, is an earlier key of the same object that
// Key equals only as encoding/json folds names (case, and the Kelvin and long-s
// signs), or the struct field Key matches only that way: encoding/json would
// read both keys into one struct field, or Key into a field another reader does
// not see. The fields hold the keys and the path verbatim; Error writes each
// key, and the path, within 128 bytes: whole when it fits, or else its head
// and its length, "… (N bytes)", with what is not UTF-8 written as U+FFFD.
type DuplicateKeyError struct {
	Key   string
	Other string
	Path  []string
}

func (e *DuplicateKeyError) Error() string {
	key := excerpt.Quoted(e.Key, quotedLimit)
	at, _ := excerpt.Of(fmt.Sprint(e.Path), quotedLimit)
	if e.Other != "" {
		return fmt.Sprintf("JSON key %s at %s differs from %s only in case, as encoding/json folds names", key, at, excerpt.Quoted(e.Other, quotedLimit))
	}
	return fmt.Sprintf("duplicate JSON key %s at %s", key, at)
}

// StrictDecoder is the only JSON decode path permitted on protocol
// boundaries. It enforces, in order:
//
//  1. duplicate-key rejection (RFC 8785 §3.2.5) — returns *DuplicateKeyError;
//     so do two keys of one object that encoding/json folds to the same name,
//     and, where v holds a struct, a key that matches one of its fields only
//     that way (encoding/json would read it into the field; a reader that
//     tells case apart would not). Fields are resolved by encoding/json's
//     rules, through pointers and through an interface already holding a
//     pointer; a type that decodes itself (json.Unmarshaler,
//     encoding.TextUnmarshaler, as encoding/json finds one) is outside this
//     check: its own decoding governs what it reads
//  2. trailing-data rejection — a document must be exactly one JSON value
//  3. numeric precision preservation — numbers decode as json.Number so
//     integers above 2^53 survive round-trips
//  4. invalid-Unicode rejection — non-UTF-8 document bytes and unpaired
//     surrogate escapes (\uD800–\uDFFF) are errors. encoding/json would
//     silently replace both with U+FFFD, so the decoded value — and every
//     canonical hash derived from it — would diverge from the received
//     bytes (RFC 8785 presumes valid Unicode; fail closed instead).
//
// A document nested deeper than 10000 arrays and objects is refused, as
// encoding/json refuses it. The work is linear in the length of the document,
// whatever its depth, so it can decode input not yet authenticated.
//
// A decode target reached through more than 64 pointers and interfaces, as
// one that holds itself is, is refused wherever the document gives it a
// value, null included, before anything is decoded: encoding/json would
// follow it without end.
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
//
// The text of an error it returns is valid UTF-8 within 1024 bytes, whatever
// the document. Its own errors name what they quote within 128 bytes; an
// error whose text would be longer or not UTF-8 (encoding/json's, or a
// type's own decoding's, which write a number's literal or a time's text) is
// returned wrapped, its text cut as package excerpt cuts it. errors.Is and
// errors.As find the error it wraps; a type assertion or == does not.
func (d *StrictDecoder) Decode(v any) error {
	return excerpt.OfError(d.decode(v), decodeErrorLimit)
}

func (d *StrictDecoder) decode(v any) error {
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
	if err := walkValue(dec, new([]string), destOf(reflect.ValueOf(v))); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("canon: trailing data after JSON document: %w", err)
		}
		next, _ := excerpt.Of(fmt.Sprint(tok), quotedLimit)
		return fmt.Errorf("canon: trailing data after JSON document (next token %s)", next)
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

// maxNesting is the deepest nesting of arrays and objects the walk enters, as
// deep as encoding/json decodes in the pass after it. The walk needs its own
// bound: json.Decoder.Token does not limit depth in every Go release, and the
// walk recurses once per level, so a megabyte of "[" would exhaust the
// goroutine stack, a fatal error no recover catches.
const maxNesting = 10000

// walkValue walks the next value. path is the one path of the whole walk: a
// member or index is pushed before its value is walked and popped after, and
// only an error copies it, so the walk is linear in the document.
// d is where the value decodes, as far as the walk follows it (none past an
// interface holding no pointer, or a type that decodes itself).
func walkValue(dec *json.Decoder, path *[]string, d dest) error {
	tok, err := dec.Token()
	if err == io.EOF {
		return errors.New("canon: empty JSON document")
	}
	if err != nil {
		return err
	}
	return walkFrom(dec, tok, path, d)
}

// walkChild walks the value of member or index step under path.
func walkChild(dec *json.Decoder, path *[]string, step string, d dest) error {
	*path = append(*path, step)
	err := walkValue(dec, path, d)
	*path = (*path)[:len(*path)-1]
	return err
}

func walkFrom(dec *json.Decoder, tok json.Token, path *[]string, d dest) error {
	if d.unbounded {
		at, _ := excerpt.Of(fmt.Sprint(*path), quotedLimit)
		return fmt.Errorf("canon: decode target at %s is reached through more than %d pointers and interfaces (as a target that holds itself is)", at, maxIndirections)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	if len(*path) >= maxNesting {
		return fmt.Errorf("canon: JSON document nested deeper than %d", maxNesting)
	}
	switch delim {
	case '{':
		seen := make(map[string]string) // folded name → the key that had it
		fields := structFields(d.t)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("canon: non-string object key %v", keyTok)
			}
			folded := foldName(key)
			if earlier, dup := seen[folded]; dup {
				e := &DuplicateKeyError{Key: key, Path: append([]string(nil), *path...)}
				if earlier != key {
					e.Other = earlier
				}
				return e
			}
			seen[folded] = key
			child := d.elem()
			if fields != nil {
				f, exact := fields.exact[key]
				if !exact {
					if name, folds := fields.folded[folded]; folds {
						return &DuplicateKeyError{Key: key, Other: name, Path: append([]string(nil), *path...)}
					}
				}
				child = d.field(f)
			}
			if err := walkChild(dec, path, key, child); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return err
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkChild(dec, path, strconv.Itoa(i), d.elemAt(i)); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return err
		}
	}
	return nil
}

// foldName folds a JSON name as encoding/json matches it to a struct field:
// ASCII letters to upper case, every other rune to the smallest rune of its
// fold set (so the Kelvin sign is k, and the long s is s).
func foldName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			continue
		}
		for {
			r2 := unicode.SimpleFold(r)
			if r2 <= r {
				r = r2
				break
			}
			r = r2
		}
		b.WriteRune(r)
	}
	return b.String()
}

var (
	jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// dest is where a JSON value decodes, as encoding/json finds it: a type, and
// the value already there when the walk can see it (along struct fields,
// pointers, and the elements a slice or array already has, from the decode
// target; a map's values are new).
// A zero dest is a place the walk does not follow. An unbounded dest is one
// reached through more than maxIndirections pointers and interfaces; the
// bound is there for a target that holds itself, which encoding/json would
// follow without end, and such a dest is refused.
type dest struct {
	t         reflect.Type
	v         reflect.Value
	unbounded bool
}

// destOf resolves where a decode into v puts a JSON value: through pointers,
// and through an interface that holds a non-nil pointer, as encoding/json
// does; not into a type that decodes itself (json.Unmarshaler or
// encoding.TextUnmarshaler), which is outside the walk.
func destOf(v reflect.Value) dest {
	if !v.IsValid() {
		return dest{}
	}
	return resolve(v.Type(), v)
}

func resolve(t reflect.Type, v reflect.Value) dest {
	// As encoding/json's indirect: a named non-pointer type is decoded
	// through its address, so its pointer methods count; past that, only a
	// pointer is asked whether it decodes itself.
	if t != nil && t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface && t.Name() != "" && decodesItself(reflect.PointerTo(t)) {
		return dest{}
	}
	for hops := 0; t != nil; hops++ {
		if hops > maxIndirections {
			// A pointer type to itself (type P *P), or an interface holding a
			// pointer to itself.
			return dest{unbounded: true}
		}
		switch t.Kind() {
		case reflect.Pointer:
			if decodesItself(t) {
				return dest{}
			}
			if v.IsValid() && !v.IsNil() {
				v = v.Elem()
			} else {
				v = reflect.Value{}
			}
			t = t.Elem()
		case reflect.Interface:
			if v.IsValid() && !v.IsNil() && v.Elem().Kind() == reflect.Pointer && !v.Elem().IsNil() {
				v = v.Elem()
				t = v.Type()
				continue
			}
			return dest{}
		default:
			return dest{t: t, v: v}
		}
	}
	return dest{}
}

// maxIndirections bounds the pointers and interfaces resolve follows to one
// destination; past it, as with a cycle among them, the destination is
// refused.
const maxIndirections = 64

func decodesItself(t reflect.Type) bool {
	return t.Implements(jsonUnmarshaler) || t.Implements(textUnmarshaler)
}

// elem is where a map value of d decodes (a new value).
func (d dest) elem() dest {
	if d.t == nil || d.t.Kind() != reflect.Map {
		return dest{}
	}
	return resolve(d.t.Elem(), reflect.Value{})
}

// elemAt is where element i of a slice or array d decodes: encoding/json
// decodes into the element already there, also one past a slice's length
// within its capacity, and drops an element past an array's length.
func (d dest) elemAt(i int) dest {
	if d.t == nil {
		return dest{}
	}
	var v reflect.Value
	switch d.t.Kind() {
	case reflect.Slice:
		if d.v.IsValid() && i < d.v.Cap() {
			v = d.v.Slice(0, d.v.Cap()).Index(i)
		}
	case reflect.Array:
		if i >= d.t.Len() {
			return dest{}
		}
		if d.v.IsValid() {
			v = d.v.Index(i)
		}
	default:
		return dest{}
	}
	return resolve(d.t.Elem(), v)
}

// field is where the struct field f of d decodes.
func (d dest) field(f *jsonField) dest {
	if f == nil {
		return dest{}
	}
	var v reflect.Value
	if d.v.IsValid() {
		if fv, err := d.v.FieldByIndexErr(f.index); err == nil {
			v = fv
		}
	}
	return resolve(f.typ, v)
}

// jsonField is a struct field as encoding/json reads it: its JSON name, its
// index path (through embedded structs), and its type.
type jsonField struct {
	name   string
	tagged bool
	depth  int
	index  []int
	typ    reflect.Type
}

// fieldSet is the fields encoding/json reads into a struct type, by JSON name
// and by folded name.
type fieldSet struct {
	exact  map[string]*jsonField
	folded map[string]string // folded name → name
}

var fieldSets sync.Map // reflect.Type → *fieldSet

func structFields(t reflect.Type) *fieldSet {
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	if fs, ok := fieldSets.Load(t); ok {
		return fs.(*fieldSet)
	}
	fs := &fieldSet{exact: map[string]*jsonField{}, folded: map[string]string{}}
	for _, f := range jsonFields(t) {
		fs.exact[f.name] = f
		if _, taken := fs.folded[foldName(f.name)]; !taken {
			fs.folded[foldName(f.name)] = f.name
		}
	}
	fieldSets.Store(t, fs)
	return fs
}

// jsonFields lists the fields encoding/json decodes into struct type t, by its
// documented rules: an exported field (or an embedded struct's fields,
// promoted) under its tag's name when the name is valid, else its Go name;
// a field tagged "-" is skipped; an embedded struct given a name in its tag
// is a field of that name. Among fields of one name, those at the shallowest
// depth are considered, the tagged ones among them if any are tagged; if
// exactly one remains it is chosen, else the name is ignored. Each embedded
// type is expanded once, at the shallowest depth it is found.
func jsonFields(t reflect.Type) []*jsonField {
	type level struct {
		typ   reflect.Type
		index []int
	}
	var all []*jsonField
	expanded := map[reflect.Type]bool{}
	current := []level{{typ: t}}
	for depth := 0; len(current) > 0; depth++ {
		count := map[reflect.Type]int{}
		for _, l := range current {
			count[l.typ]++
		}
		var next []level
		for _, l := range current {
			if expanded[l.typ] {
				continue
			}
			expanded[l.typ] = true
			for i := range l.typ.NumField() {
				sf := l.typ.Field(i)
				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if sf.Anonymous {
					if !sf.IsExported() && ft.Kind() != reflect.Struct {
						continue
					}
				} else if !sf.IsExported() {
					continue
				}
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, _, _ := strings.Cut(tag, ",")
				if !validTagName(name) {
					name = ""
				}
				index := append(append([]int(nil), l.index...), i)
				if name != "" || !sf.Anonymous || ft.Kind() != reflect.Struct {
					f := &jsonField{name: name, tagged: name != "", depth: depth, index: index, typ: sf.Type}
					if f.name == "" {
						f.name = sf.Name
					}
					all = append(all, f)
					if count[l.typ] > 1 {
						// The type is embedded more than once at this depth:
						// encoding/json sees its fields twice, so they conflict.
						all = append(all, f)
					}
					continue
				}
				next = append(next, level{typ: ft, index: index})
			}
		}
		current = next
	}
	byName := map[string][]*jsonField{}
	var names []string
	for _, f := range all {
		if _, ok := byName[f.name]; !ok {
			names = append(names, f.name)
		}
		byName[f.name] = append(byName[f.name], f)
	}
	var out []*jsonField
	for _, name := range names {
		if f := dominant(byName[name]); f != nil {
			out = append(out, f)
		}
	}
	return out
}

// dominant chooses among the fields of one name as encoding/json does, or
// returns nil when they conflict.
func dominant(fields []*jsonField) *jsonField {
	shallowest := fields[0].depth
	for _, f := range fields {
		shallowest = min(shallowest, f.depth)
	}
	var top, tagged []*jsonField
	for _, f := range fields {
		if f.depth == shallowest {
			top = append(top, f)
			if f.tagged {
				tagged = append(tagged, f)
			}
		}
	}
	if len(tagged) > 0 {
		top = tagged
	}
	if len(top) != 1 {
		return nil
	}
	return top[0]
}

// validTagName reports whether encoding/json accepts name as a JSON tag name.
func validTagName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}
