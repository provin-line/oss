package urdna2015

import "fmt"

// What Canonicalize signs must hold every value of the document (see the
// package doc). Rather than rest on a list of the forms JSON-LD processing
// loses a value in, Canonicalize counts the document's values through its
// stages and refuses a document whose count changes:
//
//   - dataValues counts, in the document, the values JSON-LD carries into
//     the expanded form one for one: each string or boolean outside a
//     context, but a value object's @type and @language. expandedValues
//     counts the same in the expanded form: each @value, each @id, and each
//     @type of a node. The two must be equal.
//   - The node map's walk (nodemap.go) then requires each value to belong to
//     a node's property, each node object to add a quad of its own, and no
//     node's property to hold one RDF term twice, and counts the quads they
//     make: the dataset json-gold builds must hold exactly that many (holds).
//
// A count holds only where a value stays one value at every stage, so the
// forms where it does not are refused first; the package doc lists them, each
// with its check. dataValues leaves out only what is written as a keyword
// (@context, and a value object's @type and @language), so its count rests on
// no alias: a key JSON-LD reads as a keyword, through an alias or a
// vocabulary, is counted as a value unless it is written as one, and can only
// make the counts disagree. It counts no value of a context, whose text is
// not signed.

// dataValues counts the document's values JSON-LD carries into the expanded
// form one for one (see the comment at the top of this file), refusing @index
// and @direction anywhere, and @language outside a value object.
func (r *contextRules) dataValues(v any, path *jsonPath) (int64, error) {
	switch t := v.(type) {
	case string, bool:
		return 1, nil
	case []any:
		var n int64
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			m, err := r.dataValues(x, path)
			if err != nil {
				return 0, err
			}
			*path = (*path)[:len(*path)-1]
			n += m
		}
		return n, nil
	case map[string]any:
		keys := sortedKeys(t)
		value, language := false, false
		for _, k := range keys {
			switch r.keyword(k) {
			case "@value":
				value = true
			case "@language":
				language = true
			case "@index":
				return 0, fmt.Errorf("urdna2015: @index at %s: RDF does not carry it, so it would ride the document unsigned", path.quoted())
			case "@direction":
				return 0, fmt.Errorf("urdna2015: @direction at %s: json-gold does not write base direction, so it would ride the document unsigned", path.quoted())
			case "@set":
				return 0, fmt.Errorf("urdna2015: @set at %s: json-gold drops what it cannot expand under @set without an error, so it would ride the document unsigned; write the set's values without @set", path.quoted())
			case "@default", "@explicit", "@embed", "@requireAll", "@omitDefault":
				return 0, fmt.Errorf("urdna2015: %s at %s: a framing keyword, which a document does not use; json-gold drops what it cannot expand under it without an error, so it would ride the document unsigned", r.keyword(k), path.quoted())
			}
		}
		if language && !value {
			return 0, fmt.Errorf("urdna2015: @language at %s outside a value object: JSON-LD drops it, so it would ride the document unsigned", path.quoted())
		}
		if value {
			for _, k := range keys {
				x := t[k]
				switch k {
				case "@value":
				case "@language":
					if err := asciiLanguage(x); err != nil {
						return 0, err
					}
				case "@type":
					if x == "@json" {
						return 0, fmt.Errorf("urdna2015: @json at %s: the RDFC path does not accept JSON literals", path.quoted())
					}
				default:
					return 0, fmt.Errorf("urdna2015: a value object at %s holds %s: the RDFC path reads a value object's keys only as the keywords written out (@value, @type, @language)", path.quoted(), bounded(k))
				}
			}
		}
		var n int64
		for _, k := range keys {
			x := t[k]
			switch {
			case k == "@context":
			case value && (k == "@type" || k == "@language"):
			default:
				*path = append(*path, pathSegment{key: k, index: -1})
				m, err := r.dataValues(x, path)
				if err != nil {
					return 0, err
				}
				*path = (*path)[:len(*path)-1]
				n += m
			}
		}
		return n, nil
	}
	return 0, nil
}

// expandedValues counts the values of an expanded document dataValues counts
// in the document: each @value that is a string or a boolean, each @id, and
// each @type of a node.
func expandedValues(v any) int64 {
	switch t := v.(type) {
	case []any:
		var n int64
		for _, x := range t {
			n += expandedValues(x)
		}
		return n
	case map[string]any:
		if x, ok := t["@value"]; ok {
			switch x.(type) {
			case string, bool:
				return 1
			}
			return 0
		}
		var n int64
		for k, x := range t {
			switch k {
			case "@id":
				if _, ok := x.(string); ok {
					n++
				}
			case "@type":
				n += stringsIn(x)
			case "@language", "@index", "@direction":
			default:
				n += expandedValues(x)
			}
		}
		return n
	}
	return 0
}

func stringsIn(v any) int64 {
	switch t := v.(type) {
	case string:
		return 1
	case []any:
		var n int64
		for _, x := range t {
			n += stringsIn(x)
		}
		return n
	}
	return 0
}
