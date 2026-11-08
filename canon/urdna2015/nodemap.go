package urdna2015

import (
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/piprate/json-gold/ld"
)

// json-gold builds an expanded document's dataset through a node map, and adds
// each value to its node's property only after comparing it with the values
// the property already holds (ld.AddValue and ld.HasValue): the work grows
// with the square of the distinct values one node's property gathers. The node
// map gathers them by the expanded document's meaning, not its JSON shape:
// every node object of one @id is one node, wherever it is; aliases are one
// property once expanded; and @type and @reverse add to a node from elsewhere.
//
// The walk (bound) counts, before json-gold runs, the comparisons its node map
// would make, by the same rules, and refuses a document whose count passes
// nodeMapBase + nodeMapPerValue per value added. The count is the most any
// order of the values takes, so it does not depend on the order json-gold or
// the walk meets them in: json-gold compares a value with the distinct values
// its property holds until one is equal, so a property of A values, D of them
// distinct, takes at most D(D-1)/2 comparisons for the distinct ones and D
// for each of the A-D repeats. Its time and memory are linear in the
// expanded document: it keeps the document's strings, never copies of them,
// and reads a node's or a graph's @id, and a property, once where the
// document writes it, counting the values added by their numbers.
//
// The same walk counts what the dataset must hold (conserve.go): it records
// values and lists outside any node's property, node objects that add no
// quad, and RDF terms a node's property holds twice, and the quads its
// values make.
//
// The node map belongs to json-gold; this is a stopgap that follows its rules
// (api_generate_node_map.go) and adds the bound. When json-gold finds a value
// among a property's values in constant time, or can bound its work, this
// file goes.

// nodeMapBase and nodeMapPerValue bound the comparisons of the node map. A
// comparison takes 20 to 40 ns, so the bound is about 40 ms, and 0.6 µs more
// per value. One node's property may gather about 1,460 distinct values.
//
// The values are measured. Ordinary credentials take at most 2% of the bound
// (TestNodeMapWork_OrdinaryDocumentsStayWellWithinTheBound):
//
//	document                                               values   pairs  share
//	W3C vc-di-eddsa Example 8                                   8       1     0%
//	20 distinct line items                                     84     190  0.02%
//	50 identical line items, each with an anonymous price     254    1225  0.12%
//	200 identical anonymous tags                              404   19900  1.89%
//
// The largest documents of each shape accepted, and Canonicalize's time for
// them; four times as many values are refused before json-gold runs, in the
// time it takes to expand them:
//
//	shape                                   largest accepted  time   refused in
//	literals on one property                            1464  37 ms        2 ms
//	blank nodes on one property                         1481  34 ms       33 ms
//	node objects of one @id, spread (@included)         1464  51 ms       54 ms
//	aliases of one property                             1464  40 ms       12 ms
//	types of one node                                   1464  22 ms       28 ms
//	reverse properties to one node                      1040  46 ms       64 ms
const (
	nodeMapBase     = 1 << 20
	nodeMapPerValue = 16
)

// bound refuses, with an error wrapping ErrTooComplex, a walked document
// whose node map would compare more pairs of values than the bound.
func (w *nodeMapWork) bound() error {
	if limit := nodeMapBase + nodeMapPerValue*w.added; w.comparisons() > limit {
		return fmt.Errorf("%w: node map: more than %d comparisons of values, for %d values", ErrTooComplex, limit, w.added)
	}
	return nil
}

// conserved refuses a walked document that holds a value the dataset would
// not (see conserve.go): a value or a list outside any node's property, which
// JSON-LD drops; a node object that adds no quad, whose @id would be in none
// of its own, however often other node objects name the same @id; or a
// node's property holding one RDF term twice, which the dataset holds once.
func (w *nodeMapWork) conserved() error {
	if w.floating > 0 {
		return errors.New("urdna2015: a value outside any node's property: JSON-LD drops it from the dataset, so it would ride the document unsigned")
	}
	if w.repeated > 0 {
		return errors.New("urdna2015: a node's property holds one value twice: the dataset holds it once, so the other would ride the document unsigned; write a node once and refer to it elsewhere by its @id, and each type once")
	}
	if w.unnamed != "" {
		return fmt.Errorf("urdna2015: a node object %s is in no quad: it is no property's value and adds no type, property or graph, so it would ride the document unsigned", w.unnamed)
	}
	return nil
}

// quads is the number of quads the walked values make: one for each distinct
// value of each node's property (a type, a reference to a node or a list,
// a literal), and two for each item of a list (rdf:first and rdf:rest).
func (w *nodeMapWork) quads() int64 {
	n := w.listQuads
	for _, g := range w.groups {
		n += g.distinct
	}
	return n
}

// holds refuses a dataset that does not hold exactly the quads the walked
// values make: json-gold dropped a value the walk counted (in its second
// expansion, its node map or ToRDF), or made one it did not.
func (w *nodeMapWork) holds(dataset *ld.RDFDataset) error {
	var n int64
	for _, qs := range dataset.Graphs {
		n += int64(len(qs))
	}
	if want := w.quads(); n != want {
		return fmt.Errorf("urdna2015: the dataset holds %d quads where the document's values make %d: a value would ride the document unsigned", n, want)
	}
	return nil
}

// nodeMapWork counts what json-gold's node map does with an expanded document:
// the values it adds to each node's property, and how many of them are
// distinct.
type nodeMapWork struct {
	groups map[groupKey]*valueGroup
	ids    map[string]int
	names  []string // each node's or graph's @id, by its number; "\x00" for a node without one
	added  int64

	occurrences []int  // by each node object the walk meets: the quads that name it
	unnamed     string // the first node object in no quad of its own, quoted
	floating    int    // values and lists outside any node's property
	repeated    int    // values a node's property already held
	listQuads   int64  // two for each item of a list
}

func newNodeMapWork() *nodeMapWork {
	return &nodeMapWork{groups: map[groupKey]*valueGroup{}, ids: map[string]int{}}
}

// id numbers a node's or a graph's @id, or a property. The walk reads each
// here, once where the document writes it, and adds values by the numbers,
// so its time does not grow with the length of an @id or a property many
// values name.
func (w *nodeMapWork) id(s string) int {
	n, ok := w.ids[s]
	if !ok {
		n = len(w.names)
		w.ids[s] = n
		w.names = append(w.names, s)
	}
	return n
}

// fresh numbers a node object without @id, a node of its own.
func (w *nodeMapWork) fresh() int {
	w.names = append(w.names, "\x00")
	return len(w.names) - 1
}

// walk walks an expanded document as GenerateNodeMap does.
func (w *nodeMapWork) walk(expanded any) {
	w.element(expanded, w.id("@default"), -1, -1, -1, false, -1, false)
}

// groupKey is a node's property in a graph, each by its number: where the
// node map gathers values.
type groupKey struct{ graph, node, property int }

// valueGroup is the values added to a node's property, and how many of them
// are distinct.
type valueGroup struct {
	seen            map[valueID]bool
	added, distinct int64
}

// maxCountedValues is the most values the count holds without overflow: with
// A values in all, the count is at most A times the most distinct values of
// one property, so at most A², below 2^63.
const maxCountedValues = 1 << 31

// comparisons is the most comparisons json-gold's node map makes to add the
// values, whatever their order: for each node's property of A values, D
// distinct, D(D-1)/2 + (A-D)D. Past maxCountedValues values it is the largest
// int64, past every bound; no such document fits in memory.
func (w *nodeMapWork) comparisons() int64 {
	if w.added > maxCountedValues {
		return math.MaxInt64
	}
	var n int64
	for _, g := range w.groups {
		d := g.distinct
		n += d*(d-1)/2 + (g.added-d)*d
	}
	return n
}

// add adds a value to a node's property; it is a new one unless an equal one
// (v) is there. A value no other equals (a list, as json-gold compares) is
// always new. The quad names the node object at subjectOcc (as its subject,
// or as a reverse value's object) and the one at graphOcc (as its graph),
// where they are not -1.
func (w *nodeMapWork) add(graph, node, property int, v valueID, unequal bool, subjectOcc, graphOcc int) {
	k := groupKey{graph, node, property}
	g := w.groups[k]
	if g == nil {
		g = &valueGroup{seen: map[valueID]bool{}}
		w.groups[k] = g
	}
	w.added++
	g.added++
	switch {
	case unequal:
		g.distinct++
	case g.seen[v]:
		w.repeated++
	default:
		g.distinct++
		g.seen[v] = true
	}
	for _, o := range [2]int{subjectOcc, graphOcc} {
		if o >= 0 {
			w.occurrences[o]++
		}
	}
}

// element walks an element of the expanded document as GenerateNodeMap does:
// in graph, as a value of subject's property (a reverse property when
// reverse: the element's node gets subject as its value), or of a list.
func (w *nodeMapWork) element(el any, graph, graphOcc, subject, subjectOcc int, reverse bool, property int, inList bool) {
	switch t := el.(type) {
	case []any:
		for _, item := range t {
			w.element(item, graph, graphOcc, subject, subjectOcc, reverse, property, inList)
		}
	case map[string]any:
		if _, ok := t["@value"]; ok {
			switch {
			case inList:
			case subject < 0 || property < 0:
				w.floating++
			default:
				v, ok := valueOf(t)
				w.add(graph, subject, property, v, !ok, subjectOcc, graphOcc)
			}
			return
		}
		if list, ok := t["@list"]; ok {
			if items, ok := list.([]any); ok {
				w.listQuads += 2 * int64(len(items))
			}
			w.element(list, graph, graphOcc, subject, subjectOcc, reverse, property, true)
			switch {
			case inList:
			case subject < 0 || property < 0:
				w.floating++
			default:
				w.add(graph, subject, property, valueID{}, true, subjectOcc, graphOcc)
			}
			return
		}
		var id int
		if s, ok := t["@id"].(string); ok {
			id = w.id(s)
		} else {
			id = w.fresh()
		}
		// This node object is in a quad of its own if it is a value (of a
		// property, a reverse property or a list), or if a quad its types,
		// reverse properties, graph or properties add names it: as subject,
		// as a reverse value's object, or as the graph. A quad its
		// descendants add in their own graphs, or what @included holds, does
		// not count for it.
		occ := len(w.occurrences)
		w.occurrences = append(w.occurrences, 0)
		named := inList
		switch {
		case reverse:
			w.add(graph, id, property, valueID{ref: true, node: subject}, false, subjectOcc, graphOcc)
			named = true
		case property >= 0 && !inList:
			w.add(graph, subject, property, valueID{ref: true, node: id}, false, subjectOcc, graphOcc)
			named = true
		}
		switch types := t["@type"].(type) {
		case []any:
			for _, ty := range types {
				s, ok := ty.(string)
				w.add(graph, id, w.id("@type"), valueID{value: s}, !ok, occ, graphOcc)
			}
		case string:
			w.add(graph, id, w.id("@type"), valueID{value: types}, false, occ, graphOcc)
		}
		if rev, ok := t["@reverse"].(map[string]any); ok {
			for p, values := range rev {
				w.element(values, graph, graphOcc, id, occ, true, w.id(p), false)
			}
		}
		if g, ok := t["@graph"]; ok {
			w.element(g, id, occ, -1, -1, false, -1, false)
		}
		for p, v := range t {
			switch p {
			case "@id", "@type", "@index", "@reverse", "@graph", "@included":
				continue
			}
			w.element(v, graph, graphOcc, id, occ, false, w.id(p), false)
		}
		if !named && w.occurrences[occ] == 0 {
			// Of the node objects in no quad, the error names the one of the
			// smallest name, so it does not depend on map order.
			name := "without @id"
			if s := w.names[id]; s != "\x00" {
				name = bounded(s)
			}
			if w.unnamed == "" || name < w.unnamed {
				w.unnamed = name
			}
		}
		if included, ok := t["@included"]; ok {
			w.element(included, graph, graphOcc, -1, -1, false, -1, false)
		}
	}
}

// valueID tells values apart as json-gold's CompareValues does, without
// copying or rereading the document's strings: a node reference by its node's
// number (ref), a string such as a type by itself, a value object by its
// @value (of kind) and its @type, @language and @index (has says which it
// has).
type valueID struct {
	ref                  bool
	node                 int
	value                string
	kind                 byte
	typ, language, index string
	has                  byte
}

const (
	hasType byte = 1 << iota
	hasLanguage
	hasIndex
)

// valueOf is the valueID of a value object, and false for one no other is
// known to equal: a @value other than a string, a boolean or a number, a
// number that is not equal to itself (NaN), or a @type, @language or @index
// that is not a string.
func valueOf(v map[string]any) (valueID, bool) {
	var id valueID
	switch x := v["@value"].(type) {
	case string:
		id.value, id.kind = x, 's'
	case bool:
		id.value, id.kind = strconv.FormatBool(x), 'b'
	case float64:
		if x != x {
			return valueID{}, false
		}
		id.value, id.kind = strconv.FormatFloat(x, 'g', -1, 64), 'f'
	default:
		return valueID{}, false
	}
	for _, f := range []struct {
		key  string
		bit  byte
		into *string
	}{{"@type", hasType, &id.typ}, {"@language", hasLanguage, &id.language}, {"@index", hasIndex, &id.index}} {
		x, present := v[f.key]
		if !present {
			continue
		}
		s, ok := x.(string)
		if !ok {
			return valueID{}, false
		}
		*f.into, id.has = s, id.has|f.bit
	}
	// Two spellings json-gold writes as one literal are one value: a string
	// typed xsd:string is the string, and a boolean is the string of its name
	// typed xsd:boolean.
	switch {
	case id.kind == 'b':
		id.kind, id.typ, id.has = 's', xsdBoolean, id.has|hasType
	case id.kind == 's' && id.has&hasType != 0 && id.typ == xsdString:
		id.typ, id.has = "", id.has&^hasType
	}
	return id, true
}
