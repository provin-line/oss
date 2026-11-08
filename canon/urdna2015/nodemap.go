package urdna2015

import (
	"fmt"
	"math"
	"strconv"
)

// json-gold builds an expanded document's dataset through a node map, and adds
// each value to its node's property only after comparing it with the values
// the property already holds (ld.AddValue and ld.HasValue): the work grows
// with the square of the distinct values one node's property gathers. The node
// map gathers them by the expanded document's meaning, not its JSON shape:
// every node object of one @id is one node, wherever it is; aliases are one
// property once expanded; and @type and @reverse add to a node from elsewhere.
//
// boundNodeMapWork counts, before json-gold runs, the comparisons its node map
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
//	node objects of one @id, spread                     1480  54 ms       59 ms
//	aliases of one property                             1464  40 ms       12 ms
//	types of one node                                   1464  22 ms       28 ms
//	reverse properties to one node                      1040  46 ms       64 ms
const (
	nodeMapBase     = 1 << 20
	nodeMapPerValue = 16
)

// boundNodeMapWork refuses, with an error wrapping ErrTooComplex, an expanded
// document whose node map would compare more pairs of values than the bound.
func boundNodeMapWork(expanded any) error {
	w := newNodeMapWork()
	w.walk(expanded)
	if limit := nodeMapBase + nodeMapPerValue*w.added; w.comparisons() > limit {
		return fmt.Errorf("%w: node map: more than %d comparisons of values, for %d values", ErrTooComplex, limit, w.added)
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
	w.element(expanded, w.id("@default"), -1, false, -1, false)
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
// always new.
func (w *nodeMapWork) add(graph, node, property int, v valueID, unequal bool) {
	k := groupKey{graph, node, property}
	g := w.groups[k]
	if g == nil {
		g = &valueGroup{seen: map[valueID]bool{}}
		w.groups[k] = g
	}
	w.added++
	g.added++
	if unequal || !g.seen[v] {
		g.distinct++
		if !unequal {
			g.seen[v] = true
		}
	}
}

// element walks an element of the expanded document as GenerateNodeMap does:
// in graph, as a value of subject's property (a reverse property when
// reverse: the element's node gets subject as its value), or of a list.
func (w *nodeMapWork) element(el any, graph, subject int, reverse bool, property int, inList bool) {
	switch t := el.(type) {
	case []any:
		for _, item := range t {
			w.element(item, graph, subject, reverse, property, inList)
		}
	case map[string]any:
		if _, ok := t["@value"]; ok {
			if !inList {
				v, ok := valueOf(t)
				w.add(graph, subject, property, v, !ok)
			}
			return
		}
		if list, ok := t["@list"]; ok {
			w.element(list, graph, subject, reverse, property, true)
			if !inList {
				w.add(graph, subject, property, valueID{}, true)
			}
			return
		}
		var id int
		if s, ok := t["@id"].(string); ok {
			id = w.id(s)
		} else {
			id = w.fresh()
		}
		switch {
		case reverse:
			w.add(graph, id, property, valueID{ref: true, node: subject}, false)
		case property >= 0 && !inList:
			w.add(graph, subject, property, valueID{ref: true, node: id}, false)
		}
		switch types := t["@type"].(type) {
		case []any:
			for _, ty := range types {
				s, ok := ty.(string)
				w.add(graph, id, w.id("@type"), valueID{value: s}, !ok)
			}
		case string:
			w.add(graph, id, w.id("@type"), valueID{value: types}, false)
		}
		if rev, ok := t["@reverse"].(map[string]any); ok {
			for p, values := range rev {
				w.element(values, graph, id, true, w.id(p), false)
			}
		}
		if g, ok := t["@graph"]; ok {
			w.element(g, id, -1, false, -1, false)
		}
		if included, ok := t["@included"]; ok {
			w.element(included, graph, -1, false, -1, false)
		}
		for p, v := range t {
			switch p {
			case "@id", "@type", "@index", "@reverse", "@graph", "@included":
				continue
			}
			w.element(v, graph, id, false, w.id(p), false)
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
	return id, true
}
