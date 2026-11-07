package urdna2015

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// The canonical labelling of blank nodes (URDNA2015, RDFC-1.0 §4.4) is done
// here, over the dataset json-gold produces, because it must be able to stop.
// Hash N-Degree Quads takes time exponential in the blank nodes of a crafted
// dataset, and RDFC-1.0 §4.4.3 requires an implementation to defend against
// that by raising an error; json-gold has no bound to set.
//
// The labelling belongs to json-gold. This is a stopgap that follows its
// labelling and its N-Quads spelling step for step (the tests compare the
// two) and adds the bound. Two differences: it relabels every blank node,
// where json-gold leaves one whose label already starts with _:c14n (toRDF
// labels every blank node _:b, so no dataset Canonicalize builds has one);
// and where two blank nodes no hash tells apart are not interchangeable
// (they differ only in the blank graph a quad sits in), json-gold's answer
// depends on map order and this labelling gives one of its answers, always
// the same one.
//
// When json-gold can bound its calls to Hash N-Degree Quads, Canonicalize
// hands the labelling back to json-gold with that bound and this file goes.
// Its bound need not refuse the same datasets; the canonical bytes of every
// dataset both accept are the same.

// Work bounds the labelling, in units of about the same time each: every call
// to Hash N-Degree Quads costs one unit, one per quad of its blank node and
// one per 32 bytes of those quads' predicates (it hashes each predicate up to
// twice); every permutation it tries costs one unit, one per blank node
// permuted and one per identifier its issuer copies. A dataset whose
// labelling would cost more than labelWorkBase units and labelWorkPerQuad
// per quad is refused with ErrTooComplex.
//
// The values are measured. Ordinary credentials, expanded as Canonicalize
// expands them, stay within half of the bound
// (TestLabel_OrdinaryDocumentsStayWellWithinTheBound):
//
//	document                                               quads    work  share
//	W3C vc-di-eddsa Example 8                                  8       0     0%
//	20 distinct line items                                    84       0     0%
//	50 identical line items, each with an anonymous price    254    1200   0.4%
//	200 identical anonymous tags                             404    1600   0.6%
//	two identical anonymous evidence entries, nested parts    16      82  0.03%
//	a chain of 12 identical anonymous objects                 17    2746     1%
//	a list (@list) of 16 identical strings                    37    5342     2%
//	a list of 40 identical strings                            85   77500    29%
//	two identical evidence entries, each of 6 alike parts     32  112716    43%
//
// The smallest datasets refused, the time json-gold takes to label them, and
// the time to refuse them:
//
//	shape                                     first refused  json-gold  refused in
//	blank nodes all linked to each other                  6      24 ms       17 ms
//	a ring of alike blank nodes                          56      11 ms       10 ms
//	a list of equal values                               62      13 ms       11 ms
//	two alike nodes each with alike leaves    7 leaves each      61 ms       17 ms
//
// Past that, a refusal costs about 3.5 µs more per quad
// (BenchmarkLabel_RefusesWithinTheBound). A bound linear in quads must, past
// some size, refuse shapes whose labelling is polynomial (a list of n equal
// values costs about n³) or worse (alike leaves under alike parents cost
// about k!); the constants decide where. With 2^16, the last ordinary
// document above is refused, and lists from 40. With 2^20, about 7 alike
// parts and lists to about 90 would pass, and a refusal would cost about
// 40–160 ms (extrapolated, not measured).
const (
	labelWorkBase    = 1 << 18
	labelWorkPerQuad = 64
)

type blankNode struct {
	quads  []*ld.Quad
	cost   int // units of one call to Hash N-Degree Quads for this node
	hash   string
	hashed bool
}

// issuer issues identifiers with a prefix, in order, as json-gold's
// IdentifierIssuer does.
type issuer struct {
	prefix string
	ids    map[string]string
	order  []string
}

func newIssuer(prefix string) *issuer {
	return &issuer{prefix: prefix, ids: map[string]string{}}
}

func (s *issuer) has(old string) bool {
	_, ok := s.ids[old]
	return ok
}

func (s *issuer) id(old string) string {
	if id, ok := s.ids[old]; ok {
		return id
	}
	id := fmt.Sprintf("%s%d", s.prefix, len(s.order))
	s.ids[old] = id
	s.order = append(s.order, old)
	return id
}

func (s *issuer) clone() *issuer {
	c := &issuer{prefix: s.prefix, ids: make(map[string]string, len(s.ids)), order: append([]string(nil), s.order...)}
	for k, v := range s.ids {
		c.ids[k] = v
	}
	return c
}

type labeller struct {
	quads  []*ld.Quad
	blanks map[string]*blankNode
	canon  *issuer
	work   int
	budget int
}

// canonicalNQuads labels the blank nodes of dataset and returns its canonical
// N-Quads, or an error wrapping ErrTooComplex. It takes the dataset's quads
// as its own.
func canonicalNQuads(dataset *ld.RDFDataset) (string, error) {
	out, _, err := label(dataset, labelWorkBase, labelWorkPerQuad)
	return out, err
}

// label is canonicalNQuads within base + perQuad units per quad, and reports
// the units the labelling took.
func label(dataset *ld.RDFDataset, base, perQuad int) (string, int, error) {
	l := &labeller{blanks: map[string]*blankNode{}, canon: newIssuer("_:c14n")}
	graphs := make([]string, 0, len(dataset.Graphs))
	for name := range dataset.Graphs {
		graphs = append(graphs, name)
	}
	sort.Strings(graphs)
	for _, name := range graphs {
		graph := name
		if graph == "@default" {
			graph = ""
		}
		for _, q := range dataset.Graphs[name] {
			if graph != "" {
				if strings.HasPrefix(graph, "_:") {
					q.Graph = ld.NewBlankNode(graph)
				} else {
					q.Graph = ld.NewIRI(graph)
				}
			}
			l.quads = append(l.quads, q)
			for _, n := range []ld.Node{q.Subject, q.Object, q.Graph} {
				if n != nil && ld.IsBlankNode(n) {
					b := l.blanks[n.GetValue()]
					if b == nil {
						b = &blankNode{}
						l.blanks[n.GetValue()] = b
					}
					b.quads = append(b.quads, q)
					b.cost += 1 + len(q.Predicate.GetValue())/32
				}
			}
		}
	}
	l.budget = base + perQuad*len(l.quads)

	// Issue canonical identifiers to the blank nodes whose first-degree hash
	// is unique, in the order of the hashes.
	pending := make([]string, 0, len(l.blanks))
	for id := range l.blanks {
		pending = append(pending, id)
	}
	sort.Strings(pending)
	byHash := map[string][]string{}
	for _, id := range pending {
		h := l.firstDegreeHash(id)
		byHash[h] = append(byHash[h], id)
	}
	for _, h := range sortedKeys(byHash) {
		if ids := byHash[h]; len(ids) == 1 {
			l.canon.id(ids[0])
			delete(byHash, h)
		}
	}

	// The rest, a group of blank nodes sharing a first-degree hash at a time,
	// in the order of the hashes: each node's N-degree hash orders the group,
	// and the issuer behind it names the nodes it reached.
	for _, h := range sortedKeys(byHash) {
		paths := map[string][]*issuer{}
		for _, id := range byHash[h] {
			if l.canon.has(id) {
				continue
			}
			tmp := newIssuer("_:b")
			tmp.id(id)
			nh, result, err := l.nDegreeHash(id, tmp)
			if err != nil {
				return "", l.work, err
			}
			paths[nh] = append(paths[nh], result)
		}
		for _, nh := range sortedKeys(paths) {
			for _, result := range paths[nh] {
				for _, old := range result.order {
					l.canon.id(old)
				}
			}
		}
	}

	lines := make([]string, len(l.quads))
	for i, q := range l.quads {
		for _, n := range []*ld.Node{&q.Subject, &q.Object, &q.Graph} {
			if *n != nil && ld.IsBlankNode(*n) {
				*n = ld.NewBlankNode(l.canon.id((*n).GetValue()))
			}
		}
		graph := ""
		if q.Graph != nil {
			graph = q.Graph.GetValue()
		}
		lines[i] = nquad(q.Subject, q.Predicate, q.Object, graph)
	}
	sort.Strings(lines)
	return strings.Join(lines, ""), l.work, nil
}

// firstDegreeHash is Hash First Degree Quads (RDFC-1.0 §4.6), cached.
func (l *labeller) firstDegreeHash(id string) string {
	b := l.blanks[id]
	if b.hashed {
		return b.hash
	}
	spell := func(n ld.Node) ld.Node {
		if n == nil || !ld.IsBlankNode(n) {
			return n
		}
		if n.GetValue() == id {
			return ld.NewBlankNode("_:a")
		}
		return ld.NewBlankNode("_:z")
	}
	lines := make([]string, 0, len(b.quads))
	for _, q := range b.quads {
		graph := ""
		if g := spell(q.Graph); g != nil {
			graph = g.GetValue()
		}
		lines = append(lines, nquad(spell(q.Subject), q.Predicate, spell(q.Object), graph))
	}
	sort.Strings(lines)
	b.hash, b.hashed = sha256Hex(lines...), true
	return b.hash
}

// relatedHash is Hash Related Blank Node (RDFC-1.0 §4.7).
func (l *labeller) relatedHash(related string, q *ld.Quad, s *issuer, position string) string {
	var id string
	switch {
	case l.canon.has(related):
		id = l.canon.id(related)
	case s.has(related):
		id = s.id(related)
	default:
		id = l.firstDegreeHash(related)
	}
	if position == "g" {
		return sha256Hex(position, id)
	}
	return sha256Hex(position, "<"+q.Predicate.GetValue()+">", id)
}

// nDegreeHash is Hash N-Degree Quads (RDFC-1.0 §4.8), within the work bound.
func (l *labeller) nDegreeHash(id string, s *issuer) (string, *issuer, error) {
	b := l.blanks[id]
	if err := l.spend(1 + b.cost); err != nil {
		return "", nil, err
	}
	related := map[string][]string{}
	positions := [...]string{"s", "o", "g"}
	for _, q := range b.quads {
		for i, n := range []ld.Node{q.Subject, q.Object, q.Graph} {
			if n != nil && ld.IsBlankNode(n) && n.GetValue() != id {
				h := l.relatedHash(n.GetValue(), q, s, positions[i])
				related[h] = append(related[h], n.GetValue())
			}
		}
	}

	h := sha256.New()
	for _, rh := range sortedKeys(related) {
		h.Write([]byte(rh))
		chosenPath := ""
		var chosen *issuer
		longer := func(path string) bool {
			return chosenPath != "" && len(path) >= len(chosenPath) && path > chosenPath
		}
		perms := newPermutations(related[rh])
	next:
		for perms.more() {
			perm := perms.next()
			if err := l.spend(1 + len(perm) + len(s.order)); err != nil {
				return "", nil, err
			}
			c := s.clone()
			var path strings.Builder
			var recursion []string
			for _, r := range perm {
				if l.canon.has(r) {
					path.WriteString(l.canon.id(r))
				} else {
					if !c.has(r) {
						recursion = append(recursion, r)
					}
					path.WriteString(c.id(r))
				}
				if longer(path.String()) {
					continue next
				}
			}
			for _, r := range recursion {
				rhash, rs, err := l.nDegreeHash(r, c)
				if err != nil {
					return "", nil, err
				}
				path.WriteString(c.id(r) + "<" + rhash + ">")
				c = rs
				if longer(path.String()) {
					continue next
				}
			}
			if chosenPath == "" || path.String() < chosenPath {
				chosenPath, chosen = path.String(), c
			}
		}
		h.Write([]byte(chosenPath))
		s = chosen
	}
	return hex.EncodeToString(h.Sum(nil)), s, nil
}

func (l *labeller) spend(units int) error {
	l.work += units
	if l.work > l.budget {
		return fmt.Errorf("%w: more than %d steps for %d quads", ErrTooComplex, l.budget, len(l.quads))
	}
	return nil
}

// permutations yields every ordering of a list, in the order json-gold's
// Permutator does (Steinhaus–Johnson–Trotter from the sorted list, with a
// direction kept per value, so a value listed twice turns twice). The order
// decides which of two equal paths is chosen, and with it the bytes.
type permutations struct {
	list []string
	left map[string]bool
	done bool
}

func newPermutations(list []string) *permutations {
	p := &permutations{list: append([]string(nil), list...), left: map[string]bool{}}
	sort.Strings(p.list)
	for _, e := range p.list {
		p.left[e] = true
	}
	return p
}

func (p *permutations) more() bool { return !p.done }

func (p *permutations) next() []string {
	out := append([]string(nil), p.list...)
	k, pos := "", 0
	for i, e := range p.list {
		left := p.left[e]
		if (k == "" || e > k) &&
			((left && i > 0 && e > p.list[i-1]) || (!left && i < len(p.list)-1 && e > p.list[i+1])) {
			k, pos = e, i
		}
	}
	if k == "" {
		p.done = true
		return out
	}
	swap := pos + 1
	if p.left[k] {
		swap = pos - 1
	}
	p.list[pos], p.list[swap] = p.list[swap], k
	for _, e := range p.list {
		if e > k {
			p.left[e] = !p.left[e]
		}
	}
	return out
}

// nquad spells one quad in N-Quads as json-gold does.
func nquad(s, p, o ld.Node, graph string) string {
	var b strings.Builder
	if ld.IsIRI(s) {
		b.WriteString("<" + escapeNQuads(s.GetValue()) + ">")
	} else {
		b.WriteString(s.GetValue())
	}
	if ld.IsIRI(p) {
		b.WriteString(" <" + escapeNQuads(p.GetValue()) + "> ")
	} else {
		b.WriteString(" " + escapeNQuads(p.GetValue()) + " ")
	}
	switch {
	case ld.IsIRI(o):
		b.WriteString("<" + escapeNQuads(o.GetValue()) + ">")
	case ld.IsBlankNode(o):
		b.WriteString(o.GetValue())
	default:
		lit := o.(ld.Literal)
		b.WriteString(`"` + escapeNQuads(lit.GetValue()) + `"`)
		if lit.Datatype == ld.RDFLangString {
			b.WriteString("@" + lit.Language)
		} else if lit.Datatype != ld.XSDString {
			b.WriteString("^^<" + escapeNQuads(lit.Datatype) + ">")
		}
	}
	if graph != "" {
		if strings.HasPrefix(graph, "_:") {
			b.WriteString(" " + graph)
		} else {
			b.WriteString(" <" + escapeNQuads(graph) + ">")
		}
	}
	b.WriteString(" .\n")
	return b.String()
}

var nquadsEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)

func escapeNQuads(s string) string { return nquadsEscaper.Replace(s) }

func sha256Hex(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
