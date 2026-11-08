// Changed by 1o1 Co. Ltd. for github.com/provin-line/oss: the compile
// queue looks a subschema up by an index (the lines marked "compile index"),
// a resource's dynamic anchors are found in its anchors rather than searched
// for (the lines marked "dynamic anchor set"), CompileWithBudget (the lines
// marked "metaschema budget"), the cache of a metaschema's vocabularies
// emptied when a vocabulary is registered (the line marked "vocabulary
// cache"), and the target of each local reference kept by the URL it
// resolves to (the lines marked "reference index"). See README.md in this
// directory.

package jsonschema

import (
	"fmt"
	"regexp"
)

// Compiler compiles json schema into *Schema.
type Compiler struct {
	schemas       map[urlPtr]*Schema
	roots         *roots
	formats       map[string]*Format
	decoders      map[string]*Decoder
	mediaTypes    map[string]*MediaType
	assertFormat  bool
	assertContent bool
}

// NewCompiler create Compiler Object.
func NewCompiler() *Compiler {
	return &Compiler{
		schemas:       map[urlPtr]*Schema{},
		roots:         newRoots(),
		formats:       map[string]*Format{},
		decoders:      map[string]*Decoder{},
		mediaTypes:    map[string]*MediaType{},
		assertFormat:  false,
		assertContent: false,
	}
}

// DefaultDraft overrides the draft used to
// compile schemas without `$schema` field.
//
// By default, this library uses the latest
// draft supported.
//
// The use of this option is HIGHLY encouraged
// to ensure continued correct operation of your
// schema. The current default value will not stay
// the same overtime.
func (c *Compiler) DefaultDraft(d *Draft) {
	c.roots.defaultDraft = d
}

// AssertFormat always enables format assertions.
//
// Default Behavior:
// for draft-07: enabled.
// for draft/2019-09: disabled unless metaschema says `format` vocabulary is required.
// for draft/2020-12: disabled unless metaschema says `format-assertion` vocabulary is required.
func (c *Compiler) AssertFormat() {
	c.assertFormat = true
}

// AssertContent enables content assertions.
//
// Content assertions include keywords:
//   - contentEncoding
//   - contentMediaType
//   - contentSchema
//
// Default behavior is always disabled.
func (c *Compiler) AssertContent() {
	c.assertContent = true
}

// RegisterFormat registers custom format.
//
// NOTE:
//   - "regex" format can not be overridden
//   - format assertions are disabled for draft >= 2019-09
//     see [Compiler.AssertFormat]
func (c *Compiler) RegisterFormat(f *Format) {
	if f.Name != "regex" {
		c.formats[f.Name] = f
	}
}

// RegisterContentEncoding registers custom contentEncoding.
//
// NOTE: content assertions are disabled by default.
// see [Compiler.AssertContent].
func (c *Compiler) RegisterContentEncoding(d *Decoder) {
	c.decoders[d.Name] = d
}

// RegisterContentMediaType registers custom contentMediaType.
//
// NOTE: content assertions are disabled by default.
// see [Compiler.AssertContent].
func (c *Compiler) RegisterContentMediaType(mt *MediaType) {
	c.mediaTypes[mt.Name] = mt
}

// RegisterVocabulary registers custom vocabulary.
//
// NOTE:
//   - vocabularies are disabled for draft >= 2019-09
//     see [Compiler.AssertVocabs]
func (c *Compiler) RegisterVocabulary(vocab *Vocabulary) {
	c.roots.vocabularies[vocab.URL] = vocab
	c.roots.loader.vocabs = nil // vocabulary cache: read the metaschemas' vocabularies again with it
}

// AssertVocabs always enables user-defined vocabularies assertions.
//
// Default Behavior:
// for draft-07: enabled.
// for draft/2019-09: disabled unless metaschema enables a vocabulary.
// for draft/2020-12: disabled unless metaschema enables a vocabulary.
func (c *Compiler) AssertVocabs() {
	c.roots.assertVocabs = true
}

// AddResource adds schema resource which gets used later in reference
// resolution.
//
// The argument url can be file path or url. Any fragment in url is ignored.
// The argument doc must be valid json value.
func (c *Compiler) AddResource(url string, doc any) error {
	uf, err := absolute(url)
	if err != nil {
		return err
	}
	if isMeta(string(uf.url)) {
		return &ResourceExistsError{string(uf.url)}
	}
	if !c.roots.loader.add(uf.url, doc) {
		return &ResourceExistsError{string(uf.url)}
	}
	return nil
}

// UseLoader overrides the default [URLLoader] used
// to load schema resources.
func (c *Compiler) UseLoader(loader URLLoader) {
	c.roots.loader.loader = loader
}

// UseRegexpEngine changes the regexp-engine used.
// By default it uses regexp package from go standard
// library.
//
// NOTE: must be called before compiling any schemas.
func (c *Compiler) UseRegexpEngine(engine RegexpEngine) {
	if engine == nil {
		engine = goRegexpCompile
	}
	c.roots.regexpEngine = engine
}

func (c *Compiler) enqueue(q *queue, up urlPtr) *Schema {
	if sch, ok := c.schemas[up]; ok {
		// already got compiled
		return sch
	}
	if sch := q.get(up); sch != nil {
		return sch
	}
	sch := newSchema(up)
	q.append(sch)
	return sch
}

// CompileWithBudget compiles the schema at loc as Compile does, checking it,
// and each subschema it reads for a reference, against its metaschema within
// budget steps of work in all (ValidateWithBudget states what a step is). When
// the checks would take more, it returns a *BudgetExceededError, never a
// schema; a budget of 0 or less admits no step. The compiler's own reading
// of the schema is not counted.
func (c *Compiler) CompileWithBudget(loc string, budget int64) (*Schema, error) { // metaschema budget
	b := &workBudget{left: budget}          // metaschema budget
	c.roots.budget = b                      // metaschema budget
	defer func() { c.roots.budget = nil }() // metaschema budget
	sch, err := c.Compile(loc)              // metaschema budget
	if b.exceeded || budget <= 0 {          // metaschema budget
		return nil, &BudgetExceededError{Budget: budget, Nested: b.nested} // metaschema budget
	} // metaschema budget
	return sch, err // metaschema budget
} // metaschema budget

// MustCompile is like [Compile] but panics if compilation fails.
// It simplifies safe initialization of global variables holding
// compiled schema.
func (c *Compiler) MustCompile(loc string) *Schema {
	sch, err := c.Compile(loc)
	if err != nil {
		panic(fmt.Sprintf("jsonschema: Compile(%q): %v", loc, err))
	}
	return sch
}

// Compile compiles json-schema at given loc.
func (c *Compiler) Compile(loc string) (*Schema, error) {
	uf, err := absolute(loc)
	if err != nil {
		return nil, err
	}
	up, err := c.roots.resolveFragment(*uf)
	if err != nil {
		return nil, err
	}
	return c.doCompile(up)
}

func (c *Compiler) doCompile(up urlPtr) (*Schema, error) {
	q := &queue{}
	compiled := 0

	c.enqueue(q, up)
	for q.len() > compiled {
		sch := q.at(compiled)
		if err := c.roots.ensureSubschema(sch.up); err != nil {
			return nil, err
		}
		r := c.roots.roots[sch.up.url]
		v, err := sch.up.lookup(r.doc)
		if err != nil {
			return nil, err
		}
		if err := c.compileValue(v, sch, r, q); err != nil {
			return nil, err
		}
		compiled++
	}
	for _, sch := range q.list { // compile index
		c.schemas[sch.up] = sch
	}
	return c.schemas[up], nil
}

func (c *Compiler) compileValue(v any, sch *Schema, r *root, q *queue) error {
	res := r.resource(sch.up.ptr)
	sch.DraftVersion = res.dialect.draft.version

	base := urlPtr{sch.up.url, res.ptr}
	sch.resource = c.enqueue(q, base)

	// if resource, enqueue dynamic anchors for compilation
	if sch.DraftVersion >= 2020 && sch.up == sch.resource.up {
		res := r.resource(sch.up.ptr)
		for _, anchor := range res.dynamicAnchors { // dynamic anchor set: each dynamic anchor, found in the anchors, rather than each anchor searched for in the dynamic ones
			if anchorPtr, ok := res.anchors[anchor]; ok { // dynamic anchor set
				up := urlPtr{sch.up.url, anchorPtr}
				danchorSch := c.enqueue(q, up)
				if sch.dynamicAnchors == nil {
					sch.dynamicAnchors = map[string]*Schema{}
				}
				sch.dynamicAnchors[string(anchor)] = danchorSch
			}
		}
	}

	switch v := v.(type) {
	case bool:
		sch.Bool = &v
	case map[string]any:
		if err := c.compileObject(v, sch, r, q); err != nil {
			return err
		}
	}

	sch.allPropsEvaluated = sch.AdditionalProperties != nil
	if sch.DraftVersion < 2020 {
		sch.allItemsEvaluated = sch.AdditionalItems != nil
		switch items := sch.Items.(type) {
		case *Schema:
			sch.allItemsEvaluated = true
		case []*Schema:
			sch.numItemsEvaluated = len(items)
		}
	} else {
		sch.allItemsEvaluated = sch.Items2020 != nil
		sch.numItemsEvaluated = len(sch.PrefixItems)
	}

	return nil
}

func (c *Compiler) compileObject(obj map[string]any, sch *Schema, r *root, q *queue) error {
	if len(obj) == 0 {
		b := true
		sch.Bool = &b
		return nil
	}
	oc := objCompiler{
		c:   c,
		obj: obj,
		up:  sch.up,
		r:   r,
		res: r.resource(sch.up.ptr),
		q:   q,
	}
	return oc.compile(sch)
}

// queue --

// queue is the subschemas one Compile compiles, in the order they were
// found, with an index by location, so a lookup takes constant time rather
// than a search of the list.
type queue struct { // compile index
	list  []*Schema          // compile index
	index map[urlPtr]*Schema // compile index
	refs  map[refKey]*Schema // reference index: the target of each local reference, by the URL it resolves to
} // compile index

// refKey is a reference resolved in a root: the root's URL, and the URL and
// decoded fragment the reference resolves to.
type refKey struct { // reference index
	root url     // reference index
	uf   urlFrag // reference index
} // reference index

// addRef records the target of a local reference, so a reference that
// resolves to the same URL in the same root takes it from here rather than
// building the target's location again: a resource's id stays with the one
// resource for the compile, so its target does not change.
func (q *queue) addRef(key refKey, sch *Schema) { // reference index
	if q.refs == nil { // reference index
		q.refs = map[refKey]*Schema{} // reference index
	} // reference index
	q.refs[key] = sch // reference index
} // reference index

func (q *queue) append(sch *Schema) {
	q.list = append(q.list, sch) // compile index
	if q.index == nil {          // compile index
		q.index = map[urlPtr]*Schema{} // compile index
	} // compile index
	if _, ok := q.index[sch.up]; !ok { // compile index: the first one, as the search found
		q.index[sch.up] = sch // compile index
	} // compile index
}

func (q *queue) at(i int) *Schema {
	return q.list[i] // compile index
}

func (q *queue) len() int {
	return len(q.list) // compile index
}

func (q *queue) get(up urlPtr) *Schema {
	return q.index[up] // compile index
}

// regexp --

// Regexp is the representation of compiled regular expression.
type Regexp interface {
	fmt.Stringer

	// MatchString reports whether the string s contains
	// any match of the regular expression.
	MatchString(string) bool
}

// RegexpEngine parses a regular expression and returns,
// if successful, a Regexp object that can be used to
// match against text.
type RegexpEngine func(string) (Regexp, error)

func (re RegexpEngine) validate(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	_, err := re(s)
	return err
}

func goRegexpCompile(s string) (Regexp, error) {
	return regexp.Compile(s)
}
