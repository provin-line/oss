// Changed by 1o1 Co. Ltd. for github.com/provin-line/oss: a work budget (the
// lines marked "work budget"), the resources found by an index by id (the
// lines marked "resource index"), a subschema read for a reference added in
// place, recorded so a failure takes it back (the lines marked "subschema
// journal"), and the metaschema checks within a budget (the lines marked
// "metaschema budget"). See README.md in this directory.

package jsonschema

import (
	"fmt"
	"strings"
)

type roots struct {
	defaultDraft *Draft
	roots        map[url]*root
	loader       defaultLoader
	regexpEngine RegexpEngine
	vocabularies map[string]*Vocabulary
	assertVocabs bool
	budget       *workBudget // metaschema budget: the checks' budget during a CompileWithBudget call, nil otherwise
}

func newRoots() *roots {
	return &roots{
		defaultDraft: draftLatest,
		roots:        map[url]*root{},
		loader: defaultLoader{
			docs:   map[url]any{},
			loader: FileLoader{},
		},
		regexpEngine: goRegexpCompile,
		vocabularies: map[string]*Vocabulary{},
	}
}

func (rr *roots) orLoad(u url) (*root, error) {
	if r, ok := rr.roots[u]; ok {
		return r, nil
	}
	doc, err := rr.loader.load(u)
	if err != nil {
		return nil, err
	}
	return rr.addRoot(u, doc)
}

func (rr *roots) addRoot(u url, doc any) (*root, error) {
	r := &root{
		url:                 u,
		doc:                 doc,
		resources:           map[jsonPointer]*resource{},
		subschemasProcessed: map[jsonPointer]struct{}{},
	}
	if err := rr.collectResources(r, doc, u, "", dialect{rr.defaultDraft, nil}); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.String(), "http://json-schema.org/") &&
		!strings.HasPrefix(u.String(), "https://json-schema.org/") {
		if err := rr.validate(r, doc, ""); err != nil {
			return nil, err
		}
	}

	rr.roots[u] = r
	return r, nil
}

func (rr *roots) resolveFragment(uf urlFrag) (urlPtr, error) {
	r, err := rr.orLoad(uf.url)
	if err != nil {
		return urlPtr{}, err
	}
	return r.resolveFragment(uf.frag)
}

func (rr *roots) collectResources(r *root, sch any, base url, schPtr jsonPointer, fallback dialect) error {
	if _, ok := r.subschemasProcessed[schPtr]; ok {
		return nil
	}
	if err := rr._collectResources(r, sch, base, schPtr, fallback); err != nil {
		return err
	}
	r.record(func() { delete(r.subschemasProcessed, schPtr) }) // subschema journal
	r.subschemasProcessed[schPtr] = struct{}{}
	return nil
}

func (rr *roots) _collectResources(r *root, sch any, base url, schPtr jsonPointer, fallback dialect) error {
	obj, ok := sch.(map[string]any)
	if !ok {
		if schPtr.isEmpty() {
			// root resource
			res := newResource(schPtr, base)
			res.dialect = fallback
			r.addResource(schPtr, res) // resource index
		}
		return nil
	}

	hasSchema := false
	if sch, ok := obj["$schema"]; ok {
		if _, ok := sch.(string); ok {
			hasSchema = true
		}
	}

	draft, err := rr.loader.getDraft(urlPtr{r.url, schPtr}, sch, fallback.draft, map[url]struct{}{})
	if err != nil {
		return err
	}
	id := draft.getID(obj)
	if id == "" && !schPtr.isEmpty() {
		// ignore $schema
		draft = fallback.draft
		hasSchema = false
		id = draft.getID(obj)
	}

	var res *resource
	if id != "" {
		uf, err := base.join(id)
		if err != nil {
			loc := urlPtr{r.url, schPtr}
			return &ParseIDError{loc.String()}
		}
		base = uf.url
		res = newResource(schPtr, base)
	} else if schPtr.isEmpty() {
		// root resource
		res = newResource(schPtr, base)
	}

	if res != nil {
		found := false
		if res, ok := r.ids[base]; ok { // resource index
			found = true
			if res.ptr != schPtr {
				return &DuplicateIDError{base.String(), r.url.String(), string(schPtr), string(res.ptr)}
			}
		}
		if !found {
			if hasSchema {
				vocabs, err := rr.loader.getMetaVocabs(sch, draft, rr.vocabularies)
				if err != nil {
					return err
				}
				res.dialect = dialect{draft, vocabs}
			} else {
				res.dialect = fallback
			}
			r.addResource(schPtr, res) // resource index
		}
	}

	baseRes := r.ids[base] // resource index
	if baseRes == nil {
		panic("baseres is nil")
	}

	// found base resource
	if err := r.collectAnchors(sch, schPtr, baseRes); err != nil {
		return err
	}

	// process subschemas
	subschemas := map[jsonPointer]any{}
	for _, sp := range draft.subschemas {
		ss := sp.collect(obj, schPtr)
		for k, v := range ss {
			subschemas[k] = v
		}
	}
	for _, vocab := range baseRes.dialect.activeVocabs(true, rr.vocabularies) {
		if v := rr.vocabularies[vocab]; v != nil {
			for _, sp := range v.Subschemas {
				ss := sp.collect(obj, schPtr)
				for k, v := range ss {
					subschemas[k] = v
				}
			}
		}
	}
	for ptr, v := range subschemas {
		if err := rr.collectResources(r, v, base, ptr, baseRes.dialect); err != nil {
			return err
		}
	}

	return nil
}

func (rr *roots) ensureSubschema(up urlPtr) error {
	r, err := rr.orLoad(up.url)
	if err != nil {
		return err
	}
	if _, ok := r.subschemasProcessed[up.ptr]; ok {
		return nil
	}
	v, err := up.lookup(r.doc)
	if err != nil {
		return err
	}
	// The subschema is added to the root in place, each addition recorded,
	// and a failure to add or check it takes them back, last first: as
	// upstream's copy of the root did, a subschema is admitted whole or not
	// at all, without a copy of the root for each subschema.
	var journal []func()             // subschema journal
	r.journal = &journal             // subschema journal
	err = rr.addSubschema(r, up.ptr) // subschema journal
	if err == nil {                  // subschema journal
		err = rr.validate(r, v, up.ptr) // subschema journal
	} // subschema journal
	r.journal = nil // subschema journal
	if err != nil { // subschema journal
		for i := len(journal) - 1; i >= 0; i-- { // subschema journal
			journal[i]() // subschema journal
		} // subschema journal
		return err // subschema journal
	} // subschema journal
	return nil
}

func (rr *roots) addSubschema(r *root, ptr jsonPointer) error {
	v, err := (&urlPtr{r.url, ptr}).lookup(r.doc)
	if err != nil {
		return err
	}
	base := r.resource(ptr)
	baseURL := base.id
	if err := rr.collectResources(r, v, baseURL, ptr, base.dialect); err != nil {
		return err
	}

	// collect anchors
	if _, ok := r.resources[ptr]; !ok {
		res := r.resource(ptr)
		if err := r.collectAnchors(v, ptr, res); err != nil {
			return err
		}
	}
	return nil
}

func (rr *roots) validate(r *root, v any, ptr jsonPointer) error {
	dialect := r.resource(ptr).dialect
	meta := dialect.getSchema(rr.assertVocabs, rr.vocabularies)
	if err := meta.validate(v, rr.regexpEngine, meta, r.resources, rr.assertVocabs, rr.vocabularies, rr.budget, 0); err != nil { // work budget: nil is unlimited; metaschema budget
		up := urlPtr{r.url, ptr}
		return &SchemaValidationError{URL: up.String(), Err: err}
	}
	return nil
}

// --

type InvalidMetaSchemaURLError struct {
	URL string
	Err error
}

func (e *InvalidMetaSchemaURLError) Error() string {
	return fmt.Sprintf("invalid $schema in %q: %v", e.URL, e.Err)
}

// --

type UnsupportedDraftError struct {
	URL string
}

func (e *UnsupportedDraftError) Error() string {
	return fmt.Sprintf("draft %q is not supported", e.URL)
}

// --

type MetaSchemaCycleError struct {
	URL string
}

func (e *MetaSchemaCycleError) Error() string {
	return fmt.Sprintf("cycle in resolving $schema in %q", e.URL)
}

// --

type MetaSchemaMismatchError struct {
	URL string
}

func (e *MetaSchemaMismatchError) Error() string {
	return fmt.Sprintf("$schema in %q does not match with $schema in root", e.URL)
}
