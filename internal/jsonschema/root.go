// Changed by 1o1 Co. Ltd. for github.com/provin-line/oss: the resources are
// also indexed by id (the lines marked "resource index"), and a subschema
// read for a reference is added in place, recorded so a failure takes it
// back (the lines marked "subschema journal"). See README.md in this
// directory.

package jsonschema

import (
	"fmt"
	"strings"
)

type root struct {
	url                 url
	doc                 any
	resources           map[jsonPointer]*resource
	ids                 map[url]*resource // resource index: resources by id
	subschemasProcessed map[jsonPointer]struct{}
	journal             *[]func() // subschema journal: how to take back what is added, while it is set
}

// record notes how to take back an addition to the root, while a journal is
// kept (roots.ensureSubschema).
func (r *root) record(undo func()) { // subschema journal
	if r.journal != nil { // subschema journal
		*r.journal = append(*r.journal, undo) // subschema journal
	} // subschema journal
} // subschema journal

// addResource adds res at ptr, indexed by its id too, so finding a resource
// by id takes constant time rather than a search of every resource.
func (r *root) addResource(ptr jsonPointer, res *resource) { // resource index
	prevRes, hadRes := r.resources[ptr] // subschema journal
	prevID, hadID := r.ids[res.id]      // subschema journal
	r.record(func() {                   // subschema journal
		if hadRes { // subschema journal
			r.resources[ptr] = prevRes // subschema journal
		} else { // subschema journal
			delete(r.resources, ptr) // subschema journal
		} // subschema journal
		if hadID { // subschema journal
			r.ids[res.id] = prevID // subschema journal
		} else { // subschema journal
			delete(r.ids, res.id) // subschema journal
		} // subschema journal
	}) // subschema journal
	r.resources[ptr] = res // resource index
	if r.ids == nil {      // resource index
		r.ids = map[url]*resource{} // resource index
	} // resource index
	r.ids[res.id] = res // resource index
} // resource index

func (r *root) rootResource() *resource {
	return r.resources[""]
}

func (r *root) resource(ptr jsonPointer) *resource {
	for {
		if res, ok := r.resources[ptr]; ok {
			return res
		}
		slash := strings.LastIndexByte(string(ptr), '/')
		if slash == -1 {
			break
		}
		ptr = ptr[:slash]
	}
	return r.rootResource()
}

func (r *root) resolveFragmentIn(frag fragment, res *resource) (urlPtr, error) {
	var ptr jsonPointer
	switch f := frag.convert().(type) {
	case jsonPointer:
		ptr = res.ptr.concat(f)
	case anchor:
		aptr, ok := res.anchors[f]
		if !ok {
			return urlPtr{}, &AnchorNotFoundError{
				URL:       r.url.String(),
				Reference: (&urlFrag{res.id, frag}).String(),
			}
		}
		ptr = aptr
	}
	return urlPtr{r.url, ptr}, nil
}

func (r *root) resolveFragment(frag fragment) (urlPtr, error) {
	return r.resolveFragmentIn(frag, r.rootResource())
}

// resolves urlFrag to urlPtr from root.
// returns nil if it is external.
func (r *root) resolve(uf urlFrag) (*urlPtr, error) {
	var res *resource
	if uf.url == r.url {
		res = r.rootResource()
	} else {
		// look for resource with id==uf.url
		res = r.ids[uf.url] // resource index
		if res == nil {
			return nil, nil // external url
		}
	}
	up, err := r.resolveFragmentIn(uf.frag, res)
	return &up, err
}

func (r *root) collectAnchors(sch any, schPtr jsonPointer, res *resource) error {
	obj, ok := sch.(map[string]any)
	if !ok {
		return nil
	}

	addAnchor := func(anchor anchor) error {
		ptr1, ok := res.anchors[anchor]
		if ok {
			if ptr1 == schPtr {
				// anchor with same root_ptr already exists
				return nil
			}
			return &DuplicateAnchorError{
				string(anchor), r.url.String(), string(ptr1), string(schPtr),
			}
		}
		r.record(func() { delete(res.anchors, anchor) }) // subschema journal
		res.anchors[anchor] = schPtr
		return nil
	}

	if res.dialect.draft.version < 2019 {
		if _, ok := obj["$ref"]; ok {
			// All other properties in a "$ref" object MUST be ignored
			return nil
		}
		// anchor is specified in id
		if id, ok := strVal(obj, res.dialect.draft.id); ok {
			_, frag, err := splitFragment(id)
			if err != nil {
				loc := urlPtr{r.url, schPtr}
				return &ParseAnchorError{loc.String()}
			}
			if anchor, ok := frag.convert().(anchor); ok {
				if err := addAnchor(anchor); err != nil {
					return err
				}
			}
		}
	}
	if res.dialect.draft.version >= 2019 {
		if s, ok := strVal(obj, "$anchor"); ok {
			if err := addAnchor(anchor(s)); err != nil {
				return err
			}
		}
	}
	if res.dialect.draft.version >= 2020 {
		if s, ok := strVal(obj, "$dynamicAnchor"); ok {
			if err := addAnchor(anchor(s)); err != nil {
				return err
			}
			n := len(res.dynamicAnchors)                                     // subschema journal
			r.record(func() { res.dynamicAnchors = res.dynamicAnchors[:n] }) // subschema journal
			res.dynamicAnchors = append(res.dynamicAnchors, anchor(s))
		}
	}

	return nil
}

// --

type resource struct {
	ptr            jsonPointer
	id             url
	dialect        dialect
	anchors        map[anchor]jsonPointer
	dynamicAnchors []anchor
}

func newResource(ptr jsonPointer, id url) *resource {
	return &resource{ptr: ptr, id: id, anchors: make(map[anchor]jsonPointer)}
}

//--

type UnsupportedVocabularyError struct {
	URL        string
	Vocabulary string
}

func (e *UnsupportedVocabularyError) Error() string {
	return fmt.Sprintf("unsupported vocabulary %q in %q", e.Vocabulary, e.URL)
}

// --

type AnchorNotFoundError struct {
	URL       string
	Reference string
}

func (e *AnchorNotFoundError) Error() string {
	return fmt.Sprintf("anchor in %q not found in schema %q", e.Reference, e.URL)
}
