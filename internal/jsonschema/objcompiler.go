// Changed by 1o1 Co. Ltd. for github.com/provin-line/oss: a work budget (the
// lines marked "work budget"), a reference's target found once for each URL
// it resolves to (the lines marked "reference index"), a number keyword whose
// number cannot be read refused (the lines marked "number keyword"), and an
// integer keyword beyond int read as the nearest int (the lines marked
// "integer keyword"). See README.md in this directory.

package jsonschema

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
)

type objCompiler struct {
	c   *Compiler
	obj map[string]any
	up  urlPtr
	r   *root
	res *resource
	q   *queue
}

func (c *objCompiler) compile(s *Schema) error {
	// id --
	if id := c.res.dialect.draft.getID(c.obj); id != "" {
		s.ID = id
	}

	// anchor --
	if s.DraftVersion < 2019 {
		// anchor is specified in id
		id := c.string(c.res.dialect.draft.id)
		if id != "" {
			_, f := split(id)
			if f != "" {
				var err error
				s.Anchor, err = decode(f)
				if err != nil {
					return &ParseAnchorError{URL: s.Location}
				}
			}
		}
	} else {
		s.Anchor = c.string("$anchor")
	}

	if err := c.compileDraft4(s); err != nil {
		return err
	}
	if s.DraftVersion >= 6 {
		if err := c.compileDraft6(s); err != nil {
			return err
		}
	}
	if s.DraftVersion >= 7 {
		if err := c.compileDraft7(s); err != nil {
			return err
		}
	}
	if s.DraftVersion >= 2019 {
		if err := c.compileDraft2019(s); err != nil {
			return err
		}
	}
	if s.DraftVersion >= 2020 {
		if err := c.compileDraft2020(s); err != nil {
			return err
		}
	}

	// vocabularies
	vocabs := c.res.dialect.activeVocabs(c.c.roots.assertVocabs, c.c.roots.vocabularies)
	for _, vocab := range vocabs {
		v := c.c.roots.vocabularies[vocab]
		if v == nil {
			continue
		}
		ext, err := v.Compile(&CompilerContext{c}, c.obj)
		if err != nil {
			return err
		}
		if ext != nil {
			s.Extensions = append(s.Extensions, ext)
		}
	}

	return nil
}

func (c *objCompiler) compileDraft4(s *Schema) error {
	var err error

	if c.hasVocab("core") {
		if s.Ref, err = c.enqueueRef("$ref"); err != nil {
			return err
		}
		if s.DraftVersion < 2019 && s.Ref != nil {
			// All other properties in a "$ref" object MUST be ignored
			return nil
		}
	}

	if c.hasVocab("applicator") {
		s.AllOf = c.enqueueArr("allOf")
		s.AnyOf = c.enqueueArr("anyOf")
		s.OneOf = c.enqueueArr("oneOf")
		s.Not = c.enqueueProp("not")

		if s.DraftVersion < 2020 {
			if items, ok := c.obj["items"]; ok {
				if _, ok := items.([]any); ok {
					s.Items = c.enqueueArr("items")
					s.AdditionalItems = c.enqueueAdditional("additionalItems")
				} else {
					s.Items = c.enqueueProp("items")
				}
			}
		}

		s.Properties = c.enqueueMap("properties")
		if m := c.enqueueMap("patternProperties"); m != nil {
			s.PatternProperties = map[Regexp]*Schema{}
			for pname, sch := range m {
				re, err := c.c.roots.regexpEngine(pname)
				if err != nil {
					return &InvalidRegexError{c.up.format("patternProperties"), pname, err}
				}
				s.PatternProperties[re] = sch
			}
		}
		s.AdditionalProperties = c.enqueueAdditional("additionalProperties")

		if m := c.objVal("dependencies"); m != nil {
			s.Dependencies = map[string]any{}
			for pname, pvalue := range m {
				if arr, ok := pvalue.([]any); ok {
					s.Dependencies[pname] = toStrings(arr)
				} else {
					ptr := c.up.ptr.append2("dependencies", pname)
					s.Dependencies[pname] = c.enqueuePtr(ptr)
				}
			}
		}
	}

	if c.hasVocab("validation") {
		if t, ok := c.obj["type"]; ok {
			s.Types = newTypes(t)
		}
		if arr := c.arrVal("enum"); arr != nil {
			s.Enum = newEnum(arr)
		}
		if s.MultipleOf, err = c.numberKeyword("multipleOf"); err != nil { // number keyword
			return err // number keyword
		} // number keyword
		if s.Maximum, err = c.numberKeyword("maximum"); err != nil { // number keyword
			return err // number keyword
		} // number keyword
		if c.boolean("exclusiveMaximum") {
			s.ExclusiveMaximum = s.Maximum
			s.Maximum = nil
		} else if s.ExclusiveMaximum, err = c.numberKeyword("exclusiveMaximum"); err != nil { // number keyword
			return err // number keyword
		}
		if s.Minimum, err = c.numberKeyword("minimum"); err != nil { // number keyword
			return err // number keyword
		} // number keyword
		if c.boolean("exclusiveMinimum") {
			s.ExclusiveMinimum = s.Minimum
			s.Minimum = nil
		} else if s.ExclusiveMinimum, err = c.numberKeyword("exclusiveMinimum"); err != nil { // number keyword
			return err // number keyword
		}

		if s.MinLength, err = c.intKeyword("minLength"); err != nil { // integer keyword
			return err // integer keyword
		} // integer keyword
		if s.MaxLength, err = c.intKeyword("maxLength"); err != nil { // integer keyword
			return err // integer keyword
		} // integer keyword
		if pat := c.strVal("pattern"); pat != nil {
			s.Pattern, err = c.c.roots.regexpEngine(*pat)
			if err != nil {
				return &InvalidRegexError{c.up.format("pattern"), *pat, err}
			}
		}

		if s.MinItems, err = c.intKeyword("minItems"); err != nil { // integer keyword
			return err // integer keyword
		} // integer keyword
		if s.MaxItems, err = c.intKeyword("maxItems"); err != nil { // integer keyword
			return err // integer keyword
		} // integer keyword
		s.UniqueItems = c.boolean("uniqueItems")

		if s.MaxProperties, err = c.intKeyword("maxProperties"); err != nil { // integer keyword
			return err // integer keyword
		} // integer keyword
		if s.MinProperties, err = c.intKeyword("minProperties"); err != nil { // integer keyword
			return err // integer keyword
		} // integer keyword
		if arr := c.arrVal("required"); arr != nil {
			s.Required = toStrings(arr)
		}
	}

	// format --
	if c.assertFormat(s.DraftVersion) {
		if f := c.strVal("format"); f != nil {
			if *f == "regex" {
				s.Format = &Format{
					Name:     "regex",
					Validate: c.c.roots.regexpEngine.validate,
				}
				s.regexEngine = c.c.roots.regexpEngine // work budget
			} else {
				s.Format = c.c.formats[*f]
				if s.Format == nil {
					s.Format = formats[*f]
				}
			}
		}
	}

	// annotations --
	s.Title = c.string("title")
	s.Description = c.string("description")
	if v, ok := c.obj["default"]; ok {
		s.Default = &v
	}

	return nil
}

func (c *objCompiler) compileDraft6(s *Schema) error {
	if c.hasVocab("applicator") {
		s.Contains = c.enqueueProp("contains")
		s.PropertyNames = c.enqueueProp("propertyNames")
	}
	if c.hasVocab("validation") {
		if v, ok := c.obj["const"]; ok {
			s.Const = &v
		}
	}
	return nil
}

func (c *objCompiler) compileDraft7(s *Schema) error {
	if c.hasVocab("applicator") {
		s.If = c.enqueueProp("if")
		if s.If != nil {
			b := c.boolVal("if")
			if b == nil || *b {
				s.Then = c.enqueueProp("then")
			}
			if b == nil || !*b {
				s.Else = c.enqueueProp("else")
			}
		}
	}

	if c.c.assertContent {
		if ce := c.strVal("contentEncoding"); ce != nil {
			s.ContentEncoding = c.c.decoders[*ce]
			if s.ContentEncoding == nil {
				s.ContentEncoding = decoders[*ce]
			}
		}
		if cm := c.strVal("contentMediaType"); cm != nil {
			s.ContentMediaType = c.c.mediaTypes[*cm]
			if s.ContentMediaType == nil {
				s.ContentMediaType = mediaTypes[*cm]
			}
		}
	}

	// annotations --
	s.Comment = c.string("$comment")
	s.ReadOnly = c.boolean("readOnly")
	s.WriteOnly = c.boolean("writeOnly")
	if arr, ok := c.obj["examples"].([]any); ok {
		s.Examples = arr
	}

	return nil
}

func (c *objCompiler) compileDraft2019(s *Schema) error {
	var err error

	if c.hasVocab("core") {
		if s.RecursiveRef, err = c.enqueueRef("$recursiveRef"); err != nil {
			return err
		}
		s.RecursiveAnchor = c.boolean("$recursiveAnchor")
	}

	if c.hasVocab("validation") {
		if s.Contains != nil {
			if s.MinContains, err = c.intKeyword("minContains"); err != nil { // integer keyword
				return err // integer keyword
			} // integer keyword
			if s.MaxContains, err = c.intKeyword("maxContains"); err != nil { // integer keyword
				return err // integer keyword
			} // integer keyword
		}
		if m := c.objVal("dependentRequired"); m != nil {
			s.DependentRequired = map[string][]string{}
			for pname, pvalue := range m {
				if arr, ok := pvalue.([]any); ok {
					s.DependentRequired[pname] = toStrings(arr)
				}
			}
		}
	}

	if c.hasVocab("applicator") {
		s.DependentSchemas = c.enqueueMap("dependentSchemas")
	}

	var unevaluated bool
	if s.DraftVersion == 2019 {
		unevaluated = c.hasVocab("applicator")
	} else {
		unevaluated = c.hasVocab("unevaluated")
	}
	if unevaluated {
		s.UnevaluatedItems = c.enqueueProp("unevaluatedItems")
		s.UnevaluatedProperties = c.enqueueProp("unevaluatedProperties")
	}

	if c.c.assertContent {
		if s.ContentMediaType != nil && s.ContentMediaType.UnmarshalJSON != nil {
			s.ContentSchema = c.enqueueProp("contentSchema")
		}
	}

	// annotations --
	s.Deprecated = c.boolean("deprecated")

	return nil
}

func (c *objCompiler) compileDraft2020(s *Schema) error {
	if c.hasVocab("core") {
		sch, err := c.enqueueRef("$dynamicRef")
		if err != nil {
			return err
		}
		if sch != nil {
			dref := c.strVal("$dynamicRef")
			_, frag, err := splitFragment(*dref)
			if err != nil {
				return err
			}
			var anch string
			if anchor, ok := frag.convert().(anchor); ok {
				anch = string(anchor)
			}
			s.DynamicRef = &DynamicRef{sch, anch}
		}
		s.DynamicAnchor = c.string("$dynamicAnchor")
	}

	if c.hasVocab("applicator") {
		s.PrefixItems = c.enqueueArr("prefixItems")
		s.Items2020 = c.enqueueProp("items")
	}

	return nil
}

// enqueue helpers --

func (c *objCompiler) enqueuePtr(ptr jsonPointer) *Schema {
	up := urlPtr{c.up.url, ptr}
	return c.c.enqueue(c.q, up)
}

func (c *objCompiler) enqueueRef(pname string) (*Schema, error) {
	ref := c.strVal(pname)
	if ref == nil {
		return nil, nil
	}
	return c.enqueueRefVal(*ref)
}

func (c *objCompiler) enqueueRefVal(ref string) (*Schema, error) {
	baseURL := c.res.id
	// baseURL := c.r.baseURL(c.up.ptr)
	uf, err := baseURL.join(ref)
	if err != nil {
		return nil, err
	}

	key := refKey{c.r.url, *uf}       // reference index
	if sch, ok := c.q.refs[key]; ok { // reference index
		return sch, nil // reference index
	} // reference index
	up, err := c.r.resolve(*uf)
	if err != nil {
		return nil, err
	}
	if up != nil {
		// local ref
		sch := c.enqueuePtr(up.ptr) // reference index
		c.q.addRef(key, sch)        // reference index
		return sch, nil             // reference index
	}

	// remote ref
	up_, err := c.c.roots.resolveFragment(*uf)
	if err != nil {
		return nil, err
	}
	return c.c.enqueue(c.q, up_), nil
}

func (c *objCompiler) enqueueProp(pname string) *Schema {
	if _, ok := c.obj[pname]; !ok {
		return nil
	}
	ptr := c.up.ptr.append(pname)
	return c.enqueuePtr(ptr)
}

func (c *objCompiler) enqueueArr(pname string) []*Schema {
	arr := c.arrVal(pname)
	if arr == nil {
		return nil
	}
	sch := make([]*Schema, len(arr))
	for i := range arr {
		ptr := c.up.ptr.append2(pname, strconv.Itoa(i))
		sch[i] = c.enqueuePtr(ptr)
	}
	return sch
}

func (c *objCompiler) enqueueMap(pname string) map[string]*Schema {
	obj := c.objVal(pname)
	if obj == nil {
		return nil
	}
	sch := make(map[string]*Schema)
	for k := range obj {
		ptr := c.up.ptr.append2(pname, k)
		sch[k] = c.enqueuePtr(ptr)
	}
	return sch
}

func (c *objCompiler) enqueueAdditional(pname string) any {
	if b := c.boolVal(pname); b != nil {
		return *b
	}
	if sch := c.enqueueProp(pname); sch != nil {
		return sch
	}
	return nil
}

// --

func (c *objCompiler) hasVocab(name string) bool {
	return c.res.dialect.hasVocab(name)
}

func (c *objCompiler) assertFormat(draftVersion int) bool {
	if c.c.assertFormat || draftVersion < 2019 {
		return true
	}
	if draftVersion == 2019 {
		return c.hasVocab("format")
	} else {
		return c.hasVocab("format-assertion")
	}
}

// value helpers --

func (c *objCompiler) boolVal(pname string) *bool {
	v, ok := c.obj[pname]
	if !ok {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

func (c *objCompiler) boolean(pname string) bool {
	b := c.boolVal(pname)
	return b != nil && *b
}

func (c *objCompiler) strVal(pname string) *string {
	v, ok := c.obj[pname]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func (c *objCompiler) string(pname string) string {
	if s := c.strVal(pname); s != nil {
		return *s
	}
	return ""
}

func (c *objCompiler) numVal(pname string) *big.Rat {
	v, ok := c.obj[pname]
	if !ok {
		return nil
	}
	switch v.(type) {
	case json.Number, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		if n, ok := new(big.Rat).SetString(fmt.Sprint(v)); ok {
			return n
		}
	}
	return nil
}

// numberKeyword reads the number keyword pname as numVal does, but a number
// big.Rat cannot read is a *LargeNumberError, not a keyword taken as absent.
func (c *objCompiler) numberKeyword(pname string) (*big.Rat, error) { // number keyword
	if n := c.numVal(pname); n != nil { // number keyword
		return n, nil // number keyword
	} // number keyword
	switch v := c.obj[pname].(type) { // number keyword
	case json.Number, float32, float64: // number keyword
		return nil, &LargeNumberError{URL: c.up.format(pname), Value: v} // number keyword
	} // number keyword
	return nil, nil // number keyword
} // number keyword

// intKeyword reads the integer keyword pname: an integer within int as
// itself, one above math.MaxInt as math.MaxInt, one below math.MinInt as
// math.MinInt. A number big.Rat cannot read is a *LargeNumberError, and a
// number that is not an integer reads as absent.
func (c *objCompiler) intKeyword(pname string) (*int, error) { // integer keyword
	n, err := c.numberKeyword(pname)          // integer keyword
	if err != nil || n == nil || !n.IsInt() { // integer keyword
		return nil, err // integer keyword
	} // integer keyword
	i := math.MaxInt         // integer keyword
	switch num := n.Num(); { // integer keyword
	case num.IsInt64() && num.Int64() <= math.MaxInt && num.Int64() >= math.MinInt: // integer keyword
		i = int(num.Int64()) // integer keyword
	case num.Sign() < 0: // integer keyword
		i = math.MinInt // integer keyword
	} // integer keyword
	return &i, nil // integer keyword
} // integer keyword

func (c *objCompiler) objVal(pname string) map[string]any {
	v, ok := c.obj[pname]
	if !ok {
		return nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return obj
}

func (c *objCompiler) arrVal(pname string) []any {
	v, ok := c.obj[pname]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	return arr
}

// --

type InvalidRegexError struct {
	URL   string
	Regex string
	Err   error
}

func (e *InvalidRegexError) Error() string {
	return fmt.Sprintf("invalid regex %q at %q: %v", e.Regex, e.URL, e.Err)
}

// -- number keyword

// LargeNumberError reports a number keyword (minimum, maximum,
// exclusiveMinimum, exclusiveMaximum, multipleOf) or an integer keyword
// (minLength, maxLength, minItems, maxItems, minProperties, maxProperties,
// minContains, maxContains) whose number big.Rat cannot read, such as
// 1e1000001, as kind.LargeNumber reports one in a value.
type LargeNumberError struct { // number keyword
	URL   string // number keyword
	Value any    // number keyword
} // number keyword

func (e *LargeNumberError) Error() string { // number keyword
	return fmt.Sprintf("number too large to parse %v at %q", e.Value, e.URL) // number keyword
} // number keyword

// --

func toStrings(arr []any) []string {
	var strings []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			strings = append(strings, s)
		}
	}
	return strings
}
