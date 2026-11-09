// Changed by 1o1 Co. Ltd. for github.com/provin-line/oss: the import path of
// package kind, a work budget (the lines marked "work budget"), and numbers
// big.Rat cannot read reported as kind.LargeNumber (the lines marked "large
// number"). See README.md in this directory.

package jsonschema

import (
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings" // work budget
	"unicode/utf8"

	"github.com/provin-line/oss/internal/jsonschema/kind"
	"golang.org/x/text/message"
)

func (sch *Schema) Validate(v any) error {
	return sch.validate(v, nil, nil, nil, false, nil, nil, 0) // work budget: nil is unlimited
}

func (sch *Schema) validate(v any, regexpEngine RegexpEngine, meta *Schema, resources map[jsonPointer]*resource, assertVocabs bool, vocabularies map[string]*Vocabulary, budget *workBudget, outer int) error { // work budget: budget, outer
	if budget.over() { // work budget
		return errBudget()
	}
	vd := validator{
		v:            v,
		vloc:         make([]string, 0, 8),
		sch:          sch,
		scp:          &scope{sch, "", 0, nil, 0, outer}, // work budget: depth, outer
		uneval:       unevalFrom(v, sch, false),
		errors:       nil,
		boolResult:   false,
		regexpEngine: regexpEngine,
		meta:         meta,
		resources:    resources,
		assertVocabs: assertVocabs,
		vocabularies: vocabularies,
		budget:       budget, // work budget
	}
	if _, err := vd.validate(); err != nil {
		verr := err.(*ValidationError)
		var causes []*ValidationError
		if _, ok := verr.ErrorKind.(*kind.Group); ok {
			causes = verr.Causes
		} else {
			causes = []*ValidationError{verr}
		}
		return &ValidationError{
			SchemaURL:        sch.Location,
			InstanceLocation: nil,
			ErrorKind:        &kind.Schema{Location: sch.Location},
			Causes:           causes,
		}
	}

	return nil
}

type validator struct {
	v            any
	vloc         []string
	sch          *Schema
	scp          *scope
	uneval       *uneval
	errors       []*ValidationError
	boolResult   bool // is interested to know valid or not (but not actuall error)
	regexpEngine RegexpEngine

	// meta validation
	meta         *Schema                   // set only when validating with metaschema
	resources    map[jsonPointer]*resource // resources which should be validated with their dialect
	assertVocabs bool
	vocabularies map[string]*Vocabulary

	budget *workBudget // work budget: shared by every validator of one call
}

func (vd *validator) validate() (*uneval, error) {
	s := vd.sch
	v := vd.v

	if vd.budget.over() || !vd.budget.nest(vd.scp.outer+vd.scp.depth) || !vd.budget.spend(1+workOf(v)) { // work budget
		return nil, errBudget()
	}

	// boolean --
	if s.Bool != nil {
		if *s.Bool {
			return vd.uneval, nil
		} else {
			return nil, vd.error(&kind.FalseSchema{})
		}
	}

	// check cycle --
	if scp := vd.scp.checkCycle(vd.budget); scp != nil { // work budget: budget
		if vd.boolResult { // work budget: no location to build
			return nil, &ValidationError{}
		}
		if !vd.budget.spend(vd.scp.depth + scp.depth) { // work budget: kwLoc walks both
			return nil, errBudget()
		}
		loc1, ok1 := vd.scp.kwLocWithin(vd.budget) // work budget
		loc2, ok2 := scp.kwLocWithin(vd.budget)    // work budget
		if !ok1 || !ok2 {                          // work budget
			return nil, errBudget()
		}
		return nil, vd.error(&kind.RefCycle{
			URL:              s.Location,
			KeywordLocation1: loc1, // work budget
			KeywordLocation2: loc2, // work budget
		})
	}

	t := typeOf(v)
	if t == invalidType {
		return nil, vd.error(&kind.InvalidJsonValue{Value: v})
	}

	// type --
	if s.Types != nil && !s.Types.IsEmpty() {
		matched := s.Types.contains(t) || (s.Types.contains(integerType) && t == numberType && isIntegerWithin(vd.budget, v)) // work budget
		if !matched {
			return nil, vd.error(&kind.Type{Got: t.String(), Want: s.Types.ToStrings()})
		}
	}

	// const --
	if s.Const != nil {
		ok, k := equalsWithin(vd.budget, v, *s.Const) // work budget
		if k != nil {
			return nil, vd.error(k)
		} else if !ok {
			return nil, vd.error(&kind.Const{Got: v, Want: *s.Const})
		}
	}

	// enum --
	if s.Enum != nil {
		matched := s.Enum.types.contains(typeOf(v))
		if matched {
			matched = false
			for _, item := range s.Enum.Values {
				if vd.budget.over() { // work budget
					return nil, errBudget()
				}
				ok, k := equalsWithin(vd.budget, v, item) // work budget
				if k != nil {
					return nil, vd.error(k)
				} else if ok {
					matched = true
					break
				}
			}
		}
		if !matched {
			return nil, vd.error(&kind.Enum{Got: v, Want: s.Enum.Values})
		}
	}

	// format --
	if s.Format != nil {
		var err error
		if s.Format.Name == "regex" && vd.regexpEngine != nil {
			err = vd.regexpEngine.validate(v)
		} else if s.Format.Name == "regex" && s.regexEngine != nil { // work budget
			err = vd.compileRegexFormat(s.regexEngine, v) // work budget
		} else {
			err = s.Format.Validate(v)
		}
		if vd.budget.over() { // work budget
			return nil, errBudget()
		}
		if err != nil {
			return nil, vd.error(&kind.Format{Got: v, Want: s.Format.Name, Err: err})
		}
	}

	// $ref --
	if s.Ref != nil {
		err := vd.validateRef(s.Ref, "$ref")
		if s.DraftVersion < 2019 {
			return vd.uneval, err
		}
		if err != nil {
			vd.addErr(err)
		}
	}

	if vd.budget.over() { // work budget
		return nil, errBudget()
	}

	// type specific validations --
	switch v := v.(type) {
	case map[string]any:
		vd.objValidate(v)
	case []any:
		vd.arrValidate(v)
	case string:
		vd.strValidate(v)
	case json.Number, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		vd.numValidate(v)
	}

	if len(vd.errors) == 0 || !vd.boolResult {
		if s.DraftVersion >= 2019 {
			vd.validateRefs()
		}
		vd.condValidate()

		for _, ext := range s.Extensions {
			if vd.budget.over() { // work budget
				return nil, errBudget()
			}
			ext.Validate(&ValidatorContext{vd}, v)
		}

		if s.DraftVersion >= 2019 {
			vd.unevalValidate()
		}
	}

	switch len(vd.errors) {
	case 0:
		return vd.uneval, nil
	case 1:
		return nil, vd.errors[0]
	default:
		verr := vd.error(&kind.Group{})
		verr.Causes = vd.errors
		return nil, verr
	}
}

func (vd *validator) objValidate(obj map[string]any) {
	s := vd.sch

	// minProperties --
	if s.MinProperties != nil {
		if len(obj) < *s.MinProperties {
			vd.addError(&kind.MinProperties{Got: len(obj), Want: *s.MinProperties})
		}
	}

	// maxProperties --
	if s.MaxProperties != nil {
		if len(obj) > *s.MaxProperties {
			vd.addError(&kind.MaxProperties{Got: len(obj), Want: *s.MaxProperties})
		}
	}

	// required --
	if len(s.Required) > 0 {
		if missing := vd.findMissing(obj, s.Required); missing != nil {
			vd.addError(&kind.Required{Missing: missing})
		}
	}

	if vd.boolResult && len(vd.errors) > 0 {
		return
	}

	// dependencies --
	for pname, dep := range s.Dependencies {
		if !vd.budget.spend(1 + len(pname)) { // work budget: the lookup hashes the name
			return
		}
		if _, ok := obj[pname]; ok {
			switch dep := dep.(type) {
			case []string:
				if missing := vd.findMissing(obj, dep); missing != nil {
					vd.addError(&kind.Dependency{Prop: pname, Missing: missing})
				}
			case *Schema:
				vd.addErr(vd.validateSelf(dep, "", false))
			}
		}
	}

	var additionalPros []string
	for pname, pvalue := range obj {
		if vd.boolResult && len(vd.errors) > 0 || vd.budget.over() { // work budget: over
			return
		}
		evaluated := false

		// properties --
		if sch, ok := s.Properties[pname]; ok {
			evaluated = true
			vd.addErr(vd.validateVal(sch, pvalue, pname))
		}

		// patternProperties --
		for regex, sch := range s.PatternProperties {
			if !vd.budget.spendSteps(product(int64(len(pname))+1, int64(patternSize(regex)/PatternInstructionsPerStep)+1)) { // work budget
				break
			}
			if regex.MatchString(pname) {
				evaluated = true
				vd.addErr(vd.validateVal(sch, pvalue, pname))
			}
		}

		if !evaluated && s.AdditionalProperties != nil {
			evaluated = true
			switch additional := s.AdditionalProperties.(type) {
			case bool:
				if !additional {
					additionalPros = append(additionalPros, pname)
				}
			case *Schema:
				vd.addErr(vd.validateVal(additional, pvalue, pname))
			}
		}

		if evaluated {
			delete(vd.uneval.props, pname)
		}
	}
	if len(additionalPros) > 0 {
		vd.addError(&kind.AdditionalProperties{Properties: additionalPros})
	}

	if s.DraftVersion == 4 {
		return
	}

	// propertyNames --
	if s.PropertyNames != nil {
		for pname := range obj {
			if vd.budget.over() { // work budget
				return
			}
			sch, meta, resources := s.PropertyNames, vd.meta, vd.resources
			res := vd.metaResource(sch)
			if res != nil {
				meta = res.dialect.getSchema(vd.assertVocabs, vd.vocabularies)
				sch = meta
			}
			if err := sch.validate(pname, vd.regexpEngine, meta, resources, vd.assertVocabs, vd.vocabularies, vd.budget, vd.scp.outer+vd.scp.depth+1); err != nil { // work budget
				verr := err.(*ValidationError)
				verr.InstanceLocation = vd.vloc
				verr.SchemaURL = s.PropertyNames.Location
				verr.ErrorKind = &kind.PropertyNames{Property: pname}
				vd.addErr(verr)
			}
		}
	}

	if s.DraftVersion == 6 {
		return
	}

	// dependentSchemas --
	for pname, sch := range s.DependentSchemas {
		if !vd.budget.spend(1 + len(pname)) { // work budget: the lookup hashes the name
			return
		}
		if _, ok := obj[pname]; ok {
			vd.addErr(vd.validateSelf(sch, "", false))
		}
	}

	// dependentRequired --
	for pname, reqd := range s.DependentRequired {
		if !vd.budget.spend(1 + len(pname)) { // work budget: the lookup hashes the name
			return
		}
		if _, ok := obj[pname]; ok {
			if missing := vd.findMissing(obj, reqd); missing != nil {
				vd.addError(&kind.DependentRequired{Prop: pname, Missing: missing})
			}
		}
	}
}

func (vd *validator) arrValidate(arr []any) {
	s := vd.sch

	// minItems --
	if s.MinItems != nil {
		if len(arr) < *s.MinItems {
			vd.addError(&kind.MinItems{Got: len(arr), Want: *s.MinItems})
		}
	}

	// maxItems --
	if s.MaxItems != nil {
		if len(arr) > *s.MaxItems {
			vd.addError(&kind.MaxItems{Got: len(arr), Want: *s.MaxItems})
		}
	}

	// uniqueItems --
	if s.UniqueItems && len(arr) > 1 {
		i, j, k := duplicatesWithin(vd.budget, arr) // work budget
		if k != nil {
			vd.addError(k)
		} else if i != -1 {
			vd.addError(&kind.UniqueItems{Duplicates: [2]int{i, j}})
		}
	}

	if s.DraftVersion < 2020 {
		evaluated := 0

		// items --
		switch items := s.Items.(type) {
		case *Schema:
			for i, item := range arr {
				if vd.budget.over() { // work budget
					return
				}
				vd.addErr(vd.validateVal(items, item, strconv.Itoa(i)))
			}
			evaluated = len(arr)
		case []*Schema:
			min := minInt(len(arr), len(items))
			for i, item := range arr[:min] {
				if vd.budget.over() { // work budget
					return
				}
				vd.addErr(vd.validateVal(items[i], item, strconv.Itoa(i)))
			}
			evaluated = min
		}

		// additionalItems --
		if s.AdditionalItems != nil {
			switch additional := s.AdditionalItems.(type) {
			case bool:
				if !additional && evaluated != len(arr) {
					vd.addError(&kind.AdditionalItems{Count: len(arr) - evaluated})
				}
			case *Schema:
				for i, item := range arr[evaluated:] {
					if vd.budget.over() { // work budget
						return
					}
					vd.addErr(vd.validateVal(additional, item, strconv.Itoa(evaluated+i)))
				}
			}
		}
	} else {
		evaluated := minInt(len(s.PrefixItems), len(arr))

		// prefixItems --
		for i, item := range arr[:evaluated] {
			if vd.budget.over() { // work budget
				return
			}
			vd.addErr(vd.validateVal(s.PrefixItems[i], item, strconv.Itoa(i)))
		}

		// items2020 --
		if s.Items2020 != nil {
			for i, item := range arr[evaluated:] {
				if vd.budget.over() { // work budget
					return
				}
				vd.addErr(vd.validateVal(s.Items2020, item, strconv.Itoa(evaluated+i)))
			}
		}
	}

	// contains --
	if s.Contains != nil {
		var errors []*ValidationError
		var matched []int

		for i, item := range arr {
			if vd.budget.over() { // work budget
				return
			}
			if err := vd.validateVal(s.Contains, item, strconv.Itoa(i)); err != nil {
				errors = append(errors, err.(*ValidationError))
			} else {
				matched = append(matched, i)
				if s.DraftVersion >= 2020 {
					delete(vd.uneval.items, i)
				}
			}
		}

		// minContains --
		if s.MinContains != nil {
			if len(matched) < *s.MinContains {
				vd.addErrors(errors, &kind.MinContains{Got: matched, Want: *s.MinContains})
			}
		} else if len(matched) == 0 {
			vd.addErrors(errors, &kind.Contains{})
		}

		// maxContains --
		if s.MaxContains != nil {
			if len(matched) > *s.MaxContains {
				vd.addError(&kind.MaxContains{Got: matched, Want: *s.MaxContains})
			}
		}
	}
}

func (vd *validator) strValidate(str string) {
	s := vd.sch

	strLen := -1
	if s.MinLength != nil || s.MaxLength != nil {
		strLen = utf8.RuneCount([]byte(str))
	}

	// minLength --
	if s.MinLength != nil {
		if strLen < *s.MinLength {
			vd.addError(&kind.MinLength{Got: strLen, Want: *s.MinLength})
		}
	}

	// maxLength --
	if s.MaxLength != nil {
		if strLen > *s.MaxLength {
			vd.addError(&kind.MaxLength{Got: strLen, Want: *s.MaxLength})
		}
	}

	// pattern --
	if s.Pattern != nil {
		if !vd.budget.spendSteps(product(int64(len(str))+1, int64(patternSize(s.Pattern)/PatternInstructionsPerStep))) { // work budget
			return
		}
		if !s.Pattern.MatchString(str) {
			vd.addError(&kind.Pattern{Got: str, Want: s.Pattern.String()})
		}
	}

	if s.DraftVersion == 6 {
		return
	}

	var err error

	// contentEncoding --
	decoded := []byte(str)
	if s.ContentEncoding != nil {
		decoded, err = s.ContentEncoding.Decode(str)
		if err != nil {
			decoded = nil
			vd.addError(&kind.ContentEncoding{Want: s.ContentEncoding.Name, Err: err})
		}
	}

	var deserialized *any
	if decoded != nil && s.ContentMediaType != nil {
		if s.ContentSchema == nil {
			err = s.ContentMediaType.Validate(decoded)
		} else {
			var value any
			value, err = s.ContentMediaType.UnmarshalJSON(decoded)
			if err == nil {
				deserialized = &value
			}
		}
		if err != nil {
			vd.addError(&kind.ContentMediaType{
				Got:  decoded,
				Want: s.ContentMediaType.Name,
				Err:  err,
			})
		}
	}

	if deserialized != nil && s.ContentSchema != nil {
		sch, meta, resources := s.ContentSchema, vd.meta, vd.resources
		res := vd.metaResource(sch)
		if res != nil {
			meta = res.dialect.getSchema(vd.assertVocabs, vd.vocabularies)
			sch = meta
		}
		if err = sch.validate(*deserialized, vd.regexpEngine, meta, resources, vd.assertVocabs, vd.vocabularies, vd.budget, vd.scp.outer+vd.scp.depth+1); err != nil { // work budget
			verr := err.(*ValidationError)
			verr.InstanceLocation = vd.vloc
			verr.SchemaURL = s.Location
			verr.ErrorKind = &kind.ContentSchema{}
			vd.addErr(verr)
		}
	}
}

func (vd *validator) numValidate(v any) {
	s := vd.sch
	if !vd.spendNumber(v) { // work budget
		return
	}

	if s.Minimum == nil && s.Maximum == nil && // large number
		s.ExclusiveMinimum == nil && s.ExclusiveMaximum == nil && // large number
		s.MultipleOf == nil { // large number
		return // large number
	} // large number
	num, ok := new(big.Rat).SetString(fmt.Sprintf("%v", v)) // large number
	if !ok {                                                // large number
		vd.addError(&kind.LargeNumber{Value: v}) // large number
		return                                   // large number
	} // large number

	// minimum --
	if s.Minimum != nil && num.Cmp(s.Minimum) < 0 { // large number
		vd.addError(&kind.Minimum{Got: num, Want: s.Minimum}) // large number
	}

	// maximum --
	if s.Maximum != nil && num.Cmp(s.Maximum) > 0 { // large number
		vd.addError(&kind.Maximum{Got: num, Want: s.Maximum}) // large number
	}

	// exclusiveMinimum
	if s.ExclusiveMinimum != nil && num.Cmp(s.ExclusiveMinimum) <= 0 { // large number
		vd.addError(&kind.ExclusiveMinimum{Got: num, Want: s.ExclusiveMinimum}) // large number
	}

	// exclusiveMaximum
	if s.ExclusiveMaximum != nil && num.Cmp(s.ExclusiveMaximum) >= 0 { // large number
		vd.addError(&kind.ExclusiveMaximum{Got: num, Want: s.ExclusiveMaximum}) // large number
	}

	// multipleOf
	if s.MultipleOf != nil {
		if q := new(big.Rat).Quo(num, s.MultipleOf); !q.IsInt() { // large number
			vd.addError(&kind.MultipleOf{Got: num, Want: s.MultipleOf}) // large number
		}
	}
}

func (vd *validator) condValidate() {
	s := vd.sch

	// not --
	if s.Not != nil {
		if vd.validateSelf(s.Not, "", true) == nil {
			vd.addError(&kind.Not{})
		}
	}

	// allOf --
	if len(s.AllOf) > 0 {
		var errors []*ValidationError
		for _, sch := range s.AllOf {
			if vd.budget.over() { // work budget
				return
			}
			if err := vd.validateSelf(sch, "", false); err != nil {
				errors = append(errors, err.(*ValidationError))
				if vd.boolResult {
					break
				}
			}
		}
		if len(errors) != 0 {
			vd.addErrors(errors, &kind.AllOf{})
		}
	}

	// anyOf
	if len(s.AnyOf) > 0 {
		var matched bool
		var errors []*ValidationError
		for _, sch := range s.AnyOf {
			if vd.budget.over() { // work budget
				return
			}
			if err := vd.validateSelf(sch, "", false); err != nil {
				errors = append(errors, err.(*ValidationError))
			} else {
				matched = true
				// for uneval, all schemas must be evaluated
				if vd.uneval.isEmpty() {
					break
				}
			}
		}
		if !matched {
			vd.addErrors(errors, &kind.AnyOf{})
		}
	}

	// oneOf
	if len(s.OneOf) > 0 {
		var matched = -1
		var errors []*ValidationError
		for i, sch := range s.OneOf {
			if vd.budget.over() { // work budget
				return
			}
			if err := vd.validateSelf(sch, "", matched != -1); err != nil {
				if matched == -1 {
					errors = append(errors, err.(*ValidationError))
				}
			} else {
				if matched == -1 {
					matched = i
				} else {
					vd.addError(&kind.OneOf{Subschemas: []int{matched, i}})
					break
				}
			}
		}
		if matched == -1 {
			vd.addErrors(errors, &kind.OneOf{Subschemas: nil})
		}
	}

	// if, then, else --
	if s.If != nil {
		if vd.validateSelf(s.If, "", true) == nil {
			if s.Then != nil {
				vd.addErr(vd.validateSelf(s.Then, "", false))
			}
		} else if s.Else != nil {
			vd.addErr(vd.validateSelf(s.Else, "", false))
		}
	}
}

func (vd *validator) unevalValidate() {
	s := vd.sch

	// unevaluatedProperties
	if obj, ok := vd.v.(map[string]any); ok && s.UnevaluatedProperties != nil {
		for pname := range vd.uneval.props {
			if vd.budget.over() { // work budget
				return
			}
			if pvalue, ok := obj[pname]; ok {
				vd.addErr(vd.validateVal(s.UnevaluatedProperties, pvalue, pname))
			}
		}
		vd.uneval.props = nil
	}

	// unevaluatedItems
	if arr, ok := vd.v.([]any); ok && s.UnevaluatedItems != nil {
		for i := range vd.uneval.items {
			if vd.budget.over() { // work budget
				return
			}
			vd.addErr(vd.validateVal(s.UnevaluatedItems, arr[i], strconv.Itoa(i)))
		}
		vd.uneval.items = nil
	}
}

// validation helpers --

func (vd *validator) validateSelf(sch *Schema, refKw string, boolResult bool) error {
	if vd.budget.over() { // work budget
		return errBudget()
	}
	scp := vd.scp.child(sch, refKw, vd.scp.vid)
	uneval := unevalFrom(vd.v, sch, !vd.uneval.isEmpty())
	subvd := validator{
		v:            vd.v,
		vloc:         vd.vloc,
		sch:          sch,
		scp:          scp,
		uneval:       uneval,
		errors:       nil,
		boolResult:   vd.boolResult || boolResult,
		regexpEngine: vd.regexpEngine,
		meta:         vd.meta,
		resources:    vd.resources,
		assertVocabs: vd.assertVocabs,
		vocabularies: vd.vocabularies,
		budget:       vd.budget, // work budget
	}
	subvd.handleMeta()
	uneval, err := subvd.validate()
	if err == nil {
		vd.uneval.merge(uneval)
	}
	return err
}

func (vd *validator) validateVal(sch *Schema, v any, vtok string) error {
	if vd.budget.over() { // work budget
		return errBudget()
	}
	vloc := append(vd.vloc, vtok)
	scp := vd.scp.child(sch, "", vd.scp.vid+1)
	uneval := unevalFrom(v, sch, false)
	subvd := validator{
		v:            v,
		vloc:         vloc,
		sch:          sch,
		scp:          scp,
		uneval:       uneval,
		errors:       nil,
		boolResult:   vd.boolResult,
		regexpEngine: vd.regexpEngine,
		meta:         vd.meta,
		resources:    vd.resources,
		assertVocabs: vd.assertVocabs,
		vocabularies: vd.vocabularies,
		budget:       vd.budget, // work budget
	}
	subvd.handleMeta()
	_, err := subvd.validate()
	return err
}

func (vd *validator) validateValue(sch *Schema, v any, vpath []string) error {
	if vd.budget.over() { // work budget
		return errBudget()
	}
	vloc := append(vd.vloc, vpath...)
	scp := vd.scp.child(sch, "", vd.scp.vid+1)
	uneval := unevalFrom(v, sch, false)
	subvd := validator{
		v:            v,
		vloc:         vloc,
		sch:          sch,
		scp:          scp,
		uneval:       uneval,
		errors:       nil,
		boolResult:   vd.boolResult,
		regexpEngine: vd.regexpEngine,
		meta:         vd.meta,
		resources:    vd.resources,
		assertVocabs: vd.assertVocabs,
		vocabularies: vd.vocabularies,
		budget:       vd.budget, // work budget
	}
	subvd.handleMeta()
	_, err := subvd.validate()
	return err
}

func (vd *validator) metaResource(sch *Schema) *resource {
	if sch != vd.meta {
		return nil
	}
	ptr := ""
	for _, tok := range vd.instanceLocation() {
		ptr += "/"
		ptr += escape(tok)
	}
	return vd.resources[jsonPointer(ptr)]
}

func (vd *validator) handleMeta() {
	res := vd.metaResource(vd.sch)
	if res == nil {
		return
	}
	sch := res.dialect.getSchema(vd.assertVocabs, vd.vocabularies)
	vd.meta = sch
	vd.sch = sch
}

// reference validation --

func (vd *validator) validateRef(sch *Schema, kw string) error {
	err := vd.validateSelf(sch, kw, false)
	if err != nil {
		refErr := vd.error(&kind.Reference{Keyword: kw, URL: sch.Location})
		verr := err.(*ValidationError)
		if _, ok := verr.ErrorKind.(*kind.Group); ok {
			refErr.Causes = verr.Causes
		} else {
			refErr.Causes = append(refErr.Causes, verr)
		}
		return refErr
	}
	return nil
}

func (vd *validator) resolveRecursiveAnchor(fallback *Schema) *Schema {
	sch := fallback
	scp := vd.scp
	for scp != nil {
		if !vd.budget.spend(1) { // work budget
			break
		}
		if scp.sch.resource.RecursiveAnchor {
			sch = scp.sch
		}
		scp = scp.parent
	}
	return sch
}

func (vd *validator) resolveDynamicAnchor(name string, fallback *Schema) *Schema {
	sch := fallback
	scp := vd.scp
	for scp != nil {
		if !vd.budget.spend(1) { // work budget
			break
		}
		if dsch, ok := scp.sch.resource.dynamicAnchors[name]; ok {
			sch = dsch
		}
		scp = scp.parent
	}
	return sch
}

func (vd *validator) validateRefs() {
	// $recursiveRef --
	if sch := vd.sch.RecursiveRef; sch != nil {
		if sch.RecursiveAnchor {
			sch = vd.resolveRecursiveAnchor(sch)
		}
		vd.addErr(vd.validateRef(sch, "$recursiveRef"))
	}

	// $dynamicRef --
	if dref := vd.sch.DynamicRef; dref != nil {
		sch := dref.Ref // initial target
		if dref.Anchor != "" {
			// $dynamicRef includes anchor
			if sch.DynamicAnchor == dref.Anchor {
				// initial target has matching $dynamicAnchor
				sch = vd.resolveDynamicAnchor(dref.Anchor, sch)
			}
		}
		vd.addErr(vd.validateRef(sch, "$dynamicRef"))
	}
}

// error helpers --

func (vd *validator) instanceLocation() []string {
	return slices.Clone(vd.vloc)
}

func (vd *validator) error(kind ErrorKind) *ValidationError {
	if vd.boolResult {
		return &ValidationError{}
	}
	if !vd.budget.spend(len(vd.vloc)) { // work budget
		return errBudget()
	}
	return &ValidationError{
		SchemaURL:        vd.sch.Location,
		InstanceLocation: vd.instanceLocation(),
		ErrorKind:        kind,
		Causes:           nil,
	}
}

func (vd *validator) addErr(err error) {
	if err != nil {
		vd.errors = append(vd.errors, err.(*ValidationError))
	}
}

func (vd *validator) addError(kind ErrorKind) {
	vd.errors = append(vd.errors, vd.error(kind))
}

func (vd *validator) addErrors(errors []*ValidationError, kind ErrorKind) {
	err := vd.error(kind)
	err.Causes = errors
	vd.errors = append(vd.errors, err)
}

func (vd *validator) findMissing(obj map[string]any, reqd []string) []string {
	if !vd.budget.spendSteps(namesLookedUp(reqd)) { // work budget
		return nil
	}
	var missing []string
	for _, pname := range reqd {
		if _, ok := obj[pname]; !ok {
			if vd.boolResult {
				return []string{} // non-nil
			}
			missing = append(missing, pname)
		}
	}
	return missing
}

// --

type scope struct {
	sch *Schema

	// if empty, compute from self.sch and self.parent.sch.
	// not empty, only when there is a jump i.e, $ref, $XXXRef
	refKeyword string

	// unique id of value being validated
	// if two scopes validate same value, they will have
	// same vid
	vid int

	parent *scope

	depth int // work budget: scopes above this one
	outer int // work budget: scopes above the validation this one is in, which propertyNames or contentSchema started
}

func (sc *scope) child(sch *Schema, refKeyword string, vid int) *scope {
	return &scope{sch, refKeyword, vid, sc, sc.depth + 1, sc.outer} // work budget: depth, outer
}

func (sc *scope) checkCycle(b *workBudget) *scope { // work budget: b
	scp := sc.parent
	for scp != nil {
		if !b.spend(1) { // work budget
			return nil
		}
		if scp.vid != sc.vid {
			break
		}
		if scp.sch == sc.sch {
			return scp
		}
		scp = scp.parent
	}
	return nil
}

// kwLocWithin is kwLoc, spending a step of b per byte of the location before
// it builds it: a location holds text the schema has. It reports false, and
// builds nothing, once b is exceeded.
func (sc *scope) kwLocWithin(b *workBudget) (string, bool) { // work budget
	var parts []string // work budget: joined once, not prepended per scope
	n := 0             // work budget
	for sc.parent != nil {
		if sc.refKeyword != "" {
			parts = append(parts, "/"+escape(sc.refKeyword)) // work budget
		} else {
			cur := sc.sch.Location
			parent := sc.parent.sch.Location
			parts = append(parts, cur[len(parent):]) // work budget
		}
		n += len(parts[len(parts)-1]) // work budget
		sc = sc.parent
	}
	if !b.spend(n) { // work budget
		return "", false
	}
	slices.Reverse(parts)                // work budget
	return strings.Join(parts, ""), true // work budget
}

// --

type uneval struct {
	props map[string]struct{}
	items map[int]struct{}
}

func unevalFrom(v any, sch *Schema, callerNeeds bool) *uneval {
	uneval := &uneval{}
	switch v := v.(type) {
	case map[string]any:
		if !sch.allPropsEvaluated && (callerNeeds || sch.UnevaluatedProperties != nil) {
			uneval.props = map[string]struct{}{}
			for k := range v {
				uneval.props[k] = struct{}{}
			}
		}
	case []any:
		if !sch.allItemsEvaluated && (callerNeeds || sch.UnevaluatedItems != nil) && sch.numItemsEvaluated < len(v) {
			uneval.items = map[int]struct{}{}
			for i := sch.numItemsEvaluated; i < len(v); i++ {
				uneval.items[i] = struct{}{}
			}
		}
	}
	return uneval
}

func (ue *uneval) merge(other *uneval) {
	for k := range ue.props {
		if _, ok := other.props[k]; !ok {
			delete(ue.props, k)
		}
	}
	for i := range ue.items {
		if _, ok := other.items[i]; !ok {
			delete(ue.items, i)
		}
	}
}

func (ue *uneval) isEmpty() bool {
	return len(ue.props) == 0 && len(ue.items) == 0
}

// --

type ValidationError struct {
	// absolute, dereferenced schema location.
	SchemaURL string

	// location of the JSON value within the instance being validated.
	InstanceLocation []string

	// kind of error
	ErrorKind ErrorKind

	// holds nested errors
	Causes []*ValidationError
}

type ErrorKind interface {
	KeywordPath() []string
	LocalizedString(*message.Printer) string
}
