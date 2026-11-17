package keybinding_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/keybinding"
	"github.com/provin-line/oss/vc"
)

// The contexts keybinding.context names. B is the snapshot Issue names; B2 is
// a later snapshot, accepted by its URI's form.
const (
	ctxV2 = vc.ContextCredentialsV2
	ctxV1 = vc.ContextDplaaxVCV1
	ctxB  = "https://dplaax.dev/vc/branches/v1/keybinding/202611101543"
	ctxB2 = "https://dplaax.dev/vc/branches/v1/keybinding/202701010000"
	ctxU  = "https://www.w3.org/ns/credentials/undefined-terms/v2"
	ctxE  = "https://example.com/ctx/v1"
)

// cutOff is the validFrom from which a binding needs the branch context.
var cutOff = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

// notBranch are URIs that look like the branch context's but are not of its
// form, so a binding treats them as any other URI.
var notBranch = map[string]string{
	"11 digits":      "https://dplaax.dev/vc/branches/v1/keybinding/20261110154",
	"13 digits":      "https://dplaax.dev/vc/branches/v1/keybinding/2026111015430",
	"a letter":       "https://dplaax.dev/vc/branches/v1/keybinding/20261110154a",
	"a slash after":  "https://dplaax.dev/vc/branches/v1/keybinding/202611101543/",
	"a suffix":       "https://dplaax.dev/vc/branches/v1/keybinding/202611101543.jsonld",
	"another scheme": "http://dplaax.dev/vc/branches/v1/keybinding/202611101543",
}

// verifyBindingWithContext issues the sample binding valid from from with
// @context set to contexts and verifies it an hour later.
func verifyBindingWithContext(t *testing.T, f *fixture, contexts any, from time.Time) error {
	t.Helper()
	b := sampleBinding()
	b.ValidFrom, b.ValidUntil = from, from.Add(24*time.Hour)
	raw, err := keybinding.IssueBody(f.signer, issuerDID, "issuer", b, func(m map[string]any) { m["@context"] = contexts })
	if err != nil {
		t.Fatal(err)
	}
	at := from.Add(time.Hour)
	_, err = f.v.VerifyBinding(context.Background(), raw, f.anchor, f.heldList(t, at), at)
	return err
}

func TestVerifyBinding_Context(t *testing.T) {
	f := newFixture(t)
	before, later := t0, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	type row struct {
		contexts any
		from     time.Time
	}
	accept := map[string]row{
		"the three":                         {[]any{ctxV2, ctxV1, ctxB}, before},
		"undefined-terms after the three":   {[]any{ctxV2, ctxV1, ctxB, ctxU}, before},
		"a later snapshot":                  {[]any{ctxV2, ctxV1, ctxB2}, before},
		"another URI after the three":       {[]any{ctxV2, ctxV1, ctxB, ctxE}, before},
		"a second snapshot after the three": {[]any{ctxV2, ctxV1, ctxB, ctxB2}, before},
		"a URN after the three":             {[]any{ctxV2, ctxV1, ctxB, "urn:example:ctx"}, before},
		"the three, from after the cut-off": {[]any{ctxV2, ctxV1, ctxB}, later},
		"the three, from the cut-off":       {[]any{ctxV2, ctxV1, ctxB}, cutOff},
		"no branch, before the cut-off":     {[]any{ctxV2, ctxV1}, before},
		"no branch and a URI, before":       {[]any{ctxV2, ctxV1, ctxU}, before},
		"no branch, a second before":        {[]any{ctxV2, ctxV1}, cutOff.Add(-time.Second)},
	}
	refuse := map[string]row{
		"no branch, from the cut-off":           {[]any{ctxV2, ctxV1}, cutOff},
		"no branch and a URI, from the cut-off": {[]any{ctxV2, ctxV1, ctxU}, cutOff},
		"dplaax first":                          {[]any{ctxV1, ctxV2, ctxB}, before},
		"no dplaax":                             {[]any{ctxV2, ctxB}, before},
		"the branch before dplaax":              {[]any{ctxV2, ctxB, ctxV1}, before},
		"a URI between v2 and dplaax":           {[]any{ctxV2, ctxU, ctxV1, ctxB}, before},
		"a URI between dplaax and the branch":   {[]any{ctxV2, ctxV1, ctxU, ctxB}, before},
		"the branch fourth, from the cut-off":   {[]any{ctxV2, ctxV1, ctxU, ctxB}, cutOff},
		"the branch after a look-alike":         {[]any{ctxV2, ctxV1, notBranch["11 digits"], ctxB}, before},
		"an inline object after the three":      {[]any{ctxV2, ctxV1, ctxB, map[string]any{"note": "https://example.org/note"}}, before},
		"an inline object, no branch":           {[]any{ctxV2, ctxV1, map[string]any{"note": "https://example.org/note"}}, before},
		"a number after the three":              {[]any{ctxV2, ctxV1, ctxB, 5}, before},
		"a word after the three":                {[]any{ctxV2, ctxV1, ctxB, "note"}, before},
		"a relative reference after the three":  {[]any{ctxV2, ctxV1, ctxB, "/ctx/v1"}, before},
		"a scheme that begins with a digit":     {[]any{ctxV2, ctxV1, ctxB, "1x:y"}, before},
		"credentials v2 only":                   {[]any{ctxV2}, before},
		"empty":                                 {[]any{}, before},
		"a string, not an array":                {ctxV2, before},
	}
	for name, x := range notBranch {
		accept["a look-alike before the cut-off: "+name] = row{[]any{ctxV2, ctxV1, x}, before}
		refuse["a look-alike from the cut-off: "+name] = row{[]any{ctxV2, ctxV1, x}, cutOff}
	}
	for name, r := range accept {
		t.Run("accept/"+name, func(t *testing.T) {
			if err := verifyBindingWithContext(t, f, r.contexts, r.from); err != nil {
				t.Errorf("@context %v from %s: %v", r.contexts, r.from.Format(time.RFC3339), err)
			}
		})
	}
	for name, r := range refuse {
		t.Run("refuse/"+name, func(t *testing.T) {
			err := verifyBindingWithContext(t, f, r.contexts, r.from)
			if !errors.Is(err, keybinding.ErrMalformed) || !strings.Contains(err.Error(), "@context") {
				t.Errorf("@context %v from %s: %v, want ErrMalformed for its @context", r.contexts, r.from.Format(time.RFC3339), err)
			}
		})
	}
	// The refusals that only the branch context's place and the cut-off decide
	// give that reason, not another's.
	for name, want := range map[string]string{
		"no branch, from the cut-off":         "no key-binding branch context",
		"the branch fourth, from the cut-off": "elsewhere than third",
		"a URI between dplaax and the branch": "elsewhere than third",
	} {
		r := refuse[name]
		if err := verifyBindingWithContext(t, f, r.contexts, r.from); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want a refusal saying %q", name, err, want)
		}
	}
}

func TestVerifyStatusList_Context(t *testing.T) {
	f := newFixture(t)
	at := t0.Add(time.Hour)
	verify := func(t *testing.T, contexts any) error {
		t.Helper()
		from := at.Add(-time.Minute)
		raw, err := keybinding.IssueStatusListBody(f.signer, issuerDID, "issuer", listID, from, from.Add(time.Hour), encodeList(t, gzip.DefaultCompression, listBits()), func(m map[string]any) { m["@context"] = contexts })
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.v.VerifyStatusList(context.Background(), raw, f.anchor, nil, at)
		return err
	}
	for name, contexts := range map[string][]any{
		"credentials v2":           {ctxV2},
		"undefined-terms after v2": {ctxV2, ctxU},
		"dplaax after v2":          {ctxV2, ctxV1},
		"the branch after v2":      {ctxV2, ctxB},
		"a URN after v2":           {ctxV2, "urn:example:ctx"},
	} {
		t.Run("accept/"+name, func(t *testing.T) {
			if err := verify(t, contexts); err != nil {
				t.Errorf("@context %v: %v", contexts, err)
			}
		})
	}
	for name, contexts := range map[string]any{
		"v2 not first":           []any{ctxU, ctxV2},
		"an inline object":       []any{ctxV2, map[string]any{"note": "https://example.org/note"}},
		"a relative reference":   []any{ctxV2, "/ctx/v1"},
		"a word":                 []any{ctxV2, "note"},
		"empty":                  []any{},
		"a string, not an array": ctxV2,
	} {
		t.Run("refuse/"+name, func(t *testing.T) {
			if err := verify(t, contexts); !errors.Is(err, keybinding.ErrMalformed) {
				t.Errorf("@context %v: %v, want ErrMalformed", contexts, err)
			}
		})
	}
}

// A binding Issue makes names the branch context and is accepted from after
// the cut-off.
func TestIssue_Context(t *testing.T) {
	f := newFixture(t)
	from := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	b := sampleBinding()
	b.ValidFrom, b.ValidUntil = from, from.Add(24*time.Hour)
	raw, err := keybinding.Issue(f.signer, issuerDID, "issuer", b)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if want := []any{ctxV2, ctxV1, ctxB}; !reflect.DeepEqual(got["@context"], want) {
		t.Errorf("@context = %v, want %v", got["@context"], want)
	}
	at := from.Add(time.Hour)
	if _, err := f.v.VerifyBinding(context.Background(), raw, f.anchor, f.heldList(t, at), at); err != nil {
		t.Errorf("VerifyBinding of an issued binding from after the cut-off: %v", err)
	}
}
