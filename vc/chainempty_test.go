package vc_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// Every call that takes a chain refuses one with nothing at a position, an
// empty chain or a nil entry, with an error that is ErrChainEmpty and not
// ErrChainLinkBroken.
func TestChainEmpty_EveryCallThatTakesAChain(t *testing.T) {
	origin, child, keys := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	ctx := context.Background()
	for name, call := range map[string]func([]*vc.PipelinePassCredential) error{
		"ValidateChainLinks": vc.ValidateChainLinks,
		"ValidateChainFrom": func(c []*vc.PipelinePassCredential) error {
			return vc.ValidateChainFrom(c, "sha256:"+strings.Repeat("0", 64))
		},
		"VerifyChain": func(c []*vc.PipelinePassCredential) error {
			_, err := v.VerifyChain(ctx, c)
			return err
		},
		"ClassifyChain": func(c []*vc.PipelinePassCredential) error {
			_, err := v.ClassifyChain(ctx, c)
			return err
		},
		"VerifyChainSigners": func(c []*vc.PipelinePassCredential) error {
			_, err := v.VerifyChainSigners(ctx, keys, c)
			return err
		},
	} {
		for shape, chain := range map[string][]*vc.PipelinePassCredential{
			"no credential":       nil,
			"a nil origin":        {nil},
			"a nil successor":     {origin, nil},
			"a nil in the middle": {origin, nil, child},
		} {
			t.Run(name+"/"+shape, func(t *testing.T) {
				err := call(chain)
				if !errors.Is(err, vc.ErrChainEmpty) || errors.Is(err, vc.ErrChainLinkBroken) {
					t.Errorf("err = %v, want ErrChainEmpty and not ErrChainLinkBroken", err)
				}
			})
		}
	}
}

// VerifyChain and ClassifyChain keep their texts; a nil entry, which
// ClassifyChain had no text for, is named by its position.
func TestChainEmpty_Texts(t *testing.T) {
	origin, _, _ := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	ctx := context.Background()
	_, verifyEmpty := v.VerifyChain(ctx, nil)
	_, verifyNil := v.VerifyChain(ctx, []*vc.PipelinePassCredential{origin, nil})
	classEmpty, classifyEmpty := v.ClassifyChain(ctx, nil)
	classNil, classifyNil := v.ClassifyChain(ctx, []*vc.PipelinePassCredential{nil})
	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"VerifyChain, no credential":    {verifyEmpty, "vc: empty chain"},
		"VerifyChain, a nil credential": {verifyNil, "vc: nil credential"},
		"ClassifyChain, no credential":  {classifyEmpty, "vc: empty chain"},
		"ClassifyChain, a nil origin":   {classifyNil, "vc: chain credential 0 is nil"},
	} {
		if c.err == nil || c.err.Error() != c.want {
			t.Errorf("%s: %v, want %q", name, c.err, c.want)
		}
	}
	if classEmpty != vc.ChainClassUnknown || classNil != vc.ChainClassUnknown {
		t.Errorf("classes = %v, %v, want ChainClassUnknown", classEmpty, classNil)
	}
}

// ClassifyChain refuses a nil entry wherever it is, also after a credential
// whose Owner it establishes.
func TestChainEmpty_ClassifyChainAfterAnOwner(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(r, ed25519Verifier())
	for name, chain := range map[string][]*vc.PipelinePassCredential{
		"a nil successor":     {origin, nil},
		"a nil in the middle": {origin, nil, child},
	} {
		class, err := v.ClassifyChain(context.Background(), chain)
		if class != vc.ChainClassUnknown || !errors.Is(err, vc.ErrChainEmpty) {
			t.Errorf("%s: %v, %v; want ChainClassUnknown and ErrChainEmpty", name, class, err)
		}
	}
}

// VerifyChain checks the context before the entries, and each entry when it
// reaches it: with a context already done, a chain with a nil entry is the
// context's error, and an empty chain is ErrChainEmpty.
func TestChainEmpty_VerifyChainChecksTheContextFirst(t *testing.T) {
	origin, _, _ := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	done, cancel := context.WithCancel(context.Background())
	cancel()
	for name, chain := range map[string][]*vc.PipelinePassCredential{
		"a nil origin":    {nil},
		"a nil successor": {origin, nil},
	} {
		if _, err := v.VerifyChain(done, chain); !errors.Is(err, context.Canceled) || errors.Is(err, vc.ErrChainEmpty) {
			t.Errorf("%s: %v, want context.Canceled and not ErrChainEmpty", name, err)
		}
	}
	if _, err := v.VerifyChain(done, nil); !errors.Is(err, vc.ErrChainEmpty) {
		t.Errorf("no credential: %v, want ErrChainEmpty", err)
	}
}
