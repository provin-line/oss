package dplaax_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/resolver"
)

func TestParse_Owner(t *testing.T) {
	d, err := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d.Method != dplaax.Method {
		t.Errorf("Method=%q, want %q", d.Method, dplaax.Method)
	}
	if d.Registry != "poc.dplaax.dev" {
		t.Errorf("Registry=%q", d.Registry)
	}
	if d.AccountType != "org" {
		t.Errorf("AccountType=%q", d.AccountType)
	}
	if d.AccountID != "acme" {
		t.Errorf("AccountID=%q", d.AccountID)
	}
	if len(d.ResourcePath) != 0 {
		t.Errorf("ResourcePath=%v, want empty (owner)", d.ResourcePath)
	}
	if !d.IsOwner() || d.IsPipeline() || d.IsProcess() {
		t.Errorf("classifiers wrong for owner: owner=%v pipeline=%v process=%v", d.IsOwner(), d.IsPipeline(), d.IsProcess())
	}
}

func TestParse_Pipeline(t *testing.T) {
	d, err := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !d.IsPipeline() {
		t.Error("IsPipeline=false, want true")
	}
	if d.IsOwner() || d.IsProcess() {
		t.Error("pipeline misclassified as owner/process")
	}
	want := []string{"pipeline", "p1"}
	if len(d.ResourcePath) != 2 || d.ResourcePath[0] != want[0] || d.ResourcePath[1] != want[1] {
		t.Errorf("ResourcePath=%v, want %v", d.ResourcePath, want)
	}
}

func TestParse_Process(t *testing.T) {
	d, err := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !d.IsProcess() {
		t.Error("IsProcess=false, want true")
	}
	if d.IsOwner() || d.IsPipeline() {
		t.Error("process misclassified as owner/pipeline")
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := []string{
		"",
		"did:web:example.com",                 // wrong method
		"did:dplaax:",                         // no segments
		"did:dplaax:poc.dplaax.dev",           // missing accountType+accountId
		"did:dplaax:poc.dplaax.dev:org",       // missing accountId
		"did:dplaax:poc.dplaax.dev:org:",      // empty accountId segment
		"did:dplaax:poc.dplaax.dev:org:acme:", // trailing empty resource segment
		"did:dplaax:poc.dplaax.dev:org:ac/me", // slash not in safe-segment set
		"did:dplaax:poc.dplaax.dev:org:..",    // all-dots segment (traversal)
		"did:dplaaxx:poc.dplaax.dev:org:acme", // method is not exactly dplaax
		"did:dplaax:poc.dplaax.dev:org:ac me", // space
	}
	for _, s := range cases {
		if _, err := dplaax.Parse(s); err == nil {
			t.Errorf("Parse(%q) = nil error, want rejection", s)
		}
	}
}

func TestString_RoundTrip(t *testing.T) {
	for _, s := range []string{
		"did:dplaax:poc.dplaax.dev:org:acme",
		"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1",
		"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1",
	} {
		d, err := dplaax.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if got := d.String(); got != s {
			t.Errorf("String()=%q, want %q", got, s)
		}
	}
}

func TestTruncation(t *testing.T) {
	d, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1")

	owner := d.OwnerDID()
	if !owner.IsOwner() || owner.String() != "did:dplaax:poc.dplaax.dev:org:acme" {
		t.Errorf("OwnerDID()=%q", owner.String())
	}
	pipe := d.PipelineDID()
	if pipe == nil || !pipe.IsPipeline() || pipe.String() != "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1" {
		t.Errorf("PipelineDID()=%v", pipe)
	}

	// An owner DID has no pipeline level.
	if owner.PipelineDID() != nil {
		t.Error("owner.PipelineDID() should be nil")
	}

	// Truncation must not alias the original's slice.
	d.ResourcePath[1] = "MUTATED"
	if pipe.String() != "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1" {
		t.Error("PipelineDID() aliased the original ResourcePath — defensive copy required")
	}
}

func TestIsSafeSegment(t *testing.T) {
	safe := []string{"acme", "poc.dplaax.dev", "p1", "proc_1", "a-b", "x.y.z", "1"}
	for _, s := range safe {
		if !dplaax.IsSafeSegment(s) {
			t.Errorf("IsSafeSegment(%q)=false, want true", s)
		}
	}
	unsafe := []string{"", ".", "..", "...", "a/b", "a:b", "a b", "a\tb", "../x", "a\\b"}
	for _, s := range unsafe {
		if dplaax.IsSafeSegment(s) {
			t.Errorf("IsSafeSegment(%q)=true, want false", s)
		}
	}
}

func TestValidateDID(t *testing.T) {
	good, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1")
	if err := dplaax.ValidateDID(good); err != nil {
		t.Errorf("ValidateDID(good): %v", err)
	}

	// Unsupported account type.
	badType, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:person:acme")
	if err := dplaax.ValidateDID(badType); err == nil {
		t.Error("ValidateDID with unsupported accountType: want error")
	}

	// Unknown resource pattern (a resource path that is neither pipeline nor process).
	unknown, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:widget:w1")
	if err := dplaax.ValidateDID(unknown); err == nil {
		t.Error("ValidateDID with unknown resource pattern: want error")
	}
}

func TestRequireKnownPattern(t *testing.T) {
	for _, s := range []string{
		"did:dplaax:poc.dplaax.dev:org:acme",
		"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1",
		"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1",
	} {
		d, _ := dplaax.Parse(s)
		if err := dplaax.RequireKnownPattern(d); err != nil {
			t.Errorf("RequireKnownPattern(%q): %v", s, err)
		}
	}
	bad, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:widget:w1")
	if err := dplaax.RequireKnownPattern(bad); err == nil {
		t.Error("RequireKnownPattern(unknown): want error")
	}
	// A half-formed process path is not a known pattern.
	half, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process")
	if err := dplaax.RequireKnownPattern(half); err == nil {
		t.Error("RequireKnownPattern(pipeline/p1/process with no id): want error")
	}
}

func TestRequireOwner(t *testing.T) {
	owner, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme")
	if err := dplaax.RequireOwner(owner); err != nil {
		t.Errorf("RequireOwner(owner): %v", err)
	}
	proc, _ := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1")
	if err := dplaax.RequireOwner(proc); err == nil {
		t.Error("RequireOwner(process): want error")
	}
}

// A DID's registry is a DNS name, of at most MaxRegistryLen octets.
func TestParse_BoundsTheRegistry(t *testing.T) {
	if dplaax.MaxRegistryLen != 253 {
		t.Fatalf("MaxRegistryLen = %d, want 253, the longest DNS name", dplaax.MaxRegistryLen)
	}
	if _, err := dplaax.Parse("did:dplaax:" + strings.Repeat("a", 253) + ":org:acme"); err != nil {
		t.Errorf("a registry of 253 octets: %v", err)
	}
	if _, err := dplaax.Parse("did:dplaax:" + strings.Repeat("a", 254) + ":org:acme"); err == nil {
		t.Error("a registry of 254 octets was taken")
	}
}

// Every refusal of Parse and of ValidateRegistry is ErrSyntax, also wrapped,
// with its text as it is: one case per refusal, and the one Parse makes when
// two hold (a segment is checked before the registry's length).
func TestErrSyntax_EveryRefusalOfParseAndValidateRegistry(t *testing.T) {
	long := strings.Repeat("a", 254)
	for name, c := range map[string]struct {
		err  error
		text string
	}{
		"Parse: another method":                            {parseErr("did:web:example.com"), `not a did:dplaax identifier: "did:web:example.com"`},
		"Parse: too few segments":                          {parseErr("did:dplaax:poc.dplaax.dev:org"), "did:dplaax requires registry:accountType:accountId, got 2 segment(s)"},
		"Parse: an unsafe segment":                         {parseErr("did:dplaax:poc.dplaax.dev:org:ac/me"), `did:dplaax segment "ac/me" violates the safe-segment rule`},
		"Parse: an empty segment":                          {parseErr("did:dplaax:poc.dplaax.dev:org:"), `did:dplaax segment "" violates the safe-segment rule`},
		"Parse: a registry too long":                       {parseErr("did:dplaax:" + long + ":org:acme"), "did:dplaax registry of 254 octets, beyond 253"},
		"Parse: a registry too long and an unsafe segment": {parseErr("did:dplaax:" + long + ":org:ac/me"), `did:dplaax segment "ac/me" violates the safe-segment rule`},
		"ValidateRegistry: empty":                          {dplaax.ValidateRegistry(""), `did:dplaax registry "" violates the safe-segment rule ([A-Za-z0-9._-], not all dots)`},
		"ValidateRegistry: all dots":                       {dplaax.ValidateRegistry(".."), `did:dplaax registry ".." violates the safe-segment rule ([A-Za-z0-9._-], not all dots)`},
		"ValidateRegistry: unsafe":                         {dplaax.ValidateRegistry("a/b"), `did:dplaax registry "a/b" violates the safe-segment rule ([A-Za-z0-9._-], not all dots)`},
		"ValidateRegistry: too long":                       {dplaax.ValidateRegistry(long), "did:dplaax registry of 254 octets, beyond 253"},
	} {
		if c.err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(c.err, dplaax.ErrSyntax) || !errors.Is(fmt.Errorf("caller: %w", c.err), dplaax.ErrSyntax) {
			t.Errorf("%s: %v is not ErrSyntax", name, c.err)
		}
		// It is ErrSyntax and no other error, so a caller branching on
		// another sentinel beside it reads no refusal of the syntax as that.
		for _, other := range []error{dplaax.Error(c.text), errors.New(c.text), resolver.ErrNotFound} {
			if errors.Is(c.err, other) {
				t.Errorf("%s: %v is also %v", name, c.err, other)
			}
		}
		if c.err.Error() != c.text {
			t.Errorf("%s: %q, want %q", name, c.err, c.text)
		}
	}
}

// The semantic gates refuse under other rules: none of their refusals is
// ErrSyntax, ValidateDID's of an empty registry included.
func TestErrSyntax_NotTheSemanticGates(t *testing.T) {
	parse := func(s string) *dplaax.DID {
		t.Helper()
		d, err := dplaax.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		return d
	}
	for name, err := range map[string]error{
		"ValidateDID: an account type":         dplaax.ValidateDID(parse("did:dplaax:poc.dplaax.dev:person:acme")),
		"ValidateDID: an empty registry":       dplaax.ValidateDID(&dplaax.DID{Method: dplaax.Method, AccountType: "org", AccountID: "acme"}),
		"ValidateDID: a resource path":         dplaax.ValidateDID(parse("did:dplaax:poc.dplaax.dev:org:acme:widget:w1")),
		"RequireKnownPattern: a resource path": dplaax.RequireKnownPattern(parse("did:dplaax:poc.dplaax.dev:org:acme:widget:w1")),
		"RequireOwner: a Process":              dplaax.RequireOwner(parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:x")),
	} {
		if err == nil || errors.Is(err, dplaax.ErrSyntax) {
			t.Errorf("%s: %v, want a refusal that is not ErrSyntax", name, err)
		}
	}
}

func parseErr(s string) error {
	_, err := dplaax.Parse(s)
	return err
}

// Parse quotes what it refuses within a bound, however long the input: the
// head and the length of a long one, all of a short one.
func TestParse_QuotesWhatItRefusesWithinABound(t *testing.T) {
	long := strings.Repeat("a", 200<<10)
	for name, c := range map[string]struct{ input, named string }{
		"no method prefix":  {long, long},
		"an unsafe segment": {"did:dplaax:poc.dplaax.dev:org:" + long + "!", long + "!"},
	} {
		_, err := dplaax.Parse(c.input)
		if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(c.named))) {
			t.Errorf("%s: %.200v (%d bytes), want a refusal naming the head and the length %d", name, err, len(fmt.Sprint(err)), len(c.named))
		}
	}
	if _, err := dplaax.Parse("nope"); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("a short input: %v, want it quoted whole", err)
	}
	if _, err := dplaax.Parse("did:dplaax:poc.dplaax.dev:org:ac/me"); err == nil || !strings.Contains(err.Error(), `"ac/me"`) {
		t.Errorf("a short unsafe segment: %v, want it quoted whole", err)
	}
}

// The semantic gates name what they refuse within a bound, however long the
// DID: the account type, the resource path, the DID that is not an Owner.
func TestValidation_NamesWhatItRefusesWithinABound(t *testing.T) {
	long := strings.Repeat("a", 200<<10)
	parse := func(s string) *dplaax.DID {
		t.Helper()
		d, err := dplaax.Parse(s)
		if err != nil {
			t.Fatalf("Parse: %.200v", err)
		}
		return d
	}
	nonOwner := "did:dplaax:poc.dplaax.dev:org:" + long + ":pipeline:p1"
	for name, c := range map[string]struct {
		err   error
		named string
	}{
		"a long account type":  {dplaax.ValidateDID(parse("did:dplaax:poc.dplaax.dev:" + long + ":acme")), long},
		"a long resource path": {dplaax.RequireKnownPattern(parse("did:dplaax:poc.dplaax.dev:org:acme:" + long)), long},
		"a long non-Owner":     {dplaax.RequireOwner(parse(nonOwner)), nonOwner},
	} {
		if c.err == nil || len(c.err.Error()) > 300 || !strings.Contains(c.err.Error(), fmt.Sprintf("(%d bytes)", len(c.named))) {
			t.Errorf("%s: %.200v (%d bytes), want a refusal naming the head and the length %d", name, c.err, len(fmt.Sprint(c.err)), len(c.named))
		}
	}
	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"a short account type":  {dplaax.ValidateDID(parse("did:dplaax:poc.dplaax.dev:person:acme")), "person"},
		"a short resource path": {dplaax.RequireKnownPattern(parse("did:dplaax:poc.dplaax.dev:org:acme:widget:w1")), "widget"},
		"a short non-Owner":     {dplaax.RequireOwner(parse("did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1")), "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"},
	} {
		if c.err == nil || !strings.Contains(c.err.Error(), c.want) {
			t.Errorf("%s: %v, want it named whole", name, c.err)
		}
	}
}

// ValidateRegistry takes exactly the registry segments Parse takes: the
// safe-segment grammar and at most MaxRegistryLen octets.
func TestValidateRegistry(t *testing.T) {
	for id, ok := range map[string]bool{
		"poc.dplaax.dev":         true,
		"a":                      true,
		"1":                      true,
		"a_b-c.d":                true,
		"under_score.example":    true,
		strings.Repeat("a", 253): true,
		"":                       false,
		".":                      false,
		"..":                     false,
		strings.Repeat("a", 254): false,
		"a/b":                    false,
		"a b":                    false,
		"a*":                     false,
		"a#b":                    false,
		"é.example":              false,
	} {
		err := dplaax.ValidateRegistry(id)
		if (err == nil) != ok {
			t.Errorf("ValidateRegistry(%.40q) = %v, want accepted %t", id, err, ok)
		}
		_, perr := dplaax.Parse("did:dplaax:" + id + ":org:acme")
		if (perr == nil) != ok {
			t.Errorf("Parse with registry %.40q = %v, want accepted %t, as ValidateRegistry", id, perr, ok)
		}
	}
}

// ValidateRegistry names what it refuses within a bound, however long the
// registry, and the length of one that is too long.
func TestValidateRegistry_NamesWhatItRefusesWithinABound(t *testing.T) {
	long := strings.Repeat("a", 200<<10)
	err := dplaax.ValidateRegistry(long + "!")
	if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long)+1)) {
		t.Errorf("a long unsafe registry: %.200v, want a refusal naming the head and the length", err)
	}
	err = dplaax.ValidateRegistry(long)
	if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), fmt.Sprint(len(long))) {
		t.Errorf("a long registry: %.200v, want a refusal naming its length", err)
	}
}

// Pipeline is the hierarchy's answer (did.dplaax.hierarchy): only a Process
// has a Pipeline. PipelineDID truncates any resource path that begins with
// pipeline.
func TestPipeline(t *testing.T) {
	for _, c := range []struct {
		did  string
		want string
	}{
		{"did:dplaax:r.example:org:acme:pipeline:p1:process:q1", "did:dplaax:r.example:org:acme:pipeline:p1"},
		{"did:dplaax:r.example:org:acme:pipeline:p1", ""},
		{"did:dplaax:r.example:org:acme", ""},
		{"did:dplaax:r.example:org:acme:pipeline:p1:widget:w1", ""},
		{"did:dplaax:r.example:org:acme:pipeline:p1:process:q1:step:s1", ""},
		{"did:dplaax:r.example:org:acme:widget:w1:process:q1", ""},
	} {
		d, err := dplaax.Parse(c.did)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.did, err)
		}
		p, ok := d.Pipeline()
		switch {
		case c.want == "" && (ok || p != nil):
			t.Errorf("Pipeline of %q = %v, %t, want none", c.did, p, ok)
		case c.want != "" && (!ok || p == nil || p.String() != c.want || !p.IsPipeline()):
			t.Errorf("Pipeline of %q = %v, %t, want %s", c.did, p, ok, c.want)
		}
	}

	if p, ok := (*dplaax.DID)(nil).Pipeline(); ok || p != nil {
		t.Errorf("Pipeline of nil = %v, %t, want none", p, ok)
	}

	d, _ := dplaax.Parse("did:dplaax:r.example:org:acme:pipeline:p1:process:q1")
	p, _ := d.Pipeline()
	d.ResourcePath[1] = "MUTATED"
	if p.String() != "did:dplaax:r.example:org:acme:pipeline:p1" {
		t.Error("Pipeline() aliased the Process's ResourcePath")
	}
	p.ResourcePath[1] = "ALSO"
	if d.ResourcePath[1] != "MUTATED" {
		t.Error("the Process shares its ResourcePath with its Pipeline")
	}
}
