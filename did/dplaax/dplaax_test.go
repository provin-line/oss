package dplaax_test

import (
	"testing"

	"github.com/provin-line/oss/did/dplaax"
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
		"did:web:example.com",                // wrong method
		"did:dplaax:",                        // no segments
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
