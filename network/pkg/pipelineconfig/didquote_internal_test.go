package pipelineconfig

import (
	"fmt"
	"strings"
	"testing"
)

// A loop's DID that does not parse, or is not of the kind its key needs, is
// named within a bound, however long it is.
func TestLoopDIDIsNamedWithinABound(t *testing.T) {
	owner := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 5000)
	unparsable := owner + "!"
	for name, c := range map[string]struct {
		err   error
		named string
	}{
		"an unparsable pipeline DID":               {requirePipelineDID(unparsable, "l", "ingress-subject"), unparsable},
		"a pipeline DID that is not":               {requirePipelineDID(owner, "l", "ingress-subject"), owner},
		"an unparsable process DID":                {requireProcessDID(unparsable, "l", "source.issuer.did"), unparsable},
		"a process DID that is not":                {requireProcessDID(owner, "l", "source.issuer.did"), owner},
		"an unparsable producing issuer":           {validateProducingIdentities([]LoopConfig{{Name: "l", Role: RoleSource, Source: SourceConfig{Issuer: IssuerConfig{DID: unparsable}}}}), unparsable},
		"a producing issuer that is not a Process": {validateProducingIdentities([]LoopConfig{{Name: "l", Role: RoleSource, Source: SourceConfig{Issuer: IssuerConfig{DID: owner}}}}), owner},
	} {
		if c.err == nil || len(c.err.Error()) > 500 || !strings.Contains(c.err.Error(), fmt.Sprintf("(%d bytes)", len(c.named))) {
			t.Errorf("%s: %.200v (%d bytes), want an error naming the DID's head and its length %d", name, c.err, len(fmt.Sprint(c.err)), len(c.named))
		}
	}
}

// Only a Process has a Pipeline (dplaax did.dplaax.hierarchy): a producing
// issuer that is not a Process does not belong to an output subject, even
// one equal to the issuer or to its first five segments.
func TestProducingIssuerIsAProcess(t *testing.T) {
	const pipeline = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
	for name, issuer := range map[string]string{
		"a Pipeline":                      pipeline,
		"a pipeline path of another kind": pipeline + ":step:s1",
	} {
		err := validateProducingIdentities([]LoopConfig{{Name: "l", Role: RoleSource, Source: SourceConfig{OutputSubject: pipeline, Issuer: IssuerConfig{DID: issuer}}}})
		if err == nil || !strings.Contains(err.Error(), "not a Process DID") {
			t.Errorf("%s as the issuer of %s: %v, want it refused as not a Process", name, pipeline, err)
		}
	}
	if err := validateProducingIdentities([]LoopConfig{{Name: "l", Role: RoleSource, Source: SourceConfig{OutputSubject: pipeline, Issuer: IssuerConfig{DID: pipeline + ":process:x"}}}}); err != nil {
		t.Errorf("a Process of the subject: %v", err)
	}
}
