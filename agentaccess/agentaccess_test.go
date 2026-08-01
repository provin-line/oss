package agentaccess_test

import (
	"errors"
	"testing"

	"github.com/provin-line/oss/agentaccess"
	"github.com/provin-line/oss/appraisal"
)

func TestDeliveryRejectsRemoteOrNonAccept(t *testing.T) {
	record := agentaccess.DeliveryRecord{
		BoundaryID:     "provin-agent-delivery@1",
		PayloadDigest:  "sha256:2b80da3dfe9909229a81420084e97f04466a184727417bcef639c4395ef1a7ac",
		HeadOutputHash: "sha256:2b80da3dfe9909229a81420084e97f04466a184727417bcef639c4395ef1a7ac",
		EvidenceViewID: "sha256:4382e8875ce5c79e0f053215993f901331003e89d125de78bc610dbdb90b06aa",
		Appraisal: agentaccess.AppraisalRef{
			Authority: "REMOTE", EvidenceViewID: "sha256:4382e8875ce5c79e0f053215993f901331003e89d125de78bc610dbdb90b06aa",
			Decision: appraisal.DecisionAccept, DecisionProfileID: "remote@1",
		},
	}
	if err := record.Validate([]byte("agent-safe-result")); !errors.Is(err, agentaccess.ErrInvalidDelivery) {
		t.Fatalf("Validate error=%v", err)
	}
}

func TestDeploymentRejectsEnabledBypass(t *testing.T) {
	d := agentaccess.Deployment{
		DeploymentID: "test@1", AppraisalBoundaryID: "gate@1",
		Paths: []agentaccess.Path{
			{ID: "sink", State: agentaccess.PathEnabled, BoundaryID: "gate@1"},
			{ID: "direct", State: agentaccess.PathEnabled, BoundaryID: "direct@1"},
		},
	}
	if err := d.Validate(); !errors.Is(err, agentaccess.ErrInvalidDeployment) {
		t.Fatalf("Validate error=%v", err)
	}
}
