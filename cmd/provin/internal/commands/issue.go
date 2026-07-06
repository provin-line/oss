package commands

import (
	"context"
	"encoding/json"
	"fmt"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/keyfile"
	"github.com/provin-line/oss/delegation"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
)

// PipelineCreate issues a pipeline DID under the owner held at ownerKeyPath:
// the owner signs a delegation credential for targetDID and the registry
// generates + holds the pipeline's signing keys (KMS model — no new private
// key reaches the client).
func PipelineCreate(ctx context.Context, env Env, targetDID, ownerKeyPath string) error {
	return issue(ctx, env, targetDID, ownerKeyPath, "pipeline")
}

// ProcessCreate issues a process DID under the owner held at ownerKeyPath
// (same delegation flow as PipelineCreate; the registry holds the keys).
func ProcessCreate(ctx context.Context, env Env, targetDID, ownerKeyPath string) error {
	return issue(ctx, env, targetDID, ownerKeyPath, "process")
}

func issue(ctx context.Context, env Env, targetDID, ownerKeyPath, kind string) error {
	key, err := keyfile.Load(ownerKeyPath)
	if err != nil {
		return err
	}
	dlg, err := delegation.Build(key.Signer(), key.DID, delegation.DelegationSubject{
		ID: targetDID, DelegatedBy: key.DID,
	})
	if err != nil {
		return fmt.Errorf("%s create: build delegation for %s: %w", kind, targetDID, err)
	}
	dlgBytes, err := json.Marshal(dlg)
	if err != nil {
		return fmt.Errorf("%s create: marshal delegation: %w", kind, err)
	}
	c, err := env.didClient()
	if err != nil {
		return err
	}
	switch kind {
	case "pipeline":
		_, err = c.IssuePipeline(ctx, connect.NewRequest(&didpb.IssuePipelineRequest{
			TargetDid: targetDID, Delegation: dlgBytes,
		}))
	case "process":
		_, err = c.IssueProcess(ctx, connect.NewRequest(&didpb.IssueProcessRequest{
			TargetDid: targetDID, Delegation: dlgBytes,
		}))
	default:
		return fmt.Errorf("issue: unknown kind %q", kind)
	}
	if err != nil {
		return fmt.Errorf("%s create: issue %s: %w", kind, targetDID, err)
	}
	fmt.Fprintf(env.out(), "issued %s %s (signing keys held by the registry)\n", kind, targetDID)
	return nil
}
