package handler_test

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/handler"
)

// issueFails is a didregistry service whose issuing fails with err.
type issueFails struct {
	handler.Service
	err error
}

func (s issueFails) IssuePipeline(context.Context, string, *delegation.DelegationCredential, *didregistry.ExternalPublicKeys) (*did.DIDDocument, *delegation.DelegationCredential, error) {
	return nil, nil, s.err
}

func (s issueFails) IssueProcess(context.Context, string, *delegation.DelegationCredential, *didregistry.ExternalPublicKeys) (*did.DIDDocument, *delegation.DelegationCredential, error) {
	return nil, nil, s.err
}

// Issuing answers Unavailable for ErrUnavailable, a code a client retries, and
// PermissionDenied for ErrUnauthorized.
func TestIssue_MapsUnavailableAndUnauthorized(t *testing.T) {
	for sentinel, want := range map[error]connect.Code{
		didregistry.ErrUnavailable:  connect.CodeUnavailable,
		didregistry.ErrUnauthorized: connect.CodePermissionDenied,
	} {
		h := handler.New(issueFails{err: fmt.Errorf("%w: detail", sentinel)})
		_, perr := h.IssuePipeline(context.Background(), connect.NewRequest(&didpb.IssuePipelineRequest{TargetDid: pipelineDID, Delegation: []byte("{}")}))
		_, serr := h.IssueProcess(context.Background(), connect.NewRequest(&didpb.IssueProcessRequest{TargetDid: processDID, Delegation: []byte("{}")}))
		for call, err := range map[string]error{"IssuePipeline": perr, "IssueProcess": serr} {
			if got := connect.CodeOf(err); got != want {
				t.Errorf("%s with %q: %v, want %v", call, sentinel, got, want)
			}
		}
	}
}
