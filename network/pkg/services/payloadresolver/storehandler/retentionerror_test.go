package storehandler

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/internal/retention"
)

// Each refusal of retention is answered with the code and the sentinel of
// its check, and a writer's own error as mapError answers it.
func TestRetentionError(t *testing.T) {
	h := &Handler{maxPayloadSize: 10}
	for _, c := range []struct {
		err  error
		code connect.Code
		is   error
	}{
		{retention.ErrEmpty, connect.CodeInvalidArgument, errZeroDeclaredSize},
		{retention.ErrOverQuota, connect.CodeResourceExhausted, errDeclaredSizeExceeded},
		{retention.ErrOverrun, connect.CodeResourceExhausted, errCumulativeOverrun},
		{retention.ErrShort, connect.CodeInvalidArgument, errSizeMismatch},
		{retention.ErrAddressMismatch, connect.CodeInvalidArgument, errContentAddressMismatch},
		{fmt.Errorf("write: %w", payloadresolver.ErrInvalidArgument), connect.CodeInvalidArgument, payloadresolver.ErrInvalidArgument},
		{fmt.Errorf("write: %w", context.Canceled), connect.CodeCanceled, context.Canceled},
		{errors.New("disk gone"), connect.CodeInternal, nil},
	} {
		got := h.retentionError(c.err, 52)
		if connect.CodeOf(got) != c.code || (c.is != nil && !errors.Is(got, c.is)) {
			t.Errorf("retentionError(%v) = %v (%v), want %v wrapping %v", c.err, connect.CodeOf(got), got, c.code, c.is)
		}
	}
	const quota = "resource_exhausted: storehandler: declared_size exceeds the configured quota: declared_size 52 exceeds max 10"
	if got := h.retentionError(retention.ErrOverQuota, 52).Error(); got != quota {
		t.Errorf("over the quota: %q, want %q", got, quota)
	}
}
