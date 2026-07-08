package transport

// This assertion lives in an INTERNAL test (package transport, not
// transport_test) because intentLog is unexported: only code inside the
// package can name it. filelog.Log provides the optional durable-sequence-
// intent capability the Emitter probes for; the build fails here if that
// structural match ever drifts (a signature change on either side), catching
// it before a silent runtime fall-through to tail-based recovery.

import "github.com/provin-line/oss/tlog/filelog"

var _ intentLog = (*filelog.Log)(nil)
