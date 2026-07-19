package tlogship

// This assertion lives in an INTERNAL test (package tlogship, not
// tlogship_test) because checkpointAtLog is unexported: only code inside
// the package can name it. filelog.Log provides the optional
// arbitrary-prefix checkpoint capability New probes for via a type
// assertion; the build fails here if that structural match ever drifts (a
// signature change on either side), catching it before New's runtime type
// assertion would start silently rejecting every filelog.Log passed to it
// — mirrors pipeline/transport's own intentlog_internal_test.go precedent.

import "github.com/provin-line/oss/tlog/filelog"

var _ checkpointAtLog = (*filelog.Log)(nil)
