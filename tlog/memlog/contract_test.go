package memlog_test

import (
	"testing"

	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/internal/logcontract"
	"github.com/provin-line/oss/tlog/memlog"
)

func TestLogContract(t *testing.T) {
	logcontract.Suite(t, func(t *testing.T) tlog.Log { return memlog.New() })
	logcontract.ChainSuite(t, func(t *testing.T) tlog.Log { return memlog.New() })
}
