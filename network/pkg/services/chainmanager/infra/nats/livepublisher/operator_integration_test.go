package livepublisher_test

import (
	neturl "net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"

	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats/livepublisher"
)

// newOperator wires a real nats.Operator exactly like cmd/network does in
// the quickstart shape: DirPublisher over the RESOLVER dir, wrapped by the
// live publisher.
func newOperator(t *testing.T, tr trust, dir, url string, timeout time.Duration) *natsop.Operator {
	t.Helper()
	nodeSeed, err := tr.nodeKP.Seed()
	if err != nil {
		t.Fatal(err)
	}
	opSeed, err := tr.opKP.Seed()
	if err != nil {
		t.Fatal(err)
	}
	userJWT, userSeed := tr.sysUser(t)
	live, err := livepublisher.New(natsop.NewDirPublisher(dir), livepublisher.Config{
		URL: url, SysUserJWT: userJWT, SysUserSeed: userSeed, Timeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	op, err := natsop.New(natsop.Config{
		AccountSeed:   string(nodeSeed),
		TrustRootSeed: string(opSeed),
		URL:           url,
		Publisher:     live,
	})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// restartServerAt boots a fresh dir-resolver server on the SAME client URL a
// previous server used (the operator holds the URL for the process lifetime).
func restartServerAt(t *testing.T, tr trust, dir, url string) *server.Server {
	t.Helper()
	u, err := neturl.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	res, err := server.NewDirAccResolver(dir, 0, 2*time.Minute, server.NoDelete)
	if err != nil {
		t.Fatal(err)
	}
	return natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: port, NoLog: true, NoSigs: true,
		TrustedOperators: []*jwt.OperatorClaims{tr.opClaims},
		AccountResolver:  res,
		SystemAccount:    tr.sysPub,
	})
}

// decodeDirClaims reads the account JWT the resolver dir holds and returns
// its export subjects — the hydrate source every restart converges on.
func decodeDirClaims(t *testing.T, dir, accountPub string) []string {
	t.Helper()
	token, err := natsop.NewDirPublisher(dir).Load(accountPub)
	if err != nil {
		t.Fatalf("load resolver-dir JWT: %v", err)
	}
	claims, err := jwt.DecodeAccountClaims(strings.TrimSpace(token))
	if err != nil {
		t.Fatalf("decode resolver-dir JWT: %v", err)
	}
	var subjects []string
	for _, e := range claims.Exports {
		subjects = append(subjects, string(e.Subject))
	}
	return subjects
}

// Spec §3.1 "same-process retry": a grant that failed while the broker was
// down leaves file, memory, and broker all WITHOUT the grant; retrying the
// same AddExport once the broker is back converges all three.
func TestOperator_FailedGrant_SameProcessRetryConverges(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT})
	s := dirServer(t, tr, dir)
	url := s.ClientURL()

	op := newOperator(t, tr, dir, url, time.Second)
	if err := op.PublishClaims(); err != nil { // boot publish, broker up
		t.Fatalf("boot PublishClaims: %v", err)
	}

	s.Shutdown() // the broker goes away before the grant

	const subject = "chain.pub.out"
	if _, err := op.AddExport(subject); err == nil {
		t.Fatal("AddExport with the broker down: want error")
	}
	if exports := decodeDirClaims(t, dir, tr.nodePub); len(exports) != 0 {
		t.Fatalf("resolver-dir JWT gained exports %v from a FAILED grant", exports)
	}

	// The broker returns on the same client URL and dir; the retry converges.
	s2 := restartServerAt(t, tr, dir, url)
	defer s2.Shutdown()
	if _, err := op.AddExport(subject); err != nil {
		t.Fatalf("AddExport retry after the broker returned: %v", err)
	}
	exports := decodeDirClaims(t, dir, tr.nodePub)
	if len(exports) != 1 || exports[0] != subject {
		t.Errorf("resolver-dir exports after retry = %v, want exactly [%s]", exports, subject)
	}
}

// Spec §3.1 "restart-before-retry": if the process restarts after a failed
// grant, the new operator hydrates the PREVIOUS claims (the compensation kept
// the file consistent with the reported failure), and a subsequent grant
// produces exactly one export — no ghost from the failed attempt.
func TestOperator_FailedGrant_RestartBeforeRetry(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT})
	s := dirServer(t, tr, dir)
	url := s.ClientURL()

	op := newOperator(t, tr, dir, url, time.Second)
	if err := op.PublishClaims(); err != nil {
		t.Fatalf("boot PublishClaims: %v", err)
	}
	s.Shutdown()

	const subject = "chain.pub.out"
	if _, err := op.AddExport(subject); err == nil {
		t.Fatal("AddExport with the broker down: want error")
	}

	// Process restart: a fresh operator hydrates from the resolver dir.
	s2 := restartServerAt(t, tr, dir, url)
	defer s2.Shutdown()
	op2 := newOperator(t, tr, dir, url, time.Second)
	if err := op2.PublishClaims(); err != nil {
		t.Fatalf("boot PublishClaims after restart: %v", err)
	}
	if exports := decodeDirClaims(t, dir, tr.nodePub); len(exports) != 0 {
		t.Fatalf("hydrated claims carry exports %v from a grant whose RPC failed", exports)
	}
	if _, err := op2.AddExport(subject); err != nil {
		t.Fatalf("AddExport after restart: %v", err)
	}
	exports := decodeDirClaims(t, dir, tr.nodePub)
	if len(exports) != 1 || exports[0] != subject {
		t.Errorf("exports after restart+grant = %v, want exactly [%s]", exports, subject)
	}
}
