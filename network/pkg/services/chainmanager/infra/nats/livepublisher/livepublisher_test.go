package livepublisher_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	natsclient "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats/livepublisher"
)

// trust builds the operator (trust root), a system account, and a node
// account, returning their keypairs and encoded JWTs.
type trust struct {
	opKP     nkeys.KeyPair
	opPub    string
	opClaims *jwt.OperatorClaims
	sysKP    nkeys.KeyPair
	sysPub   string
	sysJWT   string
	nodeKP   nkeys.KeyPair
	nodePub  string
}

func newTrust(t *testing.T) trust {
	t.Helper()
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	opPub, _ := op.PublicKey()
	// The directory resolver refuses to start from bare trusted KEYS — it
	// needs the operator's claims (the broker conf's `operator:` line); mint
	// the same self-signed operator JWT provisioning writes.
	opToken, err := jwt.NewOperatorClaims(opPub).Encode(op)
	if err != nil {
		t.Fatal(err)
	}
	opClaims, err := jwt.DecodeOperatorClaims(opToken)
	if err != nil {
		t.Fatal(err)
	}

	mint := func(name string) (nkeys.KeyPair, string, string) {
		acc, err := nkeys.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := acc.PublicKey()
		claims := jwt.NewAccountClaims(pub)
		claims.Name = name
		token, err := claims.Encode(op)
		if err != nil {
			t.Fatal(err)
		}
		return acc, pub, token
	}
	sysKP, sysPub, sysJWT := mint("SYS")
	nodeKP, nodePub, _ := mint("node")
	return trust{opKP: op, opPub: opPub, opClaims: opClaims, sysKP: sysKP, sysPub: sysPub, sysJWT: sysJWT, nodeKP: nodeKP, nodePub: nodePub}
}

// nodeJWT encodes the node account's claims with the given exported subjects —
// the "grant mutation" shape the operator produces.
func (tr trust) nodeJWT(t *testing.T, exports ...string) string {
	t.Helper()
	claims := jwt.NewAccountClaims(tr.nodePub)
	claims.Name = "node"
	for _, sub := range exports {
		claims.Exports = append(claims.Exports, &jwt.Export{
			Name: sub, Subject: jwt.Subject(sub), Type: jwt.Stream,
		})
	}
	token, err := claims.Encode(tr.opKP)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// sysUser mints a system-account user narrowed exactly like provisioning
// does: publish only this node's claims-update subject, subscribe only to
// request-reply inboxes.
func (tr trust) sysUser(t *testing.T) (userJWT, userSeed string) {
	t.Helper()
	u, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	uPub, _ := u.PublicKey()
	uSeed, _ := u.Seed()
	claims := jwt.NewUserClaims(uPub)
	claims.Permissions.Pub.Allow.Add("$SYS.REQ.ACCOUNT." + tr.nodePub + ".CLAIMS.UPDATE")
	claims.Permissions.Sub.Allow.Add("_INBOX.>")
	token, err := claims.Encode(tr.sysKP)
	if err != nil {
		t.Fatal(err)
	}
	return token, string(uSeed)
}

// dirServer runs an embedded nats-server in operator mode with a directory
// account resolver rooted at dir and the system account configured — the
// quickstart broker shape after this slice.
func dirServer(t *testing.T, tr trust, dir string) *server.Server {
	t.Helper()
	res, err := server.NewDirAccResolver(dir, 0, 2*time.Minute, server.NoDelete)
	if err != nil {
		t.Fatal(err)
	}
	s := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedOperators: []*jwt.OperatorClaims{tr.opClaims},
		AccountResolver:  res,
		SystemAccount:    tr.sysPub,
	})
	return s
}

// seedDir writes the account JWTs a DirAccResolver needs before boot (what
// provisioning does).
func seedDir(t *testing.T, dir string, entries map[string]string) {
	t.Helper()
	for pub, token := range entries {
		if err := os.WriteFile(filepath.Join(dir, pub+".jwt"), []byte(token), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newLive(t *testing.T, tr trust, inner natsop.JWTPublisher, url string, timeout time.Duration) *livepublisher.Publisher {
	t.Helper()
	userJWT, userSeed := tr.sysUser(t)
	p, err := livepublisher.New(inner, livepublisher.Config{
		URL: url, SysUserJWT: userJWT, SysUserSeed: userSeed, Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// fakeInner records calls and can fail on demand.
type fakeInner struct {
	stored   map[string]string
	fail     error
	publishN int
}

func newFakeInner() *fakeInner { return &fakeInner{stored: map[string]string{}} }

func (f *fakeInner) Publish(pub, token string) error {
	f.publishN++
	if f.fail != nil {
		return f.fail
	}
	f.stored[pub] = token
	return nil
}

func (f *fakeInner) Load(pub string) (string, error) {
	token, ok := f.stored[pub]
	if !ok {
		return "", natsop.ErrNotPublished
	}
	return token, nil
}

// connectUnder connects a client under the given account.
func connectUnder(t *testing.T, url string, acc nkeys.KeyPair) *natsclient.Conn {
	t.Helper()
	u, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	uPub, _ := u.PublicKey()
	uSeed, _ := u.Seed()
	ujwt, err := jwt.NewUserClaims(uPub).Encode(acc)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := natsclient.Connect(url, natsclient.UserJWTAndSeed(ujwt, string(uSeed)))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return nc
}

// The slice's acceptance property, end to end: a subscriber that imported a
// subject BEFORE the publisher's export existed receives nothing (the silent
// no-flow state), and starts receiving as soon as the publisher's granted
// claims are pushed to the RUNNING broker — no reconnect, no restart.
func TestPublish_LiveUpdate_LoadedAccountStartsFlowing(t *testing.T) {
	tr := newTrust(t)
	const subject = "chain.pub.out"

	// A subscriber account importing the publisher's subject from the start.
	subKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	subPub, _ := subKP.PublicKey()
	subClaims := jwt.NewAccountClaims(subPub)
	subClaims.Imports = append(subClaims.Imports, &jwt.Import{
		Name: subject, Subject: jwt.Subject(subject),
		Account: tr.nodePub, LocalSubject: "in.granted", Type: jwt.Stream,
	})
	subJWT, err := subClaims.Encode(tr.opKP)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	seedDir(t, dir, map[string]string{
		tr.sysPub:  tr.sysJWT,
		tr.nodePub: tr.nodeJWT(t), // no export yet
		subPub:     subJWT,
	})
	s := dirServer(t, tr, dir)
	defer s.Shutdown()

	pubNC := connectUnder(t, s.ClientURL(), tr.nodeKP)
	defer pubNC.Close()
	subNC := connectUnder(t, s.ClientURL(), subKP)
	defer subNC.Close()
	inbox, err := subNC.SubscribeSync("in.granted")
	if err != nil {
		t.Fatal(err)
	}
	if err := subNC.Flush(); err != nil {
		t.Fatal(err)
	}

	// Before the grant: structurally routable but blocked (no export).
	if err := pubNC.Publish(subject, []byte("pre-grant")); err != nil {
		t.Fatal(err)
	}
	if err := pubNC.Flush(); err != nil {
		t.Fatal(err)
	}
	if msg, err := inbox.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("received %q before the export grant — isolation broken", msg.Data)
	}

	// Push the granted claims to the live broker.
	inner := natsop.NewDirPublisher(dir)
	p := newLive(t, tr, inner, s.ClientURL(), 5*time.Second)
	granted := tr.nodeJWT(t, subject)
	if err := p.Publish(tr.nodePub, granted); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// After the push the flow starts — the broker applied the claims without
	// any reconnect. Retry publish briefly: the account update is applied by
	// the server asynchronously to the claims-update reply.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := pubNC.Publish(subject, []byte("post-grant")); err != nil {
			t.Fatal(err)
		}
		if err := pubNC.Flush(); err != nil {
			t.Fatal(err)
		}
		if msg, err := inbox.NextMsg(300 * time.Millisecond); err == nil {
			// Core NATS drops unauthorized publishes, so only post-grant
			// messages can ever arrive here.
			if string(msg.Data) != "post-grant" {
				t.Fatalf("unexpected message %q", msg.Data)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("granted subject never started flowing after the live push")
		}
	}

	got, err := inner.Load(tr.nodePub)
	if err != nil || got != granted {
		t.Errorf("durable file = %.20q…, %v; want the granted JWT", got, err)
	}
}

// A push for an account nobody is connected under still succeeds AND lands in
// the resolver directory: the DirAccResolver's update handler saves the JWT,
// so the next first-lookup serves the grant. This is the load-bearing premise
// behind accepting a non-error response for an unloaded account.
func TestPublish_UnloadedAccount_PersistsToResolverDir(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT, tr.nodePub: tr.nodeJWT(t)})
	s := dirServer(t, tr, dir)
	defer s.Shutdown()

	// Inner writes somewhere else, so the resolver-dir content below can only
	// have come from the broker's own claims-update save path.
	inner := natsop.NewDirPublisher(t.TempDir())
	p := newLive(t, tr, inner, s.ClientURL(), 5*time.Second)

	granted := tr.nodeJWT(t, "chain.pub.out")
	if err := p.Publish(tr.nodePub, granted); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, tr.nodePub+".jwt"))
	if err != nil {
		t.Fatalf("resolver dir after push: %v", err)
	}
	if string(b) != granted {
		t.Error("resolver dir does not hold the pushed JWT (unloaded-account save path)")
	}
}

// The MEM-resolver "jwt update skipped" response (account not loaded) is
// accepted as success. This tolerance is safe ONLY when the durable inner
// store is also the broker's next-lookup source; the quickstart satisfies it
// by running the directory resolver (see the package doc).
func TestPublish_MemResolverSkipped_Accepted(t *testing.T) {
	tr := newTrust(t)
	mr := &server.MemAccResolver{}
	if err := mr.Store(tr.sysPub, tr.sysJWT); err != nil {
		t.Fatal(err)
	}
	if err := mr.Store(tr.nodePub, tr.nodeJWT(t)); err != nil {
		t.Fatal(err)
	}
	s := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedOperators: []*jwt.OperatorClaims{tr.opClaims},
		AccountResolver:  mr,
		SystemAccount:    tr.sysPub,
	})
	defer s.Shutdown()

	inner := newFakeInner()
	p := newLive(t, tr, inner, s.ClientURL(), 5*time.Second)
	if err := p.Publish(tr.nodePub, tr.nodeJWT(t, "chain.pub.out")); err != nil {
		t.Fatalf("Publish (skipped path): %v", err)
	}
}

// Durability comes first: when the inner publisher fails, nothing is pushed
// and the inner error surfaces.
func TestPublish_InnerFails_NoPush(t *testing.T) {
	tr := newTrust(t)
	inner := newFakeInner()
	boom := errors.New("disk full")
	inner.fail = boom
	// Unreachable URL: if a push were attempted it would burn the budget; the
	// call must return the inner error immediately instead.
	p := newLive(t, tr, inner, "nats://127.0.0.1:1", 3*time.Second)

	start := time.Now()
	err := p.Publish(tr.nodePub, tr.nodeJWT(t))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the inner publish error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("inner failure took %s — a push was attempted", elapsed)
	}
	if inner.publishN != 1 {
		t.Errorf("inner.Publish called %d times, want 1 (no compensation on inner failure)", inner.publishN)
	}
}

// A server-side rejection (here: the JWT subject does not match the account
// in the subject) is an error, and the durable file is COMPENSATED back to
// the previous JWT so the rolled-back in-memory claims and the file agree —
// otherwise a later restart would hydrate a grant whose RPC failed.
func TestPublish_ServerRejects_CompensatesFile(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	base := tr.nodeJWT(t)
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT, tr.nodePub: base})
	s := dirServer(t, tr, dir)
	defer s.Shutdown()

	fileDir := t.TempDir()
	inner := natsop.NewDirPublisher(fileDir)
	if err := inner.Publish(tr.nodePub, base); err != nil {
		t.Fatal(err)
	}

	// A sys user allowed to push for the OTHER account key, so the request
	// reaches the server and is rejected there (subject/JWT mismatch).
	other, _ := nkeys.CreateAccount()
	otherPub, _ := other.PublicKey()
	u, _ := nkeys.CreateUser()
	uPub, _ := u.PublicKey()
	uSeed, _ := u.Seed()
	uc := jwt.NewUserClaims(uPub)
	uc.Permissions.Pub.Allow.Add("$SYS.REQ.ACCOUNT." + otherPub + ".CLAIMS.UPDATE")
	uc.Permissions.Sub.Allow.Add("_INBOX.>")
	ujwt, err := uc.Encode(tr.sysKP)
	if err != nil {
		t.Fatal(err)
	}
	p, err := livepublisher.New(inner, livepublisher.Config{
		URL: s.ClientURL(), SysUserJWT: ujwt, SysUserSeed: string(uSeed), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Publish the NODE's JWT under the OTHER account key: durable write happens
	// under otherPub, the server rejects the mismatched claims, compensation
	// must remove/restore the durable state for otherPub.
	if err := inner.Publish(otherPub, base); err != nil { // prior state for otherPub
		t.Fatal(err)
	}
	err = p.Publish(otherPub, tr.nodeJWT(t, "chain.pub.out"))
	if err == nil {
		t.Fatal("Publish with mismatched account/JWT: want error")
	}
	got, loadErr := inner.Load(otherPub)
	if loadErr != nil || got != base {
		t.Errorf("durable file after failed push = %.20q…, %v; want the previous JWT restored", got, loadErr)
	}
}

// An unreachable broker fails within the configured budget (single absolute
// deadline across dial retries and the request), and the file is compensated.
func TestPublish_BrokerUnreachable_BoundedBudget(t *testing.T) {
	tr := newTrust(t)
	inner := newFakeInner()
	base := tr.nodeJWT(t)
	inner.stored[tr.nodePub] = base

	const budget = 1500 * time.Millisecond
	p := newLive(t, tr, inner, "nats://127.0.0.1:1", budget)

	start := time.Now()
	err := p.Publish(tr.nodePub, tr.nodeJWT(t, "chain.pub.out"))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Publish against a dead broker: want error")
	}
	// Worst case is the configured budget plus ONE bounded ambiguity retry.
	if elapsed < budget/2 || elapsed > budget+5*time.Second {
		t.Errorf("elapsed %s outside budget+retry (%s + bounded retry)", elapsed, budget)
	}
	if got := inner.stored[tr.nodePub]; got != base {
		t.Error("durable state not compensated back to the previous JWT")
	}
}

// The broker-restart replay: a grant pushed while the broker runs must
// survive a broker restart because the directory resolver re-reads the same
// dir. This is the deployment property that makes the whole design converge
// on one source of truth.
func TestBrokerRestart_ReplaysUpdatedClaims(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT, tr.nodePub: tr.nodeJWT(t)})
	s := dirServer(t, tr, dir)

	inner := natsop.NewDirPublisher(dir)
	p := newLive(t, tr, inner, s.ClientURL(), 5*time.Second)
	granted := tr.nodeJWT(t, "chain.pub.out")
	if err := p.Publish(tr.nodePub, granted); err != nil {
		s.Shutdown()
		t.Fatalf("Publish: %v", err)
	}
	s.Shutdown()

	s2 := dirServer(t, tr, dir)
	defer s2.Shutdown()
	served, err := s2.AccountResolver().Fetch(tr.nodePub)
	if err != nil {
		t.Fatalf("resolver fetch after restart: %v", err)
	}
	if served != granted {
		t.Error("restarted broker does not serve the granted claims from the resolver dir")
	}
}

// A lost REPLY is ambiguous, not a rejection: the publisher retries the
// idempotent update once before compensating. Simulated with a sys user whose
// UPDATE publish is allowed but whose reply inbox is NOT subscribable — the
// broker applies every update, our client never sees a reply. Both attempts
// time out, so the publish errors and compensates the durable store; the
// elapsed time evidences that the retry ran (first budget + retry budget).
// The transient residual — a broker that applied an unacknowledged update
// serving it until restart — is the documented bound of this protocol.
func TestPublish_ReplyLost_RetriesThenCompensates(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	base := tr.nodeJWT(t)
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT, tr.nodePub: base})
	s := dirServer(t, tr, dir)
	defer s.Shutdown()

	u, _ := nkeys.CreateUser()
	uPub, _ := u.PublicKey()
	uSeed, _ := u.Seed()
	uc := jwt.NewUserClaims(uPub)
	uc.Permissions.Pub.Allow.Add("$SYS.REQ.ACCOUNT." + tr.nodePub + ".CLAIMS.UPDATE")
	uc.Permissions.Sub.Deny.Add("_INBOX.>") // replies never arrive
	ujwt, err := uc.Encode(tr.sysKP)
	if err != nil {
		t.Fatal(err)
	}
	inner := natsop.NewDirPublisher(dir) // the provisioned shape: inner == resolver dir
	p, err := livepublisher.New(inner, livepublisher.Config{
		URL: s.ClientURL(), SysUserJWT: ujwt, SysUserSeed: string(uSeed), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	granted := tr.nodeJWT(t, "chain.pub.out")
	start := time.Now()
	err = p.Publish(tr.nodePub, granted)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want error when no reply ever arrives")
	}
	// First attempt (~1s request timeout) + one retry (~2s budget): the retry
	// must have run, and the total stays bounded.
	if elapsed < 2*time.Second || elapsed > 8*time.Second {
		t.Errorf("elapsed %s — want first budget + one bounded retry", elapsed)
	}
	if got, _ := inner.Load(tr.nodePub); got != base {
		t.Error("durable state not compensated back to the previous JWT")
	}
}

// A DECODED rejection is final: no retry, immediate compensation — asserted
// in the exact provisioned wiring (inner directory == the broker's resolver
// directory), where a lookup-style reconciliation would tautologically
// "confirm" whatever the inner publisher just wrote. This is the regression
// pin for the review finding that an applied-state probe must never be able
// to ACK a rejected grant.
func TestPublish_ServerRejects_ProvisionedShape_CompensatesFast(t *testing.T) {
	tr := newTrust(t)
	dir := t.TempDir()
	base := tr.nodeJWT(t)
	seedDir(t, dir, map[string]string{tr.sysPub: tr.sysJWT, tr.nodePub: base})
	s := dirServer(t, tr, dir)
	defer s.Shutdown()

	// The node's OTHER-account JWT under the node key: the server decodes it
	// and rejects the subject mismatch ("jwt update resulted in error").
	other, _ := nkeys.CreateAccount()
	otherPub, _ := other.PublicKey()
	otherClaims := jwt.NewAccountClaims(otherPub)
	otherJWT, err := otherClaims.Encode(tr.opKP)
	if err != nil {
		t.Fatal(err)
	}

	inner := natsop.NewDirPublisher(dir) // provisioned shape
	p := newLive(t, tr, inner, s.ClientURL(), 5*time.Second)

	start := time.Now()
	err = p.Publish(tr.nodePub, otherJWT) // JWT subject != accountPub → rejected
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("broker-rejected update: want error")
	}
	if elapsed > 3*time.Second {
		t.Errorf("rejection took %s — a rejection must not be retried", elapsed)
	}
	if got, _ := inner.Load(tr.nodePub); got != base {
		t.Error("resolver-dir JWT not compensated back after the rejection")
	}
}

// When there is no previous JWT to restore (the durable file vanished before
// the publish), a failed push cannot compensate: the error must say so and
// name the file-ahead residual, so the operator knows durable state carries
// an unacknowledged mutation.
func TestPublish_NoPrevSnapshot_FailureNamesResidual(t *testing.T) {
	tr := newTrust(t)
	inner := newFakeInner() // empty: Load returns ErrNotPublished
	p := newLive(t, tr, inner, "nats://127.0.0.1:1", 800*time.Millisecond)

	granted := tr.nodeJWT(t, "chain.pub.out")
	err := p.Publish(tr.nodePub, granted)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "no previous JWT") {
		t.Errorf("error %q must name the uncompensatable residual", err)
	}
	if got := inner.stored[tr.nodePub]; got != granted {
		t.Error("durable state should still hold the new JWT (nothing to restore)")
	}
}

// Timeout zero is fail-fast (mirroring connect-wait = 0s): one immediate
// attempt, no retry loop stretching the budget to a default.
func TestPublish_ZeroTimeout_FailsFast(t *testing.T) {
	tr := newTrust(t)
	inner := newFakeInner()
	inner.stored[tr.nodePub] = tr.nodeJWT(t)
	p := newLive(t, tr, inner, "nats://127.0.0.1:1", 0)

	start := time.Now()
	if err := p.Publish(tr.nodePub, tr.nodeJWT(t, "chain.pub.out")); err == nil {
		t.Fatal("want error against a dead broker")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("zero timeout took %s — not fail-fast", elapsed)
	}
}

func TestLoad_Delegates(t *testing.T) {
	tr := newTrust(t)
	inner := newFakeInner()
	inner.stored["X"] = "token"
	p := newLive(t, tr, inner, "nats://127.0.0.1:1", time.Second)
	got, err := p.Load("X")
	if err != nil || got != "token" {
		t.Errorf("Load = %q, %v; want delegation to inner", got, err)
	}
	if _, err := p.Load("Y"); !errors.Is(err, natsop.ErrNotPublished) {
		t.Errorf("Load(miss) = %v, want ErrNotPublished passthrough", err)
	}
}

func TestNew_Validation(t *testing.T) {
	tr := newTrust(t)
	userJWT, userSeed := tr.sysUser(t)
	accSeedKP, _ := nkeys.CreateAccount()
	accSeed, _ := accSeedKP.Seed()
	inner := newFakeInner()

	cases := []struct {
		name string
		in   natsop.JWTPublisher
		cfg  livepublisher.Config
	}{
		{"nil inner", nil, livepublisher.Config{URL: "nats://h:4222", SysUserJWT: userJWT, SysUserSeed: userSeed}},
		{"empty URL", inner, livepublisher.Config{SysUserJWT: userJWT, SysUserSeed: userSeed}},
		{"missing seed", inner, livepublisher.Config{URL: "nats://h:4222", SysUserJWT: userJWT}},
		{"missing jwt", inner, livepublisher.Config{URL: "nats://h:4222", SysUserSeed: userSeed}},
		{"account seed not a user seed", inner, livepublisher.Config{URL: "nats://h:4222", SysUserJWT: userJWT, SysUserSeed: string(accSeed)}},
		{"garbage seed", inner, livepublisher.Config{URL: "nats://h:4222", SysUserJWT: userJWT, SysUserSeed: "not-a-seed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := livepublisher.New(tc.in, tc.cfg); err == nil {
				t.Error("want error")
			}
		})
	}
}
