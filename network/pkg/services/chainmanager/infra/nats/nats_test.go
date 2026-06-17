package nats_test

import (
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

// The nats Operator must satisfy the infra.Operator contract.
var _ infra.Operator = (*natsop.Operator)(nil)

// recorder is a fake JWTPublisher that captures every published account JWT so a
// test can decode the resulting claims and count publish calls (D-n2: a no-op
// mutation must NOT re-publish).
type recorder struct {
	calls []published
}

type published struct {
	accountPub string
	token      string
}

func (r *recorder) Publish(accountPub, token string) error {
	r.calls = append(r.calls, published{accountPub, token})
	return nil
}

// last decodes the most recently published account JWT.
func (r *recorder) last(t *testing.T) *jwt.AccountClaims {
	t.Helper()
	if len(r.calls) == 0 {
		t.Fatal("no JWT published")
	}
	ac, err := jwt.DecodeAccountClaims(r.calls[len(r.calls)-1].token)
	if err != nil {
		t.Fatalf("DecodeAccountClaims: %v", err)
	}
	return ac
}

// fixture builds an Operator over fresh throwaway keys (test scaffolding — never
// committed key material) and returns it with the recorder and the public keys.
func fixture(t *testing.T) (*natsop.Operator, *recorder, string, string) {
	t.Helper()
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	accSeed, _ := acc.Seed()
	accPub, _ := acc.PublicKey()
	opSeed, _ := op.Seed()
	opPub, _ := op.PublicKey()
	r := &recorder{}
	o, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(opSeed),
		URL:           "nats://localhost:4222",
		Publisher:     r,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, r, accPub, opPub
}

func TestPublishType(t *testing.T) {
	o, _, _, _ := fixture(t)
	if got := o.PublishType(); got != "nats" {
		t.Errorf("PublishType = %q, want nats", got)
	}
}

func TestNew_RejectsMalformedSeeds(t *testing.T) {
	r := &recorder{}
	good, _ := nkeys.CreateAccount()
	goodSeed, _ := good.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()

	if _, err := natsop.New(natsop.Config{AccountSeed: "not-a-seed", TrustRootSeed: string(opSeed), URL: "nats://h:4222", Publisher: r}); err == nil {
		t.Error("malformed account seed accepted")
	}
	if _, err := natsop.New(natsop.Config{AccountSeed: string(goodSeed), TrustRootSeed: "not-a-seed", URL: "nats://h:4222", Publisher: r}); err == nil {
		t.Error("malformed trust-root seed accepted")
	}
	if _, err := natsop.New(natsop.Config{AccountSeed: string(goodSeed), TrustRootSeed: string(opSeed), URL: "", Publisher: r}); err == nil {
		t.Error("empty URL accepted")
	}
	if _, err := natsop.New(natsop.Config{AccountSeed: string(goodSeed), TrustRootSeed: string(opSeed), URL: "nats://h:4222", Publisher: nil}); err == nil {
		t.Error("nil publisher accepted")
	}
}

func TestAddExport_PublishesStreamExport(t *testing.T) {
	o, r, accPub, opPub := fixture(t)
	ci, err := o.AddExport("chain.pub1")
	if err != nil {
		t.Fatalf("AddExport: %v", err)
	}
	// connection_info contract (D-n4): subject/account/url/publishType
	if ci["subject"] != "chain.pub1" || ci["account"] != accPub ||
		ci["url"] != "nats://localhost:4222" || ci["publishType"] != "nats" {
		t.Errorf("connection_info = %v", ci)
	}
	ac := r.last(t)
	if ac.Subject != accPub {
		t.Errorf("account JWT subject = %q, want %q", ac.Subject, accPub)
	}
	if ac.Issuer != opPub {
		t.Errorf("account JWT issuer = %q, want trust-root %q", ac.Issuer, opPub)
	}
	if len(ac.Exports) != 1 || string(ac.Exports[0].Subject) != "chain.pub1" || ac.Exports[0].Type != jwt.Stream {
		t.Errorf("exports = %+v, want one Stream export chain.pub1", ac.Exports)
	}
}

func TestAddImport_PublishesStreamImport(t *testing.T) {
	o, r, _, _ := fixture(t)
	remote, _ := nkeys.CreateAccount()
	remotePub, _ := remote.PublicKey()
	if err := o.AddImport("chain.pubX", remotePub, "local.pubX"); err != nil {
		t.Fatalf("AddImport: %v", err)
	}
	ac := r.last(t)
	if len(ac.Imports) != 1 {
		t.Fatalf("imports = %+v, want one", ac.Imports)
	}
	im := ac.Imports[0]
	if string(im.Subject) != "chain.pubX" || im.Account != remotePub ||
		string(im.LocalSubject) != "local.pubX" || im.Type != jwt.Stream {
		t.Errorf("import = %+v", im)
	}
}

func TestAddExport_Idempotent_NoRepublish(t *testing.T) {
	o, r, _, _ := fixture(t)
	if _, err := o.AddExport("chain.dup"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.AddExport("chain.dup"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Errorf("publish calls = %d, want 1 (duplicate AddExport must be a no-op)", len(r.calls))
	}
	if exps := r.last(t).Exports; len(exps) != 1 {
		t.Errorf("exports = %+v, want one (no duplicate)", exps)
	}
}

func TestAddImport_Idempotent_NoRepublish(t *testing.T) {
	o, r, _, _ := fixture(t)
	remote, _ := nkeys.CreateAccount()
	remotePub, _ := remote.PublicKey()
	if err := o.AddImport("chain.s", remotePub, "local.s"); err != nil {
		t.Fatal(err)
	}
	if err := o.AddImport("chain.s", remotePub, "local.s"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Errorf("publish calls = %d, want 1 (duplicate AddImport must be a no-op)", len(r.calls))
	}
}

func TestRemoveExport_Symmetric_Idempotent(t *testing.T) {
	o, r, _, _ := fixture(t)
	if _, err := o.AddExport("chain.r"); err != nil {
		t.Fatal(err)
	}
	if err := o.RemoveExport("chain.r"); err != nil {
		t.Fatal(err)
	}
	if exps := r.last(t).Exports; len(exps) != 0 {
		t.Errorf("after RemoveExport, exports = %+v, want none", exps)
	}
	calls := len(r.calls)
	if err := o.RemoveExport("chain.r"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != calls {
		t.Errorf("removing an absent export re-published (calls %d -> %d)", calls, len(r.calls))
	}
}

func TestRemoveImport_Symmetric_BySubjectAndAccount(t *testing.T) {
	o, r, _, _ := fixture(t)
	a1, _ := nkeys.CreateAccount()
	a1Pub, _ := a1.PublicKey()
	a2, _ := nkeys.CreateAccount()
	a2Pub, _ := a2.PublicKey()
	// two imports of the SAME subject from DIFFERENT accounts (the (subject,
	// account) identity, D-n8): removing one must leave the other.
	if err := o.AddImport("chain.shared", a1Pub, "local.a1"); err != nil {
		t.Fatal(err)
	}
	if err := o.AddImport("chain.shared", a2Pub, "local.a2"); err != nil {
		t.Fatal(err)
	}
	if err := o.RemoveImport("chain.shared", a1Pub); err != nil {
		t.Fatal(err)
	}
	ac := r.last(t)
	if len(ac.Imports) != 1 || ac.Imports[0].Account != a2Pub {
		t.Errorf("imports = %+v, want only the a2 import to remain", ac.Imports)
	}
}

func TestMutators_RejectMalformed(t *testing.T) {
	o, _, _, _ := fixture(t)
	if _, err := o.AddExport(""); err == nil {
		t.Error("empty export subject accepted")
	}
	if _, err := o.AddExport("bad subject with spaces"); err == nil {
		t.Error("subject with spaces accepted")
	}
	if err := o.AddImport("chain.s", "not-an-account-key", "local.s"); err == nil {
		t.Error("malformed remote account key accepted")
	}
	if err := o.AddImport("", "irrelevant", "local.s"); err == nil {
		t.Error("empty import subject accepted")
	}
}
