package runtime

import (
	"context"
	"io"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/pipeline/sink/console"
)

// dpCustodyKeyStore returns a filestore keystore holding fresh signing keys for
// BOTH the source loop's issuer (dpIssuerDID) and the archival sink's receipt
// issuer (dpArchiveReceiptIssr) — dpCustodyCfg's combined pipeline needs both
// to boot (each loop's vcdid.NewSigner / filelog.WithCheckpointSigner resolves
// its own DID's key from the shared keystore).
func dpCustodyKeyStore(t *testing.T) keystore.KeyStore {
	t.Helper()
	ks := filestore.New(t.TempDir())
	for _, did := range []string{dpIssuerDID, dpArchiveReceiptIssr} {
		kp, err := (ed25519.Generator{}).Generate()
		if err != nil {
			t.Fatalf("keygen %s: %v", did, err)
		}
		if err := ks.SaveKeyPair(did, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatalf("save key %s: %v", did, err)
		}
	}
	return ks
}

// dpCustodyCfg wires a source loop (emits on dpPipelineDID) feeding a
// receipt-configured archival sink (ingresses dpPipelineDID) — the combined
// shape the custody-registry tests need: one Build produces an emission log,
// a sink-receipt log, and a sink-reject log.
func dpCustodyCfg() *Config {
	cfg := dpPipelineCfg()
	cfg.Loops = append(cfg.Loops, dpArchivalSinkCfg().Loops...)
	return cfg
}

func custodyIDs(cs []CustodyLog) []string {
	ids := make([]string, len(cs))
	for i, c := range cs {
		ids[i] = c.LogID
	}
	return ids
}

// TestDataPlane_CustodyLogs_DurableEntries is the D6 capstone: a config with a
// source loop plus a receipt-configured archival sink, with both TlogDir and
// RejectLogDir set, must yield custody entries for the emission log, the
// sink-receipt log, and the sink-reject log — each labelled with the exact log
// id it signs as and the issuer identity that signs its checkpoints (the SAME
// identity the mirror shipper will later sign MirrorLogSegment wireauth proofs
// as, D-T3). Tlogs() (the TlogService READ surface) must still exclude the
// reject log — CustodyLogs() is a separate, custody-only registry.
func TestDataPlane_CustodyLogs_DurableEntries(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	cfg := withNATS(url, accSeed, dpCustodyCfg())
	cfg.TlogDir = t.TempDir()
	cfg.RejectLogDir = t.TempDir()

	dp, err := Build(context.Background(), cfg, dpCustodyKeyStore(t), Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
		AuditQueue: newMemAuditQueue(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.conn.Close() })

	custody := dp.CustodyLogs()
	if len(custody) != 3 {
		t.Fatalf("custody entries: got %d (%v), want 3 (emission + receipt + reject)", len(custody), custodyIDs(custody))
	}

	byID := map[string]CustodyLog{}
	for _, c := range custody {
		byID[c.LogID] = c
	}

	const (
		wantEmissionID = dpPipelineDID
		wantReceiptID  = "sink-receipt:" + dpArchiveReceiptIssr
		wantRejectID   = "sink-reject:" + dpArchiveReceiptIssr
	)
	for _, id := range []string{wantEmissionID, wantReceiptID, wantRejectID} {
		if _, ok := byID[id]; !ok {
			t.Errorf("custody registry missing entry for log id %q; got ids %v", id, custodyIDs(custody))
		}
	}

	// Pin the FULL signer identity per entry (DID + KeyID + VerificationMethod)
	// — the shipper signs MirrorLogSegment proofs as exactly this identity, and
	// the registry's D-T3 check requires it to equal the checkpoint signer.
	wantEmissionSigner := IssuerConfig{DID: dpIssuerDID, KeyID: string(keystore.KeyIDSigning), VerificationMethod: dpIssuerDID + "#signing"}
	wantArchiveSigner := IssuerConfig{DID: dpArchiveReceiptIssr, KeyID: string(keystore.KeyIDSigning), VerificationMethod: dpArchiveReceiptIssr + "#signing"}
	if c := byID[wantEmissionID]; c.Signer != wantEmissionSigner {
		t.Errorf("emission custody signer = %+v, want %+v", c.Signer, wantEmissionSigner)
	}
	if c := byID[wantReceiptID]; c.Signer != wantArchiveSigner {
		t.Errorf("receipt custody signer = %+v, want %+v", c.Signer, wantArchiveSigner)
	}
	if c := byID[wantRejectID]; c.Signer != wantArchiveSigner {
		t.Errorf("reject custody signer = %+v, want %+v", c.Signer, wantArchiveSigner)
	}

	// Each custody Log handle actually checkpoints under its claimed log id —
	// not just a matching struct field copied from config.
	for _, id := range []string{wantEmissionID, wantReceiptID, wantRejectID} {
		c, ok := byID[id]
		if !ok {
			continue // already reported above
		}
		cp, err := c.Log.Checkpoint(context.Background())
		if err != nil {
			t.Fatalf("Checkpoint on custody log %q: %v", id, err)
		}
		if cp.Origin != id {
			t.Errorf("custody log %q checkpoint Origin = %q, want %q", id, cp.Origin, id)
		}
	}

	// D-T5 unchanged: Tlogs() (the READ surface) still excludes the reject log.
	if _, ok := dp.Tlogs()[wantRejectID]; ok {
		t.Fatalf("reject log leaked into Tlogs() (the READ surface) under %q", wantRejectID)
	}
}

// TestDataPlane_CustodyLogs_MemlogEmpty asserts the unit-test seam: with
// TlogDir/RejectLogDir both empty, every durable-log construction site falls
// back to an in-memory log — nothing durable to custody, so CustodyLogs()
// must be empty even though the same source+archival-sink pipeline boots.
func TestDataPlane_CustodyLogs_MemlogEmpty(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	cfg := withNATS(url, accSeed, dpCustodyCfg())

	dp, err := Build(context.Background(), cfg, dpCustodyKeyStore(t), Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
		AuditQueue: newMemAuditQueue(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.conn.Close() })

	if custody := dp.CustodyLogs(); len(custody) != 0 {
		t.Fatalf("custody entries with memlog fallback: got %d (%v), want 0", len(custody), custodyIDs(custody))
	}
}
