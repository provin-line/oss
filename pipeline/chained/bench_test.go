package chained_test

import (
	"context"
	stded25519 "crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/pipeline/chained"
	converterjsonata "github.com/provin-line/oss/pipeline/chained/converter/jsonata"
	"github.com/provin-line/oss/pipeline/chained/filter"
	filterjsonata "github.com/provin-line/oss/pipeline/chained/filter/jsonata"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// Paper 04 §6.4 microbenchmarks: pipeline overhead — the chained relay path
// with and without VC provenance.
//
//   - Baseline ("without VC"): the transformation work alone — JSONata filter + JSONata
//     converter over the payload bytes, exactly the runtime's stages 6-7.
//   - With VC: chained.Processor.Process end to end — envelope decode, real Ed25519
//     ingress verification (vc.Verifier over an in-memory DID resolver), payload↔credential
//     binding, filter, convert, strict decode, hashing, and a real chain-preserving
//     Ed25519 sign via vcdid.Signer.
//
// Cryptographic work only: signing uses an in-memory crypto.Signer (no keystore)
// and the ingress-VC store is a no-op (persistence is I/O, not cryptographic
// work). Network transport and TLS are absent by construction.

const (
	benchOwnerDID    = "did:dplaax:reg:org:acme"
	benchPipelineDID = "did:dplaax:reg:org:acme:pipeline:bench"
	benchSourceDID   = "did:dplaax:reg:org:acme:pipeline:bench:process:source"
	benchChainedDID  = "did:dplaax:reg:org:acme:pipeline:bench:process:chained"
	benchKeyID       = "signing"
)

// benchFilterExpr is truthy for every bench payload; benchConvertExpr derives a
// field while passing the document through, so conversion cost scales with
// payload size the way a real projection does.
const (
	benchFilterExpr  = `status = "active"`
	benchConvertExpr = `$merge([$, {"norm": value * 2}])`
)

// benchCryptoSigner is an in-memory crypto.Signer over one raw Ed25519 key.
type benchCryptoSigner struct{ priv stded25519.PrivateKey }

var _ crypto.Signer = benchCryptoSigner{}

func (s benchCryptoSigner) Sign(_, _ string, data []byte) ([]byte, error) {
	return stded25519.Sign(s.priv, data), nil
}

// benchNopStore satisfies contract.IngressVCStore without persisting: storage is
// I/O, excluded from the cryptographic-work measurement scope.
type benchNopStore struct{}

func (benchNopStore) StoreIngressVC(context.Context, *vc.PipelinePassCredential, string) error {
	return nil
}

// benchDoc builds a DID Document. When pub is non-nil the document carries a
// Multikey AssertionMethod key (id + "#signing") — the encoding the builder's
// eddsa-jcs-2022 W3C contract (proof-local @context) dispatches on.
func benchDoc(b *testing.B, id, controller string, pub []byte) *did.DIDDocument {
	b.Helper()
	fields := did.DocumentFields{
		Context: did.IssuedDocumentContexts(),
		ID:      id, Controller: controller,
	}
	if pub != nil {
		vm, err := did.NewMultikeyVerificationMethod(id+"#signing", id, pub)
		if err != nil {
			b.Fatalf("multikey vm: %v", err)
		}
		fields.VerificationMethod = []did.VerificationMethod{vm}
		fields.AssertionMethod = []string{id + "#signing"}
	}
	return did.New(fields)
}

// benchJSONPayload builds a JSON document of exactly size bytes: fixed fields the
// filter/converter expressions touch, padded to size with a filler string field.
func benchJSONPayload(b *testing.B, size int) []byte {
	b.Helper()
	head := `{"device":"sensor-1","status":"active","value":42.5,"pad":"`
	tail := `"}`
	padLen := size - len(head) - len(tail)
	if padLen < 0 {
		b.Fatalf("payload size %d too small for the base document (%d bytes)", size, len(head)+len(tail))
	}
	return []byte(head + strings.Repeat("x", padLen) + tail)
}

func benchHashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func benchVCDIDSigner(b *testing.B, issuerDID, processID string, signer benchCryptoSigner) *vcdid.Signer {
	b.Helper()
	s, err := vcdid.NewSigner(vcdid.Config{
		Builder:             vc.NewBuilder(signer),
		IssuerDID:           issuerDID,
		KeyID:               benchKeyID,
		VerificationMethod:  issuerDID + "#signing",
		PipelineID:          "bench",
		ProcessID:           processID,
		TransformationClaim: vc.ClaimConvert,
	})
	if err != nil {
		b.Fatalf("vcdid.NewSigner(%s): %v", processID, err)
	}
	return s
}

func benchKeygen(b *testing.B) (benchCryptoSigner, []byte) {
	b.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	return benchCryptoSigner{priv: stded25519.PrivateKey(kp.PrivateKey)}, kp.PublicKey
}

// benchSetup builds a processor plus the matching wire envelope for one payload:
// the ingress credential is signed with the same source key the processor's
// resolver resolves, so verification succeeds.
func benchSetup(b *testing.B, payload []byte, nFilters int) (*chained.Processor, []byte) {
	b.Helper()
	sourceSigner, sourcePub := benchKeygen(b)
	chainedSigner, _ := benchKeygen(b)

	// The ingress issuer's full controller chain on the current DID hierarchy:
	// Process (controller = Pipeline) → Pipeline (controller = Owner) → Owner.
	res := local.New()
	res.Add(benchDoc(b, benchSourceDID, benchPipelineDID, sourcePub))
	res.Add(benchDoc(b, benchPipelineDID, benchOwnerDID, nil))
	res.Add(benchDoc(b, benchOwnerDID, benchOwnerDID, nil))

	filters := make([]filter.Filter, 0, nFilters)
	for i := 0; i < nFilters; i++ {
		f, err := filterjsonata.New([]string{benchFilterExpr})
		if err != nil {
			b.Fatalf("filter compile: %v", err)
		}
		filters = append(filters, f)
	}
	conv, err := converterjsonata.New(benchConvertExpr)
	if err != nil {
		b.Fatalf("converter compile: %v", err)
	}

	proc, err := chained.New(chained.Config{
		Strategy:          contract.VerificationAdjacent,
		IngressConformant: true,
		UpstreamEndpoint:  "bench://upstream",
		Codec:             envelopecodec.New(),
		Verifier:          vc.NewVerifier(res, ed25519.Verifier{}),
		Store:             benchNopStore{},
		Signer:            benchVCDIDSigner(b, benchChainedDID, "chained", chainedSigner),
		Filters:           filters,
		Converter:         conv,
	})
	if err != nil {
		b.Fatalf("chained.New: %v", err)
	}

	h := benchHashBytes(payload)
	ingress, err := benchVCDIDSigner(b, benchSourceDID, "source", sourceSigner).
		SignFirstDrop(context.Background(), payload, h, h)
	if err != nil {
		b.Fatalf("ingress SignFirstDrop: %v", err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: ingress, Payload: payload, SequenceNo: 1})
	if err != nil {
		b.Fatalf("marshal envelope: %v", err)
	}

	// Fail loud before timing if the pipeline does not pass end to end.
	r, err := proc.Process(context.Background(), wire)
	if err != nil {
		b.Fatalf("warmup Process: %v", err)
	}
	if r.Status != contract.StatusPassed {
		b.Fatalf("warmup Process status=%v error=%q", r.Status, r.Error)
	}
	return proc, wire
}

var benchPayloadSizes = []struct {
	name string
	n    int
}{
	{"256B", 256},
	{"1KB", 1024},
	{"4KB", 4096},
}

var (
	sinkResult *contract.Result
	sinkBytes  []byte
)

// BenchmarkPipelineBaseline ("without VC"): the transformation work alone —
// one JSONata filter step + the JSONata converter over the payload bytes.
func BenchmarkPipelineBaseline(b *testing.B) {
	f, err := filterjsonata.New([]string{benchFilterExpr})
	if err != nil {
		b.Fatalf("filter compile: %v", err)
	}
	conv, err := converterjsonata.New(benchConvertExpr)
	if err != nil {
		b.Fatalf("converter compile: %v", err)
	}
	ctx := context.Background()
	for _, sz := range benchPayloadSizes {
		payload := benchJSONPayload(b, sz.n)
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz.n))
			for i := 0; i < b.N; i++ {
				res, err := f.Apply(ctx, payload)
				if err != nil || !res.Pass {
					b.Fatalf("filter: pass=%v err=%v", res != nil && res.Pass, err)
				}
				out, err := conv.Convert(ctx, payload)
				if err != nil || len(out) == 0 {
					b.Fatalf("convert: len=%d err=%v", len(out), err)
				}
				sinkBytes = out
			}
		})
	}
}

// BenchmarkPipelineWithVC ("with VC"): the full chained relay runtime —
// envelope decode, Ed25519 ingress verify, binding gate, filter, convert, strict
// decode, hashing, chain-preserving Ed25519 sign.
func BenchmarkPipelineWithVC(b *testing.B) {
	ctx := context.Background()
	for _, sz := range benchPayloadSizes {
		payload := benchJSONPayload(b, sz.n)
		proc, wire := benchSetup(b, payload, 1)
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r, err := proc.Process(ctx, wire)
				if err != nil || r.Status != contract.StatusPassed {
					b.Fatalf("process: result=%v err=%v", r, err)
				}
				sinkResult = r
			}
		})
	}
}

// BenchmarkPipelineStepScaling (§6.4 prose): with-VC latency at 256 B as filter
// step count grows — the signing cost, not step execution, should dominate.
func BenchmarkPipelineStepScaling(b *testing.B) {
	ctx := context.Background()
	payload := benchJSONPayload(b, 256)
	for _, steps := range []int{1, 5} {
		proc, wire := benchSetup(b, payload, steps)
		b.Run(fmt.Sprintf("steps=%d", steps), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r, err := proc.Process(ctx, wire)
				if err != nil || r.Status != contract.StatusPassed {
					b.Fatalf("process: result=%v err=%v", r, err)
				}
				sinkResult = r
			}
		})
	}
}
