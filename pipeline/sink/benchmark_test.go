package sink_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/vc"
)

type benchmarkVerifier struct{}

func (benchmarkVerifier) Verify(context.Context, *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return &vc.VerifyResult{Overall: vc.ConfidenceVerified}, nil
}

type benchmarkAppraiser struct {
	view *appraisal.View
}

func (a benchmarkAppraiser) Appraise(context.Context, *vc.PipelinePassCredential) (*appraisal.View, *vc.VerifyResult, error) {
	return a.view, &vc.VerifyResult{Overall: vc.ConfidenceVerified}, nil
}

type benchmarkStore struct{}

func (benchmarkStore) StoreIngressVC(context.Context, *vc.PipelinePassCredential, string) error {
	return nil
}

type benchmarkWriter struct{}

func (benchmarkWriter) Write(context.Context, sink.Record) error { return nil }

func BenchmarkSinkDelivery(b *testing.B) {
	payload := []byte(`{"lot":"LOT-BENCH","co2e_kg":12.5,"generated_by":"model"}`)
	issuer := "did:dplaax:reg:org:acme:pipeline:p:process:upstream"
	credential := boundCredIssuer(b, payload, issuer)
	wire := encode(b, credential, payload)
	truth := appraisal.TruthVerified
	view := appraisedView(b, credential, truth, appraisal.DecisionAccept)
	ctx := context.Background()

	cases := []struct {
		name      string
		appraiser sink.Appraiser
		verifier  benchmarkVerifier
		boundary  string
	}{
		{name: "legacy-adjacent", verifier: benchmarkVerifier{}},
		{name: "exact-view-delivery", appraiser: benchmarkAppraiser{view: view}, boundary: "provin-agent-delivery@1"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			cfg := sink.Config{
				Strategy: contract.VerificationAdjacent, Kind: contract.SinkProduction,
				Codec: envelopecodec.New(), Verifier: tc.verifier, Appraiser: tc.appraiser,
				AgentBoundaryID: tc.boundary, Store: benchmarkStore{}, Writer: benchmarkWriter{},
				UpstreamEndpoint: "https://upstream.example", AllowIssuers: []string{issuer},
			}
			processor, err := sink.New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := processor.Process(ctx, wire)
				if err != nil || result.Status != contract.StatusPassed {
					b.Fatalf("Process: result=%+v err=%v", result, err)
				}
			}
		})
	}
}
