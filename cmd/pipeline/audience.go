package main

import (
	"fmt"

	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// The audience of a wire proof is the registry ID of the node it is sent to
// (docs/protocol/auth.md § L2, D-w12). The configuration names a destination's
// registry only when it is not the one these functions derive from DIDs the
// configuration already holds (wireauth.AudienceForDID).

// ownNodeAudience is the audience of every proof the pipeline sends its own
// node (vc-store-endpoint), decided once at start: nodeRegistry
// (node-registry) when set, else the registry every signer shares, as a
// pipeline publishes to its own registry's node. Signers of two registries
// without node-registry are an error naming both and node-registry: the node
// accepts proofs for one audience only, so the pipeline does not start. A
// signer that does not parse is an error naming it. No signer and no
// node-registry is no audience: the pipeline sends its node no proof. The
// pairing with vc-store-endpoint is the configuration's: an endpoint at
// another registry's node, with no node-registry, sends that node proofs for
// this registry's node, which it refuses but holds
// (docs/architecture/deployment.md, "Wire proof audience").
func ownNodeAudience(nodeRegistry string, signers []string) (string, error) {
	if nodeRegistry != "" {
		return nodeRegistry, nil
	}
	audience, first := "", ""
	for _, signer := range signers {
		a, err := wireauth.AudienceForDID(signer)
		if err != nil {
			return "", fmt.Errorf("pipeline: a signer of the node's proofs: %w", err)
		}
		switch {
		case audience == "":
			audience, first = a, signer
		case a != audience:
			return "", fmt.Errorf("pipeline: the node's proofs are signed as DIDs of registries %q (%s) and %q (%s); the node accepts one audience, so set node-registry", audience, excerpt.Quoted(first, 128), a, excerpt.Quoted(signer, 128))
		}
	}
	return audience, nil
}

// ownNodeSigners are the DIDs the pipeline signs its own node's proofs as:
// nodeDID (the audit head), each producing loop's
// output subject (retained payloads, emit health) and issuer (emission
// evidence, its custody log's mirror), and each sink's receipt issuer (its
// receipt and reject logs' mirror), in the loops' order.
func ownNodeSigners(loops []pipelineconfig.LoopConfig, nodeDID string) []string {
	var out []string
	add := func(dids ...string) {
		for _, d := range dids {
			if d != "" {
				out = append(out, d)
			}
		}
	}
	add(nodeDID)
	for _, lc := range loops {
		switch lc.Role {
		case pipelineconfig.RoleSource:
			add(lc.Source.OutputSubject, lc.Source.Issuer.DID)
		case pipelineconfig.RoleChained:
			add(lc.Chained.OutputSubject, lc.Chained.Issuer.DID)
		case pipelineconfig.RoleAggregate:
			add(lc.Aggregate.OutputSubject, lc.Aggregate.Issuer.DID)
		case pipelineconfig.RoleSink:
			if lc.Sink.Receipt.Issue {
				add(lc.Sink.Receipt.Issuer.DID)
			}
		}
	}
	return out
}

// upstreamAudiences maps each by-reference ingress's upstream-endpoint to the
// audience its fetches name: the ingress's upstream-registry when set, else
// the registry segment of its upstream pipeline DID (ingress-subject, or an
// aggregate ingress's subject), whose node holds and serves that pipeline's
// payloads. Inline ingresses fetch nothing and are left out. One endpoint
// with two audiences is an error, as one endpoint is one node.
func upstreamAudiences(loops []pipelineconfig.LoopConfig) (map[string]string, error) {
	out := map[string]string{}
	add := func(endpoint, override, subject string) error {
		audience := override
		if audience == "" {
			var err error
			if audience, err = wireauth.AudienceForDID(subject); err != nil {
				return fmt.Errorf("upstream %q: the upstream pipeline DID: %w", endpoint, err)
			}
		}
		if prev, ok := out[endpoint]; ok && prev != audience {
			return fmt.Errorf("upstream %q is named for two registries, %q and %q; one endpoint is one node (set upstream-registry)", endpoint, prev, audience)
		}
		out[endpoint] = audience
		return nil
	}
	for _, lc := range loops {
		var err error
		switch lc.Role {
		case pipelineconfig.RoleSink:
			if lc.Sink.PayloadDelivery == byReference {
				err = add(lc.Sink.UpstreamEndpoint, lc.Sink.UpstreamRegistry, lc.IngressSubject)
			}
		case pipelineconfig.RoleChained:
			if lc.Chained.PayloadDelivery == byReference {
				err = add(lc.Chained.UpstreamEndpoint, lc.Chained.UpstreamRegistry, lc.IngressSubject)
			}
		case pipelineconfig.RoleAggregate:
			for _, ing := range lc.Aggregate.Ingresses {
				if ing.PayloadDelivery == byReference {
					if err = add(ing.UpstreamEndpoint, ing.UpstreamRegistry, ing.Subject); err != nil {
						break
					}
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("pipeline: loop %q: %w", lc.Name, err)
		}
	}
	return out, nil
}

// byReference is pipelineconfig's spelling of the by-reference delivery mode.
const byReference = "by-reference"
