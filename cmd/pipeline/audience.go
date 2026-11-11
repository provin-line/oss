package main

import (
	"fmt"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

// The audience of a wire proof is the registry ID of the node it is sent to
// (docs/protocol/auth.md § L2, D-w12). The configuration names a destination's
// registry only when it is not the one these functions derive from DIDs the
// configuration already holds.

// ownNodeAudience is the audience of a proof the pipeline signs as signerDID
// for its own node (vc-store-endpoint): override (vc-store-registry) when
// set, else the registry segment of signerDID, as a pipeline publishes to its
// own registry's node. A signerDID that does not parse is an error naming it.
// The pairing with vc-store-endpoint is the configuration's: an endpoint at
// another registry's node, with no override, sends that node proofs for this
// registry's node, which it refuses but holds (docs/architecture/deployment.md,
// "Wire proof audience").
func ownNodeAudience(override, signerDID string) (string, error) {
	if override != "" {
		return override, nil
	}
	d, err := dplaax.Parse(signerDID)
	if err != nil {
		return "", fmt.Errorf("pipeline: signer %s does not parse as a did:dplaax DID, so the audience of its node is unknown: %w", excerpt.Quoted(signerDID, 128), err)
	}
	return d.Registry, nil
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
			d, err := dplaax.Parse(subject)
			if err != nil {
				return fmt.Errorf("upstream %q: the upstream pipeline DID %s: %w", endpoint, excerpt.Quoted(subject, 128), err)
			}
			audience = d.Registry
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
